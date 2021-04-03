#[macro_use]
extern crate log;

#[macro_use]
extern crate diesel;
extern crate dotenv;


mod auth;
mod error;
mod key;
mod utils;
mod yubikey;

use auth::{AuthMechanism, AuthorizationRequestProperties, AuthServer, LocalDatabase, RegisterKeyRequestProperties};

use clap::{App, Arg};
use x509_parser::prelude::*;
use x509_parser::der_parser::oid;

use error::RusticaServerError;

use influx_db_client::{
    Client, Point, Points, Precision, points
};

use rustica::rustica_server::{Rustica, RusticaServer as GRPCRusticaServer};
use rustica::{
    CertificateRequest,
    CertificateResponse,
    Challenge,
    ChallengeRequest,
    ChallengeResponse,
    RegisterKeyRequest,
    RegisterKeyResponse,
};

use sshcerts::yubikey::Yubikey;

use sshcerts::ssh::{
    CertType, Certificate, CurveKind, CriticalOptions, PublicKey as SSHPublicKey, PublicKeyKind as SSHPublicKeyKind
};

//use sshcerts::yubikey::ssh::{ssh_cert_fetch_pubkey, ssh_cert_signer};

use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ED25519};
use ring::{hmac, rand};
use std::convert::TryFrom;
// It is my understanding that it is fine to use a standard Mutex here
// instead of a tokio Mutex because we are not holding the lock across an
// await boundary.
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tonic::{Request, Response, Status};
use tonic::transport::{Certificate as TonicCertificate, Identity, Server, ServerTlsConfig};

use yubikey_piv::key::SlotId;

pub mod rustica {
    tonic::include_proto!("rustica");
}

pub struct RusticaServer {
    influx_client: Option<Client>,
    hmac_key: hmac::Key,
    authorizer: auth::AuthMechanism,
    user_ca_cert: SSHPublicKey,
    user_ca_signer: Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>,
    host_ca_cert: SSHPublicKey,
    host_ca_signer: Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>,
}

fn create_signer(slot: SlotId, mutex: Arc<Mutex<u32>>) -> Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync> {
    Box::new(move |buf: &[u8]| {
        match mutex.lock() {
            Ok(_) => {
                let mut yk = Yubikey::new().unwrap();
                match yk.ssh_cert_signer(buf, &slot) {
                    Ok(sig) => Some(sig),
                    Err(_) => None,
                }
            },
            Err(e) => {
                println!("Error in acquiring mutex for yubikey signing: {}", e);
                None
            }
        }
    })
}

fn create_response<T>(e: T) -> Response<CertificateResponse> where 
T : Into::<RusticaServerError> {
    let e = e.into();
    Response::new(CertificateResponse {
        certificate: String::new(),
        error: format!("{:?}", e),
        error_code: e as i64,
    })
}

/// Validates a request passes all the following checks in this order:
/// Validate the peer certs are the way we expect
/// Validate Time is not expired
/// Validate Mac
/// Validate Signature
fn validate_request(hmac_key: &ring::hmac::Key, peer_certs: &Arc<Vec<TonicCertificate>>, challenge: &Challenge) -> Result<(SSHPublicKey, Vec<String>), RusticaServerError> {
    if peer_certs.is_empty() {
        return Err(RusticaServerError::NotAuthorized);
    }

    let mut mtls_identities = vec![];
    for peer in peer_certs.iter() {
        match x509_parser::parse_x509_certificate(peer.as_ref()) {
            Err(_) => return Err(RusticaServerError::NotAuthorized),
            Ok((_, cert)) => {
                for ident in cert.tbs_certificate.subject.rdn_seq {
                    for attr in ident.set {
                        if attr.attr_type == oid!(2.5.4.3) {    // CommonName
                            mtls_identities.push(String::from(attr.attr_value.as_str().unwrap_or_default()))
                        }
                    }
                }
            },
        };
    }

    // If something happens with the timestamp, we go with worst case scenario:
    // Client timestamp issues - Assume it was sent at time 0
    // Host timestamp issues   - Assume it's about 292 billion years from now
    let client_timestamp = &challenge.challenge_time.parse::<u64>().unwrap_or(0);
    let current_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(ts) => ts.as_secs(),
        Err(_e) => 0xFFFFFFFFFFFFFFFF,
    };

    if (current_timestamp - client_timestamp) > 5 {
        return Err(RusticaServerError::TimeExpired);
    }

    let hmac_verification = format!("{}-{}", client_timestamp, challenge.pubkey);
    let decoded_challenge = match hex::decode(&challenge.challenge) {
        Ok(dc) => dc,
        Err(_) => return Err(RusticaServerError::BadChallenge),
    };

    if let Err(_) = hmac::verify(hmac_key, hmac_verification.as_bytes(), &decoded_challenge) {
       return Err(RusticaServerError::BadChallenge);
    }

    // Verification of the integrity of the request is now done, we can
    // parse the rest of the request knowing it has not been replayed
    // significantly in time or it's publickey tampered with since its
    // its initial request.
    let ssh_pubkey = match SSHPublicKey::from_string(&challenge.pubkey) {
        Ok(sshpk) => sshpk,
        Err(_) => return Err(RusticaServerError::InvalidKey),
    };

    let result = match &ssh_pubkey.kind {
        SSHPublicKeyKind::Ecdsa(key) => {
            let (pubkey, alg) = match key.curve.kind {
                CurveKind::Nistp256 => (key, &ECDSA_P256_SHA256_ASN1),
                CurveKind::Nistp384 => (key, &ECDSA_P384_SHA384_ASN1),
                _ => return Err(RusticaServerError::UnsupportedKeyType),
            };

            UnparsedPublicKey::new(alg, &pubkey.key).verify(
                &hex::decode(&challenge.challenge).unwrap(),
                &hex::decode(&challenge.challenge_signature).unwrap(),
            )
        },
        SSHPublicKeyKind::Ed25519(key) => {
            let alg = &ED25519;
            let peer_public_key = UnparsedPublicKey::new(alg, &key.key);
            peer_public_key.verify(
                &hex::decode(&challenge.challenge).unwrap(),
                &hex::decode(&challenge.challenge_signature).unwrap()
            )
        },
        _ => return Err(RusticaServerError::UnsupportedKeyType),
    };

    if let Err(_) = result {
        return Err(RusticaServerError::BadChallenge)
    }

    Ok((ssh_pubkey, mtls_identities))
}

#[tonic::async_trait]
impl Rustica for RusticaServer {
    /// Handler when a host is going to make a further request to Rustica
    async fn challenge(&self, request: Request<ChallengeRequest>) -> Result<Response<ChallengeResponse>, Status> {
        let request = request.into_inner();
        debug!("Someone wants to authenticate: {}", request.pubkey);

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let pubkey = &request.pubkey;
        let challenge = format!("{}-{}", timestamp, pubkey);
        let tag = hmac::sign(&self.hmac_key, challenge.as_bytes());

        let reply = ChallengeResponse {
            time: timestamp,
            challenge: hex::encode(tag),
        };

        Ok(Response::new(reply))
    }

    /// Handler used when a host requests a new certificate from Rustica
    async fn certificate(&self, request: Request<CertificateRequest>) -> Result<Response<CertificateResponse>, Status> {
        debug!("Received certificate request: {:?}", request);
        let remote_addr = request.remote_addr().unwrap();
        let peer = request.peer_certs();
        let request = request.into_inner();

        let (challenge, peer) = match (&request.challenge, peer) {
            (Some(challenge), Some(peer)) => (challenge, peer),
            _ => return Ok(create_response(RusticaServerError::BadRequest)),
        };

        let (ssh_pubkey, mtls_identities) = match validate_request(&self.hmac_key, &peer, &challenge) {
            Ok((ssh_pk, idents)) => (ssh_pk, idents),
            Err(e) => return Ok(create_response(e)),
        };

        let current_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(ts) => ts.as_secs(),
            Err(_e) => 0xFFFFFFFFFFFFFFFF,
        };

        if (request.valid_before < request.valid_after) || current_timestamp > request.valid_before {
            // Can't have a cert where the start time (valid_after) is before
            // the end time (valid_before)
            // Disallow certificates that are already expired
            return Ok(create_response(RusticaServerError::BadCertOptions));
        }

        let (req_cert_type, ca_cert, signer) = match request.cert_type {
            1 => (CertType::User, &self.user_ca_cert, &self.user_ca_signer),
            2 => (CertType::Host, &self.host_ca_cert, &self.host_ca_signer),
            _ => return Ok(create_response(RusticaServerError::BadCertOptions)),
        };

        let fingerprint = ssh_pubkey.fingerprint().hash;

        let auth_props = AuthorizationRequestProperties {
            fingerprint: fingerprint.clone(),
            mtls_identities: mtls_identities.clone(),
            requester_ip: remote_addr.to_string(),
            principals: request.principals.clone(),
            servers: request.servers.clone(),
            cert_type: req_cert_type,
            valid_after: request.valid_after,
            valid_before: request.valid_before,
        };

        let authorization = match &self.authorizer {
            AuthMechanism::Local(local) => local.authorize(&auth_props),
            AuthMechanism::External(external) => external.authorize(&auth_props).await,
        };

        let authorization = match authorization {
            Err(e) => return Ok(create_response(e)),
            Ok(auth) => auth,
        };

        debug!("Authorization: {:?}", authorization);

        let critical_options = match utils::build_login_script(&authorization.hosts, &authorization.force_command) {
            Ok(cmd) => {
                let mut co = std::collections::HashMap::new();
                // If our authorization contains no hosts and no command,
                // this becomes an unrestricted cert good for all commands on all
                // hosts
                if let Some(cmd) = cmd {
                    co.insert(String::from("force-command"), cmd);
                }

                if authorization.force_source_ip {
                    co.insert(String::from("source-address"), remote_addr.ip().to_string());
                }

                CriticalOptions::Custom(co)
            },
            Err(_) => return Ok(create_response(RusticaServerError::Unknown)),
        };

        let cert = Certificate::builder(&ssh_pubkey, req_cert_type, &ca_cert).unwrap()
            .serial(authorization.serial)
            .key_id(format!("Rustica-JITC-for-{}", &fingerprint))
            .set_principals(&authorization.principals)
            .valid_after(authorization.valid_after)
            .valid_before(authorization.valid_before)
            .set_critical_options(critical_options)
            .set_extensions(authorization.extensions)
            .sign(signer);

        let serialized_cert = match cert {
            Ok(cert) => {
                let serialized = format!("{}", cert);

                // Sanity check that we can parse the cert we just generated
                if let Err(e) = Certificate::from_string(&serialized) {
                    error!("Couldn't deserialize certificate: {}", e);
                    return Ok(create_response(RusticaServerError::BadCertOptions));
                }
                serialized
            }
            Err(e) => {
                error!("Creating certificate failed: {}", e);
                return Ok(create_response(RusticaServerError::BadChallenge));
            }
        };

        let reply = CertificateResponse {
            certificate: serialized_cert,
            error: String::new(),
            error_code: RusticaServerError::Success as i64,
        };

        if let Some(influx_client) = &self.influx_client {
            let point = Point::new("rustica_logs")
                .add_tag("fingerprint", fingerprint)
                .add_tag("mtls_identities", mtls_identities.join(","))
                .add_field("principals", authorization.principals.join(","))
                .add_field("hosts", authorization.hosts.unwrap_or_default().join(","));

            if let Err(e) = influx_client.write_points(points!(point), Some(Precision::Seconds), None).await {
                error!("Could not log to influx DB: {}", e);
            }
        }

        Ok(Response::new(reply))
    }

    async fn register_key(&self, request: Request<RegisterKeyRequest>) -> Result<Response<RegisterKeyResponse>, Status> {
        debug!("Received register key request: {:?}", request);
        let requester_ip = match request.remote_addr() {
            Some(x) => x.to_string(),
            None => String::new(),
        };

        let peer = request.peer_certs();
        let request = request.into_inner();

        let (challenge, peer) = match (&request.challenge, peer) {
            (Some(challenge), Some(peer)) => (challenge, peer),
            _ => return Err(Status::permission_denied("")),
        };

        let (ssh_pubkey, mtls_identities) = match validate_request(&self.hmac_key, &peer, &challenge) {
            Ok((ssh_pk, idents)) => (ssh_pk, idents),
            Err(e) => return Err(Status::cancelled(format!("{:?}", e))),
        };

        let (fingerprint, attestation) = match yubikey::verify_certificate_chain(&request.certificate, &request.intermediate) {
            Ok(key) => (key.fingerprint, key.attestation),
            _ => (ssh_pubkey.fingerprint().hash, None),
        };

        let register_properties = RegisterKeyRequestProperties {
            fingerprint,
            mtls_identities,
            requester_ip,
            attestation,
        };

        let response = match &self.authorizer {
            AuthMechanism::Local(local) => local.register_key(&register_properties),
            AuthMechanism::External(external) => external.register_key(&register_properties).await,
        };

        match response {
            Ok(true) => return Ok(Response::new(RegisterKeyResponse{})),
            _ => return Err(Status::unavailable("Could not register new key")),
        }
    }
}

fn slot_parser(slot: &str) -> Result<SlotId, String> {
    // If first character is R, then we need to parse the nice
    // notation
    if (slot.len() == 2 || slot.len() == 3) && slot.starts_with('R') {
        let slot_value = slot[1..].parse::<u8>();
        match slot_value {
            Ok(v) if v <= 20 => Ok(SlotId::try_from(0x81_u8 + v).unwrap()),
            _ => Err(String::from("Invalid slot provided")),
        }
    } else if let Ok(s) = SlotId::try_from(slot.to_owned()) {
        Ok(s)
    } else {
        Err(String::from("Could not interpret input as slot. Must be in format R1-R20. E.g: R1, R5, R17, R20"))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let matches = App::new("rustica")
    .version(env!("CARGO_PKG_VERSION"))
    .author("Mitchell Grenier <mitchell@confurious.io>")
    .about("Rustica is a Yubikey backed SSHCA")
    .arg(
        Arg::new("servercert")
            .about("Path to PEM that contains server public key")
            .long("servercert")
            .required(true)
            .takes_value(true),
    )
    .arg(
        Arg::new("serverkey")
            .about("Path to pem that contains server private key")
            .long("serverkey")
            .required(true)
            .takes_value(true),
    )
    .arg(
        Arg::new("clientcacert")
            .about("Path to pem that contains client ca public key")
            .long("clientcacert")
            .required(true)
            .takes_value(true),
    )
    .arg(
        Arg::new("keytype")
            .about("The type of key you want to use for your keys. Slot expects a Yubikey slot R1-R20. File expects a file path.")
            .possible_value("slot")
            .possible_value("file")
            .long("keytype")
            .required(true)
            .takes_value(true),
    )
    .arg(
        Arg::new("userkey")
            .about("Slot to use for user CA")
            .long("userkey")
            .required(true)
            .takes_value(true),
    )
    .arg(
        Arg::new("hostkey")
            .about("Slot to use for host CA")
            .long("hostkey")
            .required(true)
            .takes_value(true),
    )
    .arg(
        Arg::new("listenaddress")
            .about("Address and port to listen on")
            .long("listen")
            .takes_value(true),
    )
    .arg(
        Arg::new("influxdbaddress")
            .about("URI of InfluxDB server")
            .long("influxdbaddress")
            .takes_value(true),
    )
    .arg(
        Arg::new("influxdbdatabase")
            .about("InfluxDB database")
            .long("influxdbdatabase")
            .takes_value(true),
    )
    .arg(
        Arg::new("influxdbuser")
            .about("InfluxDB user")
            .long("influxdbuser")
            .takes_value(true),
    )
    .arg(
        Arg::new("influxdbpassword")
            .about("InfluxDB password")
            .long("influxdbpassword")
            .takes_value(true),
    )
    .arg(
        Arg::new("authtype")
            .about("What source of truth should be used for requests")
            .default_value("local")
            .possible_value("local")
            .possible_value("external")
            .long("authtype")
            .takes_value(true),
    )
    .arg(
        Arg::new("authserver")
            .about("If using external auth: the hostname of the auth server")
            .long("authserver")
            .takes_value(true),
    )
    .arg(
        Arg::new("authserverport")
            .about("If using external auth: the port of the auth server")
            .long("authserverport")
            .takes_value(true),
    )
    .arg(
        Arg::new("authserverca")
            .about("If using external auth: The certificate of the auth server's CA")
            .long("authserverca")
            .takes_value(true),
    )
    .arg(
        Arg::new("authservermtlspem")
            .about("If using external auth: The certificate to present to the remote server for mTLS")
            .long("authservermtlspem")
            .takes_value(true),
    )
    .arg(
        Arg::new("authservermtlskey")
            .about("If using external auth: The key for authenticating to the remote server via mTLS")
            .long("authservermtlskey")
            .takes_value(true),
    )
    .get_matches();

    let (user_ca_cert, user_signer, host_ca_cert, host_signer) = match (matches.value_of("keytype"), matches.value_of("userkey"), matches.value_of("hostkey")) {
        (Some("slot"), Some(uk), Some(hk)) => {
            let us = slot_parser(uk)?;
            let hs = slot_parser(hk)?;
            let mut yk = Yubikey::new().unwrap();
            
            let user_ca_cert = yk.ssh_cert_fetch_pubkey(&us);
            let host_ca_cert = yk.ssh_cert_fetch_pubkey(&hs);
            let yubikey_mutex = Arc::new(Mutex::new(0));

            match (user_ca_cert, host_ca_cert) {
                (Ok(ucc), Ok(hcc)) => (
                    ucc,
                    create_signer(us, yubikey_mutex.clone()),
                    hcc,
                    create_signer(hs, yubikey_mutex)
                ),
                _ => {
                    error!("Could not fetch CA public keys from YubiKey. Is it connected/configured?");
                    return Ok(());
                }
            }
        },
        (Some("file"), Some(uk), Some(hk)) => {
            let userkey = sshcerts::ssh::PrivateKey::from_path(uk)?;
            let hostkey = sshcerts::ssh::PrivateKey::from_path(hk)?;
            (userkey.pubkey.clone(), userkey.into(), hostkey.pubkey.clone(), hostkey.into())
        },
        _ => {
            println!("The key type must be one of: [slot, file]. Both a user and host key must be provided");
            return Ok(());
        },
    };

    let servercert = matches.value_of("servercert").unwrap();
    let serverkey = matches.value_of("serverkey").unwrap();
    let addr = matches.value_of("listenaddress").unwrap_or("[::1]:50051").parse().unwrap();

    let servercert = tokio::fs::read(servercert).await?;
    let serverkey = tokio::fs::read(serverkey).await?;
    let identity = Identity::from_pem(servercert, serverkey);
    let client_ca_cert = tokio::fs::read(matches.value_of("clientcacert").unwrap()).await?;
    let client_ca_cert = TonicCertificate::from_pem(client_ca_cert);

    let address = matches.value_of("influxdbaddress");
    let user = matches.value_of("influxdbuser");
    let password = matches.value_of("influxdbpassword");
    let db = matches.value_of("influxdbdatabase");

    let influx_client = match (address, user, password, db) {
        (Some(address), Some(user), Some(password), Some(db)) => Some(
            Client::new(address.parse().unwrap(), db).set_authentication(user, password)
        ),
        _ => {
            info!("InfluxDB is not configured");
            None
        },
    };

    let authorizer = match matches.value_of("authtype") {
        Some("local") => AuthMechanism::Local(LocalDatabase{}),
        Some("external") => AuthMechanism::External(AuthServer {
            server: matches.value_of("authserver").unwrap().to_string(),
            port: matches.value_of("authserverport").unwrap().to_string(),
            ca: tokio::fs::read(matches.value_of("authserverca").unwrap().to_string()).await?,
            mtls_cert: tokio::fs::read(matches.value_of("authservermtlspem").unwrap().to_string()).await?,
            mtls_key: tokio::fs::read(matches.value_of("authservermtlskey").unwrap().to_string()).await?,
        }),
        _ => unreachable!("Clap should ensure it must be one of the two values above"),
    };

    println!("Starting Rustica");
    info!("User CA Pubkey: {}", user_ca_cert);
    println!("User CA Fingerprint (SHA256): {}", user_ca_cert.fingerprint().hash);

    info!("Host CA Pubkey: {}", host_ca_cert);
    println!("Host CA Fingerprint (SHA256): {}", host_ca_cert.fingerprint().hash);

    match &authorizer {
        AuthMechanism::Local(_) => println!("Authorization handled by local database"),
        AuthMechanism::External(_) => println!("Authorization handled by remote service"),
    }

    let rng = rand::SystemRandom::new();
    let hmac_key = hmac::Key::generate(hmac::HMAC_SHA256, &rng).unwrap();

    let rs = RusticaServer {
        influx_client,
        hmac_key,
        authorizer,
        user_ca_cert,
        host_ca_cert,
        user_ca_signer: user_signer,
        host_ca_signer: host_signer,
    };

    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity).client_ca_root(client_ca_cert))?
        .add_service(GRPCRusticaServer::new(rs))
        .serve(addr)
        .await?;

    Ok(())
}
