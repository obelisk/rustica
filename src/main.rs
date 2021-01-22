#[macro_use]
extern crate log;

#[macro_use]
extern crate diesel;
extern crate dotenv;

mod database;
mod error;
mod utils;

use clap::{App, Arg};

use database::get_fingerprint_authorization;
use error::RusticaServerError;

use rustica::rustica_server::{Rustica, RusticaServer as GRPCRusticaServer};
use rustica::{CertificateRequest, CertificateResponse, ChallengeRequest, ChallengeResponse};

use rustica_keys::ssh::{
    CertType, Certificate, CurveKind, CriticalOptions, PublicKey as SSHPublicKey, PublicKeyKind as SSHPublicKeyKind,
};
use rustica_keys::yubikey::ssh::{ssh_cert_fetch_pubkey, ssh_cert_signer};

use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ED25519};
use ring::{hmac, rand};
use std::convert::TryFrom;
use std::time::SystemTime;
use tonic::{Request, Response, Status};
use tonic::transport::{Identity, Server, ServerTlsConfig};

use yubikey_piv::key::SlotId;

pub mod rustica {
    tonic::include_proto!("rustica");
}

pub struct RusticaServer {
    hmac_key: hmac::Key,
    user_ca_cert: SSHPublicKey,
    user_ca_signer: Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>,
    host_ca_cert: SSHPublicKey,
    host_ca_signer: Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>,
}

fn create_signer(slot: SlotId) -> Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync> {
    Box::new(move |buf: &[u8]| {
        ssh_cert_signer(buf, slot)
    })
}

fn create_response(e: RusticaServerError) -> Response<CertificateResponse> {
    Response::new(CertificateResponse {
        certificate: String::new(),
        error: format!("{:?}", e),
        error_code: e as i64,
    })
}

#[tonic::async_trait]
impl Rustica for RusticaServer {
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

    /// This function is responsible for validating the request passes all the
    /// following checks, and in this order.
    /// Zeroth Validate Time is not expired
    /// First Validate Mac
    /// Second Validate Signature
    /// Third Validate PubKey is authorized
    async fn certificate(&self, request: Request<CertificateRequest>) -> Result<Response<CertificateResponse>, Status> {
        debug!("Received certificate request: {:?}", request);
        let request = request.into_inner();

        // If something happens with the timestamp, we go with worst case scenario:
        // Client timestamp issues - Assume it was sent at time 0
        // Host timestamp issues   - Assume it's about 292 billion years from now
        let client_timestamp = &request.challenge_time.parse::<u64>().unwrap_or(0);
        let current_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(ts) => ts.as_secs(),
            Err(_e) => 0xFFFFFFFFFFFFFFFF,
        };

        if (current_timestamp - client_timestamp) > 5 {
            return Ok(create_response(RusticaServerError::TimeExpired));
        }

        let hmac_verification = format!("{}-{}", client_timestamp, &request.pubkey);
        let decoded_challenge = match hex::decode(&request.challenge) {
            Ok(dc) => dc,
            Err(_) => return Ok(create_response(RusticaServerError::BadChallenge)),
        };

        if let Err(_) = hmac::verify(&self.hmac_key, hmac_verification.as_bytes(), &decoded_challenge) {
           return Ok(create_response(RusticaServerError::BadChallenge));
        }

        // Verification of the integrity of the request is now done, we can
        // parse the rest of the request knowing it has not been replayed
        // significantly in time or it's publickey tampered with since its
        // its initial request.
        let ssh_pubkey = match SSHPublicKey::from_string(&request.pubkey) {
            Ok(sshpk) => sshpk,
            Err(_) => return Ok(create_response(RusticaServerError::InvalidKey)),
        };

        let result = match &ssh_pubkey.kind {
            SSHPublicKeyKind::Ecdsa(key) => {
                let (pubkey, alg) = match key.curve.kind {
                    CurveKind::Nistp256 => (key, &ECDSA_P256_SHA256_ASN1),
                    CurveKind::Nistp384 => (key, &ECDSA_P384_SHA384_ASN1),
                    _ => return Ok(create_response(RusticaServerError::UnsupportedKeyType)),
                };

                UnparsedPublicKey::new(alg, &pubkey.key).verify(
                    &hex::decode(&request.challenge).unwrap(),
                    &hex::decode(&request.challenge_signature).unwrap(),
                )
            },
            SSHPublicKeyKind::Ed25519(key) => {
                let alg = &ED25519;
                let peer_public_key = UnparsedPublicKey::new(alg, &key.key);
                peer_public_key.verify(
                    &hex::decode(&request.challenge).unwrap(),
                    &hex::decode(&request.challenge_signature).unwrap()
                )
            },
            _ => return Ok(create_response(RusticaServerError::UnsupportedKeyType)),
        };

        if let Err(_) = result {
            return Ok(create_response(RusticaServerError::BadChallenge))
        }

        let fingerprint = ssh_pubkey.fingerprint().hash;
        let authorization = get_fingerprint_authorization(&fingerprint);

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

        // Check they have permission to create this cert type
        if (req_cert_type == CertType::User && !authorization.permissions.can_create_user_certs) ||
           (req_cert_type == CertType::Host && !authorization.permissions.can_create_host_certs) {
            return Ok(create_response(RusticaServerError::NotAuthorized));
        }

        let critical_options =
        if authorization.permissions.host_unrestricted || req_cert_type == CertType::Host {
            authorization.critical_options
        } else {
            match utils::build_force_command(&authorization.hosts) {
                Ok(cmd) => {
                    let mut co = std::collections::HashMap::new();
                    co.insert(String::from("force-command"), cmd);
                    CriticalOptions::Custom(co)
                },
                Err(_) => return Ok(create_response(RusticaServerError::Unknown)),
            }
        };

        let valid_before = std::cmp::min(
            current_timestamp + authorization.permissions.max_creation_time as u64,
            request.valid_before,
        );

        let valid_after = std::cmp::max(
            current_timestamp,
            request.valid_after,
        );

        let principals = if authorization.permissions.principal_unrestricted {
            request.principals
        } else {
            authorization.principals
        };

        let cert = Certificate::new(
            ssh_pubkey,
            req_cert_type,
            0xFEFEFEFEFEFEFEFE,
            format!("Rustica-JITC-for-{}", &fingerprint),
            principals,
            valid_after,
            valid_before,
            critical_options,
            authorization.extensions,
            ca_cert.clone(),
            signer,
        );

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

        Ok(Response::new(reply))
    }
}

fn slot_parser(slot: &str) -> Option<SlotId> {
    // If first character is R, then we need to parse the nice
    // notation
    if (slot.len() == 2 || slot.len() == 3) && slot.starts_with('R') {
        let slot_value = slot[1..].parse::<u8>();
        match slot_value {
            Ok(v) if v <= 20 => Some(SlotId::try_from(0x81_u8 + v).unwrap()),
            _ => None,
        }
    } else if let Ok(s) = SlotId::try_from(slot.to_owned()) {
        Some(s)
    } else {
        None
    }
}

fn slot_validator(slot: &str) -> Result<(), String> {
    match slot_parser(slot) {
        Some(_) => Ok(()),
        None => Err(String::from("Provided slot was not valid. Should be R1 - R20 or a raw hex identifier")),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let matches = App::new("rustica")
    .version(env!("CARGO_PKG_VERSION"))
    .author("Mitchell Grenier <mitchell@confurious.io>")
    .about("Rustica is an Yubikey backed SSHCA")
    .arg(
        Arg::new("servercert")
            .about("Path to PEM that contains server public key")
            .long("servercert")
            .short('c')
            .required(true)
            .takes_value(true),
    )
    .arg(
        Arg::new("serverkey")
            .about("Path to key that contains server private key")
            .long("serverkey")
            .short('k')
            .required(true)
            .takes_value(true),
    )
    .arg(
        Arg::new("userslot")
            .about("Slot to use for user CA")
            .default_value("R1")
            .long("userslot")
            .short('u')
            .validator(slot_validator)
            .takes_value(true),
    )
    .arg(
        Arg::new("hostslot")
            .about("Slot to use for host CA")
            .default_value("R2")
            .long("hostslot")
            .short('h')
            .validator(slot_validator)
            .takes_value(true),
    )
    .arg(
        Arg::new("listenaddress")
            .about("URI to listen on")
            .long("listen")
            .short('l')
            .takes_value(true),
    )
    .get_matches();

    let user_slot = slot_parser(matches.value_of("userslot").unwrap()).unwrap();
    let host_slot = slot_parser(matches.value_of("hostslot").unwrap()).unwrap();

    let servercert = matches.value_of("servercert").unwrap();
    let serverkey = matches.value_of("serverkey").unwrap();
    let addr = matches.value_of("listenaddress").unwrap_or("[::1]:50051").parse().unwrap();

    let servercert = tokio::fs::read(servercert).await?;
    let serverkey = tokio::fs::read(serverkey).await?;
    let identity = Identity::from_pem(servercert, serverkey);

    let user_ca_cert = ssh_cert_fetch_pubkey(user_slot);
    let host_ca_cert = ssh_cert_fetch_pubkey(host_slot);

    let (user_ca_cert, host_ca_cert) = match (user_ca_cert, host_ca_cert) {
        (Some(ucc), Some(hcc)) => (ucc, hcc),
        _ => {
            error!("Could not fetch CA public keys from YubiKey. Is it connected/configured?");
            return Ok(());
        }
    };

    let user_signer = create_signer(user_slot);
    let host_signer = create_signer(host_slot);

    println!("Starting Rustica");
    info!("User CA Pubkey: {}", user_ca_cert);
    println!("User CA Fingerprint (SHA256): {}", user_ca_cert.fingerprint().hash);

    info!("Host CA Pubkey: {}", host_ca_cert);
    println!("Host CA Fingerprint (SHA256): {}", host_ca_cert.fingerprint().hash);

    let rng = rand::SystemRandom::new();
    let hmac_key = hmac::Key::generate(hmac::HMAC_SHA256, &rng).unwrap();

    let rs = RusticaServer {
        hmac_key,
        user_ca_cert,
        host_ca_cert,
        user_ca_signer: user_signer,
        host_ca_signer: host_signer,
    };

    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))?
        .add_service(GRPCRusticaServer::new(rs))
        .serve(addr)
        .await?;

    Ok(())
}
