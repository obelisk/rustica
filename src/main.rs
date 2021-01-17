#[macro_use]
extern crate log;

#[macro_use]
extern crate diesel;
extern crate dotenv;

mod database;

use database::get_fingerprint_authorization;

use rustica::rustica_server::{Rustica, RusticaServer as GRPCRusticaServer};
use rustica::{CertificateRequest, CertificateResponse, ChallengeRequest, ChallengeResponse};

use rustica_keys::ssh::{
    CertType, Certificate, CurveKind, CriticalOptions, PublicKey as SSHPublicKey, PublicKeyKind as SSHPublicKeyKind,
};
use rustica_keys::yubikey::ssh::{ssh_cert_fetch_pubkey, ssh_cert_signer};

use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1};
use ring::{hmac, rand};
use ring::rand::SecureRandom;
use std::time::SystemTime;
use tonic::{transport::Server, Request, Response, Status};
use yubikey_piv::key::{RetiredSlotId, SlotId};

pub mod rustica {
    tonic::include_proto!("rustica");
}

#[derive(Debug)]
pub struct RusticaServer {
    hmac_key: hmac::Key,
    user_ca_cert: SSHPublicKey,
    host_ca_cert: SSHPublicKey,
}

#[derive(Debug)]
pub enum RusticaServerError {
    Success = 0,
    TimeExpired = 1,
    BadChallenge = 2,
    InvalidKey = 3,
    UnsupportedKeyType = 4,
    BadCertOptions = 5,
    NoAuthorizations = 6,
    Unknown = 9001,
}

fn sign_user_key(buf: &[u8]) -> Option<Vec<u8>> {
    let slot = SlotId::Retired(RetiredSlotId::R11);
    ssh_cert_signer(buf, slot)
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
            return Ok(Response::new(CertificateResponse {
                certificate: String::new(),
                error: format!("{:?}", RusticaServerError::TimeExpired),
                error_code: RusticaServerError::TimeExpired as i64,
            }));
        }

        let hmac_verification = format!("{}-{}", client_timestamp, &request.pubkey);
        let decoded_challenge = match hex::decode(&request.challenge) {
            Ok(dc) => dc,
            Err(_) => {
                return Ok(Response::new(CertificateResponse {
                    certificate: String::new(),
                    error: format!("{:?}", RusticaServerError::BadChallenge),
                    error_code: RusticaServerError::BadChallenge as i64,
                }));
            }
        };

        match hmac::verify(&self.hmac_key, hmac_verification.as_bytes(), &decoded_challenge) {
            Ok(_) => (),
            Err(_) => {
                return Ok(Response::new(CertificateResponse {
                    certificate: String::new(),
                    error: format!("{:?}", RusticaServerError::BadChallenge),
                    error_code: RusticaServerError::BadChallenge as i64,
                }));
            }
        };

        let ssh_pubkey = match SSHPublicKey::from_string(&request.pubkey) {
            Ok(sshpk) => sshpk,
            Err(_) => {
                return Ok(Response::new(CertificateResponse {
                    certificate: String::new(),
                    error: format!("{:?}", RusticaServerError::InvalidKey),
                    error_code: RusticaServerError::InvalidKey as i64,
                }));
            }
        };

        // TODO @obelisk Support Ed25519
        let (pubkey, alg) = match &ssh_pubkey.kind {
            SSHPublicKeyKind::Ecdsa(key) => {
                match key.curve.kind {
                    CurveKind::Nistp256 => (key, &ECDSA_P256_SHA256_ASN1),
                    CurveKind::Nistp384 => (key, &ECDSA_P384_SHA384_ASN1),
                    _ => {
                        return Ok(Response::new(CertificateResponse {
                            certificate: String::new(),
                            error: format!("{:?}", RusticaServerError::UnsupportedKeyType),
                            error_code: RusticaServerError::UnsupportedKeyType as i64,
                        }));
                    },
                }
            },
            _ => {
                return Ok(Response::new(CertificateResponse {
                    certificate: String::new(),
                    error: format!("{:?}", RusticaServerError::UnsupportedKeyType),
                    error_code: RusticaServerError::UnsupportedKeyType as i64,
                }));
            }
        };

        let result = UnparsedPublicKey::new(alg, &pubkey.key).verify(
            &hex::decode(&request.challenge).unwrap(),
            &hex::decode(&request.challenge_signature).unwrap(),
        );

        match result {
            Ok(()) => (),
            Err(_) => {
                return Ok(Response::new(CertificateResponse {
                    certificate: String::new(),
                    error: format!("{:?}", RusticaServerError::BadChallenge),
                    error_code: RusticaServerError::BadChallenge as i64,
                }))
            }
        }

        let authorization = get_fingerprint_authorization(&ssh_pubkey.fingerprint().hash);

        if authorization.users.is_empty() {
            return Ok(Response::new(CertificateResponse {
                certificate: String::new(),
                error: format!("{:?}", RusticaServerError::NoAuthorizations),
                error_code: RusticaServerError::NoAuthorizations as i64,
            }))
        }

        if authorization.hosts.is_empty() && !authorization.unrestricted {
            return Ok(Response::new(CertificateResponse {
                certificate: String::new(),
                error: format!("{:?}", RusticaServerError::NoAuthorizations),
                error_code: RusticaServerError::NoAuthorizations as i64,
            }))
        }

        // Build our script that will force authorization to the particular servers
        // we have access to
        let mut file_rand = [0; 4];

        let rng = rand::SystemRandom::new();
        if let Err(_) = rng.fill(&mut file_rand) {
            return Ok(Response::new(CertificateResponse {
                certificate: String::new(),
                error: format!("{:?}", RusticaServerError::Unknown),
                error_code: RusticaServerError::Unknown as i64,
            }))
        }

        let critical_options = match authorization.unrestricted {
            true => authorization.critical_options,
            false => {
                let authorized_hosts = authorization.hosts.join(",");
                let file_rand = u32::from_be_bytes(file_rand);
                let mut force_command = String::new();
                force_command.push_str(&format!("export RUSTICA_AUTHORIZED_HOSTS={};", authorized_hosts));
                force_command.push_str(&format!("export LOGIN_SCRIPT=/tmp/rustica_login_{}.sh;", file_rand));
                let script = base64::encode(include_str!("../bash/verify.sh"));
                force_command.push_str(&format!("echo \"{}\" | base64 -d > $LOGIN_SCRIPT && chmod +x $LOGIN_SCRIPT && $LOGIN_SCRIPT", script));

                debug!("Force Command: {}", force_command);
                let mut co = std::collections::HashMap::new();
                co.insert(String::from("force-command"), force_command);

                CriticalOptions::Custom(co)
            }
        };

        let user_cert = Certificate::new(
            ssh_pubkey,
            CertType::User,
            0xFEFEFEFEFEFEFEFE,
            request.key_id,
            authorization.users,
            current_timestamp,
            current_timestamp + 10,
            critical_options,
            authorization.extensions,
            self.user_ca_cert.clone(),
            sign_user_key,
        );

        let serialized_cert = match user_cert {
            Ok(cert) => {
                let serialized = format!("{}", cert);

                // Sanity check that we can parse the cert we just generated
                if let Err(e) = Certificate::from_string(&serialized) {
                    error!("Couldn't deserialize certificate: {}", e);
                    return Ok(Response::new(CertificateResponse {
                        certificate: String::new(),
                        error: format!("{:?}", RusticaServerError::BadCertOptions),
                        error_code: RusticaServerError::BadCertOptions as i64,
                    }));
                }
                serialized
            }
            Err(_) => {
                return Ok(Response::new(CertificateResponse {
                    certificate: String::new(),
                    error: format!("{:?}", RusticaServerError::BadChallenge),
                    error_code: RusticaServerError::BadChallenge as i64,
                }))
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

impl RusticaServer {
    pub fn new(user_ca_cert: SSHPublicKey, host_ca_cert: SSHPublicKey) -> RusticaServer {
        let rng = rand::SystemRandom::new();
        let hmac_key = hmac::Key::generate(hmac::HMAC_SHA256, &rng).unwrap();
        RusticaServer {
            hmac_key,
            user_ca_cert,
            host_ca_cert,
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    println!("Starting Rustica");

    // These can be two different slots if you want hosts to be based on a separate
    // CA
    let user_ca_cert = ssh_cert_fetch_pubkey(SlotId::Retired(RetiredSlotId::R11));
    let host_ca_cert = ssh_cert_fetch_pubkey(SlotId::Retired(RetiredSlotId::R11));

    let (user_ca_cert, host_ca_cert) = match (user_ca_cert, host_ca_cert) {
        (Some(ucc), Some(hcc)) => (ucc, hcc),
        _ => {
            error!("Could not fetch CA public keys from YubiKey. Is it connected/configured?");
            return;
        }
    };

    info!("User CA Pubkey: {}", user_ca_cert);
    println!("User CA Fingerprint (SHA256): {}", user_ca_cert.fingerprint().hash);

    info!("Host CA Pubkey: {}", host_ca_cert);
    println!("Host CA Fingerprint (SHA256): {}", host_ca_cert.fingerprint().hash);

    let addr = "[::1]:50051".parse().unwrap();
    let rs = RusticaServer::new(user_ca_cert, host_ca_cert);

    Server::builder()
        .add_service(GRPCRusticaServer::new(rs))
        .serve(addr)
        .await
        .unwrap();
}
