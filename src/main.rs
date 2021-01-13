use rustica::rustica_server::{Rustica, RusticaServer};
use rustica::{  CertificateRequest,
                CertificateResponse,
                ChallengeRequest,
                ChallengeResponse
            };


use rustica_sshkey::yubikey::{ssh_cert_fetch_pubkey, ssh_cert_signer};
use rustica_sshkey::ssh::{CertType, Certificate, PublicKey as SSHPublicKey, PublicKeyKind as SSHPublicKeyKind};

use ring::{hmac, rand};
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use std::collections::HashMap;
use std::time::SystemTime;
use tonic::{transport::Server, Request, Response, Status};
use yubikey_piv::key::{RetiredSlotId, SlotId};

pub mod rustica {
    tonic::include_proto!("rustica");
}

#[derive(Debug)]
pub struct MyRusticaServer {
    hmac_key: hmac::Key,
    user_ca_cert: SSHPublicKey,
    host_ca_cert: SSHPublicKey,
}

fn sign_user_key(buf: &[u8]) -> Option<Vec<u8>> {
    let slot = SlotId::Retired(RetiredSlotId::R11);
    ssh_cert_signer(buf, slot)
}

#[tonic::async_trait]
impl Rustica for MyRusticaServer {
    async fn challenge(
        &self,
        request: Request<ChallengeRequest>,
    ) -> Result<Response<ChallengeResponse>, Status> {
        let request = request.into_inner();
        println!("Someone wants to authenticate: {}", request.pubkey);

        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs().to_string();
        let pubkey = &request.pubkey;
        let challenge = format!("{}-{}", timestamp, pubkey);

        let tag = hmac::sign(&self.hmac_key, challenge.as_bytes());
        
        let reply = ChallengeResponse {
            time: timestamp,
            challenge: hex::encode(tag),
        };

        Ok(Response::new(reply))
    }

    async fn certificate(
        &self,
        request: Request<CertificateRequest>,
    ) -> Result<Response<CertificateResponse>, Status> {
        println!("Received certificate request: {:?}", request);
        let request = request.into_inner();
        // Zeroth Validate Time is not expired  DONE
        // First Validate Mac                   DONE
        // Second Validate Signature            DONE
        // Third Validate PubKey is authorized
        let timestamp = &request.challenge_time.parse::<u64>().unwrap_or(0);
        let current_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(ts) => ts.as_secs(),
            Err(_e) => 0xFFFFFFFFFFFFFFFF,
        };

        if (current_timestamp - timestamp) > 5 {
            return Ok(Response::new(CertificateResponse {
                certificate: String::new(),
                error: String::from("Time Expired"),
                error_code: -1,
            }));
        }

        let hmac_verification = format!("{}-{}", timestamp, &request.pubkey);
        let decoded_challenge = match hex::decode(&request.challenge) {
            Ok(dc) => dc,
            Err(_) => {
                return Ok(Response::new(CertificateResponse {
                    certificate: String::new(),
                    error: String::from("Bad Challenge Encoding"),
                    error_code: -2,
                }));
            },
        };

        match hmac::verify(&self.hmac_key, hmac_verification.as_bytes(), &decoded_challenge) {
            Ok(_) => (),
            Err(_) => {
                return Ok(Response::new(CertificateResponse {
                    certificate: String::new(),
                    error: String::from("Bad Challenge"),
                    error_code: -3,
                }));
            }
        };

        let ssh_pubkey = match SSHPublicKey::from_string(&request.pubkey) {
            Ok(sshpk) => sshpk,
            Err(_) => {
                return Ok(Response::new(CertificateResponse {
                    certificate: String::new(),
                    error: String::from("Invalid Key"),
                    error_code: -4,
                }));
            },
        };

        let pubkey = match &ssh_pubkey.kind {
            SSHPublicKeyKind::Ecdsa(key) => key,
           _ => panic!("Bad Key"),
        };

        let result = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &pubkey.key).verify(&hex::decode(&request.challenge).unwrap(), &hex::decode(&request.challenge_signature).unwrap());
        match result {
            Ok(()) => (),
            Err(_) => return Ok(Response::new(CertificateResponse {
                certificate: String::new(),
                error: String::from("Bad Challenge"),
                error_code: -5,
            })),
        }

        /*
        if pubkey.key != vec![0x04, 0xE0, 0x7B, 0x2A, 0x40, 0x89, 0x5B, 0xC0, 0xB9, 0xA0, 0x60, 0x8F, 0x6B, 0xDD, 0xF6, 0x0B, 0x85, 0x34, 0x5F, 0x89, 0xE3, 0xC0, 0xFE, 0x6C, 0xAB, 0x4D, 0xE9, 0x3B, 0x11, 0x06, 0xBE, 0xA3, 0xC1, 0xD5, 0xD7, 0x03, 0x56, 0x1E, 0x84, 0x1C, 0x2B, 0x9F, 0x28, 0x35, 0x38, 0x69, 0x34, 0xFE, 0xF3, 0x73, 0xB7, 0xC5, 0xFF, 0x4A, 0x81, 0xE4, 0x0F, 0x7D, 0x3D, 0x7D, 0x24, 0xFA, 0xF7, 0x00, 0x3D] {
            return Ok(Response::new(CertificateResponse {
                certificate: String::new(),
                error: String::from("Bad Public Key"),
                error_code: -6,
            }))
        }
        */

        let user_cert = Certificate::new(
            ssh_pubkey,
            CertType::User,
            0xFEFEFEFEFEFEFEFE,
            request.key_id,
            request.principals,
            current_timestamp,
            current_timestamp + 10,
            request.critical_options,
            request.extensions,
            self.user_ca_cert.clone(),
            sign_user_key,
        );
    
        let serialized_cert = match user_cert {
            Ok(cert) => {
                let serialized = format!("{}", cert);
                if let Err(e) = Certificate::from_string(&serialized) {
                    println!("Couldn't deserialize certificate: {}", e);
                    return Ok(Response::new(CertificateResponse {
                        certificate: String::new(),
                        error: String::from("Bad Options For Cert Creation"),
                        error_code: -5,
                    }))
                }
                serialized
            },
            Err(_) => {
                return Ok(Response::new(CertificateResponse {
                    certificate: String::new(),
                    error: String::from("Bad Challenge"),
                    error_code: -6,
                }))
            },
        };
    

        let reply = CertificateResponse {
            certificate: serialized_cert,
            error: String::from(""),
            error_code: 0,
        };

        Ok(Response::new(reply))
    }
}

impl MyRusticaServer {
    pub fn new(user_ca_cert: SSHPublicKey, host_ca_cert: SSHPublicKey) -> MyRusticaServer {
        let rng = rand::SystemRandom::new();
        let hmac_key = hmac::Key::generate(hmac::HMAC_SHA256, &rng).unwrap();
        MyRusticaServer {
            hmac_key,
            user_ca_cert,
            host_ca_cert,
        }
    }
}

#[tokio::main]
async fn main() {
    println!("Starting Rustica...");
    let user_ca_cert = match ssh_cert_fetch_pubkey(SlotId::Retired(RetiredSlotId::R11)) {
        Some(ca_cert) => ca_cert,
        None => {
            println!("Could not fetch user CA public key from YubiKey. Is it configured?");
            return;
        },
    };

    // Eventually this will be stored in another slot but for now, it's fine to keep
    // the same for each
    let host_ca_cert = match ssh_cert_fetch_pubkey(SlotId::Retired(RetiredSlotId::R11)) {
        Some(ca_cert) => ca_cert,
        None => {
            println!("Could not fetch host CA public key from YubiKey. Is it configured?");
            return;
        },
    };

    println!("User CA Pubkey: {}", user_ca_cert);
    println!("User CA Fingerprint (SHA256): {}\n", user_ca_cert.fingerprint().hash);

    println!("Host CA Pubkey: {}", host_ca_cert);
    println!("Host CA Fingerprint (SHA256): {}\n", host_ca_cert.fingerprint().hash);

    let addr = "[::1]:50051".parse().unwrap();
    let rs = MyRusticaServer::new(user_ca_cert, host_ca_cert);

    Server::builder()
        .add_service(RusticaServer::new(rs))
        .serve(addr)
        .await.unwrap();
}