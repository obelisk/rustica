use super::error::{RefreshError, ServerError};

use rustica::rustica_client::{RusticaClient};
use rustica::{CertificateRequest, ChallengeRequest};

use sshcerts::ssh::{CertType, CriticalOptions, CurveKind, Extensions, PrivateKey, PublicKeyKind, PrivateKeyKind};
use sshcerts::yubikey::{sign_data, ssh::{ssh_cert_fetch_pubkey, get_ssh_key_type}};

use ring::{rand, signature};
use std::collections::HashMap;
use std::time::SystemTime;
use tokio::runtime::Runtime;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use yubikey_piv::key::SlotId;

pub mod rustica {
    tonic::include_proto!("rustica");
}

pub struct RusticaCert {
    pub cert: String,
    pub comment: String,
}

#[derive(Debug)]
pub enum Signatory {
    Yubikey(SlotId),
    Direct(PrivateKey),
}

#[derive(Debug)]
pub struct RusticaServer {
    pub address: String,
    pub ca: String,
    pub mtls_cert: String,
    pub mtls_key: String,
}

#[derive(Debug)]
pub struct CertificateConfig {
    pub principals: Vec<String>,
    pub hosts: Vec<String>,
    pub cert_type: CertType,
    pub duration: u64,
}

pub async fn refresh_certificate_async(server: &RusticaServer, signatory: &Signatory, options: &CertificateConfig) -> Result<RusticaCert, RefreshError> {
    let ssh_pubkey = match signatory {
        Signatory::Yubikey(user_key_slot) => ssh_cert_fetch_pubkey(*user_key_slot).unwrap(),
        Signatory::Direct(ref privkey) => privkey.pubkey.clone(),
    };
    
    let encoded_key = format!("{}", ssh_pubkey);
    debug!("Requesting cert for key with fingerprint: {}", ssh_pubkey.fingerprint());
    let request = tonic::Request::new(ChallengeRequest {
        pubkey: encoded_key.to_string(),
    });

    let client_identity = Identity::from_pem(&server.mtls_cert, &server.mtls_key);

    let channel = match Channel::from_shared(server.address.clone()) {
        Ok(c) => c,
        Err(_) => return Err(RefreshError::InvalidURI),
    };

    let ca = Certificate::from_pem(&server.ca);
    let tls = ClientTlsConfig::new().ca_certificate(ca).identity(client_identity);
    let channel = channel.tls_config(tls)?.connect().await?;

    let mut client = RusticaClient::new(channel);
    let response = client.challenge(request).await?;

    let response = response.into_inner();
    let decoded_challenge = hex::decode(&response.challenge)?;

    let challenge_signature = match signatory {
        Signatory::Yubikey(user_key_slot) => {
            let alg = match get_ssh_key_type(*user_key_slot){
                Some(alg) => alg,
                None => return Err(RefreshError::SigningError),
            };

            match sign_data(&decoded_challenge, alg, *user_key_slot) {
                Ok(v) => hex::encode(v),
                Err(_) => {
                    return Err(RefreshError::SigningError);
                }
            }
        },
        Signatory::Direct(privkey) => {
            let rng = rand::SystemRandom::new();

            match &privkey.kind {
                PrivateKeyKind::Rsa(_) => return Err(RefreshError::UnsupportedMode),
                PrivateKeyKind::Ecdsa(key) => {
                    let alg = match key.curve.kind {
                        CurveKind::Nistp256 => &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                        CurveKind::Nistp384 => &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                        CurveKind::Nistp521 => return Err(RefreshError::UnsupportedMode),
                    };

                    let pubkey = match &privkey.pubkey.kind {
                        PublicKeyKind::Ecdsa(key) => &key.key,
                        _ => return Err(RefreshError::UnsupportedMode),
                    };

                    let key = if key.key[0] == 0x0_u8 {&key.key[1..]} else {&key.key};
                    let key_pair = signature::EcdsaKeyPair::from_private_key_and_public_key(alg, &key, &pubkey).unwrap();

                    hex::encode(key_pair.sign(&rng, &decoded_challenge).unwrap())
                },
                PrivateKeyKind::Ed25519(key) => {
                    let public_key = match &privkey.pubkey.kind {
                        PublicKeyKind::Ed25519(key) => &key.key,
                        _ => return Err(RefreshError::UnsupportedMode),
                    };

                    let key_pair = match signature::Ed25519KeyPair::from_seed_and_public_key(&key.key[..32], public_key) {
                        Ok(kp) => kp,
                        Err(_) => return Err(RefreshError::SigningError),
                    };

                    hex::encode(key_pair.sign(&decoded_challenge))
                },
            }
        },
    };
    let current_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(ts) => ts.as_secs(),
        Err(_e) => 0xFFFFFFFFFFFFFFFF,
    };

    let request = tonic::Request::new(CertificateRequest {
        pubkey: encoded_key.to_string(),
        cert_type: options.cert_type as u32,
        key_id: String::from(""),           // Rustica Server ignores this field
        challenge_time: response.time,
        critical_options: HashMap::from(CriticalOptions::None),
        extensions: HashMap::from(Extensions::Standard),
        servers: options.hosts.clone(),
        principals: options.principals.clone(),
        valid_before: current_timestamp + options.duration,
        valid_after: 0x0,
        challenge: response.challenge,
        challenge_signature,
    });

    let response = client.certificate(request).await?;
    let response = response.into_inner();

    if response.error_code != 0 {
        return Err(RefreshError::RusticaServerError(
            ServerError {
                code: response.error_code,
                message: response.error,
            }))
    }

    Ok(RusticaCert {
        cert: response.certificate,
        comment: "JITC".to_string(),
    })
}

pub fn get_custom_certificate(server: &RusticaServer, signatory: &Signatory, options: &CertificateConfig) -> Result<RusticaCert, RefreshError> {
    Runtime::new().unwrap().block_on(async {
        refresh_certificate_async(server, signatory, options).await
    })
}