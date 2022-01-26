pub mod cert;
pub mod error;
pub mod key;

pub use error::RefreshError;

pub use rustica_proto::rustica_client::{RusticaClient};
pub use rustica_proto::{
    CertificateRequest,
    CertificateResponse,
    Challenge,
    ChallengeRequest,
    RegisterKeyRequest,
};

use sshcerts::ssh::{CurveKind, PublicKeyKind, PrivateKeyKind};

use ring::{rand, signature};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use crate::{RusticaServer, Signatory};

pub mod rustica_proto {
    tonic::include_proto!("rustica");
}

pub struct RusticaCert {
    pub cert: String,
    pub comment: String,
}

pub async fn complete_rustica_challenge(server: &RusticaServer, signatory: &mut Signatory) -> Result<(RusticaClient<tonic::transport::Channel>, Challenge), RefreshError> {
    let ssh_pubkey = match signatory {
        Signatory::Yubikey(signer) => {
            signer.yk.reconnect()?;
            match signer.yk.ssh_cert_fetch_pubkey(&signer.slot) {
                Ok(pkey) => pkey,
                Err(_) => return Err(RefreshError::SigningError),
            }
        },
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
        Err(_) => return Err(RefreshError::InvalidUri),
    };

    let ca = Certificate::from_pem(&server.ca);
    let tls = ClientTlsConfig::new().ca_certificate(ca).identity(client_identity);
    let channel = channel.tls_config(tls)?.connect().await?;

    let mut client = RusticaClient::new(channel);
    let response = client.challenge(request).await?;

    let response = response.into_inner();
    let decoded_challenge = hex::decode(&response.challenge)?;

    if response.no_signature_required {
        debug!("This server does not require signatures be sent to Rustica, not signing the challenge");
        return Ok((
            client,
            Challenge {
                pubkey: encoded_key.to_string(),
                challenge_time: response.time,
                challenge: response.challenge,
                challenge_signature: String::new(),
        }))
    }

    let challenge_signature = match signatory {
        Signatory::Yubikey(signer) => {
            let alg = match signer.yk.get_ssh_key_type(&signer.slot){
                Ok(alg) => alg,
                Err(_) => return Err(RefreshError::SigningError),
            };

            hex::encode(signer.yk.sign_data(&decoded_challenge, alg, &signer.slot)?)
        },
        // TODO: @obelisk Find a way to replace this with sshcerts::ssh::signer code
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
                    let key_pair = signature::EcdsaKeyPair::from_private_key_and_public_key(alg, key, pubkey)?;

                    hex::encode(key_pair.sign(&rng, &decoded_challenge)?)
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

    Ok((
        client,
        Challenge {
            pubkey: encoded_key.to_string(),
            challenge_time: response.time,
            challenge: response.challenge,
            challenge_signature,
    }))
}