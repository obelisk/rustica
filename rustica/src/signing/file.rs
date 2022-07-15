use sshcerts::{Certificate, PublicKey, PrivateKey, ssh::CertType};
use serde::Deserialize;

use super::{Signer, SigningError};

use async_trait::async_trait;

#[derive(Deserialize)]
pub struct Config {
    /// The private key used to sign user certificates
    #[serde(deserialize_with = "parse_private_key")]
    user_key: PrivateKey,
    /// The private key used to sign host certificates
    #[serde(deserialize_with = "parse_private_key")]
    host_key: PrivateKey,
}

pub struct FileSigner {
    /// The private key used to sign user certificates
    user_key: PrivateKey,
    /// The private key used to sign host certificates
    host_key: PrivateKey,
}

#[async_trait]
impl Signer<Config> for FileSigner {
    async fn new(config: Config) -> Result<Box<Self>, SigningError> {
        Ok(Box::new(Self {
            user_key: config.user_key,
            host_key: config.host_key,
        }))
    }

    async fn sign(&self, cert: Certificate) -> Result<Certificate, SigningError> {
        let final_cert = match cert.cert_type {
            CertType::User => cert.sign(&self.user_key),
            CertType::Host => cert.sign(&self.host_key),
        };

        final_cert.map_err(|_| SigningError::SigningFailure)
    }

    fn get_signer_public_key(&self, cert_type: CertType) -> PublicKey {
        match cert_type {
            CertType::User => self.user_key.pubkey.clone(),
            CertType::Host => self.host_key.pubkey.clone(),
        }
    }
}

fn parse_private_key<'de, D>(deserializer: D) -> Result<PrivateKey, D::Error>
where
    D: serde::Deserializer<'de>
{
    let key = String::deserialize(deserializer)?;
    match PrivateKey::from_string(&key) {
        Ok(key) => Ok(key),
        Err(e) => Err(serde::de::Error::custom(e.to_string()))
    }
}