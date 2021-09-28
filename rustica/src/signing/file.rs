use sshcerts::{Certificate, PublicKey, PrivateKey, ssh::CertType, ssh::SigningFunction};
use serde::Deserialize;

use super::{FileSigner, SigningError};

impl FileSigner {
    pub fn get_signer(&self, cert_type: CertType) -> SigningFunction {
        match cert_type {
            CertType::User => self.user_key.clone().into(),
            CertType::Host => self.host_key.clone().into(),
        }
    }

    pub fn get_signer_public_key(&self, cert_type: CertType) -> PublicKey {
        match cert_type {
            CertType::User => self.user_key.pubkey.clone(),
            CertType::Host => self.host_key.pubkey.clone(),
        }
    }

    pub fn parse_private_key<'de, D>(deserializer: D) -> Result<PrivateKey, D::Error>
    where
        D: serde::Deserializer<'de>
    {
        let key = String::deserialize(deserializer)?;
        match PrivateKey::from_string(&key) {
            Ok(key) => Ok(key),
            Err(e) => Err(serde::de::Error::custom(e.to_string()))
        }
    }
}