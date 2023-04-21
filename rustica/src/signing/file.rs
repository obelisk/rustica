use rcgen::{Certificate as X509Certificate, CertificateParams, DnType, IsCa};
use serde::Deserialize;
/// The file signer uses private keys stored inside the Rustica
/// configuration to sign certificate requests. This is currently the only
/// signer which is present regardless of the features enabled at build
/// time. It supports Ecdsa256, Ecdsa384, and Ed25519.
use sshcerts::{ssh::CertType, Certificate, PrivateKey, PublicKey};

use super::{Signer, SignerConfig, SigningError};

use async_trait::async_trait;

#[derive(Deserialize)]
pub struct Config {
    /// The private key used to sign user certificates
    #[serde(deserialize_with = "parse_private_key")]
    user_key: PrivateKey,
    /// The private key used to sign host certificates
    #[serde(deserialize_with = "parse_private_key")]
    host_key: PrivateKey,
    /// X509 base64 encoded private key that will be used to issue client
    /// certificates
    x509_private_key: String,
    /// X509 private key type to use, either ECDSA 256 or ECDSA 384.
    /// This should be one of p256 or p384
    x509_private_key_alg: String,
}

pub struct FileSigner {
    /// The private key used to sign user certificates
    user_key: PrivateKey,
    /// The private key used to sign host certificates
    host_key: PrivateKey,
    /// The public portion of the key that will be used to sign X509
    /// certificates
    x509_certificate: X509Certificate,
}

#[async_trait]
impl Signer for FileSigner {
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

    fn get_x509_certificate_authority(&self) -> &rcgen::Certificate {
        &self.x509_certificate
    }
}

#[async_trait]
impl SignerConfig for Config {
    async fn into_signer(self) -> Result<Box<dyn Signer + Send + Sync>, SigningError> {
        let mut ca_params = CertificateParams::new(vec![]);
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Rustica");

        let key_bytes =
            base64::decode(&self.x509_private_key).map_err(|_| SigningError::ParsingError)?;

        let kp = rcgen::KeyPair::from_der(&key_bytes).map_err(|_| SigningError::ParsingError)?;
        ca_params.alg = match self.x509_private_key_alg.as_str() {
            "p256" => &rcgen::PKCS_ECDSA_P256_SHA256,
            "p384" => &rcgen::PKCS_ECDSA_P384_SHA384,
            _ => return Err(SigningError::ParsingError),
        };

        ca_params.key_pair = Some(kp);
        let x509_certificate =
            X509Certificate::from_params(ca_params).map_err(|_| SigningError::SigningFailure)?;

        Ok(Box::new(FileSigner {
            user_key: self.user_key,
            host_key: self.host_key,
            x509_certificate,
        }))
    }
}

fn parse_private_key<'de, D>(deserializer: D) -> Result<PrivateKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let key = String::deserialize(deserializer)?;
    match PrivateKey::from_string(&key) {
        Ok(key) => Ok(key),
        Err(e) => Err(serde::de::Error::custom(e.to_string())),
    }
}
