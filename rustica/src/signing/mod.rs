use std::collections::{HashMap};

/// This is the signing module of the Rustica project. The module is designed
/// to be easily extended, allowing the creation of new signing submodules with
/// minimal code changes. The interfaces are also async with access to a tokio
/// runtime (provided by the server module) so key signing occuring on remote
/// systems can be simply implemented.

use async_trait::async_trait;

use sshcerts::ssh::{CertType, Certificate, PublicKey};
use serde::Deserialize;

#[cfg(feature = "amazon-kms")]
mod amazon_kms;
mod file;
#[cfg(feature = "yubikey-support")]
mod yubikey;

#[derive(Deserialize)]
#[serde(untagged)]
pub enum SignerType {
    File(file::Config),
    #[cfg(feature = "yubikey-support")]
    Yubikey(yubikey::Config),
    #[cfg(feature = "amazon-kms")]
    AmazonKMS(amazon_kms::Config),
}

impl SignerType {
    async fn into_signer(self) -> Result<Box<dyn Signer + Send + Sync>, SigningError> {
        match self {
            Self::File(x) => x.into_signer().await,
            #[cfg(feature = "yubikey-support")]
            Self::Yubikey(x) => x.into_signer().await,
            #[cfg(feature = "amazon-kms")]
            Self::AmazonKMS(f) => f.into_signer().await,
        }
    }
}

#[async_trait]
pub trait SignerConfig {
    async fn into_signer(self) -> Result<Box<dyn Signer + Send + Sync>, SigningError>;
}

/// Any code that wants to be able to sign certificates for Rustica must implement
/// this trait. The trait is async to allow calls out to external services during
/// sign but fetching public keys must be fast and low cost.
#[async_trait]
pub trait Signer {
    /// Take in a certificate and sign it turning it into a valid certificate. This call
    /// is async allowing calls to be made over the network or to other blocking resources.
    /// This call however should execute as fast as possible and have a strict timeout as 
    /// the runtime this is executing on is the one fulfilling certificate requests from
    /// users.
    async fn sign(&self, cert: Certificate) -> Result<Certificate, SigningError>;

    /// This function is intentionally not async. This is to discourage this call being reliant
    /// on further network dependence as it is called earlier in the stack than `sign`. Creating
    /// a `Signer` from a config is async so memoization of the public key should be done in
    /// there. See the AWS signer as an example.
    fn get_signer_public_key(&self, cert_type: CertType) -> PublicKey;
}

#[derive(Deserialize)]
pub struct ExternalSigningConfig {
    pub server: String,
    pub port: String,
    pub ca: String,
    pub mtls_cert: String,
    pub mtls_key: String,
}

/// Represents the configuration of the signing module. A HashMap of strings
/// (which is the name of the authority) to a configuration struct of the
/// particular signer.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum SigningConfiguration {
    Internal(HashMap<String, SignerType>),
    External(ExternalSigningConfig)
}

/// A `SigningConfiguration` can be coerced into a `SigningMechanism` to
/// handle the signing operations as well as other convenience functions
/// such as fetching public keys or printing info about how signing is
/// configured.
pub enum SigningMechanism {
    Internal(HashMap<String, Box<dyn Signer + Send + Sync>>),
    External(ExternalSigningConfig),
}

#[derive(Debug)]
pub enum SigningError {
    /// Represents when there was an issue accessing the key material. This
    /// could occur when AmazonKMS is unreachable or a Yubikey has been
    /// disconnected during runtime.
    #[allow(dead_code)]
    AccessError(String),
    /// SigningFailure represents the private key material being unable to
    /// sign the provided certificate. This could be because of a key
    /// incompatiblity or a corrupted private key.
    SigningFailure,
    /// ParsingError represents any error that occurs from unexpected data
    /// not being able to be parsed correctly, or code that fails to parse
    /// expected data
    #[allow(dead_code)]
    ParsingError,
    UnknownAuthority,
    DuplicatedKey(String, String),
    IdenticalUserHostKey(String),
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningError::AccessError(e) => write!(f, "Could not access the private key material: {}", e),
            SigningError::SigningFailure => write!(f, "The signing operation on the provided certificate failed"),
            SigningError::ParsingError => write!(f, "The signature could not be parsed"),
            SigningError::UnknownAuthority => write!(f, "Unknown authority was requested for signing or public key"),
            SigningError::DuplicatedKey(a1, a2) => write!(f, "Authorities {a1} and {a2} share at least one key. This is not allowed as it almost always a misconfiguration leading to access that is not correctly restricted"),
            SigningError::IdenticalUserHostKey(authority) => write!(f, "Authority {authority} has an identical key for both user and host certificates. This is not allowed as it's much safer to use separate keys for both."),
        }
    }
}

impl std::fmt::Display for SigningMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut output = String::new();
        match self {
            SigningMechanism::Internal(authorities) => 
                for signer in authorities.iter() {
                    output.push_str(&format!("Authority: {}\n", signer.0));
                    output.push_str(&format!("\tUser CA Fingerprint (SHA256): {}\n", signer.1.get_signer_public_key(CertType::User).fingerprint().hash));
                    output.push_str(&format!("\tHost CA Fingerprint (SHA256): {}\n", signer.1.get_signer_public_key(CertType::Host).fingerprint().hash));
                }
            SigningMechanism::External(_) => panic!("Still need to impl"),
        };
        write!(f, "{}", output)
    }
}

impl SigningMechanism {
    /// Takes in a certificate and handles the getting a signature from the 
    /// configured SigningMechanism.
    pub async fn sign(&self, authority: &str, cert: Certificate) -> Result<Certificate, SigningError> {
        match self {
            SigningMechanism::Internal(authorities) => 
                if let Some(authority) = authorities.get(authority) {
                    authority.sign(cert).await
                } else {
                    Err(SigningError::UnknownAuthority)
                }
            SigningMechanism::External(_) => panic!("Still need to impl"),
        }
    }

    /// Return an sshcerts::PublicKey type for the signing key asked for,
    /// either User or Host
    pub fn get_signer_public_key(&self, authority: &str, cert_type: CertType) -> Result<PublicKey, SigningError> {
        match self {
            SigningMechanism::Internal(authorities) => 
                if let Some(authority) = authorities.get(authority) {
                    Ok(authority.get_signer_public_key(cert_type))
                } else {
                    Err(SigningError::UnknownAuthority)
                }
            SigningMechanism::External(_) => panic!("Still need to impl"),
        }
    }
}

impl SigningConfiguration {
    pub async fn convert_to_signing_mechanism(self) -> Result<SigningMechanism, SigningError> {
        match self {
            SigningConfiguration::Internal(authorities) => {
                let mut converted_authorities = HashMap::new();
                let mut public_keys: HashMap<String, String> = HashMap::new();
                for authority in authorities.into_iter() {
                    let signer = authority.1.into_signer().await?;
                    let user_hash = signer.get_signer_public_key(CertType::User).fingerprint().hash;
                    let host_hash = signer.get_signer_public_key(CertType::Host).fingerprint().hash;
        
                    if user_hash == host_hash {
                        return Err(SigningError::IdenticalUserHostKey(authority.0));
                    }
        
                    if let Some(existing) = public_keys.get(&user_hash) {
                        return Err(SigningError::DuplicatedKey(authority.0, existing.to_owned()));
                    }
        
                    if let Some(existing) = public_keys.get(&host_hash) {
                        return Err(SigningError::DuplicatedKey(authority.0, existing.to_owned()));
                    }
        
                    public_keys.insert(user_hash, authority.0.to_owned());
                    public_keys.insert(host_hash, authority.0.to_owned());
                    converted_authorities.insert(authority.0, signer);
                }
        
                Ok(SigningMechanism::Internal(converted_authorities))
            },
            SigningConfiguration::External(e) => Ok(SigningMechanism::External(e)),
        }

    }
}
