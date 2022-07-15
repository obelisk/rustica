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


/// Any code that wants to be able to sign certificates for Rustica must implement
/// this trait. The trait is async to allow calls out to external services during
/// sign but fetching public keys must be fast and low cost.
#[async_trait]
trait Signer<T> {
    /// When configuring a signer from its config, network and blocking calls are allowed.
    /// This allows calls to be made to external services to verify they are able to fulfil
    /// signing requests as well as to cache the public keys returned from
    /// `get_signer_public_key`.
    async fn new(config: T) -> Result<Box<Self>, SigningError>;

    /// Take in a certificate and sign it turning it into a valid certificate. This call
    /// is async allowing calls to be made over the network or to other blocking resources.
    /// This call however should execute as fast as possible and have a strict timeout as 
    /// the runtime this is executing on is the one fulfilling certificate requests from
    /// users.
    async fn sign(&self, cert: Certificate) -> Result<Certificate, SigningError>;

    /// This function is not async intentionally. This is to discourage this call being reliant
    /// on further network calls because it can be hit earlier in the stack than `sign`. Creating
    /// a `Signer` is async so memoization of the public key should be done in there. See the
    /// AWS signer as an example.
    fn get_signer_public_key(&self, cert_type: CertType) -> PublicKey;
}

/// Represents the configuration of the signing module. Fields that introduce
/// new dependencies are gated by features to help reduce final binary size as
/// well as reducing attack surface.
#[derive(Deserialize)]
pub struct SigningConfiguration {
    /// The file signer uses private keys stored inside the Rustica
    /// configuration to sign certificate requests. This is currently the only
    /// signer which is present regardless of the features enabled at build
    /// time. It supports Ecdsa256, Ecdsa384, and Ed25519.
    pub file: Option<file::Config>,
    /// The Yubikey signer uses a connected Yubikey 4/5 to sign requests. It
    /// currently only supports Ecdsa256 and Ecdsa384. To use the Yubikey
    /// signer, the `yubikey-support` feature must be enabled.
    #[cfg(feature = "yubikey-support")]
    pub yubikey: Option<yubikey::Config>,
    /// The AmazonKMS signer uses customer managed keys stored in AWS to handle
    /// signing operations. It supports Ecdsa256 and Ecdsa384. Ecdsa521 is not
    /// currently supported due to a lack of support in the Ring crypto
    /// dependency. This signer is also an example of how to write a signing
    /// module that is async. To use the AmazonKMS signer, the `amazon-kms`
    /// feature must be enabled.
    #[cfg(feature = "amazon-kms")]
    pub amazonkms: Option<amazon_kms::Config>,
}

/// A `SigningConfiguration` can be coerced into a `SigningMechanism` to
/// handle the signing operations as well as other convenience functions
/// such as fetching public keys or printing info about how signing is
/// configured.
pub enum SigningMechanism {
    /// The file configuration converted into a SigningMechanism
    File(file::FileSigner),
    /// The Yubikey configuration converted into a SigningMechanism
    #[cfg(feature = "yubikey-support")]
    Yubikey(yubikey::YubikeySigner),
    /// The AmazonKMS configuration converted into a SigningMechanism
    #[cfg(feature = "amazon-kms")]
    AmazonKMS(amazon_kms::AmazonKMSSigner),
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
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningError::AccessError(e) => write!(f, "Could not access the private key material: {}", e),
            SigningError::SigningFailure => write!(f, "The signing operation on the provided certificate failed"),
            SigningError::ParsingError => write!(f, "The signature could not be parsed"),
        }
    }
}

impl SigningMechanism {
    /// Takes in a certificate and handles the getting a signature from the 
    /// configured SigningMechanism.
    pub async fn sign(&self, cert: Certificate) -> Result<Certificate, SigningError> {
        match self {
            SigningMechanism::File(file) => file.sign(cert).await,
            #[cfg(feature = "yubikey-support")]
            SigningMechanism::Yubikey(yubikey) => yubikey.sign(cert).await,
            #[cfg(feature = "amazon-kms")]
            SigningMechanism::AmazonKMS(amazonkms) => amazonkms.sign(cert).await,
        }
    }

    /// Return an sshcerts::PublicKey type for the signing key asked for,
    /// either User or Host
    pub fn get_signer_public_key(&self, cert_type: CertType) -> PublicKey {
        match self {
            SigningMechanism::File(file) => file.get_signer_public_key(cert_type),
            #[cfg(feature = "yubikey-support")]
            SigningMechanism::Yubikey(yubikey) => yubikey.get_signer_public_key(cert_type),
            #[cfg(feature = "amazon-kms")]
            SigningMechanism::AmazonKMS(amazonkms) => amazonkms.get_signer_public_key(cert_type),
        }
    }

    /// Print out information about the current configuration of the signing
    /// system. This is generally only called once from main before starting
    /// the main Rustica server.
    pub fn print_signing_info(&self) {
        match self {
            SigningMechanism::File(file) => {
                println!("User CA Fingerprint (SHA256): {}", file.get_signer_public_key(CertType::User).fingerprint().hash);
                println!("Host CA Fingerprint (SHA256): {}", file.get_signer_public_key(CertType::Host).fingerprint().hash);
                println!("Configured signer: file");
            },
            #[cfg(feature = "yubikey-support")]
            SigningMechanism::Yubikey(yubikey) => {
                println!("User CA Fingerprint (SHA256): {}", yubikey.get_signer_public_key(CertType::User).fingerprint().hash);
                println!("Host CA Fingerprint (SHA256): {}", yubikey.get_signer_public_key(CertType::Host).fingerprint().hash);
                println!("Configured signer: yubikey");
            },
            #[cfg(feature = "amazon-kms")]
            SigningMechanism::AmazonKMS(amazonkms) => {
                println!("User CA Fingerprint (SHA256): {}", amazonkms.get_signer_public_key(CertType::User).fingerprint().hash);
                println!("Host CA Fingerprint (SHA256): {}", amazonkms.get_signer_public_key(CertType::Host).fingerprint().hash);
                println!("Configured signer: amazon-kms");
            },
        }
    }
}

impl SigningConfiguration {
    /// Convert the `SigningConfiguration` into a `SigningMechanism` by calling
    /// the appropriate initalizers then wrapping the returned object in the
    /// `SigningMechanism` enum varient.
    pub async fn convert_to_signing_mechanism(self) -> Result<SigningMechanism, ()> {
        // Try and create a file based SigningMechanism
        let file_sm = 
        match self.file {
            Some(config) => {
                if let Ok(f) = file::FileSigner::new(config).await {
                    Some(SigningMechanism::File(*f))
                } else {
                    None
                }
            },
            _ => None,
        };

        // Try and create a yubikey based SigningMechanism
        let yubikey_sm = {
            #[cfg(feature = "yubikey-support")]
            match self.yubikey {
                Some(config) => {
                    if let Ok(yk) = yubikey::YubikeySigner::new(config).await {
                        Some(SigningMechanism::Yubikey(*yk))
                    } else {
                        None
                    }
                },
                _ => None,
            }
            #[cfg(not(feature = "yubikey-support"))]
            None
        };

        // Try and create a AmazonKMS based SigningMechanism
        let amazonkms_sm = {
            #[cfg(feature = "amazon-kms")]
            match self.amazonkms {
                Some(config) => {
                    if let Ok(amazonkms) = amazon_kms::AmazonKMSSigner::new(config).await {
                        Some(SigningMechanism::AmazonKMS(*amazonkms))
                    } else {
                        None
                    }
                },
                _ => None,
            }
            #[cfg(not(feature = "amazon-kms"))]
            None
        };

        // If a feature is not enabled, that type will always be None here
        // making it easy to check that no two signing systems have been
        // accidentally configured causing ambiguity on which should be used
        match (file_sm, yubikey_sm, amazonkms_sm) {
            (Some(file), None, None) => Ok(file),
            (None, Some(yubikey), None) => Ok(yubikey),
            (None, None, Some(amazonkms)) => Ok(amazonkms),
            _ => Err(()),
        }
    }
}
