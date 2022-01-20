use sshcerts::ssh::{CertType, Certificate, PublicKey};
use serde::Deserialize;

#[cfg(feature = "amazon-kms")]
mod amazon_kms;
mod file;
#[cfg(feature = "yubikey-support")]
mod yubikey;


#[derive(Deserialize)]
pub struct SigningConfiguration {
    pub file: Option<file::FileSigner>,
    #[cfg(feature = "yubikey-support")]
    pub yubikey: Option<yubikey::YubikeySigner>,
    #[cfg(feature = "amazon-kms")]
    pub amazonkms: Option<amazon_kms::Config>,
}

pub enum SigningMechanism {
    File(file::FileSigner),
    #[cfg(feature = "yubikey-support")]
    Yubikey(yubikey::YubikeySigner),
    #[cfg(feature = "amazon-kms")]
    AmazonKMS(amazon_kms::AmazonKMSSigner),
}

#[derive(Debug)]
pub enum SigningError {
    #[allow(dead_code)]
    AccessError(String),
    SigningFailure,
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningError::AccessError(e) => write!(f, "Could access the private key material: {}", e),
            SigningError::SigningFailure => write!(f, "The signing operation on the provided certificate failed"),
        }
    }
}

impl SigningMechanism {
    pub async fn sign_certificate(&self, cert: Certificate) -> Result<Certificate, SigningError> {
        match self {
            SigningMechanism::File(file) => {
                let signer = file.get_signer(cert.cert_type);
                match cert.sign(signer) {
                    Ok(c) => Ok(c),
                    Err(_) => Err(SigningError::SigningFailure)
                }
            },
            #[cfg(feature = "yubikey-support")]
            SigningMechanism::Yubikey(yubikey) => {
                let signer = yubikey.get_signer(cert.cert_type);
                match cert.sign(signer) {
                    Ok(c) => Ok(c),
                    Err(_) => Err(SigningError::SigningFailure)
                }
            },
            #[cfg(feature = "amazon-kms")]
            SigningMechanism::AmazonKMS(amazonkms) => {
                amazonkms.sign_certificate(cert).await
            },
        }
    }

    pub fn get_signer_public_key(&self, cert_type: CertType) -> Result<PublicKey, SigningError> {
        match self {
            SigningMechanism::File(file) => Ok(file.get_signer_public_key(cert_type)),
            #[cfg(feature = "yubikey-support")]
            SigningMechanism::Yubikey(yubikey) => yubikey.get_signer_public_key(cert_type),
            #[cfg(feature = "amazon-kms")]
            SigningMechanism::AmazonKMS(amazonkms) => Ok(amazonkms.get_signer_public_key(cert_type)),
        }
    }

    pub fn print_signing_info(&self) {
        match self {
            SigningMechanism::File(file) => {
                println!("User CA Fingerprint (SHA256): {}", file.get_signer_public_key(CertType::User).fingerprint().hash);
                println!("Host CA Fingerprint (SHA256): {}", file.get_signer_public_key(CertType::Host).fingerprint().hash);
                println!("Configured signer: file");
            },
            #[cfg(feature = "yubikey-support")]
            SigningMechanism::Yubikey(yubikey) => {
                println!("User CA Fingerprint (SHA256): {}", yubikey.get_signer_public_key(CertType::User).unwrap().fingerprint().hash);
                println!("Host CA Fingerprint (SHA256): {}", yubikey.get_signer_public_key(CertType::Host).unwrap().fingerprint().hash);
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
    pub async fn convert_to_signing_mechanism(self) -> Result<SigningMechanism, ()> {
        // Try and create a file based SigningMechanism
        let file_sm = match self.file {
            Some(file) => Some(SigningMechanism::File(file)),
            _ => None,
        };

        // Try and create a yubikey based SigningMechanism
        let yubikey_sm = {
            #[cfg(feature = "yubikey-support")]
            match self.yubikey {
                Some(yubikey) => Some(SigningMechanism::Yubikey(yubikey)),
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
                        Some(SigningMechanism::AmazonKMS(amazonkms))
                    } else {
                        None
                    }
                },
                _ => None,
            }
            #[cfg(not(feature = "amazon-kms"))]
            None
        };

        match (file_sm, yubikey_sm, amazonkms_sm) {
            (Some(file), None, None) => Ok(file),
            (None, Some(yubikey), None) => Ok(yubikey),
            (None, None, Some(amazonkms)) => Ok(amazonkms),
            _ => return Err(()),
        }
    }
}
