use sshcerts::ssh::{CertType, PublicKey, SigningFunction};
use serde::Deserialize;
use std::convert::TryInto;

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
    pub amazonkms: Option<amazon_kms::AmazonKMSSigner>,
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
}

impl SigningMechanism {
    pub fn get_signer(&self, cert_type: CertType) -> SigningFunction {
        match self {
            SigningMechanism::File(file) => file.get_signer(cert_type),
            #[cfg(feature = "yubikey-support")]
            SigningMechanism::Yubikey(yubikey) => yubikey.get_signer(cert_type),
            #[cfg(feature = "amazon-kms")]
            SigningMechanism::AmazonKMS(amazonkms) => amazonkms.get_signer(cert_type),
        }
    }

    pub async fn get_signer_public_key(&self, cert_type: CertType) -> Result<PublicKey, SigningError> {
        match self {
            SigningMechanism::File(file) => Ok(file.get_signer_public_key(cert_type)),
            #[cfg(feature = "yubikey-support")]
            SigningMechanism::Yubikey(yubikey) => yubikey.get_signer_public_key(cert_type),
            #[cfg(feature = "amazon-kms")]
            SigningMechanism::AmazonKMS(amazonkms) => Ok(amazonkms.get_signer_public_key(cert_type).await),
        }
    }
}

impl TryInto<SigningMechanism> for SigningConfiguration {
    type Error = ();
    fn try_into(self) -> Result<SigningMechanism, ()> {
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
                Some(amazonkms) => Some(SigningMechanism::AmazonKMS(amazonkms)),
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
