use sshcerts::ssh::{CertType, PublicKey, SigningFunction};
use serde::Deserialize;
use std::convert::TryInto;

mod file;
mod vault;
#[cfg(feature = "yubikey-support")]
mod yubikey;

#[derive(Deserialize)]
pub struct SigningConfiguration {
    pub file: Option<file::FileSigner>,
    pub vault: Option<vault::VaultSigner>,
    #[cfg(feature = "yubikey-support")]
    pub yubikey: Option<yubikey::YubikeySigner>,
}

pub enum SigningMechanism {
    File(file::FileSigner),
    Vault(vault::VaultSigner),
    #[cfg(feature = "yubikey-support")]
    Yubikey(yubikey::YubikeySigner),
}

#[derive(Debug)]
pub enum SigningError {
    AccessError(String),
}

impl SigningMechanism {
    pub fn get_signer(&self, cert_type: CertType) -> SigningFunction {
        match self {
            SigningMechanism::File(file) => file.get_signer(cert_type),
            SigningMechanism::Vault(_vault) => panic!("Unimplemented"),
            #[cfg(feature = "yubikey-support")]
            SigningMechanism::Yubikey(yubikey) => yubikey.get_signer(cert_type),
        }
    }

    pub fn get_signer_public_key(&self, cert_type: CertType) -> Result<PublicKey, SigningError> {
        match self {
            SigningMechanism::File(file) => Ok(file.get_signer_public_key(cert_type)),
            SigningMechanism::Vault(_vault) => panic!("Unimplemented"),
            #[cfg(feature = "yubikey-support")]
            SigningMechanism::Yubikey(yubikey) => yubikey.get_signer_public_key(cert_type),
        }
    }
}

impl TryInto<SigningMechanism> for SigningConfiguration {
    type Error = ();
    fn try_into(self) -> Result<SigningMechanism, ()> {
        #[cfg(feature = "yubikey-support")]
        match (self.file, self.vault, self.yubikey) {
            (Some(file), None, None) => Ok(SigningMechanism::File(file)),
            (None, Some(vault), None) => Ok(SigningMechanism::Vault(vault)),
            (None, None, Some(yubikey)) => Ok(SigningMechanism::Yubikey(yubikey)),
            _ => return Err(()),
        }

        #[cfg(not(feature = "yubikey-support"))]
        match (self.file, self.vault) {
            (Some(file), None) => Ok(SigningMechanism::File(file)),
            (None, Some(vault)) => Ok(SigningMechanism::Vault(vault)),
            _ => return Err(()),
        }
    }
}
