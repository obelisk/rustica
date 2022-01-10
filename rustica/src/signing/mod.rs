use sshcerts::ssh::{CertType, PublicKey, PrivateKey, SigningFunction};
#[cfg(feature = "yubikey-support")]
use sshcerts::yubikey::piv::{SlotId, Yubikey};
#[cfg(feature = "yubikey-support")]
use std::sync::{Arc, Mutex};
use serde::Deserialize;
use std::convert::TryInto;

mod file;
#[cfg(feature = "yubikey-support")]
mod yubikey;

#[derive(Deserialize)]
pub struct FileSigner {
    #[serde(deserialize_with = "FileSigner::parse_private_key")]
    user_key: PrivateKey,
    #[serde(deserialize_with = "FileSigner::parse_private_key")]
    host_key: PrivateKey,
}

#[derive(Deserialize)]
pub struct VaultSigner {

}

#[cfg(feature = "yubikey-support")]
#[derive(Deserialize)]
pub struct YubikeySigner {
    #[serde(deserialize_with = "YubikeySigner::parse_slot")]
    user_slot: SlotId,
    #[serde(deserialize_with = "YubikeySigner::parse_slot")]
    host_slot: SlotId,
    #[serde(skip_deserializing, default = "YubikeySigner::new_yubikey_mutex")]
    yubikey: Arc<Mutex<Yubikey>>
}

#[derive(Deserialize)]
pub struct SigningConfiguration {
    pub file: Option<FileSigner>,
    pub vault: Option<VaultSigner>,
    #[cfg(feature = "yubikey-support")]
    pub yubikey: Option<YubikeySigner>,
}


pub enum SigningMechanism {
    File(FileSigner),
    Vault(VaultSigner),
    #[cfg(feature = "yubikey-support")]
    Yubikey(YubikeySigner),
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
