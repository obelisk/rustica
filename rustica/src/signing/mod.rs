use sshcerts::ssh::{CertType, PublicKey, PrivateKey, SigningFunction};
use sshcerts::yubikey::{SlotId, Yubikey};
use std::sync::{Arc, Mutex};
use serde::Deserialize;

mod file;
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

#[derive(Deserialize)]
pub struct YubikeySigner {
    #[serde(deserialize_with = "YubikeySigner::parse_slot")]
    user_slot: SlotId,
    #[serde(deserialize_with = "YubikeySigner::parse_slot")]
    host_slot: SlotId,
    #[serde(skip_deserializing, default = "YubikeySigner::new_yubikey_mutex")]
    yubikey: Arc<Mutex<Yubikey>>
}

pub enum SigningMechanism {
    File(FileSigner),
    Vault(VaultSigner),
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
            SigningMechanism::Yubikey(yubikey) => yubikey.get_signer(cert_type),
        }
    }

    pub fn get_signer_public_key(&self, cert_type: CertType) -> Result<PublicKey, SigningError> {
        match self {
            SigningMechanism::File(file) => Ok(file.get_signer_public_key(cert_type)),
            SigningMechanism::Vault(_vault) => panic!("Unimplemented"),
            SigningMechanism::Yubikey(yubikey) => yubikey.get_signer_public_key(cert_type),
        }
    }
}