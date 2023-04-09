/// The Yubikey signer uses a connected Yubikey 4/5 to sign requests. It
/// currently only supports Ecdsa256 and Ecdsa384. To use the Yubikey
/// signer, the `yubikey-support` feature must be enabled.

use super::{Signer, SignerConfig, SigningError};

use sshcerts::{Certificate, PublicKey, ssh::CertType};
use sshcerts::yubikey::piv::{SlotId, Yubikey};

use async_trait::async_trait;

use serde::Deserialize;
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};

#[derive(Deserialize)]
pub struct Config {
    /// The slot on the Yubikey to use for signing user certificates
    #[serde(deserialize_with = "parse_slot")]
    user_slot: SlotId,
    /// The slot on the Yubikey to use for signing host certificates
    #[serde(deserialize_with = "parse_slot")]
    host_slot: SlotId,
}

pub struct YubikeySigner {
    /// The slot on the Yubikey to use for signing user certificates
    user_slot: SlotId,
    // The public key of the CA used for signing user certificates
    user_public_key: PublicKey,
    /// The slot on the Yubikey to use for signing host certificates
    host_slot: SlotId,
    /// The public key of the CA used for signing host certificates
    host_public_key: PublicKey,
    /// A mutex to ensure there is no concurrent access to the Yubikey. Without
    /// this, handling two requests at the same time would result in possibly
    /// corrupted certificates for both.
    yubikey: Arc<Mutex<Yubikey>>
}

#[async_trait]
impl SignerConfig for Config {
    async fn into_signer(self) -> Result<Box<dyn Signer + Send + Sync>, SigningError> {
        let yubikey = new_yubikey_mutex();

        let (user_public_key, host_public_key) = {
            let mut yk = yubikey.lock().map_err(|e| SigningError::AccessError(format!("Could not lock Yubikey. Error: {}", e)))?;

            (
                yk.ssh_cert_fetch_pubkey(&self.user_slot).map_err(|_| SigningError::AccessError(format!("Could fetch public key for user key")))?,
                yk.ssh_cert_fetch_pubkey(&self.host_slot).map_err(|_| SigningError::AccessError(format!("Could fetch public key for host key")))?
            )
        };

        Ok(Box::new(YubikeySigner {
            user_slot: self.user_slot,
            user_public_key,
            host_slot: self.host_slot,
            host_public_key,
            yubikey,
        }))
    }
}

#[async_trait]
impl Signer for YubikeySigner {
    async fn sign(&self, cert: Certificate) -> Result<Certificate, SigningError> {
        let slot = match cert.cert_type {
            CertType::User => self.user_slot,
            CertType::Host => self.host_slot,
        };

        match self.yubikey.lock() {
            Ok(_) => {
                // Unfortunatly we need to create a new Yubikey here because otherwise
                // everything will have to be mutable which causes an issue
                // for the RusticaServer struct
                let mut yk = Yubikey::new().unwrap();
                match yk.ssh_cert_signer(&cert.tbs_certificate(), &slot) {
                    Ok(sig) => cert.add_signature(&sig).map_err(|_| SigningError::SigningFailure),
                    Err(_) => Err(SigningError::SigningFailure),
                }
            },
            Err(e) => Err(SigningError::AccessError(e.to_string())),
        }
    }

    fn get_signer_public_key(&self, cert_type: CertType) -> PublicKey {
        match cert_type {
            CertType::User => self.user_public_key.clone(),
            CertType::Host => self.host_public_key.clone(),
        }
    }

    fn get_x509_certificate_authority(&self) -> &rcgen::Certificate {
        panic!("Unimplemented")
    }
}

pub fn parse_slot<'de, D>(deserializer: D) -> Result<SlotId, D::Error>
where
    D: serde::Deserializer<'de>
{
    let slot = String::deserialize(deserializer)?;
    // If first character is R, then we need to parse the nice
    // notation
    if (slot.len() == 2 || slot.len() == 3) && slot.starts_with('R') {
        let slot_value = slot[1..].parse::<u8>();
        match slot_value {
            Ok(v) if v <= 20 => Ok(SlotId::try_from(0x81_u8 + v).unwrap()),
            _ => Err(serde::de::Error::custom("Invalid Slot")),
        }
    } else {
        Err(serde::de::Error::custom("Invalid Slot"))
    }
}

pub fn new_yubikey_mutex() -> Arc<Mutex<Yubikey>> {
    let yk = Yubikey::new().unwrap();
    Arc::new(Mutex::new(yk))
} 