use sshcerts::{Certificate, PublicKey, ssh::CertType};
use sshcerts::yubikey::piv::{SlotId, Yubikey};
use serde::Deserialize;
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};

use super::SigningError;

#[derive(Deserialize)]
pub struct YubikeySigner {
    /// The slot on the Yubikey to use for signing user certificates
    #[serde(deserialize_with = "YubikeySigner::parse_slot")]
    user_slot: SlotId,
    /// The slot on the Yubikey to use for signing host certificates
    #[serde(deserialize_with = "YubikeySigner::parse_slot")]
    host_slot: SlotId,
    /// A mutex to ensure there is no concurrent access to the Yubikey. Without
    /// this, handling two requests at the same time would result in possibly
    /// corrupted certificates for both.
    #[serde(skip_deserializing, default = "YubikeySigner::new_yubikey_mutex")]
    yubikey: Arc<Mutex<Yubikey>>
}


impl YubikeySigner {
    pub fn sign(&self, cert: Certificate) -> Result<Certificate, SigningError> {
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

    pub fn get_signer_public_key(&self, cert_type: CertType) -> Result<PublicKey, SigningError> {
        let slot = match cert_type {
            CertType::User => self.user_slot,
            CertType::Host => self.host_slot,
        };

        let public_key = match self.yubikey.lock() {
            // Unfortunatly we need to create a new Yubikey here because otherwise
            // everything will have to be mutable which causes an issue
            // for the RusticaServer struct
            Ok(_) => Yubikey::new().unwrap().ssh_cert_fetch_pubkey(&slot),
            Err(e) => return Err(SigningError::AccessError(format!("Could not lock Yubikey to fetch from slot: {:?}. Error: {}", slot, e))),
        };

        match public_key {
            Ok(public_key) => Ok(public_key),
            Err(e) => Err(SigningError::AccessError(format!("Could not fetch public key from slot: {:?}. Error: {}", slot, e)))
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
}