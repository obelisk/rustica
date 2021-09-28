use sshcerts::{PublicKey, ssh::CertType, ssh::SigningFunction};
use sshcerts::yubikey::{SlotId, Yubikey};
use serde::Deserialize;
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};

use super::{YubikeySigner, SigningError};

impl YubikeySigner {
    fn create_signer(&self, slot: SlotId) -> SigningFunction {
        let yk = self.yubikey.clone();
        Box::new(move |buf: &[u8]| {
            match yk.lock() {
                Ok(_) => {
                    // Unfortunatly we need to create a new Yubikey here because otherwise
                    // everything will have to be mutable which causes an issue
                    // for the RusticaServer struct
                    let mut yk = Yubikey::new().unwrap();
                    match yk.ssh_cert_signer(buf, &slot) {
                        Ok(sig) => Some(sig),
                        Err(_) => None,
                    }
                },
                Err(e) => {
                    error!("Error in acquiring mutex for yubikey signing: {}", e);
                    None
                }
            }
        })
    }

    pub fn get_signer(&self, cert_type: CertType) -> SigningFunction {
        let slot = match cert_type {
            CertType::User => self.user_slot,
            CertType::Host => self.host_slot,
        };

        self.create_signer(slot)
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
            Err(e) => return Err(SigningError::AccessError(format!("Could not lock Yubikey to fetch from slot: {:?}", slot))),
        };

        match public_key {
            Ok(public_key) => Ok(public_key),
            Err(e) => Err(SigningError::AccessError(format!("Could not fetch public key from slot: {:?}", slot)))
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
        } else if let Ok(s) = SlotId::try_from(slot.to_owned()) {
            Ok(s)
        } else {
            Err(serde::de::Error::custom("Invalid Slot"))
        }
    }

    pub fn new_yubikey_mutex() -> Arc<Mutex<Yubikey>> {
        let yk = Yubikey::new().unwrap();
        Arc::new(Mutex::new(yk))
    }    
}