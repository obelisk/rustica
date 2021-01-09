use sha2::{Digest, Sha256};

use yubikey_piv::{MgmKey, YubiKey};
use yubikey_piv::policy::{PinPolicy, TouchPolicy};
use yubikey_piv::key::{AlgorithmId, RetiredSlotId, sign_data as yk_sign_data, SlotId};
use yubikey_piv::certificate::{Certificate, PublicKeyInfo};


#[derive(Debug)]
pub enum Error {
    Unprovisioned,
    WrongKeyType,
    InternalYubiKeyError(yubikey_piv::error::Error),
}

fn configured(yk: &mut YubiKey) -> Result<PublicKeyInfo, Error> {
    match yubikey_piv::certificate::Certificate::read(yk, SlotId::Retired(RetiredSlotId::R11)) {
        Ok(cert) => Ok(cert.subject_pki().clone()),
        Err(e) => Err(Error::InternalYubiKeyError(e)),
    }
}

pub fn fetch_pubkey() -> Result<PublicKeyInfo, Error> {
    let mut yubikey = match YubiKey::open() {
        Ok(yk) => yk,
        Err(e) => return Err(Error::InternalYubiKeyError(e)),
    };
    configured(&mut yubikey)
}

pub fn fetch_yubikey(id: Option<&[u8]>) -> Result<YubiKey, Error> {
    match YubiKey::open() {
        Ok(yk) => Ok(yk),
        Err(e) => return Err(Error::InternalYubiKeyError(e)),
    }
}

pub fn provision(yk: &mut YubiKey, pin: &[u8]) -> Result<PublicKeyInfo, Error> {
    match yk.verify_pin(pin) {
        Ok(_) => (),
        Err(e) => {
            println!("Error in verify pin: {}", e);
            return Err(Error::InternalYubiKeyError(e))
        },
    }

    match yk.authenticate(MgmKey::default()) {
        Ok(_) => (),
        Err(e) => {
            println!("Error in MGM Key Authentication: {}", e);
            return Err(Error::InternalYubiKeyError(e));
        },
    }

    let slot = SlotId::Retired(RetiredSlotId::R11);
    let key_info = match yubikey_piv::key::generate(yk, slot, AlgorithmId::EccP256, PinPolicy::Never, TouchPolicy::Never) {
        Ok(ki) => ki,
        Err(e) => {
            println!("Error in provisioning new key: {}", e);
            return Err(Error::InternalYubiKeyError(e));
        },
    };

    // Generate a self-signed certificate for the new key.
    if let Err(e) =  Certificate::generate_self_signed(
        yk,
        slot,
        [0u8; 20],
        None,
        "testSubject".to_owned(),
        key_info,
    ) {
        return Err(Error::InternalYubiKeyError(e));
    }

    configured(yk)
}

pub fn sign_data(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut yk = match YubiKey::open() {
        Ok(yk) => yk,
        Err(e) => return Err(Error::InternalYubiKeyError(e)),
    };

    match configured(&mut yk) {
        Ok(PublicKeyInfo::EcP256(_)) => (),
        Ok(_) => return Err(Error::WrongKeyType),
        Err(_) => return Err(Error::Unprovisioned),
    };

    let mut hasher = Sha256::new(); 
    hasher.update(data);

    let hash = &hasher.finalize()[..];

    match yk_sign_data(&mut yk, hash, AlgorithmId::EccP256, SlotId::Retired(RetiredSlotId::R11)) {
        Ok(sig) => Ok(sig.to_vec()),
        Err(e) => Err(Error::InternalYubiKeyError(e)),
    }
}