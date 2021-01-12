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

fn configured(yk: &mut YubiKey, slot: SlotId) -> Result<PublicKeyInfo, Error> {
    match yubikey_piv::certificate::Certificate::read(yk, slot) {
        Ok(cert) => Ok(cert.subject_pki().clone()),
        Err(e) => Err(Error::InternalYubiKeyError(e)),
    }
}

fn fetch_pubkey(slot: SlotId) -> Result<PublicKeyInfo, Error> {
    let mut yubikey = match YubiKey::open() {
        Ok(yk) => yk,
        Err(e) => return Err(Error::InternalYubiKeyError(e)),
    };
    configured(&mut yubikey, slot)
}

/// This provisions the YubiKey with a new certificate. It is generally not advisable
/// to use as this means there is no backup of the key should it be lost.
/// It is however provided as an easy method quickly get a YubiKey properly configured
/// for use with Rustica.
/// 
/// It requires that a YubiKey object be passed in a long with a pin to make sure that
/// it is configuring the correct one.
pub fn _provision(yk: &mut YubiKey, pin: &[u8]) -> Result<PublicKeyInfo, Error> {
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
    if let Err(e) = Certificate::generate_self_signed(
        yk,
        slot,
        [0u8; 20],
        None,
        "/CN=RusticaProvisioned/".to_owned(),
        key_info,
    ) {
        return Err(Error::InternalYubiKeyError(e));
    }

    configured(yk, slot)
}

fn sign_data(data: &[u8], alg: AlgorithmId, slot: SlotId) -> Result<Vec<u8>, Error> {
    let mut yk = match YubiKey::open() {
        Ok(yk) => yk,
        Err(e) => return Err(Error::InternalYubiKeyError(e)),
    };

    let slot_alg = match configured(&mut yk, slot) {
        Ok(PublicKeyInfo::EcP256(_)) => AlgorithmId::EccP256,
        Ok(PublicKeyInfo::EcP384(_)) => AlgorithmId::EccP384,
        Ok(_) => AlgorithmId::Rsa2048,  // RSAish
        Err(_) => return Err(Error::Unprovisioned),
    };

    if slot_alg != alg {
        return Err(Error::WrongKeyType);
    }

    let mut hasher = Sha256::new(); 
    hasher.update(data);

    let hash = &hasher.finalize()[..];

    match yk_sign_data(&mut yk, hash, alg, slot) {
        Ok(sig) => Ok(sig.to_vec()),
        Err(e) => Err(Error::InternalYubiKeyError(e)),
    }
}

/// Pull the public key from the YubiKey and wrap it in a Rustica
/// PublicKey object.
pub fn ssh_cert_fetch_pubkey(slot: SlotId) -> Option<rustica_sshkey::PublicKey> {
    match fetch_pubkey(slot) {
        //Ok(hsm::PublicKeyInfo::Rsa { pubkey, .. }) => pubkey,
        Ok(PublicKeyInfo::EcP256(pubkey)) => {
            let key_type = rustica_sshkey::KeyType::from_name("ecdsa-sha2-nistp256").unwrap();
            let curve = rustica_sshkey::Curve::from_identifier("nistp256").unwrap();
            let kind = rustica_sshkey::EcdsaPublicKey {
                curve,
                key: pubkey.as_bytes().to_vec(),
            };

            Some(rustica_sshkey::PublicKey {
                key_type,
                kind: rustica_sshkey::PublicKeyKind::Ecdsa(kind),
                comment: None,
            })
        },
        Ok(PublicKeyInfo::EcP384(pubkey)) => {
            let key_type = rustica_sshkey::KeyType::from_name("ecdsa-sha2-nistp384").unwrap();
            let curve = rustica_sshkey::Curve::from_identifier("nistp384").unwrap();
            let kind = rustica_sshkey::EcdsaPublicKey {
                curve,
                key: pubkey.as_bytes().to_vec(),
            };

            Some(rustica_sshkey::PublicKey {
                key_type,
                kind: rustica_sshkey::PublicKeyKind::Ecdsa(kind),
                comment: None,
            })
        }
        _ => None,
    }
}

/// Sign the provided buffer of data and return it in an SSH Certificiate
/// signature formatted byte vector
pub fn ssh_cert_signer(buf: &[u8]) -> Option<Vec<u8>> {
    match sign_data(&buf, AlgorithmId::EccP256, SlotId::Retired(RetiredSlotId::R11)) {
        Ok(signature) => {
            let sig_type = "ecdsa-sha2-nistp256";
            let mut encoded: Vec<u8> = (sig_type.len() as u32).to_be_bytes().to_vec();
            encoded.extend_from_slice(sig_type.as_bytes());
            let (r,s) = match rustica_sshkey::utils::asn_der_to_r_s(&signature) {
                Some((r,s)) => (r, s),
                None => return None,
            };
            let mut sig_encoding = vec![];
            sig_encoding.extend_from_slice(&(r.len() as u32).to_be_bytes());
            sig_encoding.extend_from_slice(r);
            sig_encoding.extend_from_slice(&(s.len() as u32).to_be_bytes());
            sig_encoding.extend_from_slice(s);

            encoded.extend_from_slice(&(sig_encoding.len() as u32).to_be_bytes());
            encoded.extend(sig_encoding);

            Some(encoded)
        },
        Err(e) => {
            println!("Error: {:?}", e);
            None
        },
    }
}

/// Sign the provided buffer of data and return it in an SSH Certificiate
/// signature formatted byte vector
pub fn asn_cert_signer(buf: &[u8]) -> Option<Vec<u8>> {
    match sign_data(&buf, AlgorithmId::EccP256, SlotId::Retired(RetiredSlotId::R11)) {
        Ok(signature) => Some(signature),
        Err(e) => {
            println!("Error: {:?}", e);
            None
        },
    }
}
