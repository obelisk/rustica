use crate::key::{U2fAttestation, PIVAttestation};
use crate::key::{Key, KeyAttestation, PinPolicy, TouchPolicy};

use crate::error::RusticaServerError;

use sshcerts::{
    fido::verification::verify_auth_data,
    yubikey::verification::verify_certificate_chain,
};
use std::convert::TryFrom;


/// Verify a provided yubikey attestation certification and intermediate
/// certificate are valid against the Yubico attestation Root CA.
pub fn verify_piv_certificate_chain(client: &[u8], intermediate: &[u8]) -> Result<Key, RusticaServerError> {
    // Extract the certificate public key and convert to an sshcerts PublicKey
    let validated_piv_data = verify_certificate_chain(client, intermediate, None).map_err(|_| RusticaServerError::InvalidKey)?;

    Ok(Key {
        fingerprint: validated_piv_data.public_key.fingerprint().hash,
        attestation: Some(KeyAttestation::Piv(PIVAttestation {
            firmware: validated_piv_data.firmware,
            serial: validated_piv_data.serial,
            pin_policy: PinPolicy::try_from(validated_piv_data.pin_policy).unwrap(),
            touch_policy: TouchPolicy::try_from(validated_piv_data.touch_policy).unwrap(),
            certificate: client.to_vec(),
            intermediate: intermediate.to_vec(),
        }))
    })
}

/// Verify a provided U2F attestation, signature, and certificate are valid
/// against the Yubico U2F Root CA.
pub fn verify_u2f_certificate_chain(auth_data: &[u8], auth_data_signature: &[u8], intermediate: &[u8], alg: i32, challenge: &[u8], application: &[u8]) -> Result<Key, RusticaServerError> {
    let validated_u2f_data = verify_auth_data(auth_data, auth_data_signature, challenge, alg, intermediate, None).map_err(|_| RusticaServerError::InvalidKey)?;
    let parsed_application = String::from_utf8(application.to_vec()).map_err(|_| RusticaServerError::InvalidKey)?;
    let ssh_public_key = validated_u2f_data.auth_data.ssh_public_key(&parsed_application).map_err(|_| RusticaServerError::InvalidKey)?;

    Ok(Key {
        fingerprint: ssh_public_key.fingerprint().hash,
        attestation: Some(KeyAttestation::U2f(U2fAttestation {
            aaguid: hex::encode(validated_u2f_data.auth_data.aaguid),
            firmware: validated_u2f_data.firmware.unwrap_or(format!("Unknown")),
            auth_data: auth_data.to_vec(),
            auth_data_signature: auth_data_signature.to_vec(),
            intermediate: intermediate.to_vec(),
            challenge: challenge.to_vec(),
            alg,
            application: application.to_vec(),
        })),
    })
}