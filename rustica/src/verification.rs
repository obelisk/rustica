use crate::key::{Key, KeyAttestation, PinPolicy, TouchPolicy};
use crate::key::{PIVAttestation, U2fAttestation};

use crate::error::RusticaServerError;

use ring::digest::{self};
use sshcerts::{
    fido::verification::verify_auth_data, yubikey::verification::verify_certificate_chain,
};
use std::convert::TryFrom;

// For Yubikey 5 Nano:
// - PIV intermediate cert size is approx 800 bytes
// - PIV client cert is approx 700 bytes
// - U2F intermediate cert is approx 800 bytes
// - U2F attestation statement is approx 256 bytes
const CERT_MAX_SIZE: usize = 1024 * 2; // 2 KiB

/// Verify a provided yubikey attestation certification and intermediate
/// certificate are valid against the Yubico attestation Root CA.
pub fn verify_piv_certificate_chain(
    client: &[u8],
    intermediate: &[u8],
) -> Result<Key, RusticaServerError> {
    // Restrict the max size of certificates
    // For Yubikey 5 Nano, actual intermediate cert size is approx 800 bytes
    if intermediate.len() > CERT_MAX_SIZE {
        return Err(RusticaServerError::PivIntermediateCertTooBig);
    }
    // For Yubikey 5 Nano, actual client cert size is approx 700 bytes
    if client.len() > CERT_MAX_SIZE {
        return Err(RusticaServerError::PivClientCertTooBig);
    }

    // Extract the certificate public key and convert to an sshcerts PublicKey
    let validated_piv_data = verify_certificate_chain(client, intermediate, None)
        .map_err(|_| RusticaServerError::InvalidKey)?;
    let pin_policy = PinPolicy::try_from(validated_piv_data.pin_policy)
        .map_err(|_| RusticaServerError::InvalidKey)?;
    let touch_policy = TouchPolicy::try_from(validated_piv_data.touch_policy)
        .map_err(|_| RusticaServerError::InvalidKey)?;

    Ok(Key {
        fingerprint: validated_piv_data.public_key.fingerprint().hash,
        attestation: Some(KeyAttestation::Piv(PIVAttestation {
            firmware: validated_piv_data.firmware,
            serial: validated_piv_data.serial,
            pin_policy,
            touch_policy,
            certificate: client.to_vec(),
            intermediate: intermediate.to_vec(),
        })),
    })
}

/// Verify a provided U2F attestation, signature, and certificate are valid
/// against the Yubico U2F Root CA.
pub fn verify_u2f_certificate_chain(
    auth_data: &[u8],
    auth_data_signature: &[u8],
    intermediate: &[u8],
    alg: i32,
    challenge: &[u8],
    application: &[u8],
    u2f_challenge_hashed: bool,
) -> Result<Key, RusticaServerError> {
    // Restrict the max size for the attestation data and intermediate certificate
    // For Yubikey 5 Nano, actual intermediate cert size is approx 800 bytes
    if intermediate.len() > CERT_MAX_SIZE {
        return Err(RusticaServerError::U2fIntermediateCertTooBig);
    }
    // For Yubikey 5 Nano, actual auth_data size is approx 256 bytes
    if auth_data.len() > CERT_MAX_SIZE {
        return Err(RusticaServerError::U2fAttestationTooBig);
    }

    // Take all the provided data and validate it up to the Yubico U2F Root CA

    let challenge = if u2f_challenge_hashed {
        challenge.to_vec()
    } else {
        digest::digest(&digest::SHA256, challenge).as_ref().to_vec()
    };
    // Earlier versions of RusticaAgent did not send the u2f_challenge hashed so
    //
    let validated_u2f_data = verify_auth_data(
        auth_data,
        auth_data_signature,
        &challenge,
        alg,
        intermediate,
        None,
    )
    .map_err(|_| RusticaServerError::InvalidKey)?;
    let parsed_application =
        String::from_utf8(application.to_vec()).map_err(|_| RusticaServerError::InvalidKey)?;
    let ssh_public_key = validated_u2f_data
        .auth_data
        .ssh_public_key(&parsed_application)
        .map_err(|_| RusticaServerError::InvalidKey)?;

    Ok(Key {
        fingerprint: ssh_public_key.fingerprint().hash,
        attestation: Some(KeyAttestation::U2f(U2fAttestation {
            aaguid: hex::encode(validated_u2f_data.auth_data.aaguid),
            firmware: validated_u2f_data
                .firmware
                .unwrap_or_else(|| "Unknown".to_string()),
            auth_data: auth_data.to_vec(),
            auth_data_signature: auth_data_signature.to_vec(),
            intermediate: intermediate.to_vec(),
            challenge: challenge.to_vec(),
            alg,
            application: application.to_vec(),
        })),
    })
}
