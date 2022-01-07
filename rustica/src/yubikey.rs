use x509_parser::der_parser::oid;
use crate::key::{Key, KeyAttestation, PinPolicy, TouchPolicy};

use sshcerts::PublicKey;
use std::convert::TryFrom;
use std::convert::TryInto;
use x509_parser::prelude::*;


const ROOT_CA: &[u8] = "-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIDBAZHMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNVBAMMIFl1
YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAwMDAwMFoY
DzIwNTIwNDE3MDAwMDAwWjArMSkwJwYDVQQDDCBZdWJpY28gUElWIFJvb3QgQ0Eg
U2VyaWFsIDI2Mzc1MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMN2
cMTNR6YCdcTFRxuPy31PabRn5m6pJ+nSE0HRWpoaM8fc8wHC+Tmb98jmNvhWNE2E
ilU85uYKfEFP9d6Q2GmytqBnxZsAa3KqZiCCx2LwQ4iYEOb1llgotVr/whEpdVOq
joU0P5e1j1y7OfwOvky/+AXIN/9Xp0VFlYRk2tQ9GcdYKDmqU+db9iKwpAzid4oH
BVLIhmD3pvkWaRA2H3DA9t7H/HNq5v3OiO1jyLZeKqZoMbPObrxqDg+9fOdShzgf
wCqgT3XVmTeiwvBSTctyi9mHQfYd2DwkaqxRnLbNVyK9zl+DzjSGp9IhVPiVtGet
X02dxhQnGS7K6BO0Qe8CAwEAAaNCMEAwHQYDVR0OBBYEFMpfyvLEojGc6SJf8ez0
1d8Cv4O/MA8GA1UdEwQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3
DQEBCwUAA4IBAQBc7Ih8Bc1fkC+FyN1fhjWioBCMr3vjneh7MLbA6kSoyWF70N3s
XhbXvT4eRh0hvxqvMZNjPU/VlRn6gLVtoEikDLrYFXN6Hh6Wmyy1GTnspnOvMvz2
lLKuym9KYdYLDgnj3BeAvzIhVzzYSeU77/Cupofj093OuAswW0jYvXsGTyix6B3d
bW5yWvyS9zNXaqGaUmP3U9/b6DlHdDogMLu3VLpBB9bm5bjaKWWJYgWltCVgUbFq
Fqyi4+JE014cSgR57Jcu3dZiehB6UtAPgad9L5cNvua/IWRmm+ANy3O2LH++Pyl8
SREzU8onbBsjMg9QDiSf5oJLKvd/Ren+zGY7
-----END CERTIFICATE-----".as_bytes();

#[derive(Debug)]
pub enum YubikeyValidationError {
    ParseError,
    ValidationError,
}

impl From<x509_parser::nom::Err<x509_parser::error::X509Error>> for YubikeyValidationError {
    fn from(_e: x509_parser::nom::Err<x509_parser::error::X509Error>) -> Self {
        YubikeyValidationError::ParseError
    }
}

impl From<x509_parser::error::X509Error> for YubikeyValidationError {
    fn from(_e: x509_parser::error::X509Error) -> Self {
        YubikeyValidationError::ValidationError
    }
}

fn build_key(ssh_pubkey: PublicKey, certificate: X509Certificate, client: &[u8], intermediate: &[u8]) -> Key {
    let extensions = certificate.extensions();

    // Find the three things we need: Firmware, Yubikey serial, Usage Policies
    let firmware = &extensions[&oid!(1.3.6.1.4.1.41482.3.3)].value;
    let serial = &extensions[&oid!(1.3.6.1.4.1.41482.3.7)].value;
    let policy = &extensions[&oid!(1.3.6.1.4.1.41482.3.8)].value;
    if firmware.len() != 3 || serial.len() > 10 || policy.len() != 2 {
        error!("The certificate has an unexpected format");
        Key {
            fingerprint: ssh_pubkey.fingerprint().hash,
            attestation: None,
        }
    } else {
        let mut serial = vec![0; 8 - (serial.len() - 2)];
        serial.extend_from_slice(&extensions[&oid!(1.3.6.1.4.1.41482.3.7)].value[2..]);
        let firmware = format!("{}.{}.{}", firmware[0] as u8, firmware[1] as u8, firmware[2] as u8);
        let serial = u64::from_be_bytes(serial.try_into().unwrap());
        let pin_policy = PinPolicy::try_from(policy[0]).unwrap();
        let touch_policy = TouchPolicy::try_from(policy[1]).unwrap();
        Key {
            fingerprint: ssh_pubkey.fingerprint().hash,
            attestation: Some(KeyAttestation {
                firmware,
                serial,
                pin_policy,
                touch_policy,
                certificate: client.to_vec(),
                intermediate: intermediate.to_vec(),
            })
        }
    }
}

/// Verify a provided yubikey attestation certification and intermediate
/// certificate are valid against the Yubico attestation root ca.
pub fn verify_certificate_chain(client: &[u8], intermediate: &[u8]) -> Result<Key, YubikeyValidationError> {
    // Extract the certificate public key and convert to an sshcerts PublicKey
    let ssh_pubkey = match sshcerts::yubikey::piv::ssh::extract_ssh_pubkey_from_x509_certificate(client) {
        Ok(ssh) => ssh,
        Err(_) => return Err(YubikeyValidationError::ParseError),
    };

    // Parse the root ca. This should never fail
    let (_, root_ca) = parse_x509_pem(ROOT_CA).unwrap();
    let root_ca = Pem::parse_x509(&root_ca).unwrap();

    // Parse the certificates
    let (_, parsed_intermediate) = parse_x509_certificate(intermediate)?;
    let (_, parsed_client) = parse_x509_certificate(client)?;
    debug!("Certificates parsed");

    // Validate that the provided intermediate certificate is signed by the Yubico Attestation Root CA
    parsed_intermediate.verify_signature(Some(&root_ca.tbs_certificate.subject_pki))?;

    // Validate that the provided certificate is signed by the intermediate CA
    parsed_client.verify_signature(Some(&parsed_intermediate.tbs_certificate.subject_pki))?;
    debug!("Certificate providence verified");

    Ok(build_key(ssh_pubkey, parsed_client, client, intermediate))
}