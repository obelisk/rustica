use x509_parser::der_parser::oid;
use crate::key::{U2fAttestation, PIVAttestation};
use crate::key::{Key, KeyAttestation, PinPolicy, TouchPolicy};

use minicbor::Decoder;

use sshcerts::{
    PublicKey,
    ssh::KeyType,
    ssh::PublicKeyKind,
    ssh::EcdsaPublicKey,
    ssh::Ed25519PublicKey,
    ssh::Curve,
};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::io::Cursor;
use std::io::Read;
use x509_parser::prelude::*;

use ring::{
    digest,
    signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1}
};

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

const U2F_ROOT_CA: &[u8] = "-----BEGIN CERTIFICATE-----
MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ
dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw
MDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290
IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk
5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep
8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw
nebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT
9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw
LvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ
hjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN
BgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4
MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt
hX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k
LVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U
sG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc
U9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==
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

#[derive(Debug, Default)]
pub struct CoseKey {
    pub key_type: i128,
    pub algorithm: i128,
    pub key: Vec<u8>,
    pub parameters: HashMap<i128, String>,
}

pub struct AuthData {
    pub aaguid: String,
    pub rpid_hash: String,
    pub public_key: PublicKey,
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
            attestation: Some(KeyAttestation::Piv(PIVAttestation {
                firmware,
                serial,
                pin_policy,
                touch_policy,
                certificate: client.to_vec(),
                intermediate: intermediate.to_vec(),
            }))
        }
    }
}

fn u2f_extract_firmware_version(certificate: &X509Certificate) -> Result<String, YubikeyValidationError> {
    let extensions = certificate.extensions();
    let firmware = extensions[&oid!(1.3.6.1.4.1.41482.13.1)].value;
    // There are two bytes at the beginning and I'm not sure what they do
    if firmware.len() != 5 {
        println!("Could not get firmware: {}", hex::encode(firmware));
        return Err(YubikeyValidationError::ParseError)
    }
    let firmware = format!("{}.{}.{}", firmware[2] as u8, firmware[3] as u8, firmware[4] as u8);

    Ok(firmware)
}

/// Verify a provided yubikey attestation certification and intermediate
/// certificate are valid against the Yubico attestation Root CA.
pub fn verify_piv_certificate_chain(client: &[u8], intermediate: &[u8]) -> Result<Key, YubikeyValidationError> {
    // Extract the certificate public key and convert to an sshcerts PublicKey
    let ssh_pubkey = match sshcerts::x509::extract_ssh_pubkey_from_x509_certificate(client) {
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

fn read_integer(decoder: &mut Decoder) -> Result<i128, YubikeyValidationError> {
    let t = decoder.datatype().map_err(|_| YubikeyValidationError::ParseError)?;
    let v = match t {
        minicbor::data::Type::U8 => decoder.u8().unwrap() as i128,
        minicbor::data::Type::U16 => decoder.u16().unwrap() as i128,
        minicbor::data::Type::U32 => decoder.u32().unwrap() as i128,
        minicbor::data::Type::U64 => decoder.u64().unwrap() as i128,
        minicbor::data::Type::I8 => decoder.i8().unwrap() as i128,
        minicbor::data::Type::I16 => decoder.i16().unwrap() as i128,
        minicbor::data::Type::I32 => decoder.i32().unwrap() as i128,
        minicbor::data::Type::I64 => decoder.i64().unwrap() as i128,
        _ => return Err(YubikeyValidationError::ParseError)
    };

    Ok(v)
}

fn parse_auth_data(auth_data_raw: &[u8], application: &[u8]) -> Result<AuthData, YubikeyValidationError> {
    let mut auth_data = Cursor::new(auth_data_raw);

    // RPID Hash
    let mut rpid_hash = [0; 32];
    if auth_data.read_exact(&mut rpid_hash).is_err() {
        return Err(YubikeyValidationError::ParseError)
    }
    let verify_rpid_hash = digest::digest(&digest::SHA256, &application).as_ref().to_vec();
    if rpid_hash.to_vec() != verify_rpid_hash {
        return Err(YubikeyValidationError::ParseError)
    }

    // Flags
    let mut flags = [0; 1];
    if auth_data.read_exact(&mut flags).is_err() {
        return Err(YubikeyValidationError::ParseError)
    }
    let credential_data_included = matches!(flags[0] & 0x40, 0x40);

    // Sign Count
    let mut _sign_count = [0; 4];
    if auth_data.read_exact(&mut _sign_count).is_err() {
        return Err(YubikeyValidationError::ParseError)
    }

    // AAGUID
    let mut aaguid = [0; 16];
    if auth_data.read_exact(&mut aaguid).is_err() {
        return Err(YubikeyValidationError::ParseError)
    }

    // Credential ID Length
    let mut cred_id_len = [0; 2];
    if auth_data.read_exact(&mut cred_id_len).is_err() {
        return Err(YubikeyValidationError::ParseError)
    }
    let cred_id_len = u16::from_be_bytes(cred_id_len) as usize;

    // Credential ID
    let mut credential_id = vec![0; cred_id_len];
    if auth_data.read_exact(&mut credential_id).is_err() {
        return Err(YubikeyValidationError::ParseError)
    }

    // Start decoding CBOR objects from after where we got with the cursor
    let cose_key = if credential_data_included {
        // Create a new decoder for the COSE data
        let mut decoder = Decoder::new(&auth_data_raw[auth_data.position() as usize..]);

        // We only deal with maps of definite length
        let len = match decoder.map() {
            Ok(Some(len)) => len,
            _ => return Err(YubikeyValidationError::ParseError),
        };


        let mut parsed_key = CoseKey::default();
        let mut idx = 0;

        // Multiply by two because maps have two entries per element
        while idx < len * 2 {
            let key = read_integer(&mut decoder)?;
            match key {
                -1 => {
                    let value = read_integer(&mut decoder).map_err(|_| YubikeyValidationError::ParseError)?;
                    parsed_key.parameters.insert(key, value.to_string());
                },
                1 => parsed_key.key_type = read_integer(&mut decoder).map_err(|_| YubikeyValidationError::ParseError)?,
                3 => parsed_key.algorithm = read_integer(&mut decoder).map_err(|_| YubikeyValidationError::ParseError)?,
                -2 | -3 => parsed_key.key = decoder.bytes().map_err(|_| YubikeyValidationError::ParseError)?.to_vec(),
                _ => decoder.undefined().map_err(|_| YubikeyValidationError::ParseError)?,
            };
            idx += 2;
        }
        Some(parsed_key)
    } else {
        None
    };

    let cose_key = cose_key.ok_or(YubikeyValidationError::ParseError)?;

    let app = String::from_utf8(application.to_vec()).map_err(|_| YubikeyValidationError::ParseError)?;

    // This code should probably be moved into SSHCerts
    let (kind, key_type) = match cose_key.algorithm {
        // ECDSA
        -7 => {
            let k = EcdsaPublicKey {
                curve: Curve::from_identifier("nistp256").unwrap(),
                key: cose_key.key,
                sk_application: Some(app),
            };
            (PublicKeyKind::Ecdsa(k), KeyType::from_name("sk-ecdsa-sha2-nistp256@openssh.com").unwrap())
        },

        // Ed25519
        -8 => {
            let k = Ed25519PublicKey {
                key: cose_key.key,
                sk_application: Some(app),
            };

            (PublicKeyKind::Ed25519(k), KeyType::from_name("sk-ssh-ed25519@openssh.com").unwrap())
        },

        // Unknown
        n => {
            error!("Unknown algorithm: {}", n);
            return Err(YubikeyValidationError::ParseError)
        },
    };

    let public_key = PublicKey {
        key_type,
        kind, 
        comment: None,
    };

    Ok(AuthData {
        rpid_hash: hex::encode(rpid_hash),
        aaguid: hex::encode(aaguid),
        public_key,
    })
}

/// Verify a provided U2F attestation, signature, and certificate are valid
/// against the Yubico U2F Root CA.
pub fn verify_u2f_certificate_chain(auth_data: &[u8], auth_data_signature: &[u8], intermediate: &[u8], alg: i32, challenge: &[u8], application: &[u8]) -> Result<Key, YubikeyValidationError> {
    match alg {
        // Verify using ECDSA256
        -7 => {
            // Parse the U2F root CA. This should never fail
            let (_, root_ca) = parse_x509_pem(U2F_ROOT_CA).unwrap();
            let root_ca = Pem::parse_x509(&root_ca).unwrap();

            let (_, parsed_intermediate) = x509_parser::parse_x509_certificate(intermediate).map_err(|_| YubikeyValidationError::ParseError)?;

            // Check the root CA has signed the intermediate, return error if not
            parsed_intermediate.verify_signature(Some(&root_ca.tbs_certificate.subject_pki))?;

            // Extract public key from verified intermediate certificate
            let key_bytes = parsed_intermediate.tbs_certificate.subject_pki.subject_public_key.data.to_vec();

            // Generate the data that was signed by the intermediate
            let mut signed_data = auth_data.clone().to_vec();
            signed_data.append(&mut digest::digest(&digest::SHA256, challenge).as_ref().to_vec());

            // Validate signature was generated by the now validated intermediate
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &key_bytes).verify(
                &signed_data,
                auth_data_signature,
            ).map_err(|_| YubikeyValidationError::ValidationError)?;
            
            let parsed_auth_data = parse_auth_data(auth_data, application)?;

            Ok(Key {
                fingerprint: parsed_auth_data.public_key.fingerprint().hash,
                attestation: Some(KeyAttestation::U2f(U2fAttestation {
                    aaguid: parsed_auth_data.aaguid,
                    firmware: u2f_extract_firmware_version(&parsed_intermediate)?,
                    auth_data: auth_data.to_vec(),
                    auth_data_signature: auth_data_signature.to_vec(),
                    intermediate: intermediate.to_vec(),
                })),
            })
        },
        // Verify using Ed25519
        -8 => {
            return Err(YubikeyValidationError::ValidationError)
        },
        _ => {
            return Err(YubikeyValidationError::ValidationError)
        }
    }
}