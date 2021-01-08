use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

use super::error::{Error, ErrorKind, Result};
use super::keytype::KeyType;
use super::pubkey::{PublicKey, PublicKeyKind};
use super::reader::Reader;

use base64;

/// Represents the different types a certificate can be.
#[derive(Debug, PartialEq)]
pub enum CertType {
    /// Represents a user certificate.
    User,

    /// Represents a host certificate.
    Host,
}

impl fmt::Display for CertType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CertType::User => write!(f, "user certificate"),
            CertType::Host => write!(f, "host certificate"),
        }
    }
}

/// A type which represents an OpenSSH certificate key.
/// Please refer to [PROTOCOL.certkeys] for more details about OpenSSH certificates.
/// [PROTOCOL.certkeys]: https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
#[derive(Debug)]
pub struct Certificate {
    /// Type of key.
    pub key_type: KeyType,

    /// Cryptographic nonce.
    pub nonce: Vec<u8>,

    /// Public key part of the certificate.
    pub key: PublicKey,

    /// Serial number of certificate.
    pub serial: u64,

    /// Represents the type of the certificate.
    pub cert_type: CertType,

    /// Key identity.
    pub key_id: String,

    /// The list of valid principals for the certificate.
    pub principals: Vec<String>,

    /// Time after which certificate is considered as valid.
    pub valid_after: u64,

    /// Time before which certificate is considered as valid.
    pub valid_before: u64,

    /// Critical options of the certificate. Generally used to
    /// control features which restrict access.
    pub critical_options: HashMap<String, String>,

    /// Certificate extensions. Extensions are usually used to
    /// enable features that grant access.
    pub extensions: HashMap<String, String>,

    /// The `reserved` field is currently unused and is ignored in this version of the protocol.
    pub reserved: Vec<u8>,

    /// Signature key contains the CA public key used to sign the certificate.
    pub signature_key: PublicKey,

    /// Signature of the certificate.
    pub signature: Vec<u8>,

    /// Associated comment, if any.
    pub comment: Option<String>,
}

impl Certificate {
    /// Reads an OpenSSH certificate from a given path.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use sshkeys;
    /// # fn example() -> sshkeys::Result<()> {
    /// let cert = sshkeys::Certificate::from_path("/path/to/id_ed25519-cert.pub")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Certificate> {
        let mut contents = String::new();
        File::open(path)?.read_to_string(&mut contents)?;

        Certificate::from_string(&contents)
    }

    /// Reads an OpenSSH certificate from a given string.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use sshkeys;
    /// # fn example() -> sshkeys::Result<()> {
    /// let cert = sshkeys::Certificate::from_string("ssh-rsa AAAAB3NzaC1yc2EAAAA...")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_string(s: &str) -> Result<Certificate> {
        let mut iter = s.split_whitespace();

        let kt_name = iter
            .next()
            .ok_or(Error::with_kind(ErrorKind::InvalidFormat))?;

        let kt = KeyType::from_name(&kt_name)?;
        if !kt.is_cert {
            return Err(Error::with_kind(ErrorKind::NotCertificate));
        }

        let data = iter
            .next()
            .ok_or(Error::with_kind(ErrorKind::InvalidFormat))?;

        let comment = iter.next().map(|v| String::from(v));
        let decoded = base64::decode(&data)?;
        let mut reader = Reader::new(&decoded);

        // Validate key types before reading the rest of the data
        let kt_from_reader = reader.read_string()?;
        if kt_name != kt_from_reader {
            return Err(Error::with_kind(ErrorKind::KeyTypeMismatch));
        }

        let nonce = reader.read_bytes()?;
        let key = PublicKey::from_reader(&kt_name, &mut reader)?;
        let serial = reader.read_u64()?;

        let cert_type = match reader.read_u32()? {
            1 => CertType::User,
            2 => CertType::Host,
            n => return Err(Error::with_kind(ErrorKind::InvalidCertType(n))),
        };

        let key_id = reader.read_string()?;
        let principals = reader.read_bytes().and_then(|v| read_principals(&v))?;
        let valid_after = reader.read_u64()?;
        let valid_before = reader.read_u64()?;
        let critical_options = reader.read_bytes().and_then(|v| read_options(&v))?;
        let extensions = reader.read_bytes().and_then(|v| read_options(&v))?;
        let reserved = reader.read_bytes()?;
        let signature_key = reader
            .read_bytes()
            .and_then(|v| PublicKey::from_bytes(&v))?;

        let signed_len = reader.get_offset();
        let signature = reader.read_bytes()?;

        reader.set_offset(0).unwrap();
        let signed_bytes = reader.read_raw_bytes(signed_len).unwrap();
        verify_signature(&signature, &signed_bytes, &signature_key)?;

        let cert = Certificate {
            key_type: kt,
            nonce: nonce,
            key: key,
            serial: serial,
            cert_type: cert_type,
            key_id: key_id,
            principals: principals,
            valid_after: valid_after,
            valid_before: valid_before,
            critical_options: critical_options,
            extensions: extensions,
            reserved: reserved,
            signature_key: signature_key,
            signature: signature,
            comment: comment,
        };

        Ok(cert)
    }
}

// Reads `option` values from a byte sequence.
// The `option` values are used to represent the `critical options` and
// `extensions` in an OpenSSH certificate key, which are represented as tuples
// containing the `name` and `data` values of type `string`.
// Some `options` are `flags` only (e.g. the certificate extensions) and the
// associated value with them is the empty string (""), while others are `string`
// options and have an associated value, which is a `string`.
// The `critical options` of a certificate are always `string` options, since they
// have an associated `string` value, which is embedded in a separate buffer, so
// in order to extract the associated value we need to read the buffer first and then
// read the `string` value itself.
fn read_options(buf: &[u8]) -> Result<HashMap<String, String>> {
    let mut reader = Reader::new(&buf);
    let mut options = HashMap::new();

    // Use a `Reader` and loop until EOF is reached, so that we can
    // read all options from the provided byte slice.
    loop {
        let name = match reader.read_string() {
            Ok(v) => v,
            Err(e) => match e.kind {
                ErrorKind::UnexpectedEof => break,
                _ => return Err(e),
            },
        };

        // If we have a `string` option extract the value from the buffer,
        // otherwise we have a `flag` option which is the `empty` string.
        let value_buf = reader.read_bytes()?;
        let value = if value_buf.len() > 0 {
            Reader::new(&value_buf).read_string()?
        } else {
            "".to_string()
        };

        options.insert(name, value);
    }

    Ok(options)
}

// Reads the `principals` field of a certificate key.
// The `principals` are represented as a sequence of `string` values
// embedded in a buffer.
// This function reads the whole byte slice until EOF is reached in order to
// ensure all principals are read from the byte slice.
fn read_principals(buf: &[u8]) -> Result<Vec<String>> {
    let mut reader = Reader::new(&buf);
    let mut items = Vec::new();

    loop {
        let principal = match reader.read_string() {
            Ok(v) => v,
            Err(e) => match e.kind {
                ErrorKind::UnexpectedEof => break,
                _ => return Err(e),
            },
        };

        items.push(principal);
    }

    Ok(items)
}

fn verify_signature(signature_buf: &[u8], signed_bytes: &[u8], public_key: &PublicKey) -> Result<Vec<u8>> {
    let mut reader = Reader::new(&signature_buf);

    let sig_type = reader.read_string().and_then(|v| KeyType::from_name(&v))?;
    if sig_type.name != public_key.key_type.name {
        return Err(Error::with_kind(ErrorKind::KeyTypeMismatch));
    }

    match &public_key.kind {
         PublicKeyKind::Ecdsa(key) => {
            let sig_reader = reader.read_bytes().unwrap();
            let mut reader = Reader::new(&sig_reader);

            // Read the R value
            let mut sig = reader.read_mpint().unwrap();
            // Read the S value
            sig.extend(reader.read_mpint().unwrap());

            let result = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &key.key).verify(&signed_bytes, &sig);
            match result {
                Ok(()) => return Ok(signature_buf.to_vec()),
                Err(_) => {
                    println!("Signature Verification Failed");
                    return Err(Error::with_kind(ErrorKind::CertificateInvalidSignature))
                },
            }
        },
        PublicKeyKind::Rsa(key) => {
            return Err(Error::with_kind(ErrorKind::CertificateInvalidSignature))
        },
        PublicKeyKind::Ed25519(key) => {
            return Err(Error::with_kind(ErrorKind::CertificateInvalidSignature))
        },
    }
}

impl fmt::Display for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Type: {} {}\n", self.key_type, self.cert_type);
        write!(f, "Public Key: {} {}:{}\n", self.key_type.short_name, self.key.fingerprint().kind, self.key.fingerprint().hash);
        write!(f, "Signing CA: {} {}:{} (using {})\n", self.signature_key.key_type.short_name, self.signature_key.fingerprint().kind, self.signature_key.fingerprint().hash, self.signature_key.key_type);
        write!(f, "Key ID: \"{}\"\n", self.key_id);
        write!(f, "Serial: {}\n", self.serial);

        if self.valid_before == 0xFFFFFFFFFFFFFFFF && self.valid_after == 0x0 {
            write!(f, "Valid: forever\n");
        } else {
            write!(f, "Valid between: {} and {}\n", self.valid_after, self.valid_before);
        }

        if self.principals.len() == 0 {
            write!(f, "Principals: (none)\n");
        } else {
            write!(f, "Principals:\n");
            for principal in &self.principals {
                write!(f, "\t{}\n", principal);
            }
        }

        if self.critical_options.len() == 0 {
            write!(f, "Critical Options: (none)\n");
        } else {
            write!(f, "Critical Options:\n");
            for (name, value) in &self.critical_options {
                write!(f, "\t{} {}\n", name, value);
            }
        }

        if self.extensions.len() == 0 {
            write!(f, "Extensions: (none)\n");
        } else {
            write!(f, "Extensions:\n");
            for (name, _) in &self.extensions {
                write!(f, "\t{}\n", name);
            }
        }

        write!(f, "")
    }
}