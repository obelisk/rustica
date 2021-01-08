use super::error::{Error, ErrorKind, Result};
use std::fmt;
/// A type which represents the various kinds of keys.
#[derive(Debug, PartialEq)]
pub enum KeyTypeKind {
    /// Represents an RSA key type.
    Rsa,

    /// Represents an ED25519 key type.
    Ed25519,

    /// Represents an ECDSA key type.
    Ecdsa,

    /// Represents an RSA certificate key type.
    RsaCert,

    /// Represents an ED25519 certificate key type.
    Ed25519Cert,

    /// Represents an ECDSA certificate key type.
    EcdsaCert,
}

/// `KeyType` represents the type of an OpenSSH key.
#[derive(Debug, PartialEq)]
pub struct KeyType {
    /// Name of the key type.
    pub name: &'static str,

    /// Short name of the key type.
    pub short_name: &'static str,

    /// Indicates whether the key type represents a certificate or not.
    pub is_cert: bool,

    /// Kind of the key type.
    pub kind: KeyTypeKind,

    /// The cert-less equivalent to a certified key type.
    pub plain: &'static str,
}

impl KeyType {
    /// Creates a new `KeyType` from a given name.
    ///
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// let kt = sshkeys::KeyType::from_name("ssh-rsa").unwrap();
    /// assert_eq!(kt.kind, sshkeys::KeyTypeKind::Rsa);
    /// ```
    pub fn from_name(name: &str) -> Result<KeyType> {
        let kt = match name {
            "ssh-rsa" => KeyType {
                name: "ssh-rsa",
                plain: "ssh-rsa",
                short_name: "RSA",
                is_cert: false,
                kind: KeyTypeKind::Rsa,
            },
            "rsa-sha2-512" => KeyType {
                name: "rsa-sha2-512",
                plain: "rsa-sha2-512",
                short_name: "RSA",
                is_cert: false,
                kind: KeyTypeKind::Rsa,
            },
            "ssh-rsa-cert-v01@openssh.com" => KeyType {
                name: "ssh-rsa-cert-v01@openssh.com",
                plain: "ssh-rsa",
                short_name: "RSA-CERT",
                is_cert: true,
                kind: KeyTypeKind::RsaCert,
            },
            "ecdsa-sha2-nistp256" => KeyType {
                name: "ecdsa-sha2-nistp256",
                plain: "ecdsa-sha2-nistp256",
                short_name: "ECDSA",
                is_cert: false,
                kind: KeyTypeKind::Ecdsa,
            },
            "ecdsa-sha2-nistp384" => KeyType {
                name: "ecdsa-sha2-nistp384",
                plain: "ecdsa-sha2-nistp384",
                short_name: "ECDSA",
                is_cert: false,
                kind: KeyTypeKind::Ecdsa,
            },
            "ecdsa-sha2-nistp521" => KeyType {
                name: "ecdsa-sha2-nistp521",
                plain: "ecdsa-sha2-nistp521",
                short_name: "ECDSA",
                is_cert: false,
                kind: KeyTypeKind::Ecdsa,
            },
            "ecdsa-sha2-nistp256-cert-v01@openssh.com" => KeyType {
                name: "ecdsa-sha2-nistp256-cert-v01@openssh.com",
                plain: "ecdsa-sha2-nistp256",
                short_name: "ECDSA-CERT",
                is_cert: true,
                kind: KeyTypeKind::EcdsaCert,
            },
            "ecdsa-sha2-nistp384-cert-v01@openssh.com" => KeyType {
                name: "ecdsa-sha2-nistp384-cert-v01@openssh.com",
                plain: "ecdsa-sha2-nistp384",
                short_name: "ECDSA-CERT",
                is_cert: true,
                kind: KeyTypeKind::EcdsaCert,
            },
            "ecdsa-sha2-nistp521-cert-v01@openssh.com" => KeyType {
                name: "ecdsa-sha2-nistp521-cert-v01@openssh.com",
                plain: "ecdsa-sha2-nistp521",
                short_name: "ECDSA-CERT",
                is_cert: true,
                kind: KeyTypeKind::EcdsaCert,
            },
            "ssh-ed25519" => KeyType {
                name: "ssh-ed25519",
                plain: "ssh-ed25519",
                short_name: "ED25519",
                is_cert: false,
                kind: KeyTypeKind::Ed25519,
            },
            "ssh-ed25519-cert-v01@openssh.com" => KeyType {
                name: "ssh-ed25519-cert-v01@openssh.com",
                plain: "ssh-ed25519",
                short_name: "ED25519-CERT",
                is_cert: true,
                kind: KeyTypeKind::Ed25519Cert,
            },
            _ => {
                return Err(Error::with_kind(ErrorKind::UnknownKeyType(
                    name.to_string(),
                )))
            }
        };

        Ok(kt)
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}
