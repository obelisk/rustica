use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use super::error::{Error, ErrorKind, Result};
use super::keytype::{KeyType, KeyTypeKind};
use super::reader::Reader;
use super::writer::Writer;

use base64;

use sha2::{Digest, Sha256, Sha384, Sha512};

/// A type which represents the different kinds a public key can be.
#[derive(Debug, PartialEq)]
pub enum PublicKeyKind {
    /// Represents an RSA public key.
    Rsa(RsaPublicKey),

    /// Represents an ECDSA public key.
    Ecdsa(EcdsaPublicKey),

    /// Represents an ED25519 public key.
    Ed25519(Ed25519PublicKey),
}

/// RSA public key.
/// The format of RSA public keys is described in RFC 4253, section 6.6
#[derive(Debug, PartialEq)]
pub struct RsaPublicKey {
    /// Exponent of key.
    pub e: Vec<u8>,

    /// Modulus of key.
    pub n: Vec<u8>,
}

/// ECDSA public key.
/// The format of ECDSA public keys is described in RFC 5656, section 3.1.
#[derive(Debug, PartialEq)]
pub struct EcdsaPublicKey {
    /// The curve being used.
    pub curve: Curve,

    /// The public key.
    pub key: Vec<u8>,
}

/// ED25519 public key.
/// The format of ED25519 public keys is described in https://tools.ietf.org/html/draft-bjh21-ssh-ed25519-02
#[derive(Debug, PartialEq)]
pub struct Ed25519PublicKey {
    /// The public key.
    pub key: Vec<u8>,
}

/// Represents the different kinds of supported curves.
#[derive(Debug, PartialEq)]
pub enum CurveKind {
    /// Represents a NIST P-256 curve.
    Nistp256,

    /// Represents a NIST P-384 curve.
    Nistp384,

    /// Represents a NIST P-521 curve.
    Nistp521,
}

/// A type which represents a cryptographic curve.
#[derive(Debug, PartialEq)]
pub struct Curve {
    /// The curve kind.
    pub kind: CurveKind,

    /// Curve identifier.
    pub identifier: &'static str,
}

impl Curve {
    /// Creates a new `Curve` from the given identifier.
    ///
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// let curve = sshkeys::Curve::from_identifier("nistp256").unwrap();
    /// assert_eq!(curve.kind, sshkeys::CurveKind::Nistp256);
    /// ```
    pub fn from_identifier(id: &str) -> Result<Curve> {
        let curve = match id {
            "nistp256" => Curve {
                kind: CurveKind::Nistp256,
                identifier: "nistp256",
            },
            "nistp384" => Curve {
                kind: CurveKind::Nistp384,
                identifier: "nistp384",
            },
            "nistp521" => Curve {
                kind: CurveKind::Nistp521,
                identifier: "nistp521",
            },
            _ => return Err(Error::with_kind(ErrorKind::UnknownCurve(id.to_string()))),
        };

        Ok(curve)
    }
}

/// A type which represents an OpenSSH public key.
#[derive(Debug, PartialEq)]
pub struct PublicKey {
    /// Key type.
    pub key_type: KeyType,

    /// The kind of public key.
    pub kind: PublicKeyKind,

    /// Associated comment, if any.
    pub comment: Option<String>,
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let comment = match self.comment {
            Some(ref c) => c,
            None => "",
        };

        write!(
            f,
            "{} {} {}",
            self.key_type,
            base64::encode(&self.encode()),
            comment
        )
    }
}

/// The `FingerprintKind` enum represents the different fingerprint representation.
#[derive(Debug, PartialEq)]
pub enum FingerprintKind {
    /// A kind used to represent the fingerprint using SHA256.
    Sha256,

    /// A kind used to represent the fingerprint using SHA384.
    Sha384,

    /// A kind used to represent the fingerprint using SHA512.
    Sha512,
}

impl fmt::Display for FingerprintKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let kind = match *self {
            FingerprintKind::Sha256 => "SHA256",
            FingerprintKind::Sha384 => "SHA384",
            FingerprintKind::Sha512 => "SHA512",
        };

        write!(f, "{}", kind)
    }
}

/// A type that represents an OpenSSH public key fingerprint.
#[derive(Debug)]
pub struct Fingerprint {
    /// The kind used to represent the fingerprint.
    pub kind: FingerprintKind,

    /// The computed fingerprint.
    pub hash: String,
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.kind, self.hash)
    }
}

impl Fingerprint {
    /// Computes the fingerprint of a byte sequence using a given fingerprint representation.
    ///
    /// This method computes a fingerprint the way OpenSSH does it and is generally being
    /// used to compute the fingerprint of an already encoded OpenSSH public key.
    ///
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// let fp = sshkeys::Fingerprint::compute(sshkeys::FingerprintKind::Sha256, "some data".as_bytes());
    /// assert_eq!(fp.kind, sshkeys::FingerprintKind::Sha256);
    /// assert_eq!(fp.hash, "EweZDmulyhRes16ZGCqb7EZTG8VN32VqYCx4D6AkDe4");
    /// ```
    pub fn compute<T: ?Sized + AsRef<[u8]>>(kind: FingerprintKind, data: &T) -> Fingerprint {
        let digest = match kind {
            FingerprintKind::Sha256 => Sha256::digest(&data.as_ref()).to_vec(),
            FingerprintKind::Sha384 => Sha384::digest(&data.as_ref()).to_vec(),
            FingerprintKind::Sha512 => Sha512::digest(&data.as_ref()).to_vec(),
        };

        let mut encoded = base64::encode(&digest);

        // Trim padding characters from end
        let hash = match encoded.find('=') {
            Some(offset) => encoded.drain(..offset).collect(),
            None => encoded,
        };

        let fp = Fingerprint {
            kind: kind,
            hash: hash,
        };

        fp
    }
}

impl PublicKey {
    /// Reads an OpenSSH public key from a given path.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn example() -> sshkeys::Result<()> {
    /// let key = sshkeys::PublicKey::from_path("/path/to/id_ed25519.pub")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<PublicKey> {
        let mut contents = String::new();
        File::open(path)?.read_to_string(&mut contents)?;

        PublicKey::from_string(&contents)
    }

    /// Reads an OpenSSH public key from a given string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use sshkeys;
    /// let key = sshkeys::PublicKey::from_string("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHkbe7gwx7s0dlApEEzpUyOAPrzPLy4czEZw/sh8m8rd me@home").unwrap();
    /// let fp = key.fingerprint();
    /// assert_eq!(fp.hash, "ciQkdxjFUhk2E2vRkWJD9kB8pi+EneOkaCJJHNWzPC4");
    /// ```
    pub fn from_string(contents: &str) -> Result<PublicKey> {
        let mut iter = contents.split_whitespace();

        let kt_name = iter
            .next()
            .ok_or(Error::with_kind(ErrorKind::InvalidFormat))?;

        let data = iter
            .next()
            .ok_or(Error::with_kind(ErrorKind::InvalidFormat))?;

        let comment = iter.next().map(|v| String::from(v));

        let kt = KeyType::from_name(&kt_name)?;

        let decoded = base64::decode(&data)?;
        let mut reader = Reader::new(&decoded);

        // Validate key type before reading rest of the data
        let kt_from_reader = reader.read_string()?;
        if kt_name != kt_from_reader {
            return Err(Error::with_kind(ErrorKind::KeyTypeMismatch));
        }

        // Construct a new `PublicKey` value and preserve the `comment` value.
        let k = PublicKey::from_reader(&kt_name, &mut reader)?;
        let key = PublicKey {
            key_type: kt,
            kind: k.kind,
            comment: comment,
        };

        Ok(key)
    }

    /// Reads a public key from a given byte sequence.
    ///
    /// The byte sequence is expected to be the base64 decoded body of the public key.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use sshkeys;
    /// let data = vec![0, 0, 0, 11, 115, 115, 104, 45,
    ///                 101, 100, 50, 53, 53, 49, 57,
    ///                 0, 0, 0, 32, 121, 27, 123, 184,
    ///                 48, 199, 187, 52, 118, 80, 41, 16,
    ///                 76, 233, 83, 35, 128, 62, 188,
    ///                 207, 47, 46, 28, 204, 70, 112,
    ///                 254, 200, 124, 155, 202, 221];
    ///
    /// let key = sshkeys::PublicKey::from_bytes(&data).unwrap();
    /// let fp = key.fingerprint();
    /// assert_eq!(fp.hash, "ciQkdxjFUhk2E2vRkWJD9kB8pi+EneOkaCJJHNWzPC4");
    /// ```
    pub fn from_bytes<T: ?Sized + AsRef<[u8]>>(data: &T) -> Result<PublicKey> {
        let mut reader = Reader::new(&data);
        let kt_name = reader.read_string()?;

        PublicKey::from_reader(&kt_name, &mut reader)
    }

    // This function is used for extracting a public key from an existing reader, e.g.
    // we already have a reader for reading an OpenSSH certificate key and
    // we want to extract the public key information from it.
    pub(crate) fn from_reader(kt_name: &str, reader: &mut Reader) -> Result<PublicKey> {
        let kt = KeyType::from_name(&kt_name)?;

        let kind = match kt.kind {
            KeyTypeKind::Rsa | KeyTypeKind::RsaCert => {
                let k = RsaPublicKey {
                    e: reader.read_mpint()?,
                    n: reader.read_mpint()?,
                };

                PublicKeyKind::Rsa(k)
            }
            KeyTypeKind::Ecdsa | KeyTypeKind::EcdsaCert => {
                let identifier = reader.read_string()?;
                let curve = Curve::from_identifier(&identifier)?;
                let key = reader.read_bytes()?;
                let k = EcdsaPublicKey {
                    curve: curve,
                    key: key,
                };

                PublicKeyKind::Ecdsa(k)
            }
            KeyTypeKind::Ed25519 | KeyTypeKind::Ed25519Cert => {
                let k = Ed25519PublicKey {
                    key: reader.read_bytes()?,
                };

                PublicKeyKind::Ed25519(k)
            }
        };

        let key = PublicKey {
            key_type: kt,
            kind: kind,
            comment: None,
        };

        Ok(key)
    }

    /// Returns the number of bits of the public key.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use sshkeys;
    /// let key = sshkeys::PublicKey::from_string("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHkbe7gwx7s0dlApEEzpUyOAPrzPLy4czEZw/sh8m8rd me@home").unwrap();
    /// assert_eq!(key.bits(), 256);
    /// ```
    pub fn bits(&self) -> usize {
        match self.kind {
            // For RSA public key the size of the key is the number of bits of the modulus
            PublicKeyKind::Rsa(ref k) => k.n.len() * 8,
            // ECDSA key size depends on the curve
            PublicKeyKind::Ecdsa(ref k) => match k.curve.kind {
                CurveKind::Nistp256 => 256,
                CurveKind::Nistp384 => 384,
                CurveKind::Nistp521 => 521,
            },
            // ED25519 key size is 256 bits
            // https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-03#section-5.5
            PublicKeyKind::Ed25519(_) => 256,
        }
    }

    /// Encodes the public key in an OpenSSH compatible format.
    ///
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// let key = sshkeys::PublicKey::from_string("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHkbe7gwx7s0dlApEEzpUyOAPrzPLy4czEZw/sh8m8rd me@home").unwrap();
    /// assert_eq!(key.encode(), vec![0, 0, 0, 11, 115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32, 121, 27, 123, 184, 48, 199, 187, 52, 118, 80, 41, 16, 76, 233, 83, 35, 128, 62, 188, 207, 47, 46, 28, 204, 70, 112, 254, 200, 124, 155, 202, 221]);
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();

        w.write_string(self.key_type.plain);
        match self.kind {
            PublicKeyKind::Rsa(ref k) => {
                w.write_mpint(&k.e);
                w.write_mpint(&k.n);
            }
            PublicKeyKind::Ecdsa(ref k) => {
                w.write_string(&k.curve.identifier);
                w.write_bytes(&k.key);
            }
            PublicKeyKind::Ed25519(ref k) => {
                w.write_bytes(&k.key);
            }
        }

        w.into_bytes()
    }

    /// Computes the fingerprint of the public key using the
    /// default OpenSSH fingerprint representation with SHA256.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use sshkeys;
    /// # fn example() -> sshkeys::Result<()> {
    /// let key = sshkeys::PublicKey::from_path("/path/to/id_ed25519.pub")?;
    /// let fp = key.fingerprint();
    /// println!("{}", fp.hash);
    /// # Ok(())
    /// # }
    /// ```
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint_with(FingerprintKind::Sha256)
    }

    /// Computes the fingerprint of the public key using a given
    /// fingerprint representation.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use sshkeys;
    /// # fn example() -> sshkeys::Result<()> {
    /// let key = sshkeys::PublicKey::from_path("/path/to/id_ed25519.pub").unwrap();
    /// let sha512fp = key.fingerprint_with(sshkeys::FingerprintKind::Sha512);
    /// println!("{}", sha512fp.hash);
    /// # Ok(())
    /// # }
    /// ```
    pub fn fingerprint_with(&self, kind: FingerprintKind) -> Fingerprint {
        Fingerprint::compute(kind, &self.encode())
    }

    /// Writes the public key to a given writer.
    ///
    /// # Example
    /// ```rust
    /// # use sshkeys;
    /// use std::fs::File;
    /// # fn example() -> sshkeys::Result<()> {
    /// let key = sshkeys::PublicKey::from_string("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...")?;
    /// let mut file = File::create("/path/to/id_ed25519.pub")?;
    /// key.write(&mut file).unwrap();
    /// # Ok(())
    /// # }
    /// ```
    pub fn write<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
        let encoded = self.encode();
        let data = base64::encode(&encoded);
        match self.comment {
            Some(ref c) => w.write_fmt(format_args!("{} {} {}\n", self.key_type.name, data, c)),
            None => w.write_fmt(format_args!("{} {}\n", self.key_type.name, data)),
        }
    }
}
