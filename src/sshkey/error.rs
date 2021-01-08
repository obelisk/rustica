use std::error::Error as StdError;
use std::{fmt, io, result, string};

use base64;

/// The `Error` type represents the possible errors that may occur when
/// working with OpenSSH keys.
#[derive(Debug)]
pub struct Error {
    pub(crate) kind: ErrorKind,
}

impl Error {
    pub(crate) fn with_kind(kind: ErrorKind) -> Error {
        Error { kind: kind }
    }
}

/// A type to represent the different kinds of errors.
#[derive(Debug)]
pub(crate) enum ErrorKind {
    Io(io::Error),
    Decode(base64::DecodeError),
    Utf8Error(string::FromUtf8Error),
    InvalidCertType(u32),
    InvalidFormat,
    UnexpectedEof,
    NotCertificate,
    KeyTypeMismatch,
    CertificateInvalidSignature,
    UnknownKeyType(String),
    UnknownCurve(String),
}

/// A `Result` type alias where the `Err` variant is `Error`
pub type Result<T> = result::Result<T, Error>;

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error {
            kind: ErrorKind::Io(error),
        }
    }
}

impl From<base64::DecodeError> for Error {
    fn from(error: base64::DecodeError) -> Error {
        Error {
            kind: ErrorKind::Decode(error),
        }
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(error: string::FromUtf8Error) -> Error {
        Error {
            kind: ErrorKind::Utf8Error(error),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self.kind {
            ErrorKind::Io(ref e) => e.source(),
            ErrorKind::Decode(ref e) => e.source(),
            ErrorKind::Utf8Error(ref e) => e.source(),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            ErrorKind::Io(ref err) => err.fmt(f),
            ErrorKind::Decode(ref err) => err.fmt(f),
            ErrorKind::Utf8Error(ref err) => err.fmt(f),
            ErrorKind::InvalidFormat => write!(f, "Invalid format"),
            ErrorKind::InvalidCertType(v) => write!(f, "Invalid certificate type with value {}", v),
            ErrorKind::UnexpectedEof => write!(f, "Unexpected EOF reached while reading data"),
            ErrorKind::NotCertificate => write!(f, "Not a certificate"),
            ErrorKind::KeyTypeMismatch => write!(f, "Key type mismatch"),
            ErrorKind::CertificateInvalidSignature => write!(f, "Certificate is improperly signed"),
            ErrorKind::UnknownKeyType(ref v) => write!(f, "Unknown key type {}", v),
            ErrorKind::UnknownCurve(ref v) => write!(f, "Unknown curve {}", v),
        }
    }
}
