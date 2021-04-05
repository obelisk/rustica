use std::fmt;
use std::error;

#[derive(Debug)]
pub struct ServerError {
    pub code: i64,
    pub message: String,
}

#[derive(Debug)]
pub enum RefreshError {
    TransportError,
    SigningError,
    UnsupportedMode,
    InvalidUri,
    ConfigurationError(String),
    TransportBadStatus(tonic::Status),
    BadEncodedData(hex::FromHexError),
    RusticaServerError(ServerError)
}


impl fmt::Display for RefreshError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RefreshError::ConfigurationError(ref err) => write!(f, "Configuration is invalid: {}", err),
            RefreshError::TransportError => write!(f, "Transport Error. Generally a TLS issue"),
            RefreshError::SigningError => write!(f, "Signing or verification failed"),
            RefreshError::UnsupportedMode => write!(f, "Attempted to use a curve or cipher not supported by rustica-agent"),
            RefreshError::InvalidUri => write!(f, "Provided address of remote service was invalid"),
            RefreshError::TransportBadStatus(ref err) => write!(f, "Bad status from server: {}", err),
            RefreshError::BadEncodedData(ref err) => write!(f, "Bad hex encoding: {}", err),
            RefreshError::RusticaServerError(ref err) => write!(f, "Error from server: {}", err.message)
        }
    }
}

impl error::Error for RefreshError {}

impl From<tonic::transport::Error> for RefreshError {
    fn from(e: tonic::transport::Error) -> Self {
        debug!("Transport Error: {}", e);
        RefreshError::TransportError
    }
}

impl From<tonic::Status> for RefreshError {
    fn from(e: tonic::Status) -> Self {
        RefreshError::TransportBadStatus(e)
    }
}

impl From<hex::FromHexError> for RefreshError {
    fn from(e: hex::FromHexError) -> Self {
        RefreshError::BadEncodedData(e)
    }
}

impl From<sshcerts::yubikey::Error> for RefreshError {
    fn from(_e: sshcerts::yubikey::Error) -> Self {
        RefreshError::SigningError
    }
}

impl From<ring::error::Unspecified> for RefreshError {
    fn from(_: ring::error::Unspecified) -> Self {
        RefreshError::SigningError
    }
}

impl From<ring::error::KeyRejected> for RefreshError {
    fn from(_: ring::error::KeyRejected) -> Self {
        RefreshError::SigningError
    }
}

