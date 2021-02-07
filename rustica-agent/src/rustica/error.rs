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
    InvalidURI,
    TransportBadStatus(tonic::Status),
    BadEncodedData(hex::FromHexError),
    RusticaServerError(ServerError)
}

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