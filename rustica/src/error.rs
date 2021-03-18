use crate::auth::AuthorizationError;
use std::convert::Into;

#[derive(Debug)]
pub enum RusticaServerError {
    Success = 0,
    TimeExpired = 1,
    BadChallenge = 2,
    InvalidKey = 3,
    UnsupportedKeyType = 4,
    BadCertOptions = 5,
    NotAuthorized = 6,
    BadRequest = 7,
    Unknown = 9001,
}

impl Into<RusticaServerError> for AuthorizationError {
    fn into(self) -> RusticaServerError {
        match self {
            AuthorizationError::CertType => RusticaServerError::BadCertOptions,
            AuthorizationError::NotAuthorized => RusticaServerError::NotAuthorized,
            AuthorizationError::AuthorizerError => RusticaServerError::Unknown,
        }
    }
}