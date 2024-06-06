use crate::auth::AuthorizationError;

#[derive(Debug)]
pub enum RusticaServerError {
    Success = 0,
    TimeExpired = 1,
    BadChallenge = 2,
    #[allow(dead_code)]
    InvalidKey = 3,
    #[allow(dead_code)]
    UnsupportedKeyType = 4,
    BadCertOptions = 5,
    NotAuthorized = 6,
    BadRequest = 7,
    PivClientCertTooBig = 8,
    PivIntermediateCertTooBig = 9,
    U2fAttestationTooBig = 10,
    U2fIntermediateCertTooBig = 11,
    Unknown = 9001,
}

impl From<AuthorizationError> for RusticaServerError {
    fn from(e: AuthorizationError) -> RusticaServerError {
        match e {
            AuthorizationError::CertType => RusticaServerError::BadCertOptions,
            AuthorizationError::NotAuthorized => RusticaServerError::NotAuthorized,
            _ => RusticaServerError::Unknown,
        }
    }
}
