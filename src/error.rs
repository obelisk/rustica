#[derive(Debug)]
pub enum RusticaServerError {
    Success = 0,
    TimeExpired = 1,
    BadChallenge = 2,
    InvalidKey = 3,
    UnsupportedKeyType = 4,
    BadCertOptions = 5,
    NoAuthorizations = 6,
    Unknown = 9001,
}