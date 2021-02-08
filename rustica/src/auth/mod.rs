pub mod database;
pub mod external;

pub use database::LocalDatabase;
pub use external::AuthServer;

use sshcerts::ssh::{CertType, Extensions};

#[derive(Debug)]
pub enum AuthorizationError {
    CertType,
    NotAuthorized,
    AuthorizerError,
}

#[derive(Debug)]
pub struct Authorization {
    pub serial: u64,
    pub valid_before: u64,
    pub valid_after: u64,
    pub principals: Vec<String>,
    pub hosts: Option<Vec<String>>,
    pub extensions: Extensions,
    pub force_command: Option<String>,
    pub source_address: Option<String>,
}

#[derive(Debug)]
pub struct AuthorizationRequestProperties {
    pub fingerprint: String,
    pub requester_ip: String,
    pub principals: Vec<String>,
    pub servers: Vec<String>,
    pub valid_before: u64,
    pub valid_after: u64,
    pub cert_type: CertType,
}

pub enum AuthMechanism {
    Local(LocalDatabase),
    External(AuthServer),
}