#[cfg(feature = "local-db")]
pub mod database;
pub mod external;

pub use super::key::KeyAttestation;

use sshcerts::ssh::CertType;

use serde::Deserialize;
use std::collections::HashMap;
use std::convert::TryInto;

#[derive(Debug)]
pub enum AuthorizationError {
    #[allow(dead_code)]
    CertType,
    NotAuthorized,
    AuthorizerError,
    ConnectionFailure,
    #[allow(dead_code)]
    DatabaseError(String),
    ExternalError(String),
}

impl std::fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorizationError::CertType => write!(f, "Not authorized for this certificate type"),
            AuthorizationError::NotAuthorized => write!(f, "Not authorized for this certificate type"),
            AuthorizationError::AuthorizerError => write!(f, "Not authorized for this certificate type"),
            AuthorizationError::ConnectionFailure => write!(f, "Not authorized for this certificate type"),
            AuthorizationError::DatabaseError(ref m) => write!(f, "Database error: {}", m),
            AuthorizationError::ExternalError(ref m) => write!(f, "{}", m),
        }
    }
}

#[derive(Deserialize)]
pub struct AuthorizationConfiguration {
    #[cfg(feature = "local-db")]
    pub database: Option<database::LocalDatabase>,
    pub external: Option<external::AuthServer>,
}

#[derive(Debug)]
pub struct Authorization {
    pub serial: u64,
    pub valid_before: u64,
    pub valid_after: u64,
    pub principals: Vec<String>,
    pub hosts: Option<Vec<String>>,
    pub extensions: HashMap<String, String>,
    pub force_command: Option<String>,
    pub force_source_ip: bool,
}

#[derive(Debug)]
pub struct AuthorizationRequestProperties {
    pub fingerprint: String,
    pub mtls_identities: Vec<String>,
    pub requester_ip: String,
    pub principals: Vec<String>,
    pub servers: Vec<String>,
    pub valid_before: u64,
    pub valid_after: u64,
    pub cert_type: CertType,
}

#[derive(Debug)]
pub struct RegisterKeyRequestProperties {
    pub fingerprint: String,
    pub mtls_identities: Vec<String>,
    pub requester_ip: String,
    pub attestation: Option<KeyAttestation>,
}

pub enum AuthorizationMechanism {
    #[cfg(feature = "local-db")]
    Local(database::LocalDatabase),
    External(external::AuthServer),
}

impl AuthorizationMechanism {
    pub async fn authorize(&self, auth_props: &AuthorizationRequestProperties) -> Result<Authorization, AuthorizationError> {
        match &self {
            #[cfg(feature = "local-db")]
            AuthorizationMechanism::Local(local) => local.authorize(auth_props),
            AuthorizationMechanism::External(external) => external.authorize(auth_props).await,
        }
    }

    pub async fn register_key(&self, register_properties: &RegisterKeyRequestProperties) -> Result<(), AuthorizationError> {
        match &self {
            #[cfg(feature = "local-db")]
            AuthorizationMechanism::Local(local) => local.register_key(register_properties),
            AuthorizationMechanism::External(external) => external.register_key(register_properties).await,
        }
    }

    pub fn info(&self) -> String {
        match &self {
            #[cfg(feature = "local-db")]
            AuthorizationMechanism::Local(local) => format!("Configured authorizer: Local DB at {}", &local.path),
            AuthorizationMechanism::External(external) => format!("Configured authorizer: Remote Service at {}", &external.server),
        }
    }
}

impl TryInto<AuthorizationMechanism> for AuthorizationConfiguration {
    type Error = ();
    fn try_into(self) -> Result<AuthorizationMechanism, ()> {
        #[cfg(feature = "local-db")]
        match (self.database, self.external) {
            (Some(database), None) => Ok(AuthorizationMechanism::Local(database)),
            (None, Some(external)) => Ok(AuthorizationMechanism::External(external)),
            _ => Err(()),
        }

        #[cfg(not(feature = "local-db"))]
        if let Some(external) = self.external {
            Ok(AuthorizationMechanism::External(external))
        } else {
            Err(())
        }
    }
}
