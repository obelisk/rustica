#[cfg(feature = "local-db")]
pub mod database;
pub mod external;

use crate::key::Key;

pub use super::key::KeyAttestation;

use rcgen::CustomExtension;
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
            AuthorizationError::NotAuthorized => write!(f, "Not authorized"),
            AuthorizationError::AuthorizerError => write!(f, "Authorization error"),
            AuthorizationError::ConnectionFailure => write!(f, "Could not connect to authorization service"),
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
pub struct SshAuthorization {
    pub serial: u64,
    pub valid_before: u64,
    pub valid_after: u64,
    pub principals: Vec<String>,
    pub hosts: Option<Vec<String>>,
    pub extensions: HashMap<String, String>,
    pub force_command: Option<String>,
    pub force_source_ip: bool,
    pub authority: String,
}

#[derive(Debug)]
pub struct SshAuthorizationRequestProperties {
    pub fingerprint: String,
    pub mtls_identities: Vec<String>,
    pub requester_ip: String,
    pub principals: Vec<String>,
    pub servers: Vec<String>,
    pub valid_before: u64,
    pub valid_after: u64,
    pub cert_type: CertType,
    pub authority: String,
}

#[derive(Debug)]
pub struct X509AuthorizationRequestProperties {
    pub authority: String,
    pub mtls_identities: Vec<String>,
    pub requester_ip: String,
    pub attestation: Vec<u8>,
    pub attestation_intermediate: Vec<u8>,
    pub key: Key,
}

#[derive(Debug)]
pub struct X509Authorization {
    pub authority: String,
    pub issuer: String,
    pub common_name: String,
    pub sans: Vec<String>,
    pub serial: i64,
    pub valid_before: u64,
    pub valid_after: u64,
    pub extensions: Vec<CustomExtension>,
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
    pub async fn authorize_ssh_cert(&self, auth_props: &SshAuthorizationRequestProperties) -> Result<SshAuthorization, AuthorizationError> {
        match &self {
            #[cfg(feature = "local-db")]
            AuthorizationMechanism::Local(local) => local.authorize_ssh_cert(auth_props),
            AuthorizationMechanism::External(external) => external.authorize_ssh_cert(auth_props).await,
        }
    }

    pub async fn authorize_x509_cert(&self, auth_props: &X509AuthorizationRequestProperties) -> Result<X509Authorization, AuthorizationError> {
        match &self {
            #[cfg(feature = "local-db")]
            AuthorizationMechanism::Local(local) => local.authorize_x509_cert(auth_props),
            AuthorizationMechanism::External(external) => external.authorize_x509_cert(auth_props).await,
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
