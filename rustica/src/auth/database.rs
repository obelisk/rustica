pub mod schema;
pub mod models;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use dotenv::dotenv;
use std::env;
use std::time::SystemTime;
use super::{
    Authorization,
    AuthorizationError,
    AuthorizationRequestProperties,
    RegisterKeyRequestProperties,
};

use sshcerts::ssh::{CertType, Extensions};

pub struct LocalDatabase {}

fn establish_connection() -> SqliteConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
        SqliteConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

impl LocalDatabase {
    pub fn authorize(&self, req: &AuthorizationRequestProperties) -> Result<Authorization, AuthorizationError> {
        let fp = &req.fingerprint;
        let current_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(ts) => ts.as_secs(),
            // Start with E because in the case we do hit this, adding a time to it below
            // does not create an overflow
            Err(_e) => 0xEFFFFFFFFFFFFFFF,
        };

        let conn = establish_connection();
        let principals = {
            use schema::fingerprint_principal_authorizations::dsl::*;
            let results = fingerprint_principal_authorizations.filter(fingerprint.eq(fp))
                .load::<models::FingerprintPrincipalAuthorization>(&conn)
                .expect("Error loading authorized hosts");
            
            results.into_iter().map(|x| x.principal).collect()
        };

        let hosts = {
            use schema::fingerprint_host_authorizations::dsl::*;

            let results = fingerprint_host_authorizations.filter(fingerprint.eq(fp))
                .load::<models::FingerprintHostAuthorization>(&conn)
                .expect("Error loading authorized hosts");
            
            Some(results.into_iter().map(|x| x.hostname).collect())
        };

        {
            use schema::fingerprint_permissions::dsl::*;
            let results = fingerprint_permissions.filter(fingerprint.eq(fp))
                .load::<models::FingerprintPermission>(&conn)
                .expect("Error loading authorized hosts");
            
            if !results.is_empty() {
                match req.cert_type {
                    CertType::User => {
                        if !results[0].can_create_user_certs {
                            return Err(AuthorizationError::CertType)
                        }
                    },
                    CertType::Host => {
                        if !results[0].can_create_host_certs {
                            return Err(AuthorizationError::CertType)
                        }
                    }
                };
                Ok(Authorization {
                    serial: 0x000000000000000,
                    // When principal is unrestricted, we just pass their requested principals through
                    principals: if results[0].principal_unrestricted {req.principals.clone()} else {principals},
                    // When host is unrestricted we return None
                    hosts: if results[0].host_unrestricted {None} else {hosts},
                    extensions: Extensions::Standard,
                    force_command: None,
                    source_address: None,
                    valid_after: req.valid_after,
                    valid_before: current_timestamp + results[0].max_creation_time as u64,
                })
            } else {
                Err(AuthorizationError::NotAuthorized)
            }
        }
    }
    
    pub fn register_key(&self, req: &RegisterKeyRequestProperties) -> Result<bool, ()> {
        let connection = establish_connection();
        let mut registered_key = models::RegisteredKey {
            fingerprint: req.fingerprint.clone(),
            user: req.mtls_identities.join(","),
            firmware: None,
            hsm_serial: None,
            touch_policy: None,
            pin_policy: None,
        };

        if let Some(attestation) = &req.attestation {
            registered_key.firmware = Some(attestation.firmware.clone());
            registered_key.hsm_serial = Some(attestation.serial.to_string());
            registered_key.touch_policy = Some(attestation.touch_policy.to_string());
            registered_key.pin_policy = Some(attestation.pin_policy.to_string());
        }

        let result = {
            use schema::registered_keys::dsl::*;
            diesel::insert_into(registered_keys)
                .values(&registered_key)
                .execute(&connection)
        };

        match result {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
