pub mod schema;
pub mod models;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use dotenv::dotenv;
use std::env;

use sshcerts::ssh::{Extensions, CriticalOptions};

pub struct Permissions {
    pub host_unrestricted: bool,
    pub principal_unrestricted: bool,
    pub can_create_host_certs: bool,
    pub can_create_user_certs: bool,
    pub max_creation_time: u32,
}

pub struct Authorization {
    pub principals: Vec<String>,
    pub hosts: Vec<String>,
    pub extensions: Extensions,
    pub critical_options: CriticalOptions,
    pub permissions: Permissions,
}

fn establish_connection() -> SqliteConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
        SqliteConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

pub fn get_fingerprint_authorization(fp: &str) -> Authorization {
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
        
        results.into_iter().map(|x| x.hostname).collect()
    };

    let permissions = {
        use schema::fingerprint_permissions::dsl::*;

        let results = fingerprint_permissions.filter(fingerprint.eq(fp))
            .load::<models::FingerprintPermission>(&conn)
            .expect("Error loading authorized hosts");
        
        if !results.is_empty() {
            Permissions {
                host_unrestricted: results[0].host_unrestricted,
                principal_unrestricted: results[0].principal_unrestricted,
                can_create_host_certs: results[0].can_create_host_certs,
                can_create_user_certs: results[0].can_create_user_certs,
                max_creation_time: results[0].max_creation_time as u32,
            }
        } else {
            Permissions {
                host_unrestricted: false,
                principal_unrestricted: false,
                can_create_host_certs: false,
                can_create_user_certs: false,
                max_creation_time: 10,
            }
        }
    };

    // TODO @obelisk: Parse extensions and critical options correctly
    Authorization {
        principals,
        hosts,
        extensions: Extensions::Standard,
        critical_options: CriticalOptions::None,
        permissions,
    }
    
}
