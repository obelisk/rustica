pub mod schema;
pub mod models;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use dotenv::dotenv;
use std::env;

use rustica_keys::ssh::{Extensions, CriticalOptions};

pub struct Authorization {
    pub users: Vec<String>,
    pub hosts: Vec<String>,
    pub unrestricted: bool,
    pub extensions: Extensions,
    pub critical_options: CriticalOptions,
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
    let users = {
        use schema::fingerprint_user_authorizations::dsl::*;
        let results = fingerprint_user_authorizations.filter(fingerprint.eq(fp))
            .load::<models::FingerprintUserAuthorization>(&conn)
            .expect("Error loading authorized hosts");
        
        results.into_iter().map(|x| x.username).collect()
    };

    let hosts = {
        use schema::fingerprint_host_authorizations::dsl::*;

        let results = fingerprint_host_authorizations.filter(fingerprint.eq(fp))
            .load::<models::FingerprintHostAuthorization>(&conn)
            .expect("Error loading authorized hosts");
        
        results.into_iter().map(|x| x.hostname).collect()
    };

    let unrestricted = {
        use schema::fingerprint_permissions::dsl::*;

        let results = fingerprint_permissions.filter(fingerprint.eq(fp))
            .load::<models::FingerprintPermission>(&conn)
            .expect("Error loading authorized hosts");
        
        if results.is_empty() {
            false
        } else {
            results[0].host_unrestricted
        }
    };

    // TODO @obelisk: Parse extensions and critical options correctly
    Authorization {
        users,
        hosts,
        unrestricted,
        extensions: Extensions::Standard,
        critical_options: CriticalOptions::None,
    }
    
}
