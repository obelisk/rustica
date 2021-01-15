pub mod schema;
pub mod models;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use dotenv::dotenv;
use std::env;

fn establish_connection() -> SqliteConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
        SqliteConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

pub fn get_authorized_users(fp: &str) -> Vec<String> {
    let conn = establish_connection();
    use schema::fingerprint_user_authorizations::dsl::*;

    let results = fingerprint_user_authorizations.filter(fingerprint.eq(fp))
            .load::<models::FingerprintUserAuthorization>(&conn)
            .expect("Error loading authorized hosts");

    results.into_iter().map(|x| x.username).collect()
}