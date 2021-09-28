#[macro_use]
extern crate log;

#[macro_use]
extern crate diesel;

mod auth;
mod config;
mod error;
mod key;
mod server;
mod signing;
mod utils;
mod yubikey;

use auth::AuthMechanism;
use rustica::rustica_server::{RusticaServer as GRPCRusticaServer};
use sshcerts::ssh::CertType;
use tonic::transport::{Certificate as TonicCertificate, Identity, Server, ServerTlsConfig};

pub mod rustica {
    tonic::include_proto!("rustica");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let settings = config::configure().await.unwrap();
    let identity = Identity::from_pem(settings.server_cert, settings.server_key);
    let client_ca_cert = TonicCertificate::from_pem(settings.client_ca_cert);

    let (user_ca_cert, host_ca_cert) = match (settings.server.signer.get_signer_public_key(CertType::User), settings.server.signer.get_signer_public_key(CertType::Host)) {
        (Ok(ucc), Ok(hcc)) => (ucc, hcc),
        (Err(e), _) => {
            error!("Could not fetch public key for user certificate signing: {:?}", e);
            // Make this error
            return Ok(());
        },
        (_, Err(e)) => {
            error!("Could not fetch public key for host certificate signing: {:?}", e);
            // Make this error
            return Ok(());
        }
    };

    println!("Starting Rustica on: {}", settings.address);
    info!("User CA Pubkey: {}", &user_ca_cert);
    println!("User CA Fingerprint (SHA256): {}", user_ca_cert.fingerprint().hash);

    info!("Host CA Pubkey: {}", &host_ca_cert);
    println!("Host CA Fingerprint (SHA256): {}", host_ca_cert.fingerprint().hash);

    match &settings.server.authorizer {
        AuthMechanism::Local(db) => println!("Authorization handled by local database at: {}", &db.path),
        AuthMechanism::External(e) => println!("Authorization handled by remote service at: {}", &e.server),
    }

    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity).client_ca_root(client_ca_cert))?
        .add_service(GRPCRusticaServer::new(settings.server))
        .serve(settings.address)
        .await?;

    Ok(())
}
