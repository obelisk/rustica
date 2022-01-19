#[macro_use]
extern crate log;

#[cfg(feature = "local-db")]
#[macro_use]
extern crate diesel;

mod auth;
mod config;
mod error;
mod key;
mod logging;
mod server;
mod signing;
mod utils;
mod yubikey;

use rustica::rustica_server::{RusticaServer as GRPCRusticaServer};
use sshcerts::ssh::CertType;
use tonic::transport::{Certificate as TonicCertificate, Identity, Server, ServerTlsConfig};

use std::thread;

pub mod rustica {
    tonic::include_proto!("rustica");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let settings = config::configure().await?;
    let identity = Identity::from_pem(settings.server_cert, settings.server_key);
    let client_ca_cert = TonicCertificate::from_pem(settings.client_ca_cert);

    let (user_ca_cert, host_ca_cert) = match (settings.server.signer.get_signer_public_key(CertType::User).await, settings.server.signer.get_signer_public_key(CertType::Host).await) {
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
    println!("User CA Fingerprint (SHA256): {}", user_ca_cert.fingerprint().hash);
    println!("Host CA Fingerprint (SHA256): {}", host_ca_cert.fingerprint().hash);
    println!("{}", settings.server.authorizer.info());

    let logging_configuration = settings.logging_configuration;
    let log_receiver = settings.log_receiver;

    thread::spawn(|| {
        logging::start_logging_thread(logging_configuration, log_receiver);
    });

    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity).client_ca_root(client_ca_cert))?
        .add_service(GRPCRusticaServer::new(settings.server))
        .serve(settings.address)
        .await?;

    Ok(())
}
