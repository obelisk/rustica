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
mod verification;

use rustica::rustica_server::RusticaServer as GRPCRusticaServer;
use tonic::transport::{Certificate as TonicCertificate, Identity, Server, ServerTlsConfig};

use std::thread;

use crate::config::ConfigurationError;

pub mod rustica {
    tonic::include_proto!("rustica");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let settings = match config::configure().await {
        Ok(settings) => settings,
        Err(ConfigurationError::ValidateOnly) => {
            println!("Configuration successfully validated");
            return Ok(());
        }
        Err(e) => return Err(e)?,
    };

    let identity = Identity::from_pem(settings.server_cert, settings.server_key);
    let client_ca_cert = TonicCertificate::from_pem(settings.client_ca_cert);

    println!("Starting Rustica on: {}", settings.address);
    println!("{}", settings.server.signer);
    println!("{}", settings.server.authorizer.info());

    let logging_configuration = settings.logging_configuration;
    let log_receiver = settings.log_receiver;

    thread::spawn(|| {
        logging::start_logging_thread(logging_configuration, log_receiver);
    });

    Server::builder()
        .tls_config(
            ServerTlsConfig::new()
                .identity(identity)
                .client_ca_root(client_ca_cert),
        )?
        .max_frame_size(1024 * 1024 * 4) // 4 MiB
        .add_service(GRPCRusticaServer::new(settings.server))
        .serve(settings.address)
        .await?;

    Ok(())
}
