use super::{Log, LoggingError, RusticaLogger};

use influx_db_client::{
    Client, Point, Points, Precision, points
};

use tokio::runtime::Runtime;

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    address: String,
    database: String,
    dataset: String,
    user: String,
    password: String,
}

pub struct InfluxLogger {
    client: Client,
    runtime: Runtime,
    dataset: String,
}

impl InfluxLogger {
    /// Create a new InfluxDB logger from the provided configuration
    pub fn new(config: Config) -> Self {
        Self {
            client: Client::new(config.address.parse().unwrap(), config.database).set_authentication(config.user, config.password),
            runtime: Runtime::new().unwrap(),
            dataset: config.dataset,
        }
    }
}

impl RusticaLogger for InfluxLogger {
    /// Sends a log to the configured InfluxDB database and dataset. This call
    /// happens asynchronous which has the benefit of not blocking the logging
    /// thread (meaning it will not hold out other loggers like stdout), but
    /// has the drawback that we cannot return a proper LoggingError on failure
    /// because we cannot wait for the call to complete.
    fn send_log(&self, log: &Log) -> Result<(), LoggingError> {
        match log {
            Log::CertificateIssued(ci) => {
                let point = Point::new(&self.dataset)
                .add_tag("fingerprint", ci.fingerprint.clone())
                .add_tag("mtls_identities", ci.mtls_identities.join(","))
                .add_field("principals", ci.principals.join(","));

                let client = self.client.clone();
                self.runtime.spawn(async move {
                    if let Err(e) = client.write_points(points!(point), Some(Precision::Seconds), None).await {
                        error!("Could not log to influx DB: {}", e);
                    }
                });  
            }
            Log::KeyRegistered(_kr) => (),
            Log::InternalMessage(_im) => (),
            Log::Heartbeat(_) => (),
        }
        Ok(())
    }
}