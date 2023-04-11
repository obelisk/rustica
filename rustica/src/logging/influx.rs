use super::{Log, LoggingError, RusticaLogger, WrappedLog};

use influxdb::InfluxDbWriteable;
use influxdb::{Client, Timestamp};

use tokio::runtime::Handle;

use serde::Deserialize;

use std::time::{SystemTime, UNIX_EPOCH};

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
    runtime: Handle,
    dataset: String,
}

impl InfluxLogger {
    /// Create a new InfluxDB logger from the provided configuration
    pub fn new(config: Config, handle: Handle) -> Self {
        Self {
            client: Client::new(config.address, config.database)
                .with_auth(config.user, config.password),
            runtime: handle,
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
    fn send_log(&self, log: &WrappedLog) -> Result<(), LoggingError> {
        match &log.log {
            Log::CertificateIssued(ci) => {
                let start = SystemTime::now();
                let timestamp = start
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards");

                let point_query = Timestamp::Seconds(timestamp.as_secs().into())
                    .into_query(&self.dataset)
                    .add_tag("fingerprint", ci.fingerprint.clone())
                    .add_tag("mtls_identities", ci.mtls_identities.join(","))
                    .add_field("principals", ci.principals.join(","));

                let client = self.client.clone();

                self.runtime.spawn(async move {
                    if let Err(e) = client.query(point_query).await {
                        error!("Could not send log to Influx: {}", e);
                    }
                });
            }
            Log::KeyRegistered(_kr) => (),
            Log::KeyRegistrationFailure(_krf) => (),
            Log::InternalMessage(_im) => (),
            Log::Heartbeat(_) => (),
            Log::X509CertificateIssued(_) => (),
        }
        Ok(())
    }
}
