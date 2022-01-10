use super::{Log, RusticaLogger};

use influx_db_client::{
    Client, Point, Points, Precision, points
};

use tokio::runtime::Runtime;

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    address: String,
    database: String,
    user: String,
    password: String,
}

pub struct InfluxLogger {
    client: Client,
    runtime: Runtime
}

impl InfluxLogger {
    pub fn new(config: Config) -> Self {
        Self {
            client: Client::new(config.address.parse().unwrap(), config.database).set_authentication(config.user, config.password),
            runtime: Runtime::new().unwrap(),
        }
    }
}

impl RusticaLogger for InfluxLogger {
    fn send_log(&self, log: &Log) -> Result<(), ()> {
        let point = Point::new(&log.dataset)
            .add_tag("fingerprint", log.fingerprint.clone())
            .add_tag("mtls_identities", log.mtls_identities.join(","))
            .add_field("principals", log.principals.join(","))
            .add_field("hosts", log.hosts.join(","));

        let client = self.client.clone();
        self.runtime.spawn(async move {
            if let Err(e) = client.write_points(points!(point), Some(Precision::Seconds), None).await {
                error!("Could not log to influx DB: {}", e);
            }
        });  
        Ok(())
    }
}