use super::{Log, RusticaLogger};

use reqwest;

use serde::{Deserialize, Serialize};
use std::time::Duration;

use tokio::runtime::Runtime;


#[derive(Deserialize)]
pub struct Config {
    pub token: String,
    pub url: String,
    pub timeout: u8,
}

pub struct SplunkLogger {
    runtime: Runtime,
    client: reqwest::Client,
    token: String,
    url: String,
}


/// Splunk needs it in the format of the whole log within the event key
/// This uses a lifetime because it only contains a reference to a gauntlet
/// log allowing us to skip a clone into this struct.
#[derive(Clone, Serialize)]
struct SplunkLogWrapper<'a> {
    event: &'a Log
}


impl SplunkLogger {
    pub fn new(config: Config) -> Self {
        // I don't think this can fail with our settings so we do an unwrap
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(config.timeout.into()))
            .build().unwrap();

        Self {
            runtime: Runtime::new().unwrap(),
            client,
            token: config.token.clone(),
            url: config.url.clone(),
        }
    }
}

impl RusticaLogger for SplunkLogger {
    fn send_log(&self, log: &Log) -> Result<(), ()> {
        let splunk_log = SplunkLogWrapper {event: log};

        let data = match serde_json::to_string(&splunk_log) {
            Ok(json) => json,
            Err(e) => {
                error!("Could not serialize event to send to splunk: {}", e);
                return Err(());
            }
        };

        let res = self.client.post(&self.url)
            .header("Authorization", format!("Splunk {}", &self.token))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Content-Length", data.len())
            .body(data);

        self.runtime.spawn(async move {
            match res.send().await {
                Ok(resp) => trace!("Sent Log: {:?}", resp),
                Err(e) => error!("Could not send log: {:?}", e),
            };
        });  
        Ok(())
    }
}