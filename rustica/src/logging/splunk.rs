use super::{LoggingError, RusticaLogger, WrappedLog};

use reqwest;

use serde::{Deserialize, Serialize};
use std::time::Duration;

use tokio::runtime::Runtime;

/// The struct that defines the Splunk specific configuration of the logging
/// service.
#[derive(Deserialize)]
pub struct Config {
    pub token: String,
    pub url: String,
    pub timeout: u8,
}

/// The Splunk specific logger that is configured from the Splunk
/// `Config` struct.
pub struct SplunkLogger {
    /// A tokio runtime to send logs on
    runtime: Runtime,
    /// A reqwest client configured with the Splunk endpoint and authentication
    client: reqwest::Client,
    /// An API token to send with our logs for authentication
    token: String,
    /// The endpoint to send the logs to
    url: String,
}


/// Splunk needs it in the format of the whole log within the event key
/// This uses a lifetime because it only contains a reference to a gauntlet
/// log allowing us to skip a clone into this struct.
#[derive(Clone, Serialize)]
struct SplunkLogWrapper<'a> {
    /// Splunk requires this specific structure when sending logs so we have
    /// to wrap again unfortunately to get the entire log in the event field
    /// of the JSON.
    event: &'a WrappedLog
}

impl SplunkLogger {
    /// Implement the new function for the Splunk logger. This converts
    /// the configuration struct into a type that can handle sending
    /// logs directly to a Splunk HEC endpoint.
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
    /// Send a log to Splunk via an HEC endpoint. This function uses a tokio
    /// runtime within the SplunkLogger type. This means that sending a log
    /// will not block sending logs to other services (like stdout) but it
    /// does mean we cannot return a proper LoggingError to the caller since
    /// we cannot wait for it to complete.
    fn send_log(&self, log: &WrappedLog) -> Result<(), LoggingError> {
        let splunk_log = SplunkLogWrapper {event: log};

        let data = match serde_json::to_string(&splunk_log) {
            Ok(json) => json,
            Err(e) => return Err(LoggingError::SerializationError(e.to_string()))
        };

        let res = self.client.post(&self.url)
            .header("Authorization", format!("Splunk {}", &self.token))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Content-Length", data.len())
            .body(data);

        self.runtime.spawn(async move {
            match res.send().await {
                Ok(_) => (),
                Err(e) => error!("Could not log to Splunk: {}", e.to_string()),
            };
        });

        Ok(())
    }
}