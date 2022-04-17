use super::{LoggingError, RusticaLogger, WrappedLog};

use reqwest;

use serde::Deserialize;
use std::time::Duration;

use tokio::runtime::Handle;

/// The struct that defines the Webhook specific configuration of the logging
/// service.
#[derive(Deserialize)]
pub struct Config {
    pub auth_header: Option<String>,
    pub url: String,
    pub timeout: u8,
}

/// The specific logger that is configured from the `Config` struct.
pub struct WebhookLogger {
    /// A tokio runtime to send logs on
    runtime: Handle,
    /// A reqwest client configured with the Splunk endpoint and authentication
    client: reqwest::Client,
    /// The configuration struct
    config: Config,
}


impl WebhookLogger {
    /// Implement the new function for the Splunk logger. This converts
    /// the configuration struct into a type that can handle sending
    /// logs directly to a Splunk HEC endpoint.
    pub fn new(config: Config, handle: Handle) -> Self {
        // I don't think this can fail with our settings so we do an unwrap
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout.into()))
            .build().unwrap();

        Self {
            runtime: handle,
            client,
            config,
        }
    }
}

impl RusticaLogger for WebhookLogger {
    /// Send a log to the webhook. Sending a log
    /// will not block sending logs to other services (like stdout) but it
    /// does mean we cannot return a proper LoggingError to the caller since
    /// we cannot wait for it to complete.
    fn send_log(&self, log: &WrappedLog) -> Result<(), LoggingError> {
        let data = match serde_json::to_string(&log) {
            Ok(json) => json,
            Err(e) => return Err(LoggingError::SerializationError(e.to_string()))
        };

        let res = self.client.post(&self.config.url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Content-Length", data.len())
            .body(data);
        
        let res = if let Some(auth) = &self.config.auth_header {
            res.header("Authorization", auth)
        } else {
            res
        };

        self.runtime.spawn(async move {
            match res.send().await {
                Ok(_) => (),
                Err(e) => error!("Could not log to webhook: {}", e.to_string()),
            };
        });

        Ok(())
    }
}