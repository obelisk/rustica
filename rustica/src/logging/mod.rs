#[cfg(feature = "influx")]
mod influx;
#[cfg(feature = "splunk")]
mod splunk;
mod stdout;

use stdout::StdoutLogger;

use crossbeam_channel::{Receiver, RecvTimeoutError};

use serde::{Deserialize, Serialize};

use std::time::Duration;

#[derive(Serialize)]
pub enum Severity {
    #[allow(dead_code)]
    Info,
    Warning,
    Error,
}

/// A generic heartbeat message to keep external systems informed
/// that Rustica is still healthy
#[derive(Serialize)]
pub struct Heartbeat {
    /// Can be used to identify this particular instance in redundant
    /// environments
    pub identifier: String,
}

/// Issued when a certificate request is granted to a user or host
#[derive(Serialize)]
pub struct CertificateIssued {
    /// The fingerprint of a related key
    pub fingerprint: String,
    /// The MTLS identities of the action taken
    pub mtls_identities: Vec<String>,
    /// The principals authorized for the request
    pub principals: Vec<String>,
    /// Hosts that were authorized
    pub hosts: Vec<String>,
}

/// Issued when a new key is registered with the service
#[derive(Serialize)]
pub struct KeyRegistered {
    /// The fingerprint of a related key
    pub fingerprint: String,
    /// The MTLS identities of registree
    pub mtls_identities: Vec<String>,
}

/// Issued when errors or notable events occur within the system
#[derive(Serialize)]
pub struct InternalMessage {
    /// The severity of the log message
    pub severity: Severity,
    /// Extra data to be passed
    pub message: String,
}


#[derive(Serialize)]
pub enum Log {
    CertificateIssued(CertificateIssued),
    KeyRegistered(KeyRegistered),
    InternalMessage(InternalMessage),
    Heartbeat(Heartbeat),
}

#[derive(Deserialize)]
pub struct LoggingConfiguration {
    stdout: Option<stdout::Config>,
    #[cfg(feature = "influx")]
    influx: Option<influx::Config>,
    #[cfg(feature = "splunk")]
    splunk: Option<splunk::Config>,
}

#[derive(Debug)]
pub enum LoggingError {
    #[allow(dead_code)]
    SerializationError(String),
    #[allow(dead_code)]
    CommunicationError(String),
}

/// To implement a new logger, it must implement the `send_log` function
/// and return success or failure.
pub trait RusticaLogger {
    fn send_log(&self, log: &Log) -> Result<(), LoggingError>;
}

pub fn start_logging_thread(config: LoggingConfiguration, log_receiver: Receiver<Log>) {
    // Configure the different loggers
    let stdout_logger = match config.stdout {
        Some(config) => {
            println!("Configured logger: stdout");
            Some(StdoutLogger::new(config))
        },
        None => None,
    };

    #[cfg(feature = "influx")]
    let influx_logger = match config.influx {
        Some(config) => {
            println!("Configured logger: influx");
            Some(influx::InfluxLogger::new(config))
        },
        None => None,
    };

    #[cfg(feature = "splunk")]
    let splunk_logger = match config.splunk {
        Some(config) => {
            println!("Configured logger: splunk");
            Some(splunk::SplunkLogger::new(config))
        },
        None => None,
    };

    // Main logging loop
    loop {
        let log = match log_receiver.recv_timeout(Duration::from_secs(300)) {
            Ok(l) => l,
            Err(RecvTimeoutError::Timeout) => Log::Heartbeat(Heartbeat {identifier: format!("")}),
            _ => break,
        };

        if let Some(logger) = &stdout_logger {
            logger.send_log(&log).unwrap();
        }

        #[cfg(feature = "influx")]
        if let Some(logger) = &influx_logger {
            if let Err(_) = logger.send_log(&log) {
                error!("Could not send logs to InfluxDB");
            }
        }

        #[cfg(feature = "splunk")]
        if let Some(logger) = &splunk_logger {
            if let Err(_) = logger.send_log(&log) {
                error!("Could not send logs to Splunk");
            }
        }
    }

    error!("Logging thread has gone away.");
}
