#[cfg(feature = "influx")]
mod influx;
#[cfg(feature = "splunk")]
mod splunk;
mod stdout;

use crossbeam_channel::{Receiver, RecvTimeoutError};

use serde::{Deserialize, Serialize};

use std::collections::HashMap;
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
    /// The fingerprint of the signing certificate
    pub signed_by: String,
    /// Certificate type, either User or Host
    pub certificate_type: String,
    /// The MTLS identities of the action taken
    pub mtls_identities: Vec<String>,
    /// The principals authorized for the request
    pub principals: Vec<String>,
    /// Extensions present in issued certificate
    pub extensions: HashMap<String, String>,
    /// Critical Options present in the issued certificate
    pub critical_options: HashMap<String, String>,
    /// Validity period starts
    pub valid_after: u64,
    /// Validity period ends
    pub valid_before: u64,
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
    /// Represents the event of issuing a certificate. This happens whenever a
    /// user connects to a remote machine that uses Rustica and they need to
    /// refresh their certificate.
    CertificateIssued(CertificateIssued),
    /// A user has registered a new key with the Rustica system. This is
    /// emitted even if Rustica is not storing these keys locally and is
    /// only forwarding them on to an authorization service.
    KeyRegistered(KeyRegistered),
    /// Used for relaying status messages to a logging backend. Rustica errors
    /// or failures send messages of this type.
    InternalMessage(InternalMessage),
    /// Is not used by other components of Rustica. This is created and sent
    /// by the logging system if it has not received a message from the server
    /// module for a period of time.
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
    /// Returned when there is a failure serializing received logging data
    SerializationError(String),
    #[allow(dead_code)]
    /// Returned when there is a issue communicating with a backend or other
    /// remote system.
    CommunicationError(String),
}

/// To implement a new logger, it must implement the `send_log` function
/// and return success or failure.
pub trait RusticaLogger {
    fn send_log(&self, log: &Log) -> Result<(), LoggingError>;
}

/// This is the entry point of our logging thread started from main. This
/// should be running in its own thread waiting for logs to come in from
/// the tonic server. If it does not receive a message in 300 seconds it
/// will send a heartbeat message instead. For stdout, and influx, this is
/// a noop and will not actually be sent to the backend (or logged to the
/// screen).
pub fn start_logging_thread(config: LoggingConfiguration, log_receiver: Receiver<Log>) {
    // Configure the different loggers
    let stdout_logger = match config.stdout {
        Some(config) => {
            println!("Configured logger: stdout");
            Some(stdout::StdoutLogger::new(config))
        },
        None => {
            println!("stdout logger is not enabled. This is not recommended!");
            None
        },
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
