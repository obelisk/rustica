#[cfg(feature = "influx")]
mod influx;
#[cfg(feature = "splunk")]
mod splunk;
#[cfg(feature = "webhook")]
mod webhook;

mod stdout;

use crossbeam_channel::{Receiver, RecvTimeoutError};

use serde::{Deserialize, Serialize};
#[cfg(any(feature = "influx", feature = "splunk", feature = "webhook"))]
use tokio::runtime::Runtime;

use std::collections::HashMap;
use std::time::Duration;

/// A severity scale to measure how critical a log is when sent
/// to a logging service.
#[derive(Serialize)]
pub enum Severity {
    /// An informative log
    #[allow(dead_code)]
    Info,
    /// A non critical error
    Warning,
    /// A critical error
    Error,
}

/// A generic heartbeat message to keep external systems informed
/// that Rustica is still healthy
#[derive(Serialize)]
pub struct Heartbeat {}

/// Issued when a certificate request is granted to a user or host
#[derive(Serialize)]
pub struct CertificateIssued {
    /// The fingerprint of a related key
    pub fingerprint: String,
    /// The fingerprint of the signing certificate
    pub signed_by: String,
    /// The configured authority name for the signer
    pub authority: String,
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
pub struct KeyInfo {
    /// The fingerprint of a related key
    pub fingerprint: String,
    /// The MTLS identities of registree
    pub mtls_identities: Vec<String>,
}

/// Issued when a new key is registered with the service
#[derive(Serialize)]
pub struct KeyRegistrationFailure {
    pub key_info: KeyInfo,
    pub message: String,
}

/// Issued when errors or notable events occur within the system
#[derive(Serialize)]
pub struct InternalMessage {
    /// The severity of the log message
    pub severity: Severity,
    /// Extra data to be passed
    pub message: String,
}

/// Represents a log to be sent to the configured logging systems.
#[derive(Serialize)]
pub enum Log {
    /// Represents the event of issuing a certificate. This happens whenever a
    /// user connects to a remote machine that uses Rustica and they need to
    /// refresh their certificate.
    CertificateIssued(CertificateIssued),
    /// A user has registered a new key with the Rustica system. This is
    /// emitted even if Rustica is not storing these keys locally and is
    /// only forwarding them on to an authorization service.
    KeyRegistered(KeyInfo),
    /// When a user tries to register a new key but it fails for any reason.
    /// This could be due to an external authorizor denying (again for any reason
    /// it sees fit) or attestation/database errors.
    KeyRegistrationFailure(KeyRegistrationFailure),
    /// Used for relaying status messages to a logging backend. Rustica errors
    /// or failures send messages of this type.
    InternalMessage(InternalMessage),
    /// Is not used by other components of Rustica. This is created and sent
    /// by the logging system if it has not received a message from the server
    /// module for a period of time.
    Heartbeat(Heartbeat),
}

/// Logs are public to the rest of the codebase so we have no control over their
/// contents. This type wraps those logs in an additional structure to allow us
/// to add metadata relevant to the logging system or instance itself.
#[derive(Serialize)]
struct WrappedLog {
    /// The log sent from the server module
    log: Log,
    /// An identifier to identify this instance or configuration in redundant
    /// environments
    identifier: String,
}

/// Defines the complete logging configuration shape. This consists of some top
/// level options for configuring logging as a whole, then several optional sub
/// structs that configure individual logging systems.
#[derive(Deserialize)]
pub struct LoggingConfiguration {
    /// This is used as a decorator when sending logs to backends in the event
    /// that there are multiple Rustica instances in a single logging
    /// environment.
    identifier: Option<String>,
    /// If logs aren't received after this many seconds, the system will send an
    /// empty heartbeat log to the logging systems to signal it is still up
    /// and healthy.
    heartbeat_interval: Option<u64>,
    /// Configures the stdout logger. This is powered by env_logger and is a
    /// thin wrapper around it, however it lets us log to stdout the same way
    /// we log to other more complex systems.
    stdout: Option<stdout::Config>,
    /// Log to InfluxDB for timerseries logging. Generally this is used in
    /// conjuction with Grafana. The influx module contains more information
    /// on configuring this logger.
    #[cfg(feature = "influx")]
    influx: Option<influx::Config>,
    /// Log to Splunk for standard logging. The splunk module contains more
    /// information on configuring this logger.
    #[cfg(feature = "splunk")]
    splunk: Option<splunk::Config>,
    /// Log JSON to a POST endpoint. This is used for generic logging systems
    /// so it's easy to operate on Rustica events. It's likely in future the
    /// Splunk logger code will be a specific instantiation of this.
    #[cfg(feature = "webhook")]
    webhook: Option<webhook::Config>,
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
trait RusticaLogger {
    fn send_log(&self, log: &WrappedLog) -> Result<(), LoggingError>;
}

/// This is the entry point of our logging thread started from main. This
/// should be running in its own thread waiting for logs to come in from
/// the tonic server. If it does not receive a message in 300 seconds it
/// will send a heartbeat message instead. For stdout, and influx, this is
/// a noop and will not actually be sent to the backend (or logged to the
/// screen).
pub fn start_logging_thread(config: LoggingConfiguration, log_receiver: Receiver<Log>) {
    #[cfg(any(feature = "influx", feature = "splunk", feature = "webhook"))]
    let runtime = Runtime::new().unwrap();
    let heartbeat_interval = config.heartbeat_interval.unwrap_or(300);
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
            Some(influx::InfluxLogger::new(config, runtime.handle().clone()))
        },
        None => None,
    };

    #[cfg(feature = "splunk")]
    let splunk_logger = match config.splunk {
        Some(config) => {
            println!("Configured logger: splunk");
            Some(splunk::SplunkLogger::new(config, runtime.handle().clone()))
        },
        None => None,
    };

    #[cfg(feature = "webhook")]
    let webhook_logger = match config.webhook {
        Some(config) => {
            println!("Configured logger: webhook");
            Some(webhook::WebhookLogger::new(config, runtime.handle().clone()))
        },
        None => None,
    };

    // Main logging loop
    loop {
        let log = match log_receiver.recv_timeout(Duration::from_secs(heartbeat_interval)) {
            Ok(l) => l,
            Err(RecvTimeoutError::Timeout) => Log::Heartbeat(Heartbeat {}),
            _ => break,
        };

        let log = WrappedLog {
            log,
            identifier: config.identifier.clone().unwrap_or_default(),
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

        #[cfg(feature = "webhook")]
        if let Some(logger) = &webhook_logger {
            if let Err(_) = logger.send_log(&log) {
                error!("Could not send logs to webhook");
            }
        }
    }

    error!("Logging thread has gone away.");
}
