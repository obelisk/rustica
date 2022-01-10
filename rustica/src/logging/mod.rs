#[cfg(feature = "influx")]
mod influx;
#[cfg(feature = "splunk")]
mod splunk;
mod stdout;

use stdout::StdoutLogger;

use crossbeam_channel::Receiver;

use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Serialize)]
pub struct Log {
    /// The severity of the log message
    pub severity: Severity,
    /// Dataset this log belongs to
    pub dataset: String,
    /// Action taken this log pertains to
    pub action: String,
    /// The fingerprint of a related key
    pub fingerprint: String,
    /// The MTLS identities of the action taken
    pub mtls_identities: Vec<String>,
    /// The principals authorized for the request
    pub principals: Vec<String>,
    /// Hosts that were authorized
    pub hosts: Vec<String>,
    /// Extra data to be passed
    pub message: String,
}

#[derive(Deserialize)]
pub struct LoggingConfiguration {
    stdout: Option<stdout::Config>,
    #[cfg(feature = "influx")]
    influx: Option<influx::Config>,
    #[cfg(feature = "splunk")]
    splunk: Option<splunk::Config>,
}

/// To implement a new logger, it must implement the `send_log` function
/// and return success or failure.
pub trait RusticaLogger {
    fn send_log(&self, log: &Log) -> Result<(), ()>;
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
    while let Ok(log) = log_receiver.recv() {
        if let Some(logger) = &stdout_logger {
            logger.send_log(&log);
        }

        #[cfg(feature = "influx")]
        if let Some(logger) = &influx_logger {
            logger.send_log(&log);
        }

        #[cfg(feature = "splunk")]
        if let Some(logger) = &splunk_logger {
            logger.send_log(&log);
        }
    }

    error!("Logging thread has gone away.");
}
