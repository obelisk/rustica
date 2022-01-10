mod influx;
mod splunk;
mod stdout;

use stdout::StdoutLogger;
use influx::InfluxLogger;

use crossbeam_channel::Receiver;

use serde::Deserialize;

pub enum Severity {
    Error,
    Warning,
    Info,
}

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
    influx: Option<influx::Config>,
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

    let influx_logger = match config.influx {
        Some(config) => {
            println!("Configured logger: influx");
            Some(InfluxLogger::new(config))
        },
        None => None,
    };

    // Main logging loop
    while let Ok(log) = log_receiver.recv() {
        if let Some(logger) = &stdout_logger {
            logger.send_log(&log);
        }

        if let Some(logger) = &influx_logger {
            logger.send_log(&log);
        }
    }

    error!("Logging thread has gone away.");
}