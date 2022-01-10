use super::{Log, Severity};

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {}

pub struct StdoutLogger {}

impl StdoutLogger {
    pub fn new(_config: Config) -> Self {
        Self {}
    }

    pub fn send_log(&self, log: &Log) -> Result<(), ()> {
        match log.severity {
            Severity::Error => error!("{}", log.message),
            Severity::Warning => warn!("{}", log.message),
            Severity::Info => info!(
                "Action: [{}] For: [{}] Identified By: [{}] Access Requested For: [{}] On: [{}]",
                log.action,
                log.fingerprint,
                log.mtls_identities.join(", "),
                log.principals.join(", "),
                log.hosts.join(", "),
            ),
        }
        Ok(())
    }
}