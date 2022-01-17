use super::{Log, LoggingError, RusticaLogger, Severity};

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {}

pub struct StdoutLogger {}

impl StdoutLogger {
    pub fn new(_config: Config) -> Self {
        Self {}
    }
}

impl RusticaLogger for StdoutLogger {
    fn send_log(&self, log: &Log) -> Result<(), LoggingError> {
        match log {
            Log::CertificateIssued(ci) => {
                info!(
                    "Certificate issued for: [{}] Identified by: [{}] Principals granted: [{}] On hosts: [{}]",
                    ci.fingerprint,
                    ci.mtls_identities.join(", "),
                    ci.principals.join(", "),
                    ci.hosts.join(", "),
                )
            }
            Log::KeyRegistered(kr) => info!("Key registered with fingerprint: [{}] Identified by: [{}]", kr.fingerprint, kr.mtls_identities.join(", ")),
            Log::InternalMessage(im) => match im.severity {
                Severity::Error => error!("{}", im.message),
                Severity::Warning => warn!("{}", im.message),
                Severity::Info => info!("{}", im.message),
            },
            Log::Heartbeat(_) => (),
        }
        Ok(())
    }
}