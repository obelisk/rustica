use super::{Log, LoggingError, RusticaLogger, Severity, WrappedLog};

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
    fn send_log(&self, log: &WrappedLog) -> Result<(), LoggingError> {
        match &log.log {
            Log::CertificateIssued(ci) => {
                info!(
                    "[{}] Certificate issued for: [{}] Authority: [{}] Identified by: [{}] Principals granted: [{}] Extensions: [{:?}] CriticalOptions: [{:?}] Valid After: [{}] Valid Before: [{}]",
                    ci.certificate_type,
                    ci.fingerprint,
                    ci.authority,
                    ci.mtls_identities.join(", "),
                    ci.principals.join(", "),
                    ci.extensions,
                    ci.critical_options,
                    ci.valid_after,
                    ci.valid_before,
                )
            }
            Log::KeyRegistered(kr) => info!("Key registered: [{}] Identified by: [{}]", kr.fingerprint, kr.mtls_identities.join(", ")),
            Log::KeyRegistrationFailure(krf) => info!("Failed to register key: [{}] Identified by: [{}]", krf.key_info.fingerprint, krf.key_info.mtls_identities.join(", ")),
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