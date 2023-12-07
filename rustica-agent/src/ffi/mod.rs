mod agent;
mod enrollment;
mod utils;
mod yubikey_utils;

use std::ffi::{c_char, c_long, CStr};

/// For functions related to starting (and stopping) RusticaAgent instances
pub use agent::*;

/// For generating and enrolling keys that will be used with RusticaAgent
pub use enrollment::*;

/// For functions that handle memory management and other utilities
pub use utils::*;

/// For functions that handle YubiKey specific functionality (generally PIV)
pub use yubikey_utils::*;

use crate::config::UpdatableConfiguration;

#[no_mangle]
/// Read a configuration file and return the expiry time of the primary server (the first one)
pub unsafe extern "C" fn ffi_get_expiry_of_primary_server(config_path: *const c_char) -> c_long {
    let cf = CStr::from_ptr(config_path);
    let config_path = match cf.to_str() {
        Err(_) => return -1,
        Ok(s) => s,
    };

    let updatable_configuration = match UpdatableConfiguration::new(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration was invalid: {e}");
            return GenerateAndEnrollStatus::ConfigurationError as i64;
        }
    };

    let server = match updatable_configuration.get_configuration().servers.first() {
        Some(s) => &s.mtls_cert,
        None => return -1,
    };

    match x509_parser::pem::parse_x509_pem(server.as_bytes()) {
        Err(_) => return -1,
        Ok((_, s)) => match s.parse_x509() {
            Err(_) => return -2,
            Ok(cert) => cert.validity().not_after.timestamp(),
        },
    }
}
