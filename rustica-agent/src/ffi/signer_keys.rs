use std::ffi::{c_char, CStr};
use std::fs::File;
use std::io::Write;

use crate::config::UpdatableConfiguration;

use tokio::runtime::Runtime;

pub enum GetAuthorizedSignerKeysStatus {
    Success = 0,
    ConfigurationError = 1,
    ParameterError,
    InternalError,
    AuthorizedSignerKeysFileError,
}

/// Request all authorized signer keys.
#[no_mangle]
pub unsafe extern "C" fn ffi_get_authorized_signer_keys(
    config_path: *const c_char,
    out_path: *const c_char,
) -> i64 {
    let cf = CStr::from_ptr(config_path);
    let config_path = match cf.to_str() {
        Ok(s) => s,
        Err(e) => {
            error!("Unable to marshall config_path to &str: {e}");
            return GetAuthorizedSignerKeysStatus::ConfigurationError as i64;
        },
    };

    let updatable_configuration = match UpdatableConfiguration::new(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration was invalid: {e}");
            return GetAuthorizedSignerKeysStatus::ConfigurationError as i64;
        },
    };

    let out_path = CStr::from_ptr(out_path);
    let out_path = match out_path.to_str() {
        Ok(s) => s,
        Err(e) => {
            error!("Unable to marshall out_path to &str: {e}");
            return GetAuthorizedSignerKeysStatus::ParameterError as i64;
        },
    };

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Unable to initialize tokio runtime: {e}");
            return GetAuthorizedSignerKeysStatus::InternalError as i64;
        },
    };
    let runtime_handle = runtime.handle().to_owned();

    let mut out_file = match File::create(out_path) {
        Ok(f) => f,
        Err(e) => {
            error!("Could not create authorized_signer_keys file at {}: {}", out_path, e);
            return GetAuthorizedSignerKeysStatus::AuthorizedSignerKeysFileError as i64;
        }
    };

    for server in &updatable_configuration.get_configuration().servers {
        let signer_keys = match server.get_all_signer_keys(&runtime_handle) {
            Ok(signer_keys) => {
                println!(
                    "Signer keys were successfully fetched from server: {}",
                    server.address
                );
                println!("{:?}", signer_keys);
                signer_keys
            }
            Err(e) => {
                error!("Signer keys could not be fetched. Server said: {}", e);
                continue;
            },
        };

        if let Err(e) = out_file.write_all(signer_keys.as_bytes()) {
            error!("Could not write to file {}: {}", out_path, e);
            return GetAuthorizedSignerKeysStatus::AuthorizedSignerKeysFileError as i64;
        }
    }

    GetAuthorizedSignerKeysStatus::InternalError as i64
}
