use std::ffi::{c_char, CStr};
use std::fs::File;
use std::io::Write;

use crate::config::UpdatableConfiguration;

use tokio::runtime::Runtime;

pub enum GetAllowedSignersStatus {
    Success = 0,
    ConfigurationError = 1,
    ParameterError,
    InternalError,
    AllowedSignersFileError,
}

/// Request all allowed signers
#[no_mangle]
pub unsafe extern "C" fn ffi_get_allowed_signers(
    config_path: *const c_char,
    out_path: *const c_char,
) -> i32 {
    let cf = CStr::from_ptr(config_path);
    let config_path = match cf.to_str() {
        Ok(s) => s,
        Err(e) => {
            error!("Unable to marshall config_path to &str: {e}");
            return GetAllowedSignersStatus::ConfigurationError as i32;
        },
    };

    let updatable_configuration = match UpdatableConfiguration::new(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration was invalid: {e}");
            return GetAllowedSignersStatus::ConfigurationError as i32;
        },
    };

    let out_path = CStr::from_ptr(out_path);
    let out_path = match out_path.to_str() {
        Ok(s) => s,
        Err(e) => {
            error!("Unable to marshall out_path to &str: {e}");
            return GetAllowedSignersStatus::ParameterError as i32;
        },
    };

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Unable to initialize tokio runtime: {e}");
            return GetAllowedSignersStatus::InternalError as i32;
        },
    };
    let runtime_handle = runtime.handle().to_owned();

    let mut out_file = match File::create(out_path) {
        Ok(f) => f,
        Err(e) => {
            error!("Could not create Allowed Signers file at {}: {}", out_path, e);
            return GetAllowedSignersStatus::AllowedSignersFileError as i32;
        }
    };

    for server in &updatable_configuration.get_configuration().servers {
        let allowed_signers = match server.get_allowed_signers(&runtime_handle) {
            Ok(data) => {
                println!(
                    "Allowed signers were successfully fetched from server: {}",
                    server.address
                );
                data
            }
            Err(e) => {
                error!("Allowed signers could not be fetched. Server said: {}", e);
                continue;
            },
        };

        match out_file.write_all(allowed_signers.as_bytes()) {
            Ok(()) => return GetAllowedSignersStatus::Success as i32,
            Err(e) => {
                error!("Could not write to file {}: {}", out_path, e);
                return GetAllowedSignersStatus::AllowedSignersFileError as i32;
            },
        }
    }

    GetAllowedSignersStatus::InternalError as i32
}
