use crate::config::UpdatableConfiguration;
use std::{ffi::{c_char, CStr, CString}, ptr::null};

#[no_mangle]
/// Read the mTLS identities of the primary server (the first one) given a config path
pub unsafe extern "C" fn ffi_get_identities_of_primary_server(config_path: *const c_char) -> *const c_char {
    let cf = CStr::from_ptr(config_path);
    let config_path = match cf.to_str() {
        Err(_) => return null(),
        Ok(s) => s,
    };

    let updatable_configuration = match UpdatableConfiguration::new(config_path) {

        Ok(c) => c,
        Err(e) => {
            error!("Configuration was invalid: {e}");
            return null();
        }
    };

    let server = match updatable_configuration.get_configuration().servers.first() {
        Some(s) => &s.mtls_cert,
        None => return null(),
    };

    let cert = match x509_parser::pem::parse_x509_pem(server.as_bytes()) {
        Err(e) => {
            error!("Unable to parse mTLS cert PEM: {e}");
            return null();
        },
        Ok((_, s)) => s,
    };

    let subject = match cert.parse_x509() {
        Err(e) => {
            error!("Unable to parse mTLS cert: {e}");
            return null();
        },
        Ok(c) => c.tbs_certificate.subject().to_string(),
    };

    match CString::new(subject) {
        Err(e) => {
            error!("Unable to marshall subject to CString: {e}");
            return null();
        },
        Ok(s) => s.into_raw(),
    }
}
