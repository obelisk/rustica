use std::ffi::{c_char, CStr};
use std::os::unix::fs::PermissionsExt;

use crate::config::UpdatableConfiguration;
use crate::rustica::key::U2FAttestation;
use crate::{PIVAttestation, Signatory, YubikeySigner};

use sshcerts::error::Error as SSHCertsError;
use sshcerts::fido::generate::generate_new_ssh_key;
use sshcerts::fido::Error as FidoError;
use sshcerts::yubikey::piv::{AlgorithmId, PinPolicy, SlotId, TouchPolicy, Yubikey};
use std::fs::File;
use tokio::runtime::Runtime;

pub enum GenerateAndEnrollStatus {
    Success = 0,
    ConfigurationError = 1,
    ParameterError,
    PinRequired,
    KeyLocked,
    KeyBlocked,
    UnknownAttemptsRemaining,
    InternalError,
    KeyFileError,
    KeyRegistrationError,
}

#[no_mangle]
/// Generate and enroll a new FIDO key with a Rustica backend
///
/// # Safety
/// All c_char pointers passed to this function must be null terminated C
/// strings or undefined behaviour occurs possibly resulting in corruption
/// or crashes.
///
/// # Return
/// Returns a GenerateAndEnrollStatus enum cast to i64.
/// If the key fails to generate due to pin, a negative value representing the attempts remaining
/// is returned instead.
pub unsafe extern "C" fn ffi_generate_and_enroll_fido(
    config_path: *const c_char,
    out: *const c_char,
    comment: *const c_char,
    pin: *const c_char,
    device: *const c_char,
) -> i64 {
    let cf = CStr::from_ptr(config_path);
    let config_path = match cf.to_str() {
        Err(_) => return GenerateAndEnrollStatus::ConfigurationError as i64,
        Ok(s) => s,
    };

    let updatable_configuration = match UpdatableConfiguration::new(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration was invalid: {e}");
            return GenerateAndEnrollStatus::ConfigurationError as i64;
        }
    };

    let out = CStr::from_ptr(out);
    let out = match out.to_str() {
        Err(_) => return GenerateAndEnrollStatus::ParameterError as i64,
        Ok(s) => s,
    };

    let comment = if !comment.is_null() {
        let comment = CStr::from_ptr(comment);
        let comment = match comment.to_str() {
            Err(_) => return GenerateAndEnrollStatus::ParameterError as i64,
            Ok(s) => s,
        };
        comment.to_string()
    } else {
        "FFI-RusticaAgent-Generated-Key".to_string()
    };

    let pin = if !pin.is_null() {
        let pin = CStr::from_ptr(pin);
        let pin = match pin.to_str() {
            Err(_) => return GenerateAndEnrollStatus::ParameterError as i64,
            Ok(s) => s,
        };
        Some(pin.to_string())
    } else {
        None
    };

    let device = if !device.is_null() {
        let device = CStr::from_ptr(device);
        let device = match device.to_str() {
            Err(_) => return GenerateAndEnrollStatus::ParameterError as i64,
            Ok(s) => s,
        };
        Some(device.to_string())
    } else {
        None
    };

    let new_fido_key = match generate_new_ssh_key("ssh:", &comment, pin, device) {
        Ok(nfk) => nfk,
        Err(SSHCertsError::FidoError(FidoError::InvalidPin(Some(attempts)))) => {
            if attempts == 0 {
                return GenerateAndEnrollStatus::UnknownAttemptsRemaining as i64;
            }
            return -(attempts as i64);
        }
        Err(SSHCertsError::FidoError(FidoError::KeyLocked)) => {
            return GenerateAndEnrollStatus::KeyLocked as i64
        }
        Err(SSHCertsError::FidoError(FidoError::KeyBlocked)) => {
            return GenerateAndEnrollStatus::KeyBlocked as i64
        }
        Err(SSHCertsError::FidoError(FidoError::PinRequired)) => {
            return GenerateAndEnrollStatus::PinRequired as i64
        }
        Err(e) => {
            error!("Unknown Error: {e}");
            return GenerateAndEnrollStatus::InternalError as i64;
        }
    };

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        _ => return GenerateAndEnrollStatus::InternalError as i64,
    };

    let runtime_handle = runtime.handle().to_owned();

    let mut signatory = Signatory::Direct(new_fido_key.private_key.clone());
    let u2f_attestation = U2FAttestation {
        auth_data: new_fido_key.attestation.auth_data,
        auth_data_sig: new_fido_key.attestation.auth_data_sig,
        intermediate: new_fido_key.attestation.intermediate,
        challenge: new_fido_key.attestation.challenge,
        alg: new_fido_key.attestation.alg,
    };

    let mut out_file = match File::create(out) {
        Ok(f) => f,
        Err(e) => {
            error!("Error: Could not create keyfile at {}: {}", out, e);
            return GenerateAndEnrollStatus::KeyFileError as i64;
        }
    };

    if let Ok(md) = out_file.metadata() {
        let mut permissions = md.permissions();
        permissions.set_mode(0o600);
    } else {
        error!("Error: Could get file info {}", out);
        return GenerateAndEnrollStatus::KeyFileError as i64;
    };

    if new_fido_key.private_key.write(&mut out_file).is_err() {
        std::fs::remove_file(out).unwrap_or_default();
        error!("Error: Could not write to file. Basically should never happen");
        return GenerateAndEnrollStatus::KeyFileError as i64;
    };

    for server in &updatable_configuration.get_configuration().servers {
        match server.register_u2f_key(&mut signatory, "ssh:", &u2f_attestation, &runtime_handle) {
            Ok(_) => {
                println!(
                    "Key was successfully registered with server: {}",
                    server.address
                );
                return GenerateAndEnrollStatus::Success as i64;
            }
            Err(e) => {
                error!("Key could not be registered. Server said: {}", e);
            }
        }
    }

    std::fs::remove_file(out).unwrap();
    return GenerateAndEnrollStatus::KeyRegistrationError as i64;
}

/// Generate and enroll a new key on the given yubikey in the given slot
///
/// # Safety
/// Subject, config_path, and pin must all be valid, null terminated C strings
/// or this functions behaviour is undefined and will result in a crash.
#[no_mangle]
pub unsafe extern "C" fn generate_and_enroll(
    yubikey_serial: u32,
    slot: u8,
    touch_policy: u8,
    pin_policy: u8,
    subject: *const c_char,
    config_path: *const c_char,
    pin: *const c_char,
    management_key: *const c_char,
) -> bool {
    println!("Generating and enrolling a new key!");
    let cf = CStr::from_ptr(config_path);
    let config_path = match cf.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let updatable_configuration = match UpdatableConfiguration::new(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration was invalid: {e}");
            return false;
        }
    };

    let pin = CStr::from_ptr(pin);
    let management_key = CStr::from_ptr(management_key);
    let management_key = hex::decode(&management_key.to_str().unwrap()).unwrap();
    let subject = CStr::from_ptr(subject);

    let alg = AlgorithmId::EccP384;
    let slot = SlotId::try_from(slot).unwrap();

    let touch_policy = match touch_policy {
        0 => TouchPolicy::Never,
        1 => TouchPolicy::Cached,
        _ => TouchPolicy::Always,
    };

    let pin_policy = match pin_policy {
        0 => PinPolicy::Never,
        1 => PinPolicy::Once,
        _ => PinPolicy::Always,
    };

    let mut yk = Yubikey::open(yubikey_serial).unwrap();

    if yk
        .unlock(pin.to_str().unwrap().as_bytes(), &management_key)
        .is_err()
    {
        println!("Could not unlock key");
        return false;
    }

    let key_config = match yk.provision(
        &slot,
        subject.to_str().unwrap(),
        alg,
        touch_policy,
        pin_policy,
    ) {
        Ok(_) => {
            let certificate = yk.fetch_attestation(&slot);
            let intermediate = yk.fetch_certificate(&SlotId::Attestation);

            match (certificate, intermediate) {
                (Ok(certificate), Ok(intermediate)) => PIVAttestation {
                    certificate,
                    intermediate,
                },
                _ => return false,
            }
        }
        Err(_) => return false,
    };

    let mut signatory = Signatory::Yubikey(YubikeySigner {
        yk: yk.into(),
        slot,
    });

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        _ => return false,
    };

    let runtime_handle = runtime.handle().to_owned();

    for server in &updatable_configuration.get_configuration().servers {
        match server.register_key(&mut signatory, &key_config, &runtime_handle) {
            Ok(_) => {
                println!(
                    "Key was successfully registered with server: {}",
                    server.address
                );
                return true;
            }
            Err(e) => {
                error!("Key could not be registered. Server said: {}", e);
            }
        };
    }

    error!("All servers failed to register key");
    false
}
