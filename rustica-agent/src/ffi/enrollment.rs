use std::ffi::{c_char, CStr};
use std::os::unix::fs::PermissionsExt;

use crate::config::UpdatableConfiguration;
use crate::rustica::key::U2FAttestation;
use crate::{PIVAttestation, Signatory, YubikeySigner};

use sshcerts::error::Error as SSHCertsError;
use sshcerts::fido::generate::generate_new_ssh_key;
use sshcerts::fido::Error as FidoError;
use sshcerts::yubikey::piv::{PinPolicy, SlotId, TouchPolicy, Yubikey};
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
    YubikeyCommunicationError,
    ManagementKeyError,
    ProvisionError,
    AttestationError,
}

/// Shared by `generate_and_enroll` and `enroll_existing_piv`: decode the hex
/// management key and slot id parameters, logging which one was invalid.
unsafe fn parse_piv_args(
    slot: u8,
    management_key: *const c_char,
) -> Result<(SlotId, Vec<u8>), i64> {
    let management_key = CStr::from_ptr(management_key);
    let management_key = match management_key
        .to_str()
        .ok()
        .and_then(|s| hex::decode(s).ok())
    {
        Some(k) => k,
        None => {
            error!("Management key was not valid UTF-8 hex");
            return Err(GenerateAndEnrollStatus::ManagementKeyError as i64);
        }
    };

    let slot = match SlotId::try_from(slot) {
        Ok(s) => s,
        Err(_) => {
            error!("Invalid slot id: {slot}");
            return Err(GenerateAndEnrollStatus::ParameterError as i64);
        }
    };

    Ok((slot, management_key))
}

/// Shared by `generate_and_enroll` and `enroll_existing_piv`: unlock the
/// YubiKey, mapping an unlock failure to a status code that either reports
/// the PIV PIN attempts remaining (negative) or that the key is blocked.
fn unlock_or_pin_status(yk: &mut Yubikey, pin: &str, management_key: &[u8]) -> Result<(), i64> {
    if let Err(e) = yk.unlock(pin.as_bytes(), management_key) {
        error!("Could not unlock key: {e}");
        return Err(match yk.yk.get_pin_retries() {
            Ok(0) => GenerateAndEnrollStatus::KeyBlocked as i64,
            Ok(n) => -(n as i64),
            Err(_) => GenerateAndEnrollStatus::UnknownAttemptsRemaining as i64,
        });
    }
    Ok(())
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

    let mut signatory = Signatory::Direct(new_fido_key.private_key.clone().into());
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
///
/// # Return
/// Returns a GenerateAndEnrollStatus enum cast to i64.
/// If the key fails to generate due to pin, a negative value representing the
/// attempts remaining is returned instead.
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
) -> i64 {
    println!("Generating and enrolling a new key!");
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

    let pin = CStr::from_ptr(pin);
    let pin = match pin.to_str() {
        Err(_) => {
            error!("PIN was not valid UTF-8");
            return GenerateAndEnrollStatus::ParameterError as i64;
        }
        Ok(s) => s,
    };

    let subject = CStr::from_ptr(subject);
    let subject = match subject.to_str() {
        Err(_) => {
            error!("Subject was not valid UTF-8");
            return GenerateAndEnrollStatus::ParameterError as i64;
        }
        Ok(s) => s,
    };

    let (slot, management_key) = match parse_piv_args(slot, management_key) {
        Ok(args) => args,
        Err(status) => return status,
    };

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

    let mut yk = match Yubikey::open(yubikey_serial) {
        Ok(yk) => yk,
        Err(e) => {
            error!("Could not open YubiKey: {e}");
            return GenerateAndEnrollStatus::YubikeyCommunicationError as i64;
        }
    };

    if let Err(status) = unlock_or_pin_status(&mut yk, pin, &management_key) {
        return status;
    }

    let key_config = match yk.provision_p384(&slot, subject, touch_policy, pin_policy) {
        Ok(_) => {
            let certificate = yk.fetch_attestation(&slot);
            let intermediate = yk.fetch_certificate(&SlotId::Attestation);

            match (certificate, intermediate) {
                (Ok(certificate), Ok(intermediate)) => PIVAttestation {
                    certificate,
                    intermediate,
                },
                _ => return GenerateAndEnrollStatus::AttestationError as i64,
            }
        }
        Err(e) => {
            error!("Could not provision key: {e}");
            return GenerateAndEnrollStatus::ProvisionError as i64;
        }
    };

    let mut signatory = Signatory::Yubikey(YubikeySigner::new(yk, slot));

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        _ => return GenerateAndEnrollStatus::InternalError as i64,
    };

    let runtime_handle = runtime.handle().to_owned();

    for server in &updatable_configuration.get_configuration().servers {
        match server.register_key(&mut signatory, &key_config, &runtime_handle) {
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
        };
    }

    error!("All servers failed to register key");
    GenerateAndEnrollStatus::KeyRegistrationError as i64
}

/// Enroll an already-provisioned key in the given slot with the Rustica server.
/// Exports the existing key's attestation and registers it; no touch_policy/
/// pin_policy argument is needed since the server reads those from the
/// attestation.
///
/// # Safety
/// config_path, pin, and management_key must all be valid, null terminated C
/// strings or this function's behaviour is undefined and will result in a crash.
///
/// # Return
/// Returns a GenerateAndEnrollStatus enum cast to i64.
/// If the key fails to unlock due to pin, a negative value representing the
/// attempts remaining is returned instead.
#[no_mangle]
pub unsafe extern "C" fn enroll_existing_piv(
    yubikey_serial: u32,
    slot: u8,
    config_path: *const c_char,
    pin: *const c_char,
    management_key: *const c_char,
) -> i64 {
    println!("Enrolling an existing key!");
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

    let pin = CStr::from_ptr(pin);
    let pin = match pin.to_str() {
        Err(_) => {
            error!("PIN was not valid UTF-8");
            return GenerateAndEnrollStatus::ParameterError as i64;
        }
        Ok(s) => s,
    };

    let (slot, management_key) = match parse_piv_args(slot, management_key) {
        Ok(args) => args,
        Err(status) => return status,
    };

    let mut yk = match Yubikey::open(yubikey_serial) {
        Ok(yk) => yk,
        Err(e) => {
            error!("Could not open YubiKey: {e}");
            return GenerateAndEnrollStatus::YubikeyCommunicationError as i64;
        }
    };

    if let Err(status) = unlock_or_pin_status(&mut yk, pin, &management_key) {
        return status;
    }

    // Export the attestation of the key already living in the slot — no
    // provisioning happens here, so the existing keypair is left untouched.
    let certificate = yk.fetch_attestation(&slot);
    let intermediate = yk.fetch_certificate(&SlotId::Attestation);

    let key_config = match (certificate, intermediate) {
        (Ok(certificate), Ok(intermediate)) => PIVAttestation {
            certificate,
            intermediate,
        },
        _ => {
            error!("Could not export attestation for slot {slot:?}. Is it provisioned and attestable (not imported)?");
            return GenerateAndEnrollStatus::AttestationError as i64;
        }
    };

    let mut signatory = Signatory::Yubikey(YubikeySigner::new(yk, slot));

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        _ => return GenerateAndEnrollStatus::InternalError as i64,
    };

    let runtime_handle = runtime.handle().to_owned();

    for server in &updatable_configuration.get_configuration().servers {
        match server.register_key(&mut signatory, &key_config, &runtime_handle) {
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
        };
    }

    error!("All servers failed to register key");
    GenerateAndEnrollStatus::KeyRegistrationError as i64
}

#[no_mangle]
// Provision a new nistp384 key in the given slot
pub unsafe extern "C" fn provision_piv(
    yubikey_serial: u32,
    slot: u8,
    touch_policy: u8,
    subject: *const c_char,
    pin: *const c_char,
    management_key: *const c_char,
) -> bool {
    let slot = SlotId::try_from(slot).unwrap();

    println!("Provisioning new PIV key in slot {:?}", slot);

    let pin = CStr::from_ptr(pin);
    let management_key = CStr::from_ptr(management_key);
    let management_key = hex::decode(&management_key.to_str().unwrap()).unwrap();
    let subject = CStr::from_ptr(subject);

    let policy = match touch_policy {
        0 => TouchPolicy::Never,
        1 => TouchPolicy::Cached,
        _ => TouchPolicy::Always,
    };

    let mut yk = Yubikey::open(yubikey_serial).unwrap();

    if yk
        .unlock(pin.to_str().unwrap().as_bytes(), &management_key)
        .is_err()
    {
        println!("Could not unlock key");
        return false;
    }

    yk.provision_p384(&slot, subject.to_str().unwrap(), policy, PinPolicy::Never)
        .is_ok()
}
