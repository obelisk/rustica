use std::ffi::{c_char, c_int, c_long, CStr, CString};

use sshcerts::yubikey::piv::{RetiredSlotId, SlotId, Yubikey};
use tokio::runtime::Runtime;

use crate::{config::UpdatableConfiguration, list_yubikey_serials, Signatory, YubikeySigner};

/// Check if the device path will require a pin to generate a new key
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn ffi_does_device_need_pin(device: *const c_char) -> i32 {
    let device_path = if !device.is_null() {
        let device = CStr::from_ptr(device);
        match device.to_str() {
            Err(_) => return -1,
            Ok(s) => s.to_owned(),
        }
    } else {
        return -1;
    };

    match sshcerts::fido::device_requires_pin(&device_path) {
        Ok(true) => return 1,
        Ok(false) => return 0,
        Err(e) => {
            println!("Could not determine if pin is needed: {e}");
            return -1;
        }
    }
}

/// Check if the device path will require a pin to generate a new key
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn ffi_device_pin_retries(device: *const c_char) -> i32 {
    let device_path = if !device.is_null() {
        let device = CStr::from_ptr(device);
        match device.to_str() {
            Err(_) => return -1,
            Ok(s) => s.to_owned(),
        }
    } else {
        return -1;
    };

    match sshcerts::fido::device_pin_retries(&device_path) {
        Ok(x) => return x,
        Err(e) => {
            println!("Could find how many pin retries are available: {e}");
            return -1;
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn unlock_yubikey(
    yubikey_serial: *const c_int,
    pin: *const c_char,
    management_key: *const c_char,
) -> c_int {
    let mut yk = match Yubikey::open(yubikey_serial as u32) {
        Ok(yk) => yk,
        Err(e) => {
            println!("Could not connect to Yubikey: {e}");
            return -1;
        }
    };

    let pin = if !pin.is_null() {
        let pin = CStr::from_ptr(pin);
        let pin = match pin.to_str() {
            Err(_) => return -2,
            Ok(s) => s,
        };
        pin.to_string()
    } else {
        return -6;
    };

    let management_key = if !management_key.is_null() {
        let management_key = CStr::from_ptr(management_key);
        let management_key = match management_key.to_str() {
            Err(_) => return -2,
            Ok(s) => s,
        };

        match hex::decode(management_key) {
            Ok(s) => s,
            Err(_) => {
                println!("Invalid management key");
                return -3;
            }
        }
    } else {
        return -4;
    };

    match yk.unlock(pin.as_bytes(), &management_key) {
        Ok(_) => 0,
        Err(e) => {
            println!("Error unlocking key: {e}");
            return yk.yk.get_pin_retries().map(|x| x as i32).unwrap_or(-9);
        }
    }
}

/// Fetch the list of serial numbers for the connected Yubikeys
/// The return from this function must be freed by the caller because we can no longer track it
/// once we return
///
/// # Safety
/// out_length must be a valid pointer to an 8 byte segment of memory
#[no_mangle]
pub unsafe extern "C" fn list_yubikeys(out_length: *mut c_int) -> *const c_long {
    match list_yubikey_serials() {
        Ok(serials) => {
            let len = serials.len();
            let ptr = serials.as_ptr();
            std::mem::forget(serials);
            std::ptr::write(out_length, len as c_int);

            ptr
        }
        Err(e) => {
            println!("{:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Free the list of Yubikey Serial Numbers
///
/// # Safety
/// This function must be passed the raw vector returned by `list_yubikeys`
/// otherwise the behaviour is undefined and will result in a crash.
#[no_mangle]
pub unsafe extern "C" fn free_list_yubikeys(length: c_int, yubikeys: *mut c_long) {
    let len = length as usize;

    // Get back our vector.
    // Previously we shrank to fit, so capacity == length.
    let _ = Vec::from_raw_parts(yubikeys, len, len);
}

/// The return from this function must be freed by the caller because we can no longer track it
/// once we return
///
/// # Safety
/// out_length must be a valid pointer to an 8 byte segment of memory
#[no_mangle]
pub unsafe extern "C" fn list_keys(
    yubikey_serial: u32,
    out_length: *mut c_int,
) -> *mut *mut c_char {
    match &mut Yubikey::open(yubikey_serial) {
        Ok(yk) => {
            let mut keys = vec![];
            for slot in 0x82..0x96_u8 {
                let slot = SlotId::Retired(RetiredSlotId::try_from(slot).unwrap());
                if let Ok(subj) = yk.fetch_subject(&slot) {
                    keys.push(CString::new(format!("{:?} - {}", slot, subj)).unwrap())
                }
            }

            let mut out = keys.into_iter().map(|s| s.into_raw()).collect::<Vec<_>>();
            out.shrink_to_fit();

            let len = out.len();
            let ptr = out.as_mut_ptr();
            std::mem::forget(out);
            std::ptr::write(out_length, len as c_int);

            // Finally return the data
            ptr
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// The return from this function must be freed by the caller because we can no longer track it
/// once we return
#[no_mangle]
pub extern "C" fn check_yubikey_slot_provisioned(yubikey_serial: u32, slot_id: u8) -> bool {
    match &mut Yubikey::open(yubikey_serial) {
        Ok(yk) => match SlotId::try_from(slot_id) {
            Ok(slot) => yk.fetch_subject(&slot).is_ok(),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

/// The return from this function must be freed by the caller because we can no longer track it
/// once we return
#[no_mangle]
pub extern "C" fn check_yubikey_slot_certificate_expiry(yubikey_serial: u32, slot_id: u8) -> u64 {
    let (mut yk, slot) = match (Yubikey::open(yubikey_serial), SlotId::try_from(slot_id)) {
        (Ok(yk), Ok(slot)) => (yk, slot),
        _ => return 0,
    };

    let cert = match yk.fetch_certificate(&slot) {
        Ok(cert) => cert,
        Err(_) => return 0,
    };

    match x509_parser::parse_x509_certificate(&cert) {
        Ok((_, cert)) => cert.tbs_certificate.validity.not_after.timestamp() as u64,
        Err(_) => 0,
    }
}

/// Free the list of Yubikey keys
///
/// # Safety
/// This function must be passed the raw vector returned by `list_keys`
/// otherwise the behaviour is undefined and will result in a crash.
#[no_mangle]
pub unsafe extern "C" fn free_list_keys(length: c_int, keys: *mut *mut c_char) {
    let len = length as usize;

    // Get back our vector.
    // Previously we shrank to fit, so capacity == length.
    let v = Vec::from_raw_parts(keys, len, len);

    // Now drop one string at a time.
    for elem in v {
        let s = CString::from_raw(elem);
        std::mem::drop(s);
    }
}

/// Fetch a string that will configure a git repository for code
/// signing under the given key
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn ffi_get_git_config_string_from_serial_and_slot(
    serial: u32,
    slot: u8,
) -> *const c_char {
    let public_key = match &mut Yubikey::open(serial) {
        Ok(yk) => {
            let slot = match RetiredSlotId::try_from(slot) {
                Ok(s) => SlotId::Retired(s),
                Err(_) => return std::ptr::null(),
            };

            match yk.ssh_cert_fetch_pubkey(&slot) {
                Ok(pk) => pk,
                Err(_) => return std::ptr::null(),
            }
        }
        Err(_) => return std::ptr::null(),
    };

    let git_config = match CString::new(crate::git_config_from_public_key(&public_key)) {
        Ok(c) => c,
        Err(_) => return std::ptr::null(), // Happens if the string contains a null byte. Should never happen but better to handle than not
    };

    git_config.into_raw()
}

/// Refresh and load a new certificate onto a yubikey
///
/// # Safety
/// Subject, config_path, and pin must all be valid, null terminated C strings
/// or this functions behaviour is undefined and will result in a crash.
#[no_mangle]
pub unsafe extern "C" fn ffi_refresh_x509_certificate(
    yubikey_serial: u32,
    slot: u8,
    config_path: *const c_char,
    pin: *const c_char,
    management_key: *const c_char,
) -> bool {
    println!("Refreshing certificate!");
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

    let slot = SlotId::try_from(slot).unwrap();
    let mut yk = Yubikey::open(yubikey_serial).unwrap();

    if yk
        .unlock(pin.to_str().unwrap().as_bytes(), &management_key)
        .is_err()
    {
        println!("Could not unlock key");
        return false;
    }

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
        match server.refresh_x509_certificate(&mut signatory, &runtime_handle) {
            Ok(c) => {
                println!("Certificate was issued from server: {}", server.address);
                let mut yk = Yubikey::open(yubikey_serial).unwrap();
                yk.unlock(pin.to_str().unwrap().as_bytes(), &management_key)
                    .unwrap();
                if yk.write_certificate(&slot, &c).is_err() {
                    error!("Could not write certificate to yubikey");
                    return false;
                } else {
                    return true;
                }
            }
            Err(e) => {
                error!("Certificate could not be issued. Server said: {}", e);
            }
        };
    }

    error!("All servers failed to issue a certificate");
    false
}
