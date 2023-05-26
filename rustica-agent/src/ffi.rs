pub use crate::sshagent::{error::Error as AgentError, Agent, Identity, Response, SshAgentHandler};
use crate::{
    config::{parse_config, Config, UpdatableConfiguration},
    list_yubikey_serials, CertificateConfig, Handler, Signatory, YubikeyPIVKeyDescriptor,
    YubikeySigner,
};

pub use crate::rustica::{
    key::PIVAttestation,
    RefreshError::{ConfigurationError, SigningError},
};

use crate::rustica::key::U2FAttestation;

use sshcerts::fido::generate::generate_new_ssh_key;
use sshcerts::ssh::PrivateKey;
use sshcerts::yubikey::piv::{AlgorithmId, PinPolicy, RetiredSlotId, SlotId, TouchPolicy, Yubikey};
use tokio::{
    runtime::Runtime,
    sync::mpsc::{channel, Sender},
};

use std::fs::File;
use std::{collections::HashMap, os::unix::prelude::PermissionsExt};
use std::{convert::TryFrom, slice};

// FFI related imports
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_long};

pub struct RusticaAgentInstance {
    runtime: Runtime,
    shutdown_sender: Sender<()>,
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

#[no_mangle]
/// Generate and enroll a new FIDO key with a Rustica backend
///
/// # Safety
/// All c_char pointers passed to this function must be null terminated C
/// strings or undefined behaviour occurs possibly resulting in corruption
/// or crashes.
pub unsafe extern "C" fn generate_and_enroll_fido(
    config_data: *const c_char,
    out: *const c_char,
    comment: *const c_char,
    pin: *const c_char,
    device: *const c_char,
) -> bool {
    let cf = CStr::from_ptr(config_data);
    let config: Config = match cf.to_str() {
        Err(_) => return false,
        Ok(s) => match parse_config(s) {
            Ok(c) => c,
            Err(e) => {
                error!("Error: Could not parse the configuration data: {}", e);
                return false;
            }
        },
    };

    let out = CStr::from_ptr(out);
    let out = match out.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let comment = if !comment.is_null() {
        let comment = CStr::from_ptr(comment);
        let comment = match comment.to_str() {
            Err(_) => return false,
            Ok(s) => s,
        };
        comment.to_string()
    } else {
        "FFI-RusticaAgent-Generated-Key".to_string()
    };

    let pin = if !pin.is_null() {
        let pin = CStr::from_ptr(pin);
        let pin = match pin.to_str() {
            Err(_) => return false,
            Ok(s) => s,
        };
        Some(pin.to_string())
    } else {
        None
    };

    let device = if !device.is_null() {
        let device = CStr::from_ptr(device);
        let device = match device.to_str() {
            Err(_) => return false,
            Ok(s) => s,
        };
        Some(device.to_string())
    } else {
        None
    };

    let new_fido_key = match generate_new_ssh_key("ssh:RusticaAgentFIDOKey", &comment, pin, device)
    {
        Ok(nfk) => nfk,
        Err(e) => {
            println!("Error: {}", e);
            return false;
        }
    };

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        _ => return false,
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
            println!("Error: Could not create keyfile at {}: {}", out, e);
            return false;
        }
    };

    if let Ok(md) = out_file.metadata() {
        let mut permissions = md.permissions();
        permissions.set_mode(0o600);
    } else {
        println!("Error: Could get file info {}", out);
        return false;
    };

    if new_fido_key.private_key.write(&mut out_file).is_err() {
        std::fs::remove_file(out).unwrap_or_default();
        println!("Error: Could not write to file. Basically should never happen");
        return false;
    };

    for server in config.servers {
        match server.register_u2f_key(&mut signatory, "ssh:RusticaAgentFIDOKey", &u2f_attestation, &runtime_handle) {
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
        }
    }

    std::fs::remove_file(out).unwrap();
    false
}

/// Generate and enroll a new key on the given yubikey in the given slot
///
/// # Safety
/// Subject, config_data, and pin must all be valid, null terminated C strings
/// or this functions behaviour is undefined and will result in a crash.
#[no_mangle]
pub unsafe extern "C" fn generate_and_enroll(
    yubikey_serial: u32,
    slot: u8,
    touch_policy: u8,
    pin_policy: u8,
    subject: *const c_char,
    config_data: *const c_char,
    pin: *const c_char,
    management_key: *const c_char,
) -> bool {
    println!("Generating and enrolling a new key!");
    let cf = CStr::from_ptr(config_data);
    let config_data = match cf.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let pin = CStr::from_ptr(pin);
    let management_key = CStr::from_ptr(management_key);
    let management_key = hex::decode(&management_key.to_str().unwrap()).unwrap();
    let subject = CStr::from_ptr(subject);

    let config: Config = match parse_config(config_data) {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration was invalid: {e}");
            return false;
        }
    };

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

    let mut signatory = Signatory::Yubikey(YubikeySigner { yk, slot });

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        _ => return false,
    };

    let runtime_handle = runtime.handle().to_owned();

    for server in config.servers {
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

/// Start a new Rustica instance. Does not return unless Rustica exits.
/// # Safety
/// `config_data` and `socket_path` must be a null terminated C strings
/// or behaviour is undefined and will result in a crash.
#[no_mangle]
pub unsafe extern "C" fn start_direct_rustica_agent(
    private_key: *const c_char,
    config_data: *const c_char,
    socket_path: *const c_char,
    pin: *const c_char,
    device: *const c_char,
    notification_fn: unsafe extern "C" fn() -> (),
    authority: *const c_char,
    certificate_priority: bool,
) -> *const RusticaAgentInstance {
    return start_direct_rustica_agent_with_piv_idents(
        private_key,
        config_data,
        socket_path,
        pin,
        device,
        notification_fn,
        authority,
        certificate_priority,
        std::ptr::null(),
        std::ptr::null(),
        std::ptr::null(),
        0,
    );
}

/// Start a new Rustica instance. Does not return unless Rustica exits.
/// # Safety
/// `config_data` and `socket_path` must be a null terminated C strings
/// or behaviour is undefined and will result in a crash.
#[no_mangle]
pub unsafe extern "C" fn start_direct_rustica_agent_with_piv_idents(
    private_key: *const c_char,
    config_path: *const c_char,
    socket_path: *const c_char,
    pin: *const c_char,
    device: *const c_char,
    notification_fn: unsafe extern "C" fn() -> (),
    authority: *const c_char,
    certificate_priority: bool,
    piv_serials: *const c_long,
    piv_slots: *const u8,
    piv_pins: *const c_long,
    piv_key_count: c_int,
) -> *const RusticaAgentInstance {
    println!("Starting a new Rustica instance!");

    let notification_f = move || {
        notification_fn();
    };

    let cf = CStr::from_ptr(config_path);
    let config_path = match cf.to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s,
    };

    let updatable_configuration = match UpdatableConfiguration::new(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration was invalid: {e}");
            return std::ptr::null();
        }
    };

    let sp = CStr::from_ptr(socket_path);
    let socket_path = match sp.to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s.to_owned(),
    };

    println!("Socket path: {socket_path}");

    let authority = CStr::from_ptr(authority);
    let authority = match authority.to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s.to_owned(),
    };

    let private_key = CStr::from_ptr(private_key);
    let mut private_key = match private_key.to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => {
            if let Ok(p) = PrivateKey::from_string(s) {
                p
            } else {
                return std::ptr::null();
            }
        }
    };

    if !pin.is_null() {
        let pin = CStr::from_ptr(pin);
        let pin = match pin.to_str() {
            Err(_) => return std::ptr::null(),
            Ok(s) => s.to_owned(),
        };
        private_key.set_pin(&pin);
    }

    if !device.is_null() {
        let device = CStr::from_ptr(device);
        let device = match device.to_str() {
            Err(_) => return std::ptr::null(),
            Ok(s) => s.to_owned(),
        };

        private_key.set_device_path(&device);
    }

    let piv_key_count = piv_key_count as usize;
    let key_serials: Vec<u32> = slice::from_raw_parts(piv_serials, piv_key_count)
        .into_iter()
        .map(|x| *x as u32)
        .collect();

    let piv_pins: Vec<Option<String>> = slice::from_raw_parts(piv_pins, piv_key_count)
        .into_iter()
        .map(|x| {
            let pin = *x as u32;
            if pin != 0 {
                Some(pin.to_string())
            } else {
                None
            }
        })
        .collect();

    let mut key_slots = vec![];

    for maybe_slot in slice::from_raw_parts(piv_slots, piv_key_count) {
        match SlotId::try_from(*maybe_slot) {
            Ok(s) => key_slots.push(s),
            Err(_) => return std::ptr::null(),
        };
    }

    let mut piv_identities = HashMap::new();
    for ((serial, slot), pin) in key_serials
        .into_iter()
        .zip(key_slots.into_iter())
        .zip(piv_pins.into_iter())
    {
        let mut yk = match Yubikey::open(serial) {
            Ok(yk) => yk,
            Err(_) => return std::ptr::null(),
        };

        let pubkey = match yk.ssh_cert_fetch_pubkey(&slot) {
            Ok(pk) => pk,
            Err(_) => return std::ptr::null(),
        };

        let subject = yk.fetch_subject(&slot).unwrap_or_default();

        piv_identities.insert(
            pubkey.encode().to_vec(),
            YubikeyPIVKeyDescriptor {
                public_key: pubkey,
                serial,
                slot,
                pin,
                subject,
            },
        );
    }

    println!("Fingerprint: {:?}", private_key.pubkey.fingerprint().hash);

    println!("Additional Fingerprints:");
    for key in piv_identities.iter() {
        println!("{}", key.1.public_key.fingerprint().hash);
    }

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        _ => return std::ptr::null(),
    };

    let mut certificate_options = CertificateConfig::from(updatable_configuration.get_configuration().options.clone());
    certificate_options.authority = authority;

    let handler = Handler {
        updatable_configuration,
        cert: None,
        stale_at: 0,
        pubkey: private_key.pubkey.clone(),
        certificate_options,
        signatory: Signatory::Direct(private_key),
        identities: HashMap::new(),
        piv_identities,
        notification_function: Some(Box::new(notification_f)),
        certificate_priority,
    };

    let (shutdown_sender, shutdown_receiver) = channel::<()>(1);

    runtime.spawn(async move {
        Agent::run_with_termination_channel(
            handler,
            socket_path.to_string(),
            Some(shutdown_receiver),
        )
        .await;
        println!("Rustica Agent has shutdown");
    });

    let agent_instance = Box::new(RusticaAgentInstance {
        runtime,
        shutdown_sender,
    });

    let agent_instance_pointer: *const RusticaAgentInstance = Box::leak(agent_instance);

    agent_instance_pointer
}

#[no_mangle]
pub unsafe extern "C" fn shutdown_rustica_agent(rai: *mut RusticaAgentInstance) -> bool {
    let rustica_agent_instance = Box::from_raw(rai);
    let shutdown_sender = rustica_agent_instance.shutdown_sender.clone();
    rustica_agent_instance.runtime.spawn(async move {
        shutdown_sender.send(()).await.unwrap();
        println!("Sent shutdown message");
    });

    true
}

/// Start a new Rustica instance. Does not return unless Rustica exits.
/// # Safety
/// `config_data` and `socket_path` must be a null terminated C strings
/// or behaviour is undefined and will result in a crash.
#[no_mangle]
pub unsafe extern "C" fn start_yubikey_rustica_agent(
    yubikey_serial: u32,
    slot: u8,
    config_path: *const c_char,
    socket_path: *const c_char,
    notification_fn: unsafe extern "C" fn() -> (),
    authority: *const c_char,
    certificate_priority: bool,
) -> *const RusticaAgentInstance {
    println!("Starting a new Rustica instance!");

    let notification_f = move || {
        notification_fn();
    };

    let cf = CStr::from_ptr(config_path);
    let config_path = match cf.to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s,
    };

    let authority = CStr::from_ptr(authority);
    let authority = match authority.to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s.to_owned(),
    };

    let updatable_configuration = match UpdatableConfiguration::new(config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration was invalid: {e}");
            return std::ptr::null();
        }
    };

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        _ => return std::ptr::null(),
    };

    let mut certificate_options = CertificateConfig::from(updatable_configuration.get_configuration().options.clone());
    certificate_options.authority = authority;

    let mut yk = Yubikey::open(yubikey_serial).unwrap();
    let slot = SlotId::try_from(slot).unwrap();
    let pubkey = match yk.ssh_cert_fetch_pubkey(&slot) {
        Ok(cert) => cert,
        Err(_) => return std::ptr::null(),
    };

    let handler = Handler {
        updatable_configuration,
        cert: None,
        stale_at: 0,
        pubkey,
        certificate_options,
        signatory: Signatory::Yubikey(YubikeySigner {
            yk: Yubikey::open(yubikey_serial).unwrap(),
            slot: SlotId::try_from(slot).unwrap(),
        }),
        identities: HashMap::new(),
        piv_identities: HashMap::new(),
        notification_function: Some(Box::new(notification_f)),
        certificate_priority,
    };

    println!("Slot: {:?}", SlotId::try_from(slot));

    let sp = CStr::from_ptr(socket_path);
    let socket_path = match sp.to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s,
    };

    let (shutdown_sender, shutdown_receiver) = channel::<()>(1);

    runtime.spawn(async move {
        Agent::run_with_termination_channel(
            handler,
            socket_path.to_string(),
            Some(shutdown_receiver),
        )
        .await;
        println!("Rustica Agent has shutdown");
    });

    let agent_instance = Box::new(RusticaAgentInstance {
        runtime,
        shutdown_sender,
    });

    let agent_instance_pointer: *const RusticaAgentInstance = Box::leak(agent_instance);

    agent_instance_pointer
}

/// Fetch a string that will configure a git repository for code
/// signing under the given key
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn ffi_get_git_config_string_from_private_key(
    private_key: *const c_char,
) -> *const c_char {
    let private_key = CStr::from_ptr(private_key);
    let public_key = match private_key.to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => {
            if let Ok(p) = PrivateKey::from_string(s) {
                p.pubkey.clone()
            } else {
                return std::ptr::null();
            }
        }
    };

    let git_config = match CString::new(crate::git_config_from_public_key(&public_key)) {
        Ok(c) => c,
        Err(_) => return std::ptr::null(), // Happens if the string contains a null byte. Should never happen but better to handle than not
    };

    git_config.into_raw()
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

/// Free a string allocated by Rust
#[no_mangle]
pub unsafe extern "C" fn ffi_free_rust_string(string_ptr: *mut c_char) {
    drop(CString::from_raw(string_ptr));
}

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

/// Refresh and load a new certificate onto a yubikey
///
/// # Safety
/// Subject, config_data, and pin must all be valid, null terminated C strings
/// or this functions behaviour is undefined and will result in a crash.
#[no_mangle]
pub unsafe extern "C" fn ffi_refresh_x509_certificate(
    yubikey_serial: u32,
    slot: u8,
    config_data: *const c_char,
    pin: *const c_char,
    management_key: *const c_char,
) -> bool {
    println!("Refreshing certificate!");
    let cf = CStr::from_ptr(config_data);
    let config_data = match cf.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let pin = CStr::from_ptr(pin);
    let management_key = CStr::from_ptr(management_key);
    let management_key = hex::decode(&management_key.to_str().unwrap()).unwrap();

    let config: Config = match parse_config(config_data) {
        Ok(c) => c,
        Err(e) => {
            error!("Configuration was invalid: {e}");
            return false;
        }
    };

    let slot = SlotId::try_from(slot).unwrap();
    let mut yk = Yubikey::open(yubikey_serial).unwrap();

    if yk
        .unlock(pin.to_str().unwrap().as_bytes(), &management_key)
        .is_err()
    {
        println!("Could not unlock key");
        return false;
    }

    let mut signatory = Signatory::Yubikey(YubikeySigner { yk, slot });

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        _ => return false,
    };

    let runtime_handle = runtime.handle().to_owned();

    for server in config.servers {
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
