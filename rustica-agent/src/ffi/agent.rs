pub use crate::sshagent::{error::Error as AgentError, Agent, Identity, Response, SshAgentHandler};
use crate::{
    config::UpdatableConfiguration, CertificateConfig, Handler, PrivateKey, Signatory,
    YubikeyPIVKeyDescriptor, YubikeySigner,
};

pub use crate::rustica::{
    key::PIVAttestation,
    RefreshError::{ConfigurationError, SigningError},
};

use sshcerts::yubikey::piv::{SlotId, Yubikey};

use tokio::{
    runtime::Runtime,
    sync::{
        mpsc::{channel, Sender},
        Mutex,
    },
};

use std::collections::HashMap;
use std::{convert::TryFrom, slice};

// FFI related imports
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_long};

pub struct RusticaAgentInstance {
    runtime: Runtime,
    shutdown_sender: Sender<()>,
}

/// Start a new Rustica instance. Does not return unless Rustica exits.
/// # Safety
/// `config_path` and `socket_path` must be a null terminated C strings
/// or behaviour is undefined and will result in a crash.
#[no_mangle]
pub unsafe extern "C" fn start_direct_rustica_agent(
    private_key: *const c_char,
    config_path: *const c_char,
    socket_path: *const c_char,
    pin: *const c_char,
    device: *const c_char,
    notification_fn: unsafe extern "C" fn() -> (),
    authority: *const c_char,
    certificate_priority: bool,
) -> *const RusticaAgentInstance {
    return start_direct_rustica_agent_with_piv_idents(
        private_key,
        config_path,
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
/// `config_path` and `socket_path` must be a null terminated C strings
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
    let _ = env_logger::try_init();
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

    let mut certificate_options =
        CertificateConfig::from(updatable_configuration.get_configuration().options.clone());
    certificate_options.authority = authority;

    let handler = Handler {
        updatable_configuration: Mutex::new(updatable_configuration),
        cert: None.into(),
        stale_at: Mutex::new(0),
        pubkey: private_key.pubkey.clone(),
        certificate_options,
        signatory: Signatory::Direct(private_key),
        identities: Mutex::new(HashMap::new()),
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
/// `config_path` and `socket_path` must be a null terminated C strings
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
    let _ = env_logger::try_init();
    println!("Starting a new Rustica instance!");

    let notification_f = move || {
        notification_fn();
    };

    let authority = CStr::from_ptr(authority);
    let authority = match authority.to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s.to_owned(),
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

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        _ => return std::ptr::null(),
    };

    let mut certificate_options =
        CertificateConfig::from(updatable_configuration.get_configuration().options.clone());
    certificate_options.authority = authority;

    let mut yk = Yubikey::open(yubikey_serial).unwrap();
    let slot = SlotId::try_from(slot).unwrap();
    let pubkey = match yk.ssh_cert_fetch_pubkey(&slot) {
        Ok(cert) => cert,
        Err(_) => return std::ptr::null(),
    };

    let handler = Handler {
        updatable_configuration: Mutex::new(updatable_configuration),
        cert: None.into(),
        stale_at: Mutex::new(0),
        pubkey,
        certificate_options,
        signatory: Signatory::Yubikey(YubikeySigner {
            yk: Mutex::new(Yubikey::open(yubikey_serial).unwrap()),
            slot: SlotId::try_from(slot).unwrap(),
        }),
        identities: Mutex::new(HashMap::new()),
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
