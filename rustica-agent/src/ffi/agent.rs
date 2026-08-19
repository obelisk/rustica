pub use crate::sshagent::{error::Error as AgentError, Agent, Identity, Response, SshAgentHandler};
use crate::{
    config::UpdatableConfiguration, piv_key_descriptor_from_yubikey, read_yubikey,
    CertificateConfig, Handler, PrivateKey, Signatory, YubikeyPIVKeyDescriptor, YubikeySigner,
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
use std::sync::Arc;
use std::{convert::TryFrom, slice};

// FFI related imports
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_long};

pub struct RusticaAgentInstance {
    runtime: Runtime,
    shutdown_sender: Sender<()>,
    handler: Arc<Handler>,
}

/// Builds PIV key descriptors from parallel C arrays (serial/slot/pin per
/// index, length `piv_key_count`). Returns `None` on malformed input or a
/// Yubikey read failure. `skip_key` excludes one encoded public key from the
/// resulting map.
unsafe fn build_piv_identities_from_ffi(
    piv_serials: *const c_long,
    piv_slots: *const u8,
    piv_pins: *const c_long,
    piv_key_count: c_int,
    // Excludes the primary signing key so it isn't duplicated in piv_identities.
    skip_key: Option<&[u8]>,
) -> Option<HashMap<Vec<u8>, YubikeyPIVKeyDescriptor>> {
    if piv_key_count < 0 {
        return None;
    }

    let piv_key_count = piv_key_count as usize;
    if piv_key_count == 0 {
        return Some(HashMap::new());
    }

    if piv_serials.is_null() || piv_slots.is_null() || piv_pins.is_null() {
        return None;
    }

    let key_serials = slice::from_raw_parts(piv_serials, piv_key_count);
    let key_slots = slice::from_raw_parts(piv_slots, piv_key_count);
    let key_pins = slice::from_raw_parts(piv_pins, piv_key_count);

    // Group the requested identities by serial so that each physical Yubikey is
    // opened once, even when several slots on the same device are requested.
    let mut keys_by_serial: HashMap<u32, Vec<(SlotId, Option<String>)>> = HashMap::new();
    for ((serial, slot), pin) in key_serials
        .iter()
        .zip(key_slots.iter())
        .zip(key_pins.iter())
    {
        let serial = u32::try_from(*serial).ok()?;
        let slot = SlotId::try_from(*slot).ok()?;
        let pin = if *pin != 0 {
            Some(pin.to_string())
        } else {
            None
        };

        keys_by_serial.entry(serial).or_default().push((slot, pin));
    }

    let mut piv_identities = HashMap::new();
    for (serial, slots) in keys_by_serial {
        read_yubikey(serial, |yk| {
            for (slot, pin) in slots {
                let descriptor = piv_key_descriptor_from_yubikey(yk, serial, slot, pin)?;
                let encoded = descriptor.public_key.encode().to_vec();
                if skip_key == Some(encoded.as_slice()) {
                    continue;
                }

                piv_identities.insert(encoded, descriptor);
            }
            Some(())
        })
        .flatten()?;
    }

    Some(piv_identities)
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
    disable_certificate: bool,
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
        disable_certificate,
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
    disable_certificate: bool,
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

    let piv_identities = match build_piv_identities_from_ffi(
        piv_serials,
        piv_slots,
        piv_pins,
        piv_key_count,
        Some(&private_key.pubkey.encode()),
    ) {
        Some(piv_identities) => piv_identities,
        None => return std::ptr::null(),
    };

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
        updatable_configuration: updatable_configuration.into(),
        cert: None.into(),
        stale_at: 0.into(),
        pubkey: private_key.pubkey.clone(),
        certificate_options,
        signatory: Signatory::Direct(private_key.into()),
        identities: HashMap::new().into(),
        piv_identities,
        notification_function: Some(Box::new(notification_f)),
        certificate_priority,
        disable_certificate,
        list_primary_certificate_only: false,
        fido_identity: None,
    };

    let (shutdown_sender, shutdown_receiver) = channel::<()>(1);
    let handler = Arc::new(handler);

    let runtime_handler = handler.clone();
    runtime.spawn(async move {
        Agent::run_with_termination_channel(
            runtime_handler,
            socket_path.to_string(),
            Some(shutdown_receiver),
        )
        .await;
        println!("Rustica Agent has shutdown");
    });

    let agent_instance = Box::new(RusticaAgentInstance {
        runtime,
        shutdown_sender,
        handler,
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
    disable_certificate: bool,
) -> *const RusticaAgentInstance {
    start_yubikey_rustica_agent_with_piv_idents(
        yubikey_serial,
        slot,
        config_path,
        socket_path,
        std::ptr::null(),
        notification_fn,
        authority,
        certificate_priority,
        std::ptr::null(),
        std::ptr::null(),
        std::ptr::null(),
        0,
        false,
        std::ptr::null(),
        disable_certificate,
    )
}

/// Start a new Rustica instance whose primary identity lives on a Yubikey PIV
/// slot (`yubikey_serial`/`slot`). Does not return unless Rustica exits.
///
/// - By default the agent advertises both the bare primary key and its
///   certificate; set `list_primary_certificate_only` to advertise only the
///   certificate (e.g. for no-touch PIV keys where the bare key isn't usable).
/// - Pass `piv_key_count > 0` to also load additional PIV identities from
///   other slots/Yubikeys (`piv_serials`/`piv_slots`/`piv_pins`); any entry
///   matching the primary key is skipped automatically.
/// - Pass a non-null `fido_private_key` to additionally advertise a FIDO
///   identity alongside the primary key.
/// - Set `disable_certificate` to never fetch or advertise the certificate,
///   only the raw key. Needed for key-only auth with OpenSSH 10.5+, which
///   always prefers certificates. Combined with
///   `list_primary_certificate_only` no primary identity is advertised.
/// # Safety
/// `config_path` and `socket_path` must be null terminated C strings. `pin` and
/// `fido_private_key`, if non-null, must also be null terminated C strings. If
/// `piv_key_count` is greater than zero, `piv_serials`, `piv_slots`, and
/// `piv_pins` must point to arrays with at least `piv_key_count` entries.
#[no_mangle]
pub unsafe extern "C" fn start_yubikey_rustica_agent_with_piv_idents(
    yubikey_serial: u32,
    slot: u8,
    config_path: *const c_char,
    socket_path: *const c_char,
    pin: *const c_char,
    notification_fn: unsafe extern "C" fn() -> (),
    authority: *const c_char,
    certificate_priority: bool,
    piv_serials: *const c_long,
    piv_slots: *const u8,
    piv_pins: *const c_long,
    piv_key_count: c_int,
    // If true, advertise only the certificate for the primary key, never the bare key.
    list_primary_certificate_only: bool,
    // Optional additional FIDO identity to advertise alongside the primary key; null if unused.
    fido_private_key: *const c_char,
    disable_certificate: bool,
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

    // Falls back to YK_PIN env vars when null.
    let primary_pin = if pin.is_null() {
        None
    } else {
        match CStr::from_ptr(pin).to_str() {
            Ok(s) => Some(s.to_owned()),
            Err(_) => return std::ptr::null(),
        }
    };

    let mut yk = Yubikey::open(yubikey_serial).unwrap();
    let slot = SlotId::try_from(slot).unwrap();
    let pubkey = match yk.ssh_cert_fetch_pubkey(&slot) {
        Ok(cert) => cert,
        Err(_) => return std::ptr::null(),
    };
    let piv_identities = match build_piv_identities_from_ffi(
        piv_serials,
        piv_slots,
        piv_pins,
        piv_key_count,
        Some(&pubkey.encode()),
    ) {
        Some(piv_identities) => piv_identities,
        None => return std::ptr::null(),
    };

    let mut signer = YubikeySigner::new(yk, slot);
    if primary_pin.is_some() {
        signer.pin = primary_pin;
    }

    let fido_identity = if fido_private_key.is_null() {
        None
    } else {
        match CStr::from_ptr(fido_private_key).to_str() {
            Ok(s) => match PrivateKey::from_string(s) {
                Ok(p) => Some(p),
                Err(_) => return std::ptr::null(),
            },
            Err(_) => return std::ptr::null(),
        }
    };

    let handler = Handler {
        updatable_configuration: Mutex::new(updatable_configuration),
        cert: None.into(),
        stale_at: Mutex::new(0),
        pubkey,
        certificate_options,
        signatory: Signatory::Yubikey(signer),
        identities: Mutex::new(HashMap::new()),
        piv_identities,
        notification_function: Some(Box::new(notification_f)),
        certificate_priority,
        disable_certificate,
        list_primary_certificate_only,
        fido_identity,
    };

    println!("Slot: {:?}", SlotId::try_from(slot));

    let sp = CStr::from_ptr(socket_path);
    // Own the path; the C pointer doesn't outlive this call.
    let socket_path = match sp.to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s.to_owned(),
    };

    let (shutdown_sender, shutdown_receiver) = channel::<()>(1);

    let handler = Arc::new(handler);

    let runtime_handler = handler.clone();
    runtime.spawn(async move {
        Agent::run_with_termination_channel(runtime_handler, socket_path, Some(shutdown_receiver))
            .await;
        println!("Rustica Agent has shutdown");
    });

    let agent_instance = Box::new(RusticaAgentInstance {
        runtime,
        shutdown_sender,
        handler,
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

/// First, fetch the previous cert if present and valid. If cert is still valid, return it.
///
/// If cached cert is invalid, and if fetch_new_cert_if_needed is:
///     - true: fetch a new cert from server. Return error if the fetch fails.
///     - false: return None.
#[no_mangle]
pub unsafe extern "C" fn ffi_get_certificate(
    rai: *mut RusticaAgentInstance,
    fetch_new_cert_if_needed: bool,
) -> *const c_char {
    let rustica_agent_instance = Box::from_raw(rai);
    let handler = rustica_agent_instance.handler.clone();

    let runtime_handle = rustica_agent_instance.runtime.handle();
    let certificate = match handler.get_certificate(runtime_handle, fetch_new_cert_if_needed) {
        Ok(Some(v)) => Some(v),
        Ok(None) => None,
        Err(e) => {
            println!("failed to fetch certificate: {}", e);
            None
        }
    };

    // We need to leak here otherwise we will free the RAI
    // when we're still using it. Would be nice if Box had Box::into_weak or
    // something similar
    Box::leak(rustica_agent_instance);

    let certificate = match certificate {
        Some(v) => v,
        None => return std::ptr::null(),
    };

    let certificate = match CString::new(certificate.to_string()) {
        Ok(c) => c,
        Err(e) => {
            println!("failed to create a new CSTring from serialized cert: {}", e);
            return std::ptr::null();
        }
    };

    certificate.into_raw()
}
