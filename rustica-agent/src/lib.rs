#[macro_use] extern crate log;

pub mod sshagent;
pub mod rustica;

use serde_derive::Deserialize;

pub use sshagent::{Agent, error::Error as AgentError, Identity, SshAgentHandler, Response};

pub use rustica::{
    key::{
        PIVAttestation,
    },
    RefreshError::{ConfigurationError, SigningError}
};

use rustica::key::U2FAttestation;


use sshcerts::ssh::{Certificate, CertType, PrivateKey, SSHCertificateSigner};
use sshcerts::fido::generate::generate_new_ssh_key;
use sshcerts::yubikey::piv::{AlgorithmId, SlotId, RetiredSlotId, TouchPolicy, PinPolicy, Yubikey};

use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::File;

use std::time::SystemTime;

// FFI related imports
use std::os::raw::{c_char, c_int, c_long};
use std::ffi::{CString, CStr};
use std::os::unix::net::{UnixListener};

#[derive(Debug, Deserialize)]
pub struct Options {
    pub principals: Option<Vec<String>>,
    pub hosts: Option<Vec<String>>,
    pub kind: Option<String>,
    pub duration: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: Option<String>,
    pub ca_pem: Option<String>,
    pub mtls_cert: Option<String>,
    pub mtls_key: Option<String>,
    pub slot: Option<String>,
    pub key: Option<String>,
    pub options: Option<Options>,
    pub socket: Option<String>,
}

#[derive(Debug)]
pub struct CertificateConfig {
    pub principals: Vec<String>,
    pub hosts: Vec<String>,
    pub cert_type: CertType,
    pub duration: u64,
}

#[derive(Debug)]
pub struct RusticaServer {
    pub address: String,
    pub ca: String,
    pub mtls_cert: String,
    pub mtls_key: String,
}

#[derive(Debug)]
pub struct YubikeySigner {
    pub slot: SlotId,
    pub yk: Yubikey,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Signatory {
    Yubikey(YubikeySigner),
    Direct(PrivateKey),
}

pub struct Handler {
    pub server: RusticaServer,
    pub cert: Option<Identity>,
    pub signatory: Signatory,
    pub stale_at: u64,
    pub certificate_options: CertificateConfig,
    pub identities: HashMap<Vec<u8>, PrivateKey>,
    pub notification_function: Option<Box<dyn Fn() + Send + Sync>>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handler")
         .field("server", &self.server)
         .field("cert", &self.cert)
         .finish()
    }
}


impl From<Option<Options>> for CertificateConfig {
    fn from(co: Option<Options>) -> CertificateConfig {
        match co {
            None => {
                CertificateConfig {
                    cert_type: CertType::User,
                    duration: 10,
                    hosts: vec![],
                    principals: vec![],
                }
            },
            Some(co) => {
                CertificateConfig {
                    cert_type: CertType::try_from(co.kind.unwrap_or_else(|| String::from("user")).as_str()).unwrap_or(CertType::User),
                    duration: co.duration.unwrap_or(10),
                    hosts: co.hosts.unwrap_or_default(),
                    principals: co.principals.unwrap_or_default(),
                }
            }
        }
    }
}

impl SshAgentHandler for Handler {
    fn add_identity(&mut self, private_key: PrivateKey) -> Result<Response, AgentError> {
        let public_key = private_key.pubkey.encode();
        self.identities.insert(public_key, private_key);
        Ok(Response::Success)
    }

    fn identities(&mut self) -> Result<Response, AgentError> {
        // Build identities from the private keys we have loaded
        let mut identities: Vec<Identity> = self.identities.iter().map(|x| Identity {
                key_blob: x.1.pubkey.encode().to_vec(),
                key_comment: x.1.comment.clone(),
            }).collect();

        // If the time hasn't expired on our certificate, we don't need to fetch a new one
        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        if let Some(cert) = &self.cert {
            if timestamp < self.stale_at {
                debug!("Certificate has not expired, not refreshing");
                identities.push(cert.clone());
                return Ok(Response::Identities(vec![cert.clone()]));
            }
        }

        if let Some(f) = &self.notification_function {
            f()
        }

        // Grab a new certificate from the server because we don't have a valid one
        match self.server.get_custom_certificate(&mut self.signatory, &self.certificate_options) {
            Ok(response) => {
                let parsed_cert = Certificate::from_string(&response.cert).map_err(|e| 
                    AgentError {
                        details: e.to_string(),
                    })?;
                info!("{:#}", parsed_cert);
                let cert: Vec<&str> = response.cert.split(' ').collect();
                let raw_cert = base64::decode(cert[1]).unwrap_or_default();
                let ident = Identity {
                    key_blob: raw_cert,
                    key_comment: response.comment.clone(),
                };
                self.cert = Some(ident.clone());

                identities.push(ident);
                Ok(Response::Identities(identities))
            },
            Err(e) => {
                error!("Refresh certificate error: {:?}", e);
                Err(AgentError::from("Could not refresh certificate"))
            },
        }
    }

    /// Sign a request coming in from an SSH command.
    fn sign_request(&mut self, pubkey: Vec<u8>, data: Vec<u8>, _flags: u32) -> Result<Response, AgentError> {
        // Tri check to find how to sign the request. Since starting rustica with a file based
        // key is the same process as keys added afterwards, we do this to prevent duplication
        // of the private key based signing code.
        // TODO: @obelisk make this better
        let private_key: Option<&PrivateKey> = if self.identities.contains_key(&pubkey) {
            Some(&self.identities[&pubkey])
        } else if let Signatory::Direct(privkey) = &self.signatory {
            Some(privkey)
        } else if let Signatory::Yubikey(signer) = &mut self.signatory {
            // Since we are using the Yubikey for a signing operation the only time they
            // won't have to tap here is if they are using cached keys and this is right after
            // a secure Rustica tap. In most cases, we'll need to send this, rarely, it'll be 
            // spurious.
            if let Some(f) = &self.notification_function {
                f()
            }

            let signature = signer.yk.ssh_cert_signer(&data, &signer.slot).map_err(|_| AgentError::from("Yubikey signing error"))?;

            return Ok(Response::SignResponse {
                signature,
            });
        } else {
            None
        };

        match private_key {
            Some(key) => {
                let signature = match key.sign(&data) {
                    None => return Err(AgentError::from("Signing Error")),
                    Some(signature) => signature,
                };

                Ok(Response::SignResponse {
                    signature,
                })
            }
            None => Err(AgentError::from("Signing Error: No Valid Keys"))
        }
    }
}

/// Takes in a human readable slot descriptor and parses it into the Yubikey
/// slot type.
pub fn slot_parser(slot: &str) -> Option<SlotId> {
    // If first character is R, then we need to parse the nice
    // notation
    if (slot.len() == 2 || slot.len() == 3) && slot.starts_with('R') {
        let slot_value = slot[1..].parse::<u8>();
        match slot_value {
            Ok(v) if v <= 20 => Some(SlotId::try_from(0x81_u8 + v).unwrap()),
            _ => None,
        }
    } else if slot.len() == 4 && slot.starts_with("0x"){
        let slot_value = hex::decode(&slot[2..]).unwrap()[0];
        Some(SlotId::try_from(slot_value).unwrap())
    } else {
        None
    }
}

/// Used to validate a string would parse to a valid Yubikey slot
pub fn slot_validator(slot: &str) -> Result<(), String> {
    match slot_parser(slot) {
        Some(_) => Ok(()),
        None => Err(String::from("Provided slot was not valid. Should be R1 - R20 or a raw hex identifier")),
    }
}

/// Provisions a new keypair on the Yubikey with the given settings.
pub fn provision_new_key(mut yubikey: YubikeySigner, pin: &str, subj: &str, mgm_key: &[u8], require_touch: bool) -> Option<PIVAttestation> {
    println!("Provisioning new NISTP384 key in slot: {:?}", &yubikey.slot);

    let policy = if require_touch {
        println!("You're creating a key that will require touch to use.");
        TouchPolicy::Always
    } else {
        TouchPolicy::Cached
    };

    if yubikey.yk.unlock(pin.as_bytes(), mgm_key).is_err() {
        println!("Could not unlock key");
        return None
    }

    match yubikey.yk.provision(&yubikey.slot, subj, AlgorithmId::EccP384, policy, PinPolicy::Never) {
        Ok(_) => {
            let certificate = yubikey.yk.fetch_attestation(&yubikey.slot);
            let intermediate = yubikey.yk.fetch_certificate(&SlotId::Attestation);

            match (certificate, intermediate) {
                (Ok(certificate), Ok(intermediate)) => Some(PIVAttestation{certificate, intermediate}),
                _ => None,
            }
        },
        Err(_) => panic!("Could not provision device with new key"),
    }
}

/// Fetch the list of serial numbers for the connected Yubikeys
/// The return from this function must be freed by the caller because we can no longer track it
/// once we return
/// 
/// # Safety
/// out_length must be a valid pointer to an 8 byte segment of memory
#[no_mangle]
pub unsafe extern fn list_yubikeys(out_length: *mut c_int) -> *mut c_long {
    match &mut yubikey::reader::Context::open() {
        Ok(readers) => {
            let mut serials: Vec<c_long> = vec![];
            for reader in readers.iter().unwrap().collect::<Vec<yubikey::reader::Reader>>() {
                let reader = reader.open();
                if reader.is_err() {
                    continue;
                }
                let reader = reader.unwrap();
                let serial: u32 = reader.serial().into();
                serials.push(serial.into());
            }

            let len = serials.len();
            let ptr = serials.as_mut_ptr();
            std::mem::forget(serials);
            std::ptr::write(out_length, len as c_int);

            ptr
        },
        Err(_) => std::ptr::null_mut()
    }
}

/// Free the list of Yubikey Serial Numbers
/// 
/// # Safety
/// This function must be passed the raw vector returned by `list_yubikeys`
/// otherwise the behaviour is undefined and will result in a crash.
#[no_mangle]
pub unsafe extern fn free_list_yubikeys(length: c_int, yubikeys: *mut c_long) {
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
pub unsafe extern fn list_keys(yubikey_serial: u32, out_length: *mut c_int) -> *mut *mut c_char {
    match &mut Yubikey::open(yubikey_serial) {
        Ok(yk) => {
            let mut keys = vec![];
            for slot in 0x82..0x96_u8 {
                let slot = SlotId::Retired(RetiredSlotId::try_from(slot).unwrap());
                if let Ok(subj) = yk.fetch_subject(&slot) {
                    keys.push(CString::new(format!("{:?} - {}", slot, subj)).unwrap())
                }
            }

            let mut out = keys
                .into_iter()
                .map(|s| s.into_raw())
                .collect::<Vec<_>>();
            out.shrink_to_fit();

            let len = out.len();
            let ptr = out.as_mut_ptr();
            std::mem::forget(out);
            std::ptr::write(out_length, len as c_int);
            
            // Finally return the data
            ptr
        },
        Err(_) => std::ptr::null_mut()
    }
}

/// Free the list of Yubikey keys
/// 
/// # Safety
/// This function must be passed the raw vector returned by `list_keys`
/// otherwise the behaviour is undefined and will result in a crash.
#[no_mangle]
pub unsafe extern fn free_list_keys(length: c_int, keys: *mut *mut c_char) {
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
pub unsafe extern fn generate_and_enroll_fido(config_data: *const c_char, out: *const c_char, comment: *const c_char, pin: *const c_char) -> bool {
    let cf = CStr::from_ptr(config_data);
    let config: Config = match cf.to_str() {
        Err(_) => return false,
        Ok(s) => {
            if let Ok(c) = toml::from_str(s) {
                c
            } else {
                return false
            }
        },
    };

    let out = CStr::from_ptr(out);
    let out = match out.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let comment = if comment != std::ptr::null() {
        let comment = CStr::from_ptr(comment);
        let comment = match comment.to_str() {
            Err(_) => return false,
            Ok(s) => s,
        };
        comment.to_string()
    } else {
        format!("FFI-RusticaAgent-Generated-Key")
    };

    let pin = if pin != std::ptr::null() {
        let pin = CStr::from_ptr(pin);
        let pin = match pin.to_str() {
            Err(_) => return false,
            Ok(s) => s,
        };
        Some(pin.to_string())
    } else {
        None
    };

    let new_fido_key = if let Ok(nfk) = generate_new_ssh_key("ssh:RusticaAgentFIDOKey", &comment, pin) {
        nfk
    } else {
        return false;
    };

    let server = RusticaServer {
        address: config.server.unwrap(),
        ca: config.ca_pem.unwrap(),
        mtls_cert: config.mtls_cert.unwrap(),
        mtls_key: config.mtls_key.unwrap(),
    };

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
        Err(_) => return false,
    };
    match new_fido_key.private_key.write(&mut out_file) {
        Err(_) => {
            std::fs::remove_file(out).unwrap();
            return false
        },
        _ => (),
    };

    match server.register_u2f_key(&mut signatory, "ssh:RusticaAgent", &u2f_attestation) {
        Ok(_) => {
            println!("Key was successfully registered");
            true
        },
        Err(e) => {
            error!("Key could not be registered. Server said: {}", e);
            std::fs::remove_file(out).unwrap();
            false
        },
    }
}

/// Generate and enroll a new key on the given yubikey in the given slot
/// 
/// # Safety
/// Subject, config_data, and pin must all be valid, null terminated C strings
/// or this functions behaviour is undefined and will result in a crash.
#[no_mangle]
pub unsafe extern fn generate_and_enroll(yubikey_serial: u32, slot: u8, high_security: bool, subject: *const c_char, config_data: *const c_char, pin: *const c_char, management_key: *const c_char) -> bool {
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

    let config: Config = toml::from_str(config_data).unwrap();

    let alg = AlgorithmId::EccP384;
    let slot = SlotId::try_from(slot).unwrap();

    let policy = if high_security {TouchPolicy::Always} else {TouchPolicy::Cached};
    let mut yk = Yubikey::open(yubikey_serial).unwrap();

    if yk.unlock(pin.to_str().unwrap().as_bytes(), &management_key).is_err() {
        println!("Could not unlock key");
        return false
    }

    let key_config = match yk.provision(&slot, subject.to_str().unwrap(), alg, policy, PinPolicy::Never) {
        Ok(_) => {
            let certificate = yk.fetch_attestation(&slot);
            let intermediate = yk.fetch_certificate(&SlotId::Attestation);

            match (certificate, intermediate) {
                (Ok(certificate), Ok(intermediate)) => PIVAttestation{certificate, intermediate},
                _ => return false,
            }
        },
        Err(_) => return false,
    };

    let mut signatory = Signatory::Yubikey(YubikeySigner {
        yk,
        slot,
    });

    let server = RusticaServer {
        address: config.server.unwrap(),
        ca: config.ca_pem.unwrap(),
        mtls_cert: config.mtls_cert.unwrap(),
        mtls_key: config.mtls_key.unwrap(),
    };

    match server.register_key(&mut signatory, &key_config) {
        Ok(_) => {
            println!("Key was successfully registered");
            true
        },
        Err(e) => {
            error!("Key could not be registered. Server said: {}", e);
            false
        },
    }
}

/// Start a new Rustica instance. Does not return unless Rustica exits.
/// # Safety
/// `config_data` and `socket_path` must be a null terminated C strings
/// or behaviour is undefined and will result in a crash.
#[no_mangle]
pub unsafe extern fn start_file_rustica_agent(private_key: *const c_char, config_data: *const c_char, socket_path: *const c_char, notification_fn: unsafe extern "C" fn() -> ()) -> bool {
    println!("Starting a new Rustica instance!");

    let notification_f = move || {
        unsafe { notification_fn(); }
    };

    let cf = CStr::from_ptr(config_data);
    let config_data = match cf.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let sp = CStr::from_ptr(socket_path);
    let socket_path = match sp.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let private_key = CStr::from_ptr(private_key);
    let private_key = match private_key.to_str() {
        Err(_) => return false,
        Ok(s) => {
            if let Ok(p) = PrivateKey::from_string(s) {
                p
            } else {
                return false
            }
        },
    };
    println!("Fingerprint: {:?}", private_key.pubkey.fingerprint().hash);

    let config: Config = toml::from_str(config_data).unwrap();
    let certificate_options = CertificateConfig::from(config.options);
    let handler = Handler {
        cert: None,
        stale_at: 0,
        certificate_options,
        server: RusticaServer {
            address: config.server.unwrap(),
            ca: config.ca_pem.unwrap(),
            mtls_cert: config.mtls_cert.unwrap(),
            mtls_key: config.mtls_key.unwrap(),
        },
        signatory: Signatory::Direct(private_key),
        identities: HashMap::new(),
        notification_function: Some(Box::new(notification_f)),
    };


    let socket = UnixListener::bind(socket_path).unwrap();
    Agent::run(handler, socket);

    true
}


/// Start a new Rustica instance. Does not return unless Rustica exits.
/// # Safety
/// `config_data` and `socket_path` must be a null terminated C strings
/// or behaviour is undefined and will result in a crash.
#[no_mangle]
pub unsafe extern fn start_yubikey_rustica_agent(yubikey_serial: u32, slot: u8, config_data: *const c_char, socket_path: *const c_char, notification_fn: unsafe extern "C" fn() -> ()) -> bool {
    println!("Starting a new Rustica instance!");

    let notification_f = move || {
        unsafe { notification_fn(); }
    };

    let cf = CStr::from_ptr(config_data);
    let config_data = match cf.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let config: Config = toml::from_str(config_data).unwrap();

    let certificate_options = CertificateConfig::from(config.options);

    let handler = Handler {
        cert: None,
        stale_at: 0,
        certificate_options,
        server: RusticaServer {
            address: config.server.unwrap(),
            ca: config.ca_pem.unwrap(),
            mtls_cert: config.mtls_cert.unwrap(),
            mtls_key: config.mtls_key.unwrap(),
        },
        signatory: Signatory::Yubikey(YubikeySigner {
            yk: Yubikey::open(yubikey_serial).unwrap(),
            slot: SlotId::try_from(slot).unwrap(),
        }),
        identities: HashMap::new(),
        notification_function: Some(Box::new(notification_f)),
    };

    println!("Slot: {:?}", SlotId::try_from(slot));

    let sp = CStr::from_ptr(socket_path);
    let socket_path = match sp.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let socket = UnixListener::bind(socket_path).unwrap();
    Agent::run(handler, socket);

    true
}