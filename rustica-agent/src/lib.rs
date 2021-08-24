#[macro_use] extern crate log;

pub mod sshagent;
pub mod rustica;

use serde_derive::Deserialize;

pub use sshagent::{Agent, error::Error as AgentError, Identity, SshAgentHandler, Response};

pub use rustica::{
    key::KeyConfig,
    RefreshError::{ConfigurationError, SigningError}
};

use sshcerts::ssh::{Certificate, CertType, PrivateKey, SigningFunction};
use sshcerts::yubikey::{AlgorithmId, SlotId, RetiredSlotId};
use yubikey_piv::policy::{TouchPolicy, PinPolicy};

use std::collections::HashMap;
use std::convert::TryFrom;

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
    pub yk: sshcerts::yubikey::Yubikey,
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
    pub notification_function: Option<Box<dyn Fn() -> () + Send + Sync>>,
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
                key_comment: x.1.comment.as_ref().unwrap_or(&String::new()).to_string(),
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
                info!("{:#}", Certificate::from_string(&response.cert).unwrap());
                let cert: Vec<&str> = response.cert.split(' ').collect();
                let raw_cert = base64::decode(cert[1]).unwrap_or_default();
                let ident = Identity {
                    key_blob: raw_cert,
                    key_comment: response.comment,
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
        let signer: Option<SigningFunction> = if self.identities.contains_key(&pubkey) {
            Some(self.identities[&pubkey].clone().into())
        } else if let Signatory::Direct(privkey) = &mut self.signatory {
            Some(privkey.clone().into())
        } else if let Signatory::Yubikey(signer) = &mut self.signatory {
            // If using long lived certificates you might need to tap again here because you didn't have to
            // to get the certificate the first time
            if let Some(f) = &self.notification_function {
                f()
            }

            let signature = signer.yk.ssh_cert_signer(&data, &signer.slot).unwrap();
                // TODO: @obelisk Why is this magic value here
                let signature = (&signature[27..]).to_vec();
                let pubkey = signer.yk.ssh_cert_fetch_pubkey(&signer.slot).unwrap();

                return Ok(Response::SignResponse {
                    algo_name: String::from(pubkey.key_type.name),
                    signature,
                });
        } else {
            None
        };

        match signer {
            Some(signer) => {
                let sig = match signer(&data) {
                    None => return Err(AgentError::from("Signing Error")),
                    Some(signature) => signature.to_vec(),
                };

                let mut reader = sshcerts::ssh::Reader::new(&sig);
                Ok(Response::SignResponse {
                    algo_name: reader.read_string().unwrap(),
                    signature: reader.read_bytes().unwrap(),
                })
            }
            None => Err(AgentError::from("Signing Error: No Valid Keys"))
        }
    }
}

/// Fetch the list of serial numbers for the connected Yubikeys
/// The return from this function must be freed by the caller because we can no longer track it
/// once we return
#[no_mangle]
pub extern fn list_yubikeys(out_length: *mut c_int) -> *mut c_long {
    match &mut yubikey_piv::readers::Readers::open() {
        Ok(readers) => {
            let mut serials: Vec<c_long> = vec![];
            for reader in readers.iter().unwrap().collect::<Vec<yubikey_piv::readers::Reader>>() {
                let reader = reader.open();
                if let Err(_) = reader {
                    continue;
                }
                let reader = reader.unwrap();
                let serial: u32 = reader.serial().into();
                serials.push(serial.into());
            }

            let len = serials.len();
            let ptr = serials.as_mut_ptr();
            std::mem::forget(serials);
            unsafe {
                std::ptr::write(out_length, len as c_int);
            }

            ptr
        },
        Err(_) => std::ptr::null_mut()
    }
}

/// Free the list of Yubikey Serial Numbers
#[no_mangle]
pub extern fn free_list_yubikeys(length: c_int, yubikeys: *mut c_long) {
    let len = length as usize;

    // Get back our vector.
    // Previously we shrank to fit, so capacity == length.
    let _ = unsafe {Vec::from_raw_parts(yubikeys, len, len)};
}

/// The return from this function must be freed by the caller because we can no longer track it
/// once we return
#[no_mangle]
pub extern fn list_keys(yubikey_serial: u32, out_length: *mut c_int) -> *mut *mut c_char {
    match &mut sshcerts::yubikey::Yubikey::open(yubikey_serial) {
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

            // Let's write back the length the caller can expect
            unsafe {
                std::ptr::write(out_length, len as c_int);
            }
            
            // Finally return the data
            ptr
        },
        Err(_) => std::ptr::null_mut()
    }
}

/// Free the list of Yubikey keys
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

/// Generate and enroll a new key on the given yubikey in the given slot
#[no_mangle]
pub extern fn generate_and_enroll(yubikey_serial: u32, slot: u8, subject: *const c_char, config_file: *const c_char, pin: *const c_char, management_key: *const c_char) -> bool {
    println!("Generating and enrolling a new key!");
    let cf = unsafe { CStr::from_ptr(config_file) };
    let config_file = match cf.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let pin = unsafe { CStr::from_ptr(pin) };
    let management_key = unsafe { CStr::from_ptr(management_key) };
    let management_key = hex::decode(&management_key.to_str().unwrap()).unwrap();
    let subject = unsafe { CStr::from_ptr(subject) };

    let config = std::fs::read_to_string(config_file);
    let config: Config = match config {
        Ok(content) => toml::from_str(&content).unwrap(),
        Err(e) => {
            println!("Could not open configuration file: {}", e);
            return false
        },
    };

    let alg = AlgorithmId::EccP384;
    let slot = sshcerts::yubikey::SlotId::try_from(slot).unwrap();
    let policy = TouchPolicy::Cached;
    let mut yk = sshcerts::yubikey::Yubikey::open(yubikey_serial).unwrap();

    if yk.unlock(pin.to_str().unwrap().as_bytes(), &management_key).is_err() {
        println!("Could not unlock key");
        return false
    }

    let key_config = match yk.provision(&slot, subject.to_str().unwrap(), alg, policy, PinPolicy::Never) {
        Ok(_) => {
            let certificate = yk.fetch_attestation(&slot);
            let intermediate = yk.fetch_certificate(&SlotId::Attestation);

            match (certificate, intermediate) {
                (Ok(certificate), Ok(intermediate)) => KeyConfig {certificate, intermediate},
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
#[no_mangle]
pub extern fn start_yubikey_rustica_agent(yubikey_serial: u32, slot: u8, config_file: *const c_char, socket_path: *const c_char, notification_fn: unsafe extern "C" fn() -> ()) -> bool {
    println!("Starting a new Rustica instance!");

    let notification_f = move || {
        unsafe { notification_fn(); }
    };

    let cf = unsafe { CStr::from_ptr(config_file) };
    let config_file = match cf.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let config = std::fs::read_to_string(config_file);
    let config: Config = match config {
        Ok(content) => toml::from_str(&content).unwrap(),
        Err(e) => {
            println!("Could not open configuration file: {}", e);
            return false
        },
    };

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
            yk: sshcerts::yubikey::Yubikey::open(yubikey_serial).unwrap(),
            slot: sshcerts::yubikey::SlotId::try_from(slot).unwrap(),
        }),
        identities: HashMap::new(),
        notification_function: Some(Box::new(notification_f)),
    };

    println!("Slot: {:?}", sshcerts::yubikey::SlotId::try_from(slot));

    let sp = unsafe { CStr::from_ptr(socket_path) };
    let socket_path = match sp.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let socket = UnixListener::bind(socket_path).unwrap();
    Agent::run(handler, socket);

    true
}