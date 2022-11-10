#[macro_use]
extern crate log;

pub mod rustica;
pub mod sshagent;

use serde_derive::Deserialize;

pub use sshagent::{error::Error as AgentError, Agent, Identity, Response, SshAgentHandler};

pub use rustica::{
    key::PIVAttestation,
    RefreshError::{ConfigurationError, SigningError},
};

use rustica::key::U2FAttestation;

use sshcerts::fido::generate::generate_new_ssh_key;
use sshcerts::ssh::{CertType, Certificate, PrivateKey, PublicKey, SSHCertificateSigner};
use sshcerts::yubikey::piv::{AlgorithmId, PinPolicy, RetiredSlotId, SlotId, TouchPolicy, Yubikey};

use std::fs::File;
use std::{collections::HashMap, os::unix::prelude::PermissionsExt};
use std::{convert::TryFrom, slice};

use std::time::SystemTime;

// FFI related imports
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_long};
use std::os::unix::net::UnixListener;

#[derive(Clone, Debug, Deserialize)]
pub struct Options {
    pub principals: Option<Vec<String>>,
    pub hosts: Option<Vec<String>>,
    pub kind: Option<String>,
    pub duration: Option<u64>,
    pub authority: Option<String>,
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
    pub authority: String,
}

#[derive(Debug)]
pub struct RusticaServer {
    pub address: String,
    pub ca: String,
    pub mtls_cert: String,
    pub mtls_key: String,
    pub runtime: tokio::runtime::Runtime,
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

#[derive(Debug)]
pub struct YubikeyPIVKeyDescriptor {
    pub serial: u32,
    pub slot: SlotId,
    pub public_key: PublicKey,
    pub pin: Option<String>,
}

#[derive(Debug)]
pub enum RusticaAgentLibraryError {
    CouldNotOpenYubikey(u32),
    CouldNotEnumerateYubikeys(String),
}

impl std::fmt::Display for RusticaAgentLibraryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            RusticaAgentLibraryError::CouldNotOpenYubikey(sn) => {
                write!(f, "Could not open Yubikey with serial: {sn}")
            }
            RusticaAgentLibraryError::CouldNotEnumerateYubikeys(e) => {
                write!(f, "Could not enumerate Yubikeys: {e}")
            }
        }
    }
}

impl std::error::Error for RusticaAgentLibraryError {}

pub struct Handler {
    /// a GRPC client for making requests to a Rustica server
    pub server: RusticaServer,
    /// A previously issued certificate
    pub cert: Option<Identity>,
    /// The public key we for the key we are providing a certificate for
    pub pubkey: PublicKey,
    /// The signing method for the private part of our public key
    pub signatory: Signatory,
    /// When our certificate expires and we must request a new one
    pub stale_at: u64,
    /// Any settings we wish to ask the server for in our certificate
    pub certificate_options: CertificateConfig,
    /// Any other identities added to our agent
    pub identities: HashMap<Vec<u8>, PrivateKey>,
    /// Other PIV identities
    pub piv_identities: HashMap<Vec<u8>, YubikeyPIVKeyDescriptor>,
    /// A function that we will call before calling the signatory
    pub notification_function: Option<Box<dyn Fn() + Send + Sync>>,
    /// Should we list the certificate or key first when we're asked to list
    /// identities
    pub certificate_priority: bool,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handler")
            .field("server", &self.server)
            .field("cert", &self.cert)
            .finish()
    }
}

impl RusticaServer {
    pub fn new(address: String, ca: String, mtls_cert: String, mtls_key: String) -> Self {
        Self {
            address,
            ca,
            mtls_cert,
            mtls_key,
            runtime: tokio::runtime::Runtime::new().unwrap(),
        }
    }
}

impl From<Option<Options>> for CertificateConfig {
    fn from(co: Option<Options>) -> CertificateConfig {
        match co {
            None => CertificateConfig {
                cert_type: CertType::User,
                duration: 10,
                hosts: vec![],
                principals: vec![],
                authority: String::new(),
            },
            Some(co) => CertificateConfig {
                cert_type: CertType::try_from(
                    co.kind.unwrap_or_else(|| String::from("user")).as_str(),
                )
                .unwrap_or(CertType::User),
                duration: co.duration.unwrap_or(10),
                hosts: co.hosts.unwrap_or_default(),
                principals: co.principals.unwrap_or_default(),
                authority: co.authority.unwrap_or_default(),
            },
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
        let mut identities = vec![];
        // Build identities from the private keys we have loaded
        let mut extra_identities: Vec<Identity> = self
            .identities
            .iter()
            .map(|x| Identity {
                key_blob: x.1.pubkey.encode().to_vec(),
                key_comment: x.1.comment.clone(),
            })
            .collect();

        extra_identities.extend(self.piv_identities.iter().map(|x| Identity {
            key_blob: x.1.public_key.encode().to_vec(),
            key_comment: format!("Yubikey Serial: {} Slot: {:?}", x.1.serial, x.1.slot),
        }));

        // If the time hasn't expired on our certificate, we don't need to fetch a new one
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if let Some(cert) = &self.cert {
            if timestamp < self.stale_at {
                debug!("Certificate has not expired, not refreshing");
                let key_ident = Identity {
                    key_blob: self.pubkey.encode().to_vec(),
                    key_comment: String::new(),
                };

                if self.certificate_priority {
                    identities.push(cert.clone());
                    identities.push(key_ident);
                } else {
                    identities.push(key_ident);
                    identities.push(cert.clone());
                }

                identities.append(&mut extra_identities);

                return Ok(Response::Identities(identities));
            }
        }

        if let Some(f) = &self.notification_function {
            f()
        }

        // Grab a new certificate from the server because we don't have a valid one
        match self
            .server
            .get_custom_certificate(&mut self.signatory, &self.certificate_options)
        {
            Ok(response) => {
                let parsed_cert =
                    Certificate::from_string(&response.cert).map_err(|e| AgentError {
                        details: e.to_string(),
                    })?;
                info!("{:#}", parsed_cert);
                let cert: Vec<&str> = response.cert.split(' ').collect();
                let raw_cert = base64::decode(cert[1]).unwrap_or_default();
                let cert_ident = Identity {
                    key_blob: raw_cert,
                    key_comment: response.comment.clone(),
                };
                self.cert = Some(cert_ident.clone());

                // Add our signatory backed public key as well for systems that
                // don't understand certificates or to make them available when
                // perhaps fetching a new certificate is not possible. Useful
                // for Git commit signing.
                let key_ident = Identity {
                    key_blob: self.pubkey.encode().to_vec(),
                    key_comment: String::new(),
                };

                if self.certificate_priority {
                    identities.push(cert_ident);
                    identities.push(key_ident);
                } else {
                    identities.push(key_ident);
                    identities.push(cert_ident);
                }
                identities.append(&mut extra_identities);
            }
            Err(e) => {
                error!("Refresh certificate error: {:?}", e);
                // We used to error on this, but now we will just return without the certificate.
                // We cannot really pass any dianostic information and not returning
                // the certificate causes similar failures to the agent not working entirely
                // except you can continue to use non-certificate functionality.
                // for Git commit signing.
                identities.push(Identity {
                    key_blob: self.pubkey.encode().to_vec(),
                    key_comment: format!("Only key available, Certificate refresh error: {e}, "),
                });
            }
        }
        return Ok(Response::Identities(identities));
    }

    /// Sign a request coming in from an SSH command.
    fn sign_request(
        &mut self,
        pubkey: Vec<u8>,
        data: Vec<u8>,
        _flags: u32,
    ) -> Result<Response, AgentError> {
        // Tri check to find how to sign the request. Since starting rustica with a file based
        // key is the same process as keys added afterwards, we do this to prevent duplication
        // of the private key based signing code.
        // TODO: @obelisk make this better
        let private_key: Option<&PrivateKey> = if self.identities.contains_key(&pubkey) {
            Some(&self.identities[&pubkey])
        } else if let Some(descriptor) = self.piv_identities.get(&pubkey) {
            let mut yk = Yubikey::open(descriptor.serial).map_err(|e| {
                println!("Unable to open Yubikey: {e}");
                AgentError::from("Unable to open Yubikey")
            })?;

            if let Some(f) = &self.notification_function {
                f()
            }

            if let Some(pin) = &descriptor.pin {
                if let Err(e) = yk.unlock(
                    pin.as_bytes(),
                    &hex::decode("010203040506070801020304050607080102030405060708").unwrap(),
                ) {
                    println!("Unlock Error: {e}");
                    let tries_remaining =
                        yk.yk.get_pin_retries().map(|x| x as i32).map_err(|e| {
                            println!(
                                "Could not fetch pin retries [{e}] for Yubikey: {}",
                                descriptor.serial
                            );
                            AgentError::from("Could not fetch pin retries")
                        })?;
                    println!("Could not unlock Yubikey: {tries_remaining} tries remaining");
                    return Err(AgentError::from("Yubikey unlocking error"));
                }
            }

            let signature = yk.ssh_cert_signer(&data, &descriptor.slot).map_err(|e| {
                println!("Signing Error: {e}");
                AgentError::from("Yubikey signing error")
            })?;

            return Ok(Response::SignResponse { signature });
        } else if let Signatory::Direct(privkey) = &self.signatory {
            // Don't sign requests if the requested key does not match the signatory
            if privkey.pubkey.encode() != pubkey {
                return Err(AgentError::from("No such key"));
            }

            Some(privkey)
        } else if let Signatory::Yubikey(signer) = &mut self.signatory {
            // Don't sign requests if the requested key does not match the signatory
            if signer
                .yk
                .ssh_cert_fetch_pubkey(&signer.slot)
                .map_err(|e| {
                    println!("Yubikey Fetch Certificate Error: {e}");
                    AgentError::from("Yubikey fetch certificate error")
                })?
                .encode()
                != pubkey
            {
                return Err(AgentError::from("No such key"));
            }
            // Since we are using the Yubikey for a signing operation the only time they
            // won't have to tap here is if they are using cached keys and this is right after
            // a secure Rustica tap. In most cases, we'll need to send this, rarely, it'll be
            // spurious.
            if let Some(f) = &self.notification_function {
                f()
            }

            let signature = signer
                .yk
                .ssh_cert_signer(&data, &signer.slot)
                .map_err(|e| {
                    println!("Signing Error: {e}");
                    AgentError::from("Yubikey signing error")
                })?;

            return Ok(Response::SignResponse { signature });
        } else {
            None
        };

        match private_key {
            Some(key) => {
                let signature = match key.sign(&data) {
                    None => return Err(AgentError::from("Signing Error")),
                    Some(signature) => signature,
                };

                Ok(Response::SignResponse { signature })
            }
            None => Err(AgentError::from("Signing Error: No Valid Keys")),
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
    } else if slot.len() == 4 && slot.starts_with("0x") {
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
        None => Err(String::from(
            "Provided slot was not valid. Should be R1 - R20 or a raw hex identifier",
        )),
    }
}

/// Provisions a new keypair on the Yubikey with the given settings.
pub fn provision_new_key(
    mut yubikey: YubikeySigner,
    pin: &str,
    subj: &str,
    mgm_key: &[u8],
    require_touch: bool,
) -> Option<PIVAttestation> {
    println!("Provisioning new NISTP384 key in slot: {:?}", &yubikey.slot);

    let policy = if require_touch {
        println!("You're creating a key that will require touch to use.");
        TouchPolicy::Always
    } else {
        TouchPolicy::Cached
    };

    if yubikey.yk.unlock(pin.as_bytes(), mgm_key).is_err() {
        println!("Could not unlock key");
        return None;
    }

    match yubikey.yk.provision(
        &yubikey.slot,
        subj,
        AlgorithmId::EccP384,
        policy,
        PinPolicy::Never,
    ) {
        Ok(_) => {
            let certificate = yubikey.yk.fetch_attestation(&yubikey.slot);
            let intermediate = yubikey.yk.fetch_certificate(&SlotId::Attestation);

            match (certificate, intermediate) {
                (Ok(certificate), Ok(intermediate)) => Some(PIVAttestation {
                    certificate,
                    intermediate,
                }),
                _ => None,
            }
        }
        Err(_) => panic!("Could not provision device with new key"),
    }
}

pub fn list_yubikey_serials() -> Result<Vec<i64>, RusticaAgentLibraryError> {
    let mut serials: Vec<i64> = vec![];

    match &mut yubikey::reader::Context::open() {
        Ok(readers) => {
            for reader in readers
                .iter()
                .unwrap()
                .collect::<Vec<yubikey::reader::Reader>>()
            {
                let reader = reader.open();
                if reader.is_err() {
                    continue;
                }
                let reader = reader.unwrap();
                let serial: u32 = reader.serial().into();
                serials.push(serial.into());
            }
        }
        Err(e) => {
            return Err(RusticaAgentLibraryError::CouldNotEnumerateYubikeys(
                e.to_string(),
            ))
        }
    };

    Ok(serials)
}

/// List all PIV keys on all connected Yubikeys
pub fn get_all_piv_keys(
) -> Result<HashMap<Vec<u8>, YubikeyPIVKeyDescriptor>, RusticaAgentLibraryError> {
    let mut all_keys = HashMap::new();
    let serials = list_yubikey_serials()?;

    for serial in serials {
        let serial = serial as u32;
        match &mut Yubikey::open(serial) {
            Ok(yk) => {
                for slot in 0x82..0x96_u8 {
                    let slot = SlotId::Retired(RetiredSlotId::try_from(slot).unwrap());
                    if let Ok(pubkey) = yk.ssh_cert_fetch_pubkey(&slot) {
                        let descriptor = YubikeyPIVKeyDescriptor {
                            serial,
                            slot,
                            public_key: pubkey.clone(),
                            pin: None,
                        };
                        all_keys.insert(pubkey.encode().to_vec(), descriptor);
                    }
                }
            }
            Err(_e) => return Err(RusticaAgentLibraryError::CouldNotOpenYubikey(serial)),
        }
    }

    Ok(all_keys)
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
        Ok(s) => match toml::from_str(s) {
            Ok(c) => c,
            Err(e) => {
                println!("Error: Could not parse the configuration data: {}", e);
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

    let server = RusticaServer::new(
        config.server.unwrap(),
        config.ca_pem.unwrap(),
        config.mtls_cert.unwrap(),
        config.mtls_key.unwrap(),
    );

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

    match server.register_u2f_key(&mut signatory, "ssh:RusticaAgentFIDOKey", &u2f_attestation) {
        Ok(_) => {
            println!("Key was successfully registered");
            true
        }
        Err(e) => {
            error!("Key could not be registered. Server said: {}", e);
            std::fs::remove_file(out).unwrap();
            false
        }
    }
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

    let config: Config = toml::from_str(config_data).unwrap();

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

    let server = RusticaServer::new(
        config.server.unwrap(),
        config.ca_pem.unwrap(),
        config.mtls_cert.unwrap(),
        config.mtls_key.unwrap(),
    );

    match server.register_key(&mut signatory, &key_config) {
        Ok(_) => {
            println!("Key was successfully registered");
            true
        }
        Err(e) => {
            error!("Key could not be registered. Server said: {}", e);
            false
        }
    }
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
) -> bool {
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
    config_data: *const c_char,
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
) -> bool {
    println!("Starting a new Rustica instance!");

    let notification_f = move || {
        notification_fn();
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

    let authority = CStr::from_ptr(authority);
    let authority = match authority.to_str() {
        Err(_) => return false,
        Ok(s) => s.to_owned(),
    };

    let private_key = CStr::from_ptr(private_key);
    let mut private_key = match private_key.to_str() {
        Err(_) => return false,
        Ok(s) => {
            if let Ok(p) = PrivateKey::from_string(s) {
                p
            } else {
                return false;
            }
        }
    };

    if !pin.is_null() {
        let pin = CStr::from_ptr(pin);
        let pin = match pin.to_str() {
            Err(_) => return false,
            Ok(s) => s,
        };
        private_key.set_pin(pin);
    }

    if !device.is_null() {
        let device = CStr::from_ptr(device);
        let device = match device.to_str() {
            Err(_) => return false,
            Ok(s) => s,
        };

        private_key.set_device_path(device);
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
            Err(_) => return false,
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
            Err(_) => return false,
        };

        let pubkey = match yk.ssh_cert_fetch_pubkey(&slot) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        piv_identities.insert(
            pubkey.encode().to_vec(),
            YubikeyPIVKeyDescriptor {
                public_key: pubkey,
                serial,
                slot,
                pin,
            },
        );
    }

    println!("Fingerprint: {:?}", private_key.pubkey.fingerprint().hash);

    println!("Additional Fingerprints:");
    for key in piv_identities.iter() {
        println!("{}", key.1.public_key.fingerprint().hash);
    }

    let config: Config = toml::from_str(config_data).unwrap();
    let mut certificate_options = CertificateConfig::from(config.options);
    certificate_options.authority = authority;

    let handler = Handler {
        cert: None,
        stale_at: 0,
        pubkey: private_key.pubkey.clone(),
        certificate_options,
        server: RusticaServer::new(
            config.server.unwrap(),
            config.ca_pem.unwrap(),
            config.mtls_cert.unwrap(),
            config.mtls_key.unwrap(),
        ),
        signatory: Signatory::Direct(private_key),
        identities: HashMap::new(),
        piv_identities,
        notification_function: Some(Box::new(notification_f)),
        certificate_priority,
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
pub unsafe extern "C" fn start_yubikey_rustica_agent(
    yubikey_serial: u32,
    slot: u8,
    config_data: *const c_char,
    socket_path: *const c_char,
    notification_fn: unsafe extern "C" fn() -> (),
    authority: *const c_char,
    certificate_priority: bool,
) -> bool {
    println!("Starting a new Rustica instance!");

    let notification_f = move || {
        notification_fn();
    };

    let cf = CStr::from_ptr(config_data);
    let config_data = match cf.to_str() {
        Err(_) => return false,
        Ok(s) => s,
    };

    let authority = CStr::from_ptr(authority);
    let authority = match authority.to_str() {
        Err(_) => return false,
        Ok(s) => s.to_owned(),
    };

    let config: Config = toml::from_str(config_data).unwrap();

    let mut certificate_options = CertificateConfig::from(config.options);
    certificate_options.authority = authority;

    let mut yk = Yubikey::open(yubikey_serial).unwrap();
    let slot = SlotId::try_from(slot).unwrap();
    let pubkey = match yk.ssh_cert_fetch_pubkey(&slot) {
        Ok(cert) => cert,
        Err(_) => return false,
    };

    let handler = Handler {
        cert: None,
        stale_at: 0,
        pubkey,
        certificate_options,
        server: RusticaServer::new(
            config.server.unwrap(),
            config.ca_pem.unwrap(),
            config.mtls_cert.unwrap(),
            config.mtls_key.unwrap(),
        ),
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
        Err(_) => return false,
        Ok(s) => s,
    };

    let socket = UnixListener::bind(socket_path).unwrap();
    Agent::run(handler, socket);

    true
}
