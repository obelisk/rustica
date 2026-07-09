#[macro_use]
extern crate log;

pub mod config;
pub mod ffi;
pub mod rustica;
pub mod sshagent;

use async_trait::async_trait;
use rustica::key::U2FAttestation;

use config::{Options, UpdatableConfiguration};
use sshagent::constraints::Constraint;

pub use config::Config;
use serde_derive::{Deserialize, Serialize};
pub use sshagent::{error::Error as AgentError, Agent, Identity, Response, SshAgentHandler};

pub use rustica::{
    key::PIVAttestation,
    RefreshError::{ConfigurationError, SigningError},
};

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::{convert::TryFrom, env};

use std::time::SystemTime;

use tokio::runtime::Handle;
use tokio::sync::Mutex;

pub use sshcerts::{
    error::Error as SSHCertsError,
    fido::{generate::generate_new_ssh_key, list_fido_devices},
    ssh::{CertType, SSHCertificateSigner},
    yubikey::piv::{
        AlgorithmId, Error as YkPivError, PinPolicy, RetiredSlotId, SlotId, TouchPolicy, Yubikey,
    },
    Certificate, PrivateKey, PublicKey,
};

#[derive(Debug)]
pub struct CertificateConfig {
    pub principals: Vec<String>,
    pub hosts: Vec<String>,
    pub cert_type: CertType,
    pub duration: u64,
    pub authority: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RusticaServer {
    pub address: String,
    pub ca_pem: String,
    pub mtls_cert: String,
    pub mtls_key: String,
}

#[derive(Debug)]
pub struct YubikeySigner {
    pub slot: SlotId,
    pub yk: Mutex<Yubikey>,
    /// Device serial; keys the per-serial card lock and the PIN env lookup.
    pub serial: u32,
    pub touch_required: bool,
    /// PIN required by the slot's PIN policy (from metadata, like touch_required).
    pub pin_required: bool,
    /// PIN resolved from YK_PIN_<serial>/YK_PIN.
    pub pin: Option<String>,
}

impl YubikeySigner {
    pub fn new(mut yk: Yubikey, slot: SlotId) -> Self {
        let touch_required = yk
            .touch_requirement(&slot)
            .map(|r| r.is_required())
            .unwrap_or(false);
        let pin_required = pin_required_for_slot(&mut yk, &slot);
        let serial: u32 = yk.serial().map(Into::into).unwrap_or(0);
        let pin = yubikey_pin_from_env(serial).or_else(|| env::var("YK_PIN").ok());
        println!(
            "Yubikey signer for slot {slot:?} (serial {serial:?}): pin_required={pin_required}, pin_resolved={}",
            pin.is_some()
        );
        Self {
            yk: yk.into(),
            slot,
            serial,
            touch_required,
            pin_required,
            pin,
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Signatory {
    Yubikey(YubikeySigner),
    Direct(Mutex<PrivateKey>),
}

#[derive(Debug, Clone)]
pub struct YubikeyPIVKeyDescriptor {
    pub serial: u32,
    pub slot: SlotId,
    pub public_key: PublicKey,
    pub pin: Option<String>,
    pub subject: String,
    pub touch_required: bool,
    /// PIN required by the slot's PIN policy (from metadata, like touch_required).
    pub pin_required: bool,
}

pub struct MtlsCredentials {
    certificate: String,
    key: String,
}

#[derive(Debug)]
pub enum RusticaAgentLibraryError {
    CouldNotOpenYubikey(u32),
    CouldNotEnumerateYubikeys(String),
    NoServersReturnedCertificate,
    ServerReturnedInvalidCertificate(sshcerts::error::Error),
    NoServersCouldRegisterKey,
    CouldNotReadConfigurationFile(String),
    BadConfiguration(String),
    UnknownConfigurationVersion(u64),
    NoServersReturnedAllowedSigners,
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
            RusticaAgentLibraryError::NoServersReturnedCertificate => write!(
                f,
                "All servers failed to return a certificate when requested"
            ),
            RusticaAgentLibraryError::ServerReturnedInvalidCertificate(e) => write!(
                f,
                "The requested server returned an invalid SSH certificate: {e}"
            ),
            RusticaAgentLibraryError::NoServersCouldRegisterKey => {
                write!(f, "All servers failed to register the requested key")
            }
            RusticaAgentLibraryError::CouldNotReadConfigurationFile(e) => {
                write!(f, "Could not read configuration file: {e}")
            }
            RusticaAgentLibraryError::BadConfiguration(e) => {
                write!(f, "The configuration could not be parsed: {e}")
            }
            RusticaAgentLibraryError::UnknownConfigurationVersion(e) => {
                write!(f, "Cannot use configuration version: {e}")
            }
            RusticaAgentLibraryError::NoServersReturnedAllowedSigners => {
                write!(
                    f,
                    "All servers failed to return allowed signers when requested"
                )
            }
        }
    }
}

impl std::error::Error for RusticaAgentLibraryError {}

pub struct Handler {
    /// Configuration path that can be updated if a server returns updated
    /// settings
    pub updatable_configuration: Mutex<UpdatableConfiguration>,
    /// A previously issued certificate
    pub cert: Mutex<Option<Certificate>>,
    /// The public key we for the key we are providing a certificate for
    pub pubkey: PublicKey,
    /// The signing method for the private part of our public key. This needs to have
    /// interior mutability because it's sometimes a Yubikey that requires exclusive
    /// access to the USB interface
    pub signatory: Signatory,
    /// When our certificate expires and we must request a new one
    pub stale_at: Mutex<u64>,
    /// Any settings we wish to ask the server for in our certificate
    pub certificate_options: CertificateConfig,
    /// Any other identities added to our agent
    pub identities: Mutex<HashMap<Vec<u8>, PrivateKey>>,
    /// Other PIV identities
    pub piv_identities: HashMap<Vec<u8>, YubikeyPIVKeyDescriptor>,
    /// A function that we will call before calling the signatory
    pub notification_function: Option<Box<dyn Fn() + Send + Sync>>,
    /// Should we list the certificate or key first when we're asked to list
    /// identities
    pub certificate_priority: bool,
    /// When true, suppress the bare primary key and only advertise its
    /// certificate (falls back to the bare key if no certificate is available).
    pub list_primary_certificate_only: bool,
    /// An optional FIDO (sk-*) key exposed as a direct signing key with no
    /// Rustica certificate.
    pub fido_identity: Option<PrivateKey>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handler").field("cert", &self.cert).finish()
    }
}

impl RusticaServer {
    pub fn new(address: String, ca_pem: String, mtls_cert: String, mtls_key: String) -> Self {
        Self {
            address,
            ca_pem,
            mtls_cert,
            mtls_key,
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

impl Handler {
    /// First, fetch the previous cert if present and valid. If cert is still valid, return it.
    ///
    /// If cached cert is invalid, and if fetch_new_cert_if_needed is:
    ///     - true: fetch a new cert from server. Return error if the fetch fails.
    ///     - false: return None.
    async fn get_certificate_async(
        &self,
        fetch_new_cert_if_needed: bool,
    ) -> Result<Option<Certificate>, RusticaAgentLibraryError> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if fetch_new_cert_if_needed {
            let mut stale_at = self.stale_at.lock().await;
            let mut existing_cert = self.cert.lock().await;
            let mut configuration = self.updatable_configuration.lock().await;

            // Fetch a new certificate or use the cached one if it's still valid
            // We add 5 to the timestamp to try and ensure by the time the user
            // taps their key, the certificate is still valid. This appears to
            // primarily be an issue with GitHub pull and push tiers.
            let certificate = match (&*existing_cert, timestamp + 5 < *stale_at) {
                // In the case we have a certificate and it's not expired.
                (Some(cert), true) => {
                    debug!(
                        "Using cached certificate which expires in {} seconds",
                        *stale_at - timestamp
                    );
                    cert.clone()
                }
                // All other cases require us to fetch a certificate from one
                // of the configured servers
                _ => {
                    // Fetch a new certificate from one of the servers
                    let cert = fetch_new_certificate(
                        &mut configuration,
                        &self.signatory,
                        &self.certificate_options,
                        &self.notification_function,
                    )
                    .await?;

                    // This is ugly doing a mutation in a map
                    // Look for a better way to do this.
                    *existing_cert = Some(cert.clone());
                    *stale_at = cert.valid_before;

                    cert
                }
            };
            Ok(Some(certificate))
        } else {
            let stale_at = self.stale_at.lock().await;
            let existing_cert = self.cert.lock().await;

            // Fetch a new certificate or use the cached one if it's still valid
            // We add 5 to the timestamp to try and ensure by the time the user
            // taps their key, the certificate is still valid. This appears to
            // primarily be an issue with GitHub pull and push tiers.
            let certificate = match (&*existing_cert, timestamp + 5 < *stale_at) {
                // In the case we have a certificate and it's not expired.
                (Some(cert), true) => {
                    debug!(
                        "Using cached certificate which expires in {} seconds",
                        *stale_at - timestamp
                    );
                    Some(cert.clone())
                }
                // All other cases require us to fetch a certificate from one
                // of the configured servers
                _ => None,
            };
            Ok(certificate)
        }
    }

    /// Fetch the previous cert if present and valid.
    /// If no such cert is present, return None.
    fn get_certificate(
        &self,
        handle: &Handle,
        fetch_new_cert_if_needed: bool,
    ) -> Result<Option<Certificate>, RusticaAgentLibraryError> {
        handle.block_on(async { self.get_certificate_async(fetch_new_cert_if_needed).await })
    }
}

#[async_trait]
impl SshAgentHandler for Handler {
    async fn add_identity(&self, private_key: PrivateKey) -> Result<Response, AgentError> {
        trace!("Add Identity call");
        let public_key = private_key.pubkey.encode();
        self.identities.lock().await.insert(public_key, private_key);
        Ok(Response::Success)
    }

    async fn add_identity_constrained(
        &self,
        private_key: PrivateKey,
        constraints: Vec<Constraint>,
    ) -> Result<Response, AgentError> {
        trace!("Add Identity Constrained call");
        if !constraints.is_empty() {
            trace!("Key is being added with constraints");
        }
        let public_key = private_key.pubkey.encode();
        self.identities.lock().await.insert(public_key, private_key);
        Ok(Response::Success)
    }

    async fn identities(&self) -> Result<Response, AgentError> {
        trace!("Identities call");
        // We start building identies with the manually loaded keys
        let mut identities: Vec<Identity> = self
            .identities
            .lock()
            .await
            .iter()
            .map(|x| Identity {
                key_blob: x.1.pubkey.encode().to_vec(),
                key_comment: x.1.comment.clone(),
            })
            .collect();

        // Then we add any multimode keys in Yubikey PIV slots
        identities.extend(self.piv_identities.iter().map(|x| Identity {
            key_blob: x.1.public_key.encode().to_vec(),
            key_comment: format!("Yubikey Serial: {} Slot: {:?}", x.1.serial, x.1.slot),
        }));

        let certificate = match self.get_certificate_async(true).await {
            Ok(Some(v)) => Ok(Identity {
                key_blob: v.serialized,
                key_comment: v.comment.unwrap_or_default(),
            }),
            Ok(None) => Err(RusticaAgentLibraryError::NoServersReturnedCertificate),
            Err(e) => Err(e),
        };

        let key = Identity {
            key_blob: self.pubkey.encode().to_vec(),
            key_comment: String::new(),
        };

        let fido = self.fido_identity.as_ref().map(|fido| Identity {
            key_blob: fido.pubkey.encode().to_vec(),
            key_comment: fido.comment.clone(),
        });

        // The last identities are our primary key/certificate (and optional FIDO
        // direct key), ordered by certificate_priority.
        match (certificate, self.certificate_priority) {
            (Err(_), _) => {
                identities.push(Identity {
                    key_blob: self.pubkey.encode().to_vec(),
                    key_comment: "No server returned valid certificate. Only your key is available"
                        .to_string(),
                });
                if let Some(fido) = fido {
                    identities.push(fido);
                }
            }
            // No-touch PIV primary mode: advertise only the certificate, never the bare key.
            (Ok(cert), priority) if self.list_primary_certificate_only => match (fido, priority) {
                (Some(fido), true) => identities.extend(vec![cert, fido]),
                (Some(fido), false) => identities.extend(vec![fido, cert]),
                (None, _) => identities.push(cert),
            },
            (Ok(cert), false) => {
                identities.extend(vec![key, cert]);
                if let Some(fido) = fido {
                    identities.push(fido);
                }
            }
            (Ok(cert), true) => {
                identities.extend(vec![cert, key]);
                if let Some(fido) = fido {
                    identities.push(fido);
                }
            }
        };

        // Finally return all identities
        Ok(Response::Identities(identities))
    }

    /// Sign a request coming in from an SSH command.
    async fn sign_request(
        &self,
        pubkey: Vec<u8>,
        data: Vec<u8>,
        _flags: u32,
    ) -> Result<Response, AgentError> {
        trace!("Sign call");

        // Extract the pubkey fingerprint from either the SSH pubkey or the SSH cert
        let fingerprint = match (
            Certificate::from_bytes(&pubkey),
            PublicKey::from_bytes(&pubkey),
        ) {
            (Ok(cert), _) => cert.key.fingerprint(),
            (_, Ok(pubkey)) => pubkey.fingerprint(),
            _ => return Err(AgentError::from("Invalid key blob")),
        };

        // Tri check to find how to sign the request. Since starting rustica with a file based
        // key is the same process as keys added afterwards, we do this to prevent duplication
        // of the private key based signing code.
        // TODO: @obelisk make this better
        if let Some(private_key) = self.identities.lock().await.get(&pubkey).map(|x| x.clone()) {
            let signature = match private_key.sign(&data) {
                None => return Err(AgentError::from("Signing Error")),
                Some(signature) => signature,
            };

            return Ok(Response::SignResponse { signature });
        } else if let Some(descriptor) = self.piv_identities.get(&pubkey) {
            // Serialize card access so a concurrent reconnect() can't reset
            // the card mid-transaction (SCARD_W_RESET_CARD).
            let serial_lock = yk_serial_lock(descriptor.serial);
            let _serial_guard = serial_lock.lock().await;

            let mut yk = Yubikey::open(descriptor.serial).map_err(|e| {
                println!("Unable to open Yubikey: {e}");
                AgentError::from("Unable to open Yubikey")
            })?;

            let signature = with_reset_retry(&mut yk, |yk| {
                if descriptor.touch_required {
                    if let Some(f) = &self.notification_function {
                        println!("Trying to send a notification");
                        f()
                    } else {
                        println!("No notification function set");
                    }
                } else {
                    println!("Skipping notification for no-touch key");
                }

                match &descriptor.pin {
                    Some(pin) => {
                        verify_yk_pin(yk, descriptor.serial, pin).map_err(CardOpError::Fatal)?
                    }
                    None if descriptor.pin_required => {
                        println!("Key requires a PIN but none was provided (set YK_PIN)");
                        return Err(CardOpError::Fatal(AgentError::from(
                            "Yubikey PIN required but not provided",
                        )));
                    }
                    None => {}
                }

                yk.ssh_cert_signer(&data, &descriptor.slot).map_err(|e| {
                    println!("Signing Error: {e}");
                    classify_yk_error(&e, yk_signing_error(descriptor.pin.is_some()))
                })
            })?;

            return Ok(Response::SignResponse { signature });
        } else if self
            .fido_identity
            .as_ref()
            .is_some_and(|fido| fido.pubkey.fingerprint() == fingerprint)
        {
            let fido = self.fido_identity.as_ref().unwrap();

            if fido.touch_requirement().is_required() {
                if let Some(f) = &self.notification_function {
                    f()
                }
            }

            let signature = match fido.sign(&data) {
                None => return Err(AgentError::from("Signing Error")),
                Some(signature) => signature,
            };

            return Ok(Response::SignResponse { signature });
        } else if let Signatory::Direct(privkey) = &self.signatory {
            let privkey = privkey.lock().await;

            // Don't sign requests if the requested key does not match the signatory
            if privkey.pubkey.fingerprint() != fingerprint {
                return Err(AgentError::from("No such key"));
            }

            if privkey.touch_requirement().is_required() {
                if let Some(f) = &self.notification_function {
                    f()
                }
            }

            let signature = match privkey.sign(&data) {
                None => return Err(AgentError::from("Signing Error")),
                Some(signature) => signature,
            };

            return Ok(Response::SignResponse { signature });
        } else if let Signatory::Yubikey(signer) = &self.signatory {
            let serial_lock = yk_serial_lock(signer.serial);
            let _serial_guard = serial_lock.lock().await;
            let mut yk = signer.yk.lock().await;

            let signature = with_reset_retry(&mut yk, |yk| {
                // Don't sign requests if the requested key does not match the signatory
                let pubkey = yk.ssh_cert_fetch_pubkey(&signer.slot).map_err(|e| {
                    println!("Yubikey Fetch Certificate Error: {e}");
                    classify_yk_error(&e, AgentError::from("Yubikey fetch certificate error"))
                })?;
                if pubkey.fingerprint() != fingerprint {
                    return Err(CardOpError::Fatal(AgentError::from("No such key")));
                }

                // Since we are using the Yubikey for a signing operation the only time they
                // won't have to tap here is if they are using cached keys and this is right after
                // a secure Rustica tap. In most cases, we'll need to send this, rarely, it'll be
                // spurious.
                if signer.touch_required {
                    if let Some(f) = &self.notification_function {
                        f()
                    }
                }

                match &signer.pin {
                    Some(pin) => {
                        verify_yk_pin(yk, signer.serial, pin).map_err(CardOpError::Fatal)?
                    }
                    None if signer.pin_required => {
                        println!("Key requires a PIN but none was provided (set YK_PIN)");
                        return Err(CardOpError::Fatal(AgentError::from(
                            "Yubikey PIN required but not provided",
                        )));
                    }
                    None => {}
                }

                yk.ssh_cert_signer(&data, &signer.slot).map_err(|e| {
                    println!("Signing Error: {e}");
                    classify_yk_error(&e, yk_signing_error(signer.pin.is_some()))
                })
            })?;

            return Ok(Response::SignResponse { signature });
        } else {
            return Err(AgentError::from("Signing Error: No Valid Keys"));
        }
    }
}

/// Per-serial locks serializing all PC/SC access to a physical Yubikey within
/// this process: `reconnect()` (and dropping a `Yubikey` handle) resets the
/// card, killing any other in-flight transaction with `SCARD_W_RESET_CARD`.
///
/// Lock ordering: serial lock OUTER, `YubikeySigner::yk` INNER. Never hold
/// this lock across a network `.await`.
static YK_SERIAL_LOCKS: OnceLock<std::sync::Mutex<HashMap<u32, Arc<Mutex<()>>>>> = OnceLock::new();

/// Returns the process-wide lock for a physical Yubikey serial.
pub(crate) fn yk_serial_lock(serial: u32) -> Arc<Mutex<()>> {
    let map = YK_SERIAL_LOCKS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut map = map.lock().expect("yubikey serial lock map poisoned");
    map.entry(serial).or_default().clone()
}

/// True when a signing error indicates the PC/SC card was reset out from
/// under us (e.g. by another process like `ykman`). `Unsupported` counts
/// because sshcerts collapses resets hit during its key-type fetch into it.
pub(crate) fn is_yk_reset_error(e: &YkPivError) -> bool {
    match e {
        YkPivError::InternalYubiKeyError(msg) => msg.contains("has been reset"),
        YkPivError::Unsupported => true,
        _ => false,
    }
}

/// Error from a single attempt of a card sequence. `Reset` means the failure
/// looked like the card was reset under us and the sequence is worth one
/// retry after a reconnect; `Fatal` aborts immediately.
enum CardOpError {
    Reset(AgentError),
    Fatal(AgentError),
}

impl CardOpError {
    fn into_agent_error(self) -> AgentError {
        match self {
            CardOpError::Reset(e) | CardOpError::Fatal(e) => e,
        }
    }
}

/// Classify a Yubikey error: reset-like failures are retryable.
fn classify_yk_error(e: &YkPivError, err: AgentError) -> CardOpError {
    if is_yk_reset_error(e) {
        CardOpError::Reset(err)
    } else {
        CardOpError::Fatal(err)
    }
}

/// The error for a failed signing op; hint at the likely cause when no PIN
/// was provided.
fn yk_signing_error(pin_provided: bool) -> AgentError {
    if pin_provided {
        AgentError::from("Yubikey signing error")
    } else {
        AgentError::from("Yubikey signing error (slot may require a PIN that wasn't provided)")
    }
}

/// Run a card sequence, reconnecting and retrying ONCE if it fails with a
/// reset-like error. Caller must hold the serial lock for this card.
fn with_reset_retry<T>(
    yk: &mut Yubikey,
    mut op: impl FnMut(&mut Yubikey) -> Result<T, CardOpError>,
) -> Result<T, AgentError> {
    match op(yk) {
        Ok(v) => Ok(v),
        Err(CardOpError::Fatal(e)) => Err(e),
        Err(CardOpError::Reset(first_err)) => {
            println!("Card sequence hit a reset-like error, reconnecting and retrying once");
            if let Err(e) = yk.reconnect() {
                println!("Reconnect after card reset failed: {e}");
                return Err(first_err);
            }
            op(yk).map_err(CardOpError::into_agent_error)
        }
    }
}

/// Whether a slot's PIN policy requires the PIN before a private-key operation.
/// Only `Once`/`Always` count; `Never` and missing metadata mean no PIN, so we
/// never risk the retry counter on keys that don't need it.
pub(crate) fn pin_required_for_slot(yk: &mut Yubikey, slot: &SlotId) -> bool {
    match yubikey::piv::metadata(&mut yk.yk, *slot) {
        Ok(metadata) => matches!(
            metadata.policy,
            Some((PinPolicy::Once | PinPolicy::Always, _))
        ),
        Err(_) => false,
    }
}

/// PIN-only verification (no management key needed for signing). Fails without
/// retrying so we never burn through the PIN retry counter.
pub(crate) fn verify_yk_pin(yk: &mut Yubikey, serial: u32, pin: &str) -> Result<(), AgentError> {
    if let Err(e) = yk.yk.verify_pin(pin.as_bytes()) {
        println!("PIN verification error for Yubikey {serial}: {e}");
        let tries_remaining = yk.yk.get_pin_retries().map(|x| x as i32).map_err(|e| {
            println!("Could not fetch pin retries [{e}] for Yubikey: {serial}");
            AgentError::from("Could not fetch pin retries")
        })?;
        println!("Could not verify PIN for Yubikey {serial}: {tries_remaining} tries remaining");
        return Err(AgentError::from("Yubikey PIN verification error"));
    }
    Ok(())
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

fn piv_key_descriptor_from_yubikey(
    yk: &mut Yubikey,
    serial: u32,
    slot: SlotId,
    pin: Option<String>,
) -> Option<YubikeyPIVKeyDescriptor> {
    let public_key = yk.ssh_cert_fetch_pubkey(&slot).ok()?;
    let subject = yk.fetch_subject(&slot).unwrap_or_default();
    let touch_required = yk
        .touch_requirement(&slot)
        .map(|r| r.is_required())
        .unwrap_or(false);
    let pin_required = pin_required_for_slot(yk, &slot);

    Some(YubikeyPIVKeyDescriptor {
        serial,
        slot,
        public_key,
        pin,
        subject,
        touch_required,
        pin_required,
    })
}

/// Provisions a new keypair on the Yubikey with the given settings.
pub async fn provision_new_key(
    yubikey: YubikeySigner,
    pin: &str,
    subj: &str,
    mgm_key: &[u8],
    touch_policy: TouchPolicy,
    pin_policy: PinPolicy,
) -> Option<PIVAttestation> {
    println!("Provisioning new NISTP384 key in slot: {:?}", &yubikey.slot);
    println!("Creating key with touch policy: {:?}", touch_policy);

    let mut yk = yubikey.yk.lock().await;

    if yk.unlock(pin.as_bytes(), mgm_key).is_err() {
        println!("Could not unlock key");
        return None;
    }

    match yk.provision_p384(&yubikey.slot, subj, touch_policy, pin_policy) {
        Ok(_) => {
            let certificate = yk.fetch_attestation(&yubikey.slot);
            let intermediate = yk.fetch_certificate(&SlotId::Attestation);

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

/// `YK_PIN_<serial>` takes precedence over `YK_PIN`.
pub(crate) fn yubikey_pin_from_env(serial: u32) -> Option<String> {
    env::var(format!("YK_PIN_{serial}"))
        .ok()
        .or_else(|| env::var("YK_PIN").ok())
}

/// List all PIV keys on all connected Yubikeys
pub fn get_all_piv_keys(
) -> Result<HashMap<Vec<u8>, YubikeyPIVKeyDescriptor>, RusticaAgentLibraryError> {
    let mut all_keys = HashMap::new();
    let serials = list_yubikey_serials()?;

    for serial in serials {
        let serial = serial as u32;
        let pin = yubikey_pin_from_env(serial);

        match &mut Yubikey::open(serial) {
            Ok(yk) => {
                for slot in 0x82..0x96_u8 {
                    let slot = SlotId::Retired(RetiredSlotId::try_from(slot).unwrap());
                    if let Some(descriptor) =
                        piv_key_descriptor_from_yubikey(yk, serial, slot, pin.clone())
                    {
                        all_keys.insert(descriptor.public_key.encode().to_vec(), descriptor);
                    }
                }
            }
            Err(_e) => return Err(RusticaAgentLibraryError::CouldNotOpenYubikey(serial)),
        }
    }

    Ok(all_keys)
}

/// Return the string that when executed in a standard shell will configure a repository
/// for SSH signing with the given PublicKey
pub fn git_config_from_public_key(public_key: &PublicKey) -> String {
    let base = "git config --local";
    format!(
        "{base} gpg.format ssh && {base} commit.gpgsign true && {base} user.signingKey \"key::{}\"",
        public_key.to_string()
    )
}

/// Fetch a new certificate from one of the provided servers
/// in the list. We will try them in order and error if none
/// return a usable certificate
pub async fn fetch_new_certificate(
    configuration: &mut UpdatableConfiguration,
    signatory: &Signatory,
    options: &CertificateConfig,
    notification_function: &Option<Box<dyn Fn() + Send + Sync>>,
) -> Result<Certificate, RusticaAgentLibraryError> {
    for server in configuration.get_servers_mut() {
        match server
            .refresh_certificate_async(signatory, options, notification_function)
            .await
        {
            Ok((cert, mtls_credentials)) => {
                let parsed_cert = Certificate::from_string(&cert.cert)
                    .map_err(|e| RusticaAgentLibraryError::ServerReturnedInvalidCertificate(e))?;

                if let Some(mtls_credentials) = mtls_credentials {
                    if !mtls_credentials.certificate.is_empty() {
                        server.mtls_cert = mtls_credentials.certificate.replace("\r", "");
                    }

                    if !mtls_credentials.key.is_empty() {
                        server.mtls_key = mtls_credentials.key.replace("\r", "");
                    }

                    if let Err(e) = configuration.write() {
                        error!("Server returned new mTLS credentials but the configuration file couldn't be updated: {e}");
                    } else {
                        println!("Your access credentials to the server have been updated");
                    }
                }
                return Ok(parsed_cert);
            }
            Err(e) => {
                error!(
                    "Could not fetch certificate from: {}. Gave error: {}",
                    server.address,
                    e.to_string()
                )
            }
        }
    }
    Err(RusticaAgentLibraryError::NoServersReturnedCertificate)
}

/// Fetch a new X509 certificate from one of the provided servers
/// in the list. We will try them in order and error if none
/// return a usable certificate
pub async fn fetch_new_attested_x509_certificate(
    servers: &[RusticaServer],
    signatory: &mut Signatory,
) -> Result<Vec<u8>, RusticaAgentLibraryError> {
    for server in servers.iter() {
        match server
            .refresh_attested_x509_certificate_async(signatory)
            .await
        {
            Ok(certificate) => return Ok(certificate),
            Err(e) => {
                error!(
                    "Could not fetch X509 certificate from: {}. Gave error: {}",
                    server.address,
                    e.to_string()
                )
            }
        }
    }
    Err(RusticaAgentLibraryError::NoServersReturnedCertificate)
}

/// Register a U2F key (along with its attestation) with a a remote server.
/// Will return an error if none of the servers report the key was successfully
/// registered. This will also only register the key with one server and will
/// return successfully once one accepts the key.
pub async fn register_u2f_key(
    servers: &[RusticaServer],
    signatory: &mut Signatory,
    app_name: &str,
    attestation: &U2FAttestation,
) -> Result<(), RusticaAgentLibraryError> {
    for server in servers.iter() {
        match server
            .register_u2f_key_async(signatory, app_name, &attestation)
            .await
        {
            Ok(_) => return Ok(()),
            Err(e) => {
                error!(
                    "Could not register U2F key with server: {}. Gave error: {}",
                    server.address,
                    e.to_string(),
                )
            }
        }
    }
    Err(RusticaAgentLibraryError::NoServersCouldRegisterKey)
}

/// Register a PIV key (along with its attestation) with a a remote server.
/// Will return an error if none of the servers report the key was successfully
/// registered. This will also only register the key with one server and will
/// return successfully once one accepts the key.
pub async fn register_key(
    servers: &[RusticaServer],
    signatory: &mut Signatory,
    attestation: &PIVAttestation,
) -> Result<(), RusticaAgentLibraryError> {
    for server in servers.iter() {
        match server.register_key_async(signatory, &attestation).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                error!(
                    "Could not register key with server: {}. Gave error: {}",
                    server.address,
                    e.to_string(),
                )
            }
        }
    }
    Err(RusticaAgentLibraryError::NoServersCouldRegisterKey)
}

pub async fn get_allowed_signers(
    servers: &[RusticaServer],
) -> Result<String, RusticaAgentLibraryError> {
    for server in servers.iter() {
        match server.get_allowed_signers_async().await {
            Ok(allowed_signers) => return Ok(allowed_signers),
            Err(e) => {
                error!(
                    "Could not fetch allowed signers from server: {}. Gave error: {}",
                    server.address,
                    e.to_string(),
                )
            }
        }
    }
    Err(RusticaAgentLibraryError::NoServersReturnedAllowedSigners)
}
