#[macro_use]
extern crate log;

pub mod config;
pub mod ffi;
pub mod rustica;
pub mod sshagent;

use async_trait::async_trait;
use rustica::key::U2FAttestation;

use config::{Options, UpdatableConfiguration};

pub use config::Config;
use serde_derive::{Deserialize, Serialize};
pub use sshagent::{error::Error as AgentError, Agent, Identity, Response, SshAgentHandler};

pub use rustica::{
    key::PIVAttestation,
    RefreshError::{ConfigurationError, SigningError},
};

use std::collections::HashMap;
use std::{convert::TryFrom, env};

use std::time::SystemTime;

use tokio::sync::Mutex;

pub use sshcerts::{
    error::Error as SSHCertsError,
    fido::{generate::generate_new_ssh_key, list_fido_devices},
    ssh::{CertType, SSHCertificateSigner},
    yubikey::piv::{AlgorithmId, PinPolicy, RetiredSlotId, SlotId, TouchPolicy, Yubikey},
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
    NoServersReturnedAuthorizedSignerKeys,
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
            RusticaAgentLibraryError::NoServersReturnedAuthorizedSignerKeys => {
                write!(f, "All servers failed to return a list of signer keys when requested")
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
    pub cert: Mutex<Option<Identity>>,
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

#[async_trait]
impl SshAgentHandler for Handler {
    async fn add_identity(&self, private_key: PrivateKey) -> Result<Response, AgentError> {
        trace!("Add Identity call");
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

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

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
                Ok(cert.clone())
            }
            // All other cases require us to fetch a certificate from one
            // of the configured servers
            _ => {
                // Fetch a new certificate from one of the servers
                fetch_new_certificate(
                    &mut configuration,
                    &self.signatory,
                    &self.certificate_options,
                    &self.notification_function,
                )
                .await
                .map(|cert| {
                    let ident = Identity {
                        key_blob: cert.serialized,
                        key_comment: cert.comment.unwrap_or_default(),
                    };

                    // This is ugly doing a mutation in a map
                    // Look for a better way to do this.
                    *existing_cert = Some(ident.clone());
                    *stale_at = cert.valid_before;

                    ident
                })
            }
        };

        let key = Identity {
            key_blob: self.pubkey.encode().to_vec(),
            key_comment: String::new(),
        };

        // The last identities are our key and certificate in the requested order
        match (certificate, self.certificate_priority) {
            (Err(_), _) => identities.push(Identity {
                key_blob: self.pubkey.encode().to_vec(),
                key_comment: "No server returned valid certificate. Only your key is available"
                    .to_string(),
            }),
            (Ok(cert), false) => identities.extend(vec![key, cert]),
            (Ok(cert), true) => identities.extend(vec![cert, key]),
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
            let mut yk = Yubikey::open(descriptor.serial).map_err(|e| {
                println!("Unable to open Yubikey: {e}");
                AgentError::from("Unable to open Yubikey")
            })?;

            if let Some(f) = &self.notification_function {
                println!("Trying to send a notification");
                f()
            } else {
                println!("No notification function set");
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
            let privkey = privkey.lock().await;

            // Don't sign requests if the requested key does not match the signatory
            if privkey.pubkey.fingerprint() != fingerprint {
                return Err(AgentError::from("No such key"));
            }

            let signature = match privkey.sign(&data) {
                None => return Err(AgentError::from("Signing Error")),
                Some(signature) => signature,
            };

            return Ok(Response::SignResponse { signature });
        } else if let Signatory::Yubikey(signer) = &self.signatory {
            let mut yk = signer.yk.lock().await;
            // Don't sign requests if the requested key does not match the signatory
            if yk
                .ssh_cert_fetch_pubkey(&signer.slot)
                .map_err(|e| {
                    println!("Yubikey Fetch Certificate Error: {e}");
                    AgentError::from("Yubikey fetch certificate error")
                })?
                .fingerprint()
                != fingerprint
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

            let signature = yk.ssh_cert_signer(&data, &signer.slot).map_err(|e| {
                println!("Signing Error: {e}");
                AgentError::from("Yubikey signing error")
            })?;

            return Ok(Response::SignResponse { signature });
        } else {
            return Err(AgentError::from("Signing Error: No Valid Keys"));
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
pub async fn provision_new_key(
    yubikey: YubikeySigner,
    pin: &str,
    subj: &str,
    mgm_key: &[u8],
    require_touch: bool,
    pin_policy: PinPolicy,
) -> Option<PIVAttestation> {
    println!("Provisioning new NISTP384 key in slot: {:?}", &yubikey.slot);

    let policy = if require_touch {
        println!("You're creating a key that will require touch to use.");
        TouchPolicy::Always
    } else {
        TouchPolicy::Cached
    };

    let mut yk = yubikey.yk.lock().await;

    if yk.unlock(pin.as_bytes(), mgm_key).is_err() {
        println!("Could not unlock key");
        return None;
    }

    match yk.provision(
        &yubikey.slot,
        subj,
        AlgorithmId::EccP384,
        policy,
        pin_policy,
    ) {
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

/// List all PIV keys on all connected Yubikeys
pub fn get_all_piv_keys(
) -> Result<HashMap<Vec<u8>, YubikeyPIVKeyDescriptor>, RusticaAgentLibraryError> {
    let mut all_keys = HashMap::new();
    let serials = list_yubikey_serials()?;

    let global_pin = match env::var("YK_PIN") {
        Ok(val) => Some(val),
        Err(_e) => None,
    };

    for serial in serials {
        let pin = match env::var(format!("YK_PIN_{serial}")) {
            Ok(val) => Some(val),
            Err(_e) => None,
        };

        let pin = match (pin, &global_pin) {
            (Some(pin), _) => Some(pin),
            (None, Some(pin)) => Some(pin.clone()),
            (None, None) => None,
        };

        let serial = serial as u32;
        match &mut Yubikey::open(serial) {
            Ok(yk) => {
                for slot in 0x82..0x96_u8 {
                    let slot = SlotId::Retired(RetiredSlotId::try_from(slot).unwrap());
                    if let Ok(pubkey) = yk.ssh_cert_fetch_pubkey(&slot) {
                        let subject = yk.fetch_subject(&slot).unwrap_or_default();
                        let descriptor = YubikeyPIVKeyDescriptor {
                            serial,
                            slot,
                            public_key: pubkey.clone(),
                            pin: pin.clone(),
                            subject,
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

pub async fn get_authorized_signers(
    servers: &[RusticaServer],
) -> Result<String, RusticaAgentLibraryError> {
    for server in servers.iter() {
        match server.get_all_signer_keys().await {
            Ok(signer_keys) => return Ok(signer_keys),
            Err(e) => {
                error!(
                    "Could not fetch signer list from server: {}. Gave error: {}",
                    server.address,
                    e.to_string(),
                )
            }
        }
    }
    Err(RusticaAgentLibraryError::NoServersReturnedAuthorizedSignerKeys)
}
