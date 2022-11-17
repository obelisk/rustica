#[macro_use]
extern crate log;

pub mod ffi;
pub mod rustica;
pub mod sshagent;

use async_trait::async_trait;
use serde_derive::Deserialize;

pub use sshagent::{error::Error as AgentError, Agent, Identity, Response, SshAgentHandler};

pub use rustica::{
    key::PIVAttestation,
    RefreshError::{ConfigurationError, SigningError},
};

use sshcerts::ssh::{CertType, Certificate, PrivateKey, PublicKey, SSHCertificateSigner};
use sshcerts::yubikey::piv::{AlgorithmId, PinPolicy, RetiredSlotId, SlotId, TouchPolicy, Yubikey};
use tokio::runtime::Handle;

use std::collections::HashMap;
use std::{convert::TryFrom, env};

use std::time::SystemTime;

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
    pub handle: Handle,
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
    pub fn new(
        address: String,
        ca: String,
        mtls_cert: String,
        mtls_key: String,
        handle: Handle,
    ) -> Self {
        Self {
            address,
            ca,
            mtls_cert,
            mtls_key,
            handle,
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
    fn add_identity(&mut self, private_key: PrivateKey) -> Result<Response, AgentError> {
        let public_key = private_key.pubkey.encode();
        self.identities.insert(public_key, private_key);
        Ok(Response::Success)
    }

    async fn identities(&mut self) -> Result<Response, AgentError> {
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
            .refresh_certificate_async(&mut self.signatory, &self.certificate_options)
            .await
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
                identities.append(&mut extra_identities);
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
                        let descriptor = YubikeyPIVKeyDescriptor {
                            serial,
                            slot,
                            public_key: pubkey.clone(),
                            pin: pin.clone(),
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
