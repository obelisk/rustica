#[macro_use] extern crate log;

pub mod sshagent;
pub mod rustica;

use serde_derive::Deserialize;

pub use sshagent::{Agent, error::Error as AgentError, Identity, SshAgentHandler, Response};

pub use rustica::{
    key::KeyConfig,
    RefreshError::{ConfigurationError, SigningError}
};

use sshcerts::ssh::{Certificate, CertType, PrivateKey};
use sshcerts::yubikey::SlotId;

use std::convert::TryFrom;

use std::time::SystemTime;

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

#[derive(Debug)]
pub struct Handler {
    pub server: RusticaServer,
    pub cert: Option<Identity>,
    pub signatory: Signatory,
    pub stale_at: u64,
    pub certificate_options: CertificateConfig,
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
    fn identities(&mut self) -> Result<Response, AgentError> {
        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        if let Some(cert) = &self.cert {
            if timestamp < self.stale_at {
                debug!("Certificate has not expired, not refreshing");
                return Ok(Response::Identities(vec![cert.clone()]));
            }
        }
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
                Ok(Response::Identities(vec![ident]))
            },
            Err(e) => {
                error!("Refresh certificate error: {:?}", e);
                Err(AgentError::from("Could not refresh certificate"))
            },
        }
    }

    /// Pubkey is currently unused because the idea is to only ever have a single cert which itself is only
    /// active for a very small window of time
    fn sign_request(&mut self, _pubkey: Vec<u8>, data: Vec<u8>, _flags: u32) -> Result<Response, AgentError> {
        match &mut self.signatory {
            Signatory::Yubikey(signer) => {
                let signature = signer.yk.ssh_cert_signer(&data, &signer.slot).unwrap();
                let signature = (&signature[27..]).to_vec();

                let pubkey = signer.yk.ssh_cert_fetch_pubkey(&signer.slot).unwrap();

                Ok(Response::SignResponse {
                    algo_name: String::from(pubkey.key_type.name),
                    signature,
                })
            },
            Signatory::Direct(privkey) => {
                let signer:sshcerts::ssh::SigningFunction = privkey.clone().into();
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
        }
    }
}

use std::os::raw::{c_char};
use std::ffi::{CStr};
use std::os::unix::net::{UnixListener};

#[no_mangle]
pub extern fn start_yubikey_rustica_agent(slot: u8, config_file: *const c_char, socket_path: *const c_char) -> bool {
    println!("Starting a new Rustica instance!");
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
            yk: sshcerts::yubikey::Yubikey::new().unwrap(),
            slot: sshcerts::yubikey::SlotId::try_from(slot).unwrap(),
        })
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