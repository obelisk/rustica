use crate::auth::{AuthMechanism, AuthServer, LocalDatabase};
use crate::server::RusticaServer;

use clap::{App, Arg};

use influx_db_client::Client;

use ring::{hmac, rand};
use serde_derive::Deserialize;
use sshcerts::yubikey::Yubikey;

use std::convert::TryFrom;
// It is my understanding that it is fine to use a standard Mutex here
// instead of a tokio Mutex because we are not holding the lock across an
// await boundary.
use std::sync::{Arc, Mutex};

use yubikey_piv::key::SlotId;

use std::net::SocketAddr;

#[derive(Deserialize)]
pub struct InfluxDBConfiguration {
    pub address: String,
    pub database: String,
    pub user: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct Authorization {
    pub database: Option<LocalDatabase>,
    pub external: Option<AuthServer>,
}

#[derive(Deserialize)]
pub struct Configuration {
    pub server_cert: String,
    pub server_key: String,
    pub client_ca_cert: String,
    pub key_type: String,
    pub user_key: String,
    pub host_key: String,
    pub listen_address: String,
    pub authorization: Authorization,
    pub influx: Option<InfluxDBConfiguration>,
}

pub struct RusticaSettings {
    pub server: RusticaServer,
    pub client_ca_cert: String,
    pub server_cert: String,
    pub server_key: String,
    pub address: SocketAddr,
}

#[derive(Debug)]
pub enum ConfigurationError {
    ParsingError,
    SlotParsingError,
    KeysConfigurationError,
    SSHKeyError,
    YubikeyError,
    InvalidListenAddress,
    AuthorizerError,
}

impl From<sshcerts::error::Error> for ConfigurationError {
    fn from(_: sshcerts::error::Error) -> ConfigurationError {
        ConfigurationError::SSHKeyError
    }
}

fn slot_parser(slot: &str) -> Result<SlotId, ConfigurationError> {
    // If first character is R, then we need to parse the nice
    // notation
    if (slot.len() == 2 || slot.len() == 3) && slot.starts_with('R') {
        let slot_value = slot[1..].parse::<u8>();
        match slot_value {
            Ok(v) if v <= 20 => Ok(SlotId::try_from(0x81_u8 + v).unwrap()),
            _ => Err(ConfigurationError::SlotParsingError),
        }
    } else if let Ok(s) = SlotId::try_from(slot.to_owned()) {
        Ok(s)
    } else {
        Err(ConfigurationError::SlotParsingError)
    }
}

fn create_signer(slot: SlotId, mutex: Arc<Mutex<u32>>) -> Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync> {
    Box::new(move |buf: &[u8]| {
        match mutex.lock() {
            Ok(_) => {
                let mut yk = Yubikey::new().unwrap();
                match yk.ssh_cert_signer(buf, &slot) {
                    Ok(sig) => Some(sig),
                    Err(_) => None,
                }
            },
            Err(e) => {
                error!("Error in acquiring mutex for yubikey signing: {}", e);
                None
            }
        }
    })
}

pub async fn configure() -> Result<RusticaSettings, ConfigurationError> {
    let matches = App::new("Rustica")
    .version(env!("CARGO_PKG_VERSION"))
    .author("Mitchell Grenier <mitchell@confurious.io>")
    .about("Rustica is a Yubikey backed SSHCA")
    .arg(
        Arg::new("config")
            .about("Path to Rustica configuration toml file")
            .long("config")
            .required(true)
            .default_value("/etc/rustica/rustica.toml")
            .takes_value(true),
    ).get_matches();

    let config = tokio::fs::read(matches.value_of("config").unwrap()).await.unwrap();
    let config: Configuration = match toml::from_slice(&config) {
        Ok(config) => config,
        Err(_) => return Err(ConfigurationError::ParsingError),
    };

    let (user_ca_cert, user_signer, host_ca_cert, host_signer) = match (config.key_type.as_str(), config.user_key, config.host_key) {
        ("yubikey", uk, hk) => {
            let us = slot_parser(&uk)?;
            let hs = slot_parser(&hk)?;
            let mut yk = Yubikey::new().unwrap();
            
            let user_ca_cert = yk.ssh_cert_fetch_pubkey(&us);
            let host_ca_cert = yk.ssh_cert_fetch_pubkey(&hs);
            let yubikey_mutex = Arc::new(Mutex::new(0));

            match (user_ca_cert, host_ca_cert) {
                (Ok(ucc), Ok(hcc)) => (
                    ucc,
                    create_signer(us, yubikey_mutex.clone()),
                    hcc,
                    create_signer(hs, yubikey_mutex)
                ),
                _ => {
                    error!("Could not fetch CA public keys from YubiKey. Is it connected/configured?");
                    return Err(ConfigurationError::YubikeyError);
                }
            }
        },
        ("file", uk, hk) => {
            let userkey = sshcerts::ssh::PrivateKey::from_string(&uk)?;
            let hostkey = sshcerts::ssh::PrivateKey::from_string(&hk)?;
            (userkey.pubkey.clone(), userkey.into(), hostkey.pubkey.clone(), hostkey.into())
        },
        _ => {
            error!("The key type must be one of: [file, yubikey]. Both a user and host key must be provided");
            return Err(ConfigurationError::KeysConfigurationError);
        },
    };

    
    let address = match config.listen_address.parse() {
        Ok(addr) => addr,
        Err(_) => return Err(ConfigurationError::InvalidListenAddress)
    };

    let influx_client = match config.influx {
        Some(influx) => Some(Client::new(influx.address.parse().unwrap(), influx.database).set_authentication(influx.user, influx.password)),
        None => None,
    };

    let authorizer = match (config.authorization.database, config.authorization.external) {
        (Some(database), None) => AuthMechanism::Local(database),
        (None, Some(external)) => AuthMechanism::External(external),
        _ => return Err(ConfigurationError::AuthorizerError),
    };

    let rng = rand::SystemRandom::new();
    let hmac_key = hmac::Key::generate(hmac::HMAC_SHA256, &rng).unwrap();
    
    let server = RusticaServer {
        influx_client,
        hmac_key,
        authorizer,
        user_ca_cert,
        host_ca_cert,
        user_ca_signer: user_signer,
        host_ca_signer: host_signer,
    };
    
    Ok(RusticaSettings {
        server,
        client_ca_cert: config.client_ca_cert,
        server_cert: config.server_cert,
        server_key: config.server_key,
        address,
    })
}