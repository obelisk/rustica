use crate::auth::{AuthMechanism, AuthServer, LocalDatabase};
use crate::server::RusticaServer;
use crate::signing::{FileSigner, VaultSigner, SigningMechanism, YubikeySigner};

use clap::{App, Arg};

use influx_db_client::Client;

use ring::{hmac, rand};
use serde::Deserialize;
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
pub struct Signing {
    pub file: Option<FileSigner>,
    pub vault: Option<VaultSigner>,
    pub yubikey: Option<YubikeySigner>,
}


#[derive(Deserialize)]
pub struct Configuration {
    pub server_cert: String,
    pub server_key: String,
    pub client_ca_cert: String,
    pub listen_address: String,
    pub authorization: Authorization,
    pub signing: Signing,
    pub require_rustica_proof: bool,
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
    FileError,
    ParsingError,
    SlotParsingError,
    KeysConfigurationError,
    SSHKeyError,
    YubikeyError,
    InvalidListenAddress,
    AuthorizerError,
    SigningMechanismError,
}

impl From<sshcerts::error::Error> for ConfigurationError {
    fn from(_: sshcerts::error::Error) -> ConfigurationError {
        ConfigurationError::SSHKeyError
    }
}

impl From<sshcerts::yubikey::Error> for ConfigurationError {
    fn from(_: sshcerts::yubikey::Error) -> ConfigurationError {
        ConfigurationError::YubikeyError
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

    // Read the configuration file
    let config = match tokio::fs::read(matches.value_of("config").unwrap()).await {
        Ok(config) => config,
        Err(_) => return Err(ConfigurationError::FileError),
    };

    // Parse the TOML into our configuration structures
    let config: Configuration = match toml::from_slice(&config) {
        Ok(config) => config,
        Err(_) => return Err(ConfigurationError::ParsingError),
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

    let signer = match (config.signing.file, config.signing.vault, config.signing.yubikey) {
        (Some(file), None, None) => SigningMechanism::File(file),
        (None, Some(vault), None) => SigningMechanism::Vault(vault),
        (None, None, Some(yubikey)) => SigningMechanism::Yubikey(yubikey),
        _ => return Err(ConfigurationError::SigningMechanismError),
    };

    let rng = rand::SystemRandom::new();
    let hmac_key = hmac::Key::generate(hmac::HMAC_SHA256, &rng).unwrap();
    
    let server = RusticaServer {
        influx_client,
        hmac_key,
        authorizer,
        signer,
        require_rustica_proof: config.require_rustica_proof,
    };
    
    Ok(RusticaSettings {
        server,
        client_ca_cert: config.client_ca_cert,
        server_cert: config.server_cert,
        server_key: config.server_key,
        address,
    })
}