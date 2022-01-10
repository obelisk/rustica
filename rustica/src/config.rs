use crate::auth::{AuthMechanism, AuthServer, LocalDatabase};
use crate::logging::{Log, LoggingConfiguration};
use crate::server::RusticaServer;
use crate::signing::{FileSigner, VaultSigner, SigningMechanism, YubikeySigner};

use clap::{App, Arg};

use crossbeam_channel::{unbounded, Receiver};

use ring::{hmac, rand};
use serde::Deserialize;

use std::net::SocketAddr;

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
    pub logging: LoggingConfiguration,
}

pub struct RusticaSettings {
    pub server: RusticaServer,
    pub client_ca_cert: String,
    pub server_cert: String,
    pub server_key: String,
    pub address: SocketAddr,
    pub log_receiver: Receiver<Log>,
    pub logging_configuration: LoggingConfiguration,
}

pub enum ConfigurationError {
    FileError,
    ParsingError,
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

impl std::error::Error for ConfigurationError {
    fn description(&self) -> &str {
        ""
    }
}

impl std::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ConfigurationError::FileError => "Could not read configuration file",
            ConfigurationError::ParsingError => "Could not parse the configuration file",
            ConfigurationError::SSHKeyError => "Could not parse the provided SSH keys file",
            ConfigurationError::YubikeyError => "Could not find or use a connected Yubikey",
            ConfigurationError::InvalidListenAddress => "Invalid address and/or port to listen on",
            ConfigurationError::AuthorizerError => "Configuration for authorization was invalid",
            ConfigurationError::SigningMechanismError => "Configuration for signing certificates was invalid",
        };
        write!(f, "{}", s)
    }
}

impl std::fmt::Debug for ConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}


pub async fn configure() -> Result<RusticaSettings, ConfigurationError> {
    let matches = App::new("Rustica")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Mitchell Grenier <mitchell@confurious.io>")
        .about("Rustica is a Yubikey backed SSHCA")
        .arg(
            Arg::new("config")
                .help("Path to Rustica configuration toml file")
                .long("config")
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
        Err(e) => {
            error!("Failed to parse config: {}", e);
            return Err(ConfigurationError::ParsingError);
        },
    };

    let address = match config.listen_address.parse() {
        Ok(addr) => addr,
        Err(_) => return Err(ConfigurationError::InvalidListenAddress)
    };

    let (log_sender, log_receiver) = unbounded();

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
        log_sender,
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
        log_receiver,
        logging_configuration: config.logging,
    })
}