use crate::auth::AuthorizationConfiguration;
use crate::logging::{Log, LoggingConfiguration};
use crate::server::RusticaServer;
use crate::signing::{SigningError, SigningConfiguration};

use clap::{
    Arg,
    Command,
};

use crossbeam_channel::{unbounded, Receiver};

use ring::{hmac, rand};
use serde::Deserialize;

use std::convert::TryInto;
use std::net::SocketAddr;

use sshcerts::{
    ssh::KeyTypeKind,
    PrivateKey,
};


#[derive(Deserialize)]
pub struct Configuration {
    pub server_cert: String,
    pub server_key: String,
    pub client_ca_cert: String,
    pub listen_address: String,
    pub authorization: AuthorizationConfiguration,
    pub signing: SigningConfiguration,
    pub require_rustica_proof: bool,
    pub require_attestation_chain: bool,
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
    InvalidListenAddress,
    AuthorizerError,
    SigningMechanismError(SigningError),
}

impl From<sshcerts::error::Error> for ConfigurationError {
    fn from(_: sshcerts::error::Error) -> ConfigurationError {
        ConfigurationError::SSHKeyError
    }
}

impl std::error::Error for ConfigurationError {
    fn description(&self) -> &str {
        ""
    }
}

impl std::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileError => write!(f, "Could not read configuration file"),
            Self::ParsingError => write!(f, "Could not parse the configuration file"),
            Self::SSHKeyError => write!(f, "Could not parse the provided SSH keys file"),
            Self::InvalidListenAddress => write!(f, "Invalid address and/or port to listen on"),
            Self::AuthorizerError => write!(f, "Configuration for authorization was invalid"),
            Self::SigningMechanismError(ref e) => write!(f, "{}", e),
        }
    }
}

impl std::fmt::Debug for ConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}


pub async fn configure() -> Result<RusticaSettings, ConfigurationError> {
    let matches = Command::new("Rustica")
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

    let authorizer = match config.authorization.try_into() {
        Ok(authorizer) => authorizer,
        _ => return Err(ConfigurationError::AuthorizerError),
    };

    let signer = match config.signing.convert_to_signing_mechanism().await {
        Ok(signer) => signer,
        Err(e) => return Err(ConfigurationError::SigningMechanismError(e)),
    };

    let rng = rand::SystemRandom::new();
    let hmac_key = hmac::Key::generate(hmac::HMAC_SHA256, &rng).unwrap();
    let challenge_key = PrivateKey::new(KeyTypeKind::Ed25519, "RusticaChallengeKey").unwrap();
    
    let server = RusticaServer {
        log_sender,
        hmac_key,
        challenge_key,
        authorizer,
        signer,
        require_rustica_proof: config.require_rustica_proof,
        require_attestation_chain: config.require_attestation_chain,
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