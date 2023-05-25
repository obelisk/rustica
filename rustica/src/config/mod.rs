use crate::auth::AuthorizationConfiguration;
use crate::logging::{Log, LoggingConfiguration};
use crate::server::RusticaServer;
use crate::signing::{SigningConfiguration, SigningError};

use clap::{Arg, Command};

use crossbeam_channel::{unbounded, Receiver};
use async_trait::async_trait;
use ring::{hmac, rand};
use serde::Deserialize;

use std::convert::TryInto;
use std::net::SocketAddr;

use sshcerts::{CertType, ssh::KeyTypeKind, PrivateKey};

/*
#[cfg(feature = "amazon-kms")]
mod amazon_kms;
mod file;
#[cfg(feature = "yubikey-support")]
mod yubikey;

/// Any code that wants to be able to renew client mTLS certificates must
/// implement this trait
#[async_trait]
pub trait Renewer {
    /// Take in the existing certificate and return a new certificate
    /// for the same public key with updated settings and expiry
    fn renew(&self, certificate: &[u8]) -> rcgen::Certificate;
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum ClientCertificateRenewalSystemConfiguration {
    File(file::Config),
    #[cfg(feature = "yubikey-support")]
    Yubikey(yubikey::Config),
    #[cfg(feature = "amazon-kms")]
    AmazonKMS(amazon_kms::Config),
}

impl ClientCertificateRenewalSystemConfiguration {
    async fn into_renewer(self) -> Result<Box<dyn Renewer>, SigningError> {
        match self {
            ClientCertificateRenewalSystemConfiguration::File(file) => Ok(Box::<dyn Renewer>::new(file.into())),
        }
    }
}
 */

#[derive(Deserialize)]
pub struct ClientAuthorityConfiguration {
    pub certificate: String,
    //pub renewal: Option<ClientCertificateRenewalSystemConfiguration>,
}

#[derive(Deserialize)]
pub struct Configuration {
    pub server_cert: String,
    pub server_key: String,
    pub client_authority: ClientAuthorityConfiguration,
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
    //pub client_certificate_renewer: Option<Box<dyn Renewer>>,
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
    ValidateOnly,
    DefaultAuthorityNotDefined,
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
            Self::ValidateOnly => write!(f, "Configuration was validated"),
            Self::DefaultAuthorityNotDefined => write!(
                f,
                "The default authority provided did not have a matching configuration"
            ),
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
        )
        .arg(
            Arg::new("validate")
                .help("Only validate the configuration and then quit. Useful for testing configuration changes.")
                .long("validate-config")
                .short('v')
                .takes_value(false),
        )
        .get_matches();

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
        }
    };

    let address = match config.listen_address.parse() {
        Ok(addr) => addr,
        Err(_) => return Err(ConfigurationError::InvalidListenAddress),
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

    if signer
        .get_signer_public_key(&signer.default_authority, CertType::User)
        .is_err()
    {
        return Err(ConfigurationError::DefaultAuthorityNotDefined);
    }

    let rng = rand::SystemRandom::new();
    let hmac_key = hmac::Key::generate(hmac::HMAC_SHA256, &rng).unwrap();
    let challenge_key = PrivateKey::new(KeyTypeKind::Ed25519, "RusticaChallengeKey").unwrap();


    //let client_certificate_renewer = config.client_authority.renewal.map(|x| x.into());

    if matches.is_present("validate") {
        return Err(ConfigurationError::ValidateOnly);
    }

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
        client_ca_cert: config.client_authority.certificate,
        //client_certificate_renewer,
        server_cert: config.server_cert,
        server_key: config.server_key,
        address,
        log_receiver,
        logging_configuration: config.logging,
    })
}
