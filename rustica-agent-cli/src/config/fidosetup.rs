use std::env;

use clap::{Arg, ArgMatches, Command};
use rustica_agent::RusticaServer;
use tokio::runtime::Handle;

use super::{
    parse_config_from_args, parse_server_from_args, ConfigurationError, RusticaAgentAction,
};

pub enum SKType {
    Ed25519,
    Ecdsa,
}

pub struct ProvisionAndRegisterFidoConfig {
    pub server: RusticaServer,
    pub app_name: String,
    pub comment: String,
    pub key_type: SKType,
    pub pin: Option<String>,
    pub out: Option<String>,
}

pub async fn configure_fido_setup(
    matches: &ArgMatches,
) -> Result<RusticaAgentAction, ConfigurationError> {
    let config = parse_config_from_args(&matches)?;
    let server = parse_server_from_args(&matches, &config).await?;

    let app_name = matches.value_of("application").unwrap().to_string();

    if !app_name.starts_with("ssh:") {
        return Err(ConfigurationError::InvalidFidoKeyName);
    }

    let comment = matches.value_of("comment").unwrap().to_string();
    let out = matches.value_of("out").map(String::from);

    let key_type = match matches.value_of("kind") {
        Some("ecdsa") => SKType::Ecdsa,
        _ => SKType::Ed25519,
    };

    let pin_env = matches.value_of("pin-env").unwrap().to_string();
    let pin = match env::var(pin_env) {
        Ok(val) => Some(val),
        Err(_e) => None,
    };

    let provision_config = ProvisionAndRegisterFidoConfig {
        server,
        app_name,
        comment,
        key_type,
        pin,
        out,
    };

    return Ok(RusticaAgentAction::ProvisionAndRegisterFido(
        provision_config,
    ));
}

pub fn add_configuration(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("application")
            .help("Specify application you are creating the key for")
            .default_value("ssh:RusticaAgent")
            .long("application")
            .short('a')
            .required(false)
            .takes_value(true),
    )
    .arg(
        Arg::new("comment")
            .help("A comment about what this SSH key will be for")
            .long("comment")
            .required(false)
            .default_value("RusticaAgentProvisionedKey"),
    )
    .arg(
        Arg::new("kind")
            .help("Whether you'd like an Ed25519 or ECDSA P256 key")
            .possible_values(vec!["ed25519", "ecdsa"])
            .default_value("ed25519")
            .long("kind")
            .short('k'),
    )
    .arg(
        Arg::new("pin-env")
            .help("Specify the pin environment variable")
            .default_value("YK_PIN")
            .long("pinenv")
            .short('p')
            .required(false)
            .takes_value(true),
    )
    .arg(
        Arg::new("out")
            .help("Relative path to write your new private key handle to")
            .required(false)
            .long("out")
            .takes_value(true)
            .short('o'),
    )
}
