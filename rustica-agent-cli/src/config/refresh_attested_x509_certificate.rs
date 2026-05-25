use std::env;

use clap::{Arg, ArgMatches, Command};
use rustica_agent::Yubikey;
use rustica_agent::{
    config::UpdatableConfiguration, slot_parser, slot_validator, Signatory, YubikeySigner,
};

use super::{parse_config_from_args, ConfigurationError, RusticaAgentAction};

pub struct RefreshAttestedX509Config {
    pub updatable_configuration: UpdatableConfiguration,
    pub signatory: Signatory,
    pub pin: String,
    pub management_key: Vec<u8>,
}

pub async fn configure_refresh_x509_certificate(
    matches: &ArgMatches,
) -> Result<RusticaAgentAction, ConfigurationError> {
    let updatable_configuration = parse_config_from_args(&matches)?;

    let slot = matches
        .value_of("slot")
        .map(|x| x.to_string())
        .ok_or(ConfigurationError::BadSlot)?;
    let slot = slot_parser(&slot).ok_or(ConfigurationError::BadSlot)?;

    let mut yk = Yubikey::new()
        .map_err(|e| ConfigurationError::YubikeyError(format!("Could not open Yubikey: {}", e)))?;
    let requires_touch = rustica_agent::key_requires_touch(&mut yk, &slot);

    let signatory = Signatory::Yubikey(YubikeySigner {
        yk: yk.into(),
        slot,
        requires_touch,
    });

    let pin_env = matches.value_of("pin-env").unwrap().to_string();
    let pin = match env::var(pin_env) {
        Ok(val) => val,
        Err(_e) => "123456".to_string(),
    };

    let management_key = match hex::decode(matches.value_of("management-key").unwrap()) {
        Ok(mgm) => mgm,
        Err(_) => return Err(ConfigurationError::YubikeyManagementKeyInvalid),
    };

    Ok(RusticaAgentAction::RefreshAttestedX509(
        RefreshAttestedX509Config {
            updatable_configuration,
            signatory,
            pin,
            management_key,
        },
    ))
}

pub fn add_configuration(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("slot")
            .help("Numerical value for the slot on the yubikey to use for your private key")
            .long("slot")
            .short('s')
            .required(true)
            .validator(slot_validator)
            .takes_value(true),
    )
    .arg(
        Arg::new("pin-env")
            .help("Specify a different pin environment variable")
            .default_value("YK_PIN")
            .long("pinenv")
            .short('p')
            .required(false)
            .takes_value(true),
    )
    .arg(
        Arg::new("management-key")
            .help("Specify the management key")
            .default_value("010203040506070801020304050607080102030405060708")
            .long("mgmkey")
            .short('m')
            .required(false)
            .takes_value(true),
    )
}
