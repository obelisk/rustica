use std::env;

use clap::{Command, Arg, ArgMatches};
use rustica_agent::{slot_validator, slot_parser, RusticaServer, Signatory, YubikeySigner};
use sshcerts::yubikey::piv::Yubikey;
use tokio::runtime::Handle;

use super::{RusticaAgentAction, ConfigurationError, parse_config_from_args};

pub struct RefreshAttestedX509Config {
    pub servers: Vec<RusticaServer>,
    pub signatory: Signatory,
    pub pin: String,
    pub management_key: Vec<u8>,
}

pub async fn configure_refresh_x509_certificate(
    matches: &ArgMatches,
) -> Result<RusticaAgentAction, ConfigurationError> {
    let config = parse_config_from_args(&matches)?;
    let servers = config.parse_servers(Handle::current());

    let slot = matches.value_of("slot").map(|x| x.to_string()).unwrap();
    let slot = slot_parser(&slot).unwrap();

    let signatory = Signatory::Yubikey(YubikeySigner {
        yk: Yubikey::new().unwrap(),
        slot,
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


    Ok(RusticaAgentAction::RefreshAttestedX509(RefreshAttestedX509Config {
        servers,
        signatory,
        pin,
        management_key,
    }))
}

pub fn add_configuration(cmd: Command) -> Command {
    cmd
        .arg(
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
