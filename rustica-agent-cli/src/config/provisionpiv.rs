use std::env;

use clap::{Arg, ArgMatches, Command};
use rustica_agent::{slot_validator, Signatory, YubikeySigner};
use yubikey::PinPolicy;

use super::{get_signatory, ConfigurationError, RusticaAgentAction};

pub struct ProvisionPIVConfig {
    pub yubikey: YubikeySigner,
    pub pin: String,
    pub management_key: Vec<u8>,
    pub require_touch: bool,
    pub pin_policy: PinPolicy,
    pub subject: String,
}

pub fn pin_policy_parser(policy: &str) -> Result<PinPolicy, String> {
    match policy {
        "always" | "a" => Ok(PinPolicy::Always),
        "once" | "o" => Ok(PinPolicy::Once),
        "never" | "n" => Ok(PinPolicy::Never),
        _ => Err(format!("{policy} is not a policy for pin I understand")),
    }
}

pub fn configure_provision_piv(
    matches: &ArgMatches,
) -> Result<RusticaAgentAction, ConfigurationError> {
    let slot = matches.value_of("slot").map(|x| x.to_string());

    let signatory = get_signatory(&slot, &None, &None, &None)?;

    let yubikey = match signatory {
        Signatory::Yubikey(yk_sig) => yk_sig,
        Signatory::Direct(_) => return Err(ConfigurationError::CannotProvisionFile),
    };

    let require_touch = matches.is_present("require-touch");
    let subject = matches.value_of("subject").unwrap().to_string();
    let management_key = match hex::decode(matches.value_of("management-key").unwrap()) {
        Ok(mgm) => mgm,
        Err(_) => return Err(ConfigurationError::YubikeyManagementKeyInvalid),
    };

    let pin_env = matches.value_of("pin-env").unwrap().to_string();
    let pin = match env::var(pin_env) {
        Ok(val) => val,
        Err(_e) => "123456".to_string(),
    };

    let pin_policy = matches
        .get_one("pin-policy")
        .map(|x: &PinPolicy| x.clone())
        .unwrap_or(PinPolicy::Once);

    let provision_config = ProvisionPIVConfig {
        yubikey,
        pin,
        management_key,
        subject,
        require_touch,
        pin_policy,
    };

    return Ok(RusticaAgentAction::ProvisionPIV(provision_config));
}

pub fn add_configuration(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("management-key")
            .help("Specify the management key")
            .default_value("010203040506070801020304050607080102030405060708")
            .long("mgmkey")
            .short('m')
            .required(false)
            .takes_value(true),
    )
    .arg(
        Arg::new("slot")
            .help("Numerical value for the slot on the yubikey to use for your private key")
            .long("slot")
            .short('s')
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
        Arg::new("require-touch")
            .help("Require the key to always be tapped. If this is not selected, a tap will be required if not tapped in the last 15 seconds.")
            .long("require-touch")
            .short('r')
    )
    .arg(
        Arg::new("pin-policy")
            .help("Require the pin be provided to use this key. Can be \"always\", \"once\", or \"never\". The chosen policy cannot be changed later and may affect the ability to enroll the key with a backend.")
            .long("pin-policy")
            .short('P')
            .value_parser(pin_policy_parser)
            .multiple_occurrences(false)
            .multiple_values(false)
            .takes_value(true)
    )
    .arg(
        Arg::new("subject")
            .help("Subject of the new cert you're creating (this is only used as a note)")
            .default_value("Rustica-AgentQuickProvision")
            .long("subj")
            .short('j')
    )
}
