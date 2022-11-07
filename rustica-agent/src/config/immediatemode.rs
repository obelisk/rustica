use clap::{Arg, ArgMatches, Command};
use rustica_agent::{slot_validator, CertificateConfig, RusticaServer, Signatory};

use super::{
    get_signatory, parse_certificate_config_from_args, parse_config_from_args,
    parse_server_from_args, ConfigurationError, RusticaAgentAction,
};

pub struct ImmediateConfig {
    pub server: RusticaServer,
    pub certificate_options: CertificateConfig,
    pub signatory: Signatory,
    pub out: Option<String>,
}

pub fn add_configuration(cmd: Command) -> Command {
    cmd
    .arg(
        Arg::new("out")
            .help("Output the certificate to a file and exit. Useful for refreshing host certificates")
            .short('o')
            .long("out")
            .takes_value(true)
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
        Arg::new("file")
            .help("Used instead of a slot to provide a private key via file")
            .long("file")
            .short('f')
            .takes_value(true),
    )
}

pub fn configure_immediate(matches: &ArgMatches) -> Result<RusticaAgentAction, ConfigurationError> {
    let config = parse_config_from_args(&matches)?;
    let server = parse_server_from_args(&matches, &config)?;
    let certificate_options = parse_certificate_config_from_args(&matches, &config)?;
    let out = matches.value_of("out").map(|x| x.to_string());
    let slot = matches.value_of("slot").map(|x| x.to_string());
    let file = matches.value_of("file").map(|x| x.to_string());

    let signatory = get_signatory(&slot, &config.slot, &file, &config.key)?;

    return Ok(RusticaAgentAction::Immediate(ImmediateConfig {
        server,
        certificate_options,
        signatory,
        out,
    }));
}
