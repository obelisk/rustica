use clap::{Arg, ArgMatches, Command};
use rustica_agent::{slot_validator, PIVAttestation, RusticaServer, Signatory};
use yubikey::piv::SlotId;

use super::{
    get_signatory, parse_config_from_args, parse_server_from_args, ConfigurationError,
    RusticaAgentAction,
};

pub struct RegisterConfig {
    pub server: RusticaServer,
    pub signatory: Signatory,
    pub attestation: PIVAttestation,
}

pub async fn configure_register(
    matches: &ArgMatches,
) -> Result<RusticaAgentAction, ConfigurationError> {
    let config = parse_config_from_args(&matches)?;
    let server = parse_server_from_args(&matches, &config).await?;

    let slot = matches.value_of("slot").map(|x| x.to_string());
    let file = matches.value_of("file").map(|x| x.to_string());

    let mut signatory = get_signatory(&slot, &config.slot, &file, &config.key)?;

    let mut attestation = PIVAttestation {
        certificate: vec![],
        intermediate: vec![],
    };

    if !matches.is_present("no-attest") {
        let signer = match &mut signatory {
            Signatory::Yubikey(s) => s,
            Signatory::Direct(_) => return Err(ConfigurationError::CannotAttestFileBasedKey),
        };

        attestation.certificate = signer
            .yk
            .fetch_attestation(&signer.slot)
            .unwrap_or_default();
        attestation.intermediate = signer
            .yk
            .fetch_certificate(&SlotId::Attestation)
            .unwrap_or_default();

        if attestation.certificate.is_empty() || attestation.intermediate.is_empty() {
            error!("Part of the attestation could not be generated. Registration may fail");
        }
    }

    return Ok(RusticaAgentAction::Register(RegisterConfig {
        server,
        signatory,
        attestation,
    }));
}

pub fn add_configuration(cmd: Command) -> Command {
    cmd
        .arg(
            Arg::new("no-attest")
                .help("Don't send attestation data for this key. This may make registration fail depending on server configurations.")
                .long("no-attest")
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
