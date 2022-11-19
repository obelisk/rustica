use std::collections::HashMap;

use clap::{Arg, ArgMatches, Command};
use rustica_agent::{slot_validator, Handler, Signatory};

use super::{
    get_signatory, parse_certificate_config_from_args, parse_config_from_args,
    parse_server_from_args, parse_socket_path_from_args, ConfigurationError, RunConfig,
    RusticaAgentAction,
};

pub async fn configure_singlemode(
    matches: &ArgMatches,
) -> Result<RusticaAgentAction, ConfigurationError> {
    let config = parse_config_from_args(&matches)?;
    let server = parse_server_from_args(&matches, &config).await?;
    let certificate_options = parse_certificate_config_from_args(&matches, &config)?;
    let socket_path = parse_socket_path_from_args(matches, &config);

    let slot = matches.value_of("slot").map(|x| x.to_string());
    let file = matches.value_of("file").map(|x| x.to_string());

    let mut signatory = get_signatory(&slot, &config.slot, &file, &config.key)?;
    let pubkey = match &mut signatory {
        Signatory::Yubikey(signer) => match signer.yk.ssh_cert_fetch_pubkey(&signer.slot) {
            Ok(cert) => cert,
            Err(_) => return Err(ConfigurationError::YubikeyNoKeypairFound),
        },
        Signatory::Direct(privkey) => {
            if let Some(path) = matches.value_of("fido-device-path") {
                privkey.set_device_path(path);
            }

            privkey.pubkey.clone()
        }
    };

    let handler = Handler {
        server,
        cert: None,
        pubkey: pubkey.clone(),
        signatory,
        stale_at: 0,
        certificate_options,
        identities: HashMap::new(),
        piv_identities: HashMap::new(),
        notification_function: None,
        certificate_priority: matches.is_present("certificate-priority"),
    };

    Ok(RusticaAgentAction::Run(RunConfig {
        socket_path,
        pubkey,
        handler,
    }))
}

pub fn add_configuration(cmd: Command) -> Command {
    // Add socket path and certificate priority
    let cmd = super::add_daemon_options(cmd);

    // Add options for setting the fields on requested certificates
    let cmd = super::add_request_options(cmd);

    cmd.arg(
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
    .arg(
        Arg::new("fido-device-path")
            .help("The device path to use for FIDO2 keys. If not provided, we'll pick a device randomly. Should be set when multiple FIDO2 devices connected.")
            .long("fido")
            .required(false)
            .takes_value(true),
    )
}
