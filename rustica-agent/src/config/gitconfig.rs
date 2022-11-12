use clap::{Arg, ArgMatches, Command};
use rustica_agent::{get_all_piv_keys, slot_parser, slot_validator};
use sshcerts::{PrivateKey, PublicKey};

use super::{ConfigurationError, RusticaAgentAction};

pub fn configure_git_config(
    matches: &ArgMatches,
) -> Result<RusticaAgentAction, ConfigurationError> {
    let file = matches.value_of("file").map(|x| x.to_string());
    let slot = matches
        .value_of("slot")
        .map(slot_parser)
        .map(|x| x.unwrap()); // This should be a safe unwrap because we have passed the slot validator
    let serial = matches.value_of("serial").map(|x| x.to_string());

    let public_key = match (file, slot, serial) {
        (Some(f), None, _) => match (PrivateKey::from_path(&f), PublicKey::from_path(&f)) {
            (Ok(p), _) => p.pubkey.clone(),
            (_, Ok(p)) => p,
            (_, _) => {
                return Err(ConfigurationError::CannotReadFile(
                    "Could not read the key as either a private or public key".to_owned(),
                ))
            }
        },
        (None, Some(slot), serial) => {
            let all_keys =
                get_all_piv_keys().map_err(|x| ConfigurationError::YubikeyError(x.to_string()))?;

            let mut candidate_keys: Vec<_> =
                all_keys.into_iter().filter(|x| x.1.slot == slot).collect();

            match (candidate_keys.len(), serial) {
                (0, _) => return Err(ConfigurationError::YubikeyNoKeypairFound),
                (1, _) => candidate_keys.pop().unwrap().1.public_key,
                (_, None) => return Err(ConfigurationError::UnableToDetermineKey),
                (_, Some(serial)) => {
                    candidate_keys
                        .into_iter()
                        .filter(|x| x.1.serial.to_string() == serial)
                        .collect::<Vec<_>>()
                        .pop()
                        .ok_or(ConfigurationError::YubikeyNoKeypairFound)?
                        .1
                        .public_key
                }
            }
        }
        (None, None, _) => return Err(ConfigurationError::UnableToDetermineKey), // They didn't provide anything
        (Some(_), Some(_), _) => return Err(ConfigurationError::UnableToDetermineKey), // They provided both and we can't disambiguate
    };

    return Ok(RusticaAgentAction::GitConfig(public_key));
}

pub fn add_configuration(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("file")
            .help("Used instead of a slot to provide a private key via file")
            .long("file")
            .short('f')
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
        Arg::new("serial")
            .help("If multiple Yubikeys are connected and the same slot is used on both, this is required to disambiguate")
            .long("serial")
            .short('S')
            .requires("slot")
            .takes_value(true),
    )
}
