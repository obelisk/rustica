use clap::{Arg, ArgMatches, Command};

use super::{ConfigurationError, RusticaAgentAction};

pub struct ListPIVKeysConfig {
    pub show_full: bool,
}

pub fn configure_list_piv_keys(
    matches: &ArgMatches,
) -> Result<RusticaAgentAction, ConfigurationError> {
    Ok(RusticaAgentAction::ListPIVKeys(ListPIVKeysConfig {
        show_full: matches.is_present("full"),
    }))
}

pub fn add_configuration(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("full")
            .help("Show the full key instead of the fingerprint")
            .long("full")
            .short('L'),
    )
}
