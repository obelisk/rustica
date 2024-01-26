use clap::ArgMatches;
use rustica_agent::config::UpdatableConfiguration;

use super::{
    parse_config_from_args, ConfigurationError,
    RusticaAgentAction,
};

pub struct GetAuthorizedSignersConfig {
    pub updatable_configuration: UpdatableConfiguration,
}

pub async fn configure_signers(
    matches: &ArgMatches,
) -> Result<RusticaAgentAction, ConfigurationError> {
    let updatable_configuration = parse_config_from_args(&matches)?;

    Ok(RusticaAgentAction::GetAuthorizedSigners(GetAuthorizedSignersConfig {
        updatable_configuration,
    }))
}
