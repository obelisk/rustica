use clap::ArgMatches;
use rustica_agent::config::UpdatableConfiguration;

use super::{
    parse_config_from_args, ConfigurationError,
    RusticaAgentAction,
};

pub struct GetAllowedSignersConfig {
    pub updatable_configuration: UpdatableConfiguration,
}

pub async fn configure_allowed_signers(
    matches: &ArgMatches,
) -> Result<RusticaAgentAction, ConfigurationError> {
    let updatable_configuration = parse_config_from_args(&matches)?;

    Ok(RusticaAgentAction::GetAllowedSigners(GetAllowedSignersConfig {
        updatable_configuration,
    }))
}
