use clap::ArgMatches;
use rustica_agent::config::UpdatableConfiguration;

use super::{
    parse_config_from_args, ConfigurationError,
    RusticaAgentAction,
};

pub struct GetAuthorizedSignerKeysConfig {
    pub updatable_configuration: UpdatableConfiguration,
}

pub async fn configure_signer_keys(
    matches: &ArgMatches,
) -> Result<RusticaAgentAction, ConfigurationError> {
    let updatable_configuration = parse_config_from_args(&matches)?;

    Ok(RusticaAgentAction::GetAuthorizedSignerKeys(GetAuthorizedSignerKeysConfig {
        updatable_configuration,
    }))
}
