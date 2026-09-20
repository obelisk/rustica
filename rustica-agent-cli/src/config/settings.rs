use std::env;
use std::path::PathBuf;

use clap::{Arg, ArgMatches, Command};
use rustica_agent::control::{default_endpoint, Setting, SettingValue};

use super::{ConfigurationError, RusticaAgentAction};

pub struct SettingsConfig {
    pub endpoint: PathBuf,
    pub operation: SettingsOperation,
}

pub enum SettingsOperation {
    Get(Setting),
    Set(Setting, SettingValue),
    ToggleDisableCertificate,
}

pub fn add_configuration(cmd: Command) -> Command {
    let setting = Arg::new("setting")
        .required(true)
        .possible_value("disable_certificate")
        .possible_value("config_path");
    cmd.arg(
        Arg::new("control-socket")
            .long("control-socket")
            .global(true)
            .takes_value(true)
            .value_name("PATH")
            .help("Path to the running agent's private control socket"),
    )
    .subcommand(Command::new("get").arg(setting.clone()))
    .subcommand(
        Command::new("set")
            .arg(setting.clone())
            .arg(Arg::new("value").required(true)),
    )
    .subcommand(Command::new("toggle").arg(setting))
}

fn setting(matches: &ArgMatches) -> Setting {
    match matches.value_of("setting") {
        Some("disable_certificate") => Setting::DisableCertificate,
        Some("config_path") => Setting::ConfigPath,
        _ => unreachable!("clap validates setting names"),
    }
}

fn endpoint(matches: &ArgMatches) -> Result<PathBuf, ConfigurationError> {
    if let Some(path) = matches.value_of("control-socket") {
        return Ok(PathBuf::from(path));
    }
    let ssh_socket = env::var_os("SSH_AUTH_SOCK")
        .filter(|path| !path.is_empty())
        .ok_or(ConfigurationError::MissingControlSocket)?;
    Ok(default_endpoint(ssh_socket))
}

pub fn configure_settings(matches: &ArgMatches) -> Result<RusticaAgentAction, ConfigurationError> {
    let endpoint = endpoint(matches)?;
    let operation = if let Some(matches) = matches.subcommand_matches("get") {
        SettingsOperation::Get(setting(matches))
    } else if let Some(matches) = matches.subcommand_matches("set") {
        let setting = setting(matches);
        let value = match setting {
            Setting::DisableCertificate => match matches.value_of("value") {
                Some("true") => SettingValue::Bool(true),
                Some("false") => SettingValue::Bool(false),
                _ => return Err(ConfigurationError::InvalidBoolean),
            },
            Setting::ConfigPath => {
                let path = PathBuf::from(matches.value_of("value").unwrap());
                let path = if path.is_absolute() {
                    path
                } else {
                    env::current_dir()?.join(path)
                };
                SettingValue::Path(path)
            }
        };
        SettingsOperation::Set(setting, value)
    } else if let Some(matches) = matches.subcommand_matches("toggle") {
        if setting(matches) != Setting::DisableCertificate {
            return Err(ConfigurationError::InvalidToggleSetting);
        }
        SettingsOperation::ToggleDisableCertificate
    } else {
        return Err(ConfigurationError::NoMode);
    };
    Ok(RusticaAgentAction::Settings(SettingsConfig {
        endpoint,
        operation,
    }))
}
