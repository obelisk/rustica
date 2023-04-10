mod fidosetup;
mod gitconfig;
mod immediatemode;
mod listpivkeys;
mod multimode;
mod provisionpiv;
mod refresh_x509_certificate;
mod register;
mod singlemode;

use clap::{Arg, ArgMatches, Command};

use sshcerts::yubikey::piv::Yubikey;
use sshcerts::{CertType, PrivateKey, PublicKey};

use rustica_agent::*;

use std::convert::TryFrom;
use std::env;
use std::process;

#[derive(Debug)]
pub enum ConfigurationError {
    BadConfiguration(rustica_agent::RusticaAgentLibraryError),
    BadSlot,
    CannotAttestFileBasedKey,
    CannotProvisionFile,
    CannotReadFile(String),
    MissingSSHKey,
    ParsingError,
    YubikeyManagementKeyInvalid,
    YubikeyNoKeypairFound,
    InvalidFidoKeyName,
    MultiModeError(multimode::Error),
    NoMode,
    YubikeyError(String),
    UnableToDetermineKey,
}

pub struct RunConfig {
    pub socket_path: String,
    pub pubkey: PublicKey,
    pub handler: Handler,
}

pub enum RusticaAgentAction {
    Run(RunConfig),
    Immediate(immediatemode::ImmediateConfig),
    ProvisionPIV(provisionpiv::ProvisionPIVConfig),
    Register(register::RegisterConfig),
    ProvisionAndRegisterFido(fidosetup::ProvisionAndRegisterFidoConfig),
    ListPIVKeys(listpivkeys::ListPIVKeysConfig),
    ListFidoDevices,
    GitConfig(PublicKey),
    RefreshX509(refresh_x509_certificate::RefreshX509Config)
}

impl From<std::io::Error> for ConfigurationError {
    fn from(e: std::io::Error) -> Self {
        ConfigurationError::CannotReadFile(e.to_string())
    }
}

impl From<sshcerts::error::Error> for ConfigurationError {
    fn from(_: sshcerts::error::Error) -> Self {
        ConfigurationError::ParsingError
    }
}

fn get_signatory(
    cmd_slot: &Option<String>,
    config_slot: &Option<String>,
    file: &Option<String>,
    config_key: &Option<String>,
) -> Result<Signatory, ConfigurationError> {
    // Determine the signatory to be used. These match statements, execute in order,
    // create a hierarchy of which keys override others.
    // If a file is specified at the command line, that overrides everything else.
    // If there is no file, check for a key in the config file.
    // If there is no key in the config, check if a slot has been passed.
    // If there is a slot both on the command line and config file, prefer the command line
    // Otherwise use the slot in the config
    // If none of these, error.
    match (cmd_slot, config_slot, file, &config_key) {
        (Some(slot), _, _, _) => match slot_parser(slot) {
            Some(s) => Ok(Signatory::Yubikey(YubikeySigner {
                yk: Yubikey::new().unwrap(),
                slot: s,
            })),
            None => Err(ConfigurationError::BadSlot),
        },
        (_, _, Some(file), _) => match PrivateKey::from_path(file) {
            Ok(p) => Ok(Signatory::Direct(p)),
            Err(e) => Err(ConfigurationError::CannotReadFile(format!(
                "{}: {}",
                e, file
            ))),
        },
        (_, Some(slot), _, _) => match slot_parser(slot) {
            Some(s) => Ok(Signatory::Yubikey(YubikeySigner {
                yk: Yubikey::new().unwrap(),
                slot: s,
            })),
            None => Err(ConfigurationError::BadSlot),
        },
        (_, _, _, Some(key_string)) => Ok(Signatory::Direct(PrivateKey::from_string(key_string)?)),
        (None, None, None, None) => Err(ConfigurationError::MissingSSHKey),
    }
}

fn new_run_agent_subcommand<'a>(name: &'a str, about: &'a str) -> Command<'a> {
    Command::new(name).about(about).arg(
        Arg::new("config")
            .help("Specify an alternate configuration file.")
            .long("config")
            .default_value("/etc/rustica/config.toml")
            .takes_value(true),
    )
}

pub fn add_request_options(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("kind")
            .help("The type of certificate you want to request")
            .long("kind")
            .short('k')
            .possible_value("user")
            .possible_value("host")
            .takes_value(true),
    )
    .arg(
        Arg::new("duration")
            .help("Your request for certificate duration in seconds")
            .long("duration")
            .short('d')
            .takes_value(true),
    )
    .arg(
        Arg::new("principals")
            .help("A comma separated list of values you are requesting as principals")
            .short('n')
            .takes_value(true),
    )
    .arg(
        Arg::new("authority")
            .help("The name of the authority you are requesting a certificate from")
            .long("authority")
            .takes_value(true),
    )
}

pub fn add_daemon_options(cmd: Command) -> Command {
    cmd
        .arg(
            Arg::new("certificate-priority")
                .help("If this is present, the certificate will be listed first in the identity listing (otherwise the key will be first)")
                .long("priority")
                .takes_value(false)
        )
        .arg(
            Arg::new("socket")
                .help("Manually specify the path that will be used for the auth sock")
                .long("socket")
                .takes_value(true)
        )
}

fn parse_config_from_args(matches: &ArgMatches) -> Result<Config, ConfigurationError> {
    rustica_agent::config::parse_config_path(matches.value_of("config").unwrap())
        .map_err(|e| ConfigurationError::BadConfiguration(e))
}

fn parse_certificate_config_from_args(
    matches: &ArgMatches,
    config: &Config,
) -> Result<CertificateConfig, ConfigurationError> {
    let mut certificate_options = CertificateConfig::from(config.options.clone());

    if let Some(principals) = matches.value_of("principals") {
        certificate_options.principals = principals.split(',').map(|s| s.to_string()).collect();
    }

    if let Some(kind) = matches.value_of("kind") {
        certificate_options.cert_type = CertType::try_from(kind).unwrap_or(CertType::User);
    }

    if let Some(duration) = matches.value_of("duration") {
        certificate_options.duration = duration.parse::<u64>().unwrap_or(10);
    }

    if let Some(authority) = matches.value_of("authority") {
        certificate_options.authority = authority.to_owned();
    }

    Ok(certificate_options)
}

fn parse_socket_path_from_args(matches: &ArgMatches, config: &Config) -> String {
    match (matches.value_of("socket"), &config.socket) {
        (Some(socket), _) => socket.to_owned(),
        (_, Some(socket)) => socket.to_owned(),
        (None, None) => {
            let mut socket = env::temp_dir();
            socket.push(format!("rustica.{}", process::id()));
            socket.to_string_lossy().to_string()
        }
    }
}

pub async fn configure() -> Result<RusticaAgentAction, ConfigurationError> {
    let command_configuration = Command::new("rustica-agent")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Mitchell Grenier <mitchell@confurious.io>")
        .about("The SSH Agent component of Rustica");

    let immediate_mode = immediatemode::add_configuration(new_run_agent_subcommand(
        "immediate",
        "Immiediately request a certificate. Useful for testing and verifying access.",
    ));

    let multi_mode = multimode::add_configuration(new_run_agent_subcommand(
        "multi",
        "Run RusticaAgent in multimode. This takes a directory of SSH public keys and will try to serve them all as hardware backed keys.",
    ));

    let fido_setup_mode = fidosetup::add_configuration(new_run_agent_subcommand(
        "fido-setup",
        "Provision and register a new FIDO2 key.",
    ));

    let provision_piv_mode = provisionpiv::add_configuration(
        Command::new("provision-piv").about("Provision a yubikey slot with a new private key."),
    );

    let register_mode = register::add_configuration(new_run_agent_subcommand(
        "register",
        "Register a key file or a provisioned PIV key.",
    ));

    let single_mode = singlemode::add_configuration(new_run_agent_subcommand(
        "single",
        "Run Rustica agent on a single Yubikey slot or with a single key file.",
    ));

    let list_piv_keys = listpivkeys::add_configuration(
        Command::new("list-piv-keys").about("List PIV keys found on connected devices."),
    );

    let list_fido_devices =
        Command::new("list-fido-devices").about("List all connected FIDO2 devices. Used for pointing private keys to the correct device when multiple are connected");

    let git_config = gitconfig::add_configuration(
        Command::new("git-config")
            .about("Show the git configuration for code-signing with the provided key"),
    );

    let refresh_x509 = refresh_x509_certificate::add_configuration(new_run_agent_subcommand(
        "refresh-x509",
        "Refresh an X509 certificate in a Yubikey slot",
    ));

    let command_configuration = command_configuration
        .subcommand(immediate_mode)
        .subcommand(multi_mode)
        .subcommand(fido_setup_mode)
        .subcommand(provision_piv_mode)
        .subcommand(register_mode)
        .subcommand(single_mode)
        .subcommand(list_piv_keys)
        .subcommand(list_fido_devices)
        .subcommand(git_config)
        .subcommand(refresh_x509);
    let mut cc_help = command_configuration.clone();

    let matches = command_configuration.get_matches();

    if let Some(immediate_mode_cmd) = matches.subcommand_matches("immediate") {
        return immediatemode::configure_immediate(immediate_mode_cmd).await;
    }

    if let Some(multi_mode_cmd) = matches.subcommand_matches("multi") {
        return multimode::configure_multimode(&multi_mode_cmd).await;
    }

    if let Some(fido_setup_mode_cmd) = matches.subcommand_matches("fido-setup") {
        return fidosetup::configure_fido_setup(&fido_setup_mode_cmd).await;
    }

    if let Some(provision_piv_mode) = matches.subcommand_matches("provision-piv") {
        return provisionpiv::configure_provision_piv(&provision_piv_mode);
    }

    if let Some(register_mode) = matches.subcommand_matches("register") {
        return register::configure_register(&register_mode).await;
    }

    if let Some(single_mode) = matches.subcommand_matches("single") {
        return singlemode::configure_singlemode(&single_mode).await;
    }

    if let Some(list_piv_keys) = matches.subcommand_matches("list-piv-keys") {
        return listpivkeys::configure_list_piv_keys(&list_piv_keys);
    }

    if let Some(_) = matches.subcommand_matches("list-fido-devices") {
        return Ok(RusticaAgentAction::ListFidoDevices);
    }

    if let Some(git_config) = matches.subcommand_matches("git-config") {
        return gitconfig::configure_git_config(git_config);
    }

    if let Some(x509_config) = matches.subcommand_matches("refresh-x509") {
        return refresh_x509_certificate::configure_refresh_x509_certificate(x509_config).await;
    }

    cc_help.print_help().unwrap();
    Err(ConfigurationError::NoMode)
}
