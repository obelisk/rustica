mod immediatemode;
mod listallkeys;
mod multimode;

use clap::{Arg, ArgMatches, Command};

use rustica_agent::rustica::cert;
use sshcerts::yubikey::piv::{SlotId, Yubikey};
use sshcerts::{CertType, PrivateKey, PublicKey};

use rustica_agent::*;

use std::collections::HashMap;
use std::convert::TryFrom;
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::process;

#[derive(Debug)]
pub enum ConfigurationError {
    BadConfiguration,
    BadSlot,
    CannotAttestFileBasedKey,
    CannotProvisionFile,
    CannotReadFile(String),
    MissingMTLSCertificate,
    MissingMTLSKey,
    MissingServerAddress,
    MissingServerCertificateAuthority,
    MissingSSHKey,
    ParsingError,
    YubikeyManagementKeyInvalid,
    YubikeyNoKeypairFound,
    InvalidFidoKeyName,
    MultiModeError(multimode::Error),
    NoMode,
}

pub struct RunConfig {
    pub socket_path: String,
    pub pubkey: PublicKey,
    pub handler: Handler,
}

pub struct ProvisionPIVConfig {
    pub yubikey: YubikeySigner,
    pub pin: String,
    pub management_key: Vec<u8>,
    pub require_touch: bool,
    pub subject: String,
}

pub enum SKType {
    Ed25519,
    Ecdsa,
}

pub struct ProvisionAndRegisterFidoConfig {
    pub server: RusticaServer,
    pub app_name: String,
    pub comment: String,
    pub key_type: SKType,
    pub pin: Option<String>,
    pub out: Option<String>,
}

pub struct RegisterConfig {
    pub server: RusticaServer,
    pub signatory: Signatory,
    pub attestation: PIVAttestation,
}

pub enum RusticaAgentAction {
    Run(RunConfig),
    Immediate(immediatemode::ImmediateConfig),
    ProvisionPIV(ProvisionPIVConfig),
    Register(RegisterConfig),
    ProvisionAndRegisterFido(ProvisionAndRegisterFidoConfig),
    ListAllKeys,
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
    Command::new(name)
        .about(about)
        .arg(
            Arg::new("config")
                .help("Specify an alternate configuration file.")
                .long("config")
                .default_value("/etc/rustica/config.toml")
                .takes_value(true),
        )
        .arg(
            Arg::new("server")
                .help("Full address of Rustica server to use as CA")
                .long("server")
                .short('r')
                .takes_value(true),
        )
        .arg(
            Arg::new("capem")
                .help("Path to PEM that contains CA of the server's certificate")
                .long("capem")
                .short('c')
                .takes_value(true),
        )
        .arg(
            Arg::new("mtlscert")
                .help("Path to PEM that contains client cert")
                .long("mtlscert")
                .takes_value(true),
        )
        .arg(
            Arg::new("mtlskey")
                .help("Path to PEM that contains client key")
                .long("mtlskey")
                .takes_value(true),
        )
        .arg(
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
    let config = fs::read_to_string(matches.value_of("config").unwrap());
    let config = match config {
        Ok(content) => {
            if let Ok(t) = toml::from_str(&content) {
                t
            } else {
                return Err(ConfigurationError::BadConfiguration);
            }
        }
        Err(_) => Config {
            server: None,
            ca_pem: None,
            mtls_cert: None,
            mtls_key: None,
            slot: None,
            key: None,
            options: None,
            socket: None,
        },
    };

    Ok(config)
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

fn parse_server_from_args(
    matches: &ArgMatches,
    config: &Config,
) -> Result<RusticaServer, ConfigurationError> {
    let mtls_cert = match (matches.value_of("mtlscert"), &config.mtls_cert) {
        (Some(mtls_cert), _) => fs::read_to_string(mtls_cert)?,
        (_, Some(mtls_cert)) => mtls_cert.to_owned(),
        (None, None) => return Err(ConfigurationError::MissingMTLSCertificate),
    };

    let mtls_key = match (matches.value_of("mtlskey"), &config.mtls_key) {
        (Some(mtls_key), _) => fs::read_to_string(mtls_key)?,
        (_, Some(mtls_key)) => mtls_key.to_owned(),
        (None, None) => return Err(ConfigurationError::MissingMTLSKey),
    };

    let address = match (matches.value_of("server"), &config.server) {
        (Some(server), _) => server.to_owned(),
        (_, Some(server)) => server.to_owned(),
        (None, None) => return Err(ConfigurationError::MissingServerAddress),
    };

    let ca = match (matches.value_of("capem"), &config.ca_pem) {
        (Some(v), _) => {
            let mut contents = String::new();
            File::open(v)?.read_to_string(&mut contents)?;
            contents
        }
        (_, Some(v)) => v.to_owned(),
        (None, None) => return Err(ConfigurationError::MissingServerCertificateAuthority),
    };

    Ok(RusticaServer::new(address, ca, mtls_cert, mtls_key))
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

pub fn configure() -> Result<RusticaAgentAction, ConfigurationError> {
    let command_configuration = Command::new("rustica-agent")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Mitchell Grenier <mitchell@confurious.io>")
        .about("The SSH Agent component of Rustica");

    let immediate_mode = immediatemode::add_configuration(new_run_agent_subcommand(
        "immediate",
        "Immiediately request a certificate. Useful for testing and verifying access",
    ));

    let multi_mode = multimode::add_configuration(new_run_agent_subcommand(
        "multi",
        "Run RusticaAgent in multimode. This takes a directory of SSH public keys and will try to serve them all as hardware backed keys.",
    ));

    let command_configuration = command_configuration.subcommand(immediate_mode);
    let command_configuration = command_configuration.subcommand(multi_mode);

    let matches = command_configuration.get_matches();

    if let Some(immediate_mode_cmd) = matches.subcommand_matches("immediate") {
        return immediatemode::configure_immediate(immediate_mode_cmd);
    }

    if let Some(multi_mode_cmd) = matches.subcommand_matches("multi") {
        return multimode::configure_multimode(&multi_mode_cmd);
    }

    Err(ConfigurationError::NoMode)

    // // Read the configuration file and use it as a base. Command line parameters
    // // will override values provided in the config.
    // let config = fs::read_to_string(matches.value_of("config").unwrap());
    // let config = match config {
    //     Ok(content) => {
    //         if let Ok(t) = toml::from_str(&content) {
    //             t
    //         } else {
    //             return Err(ConfigurationError::BadConfiguration);
    //         }
    //     }
    //     Err(_) => Config {
    //         server: None,
    //         ca_pem: None,
    //         mtls_cert: None,
    //         mtls_key: None,
    //         slot: None,
    //         key: None,
    //         options: None,
    //         socket: None,
    //     },
    // };

    // let mtls_cert = match (matches.value_of("mtlscert"), &config.mtls_cert) {
    //     (Some(mtls_cert), _) => fs::read_to_string(mtls_cert)?,
    //     (_, Some(mtls_cert)) => mtls_cert.to_owned(),
    //     (None, None) => return Err(ConfigurationError::MissingMTLSCertificate),
    // };

    // let mtls_key = match (matches.value_of("mtlskey"), &config.mtls_key) {
    //     (Some(mtls_key), _) => fs::read_to_string(mtls_key)?,
    //     (_, Some(mtls_key)) => mtls_key.to_owned(),
    //     (None, None) => return Err(ConfigurationError::MissingMTLSKey),
    // };

    // let address = match (matches.value_of("server"), &config.server) {
    //     (Some(server), _) => server.to_owned(),
    //     (_, Some(server)) => server.to_owned(),
    //     (None, None) => return Err(ConfigurationError::MissingServerAddress),
    // };

    // let ca = match (matches.value_of("capem"), &config.ca_pem) {
    //     (Some(v), _) => {
    //         let mut contents = String::new();
    //         File::open(v)?.read_to_string(&mut contents)?;
    //         contents
    //     }
    //     (_, Some(v)) => v.to_owned(),
    //     (None, None) => return Err(ConfigurationError::MissingServerCertificateAuthority),
    // };

    // // Build a gRPC server used to talk to the backend
    // let server = RusticaServer::new(address, ca, mtls_cert, mtls_key);
    // // Determine if we should present the certificate or raw key first
    // let certificate_priority = matches.is_present("certificate-priority");
    // // Determine where the socket path should be, either provided, or a random
    // // path in a temp folder
    // let socket_path = match (matches.value_of("socket"), &config.socket) {
    //     (Some(socket), _) => socket.to_owned(),
    //     (_, Some(socket)) => socket.to_owned(),
    //     (None, None) => {
    //         let mut socket = env::temp_dir();
    //         socket.push(format!("rustica.{}", process::id()));
    //         socket.to_string_lossy().to_string()
    //     }
    // };

    // let cmd_slot = matches.value_of("slot").map(|x| x.to_owned());

    // if let Some(cmd_matches) = matches.subcommand_matches("provision-piv") {
    //     let signatory = get_signatory(&cmd_slot, &config.slot, &matches, &config.key)?;
    //     let yubikey = match signatory {
    //         Signatory::Yubikey(yk_sig) => yk_sig,
    //         Signatory::Direct(_) => return Err(ConfigurationError::CannotProvisionFile),
    //     };

    //     let require_touch = cmd_matches.is_present("require-touch");
    //     let subject = cmd_matches.value_of("subject").unwrap().to_string();
    //     let management_key = match hex::decode(cmd_matches.value_of("management-key").unwrap()) {
    //         Ok(mgm) => mgm,
    //         Err(_) => return Err(ConfigurationError::YubikeyManagementKeyInvalid),
    //     };

    //     let pin_env = cmd_matches.value_of("pin-env").unwrap().to_string();
    //     let pin = match env::var(pin_env) {
    //         Ok(val) => val,
    //         Err(_e) => "123456".to_string(),
    //     };

    //     let provision_config = ProvisionPIVConfig {
    //         yubikey,
    //         pin,
    //         management_key,
    //         subject,
    //         require_touch,
    //     };

    //     return Ok(RusticaAgentAction::ProvisionPIV(provision_config));
    // }

    // if let Some(matches) = matches.subcommand_matches("fido-setup") {
    //     let app_name = matches.value_of("application").unwrap().to_string();

    //     if !app_name.starts_with("ssh:") {
    //         return Err(ConfigurationError::InvalidFidoKeyName);
    //     }

    //     let comment = matches.value_of("comment").unwrap().to_string();
    //     let out = matches.value_of("out").map(String::from);

    //     let key_type = match matches.value_of("kind") {
    //         Some("ecdsa") => SKType::Ecdsa,
    //         _ => SKType::Ed25519,
    //     };

    //     let pin_env = matches.value_of("pin-env").unwrap().to_string();
    //     let pin = match env::var(pin_env) {
    //         Ok(val) => Some(val),
    //         Err(_e) => None,
    //     };

    //     let provision_config = ProvisionAndRegisterFidoConfig {
    //         server,
    //         app_name,
    //         comment,
    //         key_type,
    //         pin,
    //         out,
    //     };

    //     return Ok(RusticaAgentAction::ProvisionAndRegisterFido(
    //         provision_config,
    //     ));
    // }

    // let mut certificate_options = CertificateConfig::from(config.options);

    // if let Some(principals) = matches.value_of("principals") {
    //     certificate_options.principals = principals.split(',').map(|s| s.to_string()).collect();
    // }

    // if let Some(hosts) = matches.value_of("hosts") {
    //     certificate_options.hosts = hosts.split(',').map(|s| s.to_string()).collect();
    // }

    // if let Some(kind) = matches.value_of("kind") {
    //     certificate_options.cert_type = CertType::try_from(kind).unwrap_or(CertType::User);
    // }

    // if let Some(duration) = matches.value_of("duration") {
    //     certificate_options.duration = duration.parse::<u64>().unwrap_or(10);
    // }

    // if let Some(authority) = matches.value_of("authority") {
    //     certificate_options.authority = authority.to_owned();
    // }

    // if let Some(matches) = matches.subcommand_matches("multi-mode") {
    //     return multimode::configure_multimode(
    //         matches,
    //         server,
    //         certificate_priority,
    //         socket_path,
    //         certificate_options,
    //     )
    //     .map_err(|e| ConfigurationError::MultiModeError(e));
    // }

    // let mut signatory = get_signatory(&cmd_slot, &config.slot, &matches, &config.key)?;
    // let pubkey = match &mut signatory {
    //     Signatory::Yubikey(signer) => match signer.yk.ssh_cert_fetch_pubkey(&signer.slot) {
    //         Ok(cert) => cert,
    //         Err(_) => return Err(ConfigurationError::YubikeyNoKeypairFound),
    //     },
    //     Signatory::Direct(privkey) => privkey.pubkey.clone(),
    // };

    // if let Some(matches) = matches.subcommand_matches("register") {
    //     let mut attestation = PIVAttestation {
    //         certificate: vec![],
    //         intermediate: vec![],
    //     };

    //     if !matches.is_present("no-attest") {
    //         let signer = match &mut signatory {
    //             Signatory::Yubikey(s) => s,
    //             Signatory::Direct(_) => return Err(ConfigurationError::CannotAttestFileBasedKey),
    //         };

    //         attestation.certificate = signer
    //             .yk
    //             .fetch_attestation(&signer.slot)
    //             .unwrap_or_default();
    //         attestation.intermediate = signer
    //             .yk
    //             .fetch_certificate(&SlotId::Attestation)
    //             .unwrap_or_default();

    //         if attestation.certificate.is_empty() || attestation.intermediate.is_empty() {
    //             error!("Part of the attestation could not be generated. Registration may fail");
    //         }
    //     }

    //     return Ok(RusticaAgentAction::Register(RegisterConfig {
    //         server,
    //         signatory,
    //         attestation,
    //     }));
    // }

    // // if matches.is_present("immediate") {
    // //     let out = matches.value_of("out").map(|outfile| outfile.to_string());

    // //     return Ok(RusticaAgentAction::Immediate(ImmediateConfig {
    // //         server,
    // //         certificate_options,
    // //         signatory,
    // //         out,
    // //     }));
    // // }

    // let handler = Handler {
    //     server,
    //     cert: None,
    //     pubkey: pubkey.clone(),
    //     signatory,
    //     stale_at: 0,
    //     certificate_options,
    //     identities: HashMap::new(),
    //     piv_identities: HashMap::new(),
    //     notification_function: None,
    //     certificate_priority,
    // };

    // Ok(RusticaAgentAction::Run(RunConfig {
    //     socket_path,
    //     pubkey,
    //     handler,
    // }))
}
