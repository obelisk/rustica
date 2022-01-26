use clap::{App, Arg};

use sshcerts::{CertType, PublicKey, PrivateKey};
use sshcerts::yubikey::piv::{SlotId, Yubikey};

use rustica_agent::*;

use std::collections::HashMap;
use std::convert::TryFrom;
use std::env;
use std::fs::{self, File};
use std::io::{Read};
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
}

pub struct RunConfig {
    pub socket_path: String,
    pub pubkey: PublicKey,
    pub handler: Handler,
}

pub struct ProvisionConfig {
    pub yubikey: YubikeySigner,
    pub pin: String,
    pub management_key: Vec<u8>,
    pub require_touch: bool,
    pub subject: String,
}

pub struct RegisterConfig {
    pub server: RusticaServer,
    pub signatory: Signatory,
    pub key_config: KeyConfig,
}

pub struct ImmediateConfig {
    pub server: RusticaServer,
    pub certificate_options: CertificateConfig,
    pub signatory: Signatory,
    pub out: Option<String>,
}

pub enum RusticaAgentAction {
    Run(RunConfig),
    Immediate(ImmediateConfig),
    Provision(ProvisionConfig),
    Register(RegisterConfig),
}


impl From<std::io::Error> for ConfigurationError {
    fn from(e: std::io::Error) -> Self {
        ConfigurationError::CannotReadFile(e.to_string())
    }
}

impl From<sshcerts::error::Error> for ConfigurationError {
    fn from(e: sshcerts::error::Error) -> Self {
        ConfigurationError::ParsingError
    }
}


pub fn configure() -> Result<RusticaAgentAction, ConfigurationError> {
    let matches = App::new("rustica-agent")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Mitchell Grenier <mitchell@confurious.io>")
        .about("The SSH Agent component of Rustica")
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
            Arg::new("hosts")
                .help("A comma separated list of hostnames you are requesting a certificate for")
                .short('h')
                .takes_value(true),
        )
        .arg(
            Arg::new("immediate")
                .help("Immiediately request a certificate. Useful for testing and verifying access")
                .short('i')
        )
        .arg(
            Arg::new("out")
                .help("Output the certificate to a file and exit. Useful for refreshing host certificates")
                .short('o')
                .takes_value(true)
                .requires("immediate")
        )
        .arg(
            Arg::new("socket")
                .help("Manually specify the path that will be used for the auth sock")
                .long("socket")
                .takes_value(true)
        )
        .subcommand(
            App::new("register")
                .about("Take your key and register with the backend. If a hardware key, proof of providence will be sent to the backend")
                .arg(
                    Arg::new("no-attest")
                        .help("Don't send an attestation even with a hardware key. Only useful if your attestation chain is broken or for testing.")
                        .long("no-attest")
                )
        )
        .subcommand(
            App::new("provision")
                .about("Provision this slot with a new private key. The pin number must be passed as parameter here")
                .arg(
                    Arg::new("management-key")
                        .help("Specify the management key")
                        .default_value("010203040506070801020304050607080102030405060708")
                        .long("mgmkey")
                        .short('m')
                        .required(false)
                        .takes_value(true),
                )
                .arg(
                    Arg::new("pin")
                        .help("Specify the pin")
                        .default_value("123456")
                        .long("pin")
                        .short('p')
                        .required(false)
                        .takes_value(true),
                )
                .arg(
                    Arg::new("require-touch")
                        .help("Newly provisioned key requires touch for signing operations (touch cached for 15 seconds)")
                        .long("require-touch")
                        .short('r')
                )
                .arg(
                    Arg::new("subject")
                        .help("Subject of the new cert you're creating (this is only used as a note)")
                        .default_value("Rustica-AgentQuickProvision")
                        .long("subj")
                        .short('j')
                )
        )
        .get_matches();

    // Read the configuration file and use it as a base. Command line parameters
    // will override values provided in the config.
    let config = fs::read_to_string(matches.value_of("config").unwrap());
    let config = match config {
        Ok(content) => {
            if let Ok(t) = toml::from_str(&content) {
                t
            } else {
                return Err(ConfigurationError::BadConfiguration)
            }
        },
        Err(_) => {
            Config {
                server: None,
                ca_pem: None,
                mtls_cert: None,
                mtls_key: None,
                slot: None,
                key: None,
                options: None,
                socket: None,
            }
        }
    };

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
        },
        (_, Some(v)) => v.to_owned(),
        (None, None) => return Err(ConfigurationError::MissingServerCertificateAuthority),
    };

    let server = RusticaServer {
        address,
        ca,
        mtls_cert,
        mtls_key,
    };

    let cmd_slot = match matches.value_of("slot") {
        Some(x) => Some(x.to_owned()),
        None => None,
    };

    // Determine the signatory to be used. These match statements, execute in order,
    // create a hierarchy of which keys override others.
    // If a file is specified at the command line, that overrides everything else.
    // If there is no file, check for a key in the config file.
    // If there is no key in the config, check if a slot has been passed.
    // If there is a slot both on the command line and config file, prefer the command line
    // Otherwise use the slot in the config
    // If none of these, error.
    let mut signatory = match (&cmd_slot, &config.slot, matches.value_of("file"), &config.key) {
        (Some(slot), _, _, _) => {
            match slot_parser(slot) {
                Some(s) => Signatory::Yubikey(YubikeySigner {
                    yk: Yubikey::new().unwrap(),
                    slot: s,
                }),
                None => return Err(ConfigurationError::BadSlot)
            }
        },
        (_, _, Some(file), _) => Signatory::Direct(PrivateKey::from_path(file)?),
        (_, Some(slot), _, _) => {
            match slot_parser(slot) {
                Some(s) => Signatory::Yubikey(YubikeySigner {
                    yk: Yubikey::new().unwrap(),
                    slot: s,
                }),
                None => return Err(ConfigurationError::BadSlot),
            }
        },
        (_, _, _, Some(key_string)) => Signatory::Direct(PrivateKey::from_string(key_string)?),
        (None, None, None, None) => return Err(ConfigurationError::MissingSSHKey)
    };

    if let Some(ref matches) = matches.subcommand_matches("provision") {
        let yubikey = match signatory {
            Signatory::Yubikey(yk_sig) => yk_sig,
            Signatory::Direct(_) => return Err(ConfigurationError::CannotProvisionFile)
        };

        let require_touch = matches.is_present("require-touch");
        let subject = matches.value_of("subject").unwrap().to_string();
        let management_key = match hex::decode(matches.value_of("management-key").unwrap()) {
            Ok(mgm) => mgm,
            Err(_) => return Err(ConfigurationError::YubikeyManagementKeyInvalid),
        };

        let pin = matches.value_of("pin").unwrap().to_string();

        let provision_config = ProvisionConfig {
            yubikey,
            pin,
            management_key,
            subject,
            require_touch,
        };

        return Ok(RusticaAgentAction::Provision(provision_config));
    }

    let pubkey = match &mut signatory {
        Signatory::Yubikey(signer) => match signer.yk.ssh_cert_fetch_pubkey(&signer.slot) {
            Ok(cert) => cert,
            Err(_) => return Err(ConfigurationError::YubikeyNoKeypairFound),
        },
        Signatory::Direct(ref privkey) => privkey.pubkey.clone()
    };

    if let Some(ref matches) = matches.subcommand_matches("register") {
        let mut key_config = KeyConfig {
            certificate: vec![],
            intermediate: vec![],
        };

        if !matches.is_present("no-attest") {
            let signer = match &mut signatory {
                Signatory::Yubikey(s) => s,
                Signatory::Direct(_) => return Err(ConfigurationError::CannotAttestFileBasedKey),
            };

            key_config.certificate = signer.yk.fetch_attestation(&signer.slot).unwrap_or_default();
            key_config.intermediate = signer.yk.fetch_certificate(&SlotId::Attestation).unwrap_or_default();

            if key_config.certificate.is_empty() || key_config.intermediate.is_empty() {
                error!("Part of the attestation could not be generated. Registration may fail");
            }
        }

        return Ok(RusticaAgentAction::Register(RegisterConfig {
            server,
            signatory,
            key_config,
        }))
    }

    let mut certificate_options = CertificateConfig::from(config.options);

    if let Some(principals) = matches.value_of("principals") {
        certificate_options.principals = principals.split(',').map(|s| s.to_string()).collect();
    }

    if let Some(hosts) = matches.value_of("hosts") {
        certificate_options.hosts = hosts.split(',').map(|s| s.to_string()).collect();
    }

    if let Some(kind) = matches.value_of("kind") {
        certificate_options.cert_type = CertType::try_from(kind).unwrap_or(CertType::User);
    }

    if let Some(duration) = matches.value_of("duration") {
        certificate_options.duration = duration.parse::<u64>().unwrap_or(10);
    }

    if matches.is_present("immediate") {
        let out = match matches.value_of("out") {
            Some(outfile) => Some(outfile.to_string()),
            None => None,
        };

        return Ok(RusticaAgentAction::Immediate(ImmediateConfig {
            server,
            certificate_options,
            signatory,
            out,
        }));
    }

    let socket_path = match (matches.value_of("socket"), &config.socket) {
        (Some(socket), _) => socket.to_owned(),
        (_, Some(socket)) => socket.to_owned(),
        (None, None) => {
            let mut socket = env::temp_dir();
            socket.push(format!("rustica.{}", process::id()));
            socket.to_string_lossy().to_string()
        }
    };

    let handler = Handler {
        server,
        cert: None,
        signatory,
        stale_at: 0,
        certificate_options,
        identities: HashMap::new(),
        notification_function: None,
    };

    Ok(RusticaAgentAction::Run(RunConfig {
        socket_path,
        pubkey,
        handler,
    }))
}