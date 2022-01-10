#[macro_use] extern crate log;

use clap::{App, Arg};
use rustica_agent::*;

use std::collections::HashMap;
use std::convert::TryFrom;
use std::env;
use std::fs::{self, File};
use std::io::{Read};
use std::os::unix::net::{UnixListener};
use std::process;

use sshcerts::ssh::{Certificate, CertType, PrivateKey};
use sshcerts::yubikey::piv::{AlgorithmId, SlotId, TouchPolicy, PinPolicy, Yubikey};


fn provision_new_key(mut signatory: YubikeySigner, pin: &str, subj: &str, mgm_key: &[u8], alg: &str, secure: bool) -> Option<KeyConfig> {
    let alg = match alg {
        "eccp256" => AlgorithmId::EccP256,
        _ => AlgorithmId::EccP384,
    };

    println!("Provisioning new {:?} key in slot: {:?}", alg, &signatory.slot);

    let policy = if secure {
        println!("You're creating a secure key that will require touch to use.");
        TouchPolicy::Always
    } else {
        TouchPolicy::Never
    };

    if signatory.yk.unlock(pin.as_bytes(), &mgm_key).is_err() {
        println!("Could not unlock key");
        return None
    }

    match signatory.yk.provision(&signatory.slot, subj, alg, policy, PinPolicy::Never) {
        Ok(_) => {
            let certificate = signatory.yk.fetch_attestation(&signatory.slot);
            let intermediate = signatory.yk.fetch_certificate(&SlotId::Attestation);

            match (certificate, intermediate) {
                (Ok(certificate), Ok(intermediate)) => Some(KeyConfig {certificate, intermediate}),
                _ => None,
            }
        },
        Err(_) => panic!("Could not provision device with new key"),
    }
}

fn slot_parser(slot: &str) -> Option<SlotId> {
    // If first character is R, then we need to parse the nice
    // notation
    if (slot.len() == 2 || slot.len() == 3) && slot.starts_with('R') {
        let slot_value = slot[1..].parse::<u8>();
        match slot_value {
            Ok(v) if v <= 20 => Some(SlotId::try_from(0x81_u8 + v).unwrap()),
            _ => None,
        }
    } else if slot.len() == 4 && slot.starts_with("0x"){
        let slot_value = hex::decode(&slot[2..]).unwrap()[0];
        Some(SlotId::try_from(slot_value).unwrap())
    } else {
        None
    }
}

fn slot_validator(slot: &str) -> Result<(), String> {
    match slot_parser(slot) {
        Some(_) => Ok(()),
        None => Err(String::from("Provided slot was not valid. Should be R1 - R20 or a raw hex identifier")),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {  
    env_logger::init();
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
                    Arg::new("type")
                        .help("Specify the type of key you want to provision")
                        .default_value("eccp384")
                        .long("type")
                        .short('t')
                        .possible_value("eccp256")
                        .possible_value("eccp384")
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

    // First we read the configuration file and use those unless overriden by
    // the commandline
    let config = fs::read_to_string(matches.value_of("config").unwrap());
    let config = match config {
        Ok(content) => toml::from_str(&content)?,
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
    let mut certificate_options = CertificateConfig::from(config.options);

    let mtls_cert = match (matches.value_of("mtlscert"), &config.mtls_cert) {
        (Some(mtls_cert), _) => fs::read_to_string(mtls_cert)?,
        (_, Some(mtls_cert)) => mtls_cert.to_owned(),
        (None, None) => {
            error!("You must provide an mTLS cert to present to Rustica server");
            return Err(Box::new(ConfigurationError(String::from("Missing mTLS certificate"))))
        }
    };

    let mtls_key = match (matches.value_of("mtlskey"), &config.mtls_key) {
        (Some(mtls_key), _) => fs::read_to_string(mtls_key)?,
        (_, Some(mtls_key)) => mtls_key.to_owned(),
        (None, None) => {
            error!("You must provide an mTLS key to present to Rustica server");
            return Err(Box::new(ConfigurationError(String::from("Missing mTLS key"))))
        }
    };
    
    let address = match (matches.value_of("server"), &config.server) {
        (Some(server), _) => server.to_owned(),
        (_, Some(server)) => server.to_owned(),
        (None, None) => {
            error!("A server must be specified either in the config file or on the commandline");
            return Err(Box::new(ConfigurationError(String::from("Missing server address"))))
        }
    };

    let ca = match (matches.value_of("capem"), &config.ca_pem) {
        (Some(v), _) => {
            let mut contents = String::new();
            File::open(v)?.read_to_string(&mut contents)?;
            contents
        },
        (_, Some(v)) => v.to_owned(),
        (None, None) => {
            error!("You must provide the server certificate's issuing authority");
            return Err(Box::new(ConfigurationError(String::from("Missing server authority certificate"))))
        }
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
        (_, _, Some(file), _) => Signatory::Direct(PrivateKey::from_path(file)?),
        (_, _, _, Some(key_string)) => Signatory::Direct(PrivateKey::from_string(key_string)?),
        (Some(slot), _, _, _) | (_, Some(slot), _, _) => {
            match slot_parser(slot) {
                Some(s) => Signatory::Yubikey(YubikeySigner {
                    yk: Yubikey::new()?,
                    slot: s,
                }),
                None => {
                    error!("Chosen slot was invalid. Slot should be of the the form of: R# where # is between 1 and 20 inclusive");
                    return Err(Box::new(ConfigurationError(String::from("Bad slot"))))
                }
            }
        },
        (None, None, None, None) => {
            error!("A slot, file, or private key must be specified for identification");
            return Err(Box::new(ConfigurationError(String::from("No identity provided"))))
        }
    };

    if let Some(ref matches) = matches.subcommand_matches("provision") {
        let signatory = match signatory {
            Signatory::Yubikey(yk_sig) => yk_sig,
            Signatory::Direct(_) => {
                println!("Cannot provision a file, requires a Yubikey slot");
                return Err(Box::new(ConfigurationError(String::from("Cannot provision file"))))
            }
        };

        let secure = matches.is_present("require-touch");
        let subj = matches.value_of("subject").unwrap();
        let mgm_key = match matches.value_of("management-key") {
            Some(mgm) => hex::decode(mgm)?,
            None => {
                println!("Management key error");
                return Ok(());
            }
        };

        let pin = matches.value_of("pin").unwrap_or("123456");
        return match provision_new_key(signatory, pin, &subj, &mgm_key, matches.value_of("type").unwrap_or("eccp384"), secure) {
            Some(_) => Ok(()),
            None => {
                println!("Provisioning Error");
                return Err(Box::new(SigningError))
            },
        }
    }

    let pubkey = match &mut signatory {
        Signatory::Yubikey(signer) => match signer.yk.ssh_cert_fetch_pubkey(&signer.slot) {
            Ok(cert) => cert,
            Err(_) => {
                println!("There was no keypair found in slot {:?}. Provision one or use another slot.", &signer.slot);
                return Err(Box::new(ConfigurationError(String::from("No key in slot"))))
            }
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
                Signatory::Direct(_) => {
                    error!("You cannot attest a file based key");
                    return Ok(());
                }
            };
            key_config.certificate = signer.yk.fetch_attestation(&signer.slot).unwrap_or_default();
            key_config.intermediate = signer.yk.fetch_certificate(&SlotId::Attestation).unwrap_or_default();

            if key_config.certificate.is_empty() || key_config.intermediate.is_empty() {
                error!("Part of the attestation could not be generated. Registration may fail");
            }
        }

        return match server.register_key(&mut signatory, &key_config) {
            Ok(_) => {
                println!("Key was successfully registered");
                Ok(())
            },
            Err(e) => {
                error!("Key could not be registered. Server said: {}", e);
                Err(Box::new(e))
            },
        }
    }

    let mut stale_at = 0;

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

    let cert = if matches.is_present("immediate") {
        match server.get_custom_certificate(&mut signatory, &certificate_options) {
            Ok(x) => {
                let cert = Certificate::from_string(&x.cert)?;
                println!("Issued Certificate Details:");
                println!("{:#}\n", &cert);
                stale_at = cert.valid_before;

                if let Some(out_file) = matches.value_of("out") {
                    use std::io::Write;
                    let mut out = File::create(out_file)?;
                    out.write_all(cert.to_string().as_bytes())?;
                    return Ok(())
                }

                let cert: Vec<&str> = x.cert.split(' ').collect();
                let raw_cert = base64::decode(cert[1]).unwrap_or_default();
                Some(Identity {
                    key_blob: raw_cert,
                    key_comment: x.comment,
                })
            }
            Err(e) => {
                error!("Error: {}", e);
                return Err(Box::new(e))
            },
        }
    } else {
        None
    };

    println!("Starting Rustica Agent");
    println!("Access Fingerprint: {}", pubkey.fingerprint().hash);

    let socket_path = match (matches.value_of("socket"), &config.socket) {
        (Some(socket), _) => socket.to_owned(),
        (_, Some(socket)) => socket.to_owned(),
        (None, None) => {
            let mut socket = env::temp_dir();
            socket.push(format!("rustica.{}", process::id()));
            socket.to_string_lossy().to_string()
        }
    };

    println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", socket_path);

    let handler = Handler {
        server,
        cert,
        signatory,
        stale_at,
        certificate_options,
        identities: HashMap::new(),
        notification_function: None,
    };

    let socket = UnixListener::bind(socket_path)?;
    Agent::run(handler, socket);

    Ok(())
}