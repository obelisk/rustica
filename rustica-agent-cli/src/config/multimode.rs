use std::sync::Arc;
use std::{collections::HashMap, env, fs};

use rustica_agent::{
    get_all_piv_keys, get_piv_key_descriptor, slot_parser, Handler, RusticaAgentLibraryError,
    Signatory, YubikeyPIVKeyDescriptor, YubikeySigner,
};

use clap::{Arg, ArgMatches, Command};
use rustica_agent::{PrivateKey, PublicKey, Yubikey};

use crate::config::{
    parse_certificate_config_from_args, parse_config_from_args, parse_socket_path_from_args,
    RunConfig,
};

use super::{ConfigurationError, RusticaAgentAction};

#[derive(Debug)]
pub enum Error {
    BadKeyDir(String),
    BadPivSelector(String),
    CertificateIsUnknownKey(String),
    UnknownPublicKey(String),
    RusticaAgentError(RusticaAgentLibraryError),
}

fn pin_for_yubikey(serial: u32) -> Option<String> {
    env::var(format!("YK_PIN_{serial}"))
        .ok()
        .or_else(|| env::var("YK_PIN").ok())
}

fn parse_piv_selector(selector: &str) -> Result<(u32, rustica_agent::SlotId), Error> {
    let (serial, slot) = selector
        .split_once(':')
        .ok_or_else(|| Error::BadPivSelector(selector.to_string()))?;
    let serial = serial
        .parse::<u32>()
        .map_err(|_| Error::BadPivSelector(selector.to_string()))?;
    let slot = slot_parser(slot).ok_or_else(|| Error::BadPivSelector(selector.to_string()))?;

    Ok((serial, slot))
}

fn get_piv_descriptor(selector: &str) -> Result<YubikeyPIVKeyDescriptor, Error> {
    let (serial, slot) = parse_piv_selector(selector)?;
    get_piv_key_descriptor(serial, slot, pin_for_yubikey(serial)).ok_or(Error::RusticaAgentError(
        RusticaAgentLibraryError::CouldNotOpenYubikey(serial),
    ))
}

fn get_piv_signatory(selector: &str) -> Result<(PublicKey, Signatory), Error> {
    let descriptor = get_piv_descriptor(selector)?;
    let yk = Yubikey::open(descriptor.serial).map_err(|_| {
        Error::RusticaAgentError(RusticaAgentLibraryError::CouldNotOpenYubikey(
            descriptor.serial,
        ))
    })?;
    let public_key = descriptor.public_key.clone();
    let signatory = Signatory::Yubikey(YubikeySigner {
        yk: yk.into(),
        slot: descriptor.slot,
        requires_touch: descriptor.requires_touch,
    });

    Ok((public_key, signatory))
}

fn get_keys_from_dir(directory: &str) -> Result<(Vec<PublicKey>, Vec<PrivateKey>), Error> {
    let key_files = fs::read_dir(directory).map_err(|e| Error::BadKeyDir(e.to_string()))?;

    let mut public_keys = vec![];
    let mut private_keys = vec![];

    for key in key_files {
        let key_path = match key {
            Ok(key) => key.path(),
            Err(e) => {
                println!("Error: {e}");
                continue;
            }
        };

        // If it's a .pub, try to parse it as a public key
        if key_path.display().to_string().ends_with(".pub") {
            match PublicKey::from_path(&key_path) {
                Ok(key) => public_keys.push(key),
                Err(e) => println!("Error for {}: {e}", key_path.to_string_lossy()),
            }
        } else {
            // Try it as a private key
            match PrivateKey::from_path(&key_path) {
                Ok(key) => private_keys.push(key),
                Err(e) => println!("Error for {}: {e}", key_path.to_string_lossy()),
            }
        }
    }

    println!(
        "Loaded: {} public keys, and {} private keys",
        public_keys.len(),
        private_keys.len()
    );

    return Ok((public_keys, private_keys));
}

fn validate_public_keys(
    public_keys: &[PublicKey],
) -> Result<HashMap<Vec<u8>, YubikeyPIVKeyDescriptor>, Error> {
    if public_keys.is_empty() {
        return Ok(HashMap::new());
    }

    let mut all_keys = get_all_piv_keys().map_err(|x| Error::RusticaAgentError(x))?;

    let mut key_map = HashMap::new();
    for public_key in public_keys {
        let encoded = public_key.encode().to_vec();
        if let Some(key) = all_keys.remove(&encoded) {
            key_map.insert(encoded, key);
        } else {
            return Err(Error::UnknownPublicKey(public_key.fingerprint().hash));
        }
    }

    Ok(key_map)
}

fn get_signatory(
    certificate_fingerprint: &str,
    public_keys: &HashMap<Vec<u8>, YubikeyPIVKeyDescriptor>,
    private_keys: &[PrivateKey],
) -> Result<(PublicKey, Signatory), Error> {
    for (key, des) in public_keys {
        let key = PublicKey::from_bytes(key).unwrap();
        if certificate_fingerprint == key.fingerprint().hash {
            let sig = Signatory::Yubikey(YubikeySigner {
                yk: Yubikey::open(des.serial).unwrap().into(),
                slot: des.slot,
                requires_touch: des.requires_touch,
            });
            return Ok((des.public_key.clone(), sig));
        }
    }

    for private_key in private_keys {
        if certificate_fingerprint == private_key.pubkey.fingerprint().hash {
            return Ok((
                private_key.pubkey.clone(),
                Signatory::Direct(private_key.clone().into()),
            ));
        }
    }

    Err(Error::CertificateIsUnknownKey(
        certificate_fingerprint.to_string(),
    ))
}

pub async fn configure_multimode(
    matches: &ArgMatches,
) -> Result<RusticaAgentAction, ConfigurationError> {
    let updatable_configuration = parse_config_from_args(&matches)?;
    let config = updatable_configuration.get_configuration();
    let certificate_options = parse_certificate_config_from_args(&matches, &config)?;
    let socket_path = parse_socket_path_from_args(matches, &config);

    let certificate_fingerprint = matches.value_of("cert-for");
    let certificate_piv = matches.value_of("cert-piv");

    let key_dir = matches.value_of("key-dir");
    let (public_keys, mut private_keys) = match key_dir {
        Some(key_dir) => {
            get_keys_from_dir(key_dir).map_err(|x| ConfigurationError::MultiModeError(x))?
        }
        None => (Vec::new(), Vec::new()),
    };
    let mut key_map =
        validate_public_keys(&public_keys).map_err(|x| ConfigurationError::MultiModeError(x))?;
    if let Some(selectors) = matches.values_of("piv") {
        for selector in selectors {
            let descriptor =
                get_piv_descriptor(selector).map_err(|x| ConfigurationError::MultiModeError(x))?;
            key_map.insert(descriptor.public_key.encode().to_vec(), descriptor);
        }
    }

    let (pubkey, signatory) = match (certificate_fingerprint, certificate_piv) {
        (Some(certificate_fingerprint), None) => {
            get_signatory(certificate_fingerprint, &key_map, &private_keys)
                .map_err(|x| ConfigurationError::MultiModeError(x))?
        }
        (None, Some(certificate_piv)) => {
            get_piv_signatory(certificate_piv).map_err(|x| ConfigurationError::MultiModeError(x))?
        }
        _ => unreachable!(),
    };

    // Set the path on all private keys. This will only be used if the type is
    // EcdsaSK or Ed25519SK
    for private_key in private_keys.iter_mut() {
        if let Some(path) = matches.value_of("fido-device-path") {
            private_key.set_device_path(path);
        }
    }

    let mut private_keys: HashMap<Vec<u8>, PrivateKey> = private_keys
        .into_iter()
        .map(|x| (x.pubkey.encode().to_vec(), x))
        .collect();

    println!("Loaded {} keys", key_map.len() + private_keys.len());

    // Remove the certificate key from the public or private key maps since
    // we will add that later as the raw portion of the certificate
    private_keys.remove(&pubkey.encode().to_vec());
    key_map.remove(&pubkey.encode().to_vec());

    let handler = Handler {
        updatable_configuration: updatable_configuration.into(),
        cert: None.into(),
        pubkey: pubkey.clone(),
        signatory,
        stale_at: 0.into(),
        certificate_options,
        identities: private_keys.into(),
        piv_identities: key_map,
        notification_function: None,
        certificate_priority: matches.is_present("certificate-priority"),
    };

    let handler = Arc::new(handler);
    Ok(RusticaAgentAction::Run(RunConfig {
        socket_path,
        pubkey,
        handler,
    }))
}

pub fn add_configuration(cmd: Command) -> Command {
    // Add socket path and certificate priority
    let cmd = super::add_daemon_options(cmd);

    // Add options for setting the fields on requested certificates
    let cmd = super::add_request_options(cmd);

    // Add the specific arguments for this command
    cmd
        .arg(
            Arg::new("key-dir")
                .help("The directory which contains all keys you'd like to serve as hardware keys")
                .long("dir")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::new("cert-for")
                .help("The fingerprint of the key to request certificates for")
                .long("certfor")
                .required(false)
                .required_unless_present("cert-piv")
                .conflicts_with("cert-piv")
                .requires("key-dir")
                .takes_value(true),
        )
        .arg(
            Arg::new("cert-piv")
                .help("The PIV key to request certificates for, formatted as <serial>:<slot>")
                .long("cert-piv")
                .required(false)
                .required_unless_present("cert-for")
                .conflicts_with("cert-for")
                .takes_value(true),
        )
        .arg(
            Arg::new("piv")
                .help("Additional PIV key to serve, formatted as <serial>:<slot>")
                .long("piv")
                .required(false)
                .multiple_occurrences(true)
                .takes_value(true),
        )
        .arg(
            Arg::new("fido-device-path")
                .help("The device path to use for FIDO2 keys. If not provided, we'll pick a device randomly. Should be set when multiple FIDO2 devices connected.")
                .long("fido")
                .required(false)
                .takes_value(true),
        )
}
