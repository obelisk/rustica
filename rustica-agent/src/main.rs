#[macro_use] extern crate log;

mod sshagent;
mod rustica;

use clap::{App, Arg};

use sshagent::{Agent, error::Error as AgentError, Identity, SSHAgentHandler, Response};
use std::env;
use std::os::unix::net::{UnixListener};
use std::process;

use ring::signature;
use rustica::{cert, RusticaServer, Signatory};
use sshcerts::ssh::{Certificate, CertType, CurveKind, PublicKeyKind, PrivateKey, PrivateKeyKind};
use sshcerts::utils::signature_convert_asn1_ecdsa_to_ssh;
use sshcerts::yubikey::{
    provision,
    ssh::{
        convert_to_ssh_pubkey,
        ssh_cert_signer,
        ssh_cert_fetch_pubkey,
    }
};

use serde_derive::Deserialize;
use std::convert::TryFrom;
use std::fs::{self, File};
use std::io::{Read};
use std::time::SystemTime;
use yubikey_piv::key::{AlgorithmId, SlotId};
use yubikey_piv::policy::TouchPolicy;

#[derive(Debug, Deserialize)]
struct Options {
    principals: Option<Vec<String>>,
    hosts: Option<Vec<String>>,
    kind: Option<String>,
    duration: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct Config {
    server: Option<String>,
    server_pem: Option<String>,
    slot: Option<String>,
    options: Option<Options>,
}

#[derive(Debug)]
struct Handler {
    server: RusticaServer,
    cert: Option<Identity>,
    signatory: Signatory,
    stale_at: u64,
    certificate_options: rustica::CertificateConfig,
}

impl From<Option<Options>> for rustica::CertificateConfig {
    fn from(co: Option<Options>) -> rustica::CertificateConfig {
        match co {
            None => {
                rustica::CertificateConfig {
                    cert_type: CertType::User,
                    duration: 10,
                    hosts: vec![],
                    principals: vec![],
                }
            },
            Some(co) => {
                rustica::CertificateConfig {
                    cert_type: CertType::try_from(co.kind.unwrap_or_else(|| String::from("user")).as_str()).unwrap_or(CertType::User),
                    duration: co.duration.unwrap_or(10),
                    hosts: co.hosts.unwrap_or_default(),
                    principals: co.principals.unwrap_or_default(),
                }
            }
        }
    }
}

impl SSHAgentHandler for Handler {
    fn identities(&mut self) -> Result<Response, AgentError> {
        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        if let Some(cert) = &self.cert {
            if timestamp < self.stale_at {
                debug!("Certificate has not expired, not refreshing");
                return Ok(Response::Identities(vec![cert.clone()]));
            }
        }
        match cert::get_custom_certificate(&self.server, &self.signatory, &self.certificate_options) {
            Ok(response) => {
                info!("{:#}", Certificate::from_string(&response.cert).unwrap());
                let cert: Vec<&str> = response.cert.split(' ').collect();
                let raw_cert = base64::decode(cert[1]).unwrap_or_default();
                let ident = Identity {
                    key_blob: raw_cert,
                    key_comment: response.comment,
                };
                self.cert = Some(ident.clone());
                Ok(Response::Identities(vec![ident]))
            },
            Err(e) => {
                error!("Refresh certificate error: {:?}", e);
                Err(AgentError::from("Could not refresh certificate"))
            },
        }
    }

    /// Pubkey is currently unused because the idea is to only ever have a single cert which itself is only
    /// active for a very small window of time
    fn sign_request(&mut self, _pubkey: Vec<u8>, data: Vec<u8>, _flags: u32) -> Result<Response, AgentError> {
        match &self.signatory {
            Signatory::Yubikey(slot) => {
                let signature = ssh_cert_signer(&data, *slot).unwrap();
                let signature = (&signature[27..]).to_vec();

                let pubkey = ssh_cert_fetch_pubkey(*slot).unwrap();

                Ok(Response::SignResponse {
                    algo_name: String::from(pubkey.key_type.name),
                    signature,
                })
            },
            Signatory::Direct(privkey) => {
                let rng = ring::rand::SystemRandom::new();

                match &privkey.kind {
                    PrivateKeyKind::Rsa(_) => Err(AgentError::from("unimplemented")),
                    PrivateKeyKind::Ecdsa(key) => {
                        let (alg, name) = match key.curve.kind {
                            CurveKind::Nistp256 => (&signature::ECDSA_P256_SHA256_ASN1_SIGNING, "ecdsa-sha2-nistp256"),
                            CurveKind::Nistp384 => (&signature::ECDSA_P384_SHA384_ASN1_SIGNING, "ecdsa-sha2-nistp384"),
                            CurveKind::Nistp521 => return Err(AgentError::from("unimplemented")),
                        };

                        let pubkey = match &privkey.pubkey.kind {
                            PublicKeyKind::Ecdsa(key) => &key.key,
                            _ => return Err(AgentError::from("unimplemented")),
                        };

                        let key = if key.key[0] == 0x0_u8 {&key.key[1..]} else {&key.key};
                        let key_pair = signature::EcdsaKeyPair::from_private_key_and_public_key(alg, &key, &pubkey).unwrap();

                        let signature = signature_convert_asn1_ecdsa_to_ssh(key_pair.sign(&rng, &data).unwrap().as_ref()).unwrap();
                        let signature = (&signature[4..]).to_vec();
                        Ok(Response::SignResponse {
                            algo_name: name.to_string(),
                            signature,
                        })
                    },
                    PrivateKeyKind::Ed25519(key) => {
                        let public_key = match &privkey.pubkey.kind {
                            PublicKeyKind::Ed25519(key) => &key.key,
                            _ => return Err(AgentError::from("Key Error")),
                        };
    
                        let key_pair = match signature::Ed25519KeyPair::from_seed_and_public_key(&key.key[..32], public_key) {
                            Ok(kp) => kp,
                            Err(_) => return Err(AgentError::from("Key Error")),
                        };
                        Ok(Response::SignResponse {
                            algo_name: String::from("ssh-ed25519"),
                            signature: key_pair.sign(&data).as_ref().to_vec(),
                        })
                    },
                }
            }
        }
    }
}

fn provision_new_key(slot: SlotId, pin: &str, subj: &str, mgm_key: &[u8], alg: &str, secure: bool) {
    let alg = match alg {
        "eccp256" => AlgorithmId::EccP256,
        _ => AlgorithmId::EccP384,
    };

    println!("Provisioning new {:?} key in slot: {:?}", alg, slot);

    let policy = if secure {
        println!("You're creating a secure key that will require touch to use.");
        TouchPolicy::Cached
    } else {
        TouchPolicy::Never
    };

    match provision(pin.as_bytes(), mgm_key, slot, subj, alg, policy) {
        Ok(pk) => {
            convert_to_ssh_pubkey(&pk).unwrap();
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
    } else if let Ok(s) = SlotId::try_from(slot.to_owned()) {
        Some(s)
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
            Arg::new("server")
                .about("Full address of Rustica server to use as CA")
                .long("server")
                .short('r')
                .takes_value(true),
        )
        .arg(
            Arg::new("serverpem")
                .about("Path to PEM that contains server public key")
                .long("serverpem")
                .short('c')
                .takes_value(true),
        )
        .arg(
            Arg::new("clientcert")
                .about("Path to PEM that contains client cert")
                .long("clientcert")
                .takes_value(true),
        )
        .arg(
            Arg::new("clientkey")
                .about("Path to PEM that contains client key")
                .long("clientkey")
                .takes_value(true),
        )
        .arg(
            Arg::new("slot")
                .about("Numerical value for the slot on the yubikey to use for your private key")
                .long("slot")
                .short('s')
                .validator(slot_validator)
                .takes_value(true),
        )
        .arg(
            Arg::new("file")
                .about("Used instead of a slot to provide a private key via file")
                .long("file")
                .short('f')
                .takes_value(true),
        )
        .arg(
            Arg::new("kind")
                .about("The type of certificate you want to request")
                .long("kind")
                .short('k')
                .possible_value("user")
                .possible_value("host")
                .takes_value(true),
        )
        .arg(
            Arg::new("duration")
                .about("Your request for certificate duration in seconds")
                .long("duration")
                .short('d')
                .takes_value(true),
        )
        .arg(
            Arg::new("principals")
                .about("A comma separated list of values you are requesting as principals")
                .short('n')
                .takes_value(true),
        )
        .arg(
            Arg::new("hosts")
                .about("A comma separated list of hostnames you are requesting a certificate for")
                .short('h')
                .takes_value(true),
        )
        .arg(
            Arg::new("immediate")
                .about("Immiediately request a certificate. Useful for testing.")
                .short('i')
        )
        .subcommand(
            App::new("provision")
                .about("Provision this slot with a new private key. The pin number must be passed as parameter here")
                .arg(
                    Arg::new("management-key")
                        .about("Specify the management key")
                        .default_value("010203040506070801020304050607080102030405060708")
                        .long("mgmkey")
                        .short('m')
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::new("pin")
                        .about("Specify the pin")
                        .default_value("123456")
                        .long("pin")
                        .short('p')
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::new("type")
                        .about("Specify the type of key you want to provision")
                        .default_value("eccp256")
                        .long("type")
                        .short('t')
                        .possible_value("eccp256")
                        .possible_value("eccp384")
                        .takes_value(true),
                )
                .arg(
                    Arg::new("require-touch")
                        .about("Newly provisioned key requires touch for signing operations (touch cached for 15 seconds)")
                        .long("require-touch")
                        .short('r')
                )
                .arg(
                    Arg::new("subject")
                        .about("Subject of the new cert you're creating (this is only used as a note)")
                        .default_value("Rustica-AgentQuickProvision")
                        .long("subj")
                        .short('j')
                )
        )
        .get_matches();

    // First we read the configuration file and use those unless overriden by
    // the commandline
    let config = fs::read_to_string("/etc/rustica/config.toml");
    let config = match config {
        Ok(content) => toml::from_str(&content)?,
        Err(_) => {
            Config {
                server: None,
                server_pem: None,
                slot: None,
                options: None,
            }
        }
    };

    let mtls_cert = fs::read_to_string(matches.value_of("clientcert").unwrap()).unwrap();
    let mtls_key = fs::read_to_string(matches.value_of("clientkey").unwrap()).unwrap();

    let mut certificate_options = rustica::CertificateConfig::from(config.options);
    
    let address = match (matches.value_of("server"), &config.server) {
        (Some(server), _) => server.to_owned(),
        (_, Some(server)) => server.to_owned(),
        (None, None) => {
            error!("A server must be specified either in the config file or on the commandline");
            return Ok(());
        }
    };

    let ca = match (matches.value_of("serverpem"), &config.server_pem) {
        (Some(v), _) => {
            let mut contents = String::new();
            File::open(v)?.read_to_string(&mut contents)?;
            contents
        },
        (_, Some(v)) => v.to_owned(),
        (None, None) => {
            error!("You must provide a pem for server authentication");
            return Ok(());
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

    let signatory = match (&cmd_slot, &config.slot, matches.value_of("file")) {
        (_, _, Some(file)) => Signatory::Direct(PrivateKey::from_path(file)?),
        (Some(slot), _, _) | (_, Some(slot), _) => {
            match slot_parser(slot) {
                Some(s) => Signatory::Yubikey(s),
                None => {
                    error!("Chosen slot was invalid. Slot should be of the the form of: R# where # is between 1 and 20 inclusive");
                    return Ok(());
                }
            }
        },
        (None, None, None) => {
            error!("A slot or file must be specified to use as identification");
            return Ok(());
        }
    };

    let pubkey = match signatory {
        Signatory::Yubikey(slot) => match ssh_cert_fetch_pubkey(slot) {
            Some(cert) => cert,
            None => {
                println!("There was no keypair found in slot {:?}. Provision one or use another slot.", slot);
                return Ok(())
            }
        },
        Signatory::Direct(ref privkey) => privkey.pubkey.clone()
    };

    if let Some(ref matches) = matches.subcommand_matches("provision") {
        let slot = match signatory {
            Signatory::Yubikey(slot) => slot,
            Signatory::Direct(_) => {
                println!("Cannot provision a file, requires a Yubikey slot");
                return Ok(());
            }
        };

        let secure = matches.is_present("require-touch");
        let subj = matches.value_of("subject").unwrap();
        let mgm_key = match matches.value_of("management-key") {
            Some(mgm) => hex::decode(mgm).unwrap(),
            None => {
                println!("Management key error");
                return Ok(());
            }
        };

        let pin = matches.value_of("pin").unwrap_or("123456");
        provision_new_key(slot, pin, &subj, &mgm_key, matches.value_of("type").unwrap_or("eccp384"), secure);
        return Ok(());
    }

    let mut cert = None;
    let mut stale_at = 0;

    if let Some(principals) =  matches.value_of("principals") {
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
        cert = match cert::get_custom_certificate(&server, &signatory, &certificate_options) {
            Ok(x) => {
                let cert = Certificate::from_string(&x.cert).unwrap();
                println!("Issued Certificate Details:");
                println!("{:#}\n", &cert);
                stale_at = cert.valid_before;
                debug!("Raw Certificate: ");
                debug!("{}", &cert);

                let cert: Vec<&str> = x.cert.split(' ').collect();
                let raw_cert = base64::decode(cert[1]).unwrap_or_default();
                Some(Identity {
                    key_blob: raw_cert,
                    key_comment: x.comment,
                })
            }
            Err(e) => {
                error!("Error: {:?}", e);
                return Ok(());
            },
        };
    }

    println!("Starting Rustica Agent");
    println!("Access Fingerprint: {}", pubkey.fingerprint().hash);

    let mut socket_path = env::temp_dir();
    socket_path.push(format!("rustica.{}", process::id()));
    println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", socket_path.to_string_lossy());

    let handler = Handler {
        server,
        cert,
        signatory,
        stale_at,
        certificate_options,
    };

    let socket = UnixListener::bind(socket_path).unwrap();
    Agent::run(handler, socket);

    Ok(())
}