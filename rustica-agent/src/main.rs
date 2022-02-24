#[macro_use] extern crate log;

mod config;

use crate::config::RusticaAgentAction;
use rustica_agent::*;
use rustica_agent::rustica::key::{
    U2FAttestation
};

use ctap_hid_fido2::{
    Cfg,
    verifier,
    make_credential_params::CredentialSupportedKeyType,
};

use sshcerts::{
    Certificate,
    PrivateKey,
    PublicKey,
    ssh::KeyType,
    ssh::Ed25519PublicKey,
    ssh::PublicKeyKind,
    ssh::PrivateKeyKind,
    ssh::Ed25519SkPrivateKey,
};

use std::fs::File;
use std::io::Write;
use std::os::unix::net::{UnixListener};


fn main() -> Result<(), Box<dyn std::error::Error>> {  
    env_logger::init();
    match config::configure() {
        // Generates a new hardware backed key in a Yubikey then exits.
        // This always generates a NISTP384 key.
        Ok(RusticaAgentAction::ProvisionPIV(config)) => {
            match provision_new_key(config.yubikey, &config.pin, &config.subject, &config.management_key, config.require_touch) {
                Some(_) => (),
                None => {
                    println!("Provisioning Error");
                    return Err(Box::new(SigningError))
                },
            };
        },
        Ok(RusticaAgentAction::ProvisionAndRegisterFido(prf)) => {
            let challenge = verifier::create_challenge();
            let att = ctap_hid_fido2::make_credential_with_key_type(
                &Cfg::init(),
                &prf.app_name,
                &challenge,
                None,
                Some(CredentialSupportedKeyType::Ed25519),
            )?;

            let mut ret = 0x0;
            if att.flags_user_present_result {
                ret = ret | 0x01;
            }
            if att.flags_user_verified_result {
                ret = ret | 0x04;
            }
            if att.flags_attested_credential_data_included {
                ret = ret | 0x40;
            }
            if att.flags_extension_data_included {
                ret = ret | 0x80;
            }

            let key_type = KeyType::from_name("sk-ssh-ed25519@openssh.com").unwrap();
            let kind = PrivateKeyKind::Ed25519Sk(Ed25519SkPrivateKey {
                flags: ret,
                handle: att.credential_descriptor.id.clone(),
                reserved: vec![],
            });

            let pubkey = PublicKey {
                key_type: key_type.clone(),
                kind: PublicKeyKind::Ed25519(Ed25519PublicKey {
                    sk_application: Some(prf.app_name.clone()),
                    key: att.credential_publickey.der[1..].to_vec()
                }),
                comment: Some(prf.comment.clone()),
            };

            let private_key = PrivateKey {
                key_type,
                kind,
                pubkey,
                magic: 0x0,
                comment: Some(prf.comment),
            };

            if let Some(out) = prf.out {
                let mut out = File::create(out)?;
                private_key.write(&mut out)?;
            } else {
                let mut buf = std::io::BufWriter::new(Vec::new());
                private_key.write(&mut buf).unwrap();
                let serialized = String::from_utf8(buf.into_inner().unwrap()).unwrap();
                println!("Your new private key handle:\n{}", serialized);
                println!("You key fingerprint: {}", private_key.pubkey.fingerprint().hash);
            }

            let mut signatory = Signatory::Direct(private_key);

            let intermediate = if att.attstmt_x5c.is_empty() {
                println!("Could not get an attestation for this key. Registration may fail");
                vec![]
            } else {
                att.attstmt_x5c[0].clone()
            };

            let u2f_attestation = U2FAttestation {
                auth_data: att.auth_data,
                auth_data_sig: att.attstmt_sig,
                intermediate,
                challenge: challenge.to_vec(),
                alg: att.attstmt_alg,
            };

            match prf.server.register_u2f_key(&mut signatory, &prf.app_name, &u2f_attestation) {
                Ok(_) => {
                    println!("Key was successfully registered");
                },
                Err(e) => {
                    error!("Key could not be registered. Server said: {}", e);
                    return Err(Box::new(e))
                },
            };
        },
        Ok(RusticaAgentAction::Register(mut config)) => {
            match config.server.register_key(&mut config.signatory, &config.attestation) {
                Ok(_) => {
                    println!("Key was successfully registered");
                },
                Err(e) => {
                    error!("Key could not be registered. Server said: {}", e);
                    return Err(Box::new(e))
                },
            };
        },
        // Immediate operation: Immediately fetch a new certificate from the
        // server and optionally write it to a file. This is generally used
        // for debugging or in scripts where passing a certificate and key
        // file is easier than using an SSH agent.
        Ok(RusticaAgentAction::Immediate(mut config)) => {
            match config.server.get_custom_certificate(&mut config.signatory, &config.certificate_options) {
                Ok(x) => {
                    let cert = Certificate::from_string(&x.cert)?;

                    if let Some(out_file) = config.out {
                        let mut out = File::create(out_file)?;
                        out.write_all(cert.to_string().as_bytes())?;
                    } else {
                        println!("{:#}", &cert);
                    }
                }
                Err(e) => return Err(Box::new(e)),
            };
        },
        // Normal operation: Starts RusticaAgent as an SSHAgent and waits to answer
        // requests from SSH clients.
        Ok(RusticaAgentAction::Run(config)) => {
            println!("Starting Rustica Agent");
            println!("Access Fingerprint: {}", config.pubkey.fingerprint().hash);
            println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", config.socket_path);
        
            let socket = UnixListener::bind(config.socket_path)?;
            Agent::run(config.handler, socket);
        },
        Err(e) => println!("Error: {:?}", e),
    };

    Ok(())
}