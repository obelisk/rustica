#[macro_use]
extern crate log;

mod config;

use crate::config::RusticaAgentAction;
use rustica_agent::rustica::key::U2FAttestation;
use rustica_agent::*;

use sshcerts::{
    fido::{generate::generate_new_ssh_key, list_fido_devices},
    Certificate,
};
use tokio::sync::mpsc::channel;

use std::fs::File;
use std::io::Write;
use std::os::unix::prelude::PermissionsExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    match config::configure().await {
        Ok(RusticaAgentAction::GitConfig(public_key)) => {
            println!("{}", git_config_from_public_key(&public_key))
        }
        Ok(RusticaAgentAction::ListFidoDevices) => {
            for device in list_fido_devices() {
                println!("{} - {}", device.path, device.product_string);
            }
        }
        // This lists all keys we can find on connected devices
        Ok(RusticaAgentAction::ListPIVKeys(config)) => {
            let all_keys = crate::get_all_piv_keys()?;

            for (_, des) in all_keys {
                let key_form = match config.show_full {
                    true => des.public_key.to_string(),
                    false => des.public_key.fingerprint().hash,
                };

                println!("{}\t{:?}:\t{key_form}", des.serial, des.slot)
            }
        }
        // Generates a new hardware backed key in a Yubikey then exits.
        // This always generates a NISTP384 key.
        Ok(RusticaAgentAction::ProvisionPIV(config)) => {
            match provision_new_key(
                config.yubikey,
                &config.pin,
                &config.subject,
                &config.management_key,
                config.require_touch,
            ) {
                Some(_) => (),
                None => {
                    println!("Provisioning Error");
                    return Err(Box::new(SigningError))?;
                }
            };
        }
        // This is done in one step instead of two because there is no way (that I know of) to get an attestation
        // for a previously generated FIDO key. So we have to send the attestation data at generation time.
        Ok(RusticaAgentAction::ProvisionAndRegisterFido(prf)) => {
            let new_fido_key = generate_new_ssh_key(&prf.app_name, &prf.comment, prf.pin, None)?;

            let mut signatory = Signatory::Direct(new_fido_key.private_key.clone());
            let u2f_attestation = U2FAttestation {
                auth_data: new_fido_key.attestation.auth_data,
                auth_data_sig: new_fido_key.attestation.auth_data_sig,
                intermediate: new_fido_key.attestation.intermediate,
                challenge: new_fido_key.attestation.challenge,
                alg: new_fido_key.attestation.alg,
            };

            match prf
                .server
                .register_u2f_key(&mut signatory, &prf.app_name, &u2f_attestation)
            {
                Ok(_) => {
                    println!("Key was successfully registered!");

                    if let Some(out) = prf.out {
                        let mut out_file = File::create(&out)?;

                        if let Ok(md) = out_file.metadata() {
                            let mut permissions = md.permissions();
                            permissions.set_mode(0o600);
                        } else {
                            println!("Error: Could not set file permissions on: {}", out);
                        };

                        new_fido_key.private_key.write(&mut out_file)?;
                    } else {
                        let mut buf = std::io::BufWriter::new(Vec::new());
                        new_fido_key.private_key.write(&mut buf).unwrap();
                        let serialized = String::from_utf8(buf.into_inner().unwrap()).unwrap();
                        println!("Your new private key handle:\n{}", serialized);
                    }

                    println!(
                        "You key fingerprint: {}",
                        new_fido_key.private_key.pubkey.fingerprint().hash
                    );
                }
                Err(e) => {
                    error!("Key could not be registered. Server said: {}", e);
                    return Err(Box::new(e))?;
                }
            };
        }
        Ok(RusticaAgentAction::Register(mut config)) => {
            match config
                .server
                .register_key(&mut config.signatory, &config.attestation)
            {
                Ok(_) => println!("Key was successfully registered"),
                Err(e) => {
                    error!("Key could not be registered. Server said: {}", e);
                    return Err(Box::new(e))?;
                }
            };
        }
        // Immediate operation: Immediately fetch a new certificate from the
        // server and optionally write it to a file. This is generally used
        // for debugging or in scripts where passing a certificate and key
        // file is easier than using an SSH agent.
        Ok(RusticaAgentAction::Immediate(mut config)) => {
            match config
                .server
                .refresh_certificate_async(&mut config.signatory, &config.certificate_options)
                .await
            {
                Ok(x) => {
                    let cert = Certificate::from_string(&x.cert)?;

                    if let Some(out_file) = config.out {
                        let mut out = File::create(out_file)?;
                        out.write_all(cert.to_string().as_bytes())?;
                    } else {
                        println!("{:#}", &cert);
                    }
                }
                Err(e) => return Err(Box::new(e))?,
            };
        }
        // Normal operation: Starts RusticaAgent as an SSHAgent and waits to answer
        // requests from SSH clients.
        Ok(RusticaAgentAction::Run(config)) => {
            println!("Starting Rustica Agent");
            println!("Access Fingerprint: {}", config.pubkey.fingerprint().hash);
            println!(
                "SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;",
                config.socket_path
            );

            let (_, shutdown_receiver) = channel(1);
            Agent::run_with_termination_channel(
                config.handler,
                config.socket_path,
                Some(shutdown_receiver),
            )
            .await;
        }
        Err(config::ConfigurationError::NoMode) => (),
        Err(e) => println!("Error: {:?}", e),
    };

    Ok(())
}
