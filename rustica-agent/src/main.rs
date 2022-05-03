#[macro_use] extern crate log;

mod config;

use crate::config::RusticaAgentAction;
use rustica_agent::*;
use rustica_agent::rustica::key::{
    U2FAttestation
};

use sshcerts::{
    Certificate,
    fido::generate::generate_new_ssh_key,
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

            match prf.server.register_u2f_key(&mut signatory, &prf.app_name, &u2f_attestation) {
                Ok(_) => {
                    println!("Key was successfully registered!");

                    if let Some(out) = prf.out {
                        let mut out = File::create(out)?;
                        new_fido_key.private_key.write(&mut out)?;
                    } else {
                        let mut buf = std::io::BufWriter::new(Vec::new());
                        new_fido_key.private_key.write(&mut buf).unwrap();
                        let serialized = String::from_utf8(buf.into_inner().unwrap()).unwrap();
                        println!("Your new private key handle:\n{}", serialized);
                    }

                    println!("You key fingerprint: {}", new_fido_key.private_key.pubkey.fingerprint().hash);
                },
                Err(e) => {
                    error!("Key could not be registered. Server said: {}", e);
                    return Err(Box::new(e))
                },
            };
        },
        Ok(RusticaAgentAction::Register(mut config)) => {
            match config.server.register_key(&mut config.signatory, &config.attestation) {
                Ok(_) => println!("Key was successfully registered"),
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