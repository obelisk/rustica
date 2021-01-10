use std::collections::HashMap;
use rustica_sshkey::{CertType, Certificate, PublicKey};

mod hsm;

use hsm::yubikey::{ssh_cert_fetch_pubkey, ssh_cert_signer};
use yubikey_piv::key::{RetiredSlotId, SlotId};

fn main() {
    //let user_key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLwHQFAZUIU+VjEsLqy04Vgbo1YUmRcZ6BybmeE3RMP6sl+ZAY4fsyGjEqIukcAFmXQ2LdGoooJsXm20KST7Vwc= obelisk@exclave.lan";
    //let host_key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN8FRyW3AnkGZmm2BBlxYULPS6hpKNyrFfsghF09wyyKpJ0GvXfwYDyDaBR+SAIybXxO3m9+LKJqQh5D91pD/a8= root@ubuntu";
    
    let user_ca_cert = match ssh_cert_fetch_pubkey(SlotId::Retired(RetiredSlotId::R11)) {
        Some(ca_cert) => ca_cert,
        None => {
            println!("Could not fetch public key from YubiKey. Is it configured?");
            return;
        },
    };

    // Eventually this will be stored in another slot but for now, it's fine to keep
    // the same for each
    let host_ca_cert = match ssh_cert_fetch_pubkey(SlotId::Retired(RetiredSlotId::R11)) {
        Some(ca_cert) => ca_cert,
        None => {
            println!("Could not fetch public key from YubiKey. Is it configured?");
            return;
        },
    };

    println!("User CA Pubkey: {}", user_ca_cert);
    println!("User CA Fingerprint (SHA256): {}\n", user_ca_cert.fingerprint().hash);

    println!("Host CA Pubkey: {}", host_ca_cert);
    println!("Host CA Fingerprint (SHA256): {}\n", host_ca_cert.fingerprint().hash);

    /*
    // Generate User Cert
    let pkey = PublicKey::from_string(user_key).unwrap();
    let mut extensions = HashMap::new();
    extensions.insert(String::from("permit-X11-forwarding"), String::from(""));
    extensions.insert(String::from("permit-agent-forwarding"), String::from(""));
    extensions.insert(String::from("permit-port-forwarding"), String::from(""));
    extensions.insert(String::from("permit-pty"), String::from(""));
    extensions.insert(String::from("permit-user-rc"), String::from(""));

    let user_cert = Certificate::new(
        pkey,
        CertType::User,
        0xFEFEFEFEFEFEFEFE,
        String::from("obelisk@exclave"),
        vec![String::from("obelisk")],
        0,
        0xFFFFFFFFFFFFFFFF,
        HashMap::new(),
        extensions,
        user_ca_cert.clone(),
        ssh_cert_signer,
    );
    
    match user_cert {
        Ok(cert) => {
            let serialized = format!("{}", cert);
            if let Err(e) = Certificate::from_string(&serialized) {
                println!("Couldn't deserialize certificate: {}", e);
                return;
            }
            println!("Certificate Generated!");
            println!("Info:");
            println!("{:#}", cert);
            println!("Export:");
            println!("{}", cert);
        },
        Err(e) => println!("Encountered an error while creating certificate: {}", e),
    }

    println!("");

    // Generate Host Cert
    let pkey = PublicKey::from_string(host_key).unwrap();
    
    let host_cert = Certificate::new(
        pkey,
        CertType::Host,
        0xFEFEFEFEFEFEFEFE,
        String::from("atheris"),
        vec![String::from("atheris")],
        0,
        0xFFFFFFFFFFFFFFFF,
        HashMap::new(),
        HashMap::new(),
        host_ca_cert.clone(),
        ssh_cert_signer,
    );

    match host_cert {
        Ok(cert) => {
            let serialized = format!("{}", cert);
            if let Err(e) = Certificate::from_string(&serialized) {
                println!("Couldn't deserialize certificate: {}", e);
                return;
            }
            println!("Certificate Generated!");
            println!("Info:");
            println!("{:#}", cert);
            println!("Export:");
            println!("{}", cert);
        },
        Err(e) => println!("Encountered an error while creating certificate: {}", e),
    }
    */
}