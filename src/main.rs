use std::collections::HashMap;
use rustica_sshkey::{Certificate, PublicKey};

mod hsm;

use hsm::yubikey;

fn test_pubkey() -> Option<Vec<u8>> {
    let encoded_key = match yubikey::fetch_pubkey() {
        //Ok(hsm::PublicKeyInfo::Rsa { pubkey, .. }) => pubkey,
        Ok(hsm::PublicKeyInfo::EcP256(pubkey)) => {
            let key_type = "ecdsa-sha2-nistp256";
            let identifier = "nistp256";

            let mut encoded: Vec<u8> = (key_type.len() as u32).to_be_bytes().to_vec();
            encoded.extend_from_slice(key_type.as_bytes());

            encoded.extend_from_slice(&(identifier.len() as u32).to_be_bytes());
            encoded.extend_from_slice(identifier.as_bytes());

            let pubkey = pubkey.as_bytes();
            encoded.extend_from_slice(&(pubkey.len() as u32).to_be_bytes());
            encoded.extend_from_slice(pubkey);

            encoded
        },
        //Ok(hsm::PublicKeyInfo::EcP384(pubkey)) => pubkey.as_bytes().to_vec(),
        _ =>  return None,
    };

    Some(encoded_key)
}

fn asn_der_to_r_s(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.len() < 4 ||  buf[0] != 0x30 {
        println!("Bad formatting at the start");
        return None;
    }
    let buf = &buf[3..];
    let r_length = buf[0] as usize;
    if buf.len() < r_length + 2 {
        println!("Bad r len");
        return None;
    }
    let buf = &buf[1..];
    let r = &buf[..r_length];
    let buf = &buf[r_length..];
    if buf[0] != 0x2 {
        println!("Bad Marker after r, found: {:x}", buf[0]);
        return None
    }
    let s_length = buf[1] as usize;
    let s = &buf[2..];

    if s.len() != s_length {
        println!("Bad s len");
        return None
    }

    Some((r, s))
}

fn test_signer(buf: &[u8]) -> Option<Vec<u8>> {
    match yubikey::sign_data(&buf) {
        Ok(signature) => {
            let sig_type = "ecdsa-sha2-nistp256";
            let mut encoded: Vec<u8> = (sig_type.len() as u32).to_be_bytes().to_vec();
            encoded.extend_from_slice(sig_type.as_bytes());
            let (r,s) = match asn_der_to_r_s(&signature) {
                Some((r,s)) => (r, s),
                None => return None,
            };
            let mut sig_encoding = vec![];
            sig_encoding.extend_from_slice(&(r.len() as u32).to_be_bytes());
            sig_encoding.extend_from_slice(r);
            sig_encoding.extend_from_slice(&(s.len() as u32).to_be_bytes());
            sig_encoding.extend_from_slice(s);

            encoded.extend_from_slice(&(sig_encoding.len() as u32).to_be_bytes());
            encoded.extend(sig_encoding);

            Some(encoded)
        },
        Err(e) => {
            println!("Error: {:?}", e);
            None
        },
    }
}

fn main() {
    let test_key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLwHQFAZUIU+VjEsLqy04Vgbo1YUmRcZ6BybmeE3RMP6sl+ZAY4fsyGjEqIukcAFmXQ2LdGoooJsXm20KST7Vwc= obelisk@exclave.lan";

    let pkey = PublicKey::from_string(test_key).unwrap();
    let mut extensions = HashMap::new();
    extensions.insert(String::from("permit-X11-forwarding"), String::from(""));
    extensions.insert(String::from("permit-agent-forwarding"), String::from(""));
    extensions.insert(String::from("permit-port-forwarding"), String::from(""));
    extensions.insert(String::from("permit-pty"), String::from(""));
    extensions.insert(String::from("permit-user-rc"), String::from(""));

    let cert = Certificate::new(
        pkey,
        0xFEFEFEFEFEFEFEFE,
        String::from("obelisk@exclave"),
        vec![String::from("obelisk2")],
        0,
        0xFFFFFFFFFFFFFFFF,
        HashMap::new(),
        extensions,
        test_pubkey,
        test_signer,
    );
    
    match cert {
        Ok(cert) => println!("{}", cert),
        Err(e) => println!("Encountered an error while creating certificate: {}", e),
    }
}