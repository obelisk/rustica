mod hsm;

use rustica::rustica_client::{RusticaClient};
use rustica::{  CertificateRequest,
                CertificateResponse,
                ChallengeRequest,
                ChallengeResponse,
            };

use rustica_sshkey::{CertType, Certificate, PublicKey as SSHPublicKey, PublicKeyKind as SSHPublicKeyKind};

use hsm::yubikey::{asn_cert_signer};

use ring::{hmac, rand};
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use std::collections::HashMap;
use std::time::SystemTime;
use tonic::{transport::Server, Request, Response, Status};
use yubikey_piv::key::{RetiredSlotId, SlotId};

pub mod rustica {
    tonic::include_proto!("rustica");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = RusticaClient::connect("http://[::1]:50051").await?;

    let key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOB7KkCJW8C5oGCPa932C4U0X4njwP5sq03pOxEGvqPB1dcDVh6EHCufKDU4aTT+83O3xf9KgeQPfT19JPr3AD0= obelisk@exclave";

    let ssh_pubkey = SSHPublicKey::from_string(key).unwrap();

    let request = tonic::Request::new(ChallengeRequest {
        pubkey: key.into(),
    });

    let response = client.challenge(request).await?;
    println!("RESPONSE={:?}", response);

    let response = response.into_inner();

    let challenge_signature = hex::encode(asn_cert_signer(&hex::decode(&response.challenge).unwrap()).unwrap());

    let request = tonic::Request::new(CertificateRequest {
        pubkey: key.to_string(),
        cert_type: 1,
        challenge_time: response.time,
        critical_options: HashMap::new(),
        extensions: HashMap::new(),
        servers: vec!["atheris".to_string()],
        users: vec!["obelisk".to_string()],
        valid_before: 0xFFFFFFFFFFFFFFFF,
        valid_after: 0x0,
        challenge: response.challenge,
        challenge_signature,
    });
    let mut client = RusticaClient::connect("http://[::1]:50051").await?;
    let response = client.certificate(request).await?;
    println!("RESPONSE={:?}", response);

    Ok(())
}