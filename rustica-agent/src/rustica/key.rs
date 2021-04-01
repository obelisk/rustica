use super::error::{RefreshError};
use super::{RegisterKeyRequest, RusticaServer, Signatory};

use tokio::runtime::Runtime;

pub mod rustica {
    tonic::include_proto!("rustica");
}

#[derive(Debug)]
pub struct KeyConfig {
    pub certificate: Vec<u8>,
    pub intermediate: Vec<u8>,
}

pub async fn register_key_async(server: &RusticaServer, mut signatory: &mut Signatory, key: &KeyConfig) -> Result<(), RefreshError> {
    let (mut client, challenge) = super::complete_rustica_challenge(&server, &mut signatory).await.unwrap();

    let request = tonic::Request::new(RegisterKeyRequest {
        certificate: key.certificate.clone(),
        intermediate: key.intermediate.clone(),
        challenge: Some(challenge),
    });

    client.register_key(request).await?;
    Ok(())
}


pub fn register_key(server: &RusticaServer, mut signatory: &mut Signatory, key: &KeyConfig) -> Result<(), RefreshError> {
    Runtime::new().unwrap().block_on(async {
        register_key_async(server, &mut signatory, key).await
    })
}