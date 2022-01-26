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

impl RusticaServer {
    pub async fn register_key_async(&self, signatory: &mut Signatory, key: &KeyConfig) -> Result<(), RefreshError> {
        let (mut client, challenge) = super::complete_rustica_challenge(self, signatory).await.unwrap();

        let request = tonic::Request::new(RegisterKeyRequest {
            certificate: key.certificate.clone(),
            intermediate: key.intermediate.clone(),
            challenge: Some(challenge),
        });

        client.register_key(request).await?;
        Ok(())
    }


    pub fn register_key(&self, signatory: &mut Signatory, key: &KeyConfig) -> Result<(), RefreshError> {
        Runtime::new().unwrap().block_on(async {
            self.register_key_async(signatory, key).await
        })
    }
}