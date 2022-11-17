use super::error::RefreshError;
use super::{RegisterKeyRequest, RegisterU2fKeyRequest, RusticaServer, Signatory};

pub mod rustica {
    tonic::include_proto!("rustica");
}

#[derive(Debug)]
pub struct PIVAttestation {
    pub certificate: Vec<u8>,
    pub intermediate: Vec<u8>,
}

#[derive(Debug)]
pub struct U2FAttestation {
    pub auth_data: Vec<u8>,
    pub auth_data_sig: Vec<u8>,
    pub intermediate: Vec<u8>,
    pub challenge: Vec<u8>,
    pub alg: i32,
}

impl RusticaServer {
    pub async fn register_key_async(
        &self,
        signatory: &mut Signatory,
        attestation: &PIVAttestation,
    ) -> Result<(), RefreshError> {
        let (mut client, challenge) = super::complete_rustica_challenge(self, signatory)
            .await
            .unwrap();

        let request = RegisterKeyRequest {
            certificate: attestation.certificate.clone(),
            intermediate: attestation.intermediate.clone(),
            challenge: Some(challenge),
        };

        let request = tonic::Request::new(request);

        client.register_key(request).await?;
        Ok(())
    }

    pub fn register_key(
        &self,
        signatory: &mut Signatory,
        key: &PIVAttestation,
    ) -> Result<(), RefreshError> {
        self.handle
            .block_on(async { self.register_key_async(signatory, key).await })
    }

    pub async fn register_u2f_key_async(
        &self,
        signatory: &mut Signatory,
        application: &str,
        attestation: &U2FAttestation,
    ) -> Result<(), RefreshError> {
        let (mut client, challenge) = super::complete_rustica_challenge(self, signatory)
            .await
            .unwrap();

        let request = RegisterU2fKeyRequest {
            auth_data: attestation.auth_data.clone(),
            auth_data_signature: attestation.auth_data_sig.clone(),
            sk_application: application.as_bytes().to_vec(),
            u2f_challenge: attestation.challenge.clone(),
            intermediate: attestation.intermediate.clone(),
            alg: attestation.alg,
            challenge: Some(challenge),
        };

        let request = tonic::Request::new(request);

        client.register_u2f_key(request).await?;
        Ok(())
    }

    pub fn register_u2f_key(
        &self,
        signatory: &mut Signatory,
        application: &str,
        key: &U2FAttestation,
    ) -> Result<(), RefreshError> {
        self.handle.block_on(async {
            self.register_u2f_key_async(signatory, application, key)
                .await
        })
    }
}
