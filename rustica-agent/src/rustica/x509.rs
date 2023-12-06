use tokio::runtime::Handle;
use yubikey::piv::SlotId;

use crate::{RusticaServer, Signatory};

use super::{error::ServerError, get_rustica_client, AttestedX509CertificateRequest, RefreshError};

impl RusticaServer {
    pub async fn refresh_attested_x509_certificate_async(
        &self,
        signatory: &mut Signatory,
    ) -> Result<Vec<u8>, RefreshError> {
        let (mut yk, slot) = match signatory {
            Signatory::Yubikey(yk) => (yk.yk.lock().await, yk.slot),
            _ => return Err(RefreshError::UnsupportedMode),
        };

        // The CN will be ignored by the backend
        let csr = yk.generate_csr(&slot, "common_name").map_err(|_| {
            RefreshError::ConfigurationError(format!(
                "Could not generate CSR for slot {}. Is it provisioned?",
                slot
            ))
        })?;

        yk.reconnect().unwrap();

        let attestation = yk.fetch_attestation(&slot).map_err(|e|
            RefreshError::ConfigurationError(format!("Could not generate attestation for slot {slot}. Is it attestable (not imported)? Error {e}")))?;

        yk.reconnect().unwrap();

        let attestation_intermediate =
            yk.fetch_certificate(&SlotId::Attestation).map_err(|_| {
                RefreshError::ConfigurationError(format!(
                    "Could not fetch attestation intermediate. Have you manually removed it?"
                ))
            })?;

        let request = tonic::Request::new(AttestedX509CertificateRequest {
            // TODO: We need to start taking in key IDs
            key_id: String::new(),
            csr,
            attestation,
            attestation_intermediate,
        });

        let mut client = get_rustica_client(self).await?;

        let response = client
            .attested_x509_certificate(request)
            .await?
            .into_inner();

        match response.error_code {
            0 => Ok(response.certificate),
            _ => Err(RefreshError::RusticaServerError(ServerError {
                code: response.error_code,
                message: response.error,
            })),
        }
    }

    pub fn refresh_x509_certificate(
        &self,
        signatory: &mut Signatory,
        handle: &Handle,
    ) -> Result<Vec<u8>, RefreshError> {
        handle.block_on(async {
            self.refresh_attested_x509_certificate_async(signatory)
                .await
        })
    }
}
