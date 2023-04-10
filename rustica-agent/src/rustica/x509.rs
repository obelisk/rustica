use yubikey::piv::SlotId;

use crate::{RusticaServer, Signatory};

use super::{RefreshError, get_rustica_client, X509CertificateRequest, error::ServerError};

impl RusticaServer {
    pub async fn refresh_x509_certificate_async(
        &self,
        signatory: &mut Signatory,
    ) -> Result<Vec<u8>, RefreshError> {
        let yk_signatory = match signatory {
            Signatory::Yubikey(yk) => yk,
            _ => return Err(RefreshError::UnsupportedMode)
        };

        // The CN will be ignored by the backend
        let csr = yk_signatory.yk.generate_csr(&yk_signatory.slot, "common_name").map_err(|_|
            RefreshError::ConfigurationError(format!("Could not generate CSR for slot {}. Is it provisioned?", yk_signatory.slot)))?;

        yk_signatory.yk.reconnect().unwrap();
        
        let attestation = yk_signatory.yk.fetch_attestation(&yk_signatory.slot).map_err(|e|
            RefreshError::ConfigurationError(format!("Could not generate attestation for slot {}. Is it attestable (not imported)? Error {e}", yk_signatory.slot)))?;

        yk_signatory.yk.reconnect().unwrap();

        let attestation_intermediate = yk_signatory.yk.fetch_certificate(&SlotId::Attestation).map_err(|_|
            RefreshError::ConfigurationError(format!("Could not fetch attestation intermediate. Have you manually removed it?")))?;

        let request = tonic::Request::new(X509CertificateRequest {
            // TODO: We need to start taking in key IDs
            key_id: String::new(),
            csr,
            attestation,
            attestation_intermediate
        });


        let mut client = get_rustica_client(self).await?;

        let response = client.x509_certificate(request).await?.into_inner();

        match response.error_code {
            0 => Ok(response.certificate),
            _ => Err(RefreshError::RusticaServerError(ServerError {
                code: response.error_code,
                message: response.error,
            }))
        }
    }
}