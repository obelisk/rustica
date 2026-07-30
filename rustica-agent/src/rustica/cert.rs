use super::error::{RefreshError, ServerError};
use super::{CertificateRequest, RusticaCert, Signatory};
use crate::{CertificateConfig, MtlsCredentials, RusticaServer};
use sshcerts::Certificate;
use tokio::runtime::Handle;

use std::collections::HashMap;
use std::time::SystemTime;

impl RusticaServer {
    /// CSR for our existing mTLS keypair, so renewal doesn't need a new key.
    /// Empty on failure, which makes the server fall back to generating one.
    fn mtls_renewal_csr(&self) -> Vec<u8> {
        let key_pair = match rcgen::KeyPair::from_pem(&self.mtls_key) {
            Ok(key_pair) => key_pair,
            Err(e) => {
                warn!("Could not parse our mTLS key to build a renewal CSR: {e}");
                return vec![];
            }
        };

        // The server overwrites subject and validity, so no point setting them here.
        let mut params = rcgen::CertificateParams::new(vec![]);
        params.alg = key_pair.algorithm();
        params.key_pair = Some(key_pair);

        match rcgen::Certificate::from_params(params).and_then(|c| c.serialize_request_der()) {
            Ok(csr) => csr,
            Err(e) => {
                warn!("Could not generate an mTLS renewal CSR: {e}");
                vec![]
            }
        }
    }

    pub async fn refresh_certificate_async(
        &self,
        signatory: &Signatory,
        options: &CertificateConfig,
        notification_function: &Option<Box<dyn Fn() + Send + Sync>>,
    ) -> Result<(RusticaCert, Option<MtlsCredentials>), RefreshError> {
        let (mut client, challenge) =
            super::complete_rustica_challenge(self, signatory, notification_function).await?;

        let current_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(ts) => ts.as_secs(),
            Err(_e) => 0xFFFFFFFFFFFFFFFF,
        };

        let request = tonic::Request::new(CertificateRequest {
            cert_type: options.cert_type as u32,
            key_id: options.authority.clone(),
            critical_options: HashMap::new(),
            extensions: Certificate::standard_extensions(),
            servers: options.hosts.clone(),
            principals: options.principals.clone(),
            valid_before: current_timestamp + options.duration,
            valid_after: current_timestamp,
            challenge: Some(challenge),
            mtls_csr: self.mtls_renewal_csr(),
        });

        let response = client.certificate(request).await?;
        let response = response.into_inner();

        if response.error_code != 0 {
            return Err(RefreshError::RusticaServerError(ServerError {
                code: response.error_code,
                message: response.error,
            }));
        }

        // If there is a certificate, then create a new MtlsCredentials struct
        // and return it. When the server renewed from our CSR it only returns
        // the certificate, which is why we only check the certificate here.
        let mtls_credentials = if !response.new_client_certificate.is_empty() {
            Some(MtlsCredentials {
                certificate: response.new_client_certificate,
                key: response.new_client_key,
            })
        } else {
            None
        };

        Ok((
            RusticaCert {
                cert: response.certificate,
                comment: "JITC".to_string(),
            },
            mtls_credentials,
        ))
    }

    pub fn get_custom_certificate(
        &self,
        signatory: &mut Signatory,
        options: &CertificateConfig,
        handle: &Handle,
        notification_function: &Option<Box<dyn Fn() + Send + Sync>>,
    ) -> Result<(RusticaCert, Option<MtlsCredentials>), RefreshError> {
        handle.block_on(async {
            self.refresh_certificate_async(signatory, options, notification_function)
                .await
        })
    }
}
