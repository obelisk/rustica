use super::error::{RefreshError, ServerError};
use super::{CertificateRequest, RusticaCert, Signatory};
use crate::{CertificateConfig, MtlsCredentials, RusticaServer};
use sshcerts::Certificate;
use tokio::runtime::Handle;

use std::collections::HashMap;
use std::time::SystemTime;

impl RusticaServer {
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
        // and return it. It's possible in the future the server will only
        // return the certificate which is why we only check the certificate.
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
