use super::error::{RefreshError, ServerError};
use super::{CertificateRequest, RusticaCert, Signatory};
use crate::{CertificateConfig, MtlsCredentials, RusticaServer};
use sshcerts::Certificate;
use tokio::runtime::Handle;

use std::collections::HashMap;
use std::time::SystemTime;

impl RusticaServer {
    /// Builds a CSR for our existing mTLS keypair so a renewal can reuse that key.
    ///
    /// Returns an empty CSR if the cert isn't within `renewal_period` of expiry, or if the
    /// CSR can't be built. If we can't tell how close the cert is to expiry, we build a CSR
    /// anyway.
    fn mtls_renewal_csr(&self, renewal_period: u64) -> Vec<u8> {
        // Parse our mTLS cert and check whether its expiry is outside the renewal window.
        let not_near_expiry = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|now| {
                let (_, pem) = x509_parser::pem::parse_x509_pem(self.mtls_cert.as_bytes()).ok()?;
                let expiry = pem.parse_x509().ok()?.validity().not_after.timestamp() as u64;
                Some(now.as_secs().saturating_add(renewal_period) < expiry)
            })
            .unwrap_or(false);
        if not_near_expiry {
            return vec![];
        }

        // Parse our existing mTLS private key so the CSR is built for it, not a new one.
        let key_pair = match rcgen::KeyPair::from_pem(&self.mtls_key) {
            Ok(key_pair) => key_pair,
            Err(e) => {
                warn!("Could not parse our mTLS key to build a renewal CSR: {e}");
                return vec![];
            }
        };

        // The server overwrites subject and validity.
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
        mtls_csr_renewal_period: u64,
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
            mtls_csr: self.mtls_renewal_csr(mtls_csr_renewal_period),
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
        mtls_csr_renewal_period: u64,
    ) -> Result<(RusticaCert, Option<MtlsCredentials>), RefreshError> {
        handle.block_on(async {
            self.refresh_certificate_async(
                signatory,
                options,
                notification_function,
                mtls_csr_renewal_period,
            )
            .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::FromDer;

    // test_server's certificate expires in the year 4096 (rcgen's default), so whether
    // it counts as near expiry depends only on the renewal period a test passes in.
    // u64::MAX covers any expiry, 60 seconds covers none.
    const ALWAYS_RENEW: u64 = u64::MAX;
    const NEVER_RENEW: u64 = 60;

    /// A server holding a self signed mTLS certificate and its matching key.
    fn test_server() -> RusticaServer {
        let key_pair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mtls_key = key_pair.serialize_pem();

        let mut params = rcgen::CertificateParams::new(vec![]);
        params.alg = key_pair.algorithm();
        params.key_pair = Some(key_pair);
        let mtls_cert = rcgen::Certificate::from_params(params)
            .unwrap()
            .serialize_pem()
            .unwrap();

        RusticaServer {
            address: String::new(),
            ca_pem: String::new(),
            mtls_cert,
            mtls_key,
        }
    }

    fn cert_public_key(pem: &str) -> Vec<u8> {
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        pem.parse_x509()
            .unwrap()
            .tbs_certificate
            .subject_pki
            .raw
            .to_vec()
    }

    fn csr_public_key(der: &[u8]) -> Vec<u8> {
        let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(der)
            .expect("CSR should be parseable");
        csr.certification_request_info.subject_pki.raw.to_vec()
    }

    #[test]
    fn csr_carries_the_key_from_our_current_certificate() {
        let server = test_server();
        let csr = server.mtls_renewal_csr(ALWAYS_RENEW);

        assert!(!csr.is_empty());
        assert_eq!(csr_public_key(&csr), cert_public_key(&server.mtls_cert));
    }

    #[test]
    fn no_csr_when_certificate_is_not_near_expiry() {
        assert!(test_server().mtls_renewal_csr(NEVER_RENEW).is_empty());
    }
}
