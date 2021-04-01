use super::error::{RefreshError, ServerError};
use super::{CertificateRequest, RusticaServer, Signatory, RusticaCert};

use sshcerts::ssh::{CertType, CriticalOptions, Extensions};

use std::collections::HashMap;
use std::time::SystemTime;
use tokio::runtime::Runtime;


#[derive(Debug)]
pub struct CertificateConfig {
    pub principals: Vec<String>,
    pub hosts: Vec<String>,
    pub cert_type: CertType,
    pub duration: u64,
}

pub async fn refresh_certificate_async(server: &RusticaServer, mut signatory: &mut Signatory, options: &CertificateConfig) -> Result<RusticaCert, RefreshError> {
    let (mut client, challenge) = super::complete_rustica_challenge(&server, &mut signatory).await.unwrap();

    let current_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(ts) => ts.as_secs(),
        Err(_e) => 0xFFFFFFFFFFFFFFFF,
    };

    let request = tonic::Request::new(CertificateRequest {
        cert_type: options.cert_type as u32,
        key_id: String::from(""),           // Rustica Server ignores this field
        critical_options: HashMap::from(CriticalOptions::None),
        extensions: HashMap::from(Extensions::Standard),
        servers: options.hosts.clone(),
        principals: options.principals.clone(),
        valid_before: current_timestamp + options.duration,
        valid_after: 0x0,
        challenge: Some(challenge),
    });

    let response = client.certificate(request).await?;
    let response = response.into_inner();

    if response.error_code != 0 {
        return Err(RefreshError::RusticaServerError(
            ServerError {
                code: response.error_code,
                message: response.error,
            }))
    }

    Ok(RusticaCert {
        cert: response.certificate,
        comment: "JITC".to_string(),
    })
}

pub fn get_custom_certificate(server: &RusticaServer, signatory: &mut Signatory, options: &CertificateConfig) -> Result<RusticaCert, RefreshError> {
    Runtime::new().unwrap().block_on(async {
        refresh_certificate_async(server, signatory, options).await
    })
}
