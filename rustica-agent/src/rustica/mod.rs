pub mod cert;
pub mod error;
pub mod key;

use std::time::Duration;

pub use error::RefreshError;

pub use rustica_proto::rustica_client::RusticaClient;
pub use rustica_proto::{
    CertificateRequest, CertificateResponse, Challenge, ChallengeRequest, RegisterKeyRequest,
    RegisterU2fKeyRequest,
};

use sshcerts::ssh::Certificate as SSHCertificate;

use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use crate::{RusticaServer, Signatory};

pub mod rustica_proto {
    tonic::include_proto!("rustica");
}

pub struct RusticaCert {
    pub cert: String,
    pub comment: String,
}

pub async fn complete_rustica_challenge(
    server: &RusticaServer,
    signatory: &mut Signatory,
) -> Result<(RusticaClient<tonic::transport::Channel>, Challenge), RefreshError> {
    let ssh_pubkey = match signatory {
        Signatory::Yubikey(signer) => {
            signer.yk.reconnect()?;
            match signer.yk.ssh_cert_fetch_pubkey(&signer.slot) {
                Ok(pkey) => pkey,
                Err(_) => return Err(RefreshError::SigningError),
            }
        }
        Signatory::Direct(ref privkey) => privkey.pubkey.clone(),
    };

    let encoded_key = format!("{}", ssh_pubkey);
    debug!(
        "Requesting cert for key with fingerprint: {}",
        ssh_pubkey.fingerprint()
    );
    let request = tonic::Request::new(ChallengeRequest {
        pubkey: encoded_key.to_string(),
    });

    let client_identity = Identity::from_pem(&server.mtls_cert, &server.mtls_key);

    let channel = match Channel::from_shared(server.address.clone()) {
        Ok(c) => c,
        Err(_) => return Err(RefreshError::InvalidUri),
    };

    let ca = Certificate::from_pem(&server.ca);
    let tls = ClientTlsConfig::new()
        .ca_certificate(ca)
        .identity(client_identity);
    let channel = channel
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .tls_config(tls)?
        .connect()
        .await?;

    let mut client = RusticaClient::new(channel);
    let response = client.challenge(request).await?;

    let response = response.into_inner();

    if response.no_signature_required {
        debug!("This server does not require signatures be sent, not resigning the certificate");
        return Ok((
            client,
            Challenge {
                pubkey: encoded_key.to_string(),
                challenge_time: response.time,
                challenge: response.challenge,
                challenge_signature: String::new(),
            },
        ));
    }

    debug!("{}", &response.challenge);

    let mut challenge_certificate =
        SSHCertificate::from_string(&response.challenge).map_err(|_| RefreshError::SigningError)?;
    challenge_certificate.signature_key = challenge_certificate.key.clone();

    let resigned_certificate = match signatory {
        Signatory::Yubikey(signer) => {
            let signature = signer
                .yk
                .ssh_cert_signer(&challenge_certificate.tbs_certificate(), &signer.slot)
                .map_err(|_| RefreshError::SigningError)?;
            challenge_certificate
                .add_signature(&signature)
                .map_err(|_| RefreshError::SigningError)?
        }
        Signatory::Direct(privkey) => challenge_certificate
            .sign(privkey)
            .map_err(|_| RefreshError::SigningError)?,
    };

    Ok((
        client,
        Challenge {
            pubkey: encoded_key.to_string(),
            challenge_time: response.time,
            challenge: format!("{}", resigned_certificate),
            challenge_signature: String::new(),
        },
    ))
}
