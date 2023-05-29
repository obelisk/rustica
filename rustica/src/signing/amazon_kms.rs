use std::time::Duration;

use aws_config::TimeoutConfig;
/// The AmazonKMS signer uses customer managed keys stored in AWS to handle
/// signing operations. It supports Ecdsa256 and Ecdsa384. Ecdsa521 is not
/// currently supported due to a lack of support in the Ring crypto
/// dependency. This signer is also an example of how to write a signing
/// module that is async. To use the AmazonKMS signer, the `amazon-kms`
/// feature must be enabled.
use sshcerts::{ssh::CertType, utils::format_signature_for_ssh, Certificate, PublicKey};
use tokio::runtime::Handle;
use tokio::task;

use super::{Signer, SignerConfig, SigningError};

use async_trait::async_trait;

use aws_sdk_kms::model::SigningAlgorithmSpec;
use aws_sdk_kms::{Blob, Client, Credentials, Region};
use aws_types::credentials::future;
use aws_types::credentials::ProvideCredentials;

use serde::Deserialize;

use rcgen::{Certificate as X509Certificate, CertificateParams, DnType, IsCa, RcgenError};

#[derive(Clone, Debug, Deserialize)]
pub struct KmsKeyDefinition {
    id: String,
    algorithm: String,
    common_name: Option<String>,
}

/// Defines the configuration of the AmazonKMS signer
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// The AWS access key that can access the KMS keys
    aws_access_key_id: String,
    /// The secret corresponding to the AWS access key
    aws_secret_access_key: String,
    /// The region to be used
    aws_region: String,

    // The key to be used to sign user SSH certificates
    user_key: Option<KmsKeyDefinition>,

    // The key to be used to sign host SSH certificates
    host_key: Option<KmsKeyDefinition>,

    // The key to be used to sign attested X509 certificate requests
    x509_key: Option<KmsKeyDefinition>,

    // The key to be used to issue new client mTLS certificates
    client_certificate_authority_key: Option<KmsKeyDefinition>,
}

/// Defines the information needed for an AmazonKMS backed SSH key
struct SshKmsKey {
    /// The public portion of the key that will be used to sign certificates
    public_key: PublicKey,
    /// The id to lookup the private portion of the key in Amazon KMS
    key_id: String,
    /// Key signing algorithm. See config docs for more details.
    key_signing_algorithm: SigningAlgorithmSpec,
}

struct SshKeys {
    user: SshKmsKey,
    host: SshKmsKey,
}

/// Represents a fully configured AmazonKMS signer that when created with
/// `new()` prefetches the public portion of the user and host keys.
pub struct AmazonKMSSigner {
    /// The configured SSH keys that will be used to sign SSH certificate
    /// requests for users and hosts
    ssh_keys: Option<SshKeys>,
    /// The public portion of the key that will be used to sign X509
    /// certificates but also contains the remote signer.
    x509_certificate: Option<X509Certificate>,
    /// The public portion of the key that will be used to sign client
    /// certificates used to connect to rustica
    client_certificate_authority: Option<X509Certificate>,
    /// A configured KMS client to use for signing and public key look up
    /// operations. Rustica does not instantiate keys meaning it does not
    /// need permission to create keys.
    client: Client,
}

impl ProvideCredentials for Config {
    fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        future::ProvideCredentials::ready(Ok(Credentials::new(
            self.aws_access_key_id.clone(),
            self.aws_secret_access_key.clone(),
            None,
            None,
            "AmazonKMSSigner",
        )))
    }
}

pub struct KmsRcgenRemoteSigner {
    x509_public_key: Vec<u8>,
    /// The id to lookup the private portion of the X509 key in Amazon KMS
    x509_key_id: String,
    /// X509 key signing algorithm. See config docs for more details.
    x509_key_signing_algorithm: SigningAlgorithmSpec,
    /// A configured KMS client to use for signing.
    client: Client,
    /// A handle to a tokio runtime we can use to make the KMS call
    handle: Handle,
}

impl rcgen::RemoteKeyPair for KmsRcgenRemoteSigner {
    fn public_key(&self) -> &[u8] {
        &self.x509_public_key
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, RcgenError> {
        let key_id = self.x509_key_id.clone();
        let key_algo = self.x509_key_signing_algorithm.clone();
        let data = msg.to_owned();
        let client = self.client.clone();
        let handle = self.handle.clone();

        // This is really ugly but I don't have a better solution right now
        // as RCGen does not provide an async signer so we have to wait for
        // this to return. block_in_place is expensive so there is probably
        // a better way to do this but for now, at the scale this will be
        // used for I don't think it'll be an issue
        let signature = task::block_in_place(move || {
            handle.block_on(async move {
                client
                    .sign()
                    .key_id(key_id)
                    .signing_algorithm(key_algo)
                    .message(Blob::new(data))
                    .send()
                    .await
            })
        });

        // Amazon container type
        let signature = match signature {
            Ok(result) => result.signature,
            Err(_) => return Err(RcgenError::RemoteKeyError),
        };

        // Was the signature successfully created
        signature
            .map(|x| x.into_inner())
            .ok_or(RcgenError::RemoteKeyError)
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        match self.x509_key_signing_algorithm {
            SigningAlgorithmSpec::EcdsaSha384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            _ => &rcgen::PKCS_ECDSA_P256_SHA256,
        }
    }
}

async fn ssh_key_from_kms(
    client: &Client,
    key_id: &str,
    key_alg: &str,
) -> Result<SshKmsKey, SigningError> {
    let public_key = client
        .get_public_key()
        .key_id(key_id)
        .send()
        .await
        .map_err(|_| SigningError::AccessError(format!("Could not access key {key_id}")))?
        .public_key;
    let public_key = public_key.ok_or(SigningError::AccessError(format!(
        "Could not access key_id {key_id}"
    )))?;

    let public_key =
        sshcerts::x509::der_encoding_to_ssh_public_key(public_key.as_ref()).map_err(|_| {
            SigningError::AccessError(format!("Key is not of a Rustica compatible type {key_id}"))
        })?;

    let key_signing_algorithm = SigningAlgorithmSpec::from(key_alg);

    if let SigningAlgorithmSpec::Unknown(_) = key_signing_algorithm {
        return Err(SigningError::AccessError(
            "Unknown algorithm for user key".to_owned(),
        ));
    }

    Ok(SshKmsKey {
        public_key,
        key_id: key_id.to_owned(),
        key_signing_algorithm,
    })
}

async fn rcgen_certificate_from_kms(
    client: Client,
    common_name: &str,
    key_id: &str,
    key_alg: &str,
) -> Result<X509Certificate, SigningError> {
    let public_key = client
        .get_public_key()
        .key_id(key_id)
        .send()
        .await
        .map_err(|_| SigningError::AccessError(format!("Could not access key {key_id}")))?
        .public_key;
    let public_key = public_key.ok_or(SigningError::AccessError(
        "One or more keys were not returned correctly or at all".to_owned(),
    ))?;

    let signing_algorithm = SigningAlgorithmSpec::from(key_alg);

    let mut ca_params = CertificateParams::new(vec![]);
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, common_name);

    let public_key = match &signing_algorithm {
        SigningAlgorithmSpec::EcdsaSha256 => {
            ca_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
            public_key.as_ref()[25..].to_vec()
        }
        SigningAlgorithmSpec::EcdsaSha384 => {
            ca_params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
            public_key.as_ref()[23..].to_vec()
        }
        _ => {
            return Err(SigningError::AccessError(format!(
                "Unsupported algorithm for key {key_id}"
            )))
        }
    };

    let remote_signer = KmsRcgenRemoteSigner {
        x509_key_id: key_id.to_owned(),
        x509_key_signing_algorithm: signing_algorithm,
        x509_public_key: public_key,
        client,
        handle: Handle::current(),
    };

    let kp = match rcgen::KeyPair::from_remote(Box::new(remote_signer)) {
        Ok(kp) => kp,
        Err(_) => {
            return Err(SigningError::AccessError(format!(
                "Could not create remote signer for key {key_id}"
            )))
        }
    };

    ca_params.key_pair = Some(kp);
    X509Certificate::from_params(ca_params).map_err(|_| {
        SigningError::AccessError(format!("Could not create certificate for key {key_id}"))
    })
}

#[async_trait]
impl SignerConfig for Config {
    async fn into_signer(self) -> Result<Box<dyn Signer + Send + Sync>, SigningError> {
        let timeout_config =
            TimeoutConfig::new().with_api_call_timeout(Some(Duration::from_secs(3)));
        let aws_config = aws_config::from_env()
            .timeout_config(timeout_config)
            .region(Region::new(self.aws_region.clone()))
            .credentials_provider(self.clone())
            .load()
            .await;
        let client = Client::new(&aws_config);

        let ssh_keys = match (self.user_key, self.host_key) {
            (Some(user), Some(host)) => Some(SshKeys {
                user: ssh_key_from_kms(&client, &user.id, &user.algorithm).await?,
                host: ssh_key_from_kms(&client, &host.id, &host.algorithm).await?,
            }),
            (None, None) => None,
            _ => return Err(SigningError::SignerDoesNotAllRequiredSSHKeys),
        };

        let x509_certificate = match self.x509_key {
            Some(x509_key) => {
                Some(rcgen_certificate_from_kms(client.clone(), "Rustica", &x509_key.id, &x509_key.algorithm).await?)
            }
            _ => None,
        };

        let client_certificate_authority = match self.client_certificate_authority_key {
            Some(client_ca_authority) => {
                let common_name = client_ca_authority.common_name.unwrap_or("RusticaAccess".to_owned());
                Some(rcgen_certificate_from_kms(client.clone(), &common_name, &client_ca_authority.id, &client_ca_authority.algorithm).await?)
            }
            _ => None,
        };

        Ok(Box::new(AmazonKMSSigner {
            ssh_keys,
            x509_certificate,
            client_certificate_authority,
            client,
        }))
    }
}

#[async_trait]
impl Signer for AmazonKMSSigner {
    async fn sign(&self, cert: Certificate) -> Result<Certificate, SigningError> {
        let ssh_keys = self.ssh_keys.as_ref().ok_or(SigningError::SignerDoesNotHaveSSHKeys)?;
        let data = cert.tbs_certificate();
        let (pubkey, key_id, key_algo) = match &cert.cert_type {
            CertType::User => (
                &ssh_keys.user.public_key,
                &ssh_keys.user.key_id,
                &ssh_keys.user.key_signing_algorithm,
            ),
            CertType::Host => (
                &ssh_keys.host.public_key,
                &ssh_keys.host.key_id,
                &ssh_keys.host.key_signing_algorithm,
            ),
        };
        let result = self
            .client
            .sign()
            .key_id(key_id)
            .signing_algorithm(key_algo.clone())
            .message(Blob::new(data))
            .send()
            .await;

        // Amazon container type
        let signature = match result {
            Ok(result) => result.signature,
            Err(e) => return Err(SigningError::AccessError(e.to_string())),
        };

        // Was the signature successfully created
        let signature = match signature {
            Some(sig) => sig.into_inner(),
            None => {
                return Err(SigningError::AccessError(
                    "No signature returned".to_owned(),
                ))
            }
        };

        // Convert to SSH styled signature
        let signature = match format_signature_for_ssh(&pubkey, &signature) {
            Some(s) => s,
            None => return Err(SigningError::ParsingError),
        };

        cert.add_signature(&signature)
            .map_err(|_| SigningError::SigningFailure)
    }

    fn get_signer_public_key(&self, cert_type: CertType) -> Option<PublicKey> {
        let ssh_keys = self.ssh_keys.as_ref()?;
        match cert_type {
            CertType::User => Some(ssh_keys.user.public_key.clone()),
            CertType::Host => Some(ssh_keys.host.public_key.clone()),
        }
    }

    fn get_attested_x509_certificate_authority(&self) -> Option<&X509Certificate> {
        return self.x509_certificate.as_ref();
    }

    fn get_client_certificate_authority(&self) -> Option<&X509Certificate> {
        return self.client_certificate_authority.as_ref();
    }
}
