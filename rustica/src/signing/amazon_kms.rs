use sshcerts::{Certificate, PublicKey, ssh::CertType};
use serde::Deserialize;

use aws_sdk_kms::{Blob, Client, Credentials, Region};
use aws_sdk_kms::model::SigningAlgorithmSpec;
use aws_types::credentials::future;
use aws_types::credentials::{ProvideCredentials};

use super::SigningError;


/// Defines the configuration of the AmazonKMS signer
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// The AWS access key that can access the KMS keys
    aws_access_key_id: String,
    /// The secret corresponding to the AWS access key
    aws_secret_access_key: String,
    /// The region to be used
    aws_region: String,
    /// The KMS key id to use as the user key
    user_key_id: String,
    /// The signing algorithm to use. This should be ECDSA_SHA_256 and
    /// ECDSA_SHA_384 for a Nistp256 and Nistp384 respectively
    user_key_signing_algorithm: String,
    /// The signing algorithm to use. This should be ECDSA_SHA_256 and
    /// ECDSA_SHA_384 for a Nistp256 and Nistp384 respectively
    host_key_signing_algorithm: String,
    /// The KMS key id to use as the host key
    host_key_id: String,
}

/// Represents a fully configured AmazonKMS signer that when created with
/// `new()` prefetches the public portion of the user and host keys.
pub struct AmazonKMSSigner {
    /// The public portion of the key that will be used to sign user
    /// certificates
    user_public_key: PublicKey,
    /// The id to lookup the private portion of the user key in Amazon KMS
    user_key_id: String,
    /// User key signing algorithm. See config docs for more details.
    user_key_signing_algorithm: SigningAlgorithmSpec,
    /// The public portion of the key that will be used to sign host
    /// certificates
    host_public_key: PublicKey,
    /// The id to lookup the private portion of the user key in Amazon KMS
    host_key_id: String,
    /// Host key signing algorithm. See config docs for more details.
    host_key_signing_algorithm: SigningAlgorithmSpec,
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

impl AmazonKMSSigner {
    pub async fn new(config: Config) -> Result<Self, ()> {
        let aws_config = aws_config::from_env().region(Region::new(config.aws_region.clone())).credentials_provider(config.clone()).load().await;
        let client = Client::new(&aws_config);

        let user_public_key = client.get_public_key().key_id(&config.user_key_id).send().await.map_err(|_| ())?.public_key;
        let host_public_key = client.get_public_key().key_id(&config.host_key_id).send().await.map_err(|_| ())?.public_key;

        let (user_public_key, host_public_key) = match (user_public_key, host_public_key) {
            (Some(upk), Some(hpk)) => (upk, hpk),
            _ => return Err(()),
        };

        let user_public_key = sshcerts::x509::der_encoding_to_ssh_public_key(user_public_key.as_ref());
        let host_public_key = sshcerts::x509::der_encoding_to_ssh_public_key(host_public_key.as_ref());

        let (user_public_key, host_public_key) = match (user_public_key, host_public_key) {
            (Ok(upk), Ok(hpk)) => (upk, hpk),
            _ => return Err(()), // Likely the key was valid in KMS but of a type not supported by Rustica
        };

        let user_key_signing_algorithm = SigningAlgorithmSpec::from(config.user_key_signing_algorithm.as_str());
        let host_key_signing_algorithm = SigningAlgorithmSpec::from(config.host_key_signing_algorithm.as_str());

        if let SigningAlgorithmSpec::Unknown(_) = user_key_signing_algorithm {
            return Err(())
        }

        if let SigningAlgorithmSpec::Unknown(_) = host_key_signing_algorithm {
            return Err(())
        }

        Ok(Self {
            user_public_key,
            user_key_id: config.user_key_id,
            user_key_signing_algorithm,
            host_public_key,
            host_key_id: config.host_key_id,
            host_key_signing_algorithm,
            client,
        })
    }

    pub async fn sign_certificate(&self, cert: Certificate) -> Result<Certificate, SigningError> {
        let data = cert.tbs_certificate();
        let (key_id, key_algo) = match &cert.cert_type {
            CertType::User => (&self.user_key_id, &self.user_key_signing_algorithm),
            CertType::Host => (&self.host_key_id, &self.host_key_signing_algorithm),
        };
        let result = self.client.sign().key_id(key_id).signing_algorithm(key_algo.clone()).message(Blob::new(data)).send().await;

        let signature = match result {
            Ok(result) => result.signature.unwrap().into_inner(),
            Err(e) => return Err(SigningError::AccessError(e.to_string())),
        };

        cert.add_signature(&signature).map_err(|_| SigningError::SigningFailure)
    }

    pub fn get_signer_public_key(&self, cert_type: CertType) -> PublicKey {
        match cert_type {
            CertType::User => self.user_public_key.clone(),
            CertType::Host => self.host_public_key.clone(),
        }
    }
}