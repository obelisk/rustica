use sshcerts::{PublicKey, PrivateKey, ssh::CertType, ssh::SigningFunction};
use serde::Deserialize;

use aws_config::meta::region::RegionProviderChain;
use aws_types::credentials::future;
use aws_types::credentials::{CredentialsError, ProvideCredentials};
use aws_sdk_kms::Client;
use aws_sdk_kms::Credentials;

use tokio::runtime::Runtime;

#[derive(Clone, Deserialize, Debug)]
pub struct AmazonKMSSigner {
    aws_access_key_id: String,
    aws_secret_access_key: String,
    aws_region: String,
    user_key_id: String,
    host_key_id: String,
}

impl ProvideCredentials for AmazonKMSSigner {
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
    pub fn get_signer(&self, cert_type: CertType) -> SigningFunction {
        match cert_type {
            CertType::User => panic!("Convert to signing function for user key not implemented"),
            CertType::Host => panic!("Convert to signing function for host key not implemented"),
        }
    }

    pub async fn get_signer_public_key(&self, cert_type: CertType) -> PublicKey {
        let region_provider = RegionProviderChain::default_provider().or_else("us-west-2");
        let config = aws_config::from_env().region("us-west-2").credentials_provider(self.clone()).load().await;

        let client = Client::new(&config);

        let public_key = client.get_public_key().key_id(&self.user_key_id).send().await.unwrap().public_key.unwrap();

        let ssh_pubkey = sshcerts::x509::der_encoding_to_ssh_public_key(public_key.as_ref()).unwrap();

        match cert_type {
            CertType::User => ssh_pubkey,
            CertType::Host => ssh_pubkey,
        }
    }
}