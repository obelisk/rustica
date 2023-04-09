/// The AmazonKMS signer uses customer managed keys stored in AWS to handle
/// signing operations. It supports Ecdsa256 and Ecdsa384. Ecdsa521 is not
/// currently supported due to a lack of support in the Ring crypto
/// dependency. This signer is also an example of how to write a signing
/// module that is async. To use the AmazonKMS signer, the `amazon-kms`
/// feature must be enabled.

use sshcerts::{
    Certificate,
    PublicKey,
    ssh::CertType,
    utils::format_signature_for_ssh,
};
use tokio::runtime::Handle;

use super::{Signer, SignerConfig, SigningError};

use async_trait::async_trait;

use aws_sdk_kms::{Blob, Client, Credentials, Region};
use aws_sdk_kms::model::SigningAlgorithmSpec;
use aws_types::credentials::future;
use aws_types::credentials::{ProvideCredentials};

use serde::Deserialize;

use rcgen::{Certificate as X509Certificate, CertificateParams, IsCa, DnType, RcgenError};

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
    /// The signing algorithm to use. This should be ECDSA_SHA_256 and
    /// ECDSA_SHA_384 for a Nistp256 and Nistp384 respectively
    x509_key_signing_algorithm: String,
    /// The KMS key id to use as the host key
    x509_key_id: String,
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
    /// The id to lookup the private portion of the host key in Amazon KMS
    host_key_id: String,
    /// Host key signing algorithm. See config docs for more details.
    host_key_signing_algorithm: SigningAlgorithmSpec,
    /// The public portion of the key that will be used to sign X509
    /// certificates
    x509_certificate: X509Certificate,
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

    fn sign(&self, msg :&[u8]) -> Result<Vec<u8>, RcgenError> {
        let key_id = self.x509_key_id.clone();
        let key_algo = self.x509_key_signing_algorithm.clone();
        let data = msg.to_owned();
        let client = self.client.clone();
        let handle = self.handle.clone();

        // This is really ugly but I don't have a better solution right now
        // as RCGen does not provide an async signer so we have to wait for
        // this to return. Spawning threads is expensive so there is probably
        // a better way to do this with threadpooling but for now, at the scales
        // this will be used for I don't think it'll be an issue
        let signature = std::thread::spawn(move || {
            handle.block_on( async {
                client.sign().key_id(key_id).signing_algorithm(key_algo).message(Blob::new(data)).send().await
            }
        )}).join().unwrap();

        // Amazon container type
        let signature = match signature {
            Ok(result) => result.signature,
            Err(_) => return Err(RcgenError::RemoteKeyError),
        };

        // Was the signature successfully created
        signature.map(|x| x.into_inner()).ok_or(RcgenError::RemoteKeyError)
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        match self.x509_key_signing_algorithm {
            SigningAlgorithmSpec::EcdsaSha384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            _ => &rcgen::PKCS_ECDSA_P256_SHA256,
        }
    }
}

#[async_trait]
impl SignerConfig for Config {
    async fn into_signer(self) -> Result<Box<dyn Signer + Send + Sync>, SigningError> {
        let aws_config = aws_config::from_env().region(Region::new(self.aws_region.clone())).credentials_provider(self.clone()).load().await;
        let client = Client::new(&aws_config);

        let user_public_key = client.get_public_key().key_id(&self.user_key_id).send().await.map_err(|_| SigningError::AccessError("Could not access user key".to_owned()))?.public_key;
        let host_public_key = client.get_public_key().key_id(&self.host_key_id).send().await.map_err(|_| SigningError::AccessError("Could not access host key".to_owned()))?.public_key;
        let x509_public_key = client.get_public_key().key_id(&self.x509_key_id).send().await.map_err(|_| SigningError::AccessError("Could not access x509 key".to_owned()))?.public_key;

        let (user_public_key, host_public_key, x509_public_key) = match (user_public_key, host_public_key, x509_public_key) {
            (Some(upk), Some(hpk), Some(x509)) => (upk, hpk, x509),
            _ => return Err(SigningError::AccessError("One or more keys was not returned correctly or at all".to_owned())),
        };

        let user_public_key = sshcerts::x509::der_encoding_to_ssh_public_key(user_public_key.as_ref());
        let host_public_key = sshcerts::x509::der_encoding_to_ssh_public_key(host_public_key.as_ref());

        let (user_public_key, host_public_key) = match (user_public_key, host_public_key) {
            (Ok(upk), Ok(hpk)) => (upk, hpk),
            _ => return Err(SigningError::AccessError("Key is not of a Rustica compatible type".to_owned())), // Likely the key was valid in KMS but of a type not supported by Rustica
        };

        let user_key_signing_algorithm = SigningAlgorithmSpec::from(self.user_key_signing_algorithm.as_str());
        let host_key_signing_algorithm = SigningAlgorithmSpec::from(self.host_key_signing_algorithm.as_str());
        let x509_key_signing_algorithm = SigningAlgorithmSpec::from(self.x509_key_signing_algorithm.as_str());

        if let SigningAlgorithmSpec::Unknown(_) = user_key_signing_algorithm {
            return Err(SigningError::AccessError("Unknown algorithm for user key".to_owned()))
        }

        if let SigningAlgorithmSpec::Unknown(_) = host_key_signing_algorithm {
            return Err(SigningError::AccessError("Unknown algorithm for host key".to_owned()))
        }

        if let SigningAlgorithmSpec::Unknown(_) = x509_key_signing_algorithm {
            return Err(SigningError::AccessError("Unknown algorithm for X509 key".to_owned()))
        }


        let mut ca_params = CertificateParams::new(vec![]);
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "Rustica");


        // This slicing is a bit of an ugly hack that means we don't have to
        // implement or import more DER parsing crates. Since DER encoding
        // will always have the same length header for given key types, we can
        // slice it off and get the compatible format we need (in this case, it
        // is dictated by ring.)
        let x509_public_key = match &x509_key_signing_algorithm {
            SigningAlgorithmSpec::EcdsaSha256 => {
                ca_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
                x509_public_key.as_ref()[25..].to_vec()
            },
            SigningAlgorithmSpec::EcdsaSha384 => {
                ca_params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
                x509_public_key.as_ref()[23..].to_vec()
            },
            _ => return Err(SigningError::AccessError("Unsupported algorithm for X509 key".to_owned())),
        };

        let x509_remote_signer = KmsRcgenRemoteSigner {
            x509_key_id: self.x509_key_id,
            x509_key_signing_algorithm,
            x509_public_key,
            client: Client::new(&aws_config),
            handle: Handle::current(),
        };

        let kp = match rcgen::KeyPair::from_remote(Box::new(x509_remote_signer)) {
            Ok(kp) => kp,
            Err(_) => return Err(SigningError::AccessError("Could not create remote signer for X509 key".to_owned()))
        };

        ca_params.key_pair = Some(kp);
        let x509_certificate = X509Certificate::from_params(ca_params).unwrap();
         

        Ok(Box::new(AmazonKMSSigner {
            user_public_key,
            user_key_id: self.user_key_id,
            user_key_signing_algorithm,
            host_public_key,
            host_key_id: self.host_key_id,
            host_key_signing_algorithm,
            x509_certificate,
            client,
        }))
    }
}

#[async_trait]
impl Signer for AmazonKMSSigner {
    async fn sign(&self, cert: Certificate) -> Result<Certificate, SigningError> {
        let data = cert.tbs_certificate();
        let (pubkey, key_id, key_algo) = match &cert.cert_type {
            CertType::User => (&self.user_public_key, &self.user_key_id, &self.user_key_signing_algorithm),
            CertType::Host => (&self.host_public_key, &self.host_key_id, &self.host_key_signing_algorithm),
        };
        let result = self.client.sign().key_id(key_id).signing_algorithm(key_algo.clone()).message(Blob::new(data)).send().await;

        // Amazon container type
        let signature = match result {
            Ok(result) => result.signature,
            Err(e) => return Err(SigningError::AccessError(e.to_string())),
        };

        // Was the signature successfully created
        let signature = match signature {
            Some(sig) => sig.into_inner(),
            None => return Err(SigningError::AccessError("No signature returned".to_owned())),
        };

        // Convert to SSH styled signature
        let signature = match format_signature_for_ssh(pubkey, &signature) {
            Some(s) => s,
            None => return Err(SigningError::ParsingError),
        };

        cert.add_signature(&signature).map_err(|_| SigningError::SigningFailure)
    }

    fn get_signer_public_key(&self, cert_type: CertType) -> PublicKey {
        match cert_type {
            CertType::User => self.user_public_key.clone(),
            CertType::Host => self.host_public_key.clone(),
        }
    }

    fn get_x509_certificate_authority(&self) -> &X509Certificate {
        return &self.x509_certificate
    }
}