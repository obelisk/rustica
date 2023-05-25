use serde::Deserialize;

/// Defines the configuration of the AmazonKMS signer
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// The AWS access key that can access the KMS keys
    aws_access_key_id: String,
    /// The secret corresponding to the AWS access key
    aws_secret_access_key: String,
    /// The region to be used
    aws_region: String,
    /// The signing algorithm to use. This should be ECDSA_SHA_256 and
    /// ECDSA_SHA_384 for a Nistp256 and Nistp384 respectively
    key_signing_algorithm: String,
    /// The KMS key id to use as the key to sign new mTLS certificates with
    key_id: String,
}