use async_trait::async_trait;

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    /// Pem encoded private key that will be used to sign new mTLS
    /// certificates for clients
    key: String,
    /// Defines how long newly issued certificates should be valid for
    certificate_validity_seconds: u64,
    /// Defines the length of the window before expiry where a new mTLS
    /// certificate will be automatically generated
    refresh_window_seconds: u64,
}

pub struct FileRenewer {
    config: Config,
}

impl Into<FileRenewer> for Config {
    fn into(self) -> FileRenewer {
        FileRenewer { config: self }
    }
}

#[async_trait]
impl super::Renewer for FileRenewer {
    fn renew(&self, certificate: &[u8]) -> rcgen::Certificate {
        todo!()
    }
}