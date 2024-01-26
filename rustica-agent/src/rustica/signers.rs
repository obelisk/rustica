use super::error::RefreshError;
use crate::RusticaServer;

use super::AuthorizedSignerKeysRequest;

use std::io::Read;
use flate2::read::GzDecoder;

use x509_parser::nom::AsBytes;

impl RusticaServer {
    pub async fn get_all_signer_keys(
        &self,
    ) -> Result<String, RefreshError> {
        let request = AuthorizedSignerKeysRequest{};
        let request = tonic::Request::new(request);

        let mut client = super::get_rustica_client(&self).await?;

        let response = client.authorized_signer_keys(request).await?;
        let response = response.into_inner();

        // Decode Gzip compressed authorized signer keys
        let mut signer_keys_decoder = GzDecoder::new(response.compressed_signer_keys.as_bytes());
        let mut signer_keys = String::new();
        if let Err(e) = signer_keys_decoder.read_to_string(&mut signer_keys) {
            error!("Unable to decompress authorized signer keys: {}", e.to_string());
            return Err(RefreshError::BadAuthorizedSignerKeys);
        }

        Ok(signer_keys)
    }
}
