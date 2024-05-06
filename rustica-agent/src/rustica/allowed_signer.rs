use super::error::RefreshError;
use crate::RusticaServer;

use super::AllowedSignersRequest;

use std::io::Read;

use x509_parser::nom::AsBytes;
use tokio::runtime::Handle;

impl RusticaServer {
    pub async fn get_allowed_signers_async(
        &self,
    ) -> Result<String, RefreshError> {
        let request = AllowedSignersRequest{};
        let request = tonic::Request::new(request);

        let mut client = super::get_rustica_client(&self).await?;

        let response = client.allowed_signers(request).await?;
        let response = response.into_inner();

        // Decode zstd-compressed allowed_signers
        let mut allowed_signers_decoder = match zstd::stream::Decoder::new(response.compressed_allowed_signers.as_bytes()) {
            Ok(decoder) => decoder,
            Err(e) => {
                error!("Unable to initialize zstd decoder: {}", e.to_string());
                return Err(RefreshError::UnknownError);
            },
        };
        let mut allowed_signers = String::new();
        if let Err(e) = allowed_signers_decoder.read_to_string(&mut allowed_signers) {
            error!("Unable to decompress allowed signers: {}", e.to_string());
            return Err(RefreshError::BadAllowedSigners);
        }

        Ok(allowed_signers)
    }

    pub fn get_allowed_signers(
        &self,
        handle: &Handle,
    ) -> Result<String, RefreshError> {
        handle.block_on(async {
            self.get_allowed_signers_async()
                .await
        })
    }
}
