use super::error::RefreshError;
use crate::RusticaServer;

use super::{SignerListRequest, SignerItem};

impl RusticaServer {
    pub async fn get_signer_list(
        &self,
    ) -> Result<Vec<SignerItem>, RefreshError> {
        let request = SignerListRequest{};
        let request = tonic::Request::new(request);

        let mut client = super::get_rustica_client(&self).await?;

        let response = client.signer_list(request).await?;
        let response = response.into_inner();

        Ok(response.signers)
    }
}
