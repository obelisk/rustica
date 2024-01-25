use super::error::RefreshError;
use crate::RusticaServer;

use super::{AuthorizedSignerKeysRequest, AuthorizedSignerKey};

impl RusticaServer {
    pub async fn get_all_signer_keys(
        &self,
    ) -> Result<Vec<AuthorizedSignerKey>, RefreshError> {
        let request = AuthorizedSignerKeysRequest{};
        let request = tonic::Request::new(request);

        let mut client = super::get_rustica_client(&self).await?;

        let response = client.authorized_signer_keys(request).await?;
        let response = response.into_inner();

        Ok(response.signer_keys)
    }
}
