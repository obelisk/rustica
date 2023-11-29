use super::protocol::Request;
use super::protocol::Response;

use super::error::HandleResult;

use async_trait::async_trait;
use sshcerts::PrivateKey;

#[async_trait]
pub trait SshAgentHandler: Send + Sync {
    async fn add_identity(&self, key: PrivateKey) -> HandleResult<Response>;
    async fn identities(&self) -> HandleResult<Response>;
    async fn sign_request(
        &self,
        pubkey: Vec<u8>,
        data: Vec<u8>,
        flags: u32,
    ) -> HandleResult<Response>;

    async fn handle_request(&self, request: Request) -> HandleResult<Response> {
        match request {
            Request::Identities => self.identities().await,
            Request::Sign {
                ref pubkey_blob,
                ref data,
                ref flags,
            } => {
                self.sign_request(pubkey_blob.clone(), data.clone(), *flags)
                    .await
            }
            Request::AddIdentity { private_key } => self.add_identity(private_key).await,
            Request::Unknown => Ok(Response::Failure),
        }
    }
}
