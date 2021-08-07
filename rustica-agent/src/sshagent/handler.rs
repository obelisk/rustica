use super::protocol::Request;
use super::protocol::Response;

use super::error::HandleResult;

use sshcerts::PrivateKey;

pub trait SshAgentHandler: Send + Sync {
	fn add_identity(&mut self, key: PrivateKey) -> HandleResult<Response>;
	fn identities(&mut self) -> HandleResult<Response>;
	fn sign_request(&mut self, pubkey: Vec<u8>, data: Vec<u8>, flags: u32) -> HandleResult<Response>;

	fn handle_request(&mut self, request: Request) -> HandleResult<Response> {
		match request {
			Request::RequestIdentities => {
				self.identities()
			}
			Request::SignRequest {ref pubkey_blob, ref data, ref flags} => {
				self.sign_request(pubkey_blob.clone(), data.clone(), *flags)
			}
			Request::AddIdentity {private_key} => {
				self.add_identity(private_key)
			}
			Request::Unknown => {
				Ok(Response::Failure)
			}
		}
	}
}

