use govna::govna_client::{GovnaClient};
use govna::{AuthorizeRequest};

use tonic::transport::{Certificate, Channel, ClientTlsConfig};

use sshcerts::ssh::Extensions;
use super::{Authorization, AuthorizationError, AuthorizationRequestProperties};
use std::collections::HashMap;

pub mod govna {
    tonic::include_proto!("govna");
}

pub struct AuthServer {
    pub server: String
}

impl AuthServer {
    pub async fn authorize(&self, auth_props: &AuthorizationRequestProperties) -> Result<Authorization, AuthorizationError> {
        let mut identities = HashMap::new();
        identities.insert(String::from("requester_ip"), auth_props.requester_ip.clone());
        identities.insert(String::from("key_fingerprint"), auth_props.fingerprint.clone());

        let mut authorization_request = HashMap::new();
        authorization_request.insert(String::from("type"), String::from("ssh"));
        authorization_request.insert(String::from("principals"), auth_props.principals.join(","));
        authorization_request.insert(String::from("servers"), auth_props.servers.join(","));
        authorization_request.insert(String::from("valid_before"), auth_props.valid_before.to_string());
        authorization_request.insert(String::from("valid_after"), auth_props.valid_after.to_string());
        authorization_request.insert(String::from("cert_type"), auth_props.cert_type.to_string());

        let request = tonic::Request::new(AuthorizeRequest {
            identities,
            authorization_request,
        });

        let channel = match Channel::from_shared(self.server.clone()) {
            Ok(c) => c,
            Err(e) => {
                error!("Could not open a channel to the authorization server: {}", e);
                return Err(AuthorizationError::AuthorizerError);
            },
        };
        let channel = channel.connect().await.unwrap();

        let mut client = GovnaClient::new(channel);
        let response = client.authorize(request).await;

        if let Err(e) = response {
            error!("Authorization server returned error: {}", e);
            return Err(AuthorizationError::AuthorizerError);
        }

        let approval_response = response.unwrap().into_inner().approval_response;

        let extensions = if !approval_response.contains_key("extensions") {
            Extensions::Standard
        } else {
            let requested_extensions = approval_response["extensions"].split(",").map(|x| (String::from(x), String::new())).collect();
            Extensions::Custom(requested_extensions)
        };

        let force_command = if !approval_response.contains_key("force_command") {
            None
        } else {
            Some(approval_response["force_command"].clone())
        };

        let source_address = if !approval_response.contains_key("source_address") {
            None
        } else {
            Some(approval_response["source_address"].clone())
        };

        Ok(Authorization {
            serial: approval_response["serial"].parse::<u64>().unwrap(),
            principals: approval_response["principals"].split(",").map(String::from).collect(),
            hosts: Some(approval_response["servers"].split(",").map(String::from).collect()),
            valid_before: approval_response["valid_before"].parse::<u64>().unwrap(),
            valid_after: approval_response["valid_after"].parse::<u64>().unwrap(),
            extensions: extensions,
            force_command: force_command,
            source_address: source_address,
        })
    }
}