use govna::govna_client::{GovnaClient};
use govna::{AuthorizeRequest, AuthorizeResponse};

use tokio::runtime::Runtime;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};

use sshcerts::ssh::{CertType, Extensions, CriticalOptions};

use std::collections::HashMap;

pub mod govna {
    tonic::include_proto!("govna");
}

pub struct GovnaServer {
    pub server: String
}

pub struct AuthorizationProperties {
    pub fingerprint: String,
    pub requester_ip: String,
    pub principals: Vec<String>,
    pub servers: Vec<String>,
    pub valid_before: u64,
    pub valid_after: u64,
    pub cert_type: CertType,
}

#[derive(Debug)]
pub struct Authorization {
    pub serial: u64,
    pub principals: Vec<String>,
    pub servers: Vec<String>,
    pub valid_before: u64,
    pub valid_after: u64,
    pub extensions: Extensions,
    pub force_command: Option<String>,
    pub source_address: Option<String>,
}

pub async fn authorize(server: &GovnaServer, auth_props: &AuthorizationProperties) -> Result<Authorization, String> {
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

    let channel = match Channel::from_shared(server.server.clone()) {
        Ok(c) => c,
        Err(_) => return Err(String::from("Could not open channel")),
    };
    let channel = channel.connect().await.unwrap();

    let mut client = GovnaClient::new(channel);
    let response = client.authorize(request).await;

    if response.is_err() {
        return Err(String::from("Error when talking to Govna Server"));
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
        servers: approval_response["servers"].split(",").map(String::from).collect(),
        valid_before: approval_response["valid_before"].parse::<u64>().unwrap(),
        valid_after: approval_response["valid_after"].parse::<u64>().unwrap(),
        extensions: extensions,
        force_command: force_command,
        source_address: source_address,
    })
}