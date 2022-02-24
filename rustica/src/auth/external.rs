use author::author_client::{AuthorClient};
use author::{AuthorizeRequest, AddIdentityDataRequest};

use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use serde::Deserialize;
use super::{
    Authorization,
    AuthorizationError,
    AuthorizationRequestProperties,
    KeyAttestation,
    RegisterKeyRequestProperties,
};
use std::collections::HashMap;

pub mod author {
    tonic::include_proto!("author");
}

#[derive(Deserialize)]
pub struct AuthServer {
    pub server: String,
    pub port: String,
    pub ca: String,
    pub mtls_cert: String,
    pub mtls_key: String,
}

impl AuthServer {
    pub async fn authorize(&self, auth_props: &AuthorizationRequestProperties) -> Result<Authorization, AuthorizationError> {
        let mut identities = HashMap::new();
        identities.insert(String::from("requester_ip"), auth_props.requester_ip.clone());
        identities.insert(String::from("key_fingerprint"), auth_props.fingerprint.clone());
        identities.insert(String::from("mtls_identities"), auth_props.mtls_identities.join(","));

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

        let client_identity = Identity::from_pem(&self.mtls_cert, &self.mtls_key);
        let tls = ClientTlsConfig::new()
            .domain_name(&self.server)
            .ca_certificate(Certificate::from_pem(&self.ca))
            .identity(client_identity);

        let channel = match Channel::from_shared(format!("https://{}:{}", &self.server, &self.port)) {
            Ok(c) => c,
            Err(e) => {
                error!("Could not open a channel to the authorization server: {}", e);
                return Err(AuthorizationError::AuthorizerError);
            },
        // TODO: @obelisk handle these TLS unwraps
        }.tls_config(tls).unwrap().connect().await.unwrap();

        let mut client = AuthorClient::new(channel);
        let response = client.authorize(request).await;

        if let Err(e) = response {
            error!("Authorization server returned error: {}", e);
            if e.code() == tonic::Code::PermissionDenied {
                return Err(AuthorizationError::NotAuthorized);
            } else {
                return Err(AuthorizationError::AuthorizerError);
            }
        }

        let approval_response = response.unwrap().into_inner().approval_response;

        // Find all extension keys, strip the "extension." prefix and create a new
        // hashmap with the values
        let extensions: HashMap<String, String> = approval_response.keys().into_iter()
            .filter(|x| x.starts_with("extension."))
            .map(|ext| (ext.strip_prefix("extension.").unwrap().to_string(), approval_response[ext].clone()))
            .collect();

        let force_command = if approval_response.contains_key("force_command") {
            Some(approval_response["force_command"].clone())
        } else {
            None
        };

        let force_source_ip = approval_response.contains_key("force_source_ip");

        let hosts = if approval_response.contains_key("authorized_fingerprints") {
            Some(approval_response["authorized_fingerprints"].split(',').map(String::from).collect())
        } else {
            None
        };

        Ok(Authorization {
            serial: approval_response["serial"].parse::<u64>().unwrap(),
            principals: approval_response["principals"].split(',').map(String::from).collect(),
            hosts,
            valid_before: approval_response["valid_before"].parse::<u64>().unwrap(),
            valid_after: approval_response["valid_after"].parse::<u64>().unwrap(),
            extensions,
            force_command,
            force_source_ip,
        })
    }

    pub async fn register_key(&self, req: &RegisterKeyRequestProperties) -> Result<bool, ()> {
        let mut identities = HashMap::new();
        identities.insert(String::from("requester_ip"), req.requester_ip.clone());
        identities.insert(String::from("key_fingerprint"), req.fingerprint.clone());
        identities.insert(String::from("mtls_identities"), req.mtls_identities.join(","));

        let mut identity_data = HashMap::new();

        match &req.attestation {
            Some(KeyAttestation::Piv(attestation)) => {
                identity_data.insert(String::from("type"), String::from("ssh_key"));
                identity_data.insert(String::from("certificate"), hex::encode(&attestation.certificate));
                identity_data.insert(String::from("intermediate_certificate"), hex::encode(&attestation.intermediate));
            },
            Some(KeyAttestation::U2f(attestation)) => {
                identity_data.insert(String::from("type"), String::from("u2f_ssh_key"));
                identity_data.insert(String::from("auth_data"), hex::encode(&attestation.auth_data));
                identity_data.insert(String::from("auth_data_signature"), hex::encode(&attestation.auth_data_signature));
                identity_data.insert(String::from("intermediate_certificate"), hex::encode(&attestation.intermediate));
            },
            None => {
                identity_data.insert(String::from("type"), String::from("ssh_key"));
            },
        };

        let request = tonic::Request::new(AddIdentityDataRequest {
            identities,
            identity_data,
        });

        let client_identity = Identity::from_pem(self.mtls_cert.as_bytes(), &self.mtls_key.as_bytes());
        let tls = ClientTlsConfig::new()
            .domain_name(&self.server)
            .ca_certificate(Certificate::from_pem(self.ca.as_bytes()))
            .identity(client_identity);

        let channel = match Channel::from_shared(format!("https://{}:{}", &self.server, &self.port)) {
            Ok(c) => c,
            Err(e) => {
                error!("Could not open a channel to the authorization server: {}", e);
                return Err(());
            },
        // TODO: @obelisk handle these TLS unwraps
        }.tls_config(tls).unwrap().connect().await.unwrap();

        let mut client = AuthorClient::new(channel);
        let response = client.add_identity_data(request).await;

        match response {
            Ok(_) => Ok(true),
            Err(e) => {
                error!("Server returned error: {}", e);
                Ok(false)
            },
        }
    }
}