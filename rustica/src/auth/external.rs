use asn1::Utf8String;
use author::author_client::AuthorClient;
use author::{AddIdentityDataRequest, AuthorizeRequest};

use rcgen::CustomExtension;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use x509_parser::oid_registry::Oid;

use super::{
    AuthorizationError, KeyAttestation, RegisterKeyRequestProperties, SshAuthorization,
    SshAuthorizationRequestProperties, X509Authorization, X509AuthorizationRequestProperties,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

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
    pub async fn authorize_ssh_cert(
        &self,
        auth_props: &SshAuthorizationRequestProperties,
    ) -> Result<SshAuthorization, AuthorizationError> {
        let mut identities = HashMap::new();
        identities.insert(
            String::from("requester_ip"),
            auth_props.requester_ip.clone(),
        );
        identities.insert(
            String::from("key_fingerprint"),
            auth_props.fingerprint.clone(),
        );
        identities.insert(
            String::from("mtls_identities"),
            auth_props.mtls_identities.join(","),
        );

        let mut authorization_request = HashMap::new();
        authorization_request.insert(String::from("type"), String::from("ssh"));
        authorization_request.insert(String::from("principals"), auth_props.principals.join(","));
        authorization_request.insert(String::from("servers"), auth_props.servers.join(","));
        authorization_request.insert(
            String::from("valid_before"),
            auth_props.valid_before.to_string(),
        );
        authorization_request.insert(
            String::from("valid_after"),
            auth_props.valid_after.to_string(),
        );
        authorization_request.insert(String::from("cert_type"), auth_props.cert_type.to_string());
        authorization_request.insert(String::from("authority"), auth_props.authority.to_string());

        let request = tonic::Request::new(AuthorizeRequest {
            identities,
            authorization_request,
        });

        let client_identity = Identity::from_pem(&self.mtls_cert, &self.mtls_key);
        let tls = ClientTlsConfig::new()
            .domain_name(&self.server)
            .ca_certificate(Certificate::from_pem(&self.ca))
            .identity(client_identity);

        let channel =
            match Channel::from_shared(format!("https://{}:{}", &self.server, &self.port)) {
                Ok(c) => c,
                Err(e) => {
                    error!(
                        "Could not open a channel to the authorization server: {}",
                        e
                    );
                    return Err(AuthorizationError::AuthorizerError);
                }
            }
            .timeout(Duration::from_secs(10))
            .tls_config(tls)
            .map_err(|_| AuthorizationError::ConnectionFailure)?
            .connect()
            .await
            .map_err(|_| AuthorizationError::ConnectionFailure)?;

        let mut client = AuthorClient::new(channel);
        let response = client.authorize(request).await;

        let approval_response = match response {
            Ok(r) => r.into_inner().approval_response,
            Err(e) => {
                error!("Authorization server returned error: {}", e);
                if e.code() == tonic::Code::PermissionDenied {
                    return Err(AuthorizationError::NotAuthorized);
                } else {
                    return Err(AuthorizationError::AuthorizerError);
                }
            }
        };

        // Fi extension keys, strip the "extension." prefix and create a new
        // hashmap with the values
        let extensions: HashMap<String, String> = approval_response
            .keys()
            .into_iter()
            .filter(|x| x.starts_with("extension."))
            .map(|ext| {
                (
                    ext.strip_prefix("extension.")
                        .unwrap_or_default()
                        .to_string(),
                    approval_response[ext].clone(),
                )
            })
            .collect();

        let force_command = if approval_response.contains_key("force_command") {
            Some(approval_response["force_command"].clone())
        } else {
            None
        };

        let force_source_ip = approval_response.contains_key("force_source_ip");

        let hosts = if approval_response.contains_key("authorized_fingerprints") {
            Some(
                approval_response["authorized_fingerprints"]
                    .split(',')
                    .map(String::from)
                    .collect(),
            )
        } else {
            None
        };

        let serial = approval_response["serial"]
            .parse::<u64>()
            .map_err(|_| AuthorizationError::AuthorizerError)?;
        let valid_before = approval_response["valid_before"]
            .parse::<u64>()
            .map_err(|_| AuthorizationError::AuthorizerError)?;
        let valid_after = approval_response["valid_after"]
            .parse::<u64>()
            .map_err(|_| AuthorizationError::AuthorizerError)?;

        Ok(SshAuthorization {
            serial,
            principals: approval_response["principals"]
                .split(',')
                .map(String::from)
                .collect(),
            hosts,
            valid_before,
            valid_after,
            extensions,
            force_command,
            force_source_ip,
            authority: approval_response["authority"].to_string(),
        })
    }

    pub async fn register_key(
        &self,
        req: &RegisterKeyRequestProperties,
    ) -> Result<(), AuthorizationError> {
        let mut identities = HashMap::new();
        identities.insert(String::from("requester_ip"), req.requester_ip.clone());
        identities.insert(String::from("key_fingerprint"), req.fingerprint.clone());
        identities.insert(
            String::from("mtls_identities"),
            req.mtls_identities.join(","),
        );

        let mut identity_data = HashMap::new();

        match &req.attestation {
            Some(KeyAttestation::Piv(attestation)) => {
                identity_data.insert(String::from("type"), String::from("ssh_key"));
                identity_data.insert(
                    String::from("certificate"),
                    hex::encode(&attestation.certificate),
                );
                identity_data.insert(
                    String::from("intermediate_certificate"),
                    hex::encode(&attestation.intermediate),
                );
            }
            Some(KeyAttestation::U2f(attestation)) => {
                identity_data.insert(String::from("type"), String::from("u2f_ssh_key"));
                identity_data.insert(
                    String::from("auth_data"),
                    hex::encode(&attestation.auth_data),
                );
                identity_data.insert(
                    String::from("auth_data_signature"),
                    hex::encode(&attestation.auth_data_signature),
                );
                identity_data.insert(
                    String::from("intermediate_certificate"),
                    hex::encode(&attestation.intermediate),
                );
                identity_data.insert(
                    String::from("challenge"),
                    hex::encode(&attestation.challenge),
                );
                identity_data.insert(
                    String::from("application"),
                    hex::encode(&attestation.application),
                );
                identity_data.insert(String::from("alg"), attestation.alg.to_string());
                identity_data.insert(String::from("aaguid"), attestation.aaguid.clone());
            }
            None => {
                identity_data.insert(String::from("type"), String::from("ssh_key"));
            }
        };

        let request = tonic::Request::new(AddIdentityDataRequest {
            identities,
            identity_data,
        });

        let client_identity =
            Identity::from_pem(self.mtls_cert.as_bytes(), &self.mtls_key.as_bytes());
        let tls = ClientTlsConfig::new()
            .domain_name(&self.server)
            .ca_certificate(Certificate::from_pem(self.ca.as_bytes()))
            .identity(client_identity);

        let channel =
            match Channel::from_shared(format!("https://{}:{}", &self.server, &self.port)) {
                Ok(c) => c,
                Err(e) => {
                    error!(
                        "Could not open a channel to the authorization server: {}",
                        e
                    );
                    return Err(AuthorizationError::ConnectionFailure);
                }
            }
            .timeout(Duration::from_secs(10))
            .tls_config(tls)
            .map_err(|_| AuthorizationError::ConnectionFailure)?
            .connect()
            .await
            .map_err(|_| AuthorizationError::ConnectionFailure)?;

        let mut client = AuthorClient::new(channel);
        let response = client.add_identity_data(request).await;

        match response {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Server returned error: {}", e);
                Err(AuthorizationError::ExternalError(format!("{}", e)))
            }
        }
    }

    pub async fn authorize_attested_x509_cert(
        &self,
        auth_props: &X509AuthorizationRequestProperties,
    ) -> Result<X509Authorization, AuthorizationError> {
        let mut authorization_request = HashMap::new();
        authorization_request.insert(format!("type"), "rustica_mtls".to_string());
        authorization_request.insert("authority".to_string(), auth_props.authority.clone());

        // Identities
        let mut identities = HashMap::new();
        identities.insert(
            String::from("mtls_identities"),
            auth_props.mtls_identities.join(","),
        );
        identities.insert(
            String::from("requester_ip"),
            auth_props.requester_ip.clone(),
        );

        identities.insert(format!("leaf"), hex::encode(&auth_props.attestation));
        identities.insert(
            format!("intermediate"),
            hex::encode(&auth_props.attestation_intermediate),
        );

        let request = tonic::Request::new(AuthorizeRequest {
            identities,
            authorization_request,
        });

        let client_identity =
            Identity::from_pem(self.mtls_cert.as_bytes(), &self.mtls_key.as_bytes());

        let tls = ClientTlsConfig::new()
            .domain_name(&self.server)
            .ca_certificate(Certificate::from_pem(self.ca.as_bytes()))
            .identity(client_identity);

        let channel =
            match Channel::from_shared(format!("https://{}:{}", &self.server, &self.port)) {
                Ok(c) => c,
                Err(e) => {
                    error!(
                        "Could not open a channel to the authorization server: {}",
                        e
                    );
                    return Err(AuthorizationError::ConnectionFailure);
                }
            }
            .timeout(Duration::from_secs(10))
            .tls_config(tls)
            .map_err(|_| AuthorizationError::ConnectionFailure)?
            .connect()
            .await
            .map_err(|_| AuthorizationError::ConnectionFailure)?;

        let mut client = AuthorClient::new(channel);
        let response = client.authorize(request).await;

        if let Err(e) = response {
            error!("Authorization server returned error: {}", e);
            if e.code() == tonic::Code::PermissionDenied {
                error!("Permission denied from backend");
                return Err(AuthorizationError::AuthorizerError);
            } else {
                error!("Backend threw an unexpected error");
                return Err(AuthorizationError::AuthorizerError);
            }
        }

        // Get the response from the backend service
        let response: HashMap<String, String> = response.unwrap().into_inner().approval_response;

        // For all the returned objects that are OIDs, pull them out and
        // process them.
        let extensions = response
            .iter()
            .filter_map(|entry| {
                if let Ok(oid) = Oid::from_str(entry.0.as_str()) {
                    let oid_ints: Vec<u64> = match oid.iter() {
                        Some(ints) => ints.collect(),
                        _ => return None,
                    };
                    let entry_bytes = match asn1::write_single(&Utf8String::new(entry.1)) {
                        Ok(b) => b,
                        Err(_) => return None,
                    };
                    let ext = CustomExtension::from_oid_content(&oid_ints, entry_bytes);
                    Some(ext)
                } else {
                    None
                }
            })
            .collect();

        let mtls_user = auth_props
            .mtls_identities
            .get(0)
            .ok_or(AuthorizationError::AuthorizerError)?;

        let (valid_before, valid_after) = match (
            response.get("valid_before").map(|x| x.parse::<u64>()),
            response.get("valid_after").map(|x| x.parse::<u64>()),
        ) {
            (Some(Ok(vb)), Some(Ok(va))) => (vb, va),
            (None, None) => {
                let current_time = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                (current_time + (3600 * 12), current_time)
            }
            _ => return Err(AuthorizationError::AuthorizerError),
        };

        let serial = match response.get("serial").map(|x| x.parse::<i64>()) {
            Some(Ok(serial)) => serial,
            Some(Err(_)) => return Err(AuthorizationError::AuthorizerError),
            None => 0xFEFEFEFEFE,
        };

        // Success, build the response
        return Ok(X509Authorization {
            authority: response
                .get("authority")
                .ok_or(AuthorizationError::AuthorizerError)?
                .to_string(),
            issuer: response
                .get("issuer")
                .unwrap_or(&"Rustica".to_owned())
                .to_string(),
            common_name: mtls_user.clone(),
            sans: vec![mtls_user.clone()],
            extensions,
            serial,
            valid_before,
            valid_after,
        });
    }
}
