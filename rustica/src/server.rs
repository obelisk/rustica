use crate::auth::{AuthMechanism, AuthorizationRequestProperties, RegisterKeyRequestProperties};
use crate::error::RusticaServerError;
use crate::rustica::{
    CertificateRequest,
    CertificateResponse,
    Challenge,
    ChallengeRequest,
    ChallengeResponse,
    RegisterKeyRequest,
    RegisterKeyResponse,
    rustica_server::Rustica,
};
use crate::signing::{SigningMechanism};
use crate::utils::build_login_script;
use crate::yubikey::verify_certificate_chain;

use influx_db_client::{
    Client, Point, Points, Precision, points
};

use sshcerts::ssh::{
    CertType, Certificate, CurveKind, CriticalOptions, PublicKey as SSHPublicKey, PublicKeyKind as SSHPublicKeyKind
};

use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ED25519};
use ring::hmac;
use std::{
    sync::Arc,
    time::SystemTime,
};
use tonic::{Request, Response, Status};
use tonic::transport::{Certificate as TonicCertificate};

use x509_parser::prelude::*;
use x509_parser::der_parser::oid;


pub struct RusticaServer {
    pub influx_client: Option<Client>,
    pub hmac_key: hmac::Key,
    pub authorizer: AuthMechanism,
    pub signer: SigningMechanism,
    pub require_rustica_proof: bool,
}


fn create_response<T>(e: T) -> Response<CertificateResponse> where 
T : Into::<RusticaServerError> {
    let e = e.into();
    Response::new(CertificateResponse {
        certificate: String::new(),
        error: format!("{:?}", e),
        error_code: e as i64,
    })
}

/// Extract the identities (CNs) from the presented mTLS certificates.
/// This should almost always be exactly 1. If it is 0, this is an error.
fn extract_certificate_identities(peer_certs: &Arc<Vec<TonicCertificate>>) -> Result<Vec<String>, RusticaServerError> {
    if peer_certs.is_empty() {
        return Err(RusticaServerError::NotAuthorized);
    }

    let mut mtls_identities = vec![];
    for peer in peer_certs.iter() {
        match x509_parser::parse_x509_certificate(peer.as_ref()) {
            Err(_) => return Err(RusticaServerError::NotAuthorized),
            Ok((_, cert)) => {
                for ident in cert.tbs_certificate.subject.rdn_seq {
                    for attr in ident.set {
                        if attr.attr_type == oid!(2.5.4.3) {    // CommonName
                            // Certificates must have a common name
                            match attr.attr_value.as_str() {
                                Ok(s) => mtls_identities.push(String::from(s)),
                                Err(_) => return Err(RusticaServerError::NotAuthorized),
                            };
                        }
                    }
                }
            },
        };
    }
    Ok(mtls_identities)
}

/// Validates a request passes all the following checks in this order:
/// - Validate the peer certs are the way we expect
/// - Validate Time is not expired
/// - Validate Mac
/// - Validate Signature
fn validate_request(hmac_key: &ring::hmac::Key, peer_certs: &Arc<Vec<TonicCertificate>>, challenge: &Challenge, check_signature: bool) -> Result<(SSHPublicKey, Vec<String>), RusticaServerError> {
    let mtls_identities = extract_certificate_identities(peer_certs)?;

    // Get request time, and current time. Any issue causes request to fail
    let (request_time, time) = match (challenge.challenge_time.parse::<u64>(), SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)) {
        (Ok(rt), Ok(time)) => (rt, time.as_secs()),
        _ => return Err(RusticaServerError::Unknown)
    };

    if (time - request_time) > 5 {
        return Err(RusticaServerError::TimeExpired);
    }

    let hmac_verification = format!("{}-{}", request_time, challenge.pubkey);
    let decoded_challenge = match hex::decode(&challenge.challenge) {
        Ok(dc) => dc,
        Err(_) => return Err(RusticaServerError::BadChallenge),
    };

    if hmac::verify(hmac_key, hmac_verification.as_bytes(), &decoded_challenge).is_err() {
        error!("Received a bad challenge from: {}", mtls_identities.join(","));
        return Err(RusticaServerError::BadChallenge);
    }

    // Request integrity confirmed, continue parsing knowing it has
    // not been replayed significantly in time or its data tampered with since
    // the initial request.
    let ssh_pubkey = match SSHPublicKey::from_string(&challenge.pubkey) {
        Ok(sshpk) => sshpk,
        Err(_) => return Err(RusticaServerError::InvalidKey),
    };

    if !check_signature {
        return Ok((ssh_pubkey, mtls_identities))
    }

    let result = match &ssh_pubkey.kind {
        SSHPublicKeyKind::Ecdsa(key) => {
            let (pubkey, alg) = match key.curve.kind {
                CurveKind::Nistp256 => (key, &ECDSA_P256_SHA256_ASN1),
                CurveKind::Nistp384 => (key, &ECDSA_P384_SHA384_ASN1),
                _ => return Err(RusticaServerError::UnsupportedKeyType),
            };

            UnparsedPublicKey::new(alg, &pubkey.key).verify(
                &hex::decode(&challenge.challenge).unwrap(),
                &hex::decode(&challenge.challenge_signature).unwrap(),
            )
        },
        SSHPublicKeyKind::Ed25519(key) => {
            let peer_public_key = UnparsedPublicKey::new(&ED25519, &key.key);
            peer_public_key.verify(
                &hex::decode(&challenge.challenge).unwrap(),
                &hex::decode(&challenge.challenge_signature).unwrap()
            )
        },
        _ => return Err(RusticaServerError::UnsupportedKeyType),
    };

    if result.is_err() {
        error!("Could not verify signature on challenge: {}", mtls_identities.join(","));
        return Err(RusticaServerError::BadChallenge)
    }

    Ok((ssh_pubkey, mtls_identities))
}

#[tonic::async_trait]
impl Rustica for RusticaServer {
    /// Handler when a host is going to make a further request to Rustica
    async fn challenge(&self, request: Request<ChallengeRequest>) -> Result<Response<ChallengeResponse>, Status> {
        // These unwraps should be fine because Tonic has already handled
        // the connection mTLS.
        let remote_addr = request.remote_addr().unwrap();
        let peer = request.peer_certs().unwrap();
        let request = request.into_inner();
        let mtls_identities = match extract_certificate_identities(&peer) {
            Ok(idents) => idents,
            Err(_) => return Err(Status::permission_denied("")),
        };

        let ssh_pubkey = match SSHPublicKey::from_string(&request.pubkey) {
            Ok(sshpk) => sshpk,
            Err(_) => return Err(Status::permission_denied("")),
        };

        info!("[{}] from [{}] wants to authenticate with key [{}]", mtls_identities.join(","), remote_addr, ssh_pubkey.fingerprint().hash);

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let pubkey = &request.pubkey;
        let challenge = format!("{}-{}", timestamp, pubkey);
        let tag = hmac::sign(&self.hmac_key, challenge.as_bytes());

        let reply = ChallengeResponse {
            time: timestamp,
            challenge: hex::encode(tag),
            no_signature_required: !self.require_rustica_proof,
        };

        Ok(Response::new(reply))
    }

    /// Handler used when a host requests a new certificate from Rustica
    async fn certificate(&self, request: Request<CertificateRequest>) -> Result<Response<CertificateResponse>, Status> {
        let remote_addr = request.remote_addr().unwrap();
        let peer = request.peer_certs();
        let request = request.into_inner();

        let (challenge, peer) = match (&request.challenge, peer) {
            (Some(challenge), Some(peer)) => (challenge, peer),
            _ => return Ok(create_response(RusticaServerError::BadRequest)),
        };

        let (ssh_pubkey, mtls_identities) = match validate_request(&self.hmac_key, &peer, &challenge, self.require_rustica_proof) {
            Ok((ssh_pk, idents)) => (ssh_pk, idents),
            Err(e) => return Ok(create_response(e)),
        };

        let current_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(ts) => ts.as_secs(),
            Err(_e) => 0xFFFFFFFFFFFFFFFF,
        };

        if (request.valid_before < request.valid_after) || current_timestamp > request.valid_before {
            // Can't have a cert where the start time (valid_after) is before
            // the end time (valid_before)
            // Disallow certificates that are already expired
            return Ok(create_response(RusticaServerError::BadCertOptions));
        }

        let (req_cert_type, ca_cert, signer) = match request.cert_type {
            1 => (CertType::User, self.signer.get_signer_public_key(CertType::User), self.signer.get_signer(CertType::User)),
            2 => (CertType::Host, self.signer.get_signer_public_key(CertType::Host), self.signer.get_signer(CertType::Host)),
            _ => return Ok(create_response(RusticaServerError::BadCertOptions)),
        };

        let ca_cert = match ca_cert {
            Ok(ca_cert) => ca_cert,
            Err(e) => {
                error!("Could not fetch public key to insert into new certificate: {:?}", e);
                return Ok(create_response(RusticaServerError::Unknown));
            }
        };

        let fingerprint = ssh_pubkey.fingerprint().hash;
        let auth_props = AuthorizationRequestProperties {
            fingerprint: fingerprint.clone(),
            mtls_identities: mtls_identities.clone(),
            requester_ip: remote_addr.to_string(),
            principals: request.principals.clone(),
            servers: request.servers.clone(),
            cert_type: req_cert_type,
            valid_after: request.valid_after,
            valid_before: request.valid_before,
        };

        info!("[{}] from [{}] requests a cert for key [{}]", mtls_identities.join(","), remote_addr, fingerprint);

        let authorization = match &self.authorizer {
            AuthMechanism::Local(local) => local.authorize(&auth_props),
            AuthMechanism::External(external) => external.authorize(&auth_props).await,
        };

        let authorization = match authorization {
            Ok(auth) => auth,
            Err(e) => return Ok(create_response(e)),
        };
        info!("[{}] from [{}] is granted a cert for key [{}]", mtls_identities.join(","), remote_addr, fingerprint);
        debug!("[{}] from [{}] is granted the following authorization on key [{}]: {:?}", mtls_identities.join(","), remote_addr, fingerprint, authorization);

        let critical_options = match build_login_script(&authorization.hosts, &authorization.force_command) {
            Ok(cmd) => {
                let mut co = std::collections::HashMap::new();
                // If our authorization contains no hosts and no command,
                // this becomes an unrestricted cert good for all commands on all
                // hosts
                if let Some(cmd) = cmd {
                    co.insert(String::from("force-command"), cmd);
                }

                if authorization.force_source_ip {
                    co.insert(String::from("source-address"), remote_addr.ip().to_string());
                }

                CriticalOptions::Custom(co)
            },
            Err(_) => return Ok(create_response(RusticaServerError::Unknown)),
        };

        let cert = Certificate::builder(&ssh_pubkey, req_cert_type, &ca_cert).unwrap()
            .serial(authorization.serial)
            .key_id(format!("Rustica-JITC-for-{}", &fingerprint))
            .set_principals(&authorization.principals)
            .valid_after(authorization.valid_after)
            .valid_before(authorization.valid_before)
            .set_critical_options(critical_options)
            .set_extensions(authorization.extensions)
            .sign(signer);

        let serialized_cert = match cert {
            Ok(cert) => {
                let serialized = format!("{}", cert);

                // Sanity check that we can parse the cert we just generated
                if let Err(e) = Certificate::from_string(&serialized) {
                    error!("Couldn't deserialize certificate: {}", e);
                    return Ok(create_response(RusticaServerError::BadCertOptions));
                }
                serialized
            }
            Err(e) => {
                error!("Creating certificate failed: {}", e);
                return Ok(create_response(RusticaServerError::BadChallenge));
            }
        };

        let reply = CertificateResponse {
            certificate: serialized_cert,
            error: String::new(),
            error_code: RusticaServerError::Success as i64,
        };

        if let Some(influx_client) = &self.influx_client {
            let point = Point::new("rustica_logs")
                .add_tag("fingerprint", fingerprint)
                .add_tag("mtls_identities", mtls_identities.join(","))
                .add_field("principals", authorization.principals.join(","))
                .add_field("hosts", authorization.hosts.unwrap_or_default().join(","));

            if let Err(e) = influx_client.write_points(points!(point), Some(Precision::Seconds), None).await {
                error!("Could not log to influx DB: {}", e);
            }
        }

        Ok(Response::new(reply))
    }

    async fn register_key(&self, request: Request<RegisterKeyRequest>) -> Result<Response<RegisterKeyResponse>, Status> {
        debug!("Received register key request: {:?}", request);
        let requester_ip = match request.remote_addr() {
            Some(x) => x.to_string(),
            None => String::new(),
        };

        let peer = request.peer_certs();
        let request = request.into_inner();

        let (challenge, peer) = match (&request.challenge, peer) {
            (Some(challenge), Some(peer)) => (challenge, peer),
            _ => return Err(Status::permission_denied("")),
        };

        let (ssh_pubkey, mtls_identities) = match validate_request(&self.hmac_key, &peer, &challenge, self.require_rustica_proof) {
            Ok((ssh_pk, idents)) => (ssh_pk, idents),
            Err(e) => return Err(Status::cancelled(format!("{:?}", e))),
        };

        let (fingerprint, attestation) = match verify_certificate_chain(&request.certificate, &request.intermediate) {
            Ok(key) => (key.fingerprint, key.attestation),
            _ => (ssh_pubkey.fingerprint().hash, None),
        };

        let register_properties = RegisterKeyRequestProperties {
            fingerprint,
            mtls_identities,
            requester_ip,
            attestation,
        };

        let response = match &self.authorizer {
            AuthMechanism::Local(local) => local.register_key(&register_properties),
            AuthMechanism::External(external) => external.register_key(&register_properties).await,
        };

        match response {
            Ok(true) => return Ok(Response::new(RegisterKeyResponse{})),
            _ => return Err(Status::unavailable("Could not register new key")),
        }
    }
}