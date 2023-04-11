use crate::auth::{
    AuthorizationMechanism, RegisterKeyRequestProperties, SshAuthorizationRequestProperties,
    X509AuthorizationRequestProperties,
};
use crate::error::RusticaServerError;
use crate::logging::{
    CertificateIssued, InternalMessage, KeyInfo, KeyRegistrationFailure, Log, Severity,
    X509CertificateIssued,
};
use crate::rustica::{
    rustica_server::Rustica, CertificateRequest, CertificateResponse, Challenge, ChallengeRequest,
    ChallengeResponse, RegisterKeyRequest, RegisterKeyResponse, RegisterU2fKeyRequest,
    RegisterU2fKeyResponse,
};
use crate::rustica::{X509CertificateRequest, X509CertificateResponse};
use crate::signing::SigningMechanism;
use crate::verification::{verify_piv_certificate_chain, verify_u2f_certificate_chain};

use crossbeam_channel::Sender;

use rcgen::{DistinguishedName, DnType, SanType};
use sshcerts::ssh::{CertType, Certificate, PrivateKey, PublicKey};

use ring::hmac;
use std::collections::HashMap;
use std::time::{Duration, UNIX_EPOCH};
use std::{sync::Arc, time::SystemTime};
use tonic::transport::Certificate as TonicCertificate;
use tonic::{Request, Response, Status};

use x509_parser::der_parser::oid;
use x509_parser::prelude::*;

pub struct RusticaServer {
    pub log_sender: Sender<Log>,
    pub hmac_key: hmac::Key,
    pub challenge_key: PrivateKey,
    pub authorizer: AuthorizationMechanism,
    pub signer: SigningMechanism,
    pub require_rustica_proof: bool,
    pub require_attestation_chain: bool,
}

/// Macro for simplifying sending error logs to the Rustica logging system.
macro_rules! rustica_error {
    ($self:ident, $message:expr) => {
        let _ = $self.log_sender.send(Log::InternalMessage(InternalMessage {
            severity: Severity::Error,
            message: $message,
        }));
    };
}

/// Macro for simplifying sending warning logs to the Rustica logging system.
macro_rules! rustica_warning {
    ($self:ident, $message:expr) => {
        let _ = $self.log_sender.send(Log::InternalMessage(InternalMessage {
            severity: Severity::Warning,
            message: $message,
        }));
    };
}

fn create_response<T>(e: T) -> Response<CertificateResponse>
where
    T: Into<RusticaServerError>,
{
    let e = e.into();
    Response::new(CertificateResponse {
        certificate: String::new(),
        error: format!("{:?}", e),
        error_code: e as i64,
    })
}

/// Extract the identities (CNs) from the presented mTLS certificates.
/// This should almost always be exactly 1. If it is 0, this is an error.
fn extract_certificate_identities(
    peer_certs: &Arc<Vec<TonicCertificate>>,
) -> Result<Vec<String>, RusticaServerError> {
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
                        if attr.attr_type == oid!(2.5.4 .3) {
                            // CommonName
                            // Certificates must have a common name
                            match attr.attr_value.as_str() {
                                Ok(s) => mtls_identities.push(String::from(s)),
                                Err(_) => return Err(RusticaServerError::NotAuthorized),
                            };
                        }
                    }
                }
            }
        };
    }
    Ok(mtls_identities)
}

/// Validates a request passes all the following checks in this order:
/// - Validate the peer certs are the way we expect
/// - Validate Time is not expired
/// - Validate Signature
/// - Validate HMAC
/// - Validate certificate parameters
fn validate_request(
    srv: &RusticaServer,
    hmac_key: &ring::hmac::Key,
    peer_certs: &Arc<Vec<TonicCertificate>>,
    challenge: &Challenge,
) -> Result<(PublicKey, Vec<String>), RusticaServerError> {
    let mtls_identities = extract_certificate_identities(peer_certs)?;

    // Get request time, and current time. Any issue causes request to fail
    let (request_time, time) = match (
        challenge.challenge_time.parse::<u64>(),
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH),
    ) {
        (Ok(rt), Ok(time)) => (rt, time.as_secs()),
        _ => return Err(RusticaServerError::Unknown),
    };

    // This is our operational window. A user must confirm they control the
    // the private key within this window or else we will kick out and make
    // them start again. This is so short because we don't want people to
    // be able to "buffer" requests, where they presign them and then use
    // them later. Admittedly, the period set here is exceedingly short but in
    // practice it has not been too much of an issue.
    if (time - request_time) > 5 {
        rustica_warning!(
            srv,
            format!(
                "Expired challenge received from: {}",
                mtls_identities.join(",")
            )
        );
        return Err(RusticaServerError::TimeExpired);
    }

    // Since we need to parse a certificate which is not signed by us, we
    // cannot validate integrity before taking an expensive parsing step.
    // To prevent a malicious host serving us an enormous certificate that
    // takes significant time to parse, we immiediately bail if it's much
    // larger than we expect.
    if challenge.challenge.len() > 1024 {
        rustica_warning!(
            srv,
            format!(
                "Received a certificate that is far too large from from: {}",
                mtls_identities.join(",")
            )
        );
        return Err(RusticaServerError::Unknown);
    }

    // This step validates the signature on the certificate. If a user tries
    // a malicious certificate which contains the correct public key but an
    // invalid signature, that is caught here.
    let parsed_certificate = Certificate::from_string(&challenge.challenge).map_err(|_| {
        rustica_warning!(
            srv,
            format!(
                "Received a bad certificate from: {}",
                mtls_identities.join(",")
            )
        );
        RusticaServerError::BadChallenge
    })?;

    let hmac_challenge = &parsed_certificate.key_id;
    let hmac_verification = format!("{}-{}", request_time, challenge.pubkey);
    let decoded_challenge =
        hex::decode(&hmac_challenge).map_err(|_| RusticaServerError::BadChallenge)?;

    if hmac::verify(hmac_key, hmac_verification.as_bytes(), &decoded_challenge).is_err() {
        rustica_warning!(
            srv,
            format!(
                "Received a bad challenge from: {}",
                mtls_identities.join(",")
            )
        );
        return Err(RusticaServerError::BadChallenge);
    }

    // This should never fail as the HMAC has passed so this cannot have been
    // tampered with. It could only fail if we gave it a bad public key to
    // start with. We check it for completeness.
    let hmac_ssh_pubkey = PublicKey::from_string(&challenge.pubkey).map_err(|_| {
        rustica_error!(
            srv,
            format!(
                "Public key was invalid when negotiating with [{}]. Public key: [{}]",
                mtls_identities.join(","),
                &challenge.pubkey
            )
        );
        RusticaServerError::BadChallenge
    })?;

    // This functionality exists because when user certificates are FIDO or
    // Yubikey PIV backed, SSHing into a remote host requires two taps: the
    // first for this check, and then a second for the server being connected
    // to. This check was made optional because in the event a user is
    // compromised, there is still a requirement for physical interaction
    // during the final step of the connection. The double tap is also
    // confusing and annoying to some users.
    //
    // The benefit of enabling this is that a compromised host cannot fetch
    // certificates to see what permissions they might be able to use after
    // waiting for a user to initiate a connection themselves.
    if !srv.require_rustica_proof {
        // Do an extra sanity check here that the certificate we received was signed by us
        if parsed_certificate.signature_key.fingerprint().hash
            != srv.challenge_key.pubkey.fingerprint().hash
        {
            rustica_warning!(
                srv,
                format!(
                    "Received an incorrect certificate from {}",
                    mtls_identities.join(",")
                )
            );
            return Err(RusticaServerError::BadChallenge);
        }
        return Ok((hmac_ssh_pubkey, mtls_identities));
    }

    // We now know the request has not been replayed significantly in time.
    // We also know the certificate is valid as it parsed. Now we need to
    // check that the signature on the certificate is from the key we
    // expect.

    // We expect the client to resign the certificate we sent it with the
    // key they are proving ownership of.
    if parsed_certificate.key.fingerprint().hash
        != parsed_certificate.signature_key.fingerprint().hash
    {
        rustica_warning!(
            srv,
            format!(
                "User key did not equal CA key when talking to: {}",
                mtls_identities.join(",")
            )
        );
        return Err(RusticaServerError::BadChallenge);
    }

    // We check that the user key in the certificate is the key that they
    // should be proving ownership of. This is valid because the challenge
    // pubkey was proved to be untamped with using the hmac.
    if parsed_certificate.key.fingerprint().hash != hmac_ssh_pubkey.fingerprint().hash {
        rustica_warning!(
            srv,
            format!(
                "User key did not equal HMAC validated public key: {}",
                mtls_identities.join(",")
            )
        );
        return Err(RusticaServerError::BadChallenge);
    }

    // We've proven user_fp == signing_fp == hmac_validated_fp. To get to
    // this point the user must have received our challenge certificate
    // containing our HMAC challenge, resigned it with their key, and
    // sent it back for which it passed all checks.
    Ok((hmac_ssh_pubkey, mtls_identities))
}

#[tonic::async_trait]
impl Rustica for RusticaServer {
    /// Handler when a host is going to make a further request to Rustica
    async fn challenge(
        &self,
        request: Request<ChallengeRequest>,
    ) -> Result<Response<ChallengeResponse>, Status> {
        // We must receive these from the Tonic system or else we should fail
        // as we may have guarantees on this information upstream.
        let remote_addr = request.remote_addr().ok_or(Status::permission_denied(""))?;
        let peer = request.peer_certs().ok_or(Status::permission_denied(""))?;
        let request = request.into_inner();
        let mtls_identities = match extract_certificate_identities(&peer) {
            Ok(idents) => idents,
            Err(_) => return Err(Status::permission_denied("")),
        };

        let ssh_pubkey = match PublicKey::from_string(&request.pubkey) {
            Ok(sshpk) => sshpk,
            Err(_) => return Err(Status::permission_denied("")),
        };

        debug!(
            "[{}] from [{}] wants to authenticate with key [{}]",
            mtls_identities.join(","),
            remote_addr,
            ssh_pubkey.fingerprint().hash
        );

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Could not get time from the system")
            .as_secs()
            .to_string();
        let pubkey = &request.pubkey;
        let challenge = format!("{}-{}", timestamp, pubkey);
        let tag = hmac::sign(&self.hmac_key, challenge.as_bytes());

        // Build an SSHCertificate as a challenge
        //
        // Generating certificates here should never fail. We map_err as a guard
        // in case there is some SSH pubkey that causes some failure condition
        // preventing us from crashing and resulting in a DOS.
        let cert = Certificate::builder(&ssh_pubkey, CertType::Host, &self.challenge_key.pubkey)
            .map_err(|_| Status::permission_denied(""))?
            .serial(0xFEFEFEFEFEFEFEFE)
            .key_id(hex::encode(tag))
            .valid_after(0)
            .valid_before(0)
            .sign(&self.challenge_key)
            .map_err(|_| Status::permission_denied(""))?;

        let reply = ChallengeResponse {
            time: timestamp,
            challenge: format!("{}", cert),
            no_signature_required: !self.require_rustica_proof,
        };

        Ok(Response::new(reply))
    }

    /// Handler used when a host requests a new certificate from Rustica
    async fn certificate(
        &self,
        request: Request<CertificateRequest>,
    ) -> Result<Response<CertificateResponse>, Status> {
        let remote_addr = request.remote_addr().ok_or(Status::permission_denied(""))?;
        let peer = request.peer_certs();
        let request = request.into_inner();

        let (challenge, peer) = match (&request.challenge, peer) {
            (Some(challenge), Some(peer)) => (challenge, peer),
            _ => return Ok(create_response(RusticaServerError::BadRequest)),
        };

        let (ssh_pubkey, mtls_identities) =
            match validate_request(self, &self.hmac_key, &peer, challenge) {
                Ok((ssh_pk, idents)) => (ssh_pk, idents),
                Err(e) => return Ok(create_response(e)),
            };

        let current_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(ts) => ts.as_secs(),
            Err(_e) => 0xFFFFFFFFFFFFFFFF,
        };

        if (request.valid_before < request.valid_after) || current_timestamp > request.valid_before
        {
            // Can't have a cert where the start time (valid_after) is before
            // the end time (valid_before)
            // Disallow certificates that are already expired
            return Ok(create_response(RusticaServerError::BadCertOptions));
        }

        let req_cert_type = match request.cert_type {
            1 => CertType::User,
            2 => CertType::Host,
            _ => return Ok(create_response(RusticaServerError::BadCertOptions)),
        };

        let authority = if request.key_id.is_empty() {
            &self.signer.default_authority
        } else {
            &request.key_id
        };

        let fingerprint = ssh_pubkey.fingerprint().hash;
        let auth_props = SshAuthorizationRequestProperties {
            fingerprint: fingerprint.clone(),
            mtls_identities: mtls_identities.clone(),
            requester_ip: remote_addr.to_string(),
            principals: request.principals.clone(),
            servers: request.servers.clone(),
            cert_type: req_cert_type,
            valid_after: request.valid_after,
            valid_before: request.valid_before,
            authority: authority.clone(),
        };

        debug!(
            "[{}] from [{}] requests a cert for key [{}] from authority [{}]",
            mtls_identities.join(","),
            remote_addr,
            fingerprint,
            authority
        );

        // I'm unsure if it's a good move to have this before or after the authorization call.
        // Before means if a key is requested we don't know about, we can prevent extraneous calls to
        // the authorization backend.
        //
        // Having it after means that it's easier to flood the backend service but brutefocing key_ids
        // is much less achievable.
        let ca_cert = match self.signer.get_signer_public_key(authority, req_cert_type) {
            Ok(public_key) => public_key,
            // Since all PublicKeys are cached, this can only happen if a public key
            // we don't have is requested.
            Err(_) => return Ok(create_response(RusticaServerError::NotAuthorized)),
        };

        let authorization = self.authorizer.authorize_ssh_cert(&auth_props).await;

        let authorization = match authorization {
            Ok(auth) => auth,
            Err(e) => return Ok(create_response(e)),
        };

        debug!("[{}] from [{}] is granted the following authorization on key [{}] for authority [{}]: {:?}", mtls_identities.join(","), remote_addr, fingerprint, authority, authorization);

        let mut critical_options = HashMap::new();
        if let Some(cmd) = authorization.force_command {
            critical_options.insert(String::from("force-command"), cmd);
        }

        if authorization.force_source_ip {
            critical_options.insert(String::from("source-address"), remote_addr.ip().to_string());
        }

        let cert = Certificate::builder(&ssh_pubkey, req_cert_type, &ca_cert)
            .map_err(|_| Status::permission_denied(""))?
            .serial(authorization.serial)
            .key_id(format!("Rustica-JITC-for-{}", &fingerprint))
            .set_principals(&authorization.principals)
            .valid_after(authorization.valid_after)
            .valid_before(authorization.valid_before)
            .set_critical_options(critical_options.clone())
            .set_extensions(authorization.extensions.clone());

        let cert = self.signer.sign(&authorization.authority, cert).await;

        let serialized_cert = match cert {
            Ok(cert) => {
                let serialized = format!("{}", cert);

                // Sanity check that we can parse the cert we just generated
                if let Err(e) = Certificate::from_string(&serialized) {
                    debug!("Offending Public Key: {}", ssh_pubkey);
                    debug!("Offending certificate: {}", serialized);
                    rustica_error!(self, format!("Couldn't deserialize certificate: {}", e));
                    return Ok(create_response(RusticaServerError::BadCertOptions));
                }
                serialized
            }
            Err(e) => {
                rustica_error!(self, format!("Creating certificate failed: {}", e));
                return Ok(create_response(RusticaServerError::BadChallenge));
            }
        };

        let reply = CertificateResponse {
            certificate: serialized_cert,
            error: String::new(),
            error_code: RusticaServerError::Success as i64,
        };

        let _ = self
            .log_sender
            .send(Log::CertificateIssued(CertificateIssued {
                fingerprint,
                signed_by: ca_cert.fingerprint().hash,
                authority: authority.to_string(),
                certificate_type: req_cert_type.to_string(),
                mtls_identities,
                principals: authorization.principals,
                extensions: authorization.extensions,
                critical_options,
                valid_after: authorization.valid_after,
                valid_before: authorization.valid_before,
            }));

        Ok(Response::new(reply))
    }

    async fn register_key(
        &self,
        request: Request<RegisterKeyRequest>,
    ) -> Result<Response<RegisterKeyResponse>, Status> {
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

        let (ssh_pubkey, mtls_identities) =
            match validate_request(self, &self.hmac_key, &peer, challenge) {
                Ok((ssh_pk, idents)) => (ssh_pk, idents),
                Err(e) => {
                    rustica_error!(self, format!("Could not validate request: {:?}", e));
                    return Err(Status::cancelled(""));
                }
            };

        let (fingerprint, attestation) = match verify_piv_certificate_chain(
            &request.certificate,
            &request.intermediate,
        ) {
            Ok(key) => {
                // This can only occur if an attestation chain has been provided
                // that doesn't match the initially provided PublicKey in the
                // challenge request
                if ssh_pubkey.fingerprint().hash != key.fingerprint {
                    rustica_warning!(self, format!("Attestation fingerprint did not match challenge from host [{requester_ip}]. Attestation: [{}] Challenge: [{}]",
                        ssh_pubkey.fingerprint().hash,
                        key.fingerprint)
                    );
                    return Err(Status::invalid_argument(
                        "Attestation did not match challenge",
                    ));
                }
                (key.fingerprint, key.attestation)
            }
            Err(_) => {
                if !self.require_attestation_chain {
                    (ssh_pubkey.fingerprint().hash, None)
                } else {
                    let key_info = KeyInfo {
                        fingerprint: ssh_pubkey.fingerprint().hash,
                        mtls_identities,
                    };

                    let _ =
                        self.log_sender
                            .send(Log::KeyRegistrationFailure(KeyRegistrationFailure {
                                key_info,
                                message:
                                    "Attempt to register a key with an invalid attestation chain"
                                        .to_string(),
                            }));
                    return Err(Status::unavailable(
                        "Could not register a key without valid attestation data",
                    ));
                }
            }
        };

        let register_properties = RegisterKeyRequestProperties {
            fingerprint: fingerprint.clone(),
            mtls_identities: mtls_identities.clone(),
            requester_ip,
            attestation,
        };

        let response = self.authorizer.register_key(&register_properties).await;

        match response {
            Ok(_) => {
                let _ = self.log_sender.send(Log::KeyRegistered(KeyInfo {
                    fingerprint,
                    mtls_identities,
                }));
                return Ok(Response::new(RegisterKeyResponse {}));
            }
            Err(e) => {
                let key_info = KeyInfo {
                    fingerprint,
                    mtls_identities,
                };

                let _ = self
                    .log_sender
                    .send(Log::KeyRegistrationFailure(KeyRegistrationFailure {
                        key_info,
                        message: e.to_string(),
                    }));
                return Err(Status::unavailable("Could not register new key"));
            }
        }
    }

    async fn register_u2f_key(
        &self,
        request: Request<RegisterU2fKeyRequest>,
    ) -> Result<Response<RegisterU2fKeyResponse>, Status> {
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

        let (ssh_pubkey, mtls_identities) =
            match validate_request(self, &self.hmac_key, &peer, challenge) {
                Ok((ssh_pk, idents)) => (ssh_pk, idents),
                Err(e) => return Err(Status::cancelled(format!("{:?}", e))),
            };

        let (fingerprint, attestation) = match verify_u2f_certificate_chain(
            &request.auth_data,
            &request.auth_data_signature,
            &request.intermediate,
            request.alg,
            &request.u2f_challenge,
            &request.sk_application,
        ) {
            Ok(key) => {
                // This can only occur if an attestation chain has been provided
                // that doesn't match the initially provided PublicKey in the
                // challenge request
                if ssh_pubkey.fingerprint().hash != key.fingerprint {
                    rustica_warning!(self, format!("Attestation fingerprint did not match challenge from host [{requester_ip}]. Attestation: [{}] Challenge: [{}]",
                        ssh_pubkey.fingerprint().hash,
                        key.fingerprint)
                    );
                    return Err(Status::invalid_argument(
                        "Attestation did not match challenge",
                    ));
                }
                (key.fingerprint, key.attestation)
            }
            Err(_) => {
                if !self.require_attestation_chain {
                    (ssh_pubkey.fingerprint().hash, None)
                } else {
                    let key_info = KeyInfo {
                        fingerprint: ssh_pubkey.fingerprint().hash,
                        mtls_identities,
                    };

                    let _ =
                        self.log_sender
                            .send(Log::KeyRegistrationFailure(KeyRegistrationFailure {
                                key_info,
                                message:
                                    "Attempt to register a key with an invalid attestation chain"
                                        .to_string(),
                            }));
                    return Err(Status::unavailable(
                        "Could not register a key without valid attestation data",
                    ));
                }
            }
        };

        let register_properties = RegisterKeyRequestProperties {
            fingerprint: fingerprint.clone(),
            mtls_identities: mtls_identities.clone(),
            requester_ip,
            attestation,
        };

        let response = self.authorizer.register_key(&register_properties).await;

        match response {
            Ok(_) => {
                let _ = self.log_sender.send(Log::KeyRegistered(KeyInfo {
                    fingerprint,
                    mtls_identities,
                }));
                return Ok(Response::new(RegisterU2fKeyResponse {}));
            }
            Err(e) => {
                let key_info = KeyInfo {
                    fingerprint,
                    mtls_identities,
                };

                let _ = self
                    .log_sender
                    .send(Log::KeyRegistrationFailure(KeyRegistrationFailure {
                        key_info,
                        message: e.to_string(),
                    }));
                return Err(Status::unavailable("Could not register new key"));
            }
        }
    }

    /// Handler used when a host requests a new X509 certificate from Rustica
    async fn x509_certificate(
        &self,
        request: Request<X509CertificateRequest>,
    ) -> Result<Response<X509CertificateResponse>, Status> {
        let remote_addr = request.remote_addr().ok_or(Status::permission_denied(""))?;

        let peer_certs = request.peer_certs().ok_or(Status::permission_denied(""))?;
        let mtls_identities = extract_certificate_identities(&peer_certs)
            .map_err(|_| Status::permission_denied(""))?;
        let request = request.into_inner();

        let key =
            verify_piv_certificate_chain(&request.attestation, &request.attestation_intermediate)
                .map_err(|_| Status::permission_denied("Invalid attestation chain"))?;

        let authority = if request.key_id.is_empty() {
            &self.signer.default_authority
        } else {
            &request.key_id
        };

        // Check authorization
        let auth_props = X509AuthorizationRequestProperties {
            authority: authority.to_owned(),
            mtls_identities: mtls_identities.clone(),
            requester_ip: remote_addr.to_string(),
            attestation: request.attestation.to_vec(),
            attestation_intermediate: request.attestation_intermediate.to_vec(),
            key,
        };

        let authorization = match self.authorizer.authorize_x509_cert(&auth_props).await {
            Ok(auth) => auth,
            Err(e) => {
                rustica_warning!(
                    self,
                    format!(
                        "Authorizer rejected [{}] from fetching new X509 certificate. Error: [{e}]",
                        mtls_identities.join(","),
                    )
                );
                return Err(Status::permission_denied("Not authorized"));
            }
        };

        // Create new certificate
        let mut csr = match rcgen::CertificateSigningRequest::from_der(&request.csr) {
            Ok(csr) => csr,
            Err(e) => {
                rustica_warning!(
                    self,
                    format!(
                        "Invalid CSR was provided by [{}]. Error: [{e}]",
                        mtls_identities.join(","),
                    )
                );
                return Err(Status::permission_denied(""));
            }
        };

        csr.params.subject_alt_names = vec![SanType::Rfc822Name(authorization.common_name.clone())];
        csr.params.serial_number = Some(authorization.serial as u64);
        csr.params.is_ca = rcgen::IsCa::NoCa;
        csr.params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        csr.params.extended_key_usages = vec![];
        csr.params.name_constraints = None;
        csr.params.custom_extensions = authorization.extensions.clone();
        csr.params.distinguished_name = DistinguishedName::new();
        csr.params.distinguished_name.push(
            DnType::OrganizationName,
            format!("Rustica-{}", &authorization.authority),
        );
        csr.params
            .distinguished_name
            .push(DnType::CommonName, &authorization.common_name);
        csr.params.use_authority_key_identifier_extension = false;

        csr.params.not_before =
            (UNIX_EPOCH + Duration::from_secs(authorization.valid_after)).into();
        csr.params.not_after =
            (UNIX_EPOCH + Duration::from_secs(authorization.valid_before)).into();

        let ca_cert = self
            .signer
            .get_x509_certificate_authority(&authorization.authority)
            .map_err(|_| Status::permission_denied("message"))?;
        let cert = csr.serialize_der_with_signer(ca_cert).unwrap();

        // Assert that the CSR contains the same public key as the provided
        // leaf. Ideally we would check this first but rcgen does not seem
        // to provide anyway for that to happen.
        let (_, new_certificate) = match X509Certificate::from_der(&cert) {
            Ok(c) => c,
            Err(e) => {
                rustica_error!(
                    self,
                    format!(
                        "Could not parse new certificate for [{}]. Error: [{e}]",
                        mtls_identities.join(","),
                    )
                );
                return Err(Status::permission_denied(""));
            }
        };

        let (_, leaf) = match X509Certificate::from_der(&request.attestation) {
            Ok(l) => l,
            Err(e) => {
                rustica_error!(
                    self,
                    format!(
                        "Could not parse provided attestation for [{}]. Error: [{e}]",
                        mtls_identities.join(","),
                    )
                );
                return Err(Status::permission_denied(""));
            }
        };

        if new_certificate.tbs_certificate.subject_pki != leaf.tbs_certificate.subject_pki {
            rustica_error!(
                self,
                format!(
                    "A CSR was submitted that didn't match their attestation chain by [{}]",
                    mtls_identities.join(","),
                )
            );

            return Err(Status::permission_denied(""));
        }

        let _ = self
            .log_sender
            .send(Log::X509CertificateIssued(X509CertificateIssued {
                authority: authority.to_string(),
                mtls_identities,
                extensions: authorization
                    .extensions
                    .iter()
                    .map(|e| {
                        (
                            format!(
                                "{}",
                                e.oid_components()
                                    .map(|x| x.to_string())
                                    .collect::<Vec<String>>()
                                    .join(".")
                            ),
                            format!("{}", hex::encode(e.content())),
                        )
                    })
                    .collect(),
                valid_after: authorization.valid_after,
                valid_before: authorization.valid_before,
                serial: authorization.serial,
            }));

        // Return certificate
        return Ok(Response::new(X509CertificateResponse {
            certificate: cert,
            error: "".to_owned(),
            error_code: 0,
        }));
    }
}
