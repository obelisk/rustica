pub mod schema;
pub mod models;

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;

use serde::Deserialize;

use std::collections::HashMap;
use std::time::SystemTime;
use crate::key::TouchPolicy;

use super::{
    SshAuthorization,
    AuthorizationError,
    SshAuthorizationRequestProperties,
    RegisterKeyRequestProperties,
    KeyAttestation,
    X509AuthorizationRequestProperties,
    X509Authorization,
    SignerList,
    Signer,
};

use sshcerts::ssh::CertType;

#[derive(Deserialize)]
pub struct LocalDatabase {
    pub path: String,
}

fn establish_connection(path: &str) -> SqliteConnection {
        SqliteConnection::establish(path)
        .unwrap_or_else(|_| panic!("Error connecting to {}", path))
}

impl LocalDatabase {
    pub fn authorize_ssh_cert(&self, req: &SshAuthorizationRequestProperties) -> Result<SshAuthorization, AuthorizationError> {
        let fp = &req.fingerprint;
        let current_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(ts) => ts.as_secs(),
            // Start with E because in the case we do hit this, adding a time to it below
            // does not create an overflow
            Err(_e) => 0xEFFFFFFFFFFFFFFF,
        };

        let mut conn = establish_connection(&self.path);
        let principals = {
            use schema::fingerprint_principal_authorizations::dsl::*;
            let results = fingerprint_principal_authorizations.filter(fingerprint.eq(fp).and(authority.eq(&req.authority)))
                .load::<models::FingerprintPrincipalAuthorization>(&mut conn)
                .expect("Error loading authorized hosts");
            
            results.into_iter().map(|x| x.principal).collect()
        };

        let hosts = {
            use schema::fingerprint_host_authorizations::dsl::*;

            let results = fingerprint_host_authorizations.filter(fingerprint.eq(fp).and(authority.eq(&req.authority)))
                .load::<models::FingerprintHostAuthorization>(&mut conn)
                .expect("Error loading authorized hosts");
            
            Some(results.into_iter().map(|x| x.hostname).collect())
        };

        let extensions: HashMap<String, String> = {
            use schema::fingerprint_extensions::dsl::*;

            let results = fingerprint_extensions.filter(fingerprint.eq(fp).and(authority.eq(&req.authority)))
                .load::<models::FingerprintExtension>(&mut conn)
                .expect("Error loading fingerprint extensions");
            
            results.into_iter().map(|x| (x.extension_name, x.extension_value.unwrap_or(String::new()))).collect()
        };

        {
            use schema::fingerprint_permissions::dsl::*;
            let results = fingerprint_permissions.filter(fingerprint.eq(fp).and(authority.eq(&req.authority)))
                .load::<models::FingerprintPermission>(&mut conn)
                .expect("Error loading authorized hosts");
            
            if !results.is_empty() {
                match req.cert_type {
                    CertType::User => {
                        if !results[0].can_create_user_certs {
                            return Err(AuthorizationError::CertType)
                        }
                    },
                    CertType::Host => {
                        if !results[0].can_create_host_certs {
                            return Err(AuthorizationError::CertType)
                        }
                    }
                };

                Ok(SshAuthorization {
                    serial: 0x000000000000000,
                    // When principal is unrestricted, we just pass their requested principals through
                    principals: if results[0].principal_unrestricted {req.principals.clone()} else {principals},
                    // When host is unrestricted we return None
                    hosts: if results[0].host_unrestricted {None} else {hosts},
                    extensions,
                    force_command: None,
                    force_source_ip: false,
                    valid_after: req.valid_after,
                    valid_before: current_timestamp + results[0].max_creation_time as u64,
                    authority: req.authority.clone(),
                })
            } else {
                Err(AuthorizationError::NotAuthorized)
            }
        }
    }
    
    pub fn register_key(&self, req: &RegisterKeyRequestProperties) -> Result<(), AuthorizationError> {
        let mut conn = establish_connection(&self.path);
        let mut registered_key = models::RegisteredKey {
            fingerprint: req.fingerprint.clone(),
            pubkey: req.pubkey.clone(),
            user: req.mtls_identities.join(","),
            firmware: None,
            hsm_serial: None,
            touch_policy: None,
            pin_policy: None,
            attestation_certificate: None,
            attestation_intermediate: None,
            auth_data: None,
            auth_data_signature: None,
            aaguid: None,
            challenge: None,
            alg: None,
            application: None,
        };

        match &req.attestation {
            Some(KeyAttestation::Piv(attestation)) => {
                registered_key.firmware = Some(attestation.firmware.clone());
                registered_key.hsm_serial = Some(attestation.serial.to_string());
                registered_key.touch_policy = Some(attestation.touch_policy.to_string());
                registered_key.pin_policy = Some(attestation.pin_policy.to_string());
                registered_key.attestation_certificate = Some(hex::encode(&attestation.certificate));
                registered_key.attestation_intermediate = Some(hex::encode(&attestation.intermediate));
            },
            Some(KeyAttestation::U2f(attestation)) => {
                registered_key.firmware = Some(attestation.firmware.clone());
                registered_key.attestation_intermediate = Some(hex::encode(&attestation.intermediate));
                registered_key.auth_data = Some(hex::encode(&attestation.auth_data));
                registered_key.auth_data_signature = Some(hex::encode(&attestation.auth_data_signature));
                registered_key.aaguid = Some(hex::encode(&attestation.aaguid));
                registered_key.challenge = Some(hex::encode(&attestation.challenge));
                registered_key.alg = Some(attestation.alg);
                registered_key.application = Some(hex::encode(&attestation.application));
            }
            _ => {},
        };

        let result = {
            use schema::registered_keys::dsl::*;
            diesel::insert_into(registered_keys)
                .values(&registered_key)
                .execute(&mut conn)
        };

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(AuthorizationError::DatabaseError(format!("{}", e))),
        }
    }

    pub fn authorize_attested_x509_cert(
        &self,
        auth_props: &X509AuthorizationRequestProperties,
    ) -> Result<X509Authorization, AuthorizationError> {
        let mut conn = establish_connection(&self.path);

        let (att_serial, touch_policy) = match &auth_props.key.attestation {
            None => return Err(AuthorizationError::AuthorizerError),
            Some(KeyAttestation::U2f(_)) => return Err(AuthorizationError::AuthorizerError),
            Some(KeyAttestation::Piv(att)) => (att.serial, &att.touch_policy)
        };

        let mtls_user = auth_props.mtls_identities.get(0).ok_or(AuthorizationError::AuthorizerError)?;

        let authorization: Vec<_> = {
            use schema::x509_authorizations::dsl::*;
            let results = x509_authorizations.filter(user.eq(mtls_user).and(authority.eq(&auth_props.authority).and(hsm_serial.eq(att_serial.to_string()))))
                .load::<models::X509Authorization>(&mut conn)
                .expect("Error loading authorized hosts");
            
            results.into_iter().collect()
        };

        let authorization = authorization.get(0).ok_or(AuthorizationError::NotAuthorized)?;

        // If we require touch but the touch policy is never then we will not
        // allow the fetching of a certificate. The other options Always or
        // cached both require some form of presence.
        if authorization.require_touch && *touch_policy == TouchPolicy::Never {
            return Err(AuthorizationError::NotAuthorized)
        }

        let current_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

        // Success, build the response
        return Ok(X509Authorization {
            authority: auth_props.authority.clone(),
            issuer: format!("Rustica"),
            common_name: mtls_user.clone(),
            sans: vec![mtls_user.clone()],
            extensions: vec![],
            serial: 0xFEFEFEFEFE,
            valid_before: current_time + (3600 * 12), // 12 hours
            valid_after: current_time,
        })
    }

    pub fn get_signer_list(&self) -> Result<SignerList, AuthorizationError> {
        let mut conn = establish_connection(&self.path);

        let result = {
            use schema::registered_keys::dsl::*;

            // Fetch every pubkey and the owner's identity
            schema::registered_keys::table
                .select((user, pubkey))
                .load(&mut conn)
        };

        if let Err(e) = result {
            return Err(AuthorizationError::DatabaseError(format!("{}", e)));
        }

        // Get the response from the backend service
        let signers: Vec<(String, String)> = result.unwrap();
        let signers = signers.into_iter()
            .map(|signer| Signer{
                identity: signer.0,
                pubkey: signer.1,
            })
            .collect();

        Ok(SignerList{ signers })
    }
}
