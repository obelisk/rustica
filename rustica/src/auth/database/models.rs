use super::schema::registered_keys;

#[derive(Queryable)]
pub struct Host {
    pub hostname: String,
    pub fingerprint: String,
}

#[derive(Queryable)]
pub struct FingerprintPrincipalAuthorization {
    pub id: i64,
    pub fingerprint: String,
    pub principal: String,
}

#[derive(Queryable)]
pub struct FingerprintHostAuthorization {
    pub id: i64,
    pub fingerprint: String,
    pub hostname: String,
}

#[derive(Queryable)]
pub struct FingerprintPermission {
    pub fingerprint: String,
    pub host_unrestricted: bool,
    pub principal_unrestricted: bool,
    pub can_create_host_certs: bool,
    pub can_create_user_certs: bool,
    pub max_creation_time: i64,
}

#[derive(Insertable)]
#[table_name = "registered_keys"]
pub struct RegisteredKey {
    pub fingerprint: String,
    pub user: String,
    pub pin_policy: Option<String>,
    pub touch_policy: Option<String>,
    pub hsm_serial: Option<String>,
    pub firmware: Option<String>,
    pub attestation_certificate: Option<String>,
    pub attestation_intermediate: Option<String>,
    pub auth_data: Option<String>,
    pub auth_data_signature: Option<String>,
    pub aaguid: Option<String>,
}