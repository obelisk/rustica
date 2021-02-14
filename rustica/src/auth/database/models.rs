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