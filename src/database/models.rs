#[derive(Queryable)]
pub struct Host {
    pub hostname: String,
    pub fingerprint: String,
}

#[derive(Queryable)]
pub struct FingerprintUserAuthorization {
    pub id: i32,
    pub fingerprint: String,
    pub username: String,
}

#[derive(Queryable)]
pub struct FingerprintHostAuthorization {
    pub id: i32,
    pub fingerprint: String,
    pub hostname: String,
}

#[derive(Queryable)]
pub struct FingerprintPermission {
    pub fingerprint: String,
    pub host_unrestricted: bool,
    pub can_create_host_certs: bool,
}