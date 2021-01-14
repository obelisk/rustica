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
pub struct FingerprintPermission {
    pub fingerprint: String,
    pub extensions: String,
    pub critical_options: String,
}