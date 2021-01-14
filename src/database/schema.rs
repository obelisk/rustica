table! {
    fingerprint_permissions (fingerprint) {
        fingerprint -> Nullable<Text>,
        extensions -> Nullable<Text>,
        critical_options -> Nullable<Text>,
    }
}

table! {
    fingerprint_user_authorizations (id) {
        id -> Integer,
        fingerprint -> Text,
        username -> Text,
    }
}

table! {
    hosts (hostname) {
        hostname -> Nullable<Text>,
        fingerprint -> Text,
    }
}

allow_tables_to_appear_in_same_query!(
    fingerprint_permissions,
    fingerprint_user_authorizations,
    hosts,
);
