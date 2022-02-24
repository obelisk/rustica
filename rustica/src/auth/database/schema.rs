table! {
    fingerprint_critical_options (id) {
        id -> BigInt,
        fingerprint -> Text,
        critical_option_name -> Text,
        critical_option_value -> Nullable<Text>,
    }
}

table! {
    fingerprint_extensions (id) {
        id -> BigInt,
        fingerprint -> Text,
        extension_name -> Text,
        extension_value -> Nullable<Text>,
    }
}

table! {
    fingerprint_host_authorizations (id) {
        id -> BigInt,
        fingerprint -> Text,
        hostname -> Text,
    }
}

table! {
    fingerprint_permissions (fingerprint) {
        fingerprint -> Text,
        host_unrestricted -> Bool,
        principal_unrestricted -> Bool,
        can_create_host_certs -> Bool,
        can_create_user_certs -> Bool,
        max_creation_time -> BigInt,
    }
}

table! {
    fingerprint_principal_authorizations (id) {
        id -> BigInt,
        fingerprint -> Text,
        principal -> Text,
    }
}

table! {
    hosts (hostname) {
        hostname -> Nullable<Text>,
        fingerprint -> Text,
    }
}

table! {
    registered_keys (fingerprint) {
        fingerprint -> Text,
        user -> Text,
        pin_policy -> Nullable<Text>,
        touch_policy -> Nullable<Text>,
        hsm_serial -> Nullable<Text>,
        firmware -> Nullable<Text>,
        attestation_certificate -> Nullable<Text>,
        attestation_intermediate -> Nullable<Text>,
        auth_data -> Nullable<Text>,
        auth_data_signature -> Nullable<Text>,
        aaguid -> Nullable<Text>,
    }
}

allow_tables_to_appear_in_same_query!(
    fingerprint_critical_options,
    fingerprint_extensions,
    fingerprint_host_authorizations,
    fingerprint_permissions,
    fingerprint_principal_authorizations,
    hosts,
    registered_keys,
);
