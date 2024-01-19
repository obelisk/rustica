table! {
    fingerprint_critical_options (fingerprint, critical_option_name, authority) {
        fingerprint -> Text,
        critical_option_name -> Text,
        critical_option_value -> Nullable<Text>,
        authority -> Text,
    }
}

table! {
    fingerprint_extensions (fingerprint, extension_name, authority) {
        fingerprint -> Text,
        extension_name -> Text,
        extension_value -> Nullable<Text>,
        authority -> Text,
    }
}

table! {
    fingerprint_host_authorizations (fingerprint, hostname, authority) {
        fingerprint -> Text,
        hostname -> Text,
        authority -> Text,
    }
}

table! {
    fingerprint_permissions (fingerprint, authority) {
        fingerprint -> Text,
        host_unrestricted -> Bool,
        principal_unrestricted -> Bool,
        can_create_host_certs -> Bool,
        can_create_user_certs -> Bool,
        max_creation_time -> BigInt,
        authority -> Text,
    }
}

table! {
    fingerprint_principal_authorizations (fingerprint, principal, authority) {
        fingerprint -> Text,
        principal -> Text,
        authority -> Text,
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
        challenge -> Nullable<Text>,
        alg -> Nullable<Integer>,
        application -> Nullable<Text>,
    }
}

table! {
    x509_authorizations (user, hsm_serial) {
        user -> Text,
        hsm_serial -> Text,
        require_touch -> Bool,
        authority -> Text,
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
    x509_authorizations,
);
