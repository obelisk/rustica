-- Revert registered keys
DROP TABLE registered_keys;
CREATE TABLE registered_keys (
	fingerprint TEXT PRIMARY KEY NOT NULL,
    user TEXT NOT NULL,
	pin_policy TEXT NULL,
	touch_policy TEXT NULL,
	hsm_serial TEXT NULL,
	firmware TEXT NULL,
	attestation_certificate TEXT NULL,
	attestation_intermediate TEXT NULL,
    auth_data TEXT,
    auth_data_signature TEXT,
    aaguid TEXT,
    challenge TEXT,
    alg INTEGER,
    application TEXT
);

DROP TABLE fingerprint_principal_authorizations;
CREATE TABLE fingerprint_principal_authorizations (
	id BIGINT PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
	principal TEXT NOT NULL
);

DROP TABLE fingerprint_extensions;
CREATE TABLE fingerprint_extensions (
	id BIGINT PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
	extension_name TEXT NOT NULL,
	extension_value TEXT NULL
);

DROP TABLE fingerprint_critical_options;
CREATE TABLE fingerprint_critical_options (
	id BIGINT PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
	critical_option_name TEXT NOT NULL,
	critical_option_value TEXT NULL
);

DROP TABLE fingerprint_host_authorizations;
CREATE TABLE fingerprint_host_authorizations (
	id BIGINT PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
	hostname TEXT NOT NULL
);