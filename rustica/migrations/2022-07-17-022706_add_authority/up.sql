DROP TABLE fingerprint_permissions;
DROP TABLE fingerprint_principal_authorizations;
DROP TABLE fingerprint_extensions;
DROP TABLE fingerprint_critical_options;
DROP TABLE fingerprint_host_authorizations;

CREATE TABLE fingerprint_principal_authorizations (
	fingerprint TEXT NOT NULL,
	principal TEXT NOT NULL,
    authority TEXT NOT NULL,
    PRIMARY KEY (fingerprint, principal, authority)
);

CREATE TABLE fingerprint_host_authorizations (
	fingerprint TEXT NOT NULL,
	hostname TEXT NOT NULL,
    authority TEXT NOT NULL,
    PRIMARY KEY (fingerprint, hostname, authority)
);

CREATE TABLE fingerprint_permissions (
	fingerprint TEXT NOT NULL,
	host_unrestricted BOOLEAN DEFAULT FALSE NOT NULL,
	principal_unrestricted BOOLEAN DEFAULT FALSE NOT NULL,
	can_create_host_certs BOOLEAN DEFAULT FALSE NOT NULL,
	can_create_user_certs BOOLEAN DEFAULT FALSE NOT NULL,
	max_creation_time BIGINT DEFAULT 10 NOT NULL,
    authority TEXT NOT NULL,
    PRIMARY KEY (fingerprint, authority)
);

CREATE TABLE fingerprint_extensions (
	fingerprint TEXT NOT NULL,
	extension_name TEXT NOT NULL,
	extension_value TEXT NULL,
    authority TEXT NOT NULL,
    PRIMARY KEY (fingerprint, authority, extension_name)
);

CREATE TABLE fingerprint_critical_options (
	fingerprint TEXT NOT NULL,
	critical_option_name TEXT NOT NULL,
	critical_option_value TEXT NULL,
    authority TEXT NOT NULL,
    PRIMARY KEY (fingerprint, authority, critical_option_name)
);