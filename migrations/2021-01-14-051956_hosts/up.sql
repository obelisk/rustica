CREATE TABLE hosts (
	hostname TEXT PRIMARY KEY,
	fingerprint TEXT NOT NULL
);

CREATE TABLE fingerprint_principal_authorizations (
	id INTEGER PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
	principal TEXT NOT NULL
);

CREATE TABLE fingerprint_host_authorizations (
	id INTEGER PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
	hostname TEXT NOT NULL
);

CREATE TABLE fingerprint_permissions (
	fingerprint TEXT PRIMARY KEY NOT NULL,
	host_unrestricted BOOLEAN DEFAULT FALSE NOT NULL,
	principal_unrestricted BOOLEAN DEFAULT FALSE NOT NULL,
	can_create_host_certs BOOLEAN DEFAULT FALSE NOT NULL,
	can_create_user_certs BOOLEAN DEFAULT FALSE NOT NULL,
	max_creation_time INT DEFAULT 10 NOT NULL
);

CREATE TABLE fingerprint_extensions (
	id INTEGER PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
	extension_name TEXT NOT NULL,
	extension_value TEXT NULL
);

CREATE TABLE fingerprint_critical_options (
	id INTEGER PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
	critical_option_name TEXT NOT NULL,
	critical_option_value TEXT NULL
);

-- --------------------------
-- Example Key Authorizations
-- --------------------------
-- The following line will allow the user with the private key of the fingerprint below
-- to login to servers as the "obelisk" user
-- INSERT INTO fingerprint_principal_authorizations VALUES (0, "jHFJGs/3e5ewMEJTidMEoR23nfxao3Szkpos3eRhQkc", "obelisk");

-- Adding multiple principals to a single key
 INSERT INTO fingerprint_principal_authorizations VALUES (1, "tSjINWcJyEdaJ/h6pk2E50WPTWcKqcZq9VtVSorbnQs", "atheris");
 INSERT INTO fingerprint_principal_authorizations VALUES (2, "RtvzDxDR6qpTsy4nGnGFIsh2z1OFdOgSZVY9R1LORLU", "obelisk");

-- This is a touch key but you can't tell here
-- INSERT INTO fingerprint_principal_authorizations VALUES (3, "CiYONGZzXXeZpQVEg6msi51EmKijhfvhfRFQRIauSQc", "obelisk");

-- ---------------------------
-- Example Host Authorizations
-- ---------------------------
 INSERT INTO fingerprint_host_authorizations VALUES (0, "RtvzDxDR6qpTsy4nGnGFIsh2z1OFdOgSZVY9R1LORLU", "atheris");
-- INSERT INTO fingerprint_host_authorizations VALUES (1, "0iJ4L6ehoaggjT6criBGTnWvDtWGSjw3Sg33aTpVyCs", "otherserver");

-- ----------------------------------
-- Example Permissions Authorizations
-- ----------------------------------
-- Seconds in 100 years: 3153600000
INSERT INTO fingerprint_permissions VALUES ("tSjINWcJyEdaJ/h6pk2E50WPTWcKqcZq9VtVSorbnQs", FALSE, FALSE, TRUE, FALSE, 3153600000);
INSERT INTO fingerprint_permissions VALUES ("RtvzDxDR6qpTsy4nGnGFIsh2z1OFdOgSZVY9R1LORLU", FALSE, FALSE, FALSE, TRUE, 10);
