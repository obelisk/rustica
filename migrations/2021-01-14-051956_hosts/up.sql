CREATE TABLE hosts (
	hostname TEXT PRIMARY KEY,
	fingerprint TEXT NOT NULL
);

CREATE TABLE fingerprint_user_authorizations (
	id INTEGER PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
	username TEXT NOT NULL
);

CREATE TABLE fingerprint_host_authorizations (
	id INTEGER PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
	hostname TEXT NOT NULL
);

CREATE TABLE fingerprint_permissions (
	fingerprint TEXT PRIMARY KEY NOT NULL,
	host_unrestricted BOOLEAN DEFAULT FALSE NOT NULL
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
INSERT INTO fingerprint_user_authorizations VALUES (0, "jHFJGs/3e5ewMEJTidMEoR23nfxao3Szkpos3eRhQkc", "obelisk");

-- Adding multiple principals to a single key
INSERT INTO fingerprint_user_authorizations VALUES (1, "0iJ4L6ehoaggjT6criBGTnWvDtWGSjw3Sg33aTpVyCs", "obelisk");
INSERT INTO fingerprint_user_authorizations VALUES (2, "0iJ4L6ehoaggjT6criBGTnWvDtWGSjw3Sg33aTpVyCs", "mitchell");

-- This is a touch key but you can't tell here
INSERT INTO fingerprint_user_authorizations VALUES (3, "CiYONGZzXXeZpQVEg6msi51EmKijhfvhfRFQRIauSQc", "obelisk");

-- ---------------------------
-- Example Host Authorizations
-- ---------------------------
INSERT INTO fingerprint_host_authorizations VALUES (0, "jHFJGs/3e5ewMEJTidMEoR23nfxao3Szkpos3eRhQkc", "atheris");
INSERT INTO fingerprint_host_authorizations VALUES (1, "0iJ4L6ehoaggjT6criBGTnWvDtWGSjw3Sg33aTpVyCs", "otherserver");

-- ----------------------------------
-- Example Permissions Authorizations
-- ----------------------------------
INSERT INTO fingerprint_permissions VALUES ("CiYONGZzXXeZpQVEg6msi51EmKijhfvhfRFQRIauSQc", TRUE);