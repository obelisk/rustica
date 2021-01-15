CREATE TABLE hosts (
	hostname TEXT PRIMARY KEY,
	fingerprint TEXT NOT NULL
);

CREATE TABLE fingerprint_user_authorizations (
	id INTEGER PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
	username TEXT NOT NULL
);

CREATE TABLE fingerprint_permissions (
	fingerprint TEXT PRIMARY KEY,
	extensions TEXT NULL,
	critical_options TEXT NULL
);

-- The following line will allow the user with the private key of the fingerprint below
-- to login to servers as the "obelisk" user
INSERT INTO fingerprint_user_authorizations VALUES (0, "jHFJGs/3e5ewMEJTidMEoR23nfxao3Szkpos3eRhQkc", "obelisk");
-- The following line shows adding multiple principals to a single key
INSERT INTO fingerprint_user_authorizations VALUES (1, "jHFJGs/3e5ewMEJTidMEoR23nfxao3Szkpos3eRhQkc", "mitchell");