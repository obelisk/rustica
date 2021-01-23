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
INSERT INTO fingerprint_principal_authorizations VALUES (0, "id2n9OXvk0phR9jIvKtfaNkj6E1RnY6TY+xVbcvSAdU", "obelisk");
INSERT INTO fingerprint_principal_authorizations VALUES (1, "0ZUOTCC6OQ7kwHJ8lXx16pICBFErB48I4rGe4wVXfW8", "test");

-- Set of host fingerprints to request new host certs
INSERT INTO fingerprint_principal_authorizations VALUES (10000, "tSjINWcJyEdaJ/h6pk2E50WPTWcKqcZq9VtVSorbnQs", "atheris");
INSERT INTO fingerprint_principal_authorizations VALUES (10002, "UdHSTiz4PuRtMlvfqE0s5FXcRxZQSxYF0LxgADTtyq0", "elderfuthark");
INSERT INTO fingerprint_principal_authorizations VALUES (10003, "reSociydTR9Hia97c+jWzv+qd4hGHXIyQwQP2m+OoMI", "chaos");
INSERT INTO fingerprint_principal_authorizations VALUES (10004, "mqouqeykZRMvHYCKjmBISMNiu8zcZP6BftYYR4swjG8", "tigstack");

-- ---------------------------
-- Example Host Authorizations
-- ---------------------------
-- INSERT INTO fingerprint_host_authorizations VALUES (0, "tSjINWcJyEdaJ/h6pk2E50WPTWcKqcZq9VtVSorbnQs", "elderfuthark");
-- INSERT INTO fingerprint_host_authorizations VALUES (1, "UdHSTiz4PuRtMlvfqE0s5FXcRxZQSxYF0LxgADTtyq0", "elderfuthark");
-- INSERT INTO fingerprint_host_authorizations VALUES (0, "2GSQ3qA1iT2xH/1o0GSI7xzOe581voW3zCsFfF+Ursg", "atheris");
-- INSERT INTO fingerprint_host_authorizations VALUES (1, "0iJ4L6ehoaggjT6criBGTnWvDtWGSjw3Sg33aTpVyCs", "otherserver");

-- ----------------------------------
-- Example Permissions Authorizations
-- ----------------------------------
-- Seconds in 100 years: 3153600000

-- Host Fingerprint Permissions 
INSERT INTO fingerprint_permissions VALUES ("tSjINWcJyEdaJ/h6pk2E50WPTWcKqcZq9VtVSorbnQs", FALSE, FALSE, TRUE, FALSE, 3153600000);
INSERT INTO fingerprint_permissions VALUES ("UdHSTiz4PuRtMlvfqE0s5FXcRxZQSxYF0LxgADTtyq0", FALSE, FALSE, TRUE, FALSE, 3153600000);
INSERT INTO fingerprint_permissions VALUES ("reSociydTR9Hia97c+jWzv+qd4hGHXIyQwQP2m+OoMI", FALSE, FALSE, TRUE, FALSE, 3153600000);
INSERT INTO fingerprint_permissions VALUES ("mqouqeykZRMvHYCKjmBISMNiu8zcZP6BftYYR4swjG8", FALSE, FALSE, TRUE, FALSE, 3153600000);

-- User Fingerprint Permissions
INSERT INTO fingerprint_permissions VALUES ("id2n9OXvk0phR9jIvKtfaNkj6E1RnY6TY+xVbcvSAdU", TRUE, FALSE, FALSE, TRUE, 10);
INSERT INTO fingerprint_permissions VALUES ("0ZUOTCC6OQ7kwHJ8lXx16pICBFErB48I4rGe4wVXfW8", TRUE, FALSE, FALSE, TRUE, 10);
