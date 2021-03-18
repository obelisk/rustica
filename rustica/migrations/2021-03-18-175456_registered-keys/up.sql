CREATE TABLE registered_keys (
	id BIGINT PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
    user TEXT NOT NULL,
	attestation_data TEXT NOT NULL,
    UNIQUE(fingerprint)
);