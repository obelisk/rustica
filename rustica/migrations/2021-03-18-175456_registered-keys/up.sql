CREATE TABLE registered_keys (
	fingerprint TEXT PRIMARY KEY NOT NULL,
	pubkey TEXT NOT NULL,
	user TEXT NOT NULL,
	pin_policy TEXT NULL,
	touch_policy TEXT NULL,
	hsm_serial TEXT NULL,
	firmware TEXT NULL,
	attestation_certificate TEXT NULL,
	attestation_intermediate TEXT NULL,
	auth_data TEXT NULL,
	auth_data_signature TEXT NULL,
	aaguid TEXT NULL,
	challenge TEXT NULL,
	alg INTEGER NULL,
	application TEXT NULL
);
