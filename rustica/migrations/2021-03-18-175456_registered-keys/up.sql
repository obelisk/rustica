CREATE TABLE registered_keys (
	fingerprint TEXT PRIMARY KEY NOT NULL,
    user TEXT NOT NULL,
	pin_policy TEXT NULL,
	touch_policy TEXT NULL,
	hsm_serial TEXT NULL,
	firmware TEXT NULL,
	attestation_certificate TEXT NULL,
	attestation_intermediate TEXT NULL
);