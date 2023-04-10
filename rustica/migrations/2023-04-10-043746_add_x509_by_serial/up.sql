-- Your SQL goes here
CREATE TABLE x509_authorizations (
	user TEXT NOT NULL,
    hsm_serial TEXT NOT NULL,
    require_touch BOOLEAN NOT NULL,
    PRIMARY KEY (user, hsm_serial)
);