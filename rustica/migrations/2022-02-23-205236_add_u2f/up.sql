ALTER TABLE registered_keys ADD COLUMN auth_data text;
ALTER TABLE registered_keys ADD COLUMN auth_data_signature text;
ALTER TABLE registered_keys ADD COLUMN aaguid text;