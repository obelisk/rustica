ALTER TABLE registered_keys ADD COLUMN auth_data text;
ALTER TABLE registered_keys ADD COLUMN auth_data_signature text;
ALTER TABLE registered_keys ADD COLUMN aaguid text;
ALTER TABLE registered_keys ADD COLUMN challenge text;
ALTER TABLE registered_keys ADD COLUMN alg integer;
ALTER TABLE registered_keys ADD COLUMN application text;