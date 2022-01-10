CREATE TABLE hosts (
	hostname TEXT PRIMARY KEY,
	fingerprint TEXT NOT NULL
);

CREATE TABLE fingerprint_principal_authorizations (
	id BIGINT PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
	principal TEXT NOT NULL
);

CREATE TABLE fingerprint_host_authorizations (
	id BIGINT PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
	hostname TEXT NOT NULL
);

CREATE TABLE fingerprint_permissions (
	fingerprint TEXT PRIMARY KEY NOT NULL,
	host_unrestricted BOOLEAN DEFAULT FALSE NOT NULL,
	principal_unrestricted BOOLEAN DEFAULT FALSE NOT NULL,
	can_create_host_certs BOOLEAN DEFAULT FALSE NOT NULL,
	can_create_user_certs BOOLEAN DEFAULT FALSE NOT NULL,
	max_creation_time BIGINT DEFAULT 10 NOT NULL
);

CREATE TABLE fingerprint_extensions (
	id BIGINT PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
	extension_name TEXT NOT NULL,
	extension_value TEXT NULL
);

CREATE TABLE fingerprint_critical_options (
	id BIGINT PRIMARY KEY NOT NULL,
	fingerprint TEXT NOT NULL,
	critical_option_name TEXT NOT NULL,
	critical_option_value TEXT NULL
);

-- --------------------------
-- Example Key Authorizations
-- --------------------------
-------------------------------------------------------------------------------
-- This is the database abstraction over SSH certificate principals. When a   -
-- comes in from one of these key IDs, these are the principals that will be  -
-- baked into the certificate                                                 -
--                                                                            -
-- For example:                                                               -
-- ID "id2n9OXvk0phR9jIvKtfaNkj6E1RnY6TY+xVbcvSAdU" will receive a certificate-
-- containing only the "obelisk" principal                                    -
--                                                                            -
-- ID "0ZUOTCC6OQ7kwHJ8lXx16pICBFErB48I4rGe4wVXfW8" will receive a certificate-
-- containing the "obelisk" and "mitchell" principals                         -
-------------------------------------------------------------------------------
-- 
INSERT INTO fingerprint_principal_authorizations VALUES (0, "oMNBoPp8pTCkeJoe2dzhFKm/grZ1qFlqmaKS9dBGHNY", "testuser");
-- INSERT INTO fingerprint_principal_authorizations VALUES (1, "0ZUOTCC6OQ7kwHJ8lXx16pICBFErB48I4rGe4wVXfW8", "test");
-- INSERT INTO fingerprint_principal_authorizations VALUES (2, "0ZUOTCC6OQ7kwHJ8lXx16pICBFErB48I4rGe4wVXfW8", "mitchell");


-------------------------------------------------------------------------------
-- When a host (not user) requests a new certificate, the hostname must be the-
-- only principal in the certificate. You would thus expect these to be a     -
-- mostly 1:1 mapping                                                         -
--                                                                            -
-- For example:                                                               -
-- ID "tSjINWcJyEdaJ/h6pk2E50WPTWcKqcZq9VtVSorbnQs" will receive a certificate-
-- containing only the "host1" principal                                      -
-------------------------------------------------------------------------------

-- INSERT INTO fingerprint_principal_authorizations VALUES (10001, "tSjINWcJyEdaJ/h6pk2E50WPTWcKqcZq9VtVSorbnQs", "host1");
-- INSERT INTO fingerprint_principal_authorizations VALUES (10002, "UdHSTiz4PuRtMlvfqE0s5FXcRxZQSxYF0LxgADTtyq0", "host2");
-- INSERT INTO fingerprint_principal_authorizations VALUES (10003, "reSociydTR9Hia97c+jWzv+qd4hGHXIyQwQP2m+OoMI", "host3");
-- INSERT INTO fingerprint_principal_authorizations VALUES (10004, "mqouqeykZRMvHYCKjmBISMNiu8zcZP6BftYYR4swjG8", "host4");
-- ---------------------------
-- Example Host Authorizations
-- ---------------------------
-------------------------------------------------------------------------------
-- When a key is host restricted (the default) they may only login to certain -
-- hosts (controlled by a bash script baked into the certificate). That bash  -
-- script will only start a shell if the hostname of the server is the list   -
-- contained within the script. This table controls the hostnames that go into-
-- that list.                                                                 -
--                                                                            -
-- For example:                                                               -
-- ID "tSjINWcJyEdaJ/h6pk2E50WPTWcKqcZq9VtVSorbnQs" can start a shell on      -
-- "host1"                                                                    -
--                                                                            -
-- ID "UdHSTiz4PuRtMlvfqE0s5FXcRxZQSxYF0LxgADTtyq0" can start a shell on      -
-- "host2" and "host3"                                                        -
--                                                                            -
-- ID "0iJ4L6ehoaggjT6criBGTnWvDtWGSjw3Sg33aTpVyCs" can start a shell on      -
-- "host4"                                                                    -
-------------------------------------------------------------------------------

-- INSERT INTO fingerprint_host_authorizations VALUES (0, "tSjINWcJyEdaJ/h6pk2E50WPTWcKqcZq9VtVSorbnQs", "host1");
-- INSERT INTO fingerprint_host_authorizations VALUES (1, "UdHSTiz4PuRtMlvfqE0s5FXcRxZQSxYF0LxgADTtyq0", "host2");
-- INSERT INTO fingerprint_host_authorizations VALUES (2, "UdHSTiz4PuRtMlvfqE0s5FXcRxZQSxYF0LxgADTtyq0", "host3");
-- INSERT INTO fingerprint_host_authorizations VALUES (3, "0iJ4L6ehoaggjT6criBGTnWvDtWGSjw3Sg33aTpVyCs", "host4");

-- ----------------------------------
-- Example Permissions Authorizations
-- ----------------------------------
-- ----------------------------------------------------------------------------
-- Each key has 5 additional associated permissions. These govern how long    -
-- certificates for that key may be valid for, in addition to what kinds of   -
-- certificates that key may request.                                         -
--                                                                            -
-- In addition to that, keys may be designated HostUnrestricted or            -
-- PrincipalUnrestricted.                                                     -
--                                                                            -
-- HostUnrestricted                                                           -
-- ----------------                                                           -
-- When a key has this permission, no bash script controlling shell start will-
-- be inserted into an issued certificate. In effect, this means it can be    -
-- used to login to any server that recognizes the CA and allows logins for   -
-- any principal in the issued certificate.                                   -
--                                                                            -
-- PrincipalUnrestricted                                                      -
-- ---------------------                                                      -
-- When a key has this permission, they are allowed to request any principal  -
-- from Rustica and it will return a certificate containing those principals. -
-- This is extremely dangerous and should be used with extreme caution as it  -
-- designates this key the ability to login as any user.                      -
--                                                                            -
-- When these two permissions are applied to the same key it effectively      -
-- becomes similar to a "breakglass" identity. Having keys that may login to  -
-- any system, as any user, should be discouraged or disallowed all together  -
-- by policy.                                                                 -
--                                                                            -
-- There are two different "classes" of permission you see here: host and     -
-- user. Host permissions are generally longer lived (though they dont have to-
-- be) and in this example last for 100 years. This effectively means host    -
-- certificates would not ever be rotated. In order to do host certificate    -
-- rotation, the host would need to run rustica-agent itself to request a new -
-- certificate periodically.                                                  -
--                                                                            -
-- The other class is for user certificates. User certificates are expected to-
-- be extremely short lived (5 to 10 seconds) because they generally requested-
-- as they are needed. Keeping the MaxCreationTime short means a user needs to-
-- refresh their certificate on every use, meaning Rustica must be involved.  -
-- This presents a double edge sword, it's great for logging and revoking     -
-- access, but makes the infrastructure even more critical than it would      -
-- otherwise be.                                                              -
--                                                                            -
-- For example:                                                               -
-- ID "tSjINWcJyEdaJ/h6pk2E50WPTWcKqcZq9VtVSorbnQs" is:                       -
--		Host: 						Restricted                                -
--		Principal:					Restricted                                -
--		CreateHostCertificates:		Yes                                       -
--		CreateUserCertificates: 	No                                        -
--		Max Certificate Validity: 	100 years                                 -
--                                                                            -
-- ID "id2n9OXvk0phR9jIvKtfaNkj6E1RnY6TY+xVbcvSAdU" is:                       -
--		Host: 						Unrestricted                              -
--		Principal:					Restricted                                -
--		CreateHostCertificates:		No                                        -
--		CreateUserCertificates: 	Yes                                       -
--		Max Certificate Validity: 	10 seconds                                -
-------------------------------------------------------------------------------

-- Host Fingerprint Permissions 
-- INSERT INTO fingerprint_permissions VALUES ("tSjINWcJyEdaJ/h6pk2E50WPTWcKqcZq9VtVSorbnQs", FALSE, FALSE, TRUE, FALSE, 3153600000);
-- INSERT INTO fingerprint_permissions VALUES ("UdHSTiz4PuRtMlvfqE0s5FXcRxZQSxYF0LxgADTtyq0", FALSE, FALSE, TRUE, FALSE, 3153600000);
-- INSERT INTO fingerprint_permissions VALUES ("reSociydTR9Hia97c+jWzv+qd4hGHXIyQwQP2m+OoMI", FALSE, FALSE, TRUE, FALSE, 3153600000);
-- INSERT INTO fingerprint_permissions VALUES ("mqouqeykZRMvHYCKjmBISMNiu8zcZP6BftYYR4swjG8", FALSE, FALSE, TRUE, FALSE, 3153600000);

-- User Fingerprint Permissions
-- Fingerprint, HostUnrestricted, PrincipalUnrestricted, AllowHostCerts, AllowUserCerts, MaxCreationTime
INSERT INTO fingerprint_permissions VALUES ("oMNBoPp8pTCkeJoe2dzhFKm/grZ1qFlqmaKS9dBGHNY", TRUE, FALSE, FALSE, TRUE, 10);
-- INSERT INTO fingerprint_permissions VALUES ("0ZUOTCC6OQ7kwHJ8lXx16pICBFErB48I4rGe4wVXfW8", TRUE, FALSE, FALSE, TRUE, 10);