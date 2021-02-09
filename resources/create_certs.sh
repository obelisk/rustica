#!/bin/zsh
CONFIG="""
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost"""

# Echo out the config which will give us a localhost SAN
echo $CONFIG > rustica.ext

CONFIG="""
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = TestHost"""

# Echo out the config which will give us a localhost SAN
echo $CONFIG > client.ext

# Generate CA key and cert
openssl ecparam -genkey -name prime256v1 -noout -out ca.key
openssl req -x509 -new -key ca.key -nodes -days 3650 -out ca.pem -subj '/CN=RusticaRootCA'

# Generate Client CA key and cert
openssl ecparam -genkey -name prime256v1 -noout -out client_ca.key
openssl req -new -key client_ca.key -x509 -nodes -days 3650 -out client_ca.pem -subj '/CN=RusticaClientRootCA'

# ------------ Generate Private Keys For Test Infra ------------ #
# Generate Rustica server key
openssl ecparam -genkey -name prime256v1 -noout -out rustica_private.pem
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in rustica_private.pem -out rusticaserver.key
rm rustica_private.pem

# Generate Author server key
openssl ecparam -genkey -name prime256v1 -noout -out author_private.pem
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in author_private.pem -out authorserver.key
rm author_private.pem

# ------------ Generate CSRs For Test Infra ------------ #
# Create certificate signing request for Rustica server
openssl req -new -key rusticaserver.key -out rusticaserver.csr -subj '/CN=RusticaServer/O=Rustica/C=CA'
# Create certificate signing request for Author server
openssl req -new -key authorserver.key -out authorserver.csr -subj '/CN=Author/O=Rustica/C=CA'

# ------------ Generate Signed Certificates For Test Infra ------------ #
# Use the CA to generate the cert for Rustica sever
openssl x509 -req -in rusticaserver.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out rusticaserver.pem -days 825 -sha256 -extfile rustica.ext
# Use the CA to generate the cert for Author sever
openssl x509 -req -in authorserver.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out authorserver.pem -days 825 -sha256 -extfile rustica.ext

# ------------ Generate Signed Certificates For Test Clients ------------ #
# Generate TestHost key
openssl ecparam -genkey -name prime256v1 -noout -out testhost_private.pem
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in testhost_private.pem -out testhost.key
rm testhost_private.pem

# Generate TestHost CSR
openssl req -new -key testhost.key -out testhost.csr -subj '/CN=TestHost/O=Rustica/C=CA'

# Generate TestHost Certificate
openssl x509 -req -in testhost.csr -CA client_ca.pem -CAkey client_ca.key -CAcreateserial -out testhost.pem -days 825 -sha256 -extfile client.ext

# Clean up
rm *.ext
rm *.srl
rm *.csr
