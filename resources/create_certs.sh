#!/bin/zsh
if [ "$1" = "clean" ]; then
    rm -rf rustica/
    rm -rf author/
    rm -rf clients/
    rm *.key
    rm *.pem
    rm *.csr
    rm *.srl
    rm user_ssh_ca*
    rm host_ssh_ca*
    rm example_user_key*
    exit
fi

if [ "$1" = "client" ]; then
    CLIENT_NAME=$2
    mkdir -p clients/$CLIENT_NAME
    cd clients/$CLIENT_NAME

    # ------------ Generate Example User Key ------------ #
    ssh-keygen -t ed25519 -f $CLIENT_NAME -q -N ""

    CLIENT_CONFIG="""
    authorityKeyIdentifier=keyid,issuer
    basicConstraints=CA:FALSE
    keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
    subjectAltName = @alt_names

    [alt_names]
    DNS.1 = ${CLIENT_NAME}"""

    echo $CLIENT_CONFIG > client.ext

    # ------------ Generate Signed Certificate For Client ------------ #
    # Generate TestHost key
    openssl ecparam -genkey -name prime256v1 -noout -out ${CLIENT_NAME}_private.pem
    openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in ${CLIENT_NAME}_private.pem -out ${CLIENT_NAME}.key
    rm ${CLIENT_NAME}_private.pem

    # Generate TestHost CSR
    openssl req -new -key ${CLIENT_NAME}.key -out ${CLIENT_NAME}.csr -subj "/CN=${CLIENT_NAME}/"

    # Generate TestHost Certificate
    openssl x509 -req -in ${CLIENT_NAME}.csr -CA ../../client_ca.pem -CAkey ../../client_ca.key -CAcreateserial -out ${CLIENT_NAME}.pem -days 825 -sha256 -extfile client.ext
    rm client.ext
    exit
fi

AUTHOR_CONFIG="""
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost"""

RUSTICA_CONFIG="""
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost"""

# Create the certificate configurations. These ext files are needed otherwise
# Rustica will not accept them.
mkdir -p author
mkdir -p rustica
echo $AUTHOR_CONFIG > author/author.ext
echo $RUSTICA_CONFIG > rustica/rustica.ext

# Generate CA key and cert
openssl ecparam -genkey -name prime256v1 -noout -out ca.key
openssl req -x509 -new -key ca.key -nodes -days 3650 -out ca.pem -subj '/CN=EnterpriseRootCA'

# Generate Client CA key and cert
openssl ecparam -genkey -name prime256v1 -noout -out client_ca.key
openssl req -new -key client_ca.key -x509 -nodes -days 3650 -out client_ca.pem -subj '/CN=EnterpriseClientRootCA'

# ------------ Generate Private Keys For Test Infra ------------ #
# Generate Rustica server key
openssl ecparam -genkey -name prime256v1 -noout -out rustica/rustica_private.pem
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in rustica/rustica_private.pem -out rustica/rusticaserver.key
rm rustica/rustica_private.pem

# Generate Author server key
openssl ecparam -genkey -name prime256v1 -noout -out author/author_private.pem
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in author/author_private.pem -out author/authorserver.key
rm author/author_private.pem

# ------------ Generate CSRs For Test Infra ------------ #
# Create certificate signing request for Rustica server
openssl req -new -key rustica/rusticaserver.key -out rustica/rusticaserver.csr -subj '/CN=RusticaServer/O=Rustica/C=CA'
# Create certificate signing request for Author server
openssl req -new -key author/authorserver.key -out author/authorserver.csr -subj '/CN=Author/O=Rustica/C=CA'

# ------------ Generate Signed Certificates For Test Infra ------------ #
# Use the CA to generate the cert for Rustica sever
openssl x509 -req -in rustica/rusticaserver.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out rustica/rusticaserver.pem -days 825 -sha256 -extfile rustica/rustica.ext
# Use the CA to generate the cert for Author sever
openssl x509 -req -in author/authorserver.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out author/authorserver.pem -days 825 -sha256 -extfile author/author.ext

# ------------ Generate User and Host CA Keys ------------ #
ssh-keygen -t ed25519 -f rustica/user_ssh_ca -q -N ""
ssh-keygen -t ed25519 -f rustica/host_ssh_ca -q -N ""

