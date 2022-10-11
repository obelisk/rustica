#!/bin/zsh
if [ "$1" = "clean" ]; then
    rm -rf rustica/
    rm -rf author/
    rm -rf clients/
    rm -rf copyeditor/
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

if [ "$1" = "build_local" ]; then
    echo "Building certifications for local testing!"
    export BUILD_LOCAL=true
fi

create_editor_certs () {
    if [ "$BUILD_LOCAL" ]; then
        DNSNAME="localhost"    
    else
        DNSNAME=$1
    fi

    CONFIG="""
    authorityKeyIdentifier=keyid,issuer
    basicConstraints=CA:FALSE
    keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
    subjectAltName = @alt_names

    [alt_names]
    DNS.1 = ${DNSNAME}"""
    NAME=$1
    mkdir -p ${NAME}
    echo $CONFIG > ${NAME}/${NAME}.ext

    openssl ecparam -genkey -name prime256v1 -noout -out ${NAME}/${NAME}_private.pem
    openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in ${NAME}/${NAME}_private.pem -out ${NAME}/${NAME}.key
    rm ${NAME}/${NAME}_private.pem

    openssl req -new -key ${NAME}/${NAME}.key -out ${NAME}/${NAME}.csr -subj "/CN=${NAME}/O=Rustica/C=CA"
    openssl x509 -req -in ${NAME}/${NAME}.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out ${NAME}/${NAME}.pem -days 825 -sha256 -extfile ${NAME}/${NAME}.ext
}

# Generate CA key and cert
openssl ecparam -genkey -name prime256v1 -noout -out ca.key
openssl req -x509 -new -key ca.key -nodes -days 3650 -out ca.pem -subj '/CN=EnterpriseRootCA'

# Generate Client CA key and cert
openssl ecparam -genkey -name prime256v1 -noout -out client_ca.key
openssl req -new -key client_ca.key -x509 -nodes -days 3650 -out client_ca.pem -subj '/CN=EnterpriseClientRootCA'

# ------------ Generate Private Keys For Test Infra ------------ #
# Generate Rustica Certificates
create_editor_certs "rustica"
# Generate Author Certificates
create_editor_certs "author"
# Generate CopyEditor Certificates
create_editor_certs "copyeditor"
# Generate Quroum Certificates
create_editor_certs "quorum"

create_editor_certs "okta-adapter"

# ------------ Generate User and Host CA Keys ------------ #
ssh-keygen -t ed25519 -f rustica/user_ssh_ca -q -N ""
ssh-keygen -t ed25519 -f rustica/host_ssh_ca -q -N ""

