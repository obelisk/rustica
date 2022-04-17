# Rustica

Rustica is a Yubikey backed SSHCA written in Rust. It is designed to be used with the accompanying `rustica-agent` tool for certificate handling but speaks gRPC so other integrations are possible.

## Features
- Multiple Ways To Secure Private Keys
    - File
    - Yubikey 4/5 (non HSM)
    - AmazonKMS
- Multiple Ways To Store Permissions
    - Built in SQLite Database
    - External Authorization Server
- Multiple Supported Logging Systems
    - Stdout
    - InfluxDB
    - Splunk
    - External JSON Webhook
- Just In Time Certificate Generation
- Use Different Keys For User and Hosts
- gRPC With mTLS
- Docker Scratch Container Support
- Extensive Feature Support 

### Protected Key Material
Malicious access to the Rustica private key would result in serious compromise and thus Rustica provides two ways to mitigate this risk with Yubikey and AmazonKMS support. These signing modules use keys that cannot be exported resulting in more control over how the private key is being used. If using AmazonKMS, Amazon logs can be compared with Rustica logs to provide assurance no misuse has occured.

### Just-In-Time Certificate Generation
Rustica and RusticaAgent work together to use short lived certificates that are generated on the fly only when needed. In effect this means your deployment will never need to deal with revocation because after ten seconds (the default) all issued certificates will have expired.

### Multiple Supported Logging Systems
All certificate issues can be logged to InfluxDB or Splunk if desired. See the logging submodule and the examples in `examples/` for more information.

### gRPC With mTLS
Rustica requires all connections be made using mutually authenticated TLS. This provides an extra level of authentication to the service and allows the tying of x509 certificates to SSH logins.

### Docker Scratch Container
When using either AmazonKMS or file based keys, Rustica can be compiled to a statically linked binary capable of running in a docker container with no external dependencies. The `docker/` folder contains `Dockerfile`s to compile Rustica this way for both amd64 (standard x86_64 architectures) and aarch64 (capable of running on Amazon Graviton servers).

### Extensive Feature Support
Compile in only what you need to reduce binary size and dependency bloat. If you're planning on using AmazonKMS for storing your keys, Rustica can be compiled without Yubikey dependencies and vice versa. The same is also true for authorization, if using a remote authorization service, Rustica can be compiled without Diesel and SQLite.

### EXPERIMENTAL: Host Restriction
It is possible to grant a principal to a user that is only valid for certain hostnames. This is achieved by setting the restricted host permission in the database. When in use, the certificate generated will have the `force-command` CriticalOption enabled. This will force the user to run a bash script, loaded inside the cert, that contains all hostnames she is allowed to log in to. If the hostname name of the remote host does not match any in the list, the connection is closed.

## Key Support
The following key types have client support via FIDO:
- ECDSA 256
- Ed25519

The following key types have Yubikey support (client and server):
- ECDSA 256
- ECDSA 384

The following key types have file support (client and server):
- ECDSA 256
- ECDSA 384
- Ed25519

The following key types have no support:
- ECDSA 521

## Running An Example Deployment
This repository comes with a set of configuration files and database to be used as an example. New certificates can be easily generated using the scripts in `resources/`. 

### Start Rustica
`rustica --config examples/rustica_local_file.toml`

### Pull a certificate with RusticaAgent
`rustica-agent --config examples/rustica_agent_local.toml -i`

The details of the certificate will be printed to the screen.

## Running Tests
Rustica ships with a small suite of integration tests aimed at ensuring some of the lesser known features do not get broken with updates. They require docker to be installed and can be run with the script in `tests/integration.sh`

## Security Warning
No review has been done. I built it because I thought people could find it useful. Be wary about using this in production without doing a thorough code review. If you find mistakes, please open a pull request or if it's a security bug, email me.

  
## Licence
This software is provided under the MIT licence so you may use it basically however you wish so long as all distributions and derivatives (source and binary) include the copyright from the `LICENSE`.
