# Rustica

Rustica is a Yubikey backed SSHCA written in Rust. It is designed to be used with the accompanying `rustica-agent` tool for certificate handling but speaks gRPC so other integrations are possible. Rustica may use a Yubikey to store its private keys but also supports unencrypted OpenSSH format private key files.

## Features
- Yubikey backed private keys
- Just In Time Certificate Generation
- Local or remote decision engine support
- InfluxDB logging support
- Ability to use different CAs for user and host certs
- gRPC over TLS with required mTLS

### JITC
The default for Rustica is to use Just In Time Certificate Generation meaning certificates are generated with a TTL of 10s (though this is adjustable on a key by key basis when using local authentication).

### Host Restriction
It is possible to grant a principal to a user that is only valid for certain hostnames. This is achieved by setting the restricted host permission in the database. When in use, the certificate generated will have the `force-command` CriticalOption enabled. This will force the user to run a bash script, loaded inside the cert, that contains all hostnames she is allowed to log in to. If the hostname name of the remote host does not match any in the list, the connection is closed.

### InfluxDB Logging
All certificate issues are logged to InfluxDB under the table `rustica_logs`. The log contains the fingerprint and some other metadata about the key used. 

### gRPC over TLS
There is a script in the resources folder to generate a self signed CA, along with the server cert. Rustica also requires mTLS for connections so an example client cert is also generated.

## Key Support
The following key types have Yubikey support:
- ECDSA 256
- ECDSA 384

The following key types have file support:
- ECDSA 256
- ECDSA 384
- Ed25519
- RSA 2048
- RSA 3072
- RSA 4096
- RSA 8192

The following key types have no support:
- ECDSA 521

## Quickstart with Local Authorization
Create an example set of all required keys and certs:
`cd resources && ./create_certs.sh && cd ..`

Read the documentation in migrations/*/up.sql. It explains how the authorization system works in much more detail and how to authorize keys via database inserts. You may modify that file directly to build your example authorization db.
> Key IDs are the SHA256 hashes of the public portion of an SSH key. To show the fingerprint of an existing SSH key use:
> `ssh-keygen -lf <path to key>`

To build the db: `diesel migration run` from the rustica directory
This will create a authorization database and is specified to Rustica via environment variable `DATABASE_URL`.
> If you have issues running diesel you may need to install it with:
> `cargo install diesel_cli --no-default-features --features sqlite`

Run Rustica (from the root the repository):
```
DATABASE_URL=rustica/rustica.db cargo run --bin rustica -- \
    --servercert resources/rusticaserver.pem \
    --serverkey resources/rusticaserver.key \
    --clientcacert resources/client_ca.pem \
    --keytype file \
    --userkey resources/user_ssh_ca \
    --hostkey resources/host_ssh_ca
```

Finally run rustica-agent:
```
cargo run --bin rustica-agent -- \
--mtlscert resources/testhost.pem \
--mtlskey resources/testhost.key \
--server "https://localhost:50051" \
--capem resources/ca.pem \
-f resources/example_user_key \
-i
```

If all has gone according to plan, you will see your certificate details print out on the screen (as well as the traditional encoding below)

  
## Security Warning
No review has been done. I built it because I thought people could find it useful. Be wary about using this in production without doing a thorough code review. If you find mistakes, please open a pull request or if it's a security bug, email me.

  
## Licence
This software is provided under the MIT licence so you may use it basically however you wish so long as all distributions and derivatives (source and binary) include the copyright from the `LICENSE`.
