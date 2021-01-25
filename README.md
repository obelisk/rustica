# Rustica

Rustica is a Yubikey backed SSHCA written in Rust powered by the Rustica-Keys library. It is designed to be used with Rustica-Agent for certificate handling but speaks generic gRPC so other integrations are possible. Rustica requires at least 1 + N standard (not HSM) Yubikey 4/5s: one for the server, and one for every client. You may also wish to generate keys directly on yubikeys (see `yk-provisioner` in Rustica-Keys) so they never exist off the key.

## Features
- Yubikey backed private keys
- Just In Time Certificate Generation
- Ability to restrict a key to a subset of hosts
- InfluxDB logging support
- DB controlled permissions that can be changed at runtime
- Ability to use different CAs for user and host certs
- gRPC over TLS

### JITC
The default for Rustica is to use Just In Time Certificate Generation meaning certificates are generated with a TTL of 10s (though this is adjustable on a key by key basis). See Rustica-Agent for more on this.

### Host Restriction
It is possible to grant a principal to a user that is only valid for certain hostnames. This is achieved by setting the restricted host permission in the database. When in use, the certificate generated will have the `force-command` CriticalOption enabled. This will force the user to run a bash script, loaded inside the cert, that contains all hostnames she is allowed to log in to. If the hostname name of the remote host does not match any in the list, the connection is closed.

### InfluxDB Logging
All certificate issues are logged to InfluxDB under the table `rustica_logs`. The log contains the fingerprint and some other metadata about the key used. 

### gRPC over TLS
There is a script in the resources folder to generate a self signed CA, along with the server cert. It will also generate a client cert if you wish to use mTLS but currently Rustica does not support this.

## Key Support
Rustica Supports ECDSA keys fully:
- ECDSA 256
- ECDSA 384

Rustica supports Ed25519 in addition to this for key verification **only**. This means sending an Ed25519 as an SSH public key can be verified by the server but the server cannot use one as a CA key. I would like to support Ed25519 fully but I need Yubikey PIV support for it which I'm not sure will happen.

RSA keys while could be technically supported, currently are not fully built out.
  
  
## Security Warning

No review has been done. I built it because I thought people could find it useful. Be wary about using this in production without doing a thorough code review. If you find mistakes, please open a pull request or if it's a security bug, email me.

  
## Licence

This software is provided under the MIT licence so you may use it basically however you wish so long as all distributions and derivatives (source and binary) include the copyright from the `LICENSE`.
