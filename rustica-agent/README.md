# RusticaAgent

## Introduction
This is the agent portion of the project and manages keys as well as talking to Rustica and remote SSH hosts. It supports using a Yubikey for hardware backed SSH keys as well as adding external key files after the agent has started.

## Limitations
RusticaAgent does not support the normal array of SSH-Agent calls, the currently supported calls are:

- `Identities` - Called when connecting to a host or running `ssh-add -L`
- `Sign` - Called when connecting to a host and a public key has been accepted.
- `AddIdentity` - Called when running `ssh-add <path>`

## Usage
When using RusticaAgent it is preferable to provide a configuration file that contains all the parameters needed for normal operation. Any configuration file setting may be override by also providing it on the command line. RusticaAgent also only presents a single Yubikey backed key to the remote server but will present any other keys added with the `AddIdentity` call (keys added with `ssh-add`).

An example configuration file can be found at `../examples/rustica_agent_local.toml`. This file is compatible with a Rustica instance running `../examples/rustica_local_file.toml`.

## Examples
### Daemon Mode
`rustica-agent --config ../examples/rustica_agent_local.toml --slot R1 --socket /tmp/rustica_agent_tmp_socket`

> Note: RusticaAgent does not currently fork and background itself because it causes issues accessing USB devices on macOS.

This command:
- Loads all the settings from the config file (server, mTLS, TLS, etc)
- Overrides the key to use with the key in Yubikey slot R1
- Overrides the socket path to be used
- Starts listening for requests from that unix socket

### Immiediate Mode
`rustica-agent --config ../examples/rustica_agent_local.toml -i`

Fetches a certificate from the backend, pretty prints it to stdout, and quits. This is useful for double checking what permissions the server has granted you for a key.

### Immiediate Save Mode
`rustica-agent --config ../examples/rustica_agent_local.toml -i -o fetched-cert.pub`

This is exactly the same as above but outputs a valid SSH certificate for the provided key. This is useful for file based keys, particularly for refreshing server certificates.

### Provision Mode
`rustica-agent --config ../examples/rustica_agent_local.toml --slot R1 provision -r --subject ExampleKey`

This creates a new key pair in the given slot. The -r flag means that touch will be needed for every usage and the subject flag adds the given string to the CN of the generated x509 self signed certificate. Once this is complete, it will generated the attestation chain using the `F9` slot and attempt to register the key with the Rustica server. The backend will use the attestation chain to verify the key was generated on a hardware device and then permissions may be assigned to it.