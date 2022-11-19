# Rustica Agent CLI

## Introduction
This is the canonical agent for Rustica. Used for generating, registering, providing, and fetching certificates for your (generally hardware) keys. Generally when new features are added, they are added and tested here first, before being ported to any of the other agent crates.

## Limitations
RusticaAgent does not support the normal array of SSH-Agent calls, the currently supported calls are:

- `Identities` - Called when connecting to a host or running `ssh-add -L`
- `Sign` - Called when connecting to a host and a public key has been accepted.
- `AddIdentity` - Called when running `ssh-add <path>`

## Usage
When using RusticaAgent it is preferable to provide a configuration file that contains all the parameters needed for normal operation. Any configuration file setting may be override by also providing it on the command line. RusticaAgent also only presents a single Yubikey backed key to the remote server but will present any other keys added with the `AddIdentity` call (keys added with `ssh-add`).

An example configuration files can be found in the root/examples directory.

## Sub Commands
There are several subcommands available for determining proper configuration as well as handling key registration of both PIV and FIDO keys with the Rustica backend. Run `rustica-agent-cli --help` to see more details.