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

## Runtime settings

Use the control socket to read or change a running agent's certificate settings:

```sh
rustica-agent-cli settings get disable_certificate
rustica-agent-cli settings get config_path
rustica-agent-cli settings set disable_certificate true
rustica-agent-cli settings toggle disable_certificate
rustica-agent-cli settings set config_path /absolute/path/to/config.toml
```

Commands use `--control-socket PATH` or append `.control/socket` to
`SSH_AUTH_SOCK`. Agent startup accepts the same option; FFI startup always derives
it from the SSH socket. Both sockets must bind before startup succeeds.

`disable_certificate` accepts `true` or `false`. Disabling takes effect during a
pending refresh, preserves the cache, and does not restrict signing. Re-enabling
resumes normal cache use and renewal. Scripts should use `set`: retrying a
`toggle` after a lost response can undo the change. Clients do not retry mutations.

Setting `config_path` validates and loads the file, replaces certificate options
including startup overrides, and clears the cached SSH certificate. It waits for
any active refresh and directs future mTLS renewal writes to the selected file.
Selecting the same path reloads it. Signing identities and listening sockets stay
unchanged. Switching does not request a certificate or write the file; certificate
requests can still fail later. The CLI resolves relative paths from its current
directory; protocol clients must send absolute paths.

Changes last until restart. Successful commands print a JSON boolean or path
string; errors exit with a nonzero status. Settings commands connect directly to
the socket without loading configuration or contacting hardware.

The control directory is owner-only (`0700`) and the socket is `0600`. Unsafe
permissions, symlinks, and `..` path components are rejected. The separate socket
keeps control commands out of SSH-agent forwarding. Shutdown removes the socket;
the directory and lock remain for recovery after a crash.

The protocol frames JSON with a four-byte big-endian length, up to 64 KiB.
Connections support sequential requests. Version 1 accepts `version`, `op`,
`setting`, and `value` only for `set`. For example:

```json
{"version":1,"op":"get","setting":"disable_certificate"}
{"version":1,"ok":true,"value":false}
{"version":1,"ok":false,"error":{"code":"invalid_request","message":"..."}}
```

Error codes are `unsupported_version`, `unknown_setting`, `invalid_request`,
`unsupported_operation`, and `invalid_value`.

## Running via systemd
See [the systemd resources for more information](../resources/systemd-config/README.md)
