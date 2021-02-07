# Rustica Agent

Rustica Agent the agent portion of the Rustica SSHCA. It is designed to be an SSH-Agent that uses keys loaded on a Yubikey though also supports a file, generally for requesting host certs which are not stored on Yubikeys. See command help for more complete documentation on use.

Rustica-Agent does not support the normal array of SSH-Agent calls, instead only supporting `Identities` and `Sign`. The reason for this is the call for identities initiates a request to a Rustica SSHCA server. Rustica is then expected to return a cert that contains all permissions your key is allowed, including all principals, and hosts. This SSH certificate is generated containing the public portion of the key present on your Yubikey (which may contain up to 24 keys, the key used is chosen at agent start either by command line flag or configuration file).

It is possible to generate keys that require touch (and Rustica Agent allows you to create such keys) though SSH in unaware this is happening so you must notice your key is blinking and act accordingly. Pin is not supported.