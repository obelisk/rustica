# Systemd config

Within this dir, you can place these files with the path prefix of ${HOME}/.config/ to add a user level systemd config for managing the rustica agent.
The examples given are specifically for serving multiple ssh keys within a dir.

```
systemd-config/
├── environment.d
│   └── rustica_ssh_socket.conf # Exports the SSH_AUTH_SOCK to your session
├── README.md
└── systemd
    └── rustica.service # The service unit file
```
