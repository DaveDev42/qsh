# QSH

QSH is a direct, resilient remote shell built on QUIC.

```bash
qsh dave@host
```

The project is currently in the specification phase.

## Documents

- [Product Requirements](docs/PRD.md)
- [CLI, JSON and MCP Contract](docs/CLI.md)

## Product boundary

QSH owns secure sessions, PTY lifecycle, reconnect, command execution and port forwarding. It connects to a user-provided routable hostname or IP address and does not depend on a control plane or relay.

