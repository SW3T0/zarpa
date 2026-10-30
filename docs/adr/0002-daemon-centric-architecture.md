# 2. Daemon-centric architecture

- Status: accepted
- Date: 2026-10-30

## Context
Zarpa needs a GUI, shell extensions, a CLI and an MCP server on five operating systems.

## Decision
A single daemon, `zarpad`, owns identity, pairing, discovery, transport, transfers, history and
permissions. All other components are thin clients of its local API, which listens only on localhost or a
local socket and requires scoped tokens. Transport is behind a trait so remote transport (Phase 2) can be
added without changing clients.

## Consequences
One place for logic and security; every client, including agents, has identical capabilities.
iOS embeds the daemon in the app and inherits platform background limits.
