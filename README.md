# Zarpa

**Right-click a file, pick one of your devices, done.**

Zarpa is an open-source, cross-platform file transfer tool for Windows, macOS, Linux, Android and iOS.
No accounts, no cloud, end-to-end encrypted, built to saturate your link and to be driven by
humans *and* AI agents.

> **Status: pre-alpha (design phase).** Nothing is installable yet. Follow the
> [roadmap](#roadmap) or read the [design](docs/superpowers/specs/2026-10-30-zarpa-design.md).

## Why another one?

| Tool | Gap |
|---|---|
| LocalSend | LAN only, little native shell integration, no history/dashboard |
| Blip | Great UX but closed source |
| Taildrop | Requires Tailscale |
| croc / Magic Wormhole / sendme | Command line only |
| WeTransfer / SwissTransfer | Cloud upload, size limits, privacy trade-offs |

Zarpa aims to combine: open source + native context-menu integration + peer-to-peer transfers that later
work beyond your LAN + a first-class API and MCP server for agents.

## Planned features

- Context menu / share sheet on every OS: *Send with Zarpa* -> choose a device.
- Zero configuration after a one-time pairing; Ed25519 device identity, QUIC + TLS 1.3.
- Parallel, resumable, BLAKE3-verified block transfers (files and folders).
- Dashboard with devices, live activity and searchable history.
- Local API, `--json` CLI and MCP server with scoped, deny-by-default permissions.

## Roadmap

| Milestone | Deliverable |
|---|---|
| M0 | Public repo, OSS foundation, draft protocol spec |
| M1 | Daemon, identity, pairing, discovery, first file between two PCs, CLI |
| M2 | Robust transfers: parallel blocks, resume, folders |
| M3-M5 | Desktop app + Windows menu, macOS/Linux, Android/iOS |
| M6 | Stable public API and MCP server |
| M7 | 1.0 release |

Later phases: transfers across networks (WireGuard-like), then between people.

## Contributing

We welcome issues and pull requests. Read [CONTRIBUTING.md](CONTRIBUTING.md) and
[AGENTS.md](AGENTS.md) first. Security issues: see [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
