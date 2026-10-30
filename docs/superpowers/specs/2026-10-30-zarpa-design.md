# Zarpa — Design Specification

Date: 2026-10-30 · Status: approved by the project owner, pending written-spec review · License: Apache-2.0

## 1. Summary

Zarpa is an open-source, cross-platform file transfer tool for Windows, macOS, Linux, Android and iOS.
Its core promise: **right-click a file, pick one of your devices, done** — fast, private, no accounts,
no cloud. It is designed from day one to be **agent-friendly** (local API, JSON CLI, MCP server) and to
grow later into remote transfers (WireGuard-like) and transfers between people.

## 2. Goals and non-goals

**Goals (v1.0)**
- Send files and folders of any size between the user's own devices on the same local network.
- Native shell integration (context menu / share sheet) on every platform.
- Dashboard with devices, live activity and searchable history.
- Saturate the available link (parallel QUIC streams); resumable and integrity-verified.
- End-to-end encrypted, zero-configuration after a one-time pairing.
- Agent-friendly: stable local API, `--json` CLI, MCP server with scoped permissions.
- A public, versioned protocol specification and a repository that follows open-source best practices.

**Non-goals (v1.0)**
- Transfers over the internet, relays, hole punching (Phase 2).
- Transfers between different people, links, asynchronous/store-and-forward hosting (Phase 3).
- Accounts, a central server, cloud storage, sync of folders.

## 3. Phases

| Phase | Scope |
|---|---|
| 1 | LAN only; context menu; dashboard; daemon with local API |
| 1.5 | JSON CLI and MCP server (delivered within milestones M1 and M6) |
| 2 | Own devices across networks: NAT traversal with relay fallback (likely built on `iroh`) |
| 3 | Between people: live P2P via code/link first; optional self-hostable store-and-forward server later |

Phase 1 is built so that Phase 2 changes only the transport implementation (see §4.2).

## 4. Architecture

### 4.1 Components

```
              ┌──────────────── zarpad (daemon, Rust) ────────────────┐
              │ identity · pairing · discovery (mDNS) · QUIC transport │
              │ block transfer · history (SQLite) · permissions · API  │
              └────────────────────────────────────────────────────────┘
                     ▲            ▲            ▲            ▲
                  App/GUI    Shell extension   CLI        MCP server
```

- `zarpad` owns **all** logic. Every other component is a thin client of its local API.
- Desktop: runs as a background service started with the OS. Mobile: embedded in the app, bound by
  iOS/Android background limits (iOS receives while the app is foreground; Android uses a foreground service).
- The local API listens on localhost / a local socket only, never on the network, and requires a scoped token.

### 4.2 Transport abstraction

Transport sits behind a trait. v1 implements QUIC (TLS 1.3) over LAN. Phase 2 adds a second implementation
(hole punching + encrypted relay) without changes to clients or to the transfer layer.

## 5. Identity, pairing and trust

- Each device generates an **Ed25519 key pair** once, stored in the OS secure store (Credential Manager,
  Keychain, Keystore). The **device ID is the public key**. The display name is a changeable label.
- **Pairing (once per device):** device A shows a QR or short code; device B scans/enters it; both exchange
  public keys and confirm a 4–6 digit verification code shown on both screens; both store each other as trusted.
- **Trusted devices** transfer without confirmation. **Unpaired but visible devices** can be sent to, but each
  transfer requires explicit acceptance by the receiver.
- No central authority: TLS peers authenticate by public key against the trust list, not by certificate authorities.

## 6. Discovery

- mDNS advertises each device on the LAN with an identifier derived from its public key, so the real name is not
  exposed to devices that are not paired.
- The device list refreshes periodically and when the context menu opens.
- If discovery fails (e.g. client isolation on guest Wi-Fi or VLANs) the app states the likely cause and offers
  the QR/code connection as the alternative.

## 7. Transfer protocol

- QUIC with TLS 1.3, end-to-end encrypted, mutual authentication by Ed25519 keys.
- Files are split into blocks hashed with **BLAKE3**; blocks travel over multiple parallel QUIC streams.
- A **manifest** describes a transfer (one file, many files, or a folder tree) and its block hashes.
- The receiver verifies every block on arrival; corrupted or tampered data is rejected before being written.
- **Resume:** after a dropped connection the transfer continues from the last verified block.
- Data is written to a temporary file and moved to the final path only after the last block verifies, so a failed
  transfer never leaves a partial file in the destination.
- File names are sanitized; writes are confined to the chosen download folder (no path traversal).
- The protocol is documented in `docs/protocol/` as a public, versioned specification with message definitions
  and examples, so third parties can build compatible clients.

## 8. Local API and agent integration

- One local API (REST or gRPC) with a published **OpenAPI** definition and stable JSON output.
- **CLI** `zarpa` with `--json` on every command; designed to be parsed without guessing text.
- **MCP server** exposing tools such as `list_devices`, `send_file`, `receive_status`, `get_history`.
- Agents are first-class clients that can pair as a device type. API tokens are **scoped**: allowed folders,
  allowed devices, and a **require-human-confirmation** policy for sends to new targets by default.
- Rationale: an agent that can send files is an exfiltration path if prompt-injected; permissions are deny-by-default.

## 9. Shell integration, app and dashboard

| OS | Mechanism |
|---|---|
| Windows 11 | `IExplorerCommand` COM extension via sparse package, plus classic "Send to" fallback |
| macOS | Finder Sync extension, Share extension, Quick Action |
| Linux | Nautilus and Dolphin extensions, `.desktop` actions |
| Android | Share sheet with Direct Share (recent devices first) |
| iOS | Share extension; heavy work delegated to the main app (extension memory limit) |

Desktop flow: right-click file -> **Send with Zarpa** -> list of available devices -> click. The extension transfers
nothing itself; it asks the daemon.

App (Tauri 2; Flutter is the fallback if Tauri mobile proves inadequate at milestone M5): tray icon with
drag-and-drop send, and a main window with **Devices**, **Activity** (speed, ETA, pause, cancel), **History**
(search, filters, open received files) and **Settings** (download folder, device name, auto-accept from trusted,
agent permissions, API tokens). Incoming transfers raise an OS notification with Accept/Reject; trusted devices save directly.

UX principles: zero configuration; never ask for what can be inferred (no IPs, ports, accounts); errors state
what happened and what to do next.

## 10. Errors

Typed errors with stable codes (e.g. `DEVICE_UNREACHABLE`, `TRANSFER_REJECTED`), returned identically by the API,
CLI and MCP. User-facing messages explain cause and remedy, not internals.

## 11. Testing

- Unit tests with the code; property and fuzz tests for the parser, manifest and path handling.
- Transfer tests: large files, resume after interruption, corrupted blocks, concurrent streams, with simulated
  packet loss and latency in CI.
- Integration: two daemons in CI covering pair -> send -> receive end to end.
- CI on Windows, macOS and Linux; Android and iOS always build; on-device mobile checks manual per release.

## 12. Security model

- Threats considered: hostile network peers, malicious file names/manifests, man-in-the-middle at pairing,
  prompt-injected agents, vulnerable dependencies.
- Mitigations: verification code at pairing, key-based mutual authentication, per-block hashes, sanitized paths,
  scoped agent tokens, no secrets or full paths in default logs, Dependabot + CodeQL + `cargo deny`.
- Vulnerabilities are reported privately per `SECURITY.md`.

## 13. Repository and OSS standards

Layout: `core/`, `apps/`, `shell/`, `cli/`, `mcp/`, `docs/` (architecture, protocol, ADRs), `.github/`.
Required files: `README.md`, `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `CHANGELOG.md`,
issue/PR templates, `CODEOWNERS`. Workflow: protected `main`, short-lived branches, squash-merged PRs, Conventional
Commits, DCO sign-off, Semantic Versioning, automated signed releases. Rust: `rustfmt`, `clippy -D warnings`,
`forbid(unsafe_code)` by default. Public-facing language is English. Full rules live in `AGENTS.md`.

Distribution targets: winget, Homebrew, Flathub, F-Droid, App Store and Google Play.

## 14. Technology stack

Rust core and daemon (QUIC via `quinn` or `iroh`; the choice is fixed at M1 by a spike that must meet the LAN
throughput and resume tests), SQLite for history, Tauri 2 for the UI, UniFFI to expose the core to Swift/Kotlin,
native shell extensions per OS.

## 15. Milestones

| ID | Deliverable |
|---|---|
| M0 | Public repo with OSS base: license, CI, templates, draft protocol spec |
| M1 | Core and daemon: identity, pairing, mDNS, send one file between two PCs, CLI |
| M2 | Robust transfer: blocks, parallelism, resume, folders |
| M3 | Desktop app with dashboard and Windows context menu |
| M4 | macOS and Linux |
| M5 | Android and iOS |
| M6 | Stable public API and MCP server |
| M7 | 1.0 release with package managers and stores |

## 16. Risks

- iOS background limits constrain receiving when the app is closed (accepted; documented to users).
- Windows 11 modern context menu is the most fragile integration (mitigated by the classic fallback).
- Networks with client isolation block mDNS (mitigated by QR/code connection).
- Name clearance is unverified at trademark level; check OEPM/EUIPO (classes 9, 42), domains and the GitHub
  organization before the public launch at M0.
- Agent permissions are a security-sensitive surface; the default policy stays deny-by-default.
