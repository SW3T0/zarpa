# AGENTS.md — Zarpa

Instructions for any AI coding agent (and a quick contributor guide) working on this repository.
`CLAUDE.md` imports this file; keep this one as the single source of truth.

## Project

**Zarpa** is an open-source, cross-platform (Windows, macOS, Linux, Android, iOS) file transfer tool.
Goal: send files of any size between your devices as simply as a right-click, with no accounts and no
cloud. Later phases: remote devices over the internet (WireGuard-like), and transfers between people.
Agent-friendly by design: local API, CLI with JSON output and an MCP server.

- License: **Apache-2.0** (SPDX header in every source file: `// SPDX-License-Identifier: Apache-2.0`).
- Public-facing language: **English** (code, comments, docs, commits, issues). Spanish translations of
  README and user docs are welcome but secondary.

## Architecture rules (do not break)

1. **One daemon (`zarpad`) holds all logic.** GUI, shell extensions, CLI and MCP server are thin clients
   of its local API. Never duplicate transfer, crypto or pairing logic in a client.
2. **Transport is behind a trait.** v1 = QUIC over LAN; remote/relay comes later without touching clients.
3. **Identity = Ed25519 key per device.** No accounts, no central server. Trust is an explicit paired list.
4. **The local API never listens on the network.** Localhost / local socket only, with scoped tokens.
5. **The wire protocol is a public, versioned spec** in `docs/protocol/`. Any protocol change updates the spec
   in the same PR.

## Repository layout

```
core/     Rust core (protocol, crypto, transfer, daemon)
apps/     desktop (Tauri), android, ios
shell/    context-menu extensions per OS (windows, macos, linux)
cli/      `zarpa` CLI (--json output)
mcp/      MCP server
docs/     architecture, protocol spec, ADRs, guides
.github/  workflows, issue/PR templates
```

## Required OSS files

`README.md`, `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant), `SECURITY.md`
(private vulnerability reporting), `CHANGELOG.md` (Keep a Changelog), `.github/` issue and PR templates,
`CODEOWNERS`. Keep them current; a PR that changes behavior updates docs and changelog.

## Git workflow

- Trunk-based: `main` is always releasable and protected. Work on short-lived branches
  (`feat/…`, `fix/…`, `docs/…`, `chore/…`), merge via PR with squash.
- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `perf:`, `ci:`;
  `!` or `BREAKING CHANGE:` for breaking). Imperative, <= 72 chars subject, body explains *why*.
- Small, focused PRs with a description, linked issue and test evidence. One logical change per PR.
- Sign off commits (DCO: `git commit -s`). No CLA.
- Semantic Versioning. Releases are automated from Conventional Commits and produce signed artifacts.
- Agents: never commit, push, merge or open PRs unless the user asked. Never force-push `main`.

## Code standards

**Rust (core, cli, mcp, daemon)**
- `cargo fmt` and `cargo clippy --all-targets -- -D warnings` must pass. MSRV declared in `Cargo.toml`.
- No `unwrap()`/`expect()` in non-test library code; typed errors (`thiserror`), `anyhow` only at binaries.
- `#![forbid(unsafe_code)]` by default; any `unsafe` needs a `// SAFETY:` comment and reviewer sign-off.
- Public items documented (`///`); no dead code, no commented-out code, no TODO without an issue link.
- `cargo deny` (licenses, advisories, bans) must pass; new dependencies need a justification in the PR.

**General**
- Match surrounding style; prefer simple over clever; small functions and modules with one purpose.
- Platform-specific code isolated behind interfaces in `shell/` and `apps/`.
- Never log secrets, keys, tokens or full user file paths at default log level.

## Testing

- Every behavior change ships with tests. Bug fixes start with a failing test.
- Unit tests next to code; integration tests for daemon API and protocol; property/fuzz tests for the
  parser, manifest and path handling.
- Transfer tests cover: large files, resume after interruption, corrupted blocks, concurrent flows.
- CI must be green on Windows, macOS and Linux before merge; mobile builds checked in CI.

## Security

- Treat all network input and file names as hostile: sanitize names, block path traversal, write only
  inside the chosen download folder, validate every block hash.
- No secrets in the repo. Keys live in the OS secure store.
- Agent/API tokens are scoped (allowed folders, allowed devices, require-confirmation for new sends).
- Dependencies: Dependabot, CodeQL and `cargo deny` stay enabled. Report vulnerabilities per `SECURITY.md`.

## Documentation

- Decisions live in `docs/adr/NNNN-title.md` (short ADRs). Architecture and protocol docs stay in sync
  with code. User-facing docs explain the "why" and include copy-pasteable examples.

## How agents should work here

1. Design before code: brainstorm -> spec in `docs/superpowers/specs/` -> plan -> implement. Do not
   scaffold or write implementation until the user approved the design.
2. Read before editing; follow existing patterns; keep diffs minimal and scoped to the task.
3. Run formatter, linter and tests before declaring work done; report failures honestly.
4. Ask before anything outward-facing or hard to reverse (push, release, publish, delete).
5. When unsure about a product decision, ask the user one focused question instead of guessing.
