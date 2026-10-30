# M0 — OSS Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the private `zarpa` repo into a public, well-formed open-source repository: license, community files, templates, CI/security automation, a minimal Rust workspace that CI can exercise, ADRs and a draft protocol spec.

**Architecture:** Plain repository scaffolding plus a one-crate Cargo workspace (`core/` -> `zarpa-core`) so lint/test/deny pipelines have real code to run. No product logic is written in M0. All changes land through a PR from `chore/m0-oss-foundation` to dogfood the workflow in `AGENTS.md`.

**Tech Stack:** Git, GitHub Actions, Rust (stable, edition 2021), cargo-deny, CodeQL, Dependabot, release-please, `gh` CLI.

**Conventions for every task:** shell is Git Bash on Windows; run commands from the repo root `C:\Users\ernes\Dev\zarpa` (`/c/Users/ernes/Dev/zarpa`). Commit with `git commit -s` (DCO) using Conventional Commits, ending the message with the `Co-Authored-By` trailer the harness provides. Never push until Task 10 and only after the user confirms.

---

## File structure (created by this plan)

| Path | Responsibility |
|---|---|
| `.gitattributes`, `.gitignore`, `.editorconfig` | Line endings, ignored files, editor consistency |
| `LICENSE`, `NOTICE` | Apache-2.0 text and attribution |
| `README.md` | Public landing page |
| `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `CHANGELOG.md`, `.github/CODEOWNERS` | Community and governance files |
| `Cargo.toml`, `rust-toolchain.toml`, `rustfmt.toml`, `deny.toml` | Workspace and Rust policy |
| `core/Cargo.toml`, `core/src/lib.rs` | Minimal `zarpa-core` crate |
| `.github/ISSUE_TEMPLATE/*`, `.github/pull_request_template.md` | Issue and PR templates |
| `.github/workflows/ci.yml`, `pr-checks.yml`, `codeql.yml`, `release-please.yml`, `.github/dependabot.yml` | Automation |
| `release-please-config.json`, `.release-please-manifest.json` | Release automation |
| `docs/README.md`, `docs/adr/0001..0003-*.md`, `docs/protocol/README.md` | Docs, ADRs, draft protocol |

---

### Task 0: Pre-flight gate (name clearance and tooling)

**Files:** none

- [ ] **Step 1: Verify tooling**

Run: `git --version && gh --version && gh auth status`
Expected: versions print and `gh auth status` shows "Logged in to github.com". If not logged in, ask the user to run `gh auth login` and stop.

Run: `cargo --version || echo "NO_RUST"`
Expected: a `cargo 1.x` version. If `NO_RUST`, ask the user to install Rust from https://rustup.rs and stop.

- [ ] **Step 2: Confirm name clearance with the user**

Ask the user, in chat, whether they have checked: (a) trademark databases OEPM/EUIPO and USPTO, classes 9 and 42, for "Zarpa"; (b) the domain they want (e.g. `zarpa.dev`); (c) that the GitHub account/org name to host the repo is the one they want public. Do not continue to Task 10 without a clear yes. Tasks 1-9 are local and safe to do regardless.

- [ ] **Step 3: Create the working branch**

Run: `git checkout -b chore/m0-oss-foundation && git branch --show-current`
Expected: `chore/m0-oss-foundation`

---

### Task 1: Repository hygiene files

**Files:**
- Create: `.gitattributes`, `.gitignore`, `.editorconfig`

- [ ] **Step 1: Write `.gitattributes`**

```gitattributes
* text=auto eol=lf
*.png binary
*.jpg binary
*.ico binary
*.ps1 text eol=crlf
*.bat text eol=crlf
```

- [ ] **Step 2: Write `.gitignore`**

```gitignore
# Rust
/target/
**/*.rs.bk
Cargo.lock.bak

# Node / UI (apps/)
node_modules/
dist/

# OS / editors
.DS_Store
Thumbs.db
.idea/
.vscode/
*.swp

# Local agent state
.claude/settings.local.json

# Secrets
.env
.env.*
*.pem
*.key
```

- [ ] **Step 3: Write `.editorconfig`**

```ini
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 4

[*.{yml,yaml,json,md,toml}]
indent_size = 2

[Makefile]
indent_style = tab
```

- [ ] **Step 4: Renormalize and verify**

Run: `git add --renormalize . && git status --short`
Expected: lists `.gitattributes`, `.gitignore`, `.editorconfig` as new (existing files may show as modified only if they contained CRLF).

- [ ] **Step 5: Commit**

```bash
git add .gitattributes .gitignore .editorconfig
git commit -s -m "chore: add gitattributes, gitignore and editorconfig"
```

---

### Task 2: License and notice

**Files:**
- Create: `LICENSE`, `NOTICE`

- [ ] **Step 1: Fetch the official Apache-2.0 text (never retype it)**

Run: `curl -fsSL https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE && head -n 3 LICENSE && wc -l LICENSE`
Expected: first lines contain "Apache License" and "Version 2.0, January 2004"; line count is about 200.

- [ ] **Step 2: Write `NOTICE`**

```
Zarpa
Copyright 2026 The Zarpa contributors
```

The "This product includes software developed by ..." paragraph with the repository URL is added in Task 10 Step 6, once the URL exists.

- [ ] **Step 3: Verify**

Run: `grep -c "Apache License" LICENSE && cat NOTICE`
Expected: count >= 1; NOTICE shows the two-line header.

- [ ] **Step 4: Commit**

```bash
git add LICENSE NOTICE
git commit -s -m "chore: add Apache-2.0 license and notice"
```

---

### Task 3: Rust workspace skeleton (TDD)

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `rustfmt.toml`, `deny.toml`, `core/Cargo.toml`, `core/src/lib.rs`

- [ ] **Step 1: Write workspace config**

`Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["core"]

[workspace.package]
version = "0.0.0"
edition = "2021"
rust-version = "1.75"
license = "Apache-2.0"
publish = false

[workspace.lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
```

`rust-toolchain.toml`:
```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

`rustfmt.toml`:
```toml
edition = "2021"
max_width = 100
```

`deny.toml`:
```toml
[graph]
all-features = true

[advisories]
yanked = "deny"

[licenses]
allow = ["Apache-2.0", "MIT", "BSD-3-Clause", "ISC", "Unicode-3.0"]
confidence-threshold = 0.9

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

`core/Cargo.toml`:
```toml
[package]
name = "zarpa-core"
description = "Core library of Zarpa: protocol, crypto and transfer engine."
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[lints]
workspace = true
```

- [ ] **Step 2: Write the failing test (no implementation yet)**

`core/src/lib.rs`:
```rust
// SPDX-License-Identifier: Apache-2.0
//! Zarpa core library.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_cargo_manifest() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
        assert!(!version().is_empty());
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p zarpa-core 2>&1 | tail -15`
Expected: FAIL to compile with "cannot find function `version` in this scope".

- [ ] **Step 4: Write minimal implementation**

Insert above the `#[cfg(test)]` block in `core/src/lib.rs`:
```rust
/// Returns the version of the `zarpa-core` crate.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
```

- [ ] **Step 5: Run all quality gates**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: all succeed; test output shows `test tests::version_matches_cargo_manifest ... ok` and `1 passed`.

Run (optional if installed): `cargo deny check`
Expected: `advisories ok, bans ok, licenses ok, sources ok`. If `cargo-deny` is not installed, skip; CI runs it.

- [ ] **Step 6: Commit (include the generated lockfile)**

```bash
git add Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml deny.toml core
git commit -s -m "chore: add Rust workspace with zarpa-core crate"
```

---

### Task 4: Community and governance files

**Files:**
- Create: `README.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `CHANGELOG.md`, `.github/CODEOWNERS`

All commands below assume the GitHub login is derived with `OWNER=$(gh api user --jq .login)` in the same command (shell state does not persist between calls).

- [ ] **Step 1: Write `README.md`**

```markdown
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
```

- [ ] **Step 2: Write `CONTRIBUTING.md`**

```markdown
# Contributing to Zarpa

Thanks for helping! This project follows common open-source practice; the full engineering rules live in
[AGENTS.md](AGENTS.md).

## Ways to contribute

- Report bugs and propose features with the issue templates.
- Improve docs, translations and the protocol spec in `docs/`.
- Pick an issue labelled `good first issue` or `help wanted`.

## Development setup

1. Install Rust via https://rustup.rs (the repo pins the toolchain in `rust-toolchain.toml`).
2. Clone the repo and run:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```

## Workflow

1. Fork and branch from `main` (`feat/...`, `fix/...`, `docs/...`, `chore/...`).
2. Keep PRs small and focused; add or update tests and docs.
3. Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages and the PR title.
4. Sign off every commit (`git commit -s`) to certify the
   [Developer Certificate of Origin](https://developercertificate.org/). There is no CLA.
5. CI must pass (format, clippy, tests on Windows/macOS/Linux, cargo-deny).

## Design changes

Non-trivial changes start with an issue or a short ADR in `docs/adr/`. Protocol changes must update
`docs/protocol/` in the same PR.

## Conduct and security

Be kind: see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md), never in public issues.
```

- [ ] **Step 3: Fetch and complete the Code of Conduct**

Run:
```bash
OWNER=$(gh api user --jq .login)
curl -fsSL https://www.contributor-covenant.org/version/2/1/code_of_conduct/code_of_conduct.md -o CODE_OF_CONDUCT.md \
  || curl -fsSL https://raw.githubusercontent.com/EthicalSource/contributor_covenant/release/content/version/2/1/code_of_conduct.md -o CODE_OF_CONDUCT.md
sed -i "s|\[INSERT CONTACT METHOD\]|the private reporting form at https://github.com/$OWNER/zarpa/security/advisories/new|" CODE_OF_CONDUCT.md
grep -c "INSERT" CODE_OF_CONDUCT.md; grep -c "Contributor Covenant" CODE_OF_CONDUCT.md
```
Expected: first count `0`; second count >= 1.

- [ ] **Step 4: Write `SECURITY.md`**

```bash
OWNER=$(gh api user --jq .login)
cat > SECURITY.md <<EOF
# Security Policy

## Supported versions

Zarpa is pre-alpha. Only the latest commit on \`main\` receives security fixes until 1.0.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub:
https://github.com/$OWNER/zarpa/security/advisories/new

Please include a description, affected component, reproduction steps and impact. You will get an
acknowledgement within 7 days and a status update within 30 days. We credit reporters unless asked not to.

## Scope

In scope: the protocol, pairing and encryption, the daemon and its local API, shell extensions, the
CLI and MCP server (including agent permission bypasses), and release artifacts.
Out of scope: attacks requiring prior full control of a paired device, and denial of service from
physically present LAN attackers.
EOF
```

- [ ] **Step 5: Write `CHANGELOG.md`**

```markdown
# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/). Entries are generated by release-please from Conventional Commits.

## [Unreleased]

### Added
- Initial repository foundation: license, community files, CI, ADRs and draft protocol specification.
```

- [ ] **Step 6: Write `.github/CODEOWNERS`**

```bash
OWNER=$(gh api user --jq .login)
mkdir -p .github && printf '# Default owner for everything\n* @%s\n' "$OWNER" > .github/CODEOWNERS
cat .github/CODEOWNERS
```
Expected: `* @<your-github-login>`.

- [ ] **Step 7: Commit**

```bash
git add README.md CONTRIBUTING.md CODE_OF_CONDUCT.md SECURITY.md CHANGELOG.md .github/CODEOWNERS
git commit -s -m "docs: add README, contributing guide, code of conduct and security policy"
```

---

### Task 5: Issue and pull request templates

**Files:**
- Create: `.github/ISSUE_TEMPLATE/bug_report.yml`, `.github/ISSUE_TEMPLATE/feature_request.yml`, `.github/ISSUE_TEMPLATE/config.yml`, `.github/pull_request_template.md`

- [ ] **Step 1: Write `bug_report.yml`**

```yaml
name: Bug report
description: Something is broken or behaves unexpectedly
labels: ["bug", "needs-triage"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for reporting! Do **not** use this form for security issues; see SECURITY.md.
  - type: textarea
    id: what-happened
    attributes:
      label: What happened?
      description: What did you expect, and what happened instead?
    validations:
      required: true
  - type: textarea
    id: steps
    attributes:
      label: Steps to reproduce
      placeholder: "1. ...\n2. ...\n3. ..."
    validations:
      required: true
  - type: input
    id: version
    attributes:
      label: Zarpa version
      description: Output of `zarpa --version`
    validations:
      required: true
  - type: dropdown
    id: os
    attributes:
      label: Operating system
      multiple: true
      options: [Windows, macOS, Linux, Android, iOS]
    validations:
      required: true
  - type: textarea
    id: logs
    attributes:
      label: Logs
      description: Redact private paths and device names.
      render: shell
```

- [ ] **Step 2: Write `feature_request.yml`**

```yaml
name: Feature request
description: Suggest an improvement or a new capability
labels: ["enhancement", "needs-triage"]
body:
  - type: textarea
    id: problem
    attributes:
      label: Problem
      description: What are you trying to do that is hard or impossible today?
    validations:
      required: true
  - type: textarea
    id: proposal
    attributes:
      label: Proposed solution
    validations:
      required: true
  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives considered
```

- [ ] **Step 3: Write `config.yml`**

```yaml
blank_issues_enabled: false
contact_links:
  - name: Report a security vulnerability
    url: https://github.com/OWNER_PLACEHOLDER/zarpa/security/advisories/new
    about: Report privately; never open a public issue for vulnerabilities.
```

Then substitute the real login (the literal `OWNER_PLACEHOLDER` must not remain):
Run: `OWNER=$(gh api user --jq .login) && sed -i "s|OWNER_PLACEHOLDER|$OWNER|" .github/ISSUE_TEMPLATE/config.yml && grep -c PLACEHOLDER .github/ISSUE_TEMPLATE/config.yml`
Expected: `0`.

- [ ] **Step 4: Write `.github/pull_request_template.md`**

```markdown
## What and why

<!-- One or two sentences. Link the issue: Closes #123 -->

## Checklist

- [ ] PR title follows Conventional Commits (e.g. `feat(core): add device identity`)
- [ ] Commits are signed off (`git commit -s`)
- [ ] Tests added or updated
- [ ] Docs, protocol spec and CHANGELOG updated if behavior changed
- [ ] `cargo fmt`, `cargo clippy -D warnings` and `cargo test` pass locally
- [ ] No secrets, keys or private paths in the diff
```

- [ ] **Step 5: Validate YAML and commit**

Run: `python -c "import sys,yaml,glob;[yaml.safe_load(open(f,encoding='utf-8')) for f in glob.glob('.github/ISSUE_TEMPLATE/*.yml')];print('yaml ok')"`
Expected: `yaml ok` (if PyYAML is missing, run `pip install pyyaml` first).

```bash
git add .github/ISSUE_TEMPLATE .github/pull_request_template.md
git commit -s -m "chore: add issue forms and pull request template"
```

---

### Task 6: CI and PR-check workflows

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/workflows/pr-checks.yml`

- [ ] **Step 1: Write `ci.yml`**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

env:
  CARGO_TERM_COLOR: always

jobs:
  lint:
    name: Format and clippy
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets -- -D warnings

  test:
    name: Test (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo test --workspace

  deny:
    name: cargo-deny
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v2
```

- [ ] **Step 2: Write `pr-checks.yml`**

```yaml
name: PR checks

on:
  pull_request:
    types: [opened, edited, synchronize, reopened]

permissions:
  contents: read
  pull-requests: read

jobs:
  title:
    name: Conventional Commit title
    runs-on: ubuntu-latest
    steps:
      - uses: amannn/action-semantic-pull-request@v5
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  dco:
    name: DCO sign-off
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Verify every commit is signed off
        env:
          BASE: ${{ github.event.pull_request.base.sha }}
          HEAD: ${{ github.event.pull_request.head.sha }}
        run: |
          missing=0
          for c in $(git rev-list --no-merges "$BASE..$HEAD"); do
            if ! git show -s --format=%B "$c" | grep -qE '^Signed-off-by: .+ <.+>$'; then
              echo "Missing Signed-off-by: $c"
              missing=1
            fi
          done
          exit $missing
```

- [ ] **Step 3: Validate YAML**

Run: `python -c "import yaml,glob;[yaml.safe_load(open(f,encoding='utf-8')) for f in glob.glob('.github/workflows/*.yml')];print('yaml ok')"`
Expected: `yaml ok`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml .github/workflows/pr-checks.yml
git commit -s -m "ci: add lint, test matrix, cargo-deny, PR title and DCO checks"
```

---

### Task 7: Security automation and releases

**Files:**
- Create: `.github/dependabot.yml`, `.github/workflows/codeql.yml`, `.github/workflows/release-please.yml`, `release-please-config.json`, `.release-please-manifest.json`

- [ ] **Step 1: Write `.github/dependabot.yml`**

```yaml
version: 2
updates:
  - package-ecosystem: cargo
    directory: /
    schedule:
      interval: weekly
    commit-message:
      prefix: "chore(deps)"
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
    commit-message:
      prefix: "ci(deps)"
```

- [ ] **Step 2: Write `.github/workflows/codeql.yml`**

```yaml
name: CodeQL

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "0 5 * * 1"

permissions:
  contents: read
  security-events: write

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: rust
          build-mode: none
      - uses: github/codeql-action/analyze@v3
```

- [ ] **Step 3: Write release automation**

`release-please-config.json`:
```json
{
  "$schema": "https://raw.githubusercontent.com/googleapis/release-please/main/schemas/config.json",
  "packages": {
    "core": {
      "release-type": "rust",
      "component": "zarpa-core",
      "changelog-path": "CHANGELOG.md"
    }
  }
}
```

`.release-please-manifest.json`:
```json
{
  "core": "0.0.0"
}
```

`.github/workflows/release-please.yml`:
```yaml
name: release-please

on:
  push:
    branches: [main]

permissions:
  contents: write
  pull-requests: write

jobs:
  release-please:
    runs-on: ubuntu-latest
    steps:
      - uses: googleapis/release-please-action@v4
        with:
          config-file: release-please-config.json
          manifest-file: .release-please-manifest.json
```

Note: signed multi-platform release artifacts are out of scope for M0; they are delivered in M7.

- [ ] **Step 4: Validate and commit**

Run: `python -c "import yaml,json;yaml.safe_load(open('.github/dependabot.yml'));yaml.safe_load(open('.github/workflows/codeql.yml'));yaml.safe_load(open('.github/workflows/release-please.yml'));json.load(open('release-please-config.json'));json.load(open('.release-please-manifest.json'));print('ok')"`
Expected: `ok`.

```bash
git add .github/dependabot.yml .github/workflows/codeql.yml .github/workflows/release-please.yml release-please-config.json .release-please-manifest.json
git commit -s -m "ci: add dependabot, codeql and release-please"
```

---

### Task 8: ADRs and docs index

**Files:**
- Create: `docs/README.md`, `docs/adr/0001-record-architecture-decisions.md`, `docs/adr/0002-daemon-centric-architecture.md`, `docs/adr/0003-apache-2-license.md`

- [ ] **Step 1: Write `docs/adr/0001-record-architecture-decisions.md`**

```markdown
# 1. Record architecture decisions

- Status: accepted
- Date: 2026-10-30

## Context
Contributors need to understand *why* the system is built the way it is.

## Decision
We record significant decisions as short ADRs in `docs/adr/`, numbered sequentially, each with Status,
Context, Decision and Consequences. Superseded ADRs are kept and marked as such.

## Consequences
Design discussion is discoverable and reviewable in PRs; small overhead per decision.
```

- [ ] **Step 2: Write `docs/adr/0002-daemon-centric-architecture.md`**

```markdown
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
```

- [ ] **Step 3: Write `docs/adr/0003-apache-2-license.md`**

```markdown
# 3. License the project under Apache-2.0

- Status: accepted
- Date: 2026-10-30

## Context
We want maximum adoption, contributions from companies, an explicit patent grant and compatibility with
app-store distribution.

## Decision
All code is licensed under Apache-2.0 with an SPDX header in each source file. Contributions are accepted
under the same license via DCO sign-off (no CLA).

## Consequences
Anyone may reuse the code, including in closed-source products. A future hosted service gains no
copyleft protection; revisit only for server components if needed.
```

- [ ] **Step 4: Write `docs/README.md`**

```markdown
# Zarpa documentation

- [Design specification](superpowers/specs/2026-10-30-zarpa-design.md)
- [Protocol specification (draft)](protocol/README.md)
- [Architecture decision records](adr/)
- [Implementation plans](superpowers/plans/)
```

- [ ] **Step 5: Commit**

```bash
git add docs/README.md docs/adr
git commit -s -m "docs: add ADRs and documentation index"
```

---

### Task 9: Draft protocol specification

**Files:**
- Create: `docs/protocol/README.md`

- [ ] **Step 1: Write `docs/protocol/README.md`**

```markdown
# Zarpa Protocol — Draft v0

Status: **draft**, not stable. Wire compatibility is not guaranteed before 1.0.
The key words MUST, SHOULD and MAY are used as in RFC 2119.

Message encoding is selected by ADR-0004 during milestone M1; this draft therefore specifies messages
semantically (fields and meaning), not byte layouts.

## 1. Transport

- Peers communicate over QUIC with TLS 1.3. The ALPN identifier is `zarpa/0`.
- Each peer presents a self-signed certificate bound to its Ed25519 identity key. Peers MUST authenticate
  each other by public key against their trust list and MUST NOT rely on certificate authorities.
- A connection carries one control stream plus one data stream per active block lane.

## 2. Identity

- A device identity is an Ed25519 key pair. The **device ID** is the public key.
- The display name is a human label, MUST NOT be used for authentication and MAY be changed at any time.

## 3. Discovery

- Devices advertise over mDNS (`_zarpa._udp.local`) with an identifier derived from the public key.
- The advertisement MUST NOT contain the display name of a device unless the viewer is a trusted peer.

## 4. Pairing

1. Initiator displays a QR or short code containing its public key and a one-time secret.
2. Responder connects, proves knowledge of the secret and sends its public key.
3. Both derive a 4-6 digit verification code from the handshake transcript and show it; users confirm
   the codes match.
4. On confirmation each side stores the other's public key as **trusted**.

## 5. Transfer

A transfer is described by a **manifest**:

```json
{
  "transfer_id": "b6c1f0e2-0d6a-4f0e-9c0b-3f0f6a1d2e11",
  "block_size": 4194304,
  "entries": [
    {
      "path": "videos/holiday.mp4",
      "size": 8388608,
      "blocks": [
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6"
      ]
    }
  ]
}
```

The example file is exactly two 4 MiB blocks; a manifest lists one BLAKE3 hash per block.

- The sender offers the manifest; the receiver accepts, rejects or (for trusted peers) auto-accepts.
- Blocks are sent in parallel across data streams. The receiver MUST verify each block's BLAKE3 hash before
  writing it and MUST reject mismatching blocks.
- Resume: the receiver reports the set of verified blocks; the sender sends only the missing ones.
- The receiver MUST write to a temporary file and move it to the final path only after all blocks verify.
- Paths in the manifest MUST be relative, MUST NOT contain `..` or absolute components, and are sanitized
  by the receiver; writes MUST stay inside the receiver's chosen download folder.

## 6. Errors

Errors carry a stable code, e.g. `DEVICE_UNREACHABLE`, `TRANSFER_REJECTED`, `BLOCK_HASH_MISMATCH`,
`PATH_NOT_ALLOWED`, `UNSUPPORTED_VERSION`.

## 7. Versioning

The protocol version is carried in the ALPN identifier. Incompatible changes bump the major number
(`zarpa/1`); peers that do not share a version MUST fail with `UNSUPPORTED_VERSION`.
```

- [ ] **Step 2: Verify no unfinished markers**

Run: `grep -rniE "TBD|TODO|FIXME|PLACEHOLDER" docs README.md CONTRIBUTING.md SECURITY.md .github || echo CLEAN`
Expected: `CLEAN`. The plan file under `docs/superpowers/plans/` is deliberately outside this search.

- [ ] **Step 3: Commit**

```bash
git add docs/protocol
git commit -s -m "docs(protocol): add draft v0 specification"
```

---

### Task 10: Publish (outward-facing — requires explicit user confirmation)

**Files:** none (remote operations)

- [ ] **Step 1: Confirm with the user**

Show the user: repo name `zarpa`, visibility **public**, owner from `gh api user --jq .login`. Ask for a clear yes. Do not proceed on silence or on a notification. Also confirm Task 0 Step 2 was answered yes.

- [ ] **Step 2: Create the repository and push `main`**

```bash
OWNER=$(gh api user --jq .login)
gh repo create "$OWNER/zarpa" --public --description "Right-click a file, pick a device, done. Open-source, agent-friendly file transfer." --source . --remote origin
git push -u origin main
```
Expected: repo URL printed; `main` pushed (it contains only the initial docs commit).

- [ ] **Step 3: Push the branch and open the PR**

```bash
git push -u origin chore/m0-oss-foundation
gh pr create --base main --title "chore: M0 open-source foundation" --body "Adds license, community files, templates, CI, security automation, Rust workspace skeleton, ADRs and the draft protocol spec.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```
Expected: a PR URL. Then run `gh pr checks --watch` and confirm CI, PR checks and CodeQL pass. Fix failures on the branch with new signed commits; do not merge red.

- [ ] **Step 4: Merge with squash, then protect `main`**

After the user approves the PR:
```bash
gh pr merge --squash --delete-branch
git checkout main && git pull
```
Then enable branch protection (requires admin; adjust check names to those shown by `gh pr checks`):
```bash
OWNER=$(gh api user --jq .login)
gh api -X PUT "repos/$OWNER/zarpa/branches/main/protection" --input - <<'JSON'
{
  "required_status_checks": {"strict": true, "contexts": ["Format and clippy", "Test (ubuntu-latest)", "Test (windows-latest)", "Test (macos-latest)", "cargo-deny", "Conventional Commit title", "DCO sign-off"]},
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```
Expected: JSON response containing `"url"` of the protection rule.

- [ ] **Step 5: Enable repository security features and labels**

```bash
OWNER=$(gh api user --jq .login)
gh api -X PUT "repos/$OWNER/zarpa/private-vulnerability-reporting"
gh api -X PATCH "repos/$OWNER/zarpa" -f delete_branch_on_merge=true -F allow_squash_merge=true -F allow_merge_commit=false -F allow_rebase_merge=false
gh label create "good first issue" --color 7057ff --description "Good for newcomers" || true
gh label create "help wanted" --color 008672 --description "Extra attention is needed" || true
gh label create "needs-triage" --color ededed --description "Awaiting maintainer triage" || true
```
Expected: commands succeed (labels that already exist are ignored).

- [ ] **Step 6: Add the repository URL where it was deliberately omitted**

On a new branch `docs/add-repo-url`: add `repository = "https://github.com/<OWNER>/zarpa"` to `[workspace.package]` in `Cargo.toml` and restore the "This product includes software developed by the Zarpa contributors (https://github.com/<OWNER>/zarpa)." paragraph in `NOTICE`, then:

```bash
cargo check --workspace
git add Cargo.toml NOTICE
git commit -s -m "chore: add repository URL to manifest and notice"
```
Open a PR, wait for green checks, squash-merge (after the user's go-ahead).

---

## Self-review (spec coverage)

| Spec requirement (M0 and §13) | Task |
|---|---|
| Public repo | 10 |
| License (Apache-2.0, SPDX) | 2, 3 (lib.rs header), 8 (ADR-0003) |
| README, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, CHANGELOG, CODEOWNERS | 4 |
| Issue/PR templates | 5 |
| CI on Windows/macOS/Linux, fmt, clippy -D warnings | 6, 3 |
| Dependabot, CodeQL, cargo-deny | 7, 6, 3 |
| Conventional Commits and DCO enforcement | 6 |
| Semantic versioning and automated releases | 7 |
| `forbid(unsafe_code)`, no unwrap in lib | 3 (workspace lints) |
| Protected `main`, squash PRs | 10 |
| Draft protocol spec | 9 |
| ADRs | 8 |
| Name clearance risk | 0, 10 |
| Line endings (CRLF warning from Windows) | 1 |
| Signed artifacts, package managers | Deferred to M7 by spec |
