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
