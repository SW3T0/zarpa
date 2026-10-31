# Spikes

Throwaway-but-kept experiments that inform architecture decisions. Not part of the root workspace and not
built by CI.

## M1.1 — transport and encoding

Compares `quinn` and `iroh` behind one `Transport` trait and compares control-message encodings.
Results: `docs/spikes/2026-m1-1-results.md`. Decisions: ADR-0004 and ADR-0005.

Run from PowerShell (Windows) or any shell (Linux/macOS), inside `spikes/`:

    cargo test --workspace
    cargo run -p bench --release -- --mib 1024
    cargo run -p bench --release -- --encoding
