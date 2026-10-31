# 6. Local state storage

- Status: accepted
- Date: 2026-10-30

## Context

The daemon must keep a device secret key and a list of trusted devices across restarts
(design spec section 5). The secret needs the strongest storage the platform offers; the
trust list is small and must be easy to inspect and back up.

## Decision

- The device secret (32-byte Ed25519 seed) goes through a `SecretStore` trait. The operating
  system's secure store is preferred (`OsKeyringStore`, Cargo feature `os-keyring`); an
  owner-only file (`FileSecretStore`, mode 0600 on Unix) is the fallback for systems without a
  keyring. Mobile platforms will provide their own store (M5).
- A stored secret of the wrong length is an error and is never replaced automatically.
- The trust list is a JSON file (`{"version":1,"devices":[...]}`) written atomically (temp file
  and rename), loaded fully in memory, with a single writer (the daemon).
- SQLite is reserved for transfer history.

## Consequences

- No new native dependency for the trust list; the file can be read, diffed and backed up.
- Losing the secret means a new device ID and re-pairing with every peer; the corrupt-secret
  rule exists to prevent doing that silently.
- The file fallback is weaker than a keyring against other processes running as the same user.
  The UI should say which store is in use (M3).
- A multi-writer or very large trust list would justify moving it into SQLite later; the
  `TrustStore` API hides the format.

## Alternatives considered

- **Everything in SQLite:** one storage engine, but adds a native dependency now and mixes
  secrets with ordinary data.
- **Keyring only:** unusable on headless Linux and CI, so there would be no way to run the
  daemon there.
