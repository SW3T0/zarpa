# 4. Use CBOR for control messages

- Status: proposed
- Date: 2026-10-30

## Context

Zarpa's control messages (offer/manifest, want-list, acknowledgements, errors) need a byte encoding. A stated project
goal is that third parties can write compatible clients from the public protocol specification, in any language. The
spike (`docs/spikes/2026-m1-1-results.md`, section 5) measured CBOR, postcard and MessagePack on a 256-block manifest
and a 64-index want list.

## Decision

Use **CBOR (RFC 8949)** for all control messages.

The pre-registered rule chooses CBOR unless encode+decode of the 256-hash manifest exceeds 1 ms, or CBOR's size exceeds
postcard's by more than 10 % for that manifest. Both thresholds are met with a wide margin:

| Rule | Measured | Result |
|---|---|---|
| Manifest encode+decode under 1 ms | 0.55 µs + 0.75 µs = 1.30 µs (about 770x under) | pass |
| CBOR manifest size within 10 % of postcard | 8229 vs 8203 bytes (+0.3 %) | pass |

Block payloads are not encoded: they travel as raw bytes in their own framing, so the encoding only touches small
control messages. Hashes are carried as one byte string (not as an array of integers), which keeps CBOR compact.

## Consequences

- Self-describing and an IETF standard, with mature libraries in practically every language: a third-party client does
  not need Rust.
- Fields can be added without breaking old readers (unknown map keys are ignorable), which supports the protocol's
  versioning plan.
- Cost: CBOR is the slowest to decode of the three and larger for small messages (want list: 121 bytes vs 66 for
  postcard, +83 %). These are microseconds and bytes against multi-megabyte blocks, so they do not matter for throughput.
- The control-message schema will be defined once in `docs/protocol/` and implemented with `ciborium` in Rust. If a
  hot path ever shows encoding cost, only that message can move to a faster format behind a protocol version bump.

## Alternatives considered

- **postcard:** smallest and fastest (manifest 0.37/0.21 µs), but a Rust-centric, non-self-describing format; weak
  support outside Rust and poor forward compatibility. Rejected for interoperability.
- **MessagePack (rmp-serde):** close to CBOR in size (manifest identical at 8229 bytes) and faster to decode
  (0.25 µs), and widely supported, but CBOR is an IETF standard with better-defined deterministic encoding. A reasonable
  fallback if CBOR ever proves a problem.
