# 5. Build the transport on quinn

- Status: proposed
- Date: 2026-10-30

## Context

Zarpa needs an authenticated, multiplexed, encrypted transport for LAN transfers now and NAT traversal later. The M1.1
spike implemented one `Transport` trait over **quinn** (plain QUIC with rustls) and over **iroh** 1.4.1 (QUIC with
identity, discovery hooks, hole punching and relays) and ran both through the same conformance suite and benchmarks
(`docs/spikes/2026-m1-1-results.md`). The decision rules were fixed before measuring (M1.1 plan).

## Decision

Build the transport on **quinn + rustls**. **This is a close call, and the owner may override it** (see Rule 2 below).

| Rule | quinn | iroh | Outcome |
|---|---|---|---|
| 1. Conformance: all five tests pass | pass | pass | neither eliminated |
| 1. Throughput at least 100 MiB/s (1 GiB, 4 streams, median of 3) | 181 | 167 | neither eliminated |
| 2a. iroh within 20 % of the best | best | 7.7 % below | satisfied |
| 2b. Local discovery works with no relay | yes (via `mdns-sd`) | yes (via `iroh-mdns-address-lookup`) | satisfied, with caveats: single host, machine online, relay and lookup disabled |
| 2c. Every license permissive per the rule's list (MIT, Apache-2.0, BSD, ISC, Unicode, Zlib, CC0, MPL-2.0) | no additions to `deny.toml` | needs `Zlib`, `BSD-2-Clause`, `CDLA-Permissive-2.0` | **not satisfied literally**: `CDLA-Permissive-2.0` is not in the list |

Rule 2 requires all three sub-conditions for `iroh` to be preferred. 2c fails on one license: `CDLA-Permissive-2.0`, which
covers only the `webpki-roots` CA bundle pulled in by iroh's relay client, a component Zarpa would not use on the LAN. It
is a permissive data license, so reading the rule by its intent rather than its literal list would flip the outcome to
iroh. The rule as written yields quinn, so quinn is proposed. Whether the intent reading should win is the owner's call.

## Consequences

**What we get with quinn**
- A far smaller dependency tree (89 vs 250 unique crates), a smaller binary (about 3.3 MB vs 11.2 MB for the discovery
  example), no new licenses, and a measured throughput about 7 % higher.
- The public protocol is plain QUIC with mutual TLS using self-signed Ed25519 certificates and the ALPN `zarpa/0`, so a
  third party can implement it with any QUIC stack. This matches the goal of a public, implementable specification.
- Full control of identity checks: both verifiers pin the peer's Ed25519 key and still verify the handshake signature.

**What we take on**
- Zarpa must build discovery on its own (`mdns-sd` worked in the spike), including choosing the right interface
  addresses on multi-adapter machines (the spike resolved a Hyper-V address instead of the LAN address).
- **Phase 2 (remote devices) is a real cost:** NAT traversal, hole punching and relays are not provided by quinn. iroh
  provides them. If remote transfer becomes the priority, reconsider iroh at the start of Phase 2; the `Transport` trait
  and the conformance suite exist precisely so that this swap is a bounded piece of work.
- The custom TLS verifier is the security-critical core of the adapter; it is code Zarpa now owns and must keep reviewed.

**Follow-ups**
- Keep the conformance suite and the spike in `spikes/` as the regression test for any future transport.
- The throughput numbers are likely harness-bound (results, section 9); profile and re-measure in M2 before claiming
  the link is saturated.
- No `deny.toml` change is needed for quinn. If iroh is chosen instead, add `Zlib`, `BSD-2-Clause` and
  `CDLA-Permissive-2.0`, and check whether `ring` needs a `licenses.clarify` entry.

## Alternatives considered

- **iroh 1.4.1:** equal conformance, 6-8 % slower, a much larger tree, and discovery in a separate crate, but it ships
  hole punching and relays, which is most of Phase 2. Its QUIC layer is n0's own `noq`, and a Zarpa protocol on iroh would
  ride iroh's conventions, so third-party clients would need a compatible stack. Strongest argument for it: Phase 2
  effort. It is the main alternative if the owner overrides rule 2c.
- **Direct decision without a spike:** rejected; the spec required measured evidence.
