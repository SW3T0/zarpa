# 5. Build the transport on iroh

- Status: accepted
- Date: 2026-10-30

## Context

Zarpa needs an authenticated, multiplexed, encrypted transport for LAN transfers now and NAT traversal later. The M1.1
spike implemented one `Transport` trait over **quinn** (plain QUIC with rustls) and over **iroh** 1.4.1 (QUIC with
identity, discovery hooks, hole punching and relays) and ran both through the same conformance suite and benchmarks
(`docs/spikes/2026-m1-1-results.md`). The decision rules were fixed before measuring (M1.1 plan).

## Decision

Build the transport on **iroh**. The project owner chose this over the outcome of a literal reading of the pre-registered
rules, which would have selected quinn. The evidence and the override are recorded here.

| Rule | quinn | iroh | Outcome |
|---|---|---|---|
| 1. Conformance: all five tests pass | pass | pass | neither eliminated |
| 1. Throughput at least 100 MiB/s (1 GiB, 4 streams, median of 3) | 181 | 167 | neither eliminated |
| 2a. iroh within 20 % of the best | best | 7.7 % below | satisfied |
| 2b. Local discovery works with no relay | yes (via `mdns-sd`) | yes (via `iroh-mdns-address-lookup`) | satisfied, with caveats: single host, machine online, relay and lookup disabled |
| 2c. Every license permissive per the rule's list (MIT, Apache-2.0, BSD, ISC, Unicode, Zlib, CC0, MPL-2.0) | no additions to `deny.toml` | needs `Zlib`, `BSD-2-Clause`, `CDLA-Permissive-2.0` | **not satisfied literally**: `CDLA-Permissive-2.0` is not in the list |

Rule 2c failed on one license only: `CDLA-Permissive-2.0`, which covers the `webpki-roots` CA bundle pulled in by iroh's
relay client. It is a permissive data license, and the rule's intent is to exclude restrictive licenses, so the owner
accepted it. The deciding factor is Phase 2 (remote devices with WireGuard-like reach): iroh already provides hole
punching, relays and key-based dialing, which is most of that phase.

## Consequences

**What we get with iroh**
- Identity by public key, NAT traversal and relay fallback ready for Phase 2, with the `Transport` trait and conformance
  suite as the safety net.
- A stable 1.x API (iroh 1.4.1) maintained by a dedicated team.
- Throughput within 8 % of quinn in the spike (and the numbers are harness-bound; see below).

**What we take on**
- A larger dependency tree (250 vs 89 unique crates) and binary (about 11.2 MB vs 3.3 MB for the discovery example).
- The public protocol rides on iroh's QUIC conventions (its own `noq` QUIC layer and key-pinned handshake). A third party
  needs a compatible stack to talk to Zarpa. The protocol draft says so (`docs/protocol/README.md`, section 1).
- Local-network discovery is not built into iroh 1.x: it needs the separate `iroh-mdns-address-lookup` crate.
- The relay client and HTTP stack (`iroh-relay`, `reqwest`) compile in even when the relay is disabled at runtime.
- Zarpa depends on n0's release cadence and defaults. The spike endpoint disables everything that contacts n0 services:
  `presets::Minimal`, `RelayMode::Disabled`, no address lookup, minimal net-report. Production code must keep relay and
  DNS/pkarr usage an explicit, user-visible choice (a privacy requirement, not only a technical one).

**Follow-ups**
- When iroh enters the root workspace (M1.2 onwards), add `Zlib`, `BSD-2-Clause` and `CDLA-Permissive-2.0` to
  `deny.toml`, and check whether `ring` needs a `licenses.clarify` entry. Run `cargo deny check` for real.
- M1.3 must choose the right interface addresses: on a multi-adapter machine the spike's quinn/mdns-sd example resolved a
  Hyper-V address; iroh's example advertised Tailscale, Hyper-V and Ethernet addresses together.
- Android needs the NDK for `ring`'s build script (both stacks); iOS is unchecked.
- The throughput numbers are likely harness-bound (results, section 9); profile and re-measure in M2 before claiming the
  link is saturated.
- Keep the spike in `spikes/`: if iroh stops fitting, the conformance suite makes a swap to quinn a bounded piece of work.

## Alternatives considered

- **quinn + rustls:** passes every test, about 7 % faster in the spike, a far smaller tree (89 crates), no new licenses,
  and a protocol that any QUIC stack can implement. It was the outcome of the literal rule. Rejected because Phase 2 would
  require building discovery, hole punching and relays ourselves.
- **Decision without a spike:** rejected; the spec required measured evidence.
