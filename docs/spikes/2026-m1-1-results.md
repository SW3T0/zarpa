# M1.1 spike results — transport stack and message encoding

Date: 2026-10-30 · Plan: [M1.1 plan](../superpowers/plans/2026-10-30-m1-1-transport-spike.md) ·
Code: `spikes/` · Decisions: [ADR-0004](../adr/0004-message-encoding.md), [ADR-0005](../adr/0005-transport-stack.md)

All numbers below were measured on one machine and copied from the tool output; nothing is estimated.

## 1. Environment

| Item | Value |
|---|---|
| OS | Windows 11 Pro 10.0.26200 |
| CPU | Intel Core i5-9400 @ 2.90 GHz |
| RAM | 16 GiB |
| Toolchain | rustc 1.99.1 (2026-10-13), cargo 1.99.1, MSVC Build Tools 2022 |
| Network | Online during all runs (Ethernet 192.168.0.50 plus Tailscale, Hyper-V and VPN adapters present) |

## 2. Versions

| Crate | Version |
|---|---|
| quinn / quinn-proto | 0.11.12 / 0.11.19 |
| rustls (both adapters) | 0.23.46, crypto provider `ring` 0.17.14 |
| rcgen / x509-parser (quinn adapter) | 0.14.10 / 0.18.1 |
| iroh | 1.4.1 (feature `tls-ring` only; its QUIC layer is n0's own `noq` 1.4.0, not quinn) |
| mdns-sd (quinn discovery) | 0.21.6 |
| iroh-mdns-address-lookup (iroh discovery) | 0.6.1 (separate crate; iroh 1.x has no built-in mDNS) |
| blake3 / ciborium / postcard / rmp-serde | 1.8.7 / 0.2.2 / 1.1.3 / 1.3.1 |
| tokio | 1.54.1 |

## 3. Conformance (the contract in `spikes/bench-core/src/conformance.rs`)

| Test | quinn | iroh |
|---|---|---|
| `authenticated_roundtrip` | pass | pass |
| `rejects_untrusted_peer` | pass | pass |
| `rejects_unknown_server` | pass | pass |
| `transfer_verified` | pass | pass |
| `resume_after_drop` (only the 5 missing blocks re-sent) | pass | pass |

Both adapters also pass three adapter-local tests. Both passed on the first implementation attempt.
Note: for `rejects_unknown_server` the client trusts nobody, so both adapters refuse before dialing; the handshake
path is covered by the adapter-local wrong-key tests (TLS certificate error for quinn, handshake failure for iroh).

## 4. Throughput (loopback, 1 GiB, median of 3 runs)

| transport | MiB sent | streams | median MiB/s |
|---|---|---|---|
| quinn | 1024 | 1 | 177 |
| iroh | 1024 | 1 | 166 |
| quinn | 1024 | 4 | 181 |
| iroh | 1024 | 4 | 167 |

iroh is 6.2 % (1 stream) and 7.7 % (4 streams) below quinn. Both clear the 100 MiB/s floor. A 64 MiB smoke run
gave 167-171 MiB/s for both. Only medians were printed, so run-to-run spread was not recorded.

## 5. Encodings

| message | encoding | bytes | encode µs | decode µs |
|---|---|---|---|---|
| manifest (256 blocks) | CBOR (ciborium) | 8229 | 0.55 | 0.75 |
| manifest (256 blocks) | postcard | 8203 | 0.37 | 0.21 |
| manifest (256 blocks) | MessagePack (rmp-serde) | 8229 | 0.50 | 0.25 |
| want list (64 indices) | CBOR (ciborium) | 121 | 0.80 | 1.92 |
| want list (64 indices) | postcard | 66 | 0.54 | 0.16 |
| want list (64 indices) | MessagePack (rmp-serde) | 82 | 0.71 | 0.30 |

The manifest is dominated by 8192 bytes of raw hashes, so the three encodings are within 26 bytes of each other.
Run-to-run noise at the microsecond level is expected (a first run gave 0.59/0.80 for CBOR manifest).

## 6. Local-network discovery (no relay, no DNS/pkarr lookup)

Two instances of each example were started 1 s and 2 s apart on this machine.

| | quinn + mdns-sd | iroh + iroh-mdns-address-lookup |
|---|---|---|
| Each instance found the other's key | yes, 2 of 2 runs | yes, 2 of 2 runs |
| Addresses resolved | a single address per resolution (`172.22.176.1`, the Hyper-V adapter, or `127.0.0.1`), never the Ethernet IP `192.168.0.50` | three addresses per peer: Tailscale `100.110.217.17`, Hyper-V `172.22.176.1`, Ethernet `192.168.0.50` |
| Extra dependency needed | `mdns-sd` (+8 crates, dev-dependency here) | `iroh-mdns-address-lookup` (+6 crates, dev-dependency here) |
| Dialable after discovery | not tested; the quinn adapter binds loopback only | not tested |

What was not covered: no two-device LAN test, the machine stayed online (so "works unplugged" is not demonstrated;
relay and address lookup were explicitly disabled and iroh logs "skipping net_report, empty RelayMap"), no packet
capture, and no connection to a discovered address. I could not observe whether a Windows Firewall prompt appeared.

## 7. Dependencies, licenses, size

| | quinn adapter | iroh adapter |
|---|---|---|
| Unique crates (name+version, normal deps) | 89 | 250 |
| Unique crates with discovery dev-dependency | 97 | 256 |
| Native build tools needed on Windows | none beyond MSVC | none beyond MSVC |
| `aws-lc-rs` / OpenSSL in tree | no / no | no / no |
| Licenses to add to `deny.toml` | none | `Zlib`, `BSD-2-Clause`, `CDLA-Permissive-2.0` |
| `discover` example, release binary | 3,263,488 bytes | 11,207,680 bytes |

Where the extra iroh licenses come from: `Zlib` is `foldhash` and `slotmap`; `BSD-2-Clause` is `spez` (proc macro);
`CDLA-Permissive-2.0` is `webpki-roots` (via `iroh-relay` and `n0-dns-resolver`), which is the Mozilla CA bundle used by
the relay client that Zarpa would not use at runtime. `bench.exe` links both adapters: 12,160,000 bytes.
`cargo-deny` was not installed, so these conclusions come from `cargo tree --format "{l}"`, not from `cargo deny check`.
`ring` may need a `licenses.clarify` entry; not checked.

## 8. Mobile (informational)

`cargo check --target aarch64-linux-android` fails for both adapters at the same point: the `ring` build script cannot
find `clang` (no Android NDK installed). Nothing beyond `ring` was reached, so other C dependencies are unchecked.
iOS cannot be checked on Windows.

## 9. Caveats

- **Throughput is probably bounded by the benchmark harness, not by the transports.** All four rows sit between 166 and
  181 MiB/s, far below what loopback QUIC can do, and 1 vs 4 streams changed almost nothing. The per-block path (4 MiB
  allocation, copy, BLAKE3 verification and AEAD encryption on both ends, plus a mutex-guarded verified set) is the likely
  limit. The ranking of the two stacks is meaningful; the absolute number is not a statement about either stack's ceiling,
  and the project goal of saturating the link must be re-measured and profiled in M2.
- Loopback is not a real LAN; one machine; one CPU model; three runs per row.
- Discovery was tested on a single host; address selection on a multi-adapter machine (Tailscale, VPN, Hyper-V) is a real
  issue for M1.3 (mdns-sd returned only one, non-LAN, address).
- The quinn adapter checks certificate identity by key only and does not validate certificate dates; its `accept` completes
  one handshake at a time. Both are acceptable for a spike and must change for production.
