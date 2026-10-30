# adapter-iroh — notes

## Versions (from `spikes/Cargo.lock`, 2026-10-30)

| Crate | Version |
|---|---|
| iroh | 1.4.1 |
| iroh-base | 1.4.1 |
| iroh-relay | 1.4.1 (always compiled, even with relay disabled at runtime) |
| iroh-dns | 1.4.1 |
| iroh-metrics | 1.0.2 |
| noq / noq-proto / noq-udp | 1.4.0 (n0's QUIC implementation used by iroh 1.x; not `quinn`) |
| netwatch | 0.19.3 |
| rustls | 0.23.46 (same as adapter-quinn) |
| ring | 0.17.14 |
| ed25519-dalek | 3.0.0 (iroh) alongside 2.2.0 (bench-core) |
| reqwest | 0.13.5 (pulled by iroh / iroh-relay / n0-dns-resolver) |
| tokio | 1.54.1 |

Toolchain: Rust 1.99.x, MSVC Build Tools, Windows 11.

### Feature flags

```toml
iroh = { version = "1.4.1", default-features = false, features = ["tls-ring"] }
```

iroh's defaults are `metrics`, `fast-apple-datapath`, `portmapper`, `tls-ring`. Only `tls-ring` is
kept: `portmapper` (UPnP/PCP/NAT-PMP gateway probing) is not compiled at all, `metrics` is off,
`fast-apple-datapath` is irrelevant on Windows. `cargo tree -e features -i iroh` shows only
`iroh feature "tls-ring"`.

## Decision-rule facts

- **(a) Version / features:** iroh 1.4.1, features `tls-ring` only (above).
- **(b) Network services at bind time with relay disabled:** none. With an empty relay map iroh's
  socket actor logs `skipping net_report, empty RelayMap` and never runs net-report (no QAD/STUN, no
  HTTPS latency probes, no captive-portal check); direct addresses are taken from local interfaces
  (`socket.rs`, `re_stun` / net-report code paths with `relay_map.is_empty()`). No address-lookup
  service is configured, so nothing is published to or resolved from DNS/pkarr. `bind()` still
  builds a `DnsResolver` from the system DNS configuration (reads local config only; it is only used
  to resolve relay hostnames or for DNS address lookup, neither of which is configured), and starts
  `netwatch` to monitor local interfaces (OS APIs, no network traffic). The endpoint only binds
  `127.0.0.1:<random>`. Not verified with a packet capture; verified from source and from the tests
  passing with loopback-only sockets.
- **(c) Native tools on Windows:** none beyond MSVC Build Tools (already needed for `ring`'s C/asm
  code, same as adapter-quinn). `cargo tree -i` finds no `aws-lc-rs`, `aws-lc-sys`, `openssl-sys`,
  `cmake` or `portmapper` in the graph. First clean build of the crate + deps: ~1 m 50 s (debug).
- **(d) TLS/crypto provider:** rustls 0.23 with the **ring** provider (`tls-ring` feature;
  `presets::Minimal` installs `rustls::crypto::ring::default_provider()`). Note: even with the
  `platform-verifier` feature off, `rustls-platform-verifier` 0.7.1 is in the graph via `reqwest`
  (used for relay/pkarr HTTPS, unused here) — relevant for the licence/dependency review in Task 9.
- **Licences of the iroh crates checked:** iroh, iroh-base, iroh-relay, iroh-dns, noq, noq-proto,
  netwatch are all `MIT OR Apache-2.0` (the full-tree licence check is Task 9's job).

## How relay and discovery are disabled (exact builder calls)

```rust
Endpoint::builder(presets::Minimal)              // empty builder + ring provider; no relay, no address lookup
    .secret_key(SecretKey::from_bytes(&seed))
    .alpns(vec![b"zarpa-spike/0".to_vec()])
    .relay_mode(RelayMode::Disabled)             // explicit (already the Minimal/empty default)
    .clear_address_lookup()                      // explicit (Minimal adds none; N0 would add pkarr + DNS)
    .net_report_config(NetReportConfig::minimal()) // https_probes = false, captive_portal_check = false
    .clear_ip_transports()                       // drop default 0.0.0.0 / [::] sockets
    .bind_addr("127.0.0.1:0")?                   // loopback only
    .bind().await?
```

Do **not** use `presets::N0` (adds n0 relays + `PkarrPublisher`/`PkarrResolver`/`DnsAddressLookup`
against `iroh.link`) or `presets::N0DisableRelay` (no relay, but still publishes/resolves via n0
DNS). The two `relay_mode`/`clear_address_lookup` calls are redundant with `Minimal` but make the
intent survive a preset change. Portmapping is absent because the `portmapper` feature is off
(otherwise use `.portmapper_config(PortmapperConfig::Disabled)`).

## API facts (non-obvious)

- iroh 1.x is built on **noq** (n0's QUIC stack), not quinn. The API shape is quinn-like
  (`open_bi`/`accept_bi`, `Connection::close(VarInt, &[u8])`), re-exported under `iroh::endpoint`.
  `SendStream`/`RecvStream` implement tokio `AsyncWrite`/`AsyncRead` directly.
- **Presets are mandatory input**: `Endpoint::builder(preset)`. `presets::Empty` has no crypto
  provider and `bind()` fails with `InvalidCryptoProvider`; `presets::Minimal` (needs `tls-ring` or
  `tls-aws-lc-rs`) sets only the provider. `Builder::empty()` already means relay disabled and no
  address lookup.
- `SecretKey::from_bytes(&[u8; 32])` = `ed25519_dalek::SigningKey::from_bytes(seed)`, so
  `endpoint.id()` (an `EndpointId` = `PublicKey`) equals `bench_core::public_key(seed)`; a unit test
  checks this. `PublicKey::as_bytes() -> &[u8; 32]`, `PublicKey::from_bytes(&[u8;32]) -> Result`.
- **Addresses**: `endpoint.addr()` returns an `EndpointAddr` from a watcher (relay URLs + IP addrs);
  `endpoint.bound_sockets()` returns the actually bound sockets. `addr()` in the adapter reports the
  union of `addr().ip_addrs()` and `bound_sockets()` (all `127.0.0.1:<port>`).
- **Dialing**: `EndpointAddr::from_parts(id, addrs.map(TransportAddr::Ip))`, then
  `endpoint.connect(addr, ALPN)`. iroh puts the expected `EndpointId` into the TLS server name and
  verifies the server's raw public key against it in the handshake, so dialing the wrong key at a
  correct address fails inside iroh (adapter test `connect_to_wrong_key_fails`, fails in < 0.5 s).
- **Accepting**: `endpoint.accept().await -> Option<Incoming>`; `incoming.await -> Result<Connection>`.
  iroh accepts **any** authenticated key (it has no trust list), so the adapter checks
  `conn.remote_id()` against `trusted` and closes with code 1 / `b"untrusted"` otherwise, then loops.
  (iroh also offers `EndpointHooks` for rejecting during the handshake, see `examples/auth-hook.rs`;
  not needed for the contract.)
- `Connection::remote_id()` is the key proven in the handshake (from the peer's raw-public-key
  certificate), not a self-reported value. It is the source of `remote_key`.
- `connect` re-checks `remote_id() == to.key` and trust after the handshake (defence in depth) and
  returns `UntrustedPeer` before dialing if `to.key` is not trusted.

## Results

`cargo test -p adapter-iroh`: all five conformance tests pass on the first implementation attempt
(no fix attempts needed), plus three adapter-local tests:

- `endpoint_id_is_seed_derived_key_and_loopback_only` — key equals `public_key(seed)`, name is
  `iroh`, all direct addresses are loopback.
- `accept_keeps_waiting_after_untrusted_client` — `accept` survives an authenticated-but-untrusted
  peer and then returns the next trusted one.
- `connect_to_wrong_key_fails` — dialing an address with the wrong expected key fails.

Note: `rejects_untrusted_peer` takes ~3 s because the conformance test waits out its `SHORT`
timeout on `accept` (which correctly never returns). In `rejects_unknown_server` the client trusts
nobody, so `connect` returns `UntrustedPeer` before dialing (same as adapter-quinn).
