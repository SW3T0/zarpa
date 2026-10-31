// SPDX-License-Identifier: Apache-2.0
//! Local-network discovery smoke test for the iroh stack (Task 9b): no relay, no internet.
//!
//! iroh 1.x no longer ships mDNS inside the `iroh` crate (there is no cargo feature for it); n0's
//! local-network lookup lives in the separate `iroh-mdns-address-lookup` crate (built on
//! `swarm-discovery`). This example binds an iroh endpoint with `test_secret(n)`, relay disabled,
//! no other address lookup and net-report probes off, but on the default unspecified sockets
//! (`0.0.0.0` / `[::]`) so LAN addresses exist to advertise (unlike `IrohTransport`, which binds
//! 127.0.0.1 only). It registers `MdnsAddressLookup` (service `irohv1`), subscribes to its events
//! for 8 seconds, prints `FOUND <hex public key>` once per distinct other endpoint, then `DONE`.
//!
//! Run two instances at the same time (from `spikes/`, PowerShell):
//!
//! ```text
//! cargo run -p adapter-iroh --example discover -- 1
//! cargo run -p adapter-iroh --example discover -- 2
//! ```

use adapter_iroh::ALPN;
use bench_core::transport::test_secret;
use iroh::endpoint::presets;
use iroh::{Endpoint, NetReportConfig, RelayMode, SecretKey};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use n0_future::StreamExt;
use std::collections::HashSet;
use std::time::Duration;

const LISTEN_FOR: Duration = Duration::from_secs(8);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let n: u8 = std::env::args()
        .nth(1)
        .ok_or("usage: discover <n>")?
        .parse()?;
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&test_secret(n)))
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .net_report_config(NetReportConfig::minimal())
        .bind()
        .await?;
    let me = endpoint.id();
    println!(
        "SELF {} sockets {:?}",
        hex(me.as_bytes()),
        endpoint.bound_sockets()
    );

    let mdns = MdnsAddressLookup::builder().build(me)?;
    endpoint.address_lookup()?.add(mdns.clone());
    let mut events = mdns.subscribe().await;

    let mut found = HashSet::new();
    let _ = tokio::time::timeout(LISTEN_FOR, async {
        while let Some(event) = events.next().await {
            if let DiscoveryEvent::Discovered { endpoint_info, .. } = event {
                let id = endpoint_info.endpoint_id;
                if id != me && found.insert(id) {
                    let addrs: Vec<_> = endpoint_info.ip_addrs().collect();
                    println!("FOUND {}", hex(id.as_bytes()));
                    println!("  via {addrs:?}");
                }
            }
        }
    })
    .await;
    println!("DONE");
    endpoint.close().await;
    Ok(())
}
