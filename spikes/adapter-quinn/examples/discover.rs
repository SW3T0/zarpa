// SPDX-License-Identifier: Apache-2.0
//! Local-network discovery smoke test for the quinn stack (Task 9b): no relay, no internet.
//!
//! quinn has no discovery of its own, so this uses the `mdns-sd` crate (plain mDNS / DNS-SD):
//! it binds a `QuinnTransport` with `test_secret(n)`, registers a `_zarpa-spike._udp.local.`
//! service whose TXT record carries the full hex public key and whose port is the transport's
//! port, browses the same service type for 8 seconds, prints `FOUND <hex public key>` once per
//! distinct other peer, then `DONE`.
//!
//! Note: `QuinnTransport::bind` listens on 127.0.0.1 only, so the advertised LAN addresses are not
//! dialable by this adapter as-is; this example only measures whether discovery finds the key.
//!
//! Run two instances at the same time (from `spikes/`, PowerShell):
//!
//! ```text
//! cargo run -p adapter-quinn --example discover -- 1
//! cargo run -p adapter-quinn --example discover -- 2
//! ```

use adapter_quinn::QuinnTransport;
use bench_core::transport::{public_key, test_secret, Transport};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashSet;
use std::time::{Duration, Instant};

const SERVICE_TYPE: &str = "_zarpa-spike._udp.local.";
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
    let secret = test_secret(n);
    let me = hex(&public_key(&secret).0);

    let transport = QuinnTransport::bind(secret, vec![]).await?;
    let port = transport
        .addr()
        .direct
        .first()
        .ok_or("no bound address")?
        .port();
    println!("SELF {me} port {port}");

    let mdns = ServiceDaemon::new()?;
    // A DNS label is at most 63 bytes, so the instance name is a prefix; the TXT record has the key.
    let instance = format!("zarpa-{}", &me[..16]);
    let host = format!("{instance}.local.");
    let props = [("key", me.as_str())];
    let info =
        ServiceInfo::new(SERVICE_TYPE, &instance, &host, "", port, &props[..])?.enable_addr_auto();
    mdns.register(info)?;
    let events = mdns.browse(SERVICE_TYPE)?;

    let mut found = HashSet::new();
    let deadline = Instant::now() + LISTEN_FOR;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match events.recv_timeout(left) {
            Ok(ServiceEvent::ServiceResolved(svc)) => {
                let Some(key) = svc.get_property_val_str("key") else {
                    continue;
                };
                if key != me && found.insert(key.to_string()) {
                    let addrs: Vec<String> =
                        svc.get_addresses().iter().map(|a| a.to_string()).collect();
                    println!("FOUND {key}");
                    println!("  via port {} addrs {:?}", svc.get_port(), addrs);
                }
            }
            Ok(_) => {}
            Err(_) => break, // timeout (deadline reached) or daemon gone
        }
    }
    println!("DONE");
    let _ = mdns.shutdown();
    drop(transport);
    Ok(())
}
