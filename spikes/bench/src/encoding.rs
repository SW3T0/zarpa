// SPDX-License-Identifier: Apache-2.0
//! Compares candidate encodings on realistic control messages.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::time::Instant;

/// 256 blocks of 4 MiB = a 1 GiB file. Hashes are one concatenated byte string.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct WireManifest {
    pub size: u64,
    pub block_size: u32,
    pub hashes: ByteBuf,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum Control {
    Want { indices: Vec<u32> },
    Ack,
    Error { code: String, message: String },
}

fn manifest() -> WireManifest {
    WireManifest { size: 1 << 30, block_size: 4 << 20, hashes: ByteBuf::from(vec![0xAB; 32 * 256]) }
}

fn control() -> Control {
    Control::Want { indices: (0..64).collect() }
}

fn measure<T, E, D>(name: &str, label: &str, value: &T, enc: E, dec: D)
where
    T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
    E: Fn(&T) -> Vec<u8>,
    D: Fn(&[u8]) -> T,
{
    const N: u32 = 5_000;
    let bytes = enc(value);
    assert_eq!(&dec(&bytes), value, "{name} roundtrip failed");
    let t = Instant::now();
    for _ in 0..N {
        std::hint::black_box(enc(value));
    }
    let enc_us = t.elapsed().as_secs_f64() * 1e6 / N as f64;
    let t = Instant::now();
    for _ in 0..N {
        std::hint::black_box(dec(&bytes));
    }
    let dec_us = t.elapsed().as_secs_f64() * 1e6 / N as f64;
    println!("| {label} | {name} | {} | {enc_us:.2} | {dec_us:.2} |", bytes.len());
}

fn run_for<T>(label: &str, value: T)
where
    T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    measure(
        "CBOR (ciborium)",
        label,
        &value,
        |v| {
            let mut out = Vec::new();
            ciborium::into_writer(v, &mut out).unwrap();
            out
        },
        |b| ciborium::from_reader(b).unwrap(),
    );
    measure(
        "postcard",
        label,
        &value,
        |v| postcard::to_allocvec(v).unwrap(),
        |b| postcard::from_bytes(b).unwrap(),
    );
    measure(
        "MessagePack (rmp-serde)",
        label,
        &value,
        |v| rmp_serde::to_vec_named(v).unwrap(),
        |b| rmp_serde::from_slice(b).unwrap(),
    );
}

pub fn run() {
    println!("| message | encoding | bytes | encode µs | decode µs |");
    println!("|---|---|---|---|---|");
    run_for("manifest (256 blocks)", manifest());
    run_for("want list (64 indices)", control());
}
