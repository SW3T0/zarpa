# Zarpa Protocol — Draft v0

Status: **draft**, not stable. Wire compatibility is not guaranteed before 1.0.
The key words MUST, SHOULD and MAY are used as in RFC 2119.

Message encoding is defined by ADR-0004 (status: proposed); this draft specifies messages
semantically (fields and meaning), not byte layouts.

## 1. Transport

- Peers communicate over QUIC with TLS 1.3, provided by iroh 1.x (ADR-0005). The ALPN identifier is `zarpa/0`.
- Each peer authenticates with its Ed25519 identity key (the iroh endpoint ID). A peer MUST check the key
  authenticated in the handshake against its trust list and MUST close connections from keys it does not trust.
  Peers MUST NOT rely on certificate authorities.
- A third-party implementation needs a QUIC stack compatible with iroh's handshake conventions (ADR-0005).
- A connection carries one control stream plus one data stream per active block lane.

## 2. Identity

- A device identity is an Ed25519 key pair. The **device ID** is the public key.
- The display name is a human label, MUST NOT be used for authentication and MAY be changed at any time.

## 3. Discovery

- Devices advertise over mDNS (`_zarpa._udp.local`) with an identifier derived from the public key.
- The advertisement MUST NOT contain the display name of a device unless the viewer is a trusted peer.

## 4. Pairing

1. Initiator displays a QR or short code containing its public key and a one-time secret.
2. Responder connects, proves knowledge of the secret and sends its public key.
3. Both derive a 4-6 digit verification code from the handshake transcript and show it; users confirm
   the codes match.
4. On confirmation each side stores the other's public key as **trusted**.

## 5. Transfer

A transfer is described by a **manifest**:

```json
{
  "transfer_id": "b6c1f0e2-0d6a-4f0e-9c0b-3f0f6a1d2e11",
  "block_size": 4194304,
  "entries": [
    {
      "path": "videos/holiday.mp4",
      "size": 8388608,
      "blocks": [
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6"
      ]
    }
  ]
}
```

The example file is exactly two 4 MiB blocks; a manifest lists one BLAKE3 hash per block.

- The sender offers the manifest; the receiver accepts, rejects or (for trusted peers) auto-accepts.
- Blocks are sent in parallel across data streams. The receiver MUST verify each block's BLAKE3 hash before
  writing it and MUST reject mismatching blocks.
- Resume: the receiver reports the set of verified blocks; the sender sends only the missing ones.
- The receiver MUST write to a temporary file and move it to the final path only after all blocks verify.
- Paths in the manifest MUST be relative, MUST NOT contain `..` or absolute components, and are sanitized
  by the receiver; writes MUST stay inside the receiver's chosen download folder.

## 6. Errors

Errors carry a stable code, e.g. `DEVICE_UNREACHABLE`, `TRANSFER_REJECTED`, `BLOCK_HASH_MISMATCH`,
`PATH_NOT_ALLOWED`, `UNSUPPORTED_VERSION`.

## 7. Versioning

The protocol version is carried in the ALPN identifier. Incompatible changes bump the major number
(`zarpa/1`); peers that do not share a version MUST fail with `UNSUPPORTED_VERSION`.
