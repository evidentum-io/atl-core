# atl-core

Pure cryptographic library for **ATL Protocol v2.0** (Anchored Transparency Log).

`atl-core` provides the foundational primitives for maintaining and verifying immutable, privacy-preserving logs of facts and evidence.

## Key Features

- **Merkle Tree Operations (RFC 6962):** Full support for inclusion and consistency proofs.
- **Bitcoin Anchoring (OpenTimestamps):** Complete implementation of OTS binary format parsing, creation, and verification.
- **TSA Anchoring (RFC 3161):** Integrated verification of legally-recognized timestamp tokens.
- **JSON Canonicalization (RFC 8785):** Deterministic hashing of structured metadata via JCS.
- **Checkpoint Integrity:** Binary-stable state signatures using Ed25519 (RFC 8032).
- **Detached Evidence Receipts:** Self-contained `.atl` files for offline-first verification.
- **Anchor-Based Trust:** No need to trust the Log Operator - trust comes from external anchors.

## Architecture

`atl-core` is a **stateless, I/O-free library**. It handles the mathematics of trust, while `atl-server` handles storage and network operations.

## Verification

ATL Protocol v2.0 uses **anchor-based trust**. You don't need a public key
to verify receipts - trust comes from external timestamping services.

### Basic Verification

```rust
use atl_core::prelude::*;

let json = std::fs::read_to_string("document.pdf.atl")?;
let receipt = Receipt::from_json(&json)?;

// Verify using external anchors (no key needed)
let verifier = ReceiptVerifier::anchor_only();
let result = verifier.verify(&receipt);

if result.is_valid {
    println!("Receipt verified!");
}
```

### Trust Model

| Source | Type | Purpose |
|--------|------|---------|
| RFC 3161 TSA | External | Trusted timestamp proof |
| Bitcoin OTS | External | Immutable blockchain proof |
| Ed25519 Signature | Internal | Integrity check (optional) |

See the [ATL Protocol specification](https://atl-protocol.org) for details.

## Installation

```toml
[dependencies]
atl-core = { version = "0.5", features = ["bitcoin-ots", "rfc3161-verify"] }
```

## License

Apache-2.0
