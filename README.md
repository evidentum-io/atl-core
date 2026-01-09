# atl-core

Pure cryptographic library for **ATL Protocol v1** (Anchored Transparency Log).

`atl-core` provides the foundational primitives for maintaining and verifying immutable, privacy-preserving logs of facts and evidence.

## Key Features

- **Merkle Tree Operations (RFC 6962):** Full support for inclusion and consistency proofs.
- **Bitcoin Anchoring (OpenTimestamps):** Complete implementation of OTS binary format parsing, creation, and verification.
- **TSA Anchoring (RFC 3161):** Integrated verification of legally-recognized timestamp tokens.
- **JSON Canonicalization (RFC 8785):** Deterministic hashing of structured metadata via JCS.
- **Secure Checkpoints:** Binary-stable state signatures using Ed25519 (RFC 8032).
- **Detached Evidence Receipts:** Self-contained `.atl` files for offline-first verification.

## Architecture

`atl-core` is a **stateless, I/O-free library**. It handles the mathematics of trust, while `atl-server` handles storage and network operations.

## Usage

### Verify a Receipt with Anchors

```rust
use atl_core::prelude::*;

// 1. Load receipt from .atl file
let receipt_json = std::fs::read_to_string("contract.pdf.atl")?;
let receipt = Receipt::from_json(&receipt_json)?;

// 2. Setup verifier with trusted log operator public key
let trusted_key: [u8; 32] = [/* ... */];
let verifier = ReceiptVerifier::new(CheckpointVerifier::new_from_bytes(&trusted_key)?);

// 3. Perform full verification (Merkle + Signature + Anchors)
let result = verifier.verify(&receipt);

if result.is_valid {
    println!("Fact is authentic and anchored in Bitcoin!");
} else {
    println!("Verification failed: {:?}", result.errors);
}
```

## Installation

```toml
[dependencies]
atl-core = { version = "0.5", features = ["bitcoin-ots", "rfc3161-verify"] }
```

## License

Apache-2.0
