# atl-core

Pure cryptographic library for ATL Protocol v1 (Anchored Transparency Log).

## What it does

- Offline verification of ATL receipts (`.atl` files)
- Merkle tree operations (RFC 6962)
- JSON Canonicalization (RFC 8785)
- Checkpoint parsing and signature verification (Ed25519)

## What it doesn't do

- No storage (see atl-server)
- No HTTP/networking
- No receipt generation

## Usage

```rust
use atl_core::prelude::*;

// Load receipt from .atl file
let receipt_json = std::fs::read_to_string("document.pdf.atl")?;
let receipt = Receipt::from_json(&receipt_json)?;

// Verify with trusted public key
let result = verify_receipt(&receipt, &trusted_public_key)?;
assert!(result.is_valid);
```

## Installation

```toml
[dependencies]
atl-core = "0.1"
```

## License

Apache-2.0
