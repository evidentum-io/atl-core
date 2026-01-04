# Test Data

This directory contains test vectors and sample data for atl-core testing.

## Structure

```
test_data/
├── vectors/           # RFC test vectors
│   ├── jcs/          # RFC 8785 JSON Canonicalization Scheme
│   │   └── cases.json
│   └── merkle/       # RFC 6962 Merkle tree operations
│       └── trees.json
└── receipts/         # Sample receipt files (*.atl)
    ├── valid/        # Valid receipts that should pass verification
    │   ├── minimal.atl
    │   ├── with_metadata.atl
    │   └── with_anchors.atl
    └── invalid/      # Invalid receipts for negative testing
        ├── unsupported_version.atl
        ├── invalid_hash_format.atl
        └── malformed_json.atl
```

## Test Vectors

### JCS (JSON Canonicalization Scheme)

`vectors/jcs/cases.json` contains test cases for RFC 8785 compliance:
- Key ordering (UTF-16 code point order)
- Number formatting (no trailing zeros)
- String escaping (control characters only)
- Unicode handling (no escaping)
- Whitespace removal

### Merkle Trees

`vectors/merkle/trees.json` contains test cases for RFC 6962 Merkle tree operations:
- Trees of various sizes (1, 2, 3, 4, 7, 8 leaves)
- Inclusion proof generation
- Root computation
- Proof verification

## Receipt Samples

### Valid Receipts

- `minimal.atl`: Minimal valid receipt (single leaf, no metadata)
- `with_metadata.atl`: Receipt with rich metadata
- `with_anchors.atl`: Receipt with external timestamp anchors (RFC 3161, Bitcoin OTS)

### Invalid Receipts

- `unsupported_version.atl`: Receipt with unsupported spec_version
- `invalid_hash_format.atl`: Receipt with malformed hash string
- `malformed_json.atl`: Receipt with invalid JSON syntax

## Usage

These test vectors are used in:
- Unit tests (in `src/core/*.rs`)
- Integration tests (`tests/integration.rs`)
- Property-based tests (`tests/proptests.rs`)

## Maintenance

When updating the ATL Protocol specification:
1. Update test vectors to match new spec
2. Add new test cases for edge cases
3. Keep invalid samples to ensure error handling
4. Document any breaking changes
