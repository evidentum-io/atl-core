# OTS Test Fixtures

Binary `.ots` files for testing OpenTimestamps parsing and verification.

## Files

### small-test.ots
- **Size**: 265 bytes
- **Source**: rust-opentimestamps-client reference implementation
- **Description**: Small OTS proof with pending calendar attestations
- **Purpose**: Test basic deserialization and fork handling
- **Calendar URLs**:
  - `https://bob.btc.calendar.opentimestamps.org`
  - `https://alice.btc.calendar.opentimestamps.org`

### large-test.ots
- **Size**: 1768 bytes
- **Source**: rust-opentimestamps-client reference implementation
- **Description**: Large OTS proof with complete Bitcoin attestations
- **Purpose**: Test complex proof chains with embedded Bitcoin transactions
- **Features**:
  - Multiple calendar forks (bob, alice)
  - Bitcoin attestations with full transaction data
  - Deep operation chains (SHA256, Prepend, Append)
  - Multiple hash operations and forks

## Format Specification

All `.ots` files follow the OpenTimestamps proof format:

```
Magic:     \x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94
Version:   1 (LEB128)
DigestType: 0x08 (SHA256)
Digest:    32 bytes
Timestamp: Variable-length proof chain
```

## Verification

To verify the magic bytes:

```bash
xxd -l 31 small-test.ots
# Expected: 004f 7065 6e54 696d 6573 7461 6d70 7300
#           0050 726f 6f66 00bf 89e2 e884 e892 94
```

## Regenerating

If fixtures need to be regenerated:

```bash
cd test_data/ots
rustc extract_fixtures.rs
./extract_fixtures
```

The extraction script reads the byte constants from the rust-opentimestamps reference
implementation and writes them as binary `.ots` files.

## Usage in Tests

```rust
use std::fs;

#[test]
fn test_load_fixture() {
    let data = fs::read("test_data/ots/small-test.ots").unwrap();
    let ots = DetachedTimestampFile::from_reader(&data[..]).unwrap();
    assert_eq!(ots.digest_type, DigestType::Sha256);
}
```

## License

These are test fixtures (binary data), not copyrightable code.
The OTS format specification is public domain.

## References

- [OpenTimestamps Specification](https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md)
- [rust-opentimestamps-client](https://github.com/apoelstra/rust-opentimestamps)
- [python-opentimestamps](https://github.com/opentimestamps/python-opentimestamps)
