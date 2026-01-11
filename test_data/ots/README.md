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

## Calendar Response Fixtures

These fixtures contain raw calendar server responses (without OTS magic header).
Used to test `DetachedTimestampFile::from_calendar_response()`.

### Files

- `calendar-response-1.bin` - Raw response from OpenTimestamps calendar
- `calendar-response-1.hash` - SHA256 hash that was submitted (hex-encoded)

### Regenerating Fixtures

```bash
# Create test hash
echo -n "your test data" | shasum -a 256 | cut -d' ' -f1 > hash.hex
xxd -r -p hash.hex > hash.bin

# Submit to calendar
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary @hash.bin \
  https://a.pool.opentimestamps.org/digest \
  -o calendar-response-1.bin

# Save hash
mv hash.hex calendar-response-1.hash
```

### Expected Format

Calendar responses start with operations (NOT magic header):
- `f0 xx` - Prepend operation
- `f1 xx` - Append operation
- `08` - SHA256 operation
- `00` + `83 df e3...` - Pending attestation

Full `.ots` files start with magic: `00 4f 70 65 6e 54 69 6d 65 73 74 61 6d 70 73...`

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
