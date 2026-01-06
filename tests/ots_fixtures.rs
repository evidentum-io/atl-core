//! OTS Test Fixtures Validation
//!
//! Verifies that test fixtures in `test_data/ots/` are valid OTS files
//! with correct magic bytes and basic structure.

use std::fs;
use std::path::Path;

/// OTS magic bytes (31 bytes)
const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";

/// Test that all OTS fixtures exist
#[test]
fn test_fixtures_exist() {
    let fixtures = ["small-test.ots", "large-test.ots"];

    for fixture in fixtures {
        let path = format!("test_data/ots/{fixture}");
        assert!(Path::new(&path).exists(), "Fixture {fixture} is missing");
    }
}

/// Test that all OTS fixtures have valid magic bytes
#[test]
fn test_fixtures_have_magic() {
    let entries = fs::read_dir("test_data/ots").expect("test_data/ots directory not found");

    for entry in entries {
        let entry = entry.expect("Failed to read directory entry");
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("ots") {
            let data = fs::read(&path).unwrap_or_else(|e| panic!("Failed to read {path:?}: {e}"));

            assert!(
                data.starts_with(MAGIC),
                "{:?} has invalid magic bytes. Expected: {:02x?}, Got: {:02x?}",
                path,
                MAGIC,
                &data[..MAGIC.len().min(data.len())]
            );
        }
    }
}

/// Test small-test.ots properties
#[test]
fn test_small_fixture() {
    let data = fs::read("test_data/ots/small-test.ots").expect("Failed to read small-test.ots");

    // Check size
    assert_eq!(data.len(), 265, "small-test.ots has unexpected size");

    // Check magic
    assert!(data.starts_with(MAGIC), "Invalid magic bytes");

    // Check version byte (should be 0x01 after magic)
    assert_eq!(data[31], 0x01, "Invalid version");

    // Check digest type (should be 0x08 for SHA256)
    assert_eq!(data[32], 0x08, "Expected SHA256 digest type");
}

/// Test large-test.ots properties
#[test]
fn test_large_fixture() {
    let data = fs::read("test_data/ots/large-test.ots").expect("Failed to read large-test.ots");

    // Check size
    assert_eq!(data.len(), 1768, "large-test.ots has unexpected size");

    // Check magic
    assert!(data.starts_with(MAGIC), "Invalid magic bytes");

    // Check version byte
    assert_eq!(data[31], 0x01, "Invalid version");

    // Check digest type
    assert_eq!(data[32], 0x08, "Expected SHA256 digest type");
}

/// Test that fixtures are under size limit
#[test]
fn test_fixtures_size_limits() {
    const MAX_FIXTURE_SIZE: u64 = 100 * 1024; // 100KB as per spec

    let entries = fs::read_dir("test_data/ots").expect("test_data/ots directory not found");

    for entry in entries {
        let entry = entry.expect("Failed to read directory entry");
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("ots") {
            let metadata = fs::metadata(&path)
                .unwrap_or_else(|e| panic!("Failed to read metadata for {path:?}: {e}"));

            assert!(
                metadata.len() <= MAX_FIXTURE_SIZE,
                "{:?} exceeds max size: {} bytes > {} bytes",
                path,
                metadata.len(),
                MAX_FIXTURE_SIZE
            );
        }
    }
}

/// Test total fixtures size is reasonable
#[test]
fn test_total_fixtures_size() {
    const MAX_TOTAL_SIZE: u64 = 500 * 1024; // 500KB as per spec

    let entries = fs::read_dir("test_data/ots").expect("test_data/ots directory not found");
    let mut total_size = 0u64;

    for entry in entries {
        let entry = entry.expect("Failed to read directory entry");
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("ots") {
            let metadata = fs::metadata(&path)
                .unwrap_or_else(|e| panic!("Failed to read metadata for {path:?}: {e}"));
            total_size += metadata.len();
        }
    }

    assert!(
        total_size <= MAX_TOTAL_SIZE,
        "Total fixtures size exceeds limit: {total_size} bytes > {MAX_TOTAL_SIZE} bytes"
    );
}
