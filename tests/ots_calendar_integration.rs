#![allow(missing_docs)]
#![cfg(feature = "bitcoin-ots")]
//! Integration tests for OTS calendar response parsing

use atl_core::ots::{DetachedTimestampFile, DigestType, MAGIC};

/// Load test fixture files
fn load_fixture(name: &str) -> (Vec<u8>, [u8; 32]) {
    let response_path = format!("test_data/ots/{name}.bin");
    let hash_path = format!("test_data/ots/{name}.hash");

    let response =
        std::fs::read(&response_path).unwrap_or_else(|_| panic!("Failed to read {response_path}"));

    let hash_hex = std::fs::read_to_string(&hash_path)
        .unwrap_or_else(|_| panic!("Failed to read {hash_path}"));
    let hash_bytes = hex::decode(hash_hex.trim()).expect("Failed to decode hash hex");
    let hash: [u8; 32] = hash_bytes.try_into().expect("Hash must be 32 bytes");

    (response, hash)
}

#[test]
fn test_calendar_response_fixture_exists() {
    let response_path = "test_data/ots/calendar-response-1.bin";
    let hash_path = "test_data/ots/calendar-response-1.hash";

    assert!(
        std::path::Path::new(response_path).exists(),
        "Calendar response fixture missing: {response_path}",
    );
    assert!(
        std::path::Path::new(hash_path).exists(),
        "Calendar response hash missing: {hash_path}",
    );
}

#[test]
fn test_calendar_response_fixture_format() {
    let (response, _hash) = load_fixture("calendar-response-1");

    // Calendar response should NOT start with OTS magic header
    // It contains raw operations only
    assert!(
        !response.starts_with(MAGIC),
        "Calendar response should not have magic header - it's raw operations"
    );

    // Should have some content
    let response_len = response.len();
    assert!(response_len > 10, "Calendar response too short: {response_len} bytes");
}

#[test]
fn test_calendar_response_to_ots_file() {
    let (response, hash) = load_fixture("calendar-response-1");

    // Build OTS file from calendar response
    let result = DetachedTimestampFile::from_calendar_response(hash, &response);
    let err = result.as_ref().err();
    assert!(result.is_ok(), "Failed to parse calendar response: {err:?}");

    let file = result.unwrap();

    // Verify structure
    assert_eq!(file.digest_type, DigestType::Sha256);
    assert_eq!(file.timestamp.start_digest, hash.to_vec());
}

#[test]
fn test_calendar_response_serialization() {
    let (response, hash) = load_fixture("calendar-response-1");

    let file = DetachedTimestampFile::from_calendar_response(hash, &response)
        .expect("Failed to parse calendar response");

    // Verify serialization produces valid OTS file
    let ots_bytes = file.to_bytes().expect("Failed to serialize");

    // Should have magic header now
    assert!(ots_bytes.starts_with(MAGIC), "Serialized file missing magic header");

    // Should be larger than just the response (has header + hash)
    let ots_len = ots_bytes.len();
    let response_len = response.len();
    assert!(ots_len > response_len, "Serialized file should be larger than raw response");
}

#[test]
fn test_calendar_response_round_trip() {
    let (response, hash) = load_fixture("calendar-response-1");

    // Build OTS file from calendar response
    let file1 = DetachedTimestampFile::from_calendar_response(hash, &response)
        .expect("Failed to parse calendar response");

    // Serialize to .ots format
    let ots_bytes = file1.to_bytes().expect("Failed to serialize");

    // Parse back from .ots format
    let file2 =
        DetachedTimestampFile::from_bytes(&ots_bytes).expect("Failed to parse serialized OTS");

    // Should be identical
    assert_eq!(file2, file1, "Round-trip produced different result");
}

#[test]
fn test_calendar_response_has_pending_attestation() {
    let (response, hash) = load_fixture("calendar-response-1");

    let file = DetachedTimestampFile::from_calendar_response(hash, &response)
        .expect("Failed to parse calendar response");

    // Fresh calendar responses contain pending attestations
    // The timestamp tree should have at least one step
    // This is a basic sanity check that we parsed something meaningful
    assert!(
        !file.timestamp.first_step.next.is_empty()
            || matches!(file.timestamp.first_step.data, atl_core::ots::StepData::Attestation(_)),
        "Timestamp should have operations or attestation"
    );
}
