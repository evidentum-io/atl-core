//! Bitcoin OTS anchor verification
//!
//! This module provides verification for Bitcoin `OpenTimestamps` anchors.
//! It validates that OTS proofs match the expected checkpoint root hash
//! and contain Bitcoin attestations.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::core::ots::{BitcoinAttestation, OtsError, extract_bitcoin_attestations};
use crate::error::AtlError;

/// Result of OTS anchor verification
///
/// Contains all Bitcoin attestations found in the proof.
/// Each attestation represents a Bitcoin block where the document hash
/// was anchored through the `OpenTimestamps` protocol.
#[derive(Debug, Clone)]
pub struct OtsVerifyResult {
    /// All Bitcoin attestations found in the proof
    pub attestations: Vec<BitcoinAttestation>,
}

/// Verify an OTS anchor against expected root hash
///
/// Performs cryptographic verification of an `OpenTimestamps` proof:
/// 1. Decodes base64-encoded .ots file content
/// 2. Validates that the proof's start digest matches the expected root hash
/// 3. Extracts all Bitcoin attestations from the proof
///
/// # Arguments
///
/// * `ots_base64` - Base64-encoded .ots file content (with or without "base64:" prefix)
/// * `expected_root` - SHA256 hash of checkpoint root (32 bytes)
///
/// # Returns
///
/// * `Ok(OtsVerifyResult)` - Proof structure is valid, contains Bitcoin attestations
/// * `Err(AtlError)` - Proof invalid, wrong hash, or pending-only
///
/// # Errors
///
/// * `AtlError::Base64Decode` - Invalid base64 encoding
/// * `AtlError::OtsHashMismatch` - Proof is for a different document
/// * `AtlError::ReceiptVerificationFailed` - Proof contains only pending attestations
///
/// # Examples
///
/// ```rust,ignore
/// use atl_core::core::verify::anchors::bitcoin_ots::verify_ots_anchor_impl;
///
/// let ots_base64 = "base64:AE9wZW5UaW1lc3RhbXBzAABQcm9vZ...";
/// let expected_root = [0xaa; 32]; // SHA256 of checkpoint root
///
/// match verify_ots_anchor_impl(ots_base64, &expected_root) {
///     Ok(result) => {
///         println!("Found {} Bitcoin attestations", result.attestations.len());
///         for att in result.attestations {
///             println!("Block: {}", att.block_height);
///         }
///     }
///     Err(e) => eprintln!("Verification failed: {}", e),
/// }
/// ```
pub fn verify_ots_anchor_impl(
    ots_base64: &str,
    expected_root: &[u8; 32],
) -> Result<OtsVerifyResult, AtlError> {
    // Strip "base64:" prefix if present
    let ots_base64_stripped = ots_base64.strip_prefix("base64:").unwrap_or(ots_base64);

    // Decode base64
    let ots_bytes =
        STANDARD.decode(ots_base64_stripped).map_err(|e| AtlError::Base64Decode(e.to_string()))?;

    // Extract attestations
    let attestations =
        extract_bitcoin_attestations(&ots_bytes, expected_root).map_err(|e| match e {
            OtsError::StartDigestMismatch { expected, actual } => {
                AtlError::OtsHashMismatch { proof_hash: actual, expected_hash: expected }
            }
            OtsError::PendingOnly { uris } => AtlError::ReceiptVerificationFailed(format!(
                "OTS proof pending, upgrade URIs: {}",
                uris.join(", ")
            )),
            other => AtlError::ReceiptVerificationFailed(other.to_string()),
        })?;

    Ok(OtsVerifyResult { attestations })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    fn load_fixture(name: &str) -> Vec<u8> {
        let path = format!("test_data/ots/{}", name);
        std::fs::read(&path).unwrap_or_else(|_| panic!("Failed to load fixture: {}", path))
    }

    #[test]
    fn test_verify_ots_anchor_with_bitcoin() {
        let ots_bytes = load_fixture("large-test.ots");
        let ots_base64 = STANDARD.encode(&ots_bytes);

        // Get expected hash from the fixture by parsing it
        use crate::core::ots::DetachedTimestampFile;
        let file = DetachedTimestampFile::from_bytes(&ots_bytes).unwrap();
        let start_digest: [u8; 32] = file
            .timestamp
            .start_digest
            .clone()
            .try_into()
            .expect("start digest should be 32 bytes");

        let result = verify_ots_anchor_impl(&ots_base64, &start_digest);

        // large-test.ots should have Bitcoin attestations
        match result {
            Ok(verify_result) => {
                assert!(
                    !verify_result.attestations.is_empty(),
                    "Expected at least one Bitcoin attestation in large-test.ots"
                );
                println!("Found {} Bitcoin attestations", verify_result.attestations.len());
                for att in &verify_result.attestations {
                    println!("  Block: {}, Path length: {}", att.block_height, att.path_len());
                }
            }
            Err(AtlError::ReceiptVerificationFailed(msg)) if msg.contains("pending") => {
                println!("large-test.ots is still pending: {}", msg);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_verify_ots_anchor_wrong_hash() {
        let ots_bytes = load_fixture("large-test.ots");
        let ots_base64 = STANDARD.encode(&ots_bytes);
        let wrong_hash = [0u8; 32];

        let result = verify_ots_anchor_impl(&ots_base64, &wrong_hash);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, AtlError::OtsHashMismatch { .. }));

        if let AtlError::OtsHashMismatch { proof_hash, expected_hash } = err {
            assert_eq!(expected_hash, hex::encode(wrong_hash));
            assert_ne!(proof_hash, expected_hash);
        }
    }

    #[test]
    fn test_verify_ots_anchor_invalid_base64() {
        let bad_base64 = "not valid base64!!!";
        let hash = [0u8; 32];

        let result = verify_ots_anchor_impl(bad_base64, &hash);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::Base64Decode(_)));
    }

    #[test]
    fn test_verify_ots_anchor_pending_only() {
        let ots_bytes = load_fixture("small-test.ots");
        let ots_base64 = STANDARD.encode(&ots_bytes);

        // Get correct hash from fixture
        use crate::core::ots::DetachedTimestampFile;
        let file = DetachedTimestampFile::from_bytes(&ots_bytes).unwrap();
        let start_digest: [u8; 32] = file
            .timestamp
            .start_digest
            .clone()
            .try_into()
            .expect("start digest should be 32 bytes");

        let result = verify_ots_anchor_impl(&ots_base64, &start_digest);

        // small-test.ots may have pending attestations only
        match result {
            Ok(verify_result) => {
                // If it succeeded, it has Bitcoin attestations
                assert!(!verify_result.attestations.is_empty());
                println!(
                    "small-test.ots has {} Bitcoin attestations",
                    verify_result.attestations.len()
                );
            }
            Err(AtlError::ReceiptVerificationFailed(msg)) if msg.contains("pending") => {
                // Expected: pending only
                assert!(msg.contains("upgrade URIs"));
                println!("small-test.ots is pending: {}", msg);
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_verify_ots_anchor_with_base64_prefix() {
        let ots_bytes = load_fixture("large-test.ots");
        let ots_base64 = format!("base64:{}", STANDARD.encode(&ots_bytes));

        use crate::core::ots::DetachedTimestampFile;
        let file = DetachedTimestampFile::from_bytes(&ots_bytes).unwrap();
        let start_digest: [u8; 32] = file
            .timestamp
            .start_digest
            .clone()
            .try_into()
            .expect("start digest should be 32 bytes");

        let result = verify_ots_anchor_impl(&ots_base64, &start_digest);

        // Should work with "base64:" prefix
        assert!(
            result.is_ok()
                || matches!(
                    result.unwrap_err(),
                    AtlError::ReceiptVerificationFailed(ref msg) if msg.contains("pending")
                )
        );
    }

    #[test]
    fn test_ots_verify_result_structure() {
        // Test the OtsVerifyResult structure
        use crate::core::ots::BitcoinAttestation;

        let att = BitcoinAttestation {
            block_height: 123456,
            merkle_path: vec![[0xaa; 32], [0xbb; 32]],
            timestamp: None,
        };

        let result = OtsVerifyResult { attestations: vec![att.clone()] };

        assert_eq!(result.attestations.len(), 1);
        assert_eq!(result.attestations[0].block_height, 123456);
        assert_eq!(result.attestations[0].path_len(), 2);
    }

    #[test]
    fn test_verify_ots_anchor_empty_input() {
        let empty_base64 = "";
        let hash = [0u8; 32];

        let result = verify_ots_anchor_impl(empty_base64, &hash);
        assert!(result.is_err());
        // Should fail on decode or parsing
    }

    #[test]
    fn test_verify_ots_anchor_malformed_ots() {
        // Create some garbage data that decodes but isn't valid OTS
        let garbage = vec![0u8; 100];
        let garbage_base64 = STANDARD.encode(&garbage);
        let hash = [0u8; 32];

        let result = verify_ots_anchor_impl(&garbage_base64, &hash);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::ReceiptVerificationFailed(_)));
    }
}
