//! Internal helper functions for receipt verification
//!
//! This module contains internal verification helper functions
//! that support the main verification logic in `ReceiptVerifier`.

use crate::core::checkpoint::{parse_hash, parse_signature, Checkpoint, CheckpointVerifier};
use crate::core::jcs::canonicalize_and_hash;
use crate::core::merkle::{compute_leaf_hash, verify_inclusion, InclusionProof};
use crate::core::receipt::{format_hash, ReceiptAnchor, ANCHOR_TARGET_DATA_TREE_ROOT, ANCHOR_TARGET_SUPER_ROOT};

use super::{AnchorVerificationResult, VerificationError};

/// Hash type (32 bytes)
pub type Hash = [u8; 32];

/// Context for anchor verification
///
/// Contains the expected hash values for different anchor targets.
/// Both `data_tree_root` and `super_root` are REQUIRED for v2.0 receipts.
#[derive(Debug, Clone)]
pub struct AnchorVerificationContext {
    /// Data Tree root hash (from `proof.root_hash`) - REQUIRED
    pub data_tree_root: Hash,

    /// Super-Tree root hash (from `super_proof.super_root`) - REQUIRED
    pub super_root: Hash,
}

impl AnchorVerificationContext {
    /// Create context for v2.0 receipt (mandatory fields)
    #[must_use]
    pub const fn new(data_tree_root: Hash, super_root: Hash) -> Self {
        Self { data_tree_root, super_root }
    }

    /// Get expected hash for target
    ///
    /// Returns the expected hash based on anchor target:
    /// - `"data_tree_root"` -> `self.data_tree_root`
    /// - `"super_root"` -> `self.super_root`
    #[must_use]
    #[allow(dead_code)] // Used in tests, may be used by future callers
    pub fn expected_hash_for_target(&self, target: &str) -> Option<&Hash> {
        match target {
            ANCHOR_TARGET_DATA_TREE_ROOT => Some(&self.data_tree_root),
            ANCHOR_TARGET_SUPER_ROOT => Some(&self.super_root),
            _ => None,
        }
    }
}

// ========== Internal Helper Functions ==========

/// Reconstruct leaf hash from payload hash, `metadata_hash`, and metadata
///
/// STEP 1 of verification algorithm:
/// 1. Decode `payload_hash` from "sha256:..."
/// 2. Compute `computed_metadata_hash` = SHA256(JCS(metadata))
/// 3. Decode and validate `metadata_hash` from receipt
/// 4. Compute `leaf_hash` = SHA256(0x00 || `payload_hash` || `metadata_hash`)
pub fn reconstruct_leaf_hash(
    payload_hash_str: &str,
    metadata_hash_str: &str,
    metadata: &serde_json::Value,
) -> Result<[u8; 32], VerificationError> {
    // Decode payload hash
    let payload_hash =
        parse_hash(payload_hash_str).map_err(|e| VerificationError::InvalidHash {
            field: "entry.payload_hash".to_string(),
            message: e.to_string(),
        })?;

    // Decode metadata hash from receipt
    let metadata_hash_from_receipt =
        parse_hash(metadata_hash_str).map_err(|e| VerificationError::InvalidHash {
            field: "entry.metadata_hash".to_string(),
            message: e.to_string(),
        })?;

    // Compute metadata hash via JCS
    let computed_metadata_hash = canonicalize_and_hash(metadata);

    // Validate metadata hash matches
    if metadata_hash_from_receipt != computed_metadata_hash {
        return Err(VerificationError::MetadataHashMismatch {
            expected: metadata_hash_str.to_string(),
            actual: format_hash(&computed_metadata_hash),
        });
    }

    // Compute leaf hash: SHA256(0x00 || payload_hash || metadata_hash)
    Ok(compute_leaf_hash(&payload_hash, &computed_metadata_hash))
}

/// Verify inclusion proof
///
/// STEP 2 of verification algorithm:
/// Uses RFC 6962 path validation to verify the leaf is included in the tree.
pub fn verify_inclusion_proof(
    leaf_hash: &[u8; 32],
    proof: &crate::core::receipt::ReceiptProof,
) -> Result<bool, VerificationError> {
    // Parse inclusion path
    let path: Vec<[u8; 32]> =
        proof.inclusion_path.iter().map(|h| parse_hash(h)).collect::<Result<Vec<_>, _>>().map_err(
            |e| VerificationError::InvalidHash {
                field: "proof.inclusion_path".to_string(),
                message: e.to_string(),
            },
        )?;

    // Parse expected root
    let expected_root =
        parse_hash(&proof.root_hash).map_err(|e| VerificationError::InvalidHash {
            field: "proof.root_hash".to_string(),
            message: e.to_string(),
        })?;

    // Verify using Merkle module
    let inclusion_proof =
        InclusionProof { leaf_index: proof.leaf_index, tree_size: proof.tree_size, path };

    verify_inclusion(leaf_hash, &inclusion_proof, &expected_root)
        .map_err(|e| VerificationError::InclusionProofFailed { reason: e.to_string() })
}

/// Verify checkpoint signature
///
/// STEP 3 of verification algorithm:
/// Verifies the Ed25519 signature on the checkpoint using the trusted public key.
pub fn verify_checkpoint_signature(
    checkpoint: &crate::core::checkpoint::CheckpointJson,
    verifier: &CheckpointVerifier,
) -> Result<bool, VerificationError> {
    // Build Checkpoint from CheckpointJson
    let origin = parse_hash(&checkpoint.origin).map_err(|_| VerificationError::SignatureFailed)?;
    let root_hash =
        parse_hash(&checkpoint.root_hash).map_err(|_| VerificationError::SignatureFailed)?;
    let signature =
        parse_signature(&checkpoint.signature).map_err(|_| VerificationError::SignatureFailed)?;
    let key_id = parse_hash(&checkpoint.key_id).map_err(|_| VerificationError::SignatureFailed)?;

    let mut cp = Checkpoint::new(
        origin,
        checkpoint.tree_size,
        checkpoint.timestamp,
        root_hash,
        [0; 64],
        key_id,
    );
    cp.signature = signature;

    // Verify signature
    cp.verify(verifier).map(|()| true).map_err(|_| VerificationError::SignatureFailed)
}

/// Verify a single anchor
///
/// Updated for ATL Protocol v2.0 with MANDATORY target field validation.
///
/// # Arguments
///
/// * `anchor` - The anchor to verify
/// * `context` - Verification context with expected hashes
///
/// # v2.0 Target Validation (MANDATORY)
///
/// For RFC 3161 anchors:
/// - `target` MUST be `"data_tree_root"` (ERROR if absent or different)
/// - `target_hash` MUST match `context.data_tree_root` (ERROR if absent or mismatch)
///
/// For Bitcoin OTS anchors:
/// - `target` MUST be `"super_root"` (ERROR if absent or different)
/// - `target_hash` MUST match `context.super_root` (ERROR if absent or mismatch)
pub fn verify_anchor(
    anchor: &ReceiptAnchor,
    context: &AnchorVerificationContext,
) -> AnchorVerificationResult {
    match anchor {
        ReceiptAnchor::Rfc3161 { target, target_hash, timestamp, token_der, .. } => {
            verify_rfc3161_anchor(target, target_hash, timestamp, token_der, context)
        }
        ReceiptAnchor::BitcoinOts { target, target_hash, timestamp, ots_proof, .. } => {
            verify_bitcoin_ots_anchor(target, target_hash, timestamp, ots_proof, context)
        }
    }
}

/// Verify RFC 3161 anchor with MANDATORY target validation
///
/// Per ATL Protocol v2.0 Section 5.5.1:
/// 1. Verify that `anchor.target` equals `"data_tree_root"` (REQUIRED)
/// 2. Verify that `anchor.target_hash` equals `proof.root_hash` (REQUIRED)
/// 3. Decode `token_der` (ASN.1 DER)
/// 4. Verify TSA signature
/// 5. Verify `MessageImprint` matches `target_hash`
///
/// NO FALLBACKS: Missing target or `target_hash` = ERROR.
fn verify_rfc3161_anchor(
    target: &str,
    target_hash: &str,
    timestamp: &str,
    token_der: &str,
    context: &AnchorVerificationContext,
) -> AnchorVerificationResult {
    use super::parse_iso8601_to_nanos;

    // 1. Validate target is "data_tree_root" (REQUIRED)
    if target != ANCHOR_TARGET_DATA_TREE_ROOT {
        return AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            is_valid: false,
            timestamp: parse_iso8601_to_nanos(timestamp),
            error: Some(format!("RFC 3161 anchor target must be 'data_tree_root', got '{target}'")),
        };
    }

    // 2. Get expected hash for target
    let expected_root = &context.data_tree_root;

    // 3. Parse and validate target_hash (REQUIRED)
    let parsed_target_hash = match parse_hash_string(target_hash) {
        Ok(hash) => hash,
        Err(e) => {
            return AnchorVerificationResult {
                anchor_type: "rfc3161".to_string(),
                is_valid: false,
                timestamp: parse_iso8601_to_nanos(timestamp),
                error: Some(format!("invalid target_hash format: {e}")),
            };
        }
    };

    // 4. Validate target_hash matches expected (REQUIRED)
    if !use_constant_time_eq(&parsed_target_hash, expected_root) {
        return AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            is_valid: false,
            timestamp: parse_iso8601_to_nanos(timestamp),
            error: Some(format!(
                "target_hash mismatch: anchor has {target_hash}, expected {}",
                format_hash(expected_root)
            )),
        };
    }

    // 5. Proceed with cryptographic verification using expected_root
    verify_rfc3161_anchor_impl(timestamp, token_der, expected_root)
}

/// Constant-time hash comparison
fn use_constant_time_eq(a: &Hash, b: &Hash) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Parse hash string `"sha256:..."` to 32-byte array
fn parse_hash_string(s: &str) -> Result<Hash, String> {
    parse_hash(s).map_err(|e| e.to_string())
}

/// Verify RFC 3161 anchor implementation (with feature flag)
#[cfg(feature = "rfc3161-verify")]
pub fn verify_rfc3161_anchor_impl(
    timestamp: &str,
    token_der: &str,
    expected_root: &[u8; 32],
) -> AnchorVerificationResult {
    use super::anchors::rfc3161::verify_rfc3161_anchor_impl;
    verify_rfc3161_anchor_impl(timestamp, token_der, expected_root)
}

/// Verify RFC 3161 anchor implementation (without feature flag)
#[cfg(not(feature = "rfc3161-verify"))]
pub fn verify_rfc3161_anchor_impl(
    timestamp: &str,
    _token_der: &str,
    _expected_root: &[u8; 32],
) -> AnchorVerificationResult {
    use super::parse_iso8601_to_nanos;

    AnchorVerificationResult {
        anchor_type: "rfc3161".to_string(),
        is_valid: false,
        timestamp: parse_iso8601_to_nanos(timestamp),
        error: Some("RFC 3161 verification requires 'rfc3161-verify' feature".to_string()),
    }
}

/// Verify Bitcoin OTS anchor with MANDATORY target validation
///
/// Per ATL Protocol v2.0 Section 5.5.2:
/// 1. Verify that `anchor.target` equals `"super_root"` (REQUIRED)
/// 2. Verify that `anchor.target_hash` equals `super_proof.super_root` (REQUIRED)
/// 3. Decode `ots_proof` (`OpenTimestamps` binary format)
/// 4. Verify the OTS proof chain from `target_hash` to the Bitcoin block
///
/// NO FALLBACKS: Missing target or `target_hash` = ERROR.
/// OTS anchors MUST target `"super_root"` (not `"data_tree_root"`).
fn verify_bitcoin_ots_anchor(
    target: &str,
    target_hash: &str,
    timestamp: &str,
    ots_proof: &str,
    context: &AnchorVerificationContext,
) -> AnchorVerificationResult {
    use super::parse_iso8601_to_nanos;

    // 1. Validate target is "super_root" (REQUIRED)
    if target != ANCHOR_TARGET_SUPER_ROOT {
        return AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            is_valid: false,
            timestamp: parse_iso8601_to_nanos(timestamp),
            error: Some(format!("Bitcoin OTS anchor target must be 'super_root', got '{target}'")),
        };
    }

    // 2. Get expected hash for target
    let expected_root = &context.super_root;

    // 3. Parse and validate target_hash (REQUIRED)
    let parsed_target_hash = match parse_hash_string(target_hash) {
        Ok(hash) => hash,
        Err(e) => {
            return AnchorVerificationResult {
                anchor_type: "bitcoin_ots".to_string(),
                is_valid: false,
                timestamp: parse_iso8601_to_nanos(timestamp),
                error: Some(format!("invalid target_hash format: {e}")),
            };
        }
    };

    // 4. Validate target_hash matches expected (REQUIRED)
    if !use_constant_time_eq(&parsed_target_hash, expected_root) {
        return AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            is_valid: false,
            timestamp: parse_iso8601_to_nanos(timestamp),
            error: Some(format!(
                "target_hash mismatch: anchor has {target_hash}, expected {}",
                format_hash(expected_root)
            )),
        };
    }

    // 5. Proceed with cryptographic verification using expected_root
    verify_bitcoin_ots_anchor_impl(timestamp, ots_proof, expected_root)
}

/// Verify Bitcoin OTS anchor implementation (with feature flag)
#[cfg(feature = "bitcoin-ots")]
pub fn verify_bitcoin_ots_anchor_impl(
    timestamp: &str,
    ots_proof: &str,
    expected_root: &[u8; 32],
) -> AnchorVerificationResult {
    use super::anchors::bitcoin_ots::verify_ots_anchor_impl;

    match verify_ots_anchor_impl(ots_proof, expected_root) {
        Ok(_result) => AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            is_valid: true,
            timestamp: None, // Core doesn't know block time
            error: None,
        },
        Err(e) => AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            is_valid: false,
            timestamp: super::parse_iso8601_to_nanos(timestamp),
            error: Some(e.to_string()),
        },
    }
}

/// Verify Bitcoin OTS anchor implementation (without feature flag)
#[cfg(not(feature = "bitcoin-ots"))]
pub fn verify_bitcoin_ots_anchor_impl(
    timestamp: &str,
    _ots_proof: &str,
    _expected_root: &[u8; 32],
) -> AnchorVerificationResult {
    use super::parse_iso8601_to_nanos;

    AnchorVerificationResult {
        anchor_type: "bitcoin_ots".to_string(),
        is_valid: false,
        timestamp: parse_iso8601_to_nanos(timestamp),
        error: Some("Bitcoin OTS verification requires 'bitcoin-ots' feature".to_string()),
    }
}

#[cfg(test)]
mod rfc3161_target_tests {
    use super::*;

    fn make_test_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn hash_from_byte(byte: u8) -> Hash {
        [byte; 32]
    }

    fn make_context() -> AnchorVerificationContext {
        AnchorVerificationContext::new(
            hash_from_byte(0xaa), // data_tree_root
            hash_from_byte(0xbb), // super_root
        )
    }

    #[test]
    fn test_rfc3161_v2_correct_target() {
        let context = make_context();

        let result = verify_rfc3161_anchor(
            "data_tree_root",
            &make_test_hash(0xaa),
            "2026-01-13T12:00:00Z",
            "base64:AAAA",
            &context,
        );

        // Target validation should pass (actual TSA verification may fail)
        // Error should NOT mention target
        if !result.is_valid {
            let error = result.error.as_ref().unwrap();
            assert!(!error.contains("target must be"));
            assert!(!error.contains("target_hash mismatch"));
        }
    }

    #[test]
    fn test_rfc3161_wrong_target_fails() {
        let context = make_context();

        let result = verify_rfc3161_anchor(
            "super_root", // Wrong! Should be "data_tree_root"
            &make_test_hash(0xaa),
            "2026-01-13T12:00:00Z",
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("must be 'data_tree_root'"));
    }

    #[test]
    fn test_rfc3161_target_hash_mismatch_fails() {
        let context = make_context(); // expects 0xaa

        let result = verify_rfc3161_anchor(
            "data_tree_root",
            &make_test_hash(0xff), // Wrong hash!
            "2026-01-13T12:00:00Z",
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("target_hash mismatch"));
    }

    #[test]
    fn test_rfc3161_invalid_target_hash_format_fails() {
        let context = make_context();

        let result = verify_rfc3161_anchor(
            "data_tree_root",
            "invalid", // Bad format
            "2026-01-13T12:00:00Z",
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("invalid target_hash format"));
    }

    #[test]
    fn test_anchor_context_creation() {
        let context = AnchorVerificationContext::new(hash_from_byte(0xaa), hash_from_byte(0xbb));

        assert_eq!(context.expected_hash_for_target("data_tree_root"), Some(&hash_from_byte(0xaa)));
        assert_eq!(context.expected_hash_for_target("super_root"), Some(&hash_from_byte(0xbb)));
        assert_eq!(context.expected_hash_for_target("unknown"), None);
    }

    #[test]
    fn test_rfc3161_empty_target_fails() {
        let context = make_context();

        let result = verify_rfc3161_anchor(
            "", // Empty!
            &make_test_hash(0xaa),
            "2026-01-13T12:00:00Z",
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_bitcoin_ots_wrong_target_fails() {
        let context = make_context();

        let result = verify_bitcoin_ots_anchor(
            "data_tree_root", // Wrong! Should be "super_root"
            &make_test_hash(0xbb),
            "2026-01-13T12:00:00Z",
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("must be 'super_root'"));
    }

    #[test]
    fn test_bitcoin_ots_target_hash_mismatch_fails() {
        let context = make_context(); // expects 0xbb for super_root

        let result = verify_bitcoin_ots_anchor(
            "super_root",
            &make_test_hash(0xff), // Wrong hash!
            "2026-01-13T12:00:00Z",
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("target_hash mismatch"));
    }

    #[test]
    fn test_ots_v2_correct_super_root_target() {
        let context = make_context();

        // Valid v2.0 anchor targeting super_root
        let result = verify_bitcoin_ots_anchor(
            "super_root",
            &make_test_hash(0xbb), // Matches context.super_root
            "2026-01-13T12:00:00Z",
            "base64:...",
            &context,
        );

        // Target validation should pass (actual OTS verification may fail)
        if !result.is_valid {
            let error = result.error.as_ref().unwrap();
            assert!(!error.contains("target must be"));
            assert!(!error.contains("target_hash mismatch"));
        }
    }

    #[test]
    fn test_ots_invalid_target_fails() {
        let context = make_context();

        let result = verify_bitcoin_ots_anchor(
            "invalid_target",
            &make_test_hash(0xbb),
            "2026-01-13T12:00:00Z",
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("must be 'super_root'"));
    }

    #[test]
    fn test_ots_invalid_target_hash_format_fails() {
        let context = make_context();

        let result = verify_bitcoin_ots_anchor(
            "super_root",
            "invalid", // Bad format
            "2026-01-13T12:00:00Z",
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("invalid target_hash format"));
    }

    #[test]
    fn test_ots_empty_target_fails() {
        let context = make_context();

        let result = verify_bitcoin_ots_anchor(
            "", // Empty!
            &make_test_hash(0xbb),
            "2026-01-13T12:00:00Z",
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_ots_empty_target_hash_fails() {
        let context = make_context();

        let result = verify_bitcoin_ots_anchor(
            "super_root",
            "", // Empty!
            "2026-01-13T12:00:00Z",
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
    }
}
