//! Internal helper functions for receipt verification
//!
//! This module contains internal verification helper functions
//! that support the main verification logic in `ReceiptVerifier`.

use crate::core::checkpoint::{parse_hash, parse_signature, Checkpoint, CheckpointVerifier};
use crate::core::jcs::canonicalize_and_hash;
use crate::core::merkle::{compute_leaf_hash, verify_inclusion, InclusionProof};
use crate::core::receipt::ReceiptAnchor;

use super::{AnchorVerificationResult, VerificationError};

// ========== Internal Helper Functions ==========

/// Reconstruct leaf hash from payload hash and metadata
///
/// STEP 1 of verification algorithm:
/// 1. Decode `payload_hash` from "sha256:..."
/// 2. Compute `metadata_hash` = SHA256(JCS(metadata))
/// 3. Compute `leaf_hash` = SHA256(0x00 || `payload_hash` || `metadata_hash`)
pub fn reconstruct_leaf_hash(
    payload_hash_str: &str,
    metadata: &serde_json::Value,
) -> Result<[u8; 32], VerificationError> {
    // Decode payload hash
    let payload_hash =
        parse_hash(payload_hash_str).map_err(|e| VerificationError::InvalidHash {
            field: "entry.payload_hash".to_string(),
            message: e.to_string(),
        })?;

    // Compute metadata hash via JCS
    let metadata_hash = canonicalize_and_hash(metadata);

    // Compute leaf hash: SHA256(0x00 || payload_hash || metadata_hash)
    Ok(compute_leaf_hash(&payload_hash, &metadata_hash))
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
/// STEP 4 of verification algorithm:
/// Verifies RFC 3161 timestamp tokens and Bitcoin OTS anchors cryptographically.
pub fn verify_anchor(anchor: &ReceiptAnchor, expected_root: &[u8; 32]) -> AnchorVerificationResult {
    match anchor {
        ReceiptAnchor::Rfc3161 { tsa_url: _, timestamp, token_der, .. } => {
            verify_rfc3161_anchor_impl(timestamp, token_der, expected_root)
        }
        ReceiptAnchor::BitcoinOts { timestamp, ots_proof, .. } => {
            verify_bitcoin_ots_anchor_impl(timestamp, ots_proof, expected_root)
        }
    }
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
