//! Convenience functions for receipt verification
//!
//! High-level API for quick verification without explicit verifier construction.

use crate::core::checkpoint::CheckpointVerifier;
use crate::core::jcs::canonicalize_and_hash;
use crate::core::merkle::{compute_leaf_hash, verify_inclusion, InclusionProof};
use crate::core::receipt::Receipt;
use crate::error::AtlResult;

use super::types::VerificationResult;
use super::verifier::ReceiptVerifier;

/// Convenience function: verify a receipt with a public key
///
/// ## Arguments
///
/// * `receipt` - The receipt to verify
/// * `public_key` - Trusted Ed25519 public key (32 bytes)
///
/// ## Returns
///
/// `VerificationResult` with detailed status
///
/// ## Errors
///
/// Returns error if the public key is invalid.
pub fn verify_receipt(receipt: &Receipt, public_key: &[u8; 32]) -> AtlResult<VerificationResult> {
    let verifier = CheckpointVerifier::from_bytes(public_key)?;
    let receipt_verifier = ReceiptVerifier::new(verifier);
    Ok(receipt_verifier.verify(receipt))
}

/// Convenience function: verify receipt JSON with a public key
///
/// ## Arguments
///
/// * `json` - Receipt JSON string
/// * `public_key` - Trusted Ed25519 public key (32 bytes)
///
/// ## Errors
///
/// Returns error if JSON parsing or public key is invalid.
pub fn verify_receipt_json(json: &str, public_key: &[u8; 32]) -> AtlResult<VerificationResult> {
    let receipt = Receipt::from_json(json)?;
    verify_receipt(&receipt, public_key)
}

/// Verify just the inclusion proof (without signature)
///
/// Useful for testing or when signature is verified separately.
///
/// ## Arguments
///
/// * `payload_hash` - SHA256 hash of the payload (32 bytes)
/// * `metadata` - Entry metadata (arbitrary JSON)
/// * `inclusion_path` - Sibling hashes along the path
/// * `leaf_index` - Index of the leaf in the tree
/// * `tree_size` - Size of the tree
/// * `expected_root` - Expected root hash (32 bytes)
///
/// ## Returns
///
/// `true` if the inclusion proof is valid, `false` otherwise.
#[must_use]
pub fn verify_inclusion_only(
    payload_hash: &[u8; 32],
    metadata: &serde_json::Value,
    inclusion_path: &[[u8; 32]],
    leaf_index: u64,
    tree_size: u64,
    expected_root: &[u8; 32],
) -> bool {
    // Compute metadata hash
    let metadata_hash = canonicalize_and_hash(metadata);

    // Compute leaf hash
    let leaf_hash = compute_leaf_hash(payload_hash, &metadata_hash);

    // Create inclusion proof
    let proof = InclusionProof { leaf_index, tree_size, path: inclusion_path.to_vec() };

    // Verify
    verify_inclusion(&leaf_hash, &proof, expected_root).unwrap_or(false)
}
