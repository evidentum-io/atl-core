//! Convenience functions for receipt verification
//!
//! This module provides high-level functions for common verification scenarios.
//! For more control, use [`ReceiptVerifier`] directly.
//!
//! ## Recommended Usage
//!
//! For most use cases, use **anchor-only** verification:
//!
//! ```rust,ignore
//! use atl_core::verify_receipt_anchor_only;
//!
//! let result = verify_receipt_anchor_only(&receipt)?;
//! if result.is_valid {
//!     println!("Receipt verified via external anchor!");
//! }
//! ```
//!
//! This follows the ATL Protocol v2.0 trust model where trust is derived from
//! external anchors (RFC 3161 TSA or Bitcoin OTS), not the Log Operator's key.

use crate::core::checkpoint::CheckpointVerifier;
use crate::core::jcs::canonicalize_and_hash;
use crate::core::merkle::{compute_leaf_hash, verify_inclusion, InclusionProof};
use crate::core::receipt::Receipt;
use crate::error::AtlResult;

use super::types::{VerificationResult, VerifyOptions};
use super::verifier::ReceiptVerifier;

// ========== Anchor-Only Functions (Recommended) ==========

/// Verify a receipt using anchor-only trust model (no public key required)
///
/// This is the **recommended** verification function for ATL Protocol v2.0.
/// It validates the receipt using external anchors (RFC 3161 TSA or Bitcoin OTS)
/// without requiring knowledge of the Log Operator's public key.
///
/// ## Trust Model
///
/// Per ATL Protocol v2.0 Section 1.2:
/// > "Verifiers do NOT need to trust the Log Operator. Trust is derived
/// > exclusively from external, independent anchors."
///
/// ## Example
///
/// ```rust,ignore
/// use atl_core::{verify_receipt_anchor_only, Receipt};
///
/// let result = verify_receipt_anchor_only(&receipt)?;
///
/// if result.is_valid {
///     println!("Receipt is valid!");
///     println!("Verified via: {:?}", result.anchor_results);
/// } else {
///     println!("Verification failed:");
///     for error in &result.errors {
///         println!("  - {}", error);
///     }
/// }
/// ```
///
/// ## When to Use
///
/// - First-time verification of receipts from unknown Log Operators
/// - When you don't have the Log Operator's public key
/// - When you want to rely solely on external timestamp proofs
///
/// ## Errors
///
/// Returns error only if the receipt structure is malformed.
/// Verification failures are reported in `result.is_valid` and `result.errors`.
pub fn verify_receipt_anchor_only(receipt: &Receipt) -> AtlResult<VerificationResult> {
    let verifier = ReceiptVerifier::anchor_only();
    Ok(verifier.verify(receipt))
}

/// Verify a receipt with custom options (no public key required)
///
/// Use this function when you need fine-grained control over verification
/// behavior while still using anchor-only trust.
///
/// ## Example
///
/// ```rust,ignore
/// use atl_core::{verify_receipt_with_options, Receipt, VerifyOptions, SignatureMode};
///
/// let options = VerifyOptions {
///     signature_mode: SignatureMode::Skip,
///     min_valid_anchors: 1,
///     ..Default::default()
/// };
///
/// let result = verify_receipt_with_options(&receipt, options)?;
/// ```
///
/// ## Options
///
/// - `signature_mode`: How to handle signature verification
/// - `skip_anchors`: Skip anchor verification entirely
/// - `skip_consistency`: Skip consistency proof verification
/// - `min_valid_anchors`: Minimum number of valid anchors required
///
/// ## Errors
///
/// Returns error only if the receipt structure is malformed.
pub fn verify_receipt_with_options(
    receipt: &Receipt,
    options: VerifyOptions,
) -> AtlResult<VerificationResult> {
    let verifier = ReceiptVerifier::anchor_only_with_options(options);
    Ok(verifier.verify(receipt))
}

// ========== Key-Based Functions ==========

/// Verify a receipt with a known public key (for additional integrity check)
///
/// Use this function when you have the Log Operator's trusted public key
/// and want to verify the checkpoint signature in addition to anchors.
///
/// ## Note
///
/// Per ATL Protocol v2.0, the signature is an **integrity check**, not a
/// trust anchor. Even with a valid signature, trust ultimately comes from
/// the external anchors.
///
/// ## Example
///
/// ```rust,ignore
/// use atl_core::{verify_receipt_with_key, Receipt};
///
/// let trusted_key = [0u8; 32];
/// let result = verify_receipt_with_key(&receipt, &trusted_key)?;
///
/// if result.signature_valid {
///     println!("Signature verified (integrity check passed)");
/// }
/// if result.is_valid {
///     println!("Receipt is valid (via anchors)");
/// }
/// ```
///
/// ## Errors
///
/// Returns error if:
/// - Receipt structure is malformed
/// - Public key bytes are invalid
pub fn verify_receipt_with_key(
    receipt: &Receipt,
    public_key: &[u8; 32],
) -> AtlResult<VerificationResult> {
    let checkpoint_verifier = CheckpointVerifier::from_bytes(public_key)?;
    let verifier = ReceiptVerifier::with_key(checkpoint_verifier);
    Ok(verifier.verify(receipt))
}

/// Verify a receipt with key and custom options
///
/// Combines key-based signature verification with custom verification options.
///
/// ## Example
///
/// ```rust,ignore
/// use atl_core::{verify_receipt_with_key_and_options, VerifyOptions, SignatureMode, Receipt};
///
/// let options = VerifyOptions {
///     signature_mode: SignatureMode::Require,
///     ..Default::default()
/// };
///
/// let result = verify_receipt_with_key_and_options(&receipt, &key, options)?;
/// ```
///
/// ## Errors
///
/// Returns error if:
/// - Receipt structure is malformed
/// - Public key bytes are invalid
pub fn verify_receipt_with_key_and_options(
    receipt: &Receipt,
    public_key: &[u8; 32],
    options: VerifyOptions,
) -> AtlResult<VerificationResult> {
    let checkpoint_verifier = CheckpointVerifier::from_bytes(public_key)?;
    let verifier = ReceiptVerifier::with_key_and_options(checkpoint_verifier, options);
    Ok(verifier.verify(receipt))
}

// ========== JSON Variants ==========

/// Verify receipt JSON using anchor-only trust model
///
/// Convenience function that parses JSON and verifies in one call.
///
/// ## Example
///
/// ```rust,ignore
/// use atl_core::verify_receipt_json_anchor_only;
///
/// let json = std::fs::read_to_string("document.pdf.atl")?;
/// let result = verify_receipt_json_anchor_only(&json)?;
/// ```
///
/// ## Errors
///
/// Returns error if JSON parsing fails.
pub fn verify_receipt_json_anchor_only(json: &str) -> AtlResult<VerificationResult> {
    let receipt = Receipt::from_json(json)?;
    verify_receipt_anchor_only(&receipt)
}

/// Verify receipt JSON with custom options
///
/// ## Errors
///
/// Returns error if JSON parsing fails.
pub fn verify_receipt_json_with_options(
    json: &str,
    options: VerifyOptions,
) -> AtlResult<VerificationResult> {
    let receipt = Receipt::from_json(json)?;
    verify_receipt_with_options(&receipt, options)
}

/// Verify receipt JSON with a known public key
///
/// ## Errors
///
/// Returns error if:
/// - JSON parsing fails
/// - Public key bytes are invalid
pub fn verify_receipt_json_with_key(
    json: &str,
    public_key: &[u8; 32],
) -> AtlResult<VerificationResult> {
    let receipt = Receipt::from_json(json)?;
    verify_receipt_with_key(&receipt, public_key)
}

/// Verify receipt JSON with key and custom options
///
/// ## Errors
///
/// Returns error if:
/// - JSON parsing fails
/// - Public key bytes are invalid
pub fn verify_receipt_json_with_key_and_options(
    json: &str,
    public_key: &[u8; 32],
    options: VerifyOptions,
) -> AtlResult<VerificationResult> {
    let receipt = Receipt::from_json(json)?;
    verify_receipt_with_key_and_options(&receipt, public_key, options)
}

// ========== Deprecated Functions ==========

/// Convenience function: verify a receipt with a public key
///
/// ## Deprecated
///
/// This function requires a public key, which contradicts ATL Protocol v2.0
/// trust model. Use one of these alternatives:
///
/// - [`verify_receipt_anchor_only()`] - Recommended for most use cases
/// - [`verify_receipt_with_options()`] - For custom verification settings
/// - [`verify_receipt_with_key()`] - If you specifically need key verification
///
/// ## Migration
///
/// ```rust,ignore
/// // Before (deprecated)
/// let result = verify_receipt(&receipt, &key)?;
///
/// // After (anchor-only, recommended)
/// use atl_core::verify_receipt_anchor_only;
/// let result = verify_receipt_anchor_only(&receipt)?;
///
/// // After (with key, if needed)
/// use atl_core::verify_receipt_with_key;
/// let result = verify_receipt_with_key(&receipt, &key)?;
/// ```
///
/// ## Errors
///
/// Returns error if:
/// - Receipt structure is malformed
/// - Public key bytes are invalid
#[deprecated(
    since = "0.5.0",
    note = "Use `verify_receipt_anchor_only()` or `verify_receipt_with_key()` instead"
)]
pub fn verify_receipt(receipt: &Receipt, public_key: &[u8; 32]) -> AtlResult<VerificationResult> {
    verify_receipt_with_key(receipt, public_key)
}

/// Convenience function: verify receipt JSON with a public key
///
/// ## Deprecated
///
/// See [`verify_receipt()`] for migration guidance.
///
/// ## Errors
///
/// Returns error if:
/// - JSON parsing fails
/// - Public key bytes are invalid
#[deprecated(
    since = "0.5.0",
    note = "Use `verify_receipt_json_anchor_only()` or `verify_receipt_json_with_key()` instead"
)]
pub fn verify_receipt_json(json: &str, public_key: &[u8; 32]) -> AtlResult<VerificationResult> {
    verify_receipt_json_with_key(json, public_key)
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
