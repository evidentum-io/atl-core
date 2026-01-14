//! Super-Tree verification functions
//!
//! This module provides verification for Super-Tree proofs per ATL Protocol v2.0.
//! The Super-Tree is a Merkle tree where each leaf is a Data Tree root hash.
//!
//! ## Mandatory `super_proof`
//!
//! All verification functions require valid `super_proof`.

use crate::core::merkle::{
    verify_consistency, verify_inclusion, ConsistencyProof, Hash, InclusionProof,
};
use crate::core::receipt::SuperProof;
use crate::error::{AtlError, AtlResult};

/// Verify Super-Tree inclusion proof
///
/// Verifies that a Data Tree root is included in the Super-Tree at the
/// claimed index. Uses RFC 9162 Merkle inclusion proof verification.
///
/// Per ATL Protocol v2.0 Section 5.4.1:
/// 1. Verify that `proof.root_hash` (Data Tree root) is included in the
///    Super-Tree at position `super_proof.data_tree_index`.
/// 2. Execute the Merkle Inclusion Proof verification algorithm using:
///    - Leaf: `data_tree_root`
///    - Index: `super_proof.data_tree_index`
///    - Tree Size: `super_proof.super_tree_size`
///    - Path: `super_proof.inclusion`
/// 3. The resulting root MUST equal `super_proof.super_root`.
///
/// **v2.0 Only**: No fallbacks. Invalid proof = verification failure.
///
/// # Arguments
///
/// * `data_tree_root` - Root hash of the Data Tree (from `proof.root_hash`)
/// * `super_proof` - Super-Tree proof from the receipt (REQUIRED)
///
/// # Returns
///
/// * `Ok(true)` - Data Tree root is validly included in Super Root
/// * `Ok(false)` - Proof is structurally valid but inclusion verification failed
/// * `Err(...)` - Proof structure is invalid
///
/// # Errors
///
/// Returns error if:
/// * `super_proof.super_tree_size` is 0
/// * `super_proof.data_tree_index` >= `super_proof.super_tree_size`
/// * Hash parsing fails for any field
/// * Proof path structure is invalid for tree geometry
///
/// # Example
///
/// ```
/// use atl_core::core::verify::super_tree::verify_super_inclusion;
/// use atl_core::core::receipt::SuperProof;
///
/// let data_tree_root = [0xaa; 32];
/// let super_proof = SuperProof {
///     genesis_super_root: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
///     data_tree_index: 0,
///     super_tree_size: 1,
///     super_root: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
///     inclusion: vec![],
///     consistency_to_origin: vec![],
/// };
///
/// let result = verify_super_inclusion(&data_tree_root, &super_proof);
/// assert!(result.is_ok());
/// assert!(result.unwrap());
/// ```
pub fn verify_super_inclusion(data_tree_root: &Hash, super_proof: &SuperProof) -> AtlResult<bool> {
    // Validate tree size
    if super_proof.super_tree_size == 0 {
        return Err(AtlError::InvalidTreeSize {
            size: 0,
            reason: "super_tree_size cannot be zero",
        });
    }

    // Validate index bounds
    if super_proof.data_tree_index >= super_proof.super_tree_size {
        return Err(AtlError::LeafIndexOutOfBounds {
            index: super_proof.data_tree_index,
            tree_size: super_proof.super_tree_size,
        });
    }

    // Parse super_root
    let expected_super_root = super_proof.super_root_bytes()?;

    // Parse inclusion path
    let inclusion_path = super_proof.inclusion_path_bytes()?;

    // Build InclusionProof for Merkle verification
    let inclusion_proof = InclusionProof {
        leaf_index: super_proof.data_tree_index,
        tree_size: super_proof.super_tree_size,
        path: inclusion_path,
    };

    // Use existing Merkle inclusion verification
    // The Data Tree root is the "leaf" being verified for inclusion
    verify_inclusion(data_tree_root, &inclusion_proof, &expected_super_root)
}

/// Verify consistency to origin proof
///
/// Verifies that the Super-Tree at its current size is consistent with
/// its genesis state (size 1). This enables transitive verification:
/// two receipts with the same `genesis_super_root` that both prove
/// consistency to origin are guaranteed to share a consistent history.
///
/// Per ATL Protocol v2.0 Section 5.4.2:
/// 1. Execute the Merkle Consistency Proof verification algorithm (RFC 9162)
/// 2. Parameters:
///    - `from_tree_size`: 1 (genesis)
///    - `to_tree_size`: `super_proof.super_tree_size`
///    - `from_root_hash`: `super_proof.genesis_super_root`
///    - `to_root_hash`: `super_proof.super_root`
///    - `path`: `super_proof.consistency_to_origin`
/// 3. The algorithm MUST confirm genesis state is a prefix of current state.
///
/// **v2.0 Only**: No fallbacks. Invalid proof = verification failure.
///
/// # Arguments
///
/// * `super_proof` - Super-Tree proof from the receipt (REQUIRED)
///
/// # Returns
///
/// * `Ok(true)` - Super-Tree is consistent with genesis
/// * `Ok(false)` - Proof is structurally valid but consistency verification failed
/// * `Err(...)` - Proof structure is invalid
///
/// # Errors
///
/// Returns error if:
/// * `super_proof.super_tree_size` is 0
/// * Hash parsing fails for `genesis_super_root` or `super_root`
/// * Consistency proof path structure is invalid
///
/// # Special Case: Genesis Tree
///
/// When `super_tree_size == 1`:
/// - `genesis_super_root` MUST equal `super_root`
/// - `consistency_to_origin` MUST be empty
/// - This is the degenerate case where the Super-Tree contains only one Data Tree
///
/// # Example
///
/// ```
/// use atl_core::core::verify::super_tree::verify_consistency_to_origin;
/// use atl_core::core::receipt::SuperProof;
///
/// // Genesis case: single Data Tree
/// let super_proof = SuperProof {
///     genesis_super_root: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
///     data_tree_index: 0,
///     super_tree_size: 1,
///     super_root: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
///     inclusion: vec![],
///     consistency_to_origin: vec![],
/// };
///
/// let result = verify_consistency_to_origin(&super_proof);
/// assert!(result.is_ok());
/// assert!(result.unwrap());
/// ```
pub fn verify_consistency_to_origin(super_proof: &SuperProof) -> AtlResult<bool> {
    // Validate super_tree_size
    if super_proof.super_tree_size == 0 {
        return Err(AtlError::InvalidTreeSize {
            size: 0,
            reason: "super_tree_size cannot be zero",
        });
    }

    // Parse hashes
    let genesis_super_root = super_proof.genesis_super_root_bytes()?;
    let super_root = super_proof.super_root_bytes()?;

    // Special case: genesis tree (size 1)
    // Consistency proof from size 1 to size 1 is trivial:
    // genesis_super_root must equal super_root, and path must be empty
    if super_proof.super_tree_size == 1 {
        // For size 1, there's no consistency proof needed
        // Just verify genesis_super_root == super_root
        if super_proof.consistency_to_origin.is_empty() {
            return Ok(use_constant_time_eq(&genesis_super_root, &super_root));
        }
        // Non-empty path for size 1 is structurally invalid
        return Err(AtlError::InvalidProofStructure {
            reason: format!(
                "consistency_to_origin must be empty for super_tree_size 1, got {} hashes",
                super_proof.consistency_to_origin.len()
            ),
        });
    }

    // Parse consistency path
    let consistency_path = super_proof.consistency_to_origin_bytes()?;

    // Build ConsistencyProof for Merkle verification
    let consistency_proof = ConsistencyProof {
        from_size: 1, // Genesis
        to_size: super_proof.super_tree_size,
        path: consistency_path,
    };

    // Use existing Merkle consistency verification
    verify_consistency(&consistency_proof, &genesis_super_root, &super_root)
}

/// Constant-time equality comparison for hashes
///
/// Prevents timing attacks by comparing hashes in constant time.
pub(crate) fn use_constant_time_eq(a: &Hash, b: &Hash) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Result of Super-Tree verification
///
/// Contains detailed status of Super-Tree proof verification.
#[derive(Debug, Clone)]
pub struct SuperVerificationResult {
    /// Whether super inclusion proof is valid
    pub inclusion_valid: bool,

    /// Whether consistency to origin is valid
    pub consistency_valid: bool,

    /// Parsed `genesis_super_root` (always present in v2.0)
    pub genesis_super_root: Hash,

    /// Parsed `super_root` (always present in v2.0)
    pub super_root: Hash,

    /// Errors encountered during verification
    pub errors: Vec<String>,
}

impl SuperVerificationResult {
    /// Create a new result for successful verification
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec::new() is not const in stable
    pub fn valid(genesis_super_root: Hash, super_root: Hash) -> Self {
        Self {
            inclusion_valid: true,
            consistency_valid: true,
            genesis_super_root,
            super_root,
            errors: vec![],
        }
    }

    /// Create a new result for failed verification
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec construction is not const in stable
    pub fn invalid(error: String) -> Self {
        Self {
            inclusion_valid: false,
            consistency_valid: false,
            genesis_super_root: [0; 32],
            super_root: [0; 32],
            errors: vec![error],
        }
    }

    /// Check if fully valid
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.inclusion_valid && self.consistency_valid
    }
}

/// Result of cross-receipt verification
///
/// Indicates whether two receipts belong to the same consistent log history.
/// All fields are concrete types - no Options because `super_proof` is mandatory.
#[derive(Debug, Clone)]
pub struct CrossReceiptVerificationResult {
    /// Whether both receipts are from the same log instance
    pub same_log_instance: bool,

    /// Whether the log history between receipts was not modified
    pub history_consistent: bool,

    /// Genesis super root shared by both receipts
    pub genesis_super_root: Hash,

    /// Data Tree index of receipt A
    pub receipt_a_index: u64,

    /// Data Tree index of receipt B
    pub receipt_b_index: u64,

    /// Super-Tree size of receipt A
    pub receipt_a_super_tree_size: u64,

    /// Super-Tree size of receipt B
    pub receipt_b_super_tree_size: u64,

    /// Errors encountered during verification
    pub errors: Vec<String>,
}

impl CrossReceiptVerificationResult {
    /// Check if cross-verification succeeded
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.same_log_instance && self.history_consistent
    }

    /// Get which receipt is earlier (by `data_tree_index`)
    ///
    /// Returns `Ordering`:
    /// - `Less`: Receipt A is earlier
    /// - `Greater`: Receipt A is later
    /// - `Equal`: Same Data Tree (possibly different entries)
    #[must_use]
    pub fn ordering(&self) -> std::cmp::Ordering {
        self.receipt_a_index.cmp(&self.receipt_b_index)
    }

    /// Get the earlier receipt's index
    #[must_use]
    pub const fn earlier_index(&self) -> u64 {
        if self.receipt_a_index <= self.receipt_b_index {
            self.receipt_a_index
        } else {
            self.receipt_b_index
        }
    }

    /// Get the later receipt's index
    #[must_use]
    pub const fn later_index(&self) -> u64 {
        if self.receipt_a_index >= self.receipt_b_index {
            self.receipt_a_index
        } else {
            self.receipt_b_index
        }
    }
}

/// Verify that two receipts belong to the same consistent log history
///
/// Per ATL Protocol v2.0 Section 5.4.3, cross-receipt verification:
/// 1. Both receipts MUST have `super_proof` (mandatory in v2.0)
/// 2. Verify that `A.super_proof.genesis_super_root == B.super_proof.genesis_super_root`
/// 3. Verify `consistency_to_origin` for both receipts
/// 4. If both pass, the log history between them was not modified.
///
/// **No server access required. Only the two receipts are needed.**
///
/// # Arguments
///
/// * `receipt_a` - First receipt (v2.0 with mandatory `super_proof`)
/// * `receipt_b` - Second receipt (v2.0 with mandatory `super_proof`)
///
/// # Returns
///
/// * `CrossReceiptVerificationResult` with detailed status
///
/// # Trust Model
///
/// This function verifies that:
/// 1. Both receipts claim the same log origin (`genesis_super_root`)
/// 2. Both receipts have valid consistency proofs to that origin
///
/// This DOES NOT verify:
/// - Individual receipt validity (signature, inclusion) - use `verify_receipt()` for that
/// - Anchor timestamps (TSA, OTS) - use `verify_receipt()` for that
///
/// For full trust, call `verify_receipt()` on both receipts first, then call this function.
///
/// # Example
///
/// ```rust,ignore
/// use atl_core::{verify_receipt, verify_cross_receipts};
///
/// // First, verify each receipt independently
/// let result_a = verify_receipt(&receipt_a, &trusted_key)?;
/// let result_b = verify_receipt(&receipt_b, &trusted_key)?;
///
/// if !result_a.is_valid || !result_b.is_valid {
///     println!("One or both receipts are invalid");
///     return;
/// }
///
/// // Then verify cross-receipt consistency
/// let cross_result = verify_cross_receipts(&receipt_a, &receipt_b);
///
/// if cross_result.is_valid() {
///     println!("Receipts are from the same consistent log");
///     println!("Earlier receipt at index: {}", cross_result.earlier_index());
///     println!("Later receipt at index: {}", cross_result.later_index());
/// } else {
///     println!("Receipts may be from different logs or inconsistent history");
///     for error in &cross_result.errors {
///         println!("  Error: {}", error);
///     }
/// }
/// ```
#[must_use]
pub fn verify_cross_receipts(
    receipt_a: &crate::core::receipt::Receipt,
    receipt_b: &crate::core::receipt::Receipt,
) -> CrossReceiptVerificationResult {
    let mut result = CrossReceiptVerificationResult {
        same_log_instance: false,
        history_consistent: false,
        genesis_super_root: [0; 32],
        receipt_a_index: 0,
        receipt_b_index: 0,
        receipt_a_super_tree_size: 0,
        receipt_b_super_tree_size: 0,
        errors: vec![],
    };

    // super_proof is mandatory in v2.0, so we can access it directly
    let super_proof_a = &receipt_a.super_proof;
    let super_proof_b = &receipt_b.super_proof;

    // Record data tree indexes and sizes
    result.receipt_a_index = super_proof_a.data_tree_index;
    result.receipt_b_index = super_proof_b.data_tree_index;
    result.receipt_a_super_tree_size = super_proof_a.super_tree_size;
    result.receipt_b_super_tree_size = super_proof_b.super_tree_size;

    // Parse genesis_super_root from both receipts
    let genesis_a = match super_proof_a.genesis_super_root_bytes() {
        Ok(h) => h,
        Err(e) => {
            result.errors.push(format!("Receipt A genesis_super_root invalid: {e}"));
            return result;
        }
    };

    let genesis_b = match super_proof_b.genesis_super_root_bytes() {
        Ok(h) => h,
        Err(e) => {
            result.errors.push(format!("Receipt B genesis_super_root invalid: {e}"));
            return result;
        }
    };

    // Check if same log instance (same genesis)
    if use_constant_time_eq(&genesis_a, &genesis_b) {
        result.same_log_instance = true;
        result.genesis_super_root = genesis_a;
    } else {
        result.errors.push(format!(
            "Different genesis_super_root: A={}, B={}",
            hex::encode(genesis_a),
            hex::encode(genesis_b)
        ));
        return result;
    }

    // Verify consistency_to_origin for both receipts
    let consistency_a = verify_consistency_to_origin(super_proof_a);
    let consistency_b = verify_consistency_to_origin(super_proof_b);

    match (consistency_a, consistency_b) {
        (Ok(true), Ok(true)) => {
            // Both are consistent with genesis
            result.history_consistent = true;
        }
        (Ok(false), _) => {
            result.errors.push("Receipt A consistency_to_origin verification failed".to_string());
        }
        (_, Ok(false)) => {
            result.errors.push("Receipt B consistency_to_origin verification failed".to_string());
        }
        (Err(e), _) => {
            result.errors.push(format!("Receipt A consistency_to_origin error: {e}"));
        }
        (_, Err(e)) => {
            result.errors.push(format!("Receipt B consistency_to_origin error: {e}"));
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::merkle::hash_children;

    fn make_test_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn hash_from_byte(byte: u8) -> Hash {
        [byte; 32]
    }

    #[test]
    fn test_verify_super_inclusion_single_tree() {
        // Super-Tree with single Data Tree (genesis)
        // In this case: super_root == data_tree_root, inclusion path is empty
        let data_tree_root = hash_from_byte(0xaa);

        let super_proof = SuperProof {
            genesis_super_root: make_test_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: make_test_hash(0xaa),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&data_tree_root, &super_proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_super_inclusion_two_trees() {
        // Super-Tree with two Data Trees
        // Leaves: [R0, R1], Root = H(R0 || R1)
        let r0 = hash_from_byte(0xaa);
        let r1 = hash_from_byte(0xbb);
        let super_root = hash_children(&r0, &r1);

        // Verify R0 is at index 0
        let super_proof_0 = SuperProof {
            genesis_super_root: make_test_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 2,
            super_root: format!("sha256:{}", hex::encode(super_root)),
            inclusion: vec![make_test_hash(0xbb)], // Sibling is R1
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&r0, &super_proof_0);
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify R1 is at index 1
        let super_proof_1 = SuperProof {
            genesis_super_root: make_test_hash(0xaa),
            data_tree_index: 1,
            super_tree_size: 2,
            super_root: format!("sha256:{}", hex::encode(super_root)),
            inclusion: vec![make_test_hash(0xaa)], // Sibling is R0
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&r1, &super_proof_1);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_super_inclusion_wrong_root_returns_false() {
        let data_tree_root = hash_from_byte(0xaa);

        let super_proof = SuperProof {
            genesis_super_root: make_test_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: make_test_hash(0xff), // Wrong root
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&data_tree_root, &super_proof);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Valid structure, wrong hash
    }

    #[test]
    fn test_verify_super_inclusion_index_out_of_bounds_error() {
        let data_tree_root = hash_from_byte(0xaa);

        let super_proof = SuperProof {
            genesis_super_root: make_test_hash(0xaa),
            data_tree_index: 5, // Out of bounds
            super_tree_size: 3,
            super_root: make_test_hash(0xbb),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&data_tree_root, &super_proof);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::LeafIndexOutOfBounds { .. }));
    }

    #[test]
    fn test_verify_super_inclusion_zero_size_error() {
        let data_tree_root = hash_from_byte(0xaa);

        let super_proof = SuperProof {
            genesis_super_root: make_test_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 0, // Invalid
            super_root: make_test_hash(0xaa),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&data_tree_root, &super_proof);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidTreeSize { .. }));
    }

    #[test]
    fn test_verify_super_inclusion_invalid_hash_format_error() {
        let data_tree_root = hash_from_byte(0xaa);

        let super_proof = SuperProof {
            genesis_super_root: make_test_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 2,
            super_root: "invalid".to_string(), // Invalid format
            inclusion: vec![make_test_hash(0xbb)],
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&data_tree_root, &super_proof);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidHash(_)));
    }

    #[test]
    fn test_super_verification_result_valid() {
        let result = SuperVerificationResult::valid(hash_from_byte(0xaa), hash_from_byte(0xbb));

        assert!(result.is_valid());
        assert!(result.inclusion_valid);
        assert!(result.consistency_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_super_verification_result_invalid() {
        let result = SuperVerificationResult::invalid("test error".to_string());

        assert!(!result.is_valid());
        assert!(!result.inclusion_valid);
        assert!(!result.consistency_valid);
        assert_eq!(result.errors.len(), 1);
    }
}

#[cfg(test)]
mod consistency_tests {
    use super::*;
    use crate::core::merkle::hash_children;

    fn make_test_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn hash_from_byte(byte: u8) -> Hash {
        [byte; 32]
    }

    #[test]
    fn test_verify_consistency_genesis_tree() {
        // Super-Tree with single Data Tree: genesis_super_root == super_root
        let super_proof = SuperProof {
            genesis_super_root: make_test_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: make_test_hash(0xaa), // Same as genesis
            inclusion: vec![],
            consistency_to_origin: vec![], // Must be empty
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_consistency_genesis_mismatch() {
        // Genesis tree but genesis_super_root != super_root
        let super_proof = SuperProof {
            genesis_super_root: make_test_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: make_test_hash(0xbb), // Different!
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Valid structure, wrong hash
    }

    #[test]
    fn test_verify_consistency_genesis_nonempty_path_error() {
        // Genesis tree but consistency_to_origin is not empty
        let super_proof = SuperProof {
            genesis_super_root: make_test_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: make_test_hash(0xaa),
            inclusion: vec![],
            consistency_to_origin: vec![make_test_hash(0xcc)], // Should be empty!
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidProofStructure { .. }));
    }

    #[test]
    fn test_verify_consistency_two_trees() {
        // Super-Tree grew from 1 to 2
        // Leaves: [R0, R1], Root at size 2 = H(R0 || R1)
        let r0 = hash_from_byte(0xaa);
        let r1 = hash_from_byte(0xbb);
        let super_root_2 = hash_children(&r0, &r1);

        // Consistency proof from size 1 (root = R0) to size 2 (root = H(R0||R1))
        let super_proof = SuperProof {
            genesis_super_root: make_test_hash(0xaa), // R0
            data_tree_index: 1,
            super_tree_size: 2,
            super_root: format!("sha256:{}", hex::encode(super_root_2)),
            inclusion: vec![],
            consistency_to_origin: vec![make_test_hash(0xbb)], // [R1]
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_consistency_wrong_path_returns_false() {
        // Super-Tree grew from 1 to 2, but wrong consistency path
        let r0 = hash_from_byte(0xaa);
        let r1 = hash_from_byte(0xbb);
        let super_root_2 = hash_children(&r0, &r1);

        let super_proof = SuperProof {
            genesis_super_root: make_test_hash(0xaa),
            data_tree_index: 1,
            super_tree_size: 2,
            super_root: format!("sha256:{}", hex::encode(super_root_2)),
            inclusion: vec![],
            consistency_to_origin: vec![make_test_hash(0xff)], // Wrong sibling!
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Valid structure, wrong proof
    }

    #[test]
    fn test_verify_consistency_zero_size_error() {
        let super_proof = SuperProof {
            genesis_super_root: make_test_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 0, // Invalid
            super_root: make_test_hash(0xaa),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidTreeSize { .. }));
    }

    #[test]
    fn test_verify_consistency_invalid_hash_error() {
        let super_proof = SuperProof {
            genesis_super_root: "invalid".to_string(), // Bad format
            data_tree_index: 0,
            super_tree_size: 2,
            super_root: make_test_hash(0xbb),
            inclusion: vec![],
            consistency_to_origin: vec![make_test_hash(0xcc)],
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidHash(_)));
    }

    #[test]
    fn test_verify_consistency_three_trees() {
        // Super-Tree grew from 1 to 3
        let r0 = hash_from_byte(0xaa);
        let r1 = hash_from_byte(0xbb);
        let r2 = hash_from_byte(0xcc);
        let h01 = hash_children(&r0, &r1);
        let super_root_3 = hash_children(&h01, &r2);

        // Consistency from 1 to 3: [R1, R2]
        let super_proof = SuperProof {
            genesis_super_root: make_test_hash(0xaa), // R0
            data_tree_index: 2,
            super_tree_size: 3,
            super_root: format!("sha256:{}", hex::encode(super_root_3)),
            inclusion: vec![],
            consistency_to_origin: vec![
                make_test_hash(0xbb), // R1
                make_test_hash(0xcc), // R2
            ],
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}

#[cfg(test)]
mod cross_receipt_tests {
    use super::*;
    use crate::core::checkpoint::CheckpointJson;
    use crate::core::receipt::{Receipt, ReceiptEntry, ReceiptProof, SuperProof};
    use uuid::Uuid;

    fn make_test_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn make_v2_receipt_with_super_proof(genesis: u8, index: u64, size: u64) -> Receipt {
        Receipt {
            spec_version: "2.0.0".to_string(),
            upgrade_url: None,
            entry: ReceiptEntry {
                id: Uuid::nil(),
                payload_hash: make_test_hash(0xcc),
                metadata: serde_json::json!({}),
            },
            proof: ReceiptProof {
                tree_size: 1,
                root_hash: make_test_hash(genesis),
                inclusion_path: vec![],
                leaf_index: 0,
                checkpoint: CheckpointJson {
                    origin: make_test_hash(0xdd),
                    tree_size: 1,
                    root_hash: make_test_hash(genesis),
                    timestamp: 1_704_067_200_000_000_000,
                    signature: "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    key_id: make_test_hash(0xee),
                },
                consistency_proof: None,
            },
            super_proof: SuperProof {
                genesis_super_root: make_test_hash(genesis),
                data_tree_index: index,
                super_tree_size: size,
                super_root: make_test_hash(genesis), // Simplified for size 1
                inclusion: vec![],
                consistency_to_origin: vec![],
            },
            anchors: vec![],
        }
    }

    #[test]
    fn test_cross_receipt_same_log() {
        // Two receipts from same log (same genesis)
        let receipt_a = make_v2_receipt_with_super_proof(0xaa, 5, 10);
        let receipt_b = make_v2_receipt_with_super_proof(0xaa, 8, 15);

        let result = verify_cross_receipts(&receipt_a, &receipt_b);

        assert!(result.same_log_instance);
        assert_eq!(result.receipt_a_index, 5);
        assert_eq!(result.receipt_b_index, 8);
        assert_ne!(result.genesis_super_root, [0u8; 32]);
    }

    #[test]
    fn test_cross_receipt_different_logs() {
        // Two receipts from different logs (different genesis)
        let receipt_a = make_v2_receipt_with_super_proof(0xaa, 5, 10);
        let receipt_b = make_v2_receipt_with_super_proof(0xbb, 5, 10); // Different genesis!

        let result = verify_cross_receipts(&receipt_a, &receipt_b);

        assert!(!result.same_log_instance);
        assert!(!result.is_valid());
        assert!(!result.errors.is_empty());
        assert!(result.errors[0].contains("Different genesis_super_root"));
    }

    #[test]
    fn test_cross_receipt_ordering_a_earlier() {
        let receipt_a = make_v2_receipt_with_super_proof(0xaa, 5, 10); // index 5
        let receipt_b = make_v2_receipt_with_super_proof(0xaa, 15, 20); // index 15

        let result = verify_cross_receipts(&receipt_a, &receipt_b);

        assert!(result.same_log_instance);
        assert_eq!(result.ordering(), std::cmp::Ordering::Less); // A < B
        assert_eq!(result.earlier_index(), 5);
        assert_eq!(result.later_index(), 15);
    }

    #[test]
    fn test_cross_receipt_ordering_b_earlier() {
        let receipt_a = make_v2_receipt_with_super_proof(0xaa, 15, 20); // index 15
        let receipt_b = make_v2_receipt_with_super_proof(0xaa, 5, 10); // index 5

        let result = verify_cross_receipts(&receipt_a, &receipt_b);

        assert!(result.same_log_instance);
        assert_eq!(result.ordering(), std::cmp::Ordering::Greater); // A > B
        assert_eq!(result.earlier_index(), 5);
        assert_eq!(result.later_index(), 15);
    }

    #[test]
    fn test_cross_receipt_same_tree() {
        // Two receipts from same Data Tree
        let receipt_a = make_v2_receipt_with_super_proof(0xaa, 5, 10);
        let receipt_b = make_v2_receipt_with_super_proof(0xaa, 5, 10); // Same index

        let result = verify_cross_receipts(&receipt_a, &receipt_b);

        assert!(result.same_log_instance);
        assert_eq!(result.ordering(), std::cmp::Ordering::Equal);
        assert_eq!(result.earlier_index(), 5);
        assert_eq!(result.later_index(), 5);
    }

    #[test]
    fn test_cross_receipt_invalid_genesis_format() {
        let mut receipt_a = make_v2_receipt_with_super_proof(0xaa, 5, 10);
        receipt_a.super_proof.genesis_super_root = "invalid".to_string();

        let receipt_b = make_v2_receipt_with_super_proof(0xaa, 8, 15);

        let result = verify_cross_receipts(&receipt_a, &receipt_b);

        assert!(!result.is_valid());
        assert!(result.errors.iter().any(|e| e.contains("Receipt A genesis_super_root invalid")));
    }

    #[test]
    fn test_cross_receipt_result_is_valid() {
        let mut result = CrossReceiptVerificationResult {
            same_log_instance: true,
            history_consistent: true,
            genesis_super_root: [0xaa; 32],
            receipt_a_index: 5,
            receipt_b_index: 10,
            receipt_a_super_tree_size: 10,
            receipt_b_super_tree_size: 15,
            errors: vec![],
        };
        assert!(result.is_valid());

        result.same_log_instance = false;
        assert!(!result.is_valid());

        result.same_log_instance = true;
        result.history_consistent = false;
        assert!(!result.is_valid());
    }

    #[test]
    fn test_cross_receipt_result_fields_non_option() {
        let result = CrossReceiptVerificationResult {
            same_log_instance: true,
            history_consistent: true,
            genesis_super_root: [0xaa; 32],
            receipt_a_index: 5,
            receipt_b_index: 10,
            receipt_a_super_tree_size: 10,
            receipt_b_super_tree_size: 15,
            errors: vec![],
        };

        // All fields should be concrete types, not Option
        let _: bool = result.same_log_instance;
        let _: bool = result.history_consistent;
        let _: Hash = result.genesis_super_root;
        let _: u64 = result.receipt_a_index;
        let _: u64 = result.receipt_b_index;
    }
}

#[cfg(test)]
mod super_inclusion_tests {
    use super::*;
    use crate::core::merkle::hash_children;

    fn make_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn hash_bytes(byte: u8) -> Hash {
        [byte; 32]
    }

    // === Valid Proof Tests ===

    #[test]
    fn test_single_tree_genesis() {
        // Super-Tree with single Data Tree: root == leaf
        let data_tree_root = hash_bytes(0xaa);

        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: make_hash(0xaa),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&data_tree_root, &super_proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_two_trees_index_0() {
        // Super-Tree: [R0, R1], Root = H(R0 || R1)
        let r0 = hash_bytes(0xaa);
        let r1 = hash_bytes(0xbb);
        let super_root = hash_children(&r0, &r1);

        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 2,
            super_root: format!("sha256:{}", hex::encode(super_root)),
            inclusion: vec![make_hash(0xbb)], // Sibling R1
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&r0, &super_proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_two_trees_index_1() {
        let r0 = hash_bytes(0xaa);
        let r1 = hash_bytes(0xbb);
        let super_root = hash_children(&r0, &r1);

        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 1,
            super_tree_size: 2,
            super_root: format!("sha256:{}", hex::encode(super_root)),
            inclusion: vec![make_hash(0xaa)], // Sibling R0
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&r1, &super_proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_four_trees_index_2() {
        // Super-Tree: [R0, R1, R2, R3]
        //         Root
        //        /    \
        //    H01       H23
        //   /  \      /  \
        //  R0  R1    R2  R3
        let r0 = hash_bytes(0xaa);
        let r1 = hash_bytes(0xbb);
        let r2 = hash_bytes(0xcc);
        let r3 = hash_bytes(0xdd);
        let h01 = hash_children(&r0, &r1);
        let h23 = hash_children(&r2, &r3);
        let super_root = hash_children(&h01, &h23);

        // Proof for R2 at index 2: [R3, H01]
        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 2,
            super_tree_size: 4,
            super_root: format!("sha256:{}", hex::encode(super_root)),
            inclusion: vec![
                make_hash(0xdd),                        // R3 (sibling)
                format!("sha256:{}", hex::encode(h01)), // H01
            ],
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&r2, &super_proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    // === Invalid Proof Tests ===

    #[test]
    fn test_wrong_super_root() {
        let data_tree_root = hash_bytes(0xaa);

        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: make_hash(0xff), // Wrong!
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&data_tree_root, &super_proof);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Valid structure, wrong hash
    }

    #[test]
    fn test_wrong_sibling() {
        let r0 = hash_bytes(0xaa);
        let r1 = hash_bytes(0xbb);
        let super_root = hash_children(&r0, &r1);

        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 2,
            super_root: format!("sha256:{}", hex::encode(super_root)),
            inclusion: vec![make_hash(0xff)], // Wrong sibling!
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&r0, &super_proof);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    // === Error Cases ===

    #[test]
    fn test_zero_tree_size() {
        let data_tree_root = hash_bytes(0xaa);

        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 0, // Invalid!
            super_root: make_hash(0xaa),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&data_tree_root, &super_proof);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidTreeSize { .. }));
    }

    #[test]
    fn test_index_out_of_bounds() {
        let data_tree_root = hash_bytes(0xaa);

        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 10, // Out of bounds!
            super_tree_size: 5,
            super_root: make_hash(0xbb),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&data_tree_root, &super_proof);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::LeafIndexOutOfBounds { .. }));
    }

    #[test]
    fn test_invalid_super_root_format() {
        let data_tree_root = hash_bytes(0xaa);

        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: "invalid".to_string(), // Bad format!
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&data_tree_root, &super_proof);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidHash(_)));
    }

    #[test]
    fn test_invalid_inclusion_path_element() {
        let data_tree_root = hash_bytes(0xaa);

        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 2,
            super_root: make_hash(0xbb),
            inclusion: vec!["invalid".to_string()], // Bad format!
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&data_tree_root, &super_proof);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidHash(_)));
    }

    #[test]
    fn test_single_leaf_with_nonempty_path() {
        let data_tree_root = hash_bytes(0xaa);

        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: make_hash(0xaa),
            inclusion: vec![make_hash(0xbb)], // Should be empty!
            consistency_to_origin: vec![],
        };

        let result = verify_super_inclusion(&data_tree_root, &super_proof);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidProofStructure { .. }));
    }
}

#[cfg(test)]
mod consistency_to_origin_tests {
    use super::*;
    use crate::core::merkle::hash_children;

    fn make_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn hash_bytes(byte: u8) -> Hash {
        [byte; 32]
    }

    // === Valid Proof Tests ===

    #[test]
    fn test_genesis_tree_consistent() {
        // Size 1: genesis == super_root, empty path
        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: make_hash(0xaa),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_two_trees_consistent() {
        // Size 1 to 2: genesis = R0, new = H(R0||R1)
        let r0 = hash_bytes(0xaa);
        let r1 = hash_bytes(0xbb);
        let super_root_2 = hash_children(&r0, &r1);

        // Consistency proof from 1 to 2: [R1]
        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 1,
            super_tree_size: 2,
            super_root: format!("sha256:{}", hex::encode(super_root_2)),
            inclusion: vec![],
            consistency_to_origin: vec![make_hash(0xbb)],
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_three_trees_consistent() {
        // Size 1 to 3
        let r0 = hash_bytes(0xaa);
        let r1 = hash_bytes(0xbb);
        let r2 = hash_bytes(0xcc);
        let h01 = hash_children(&r0, &r1);
        let super_root_3 = hash_children(&h01, &r2);

        // Consistency from 1 to 3: [R1, R2]
        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 2,
            super_tree_size: 3,
            super_root: format!("sha256:{}", hex::encode(super_root_3)),
            inclusion: vec![],
            consistency_to_origin: vec![make_hash(0xbb), make_hash(0xcc)],
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    // === Invalid Proof Tests ===

    #[test]
    fn test_genesis_mismatch() {
        // genesis != super_root for size 1
        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: make_hash(0xff), // Different!
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Valid structure, wrong hash
    }

    #[test]
    fn test_wrong_consistency_path() {
        let r0 = hash_bytes(0xaa);
        let r1 = hash_bytes(0xbb);
        let super_root_2 = hash_children(&r0, &r1);

        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 1,
            super_tree_size: 2,
            super_root: format!("sha256:{}", hex::encode(super_root_2)),
            inclusion: vec![],
            consistency_to_origin: vec![make_hash(0xff)], // Wrong!
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    // === Error Cases ===

    #[test]
    fn test_zero_size_error() {
        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 0, // Invalid!
            super_root: make_hash(0xaa),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidTreeSize { .. }));
    }

    #[test]
    fn test_genesis_nonempty_path_error() {
        // Size 1 but non-empty consistency path
        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: make_hash(0xaa),
            inclusion: vec![],
            consistency_to_origin: vec![make_hash(0xbb)], // Should be empty!
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidProofStructure { .. }));
    }

    #[test]
    fn test_invalid_genesis_format() {
        let super_proof = SuperProof {
            genesis_super_root: "invalid".to_string(), // Bad format!
            data_tree_index: 0,
            super_tree_size: 2,
            super_root: make_hash(0xbb),
            inclusion: vec![],
            consistency_to_origin: vec![make_hash(0xcc)],
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidHash(_)));
    }

    #[test]
    fn test_invalid_super_root_format() {
        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 2,
            super_root: "invalid".to_string(), // Bad format!
            inclusion: vec![],
            consistency_to_origin: vec![make_hash(0xcc)],
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidHash(_)));
    }

    #[test]
    fn test_invalid_consistency_path_element() {
        let super_proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 2,
            super_root: make_hash(0xbb),
            inclusion: vec![],
            consistency_to_origin: vec!["invalid".to_string()], // Bad format!
        };

        let result = verify_consistency_to_origin(&super_proof);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidHash(_)));
    }
}
