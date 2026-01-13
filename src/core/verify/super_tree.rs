//! Super-Tree verification functions
//!
//! This module provides verification for Super-Tree proofs per ATL Protocol v2.0.
//! The Super-Tree is a Merkle tree where each leaf is a Data Tree root hash.
//!
//! ## Mandatory `super_proof`
//!
//! All verification functions require valid `super_proof`.

use crate::core::merkle::{verify_inclusion, Hash, InclusionProof};
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
