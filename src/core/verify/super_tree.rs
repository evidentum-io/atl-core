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
fn use_constant_time_eq(a: &Hash, b: &Hash) -> bool {
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
