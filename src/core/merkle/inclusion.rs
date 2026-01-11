//! Merkle inclusion proof generation and verification
//!
//! This module provides functions for generating and verifying inclusion proofs
//! per RFC 6962 (Certificate Transparency).
//!
//! An inclusion proof demonstrates that a specific leaf exists at a given index
//! in a tree of known size by providing the minimal set of sibling hashes needed
//! to reconstruct the root.

use crate::{AtlError, AtlResult};

use super::crypto::{hash_children, Hash};
use super::helpers::{compute_subtree_root, largest_power_of_2_less_than};

/// Merkle inclusion proof
///
/// Proves that a specific leaf exists at a given index in a tree of known size.
/// The proof consists of sibling hashes along the path from leaf to root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Index of the leaf in the tree (0-based)
    pub leaf_index: u64,
    /// Size of the tree when proof was generated
    pub tree_size: u64,
    /// Sibling hashes along the path to root (ordered from leaf to root)
    pub path: Vec<Hash>,
}

/// Generate an inclusion proof for a leaf
///
/// Generates a proof that the leaf at `leaf_index` is included in a tree of size
/// `tree_size`. The proof is a vector of sibling hashes from leaf to root.
///
/// # Arguments
/// * `leaf_index` - Index of the leaf (0-based)
/// * `tree_size` - Size of the tree
/// * `get_node` - Callback to retrieve node hashes: `(level, index) -> Option<Hash>`
///   Level 0 is leaves, higher levels are internal nodes
///
/// # Returns
/// * Inclusion proof with path hashes in leaf-to-root order
///
/// # Errors
/// * `InvalidArgument` - `tree_size` is 0
/// * `LeafIndexOutOfBounds` - `leaf_index` >= `tree_size`
/// * `MissingNode` - required node not found in storage
/// * `ArithmeticOverflow` - tree size exceeds implementation limits
///
/// # Example
///
/// ```
/// use atl_core::core::merkle::{generate_inclusion_proof, Hash};
///
/// let leaves = vec![[0u8; 32], [1u8; 32]];
///
/// let get_node = |level: u32, index: u64| -> Option<Hash> {
///     if level == 0 && (index as usize) < leaves.len() {
///         Some(leaves[index as usize])
///     } else {
///         None
///     }
/// };
///
/// let proof = generate_inclusion_proof(0, 2, get_node).unwrap();
/// assert_eq!(proof.leaf_index, 0);
/// assert_eq!(proof.tree_size, 2);
/// assert_eq!(proof.path.len(), 1); // One sibling (leaf 1)
/// ```
pub fn generate_inclusion_proof<F>(
    leaf_index: u64,
    tree_size: u64,
    get_node: F,
) -> Result<InclusionProof, AtlError>
where
    F: Fn(u32, u64) -> Option<Hash>,
{
    // Validate inputs
    if tree_size == 0 {
        return Err(AtlError::InvalidArgument(format!("invalid tree size: {tree_size}")));
    }
    if leaf_index >= tree_size {
        return Err(AtlError::LeafIndexOutOfBounds { index: leaf_index, tree_size });
    }

    let mut path = Vec::new();
    let mut index = leaf_index;
    let mut size = tree_size;
    let mut base_offset = 0u64; // Track absolute position in tree

    // Single leaf tree has empty proof
    if size == 1 {
        return Ok(InclusionProof { leaf_index, tree_size, path });
    }

    // Traverse from leaf to root, collecting sibling hashes
    while size > 1 {
        let k = largest_power_of_2_less_than(size);

        if index < k {
            // We're in left subtree, need right subtree hash
            let subtree_offset =
                base_offset.checked_add(k).ok_or(AtlError::ArithmeticOverflow {
                    operation: "inclusion proof: base_offset + k",
                })?;
            let subtree_size = size
                .checked_sub(k)
                .ok_or(AtlError::ArithmeticOverflow { operation: "inclusion proof: size - k" })?;
            let sibling_hash = compute_subtree_root(subtree_offset, subtree_size, &get_node)?;
            path.push(sibling_hash);
            size = k;
            // base_offset stays the same (left subtree starts at same position)
        } else {
            // We're in right subtree, need left subtree hash
            let sibling_hash = compute_subtree_root(base_offset, k, &get_node)?;
            path.push(sibling_hash);
            index = index
                .checked_sub(k)
                .ok_or(AtlError::ArithmeticOverflow { operation: "inclusion proof: index - k" })?;
            size = size.checked_sub(k).ok_or(AtlError::ArithmeticOverflow {
                operation: "inclusion proof: size - k (right)",
            })?;
            base_offset = base_offset.checked_add(k).ok_or(AtlError::ArithmeticOverflow {
                operation: "inclusion proof: base_offset + k (right)",
            })?;
        }
    }

    // RFC 6962 requires siblings in leaf-to-root order for verification
    // Our traversal collects them root-to-leaf, so reverse
    path.reverse();

    Ok(InclusionProof { leaf_index, tree_size, path })
}

/// Verify an inclusion proof
///
/// Verifies that a leaf with given hash exists at the claimed index in a tree
/// with the given root hash.
///
/// # Arguments
/// * `leaf_hash` - Hash of the leaf being proved
/// * `proof` - The inclusion proof
/// * `expected_root` - Expected root hash
///
/// # Returns
/// * `Ok(true)` - proof is mathematically valid
/// * `Ok(false)` - proof is mathematically invalid (hash mismatch)
/// * `Err(InvalidTreeSize)` - `tree_size` is 0
/// * `Err(LeafIndexOutOfBounds)` - `leaf_index` >= `tree_size`
/// * `Err(InvalidProofStructure)` - path length doesn't match tree geometry
///
/// # Errors
///
/// Returns error if the proof structure is invalid and cannot be verified.
/// Returns `Ok(false)` if the proof structure is valid but doesn't prove inclusion.
///
/// # Example
///
/// ```
/// use atl_core::core::merkle::{compute_root, generate_inclusion_proof, verify_inclusion, Hash};
///
/// let leaves = vec![[0u8; 32], [1u8; 32]];
/// let root = compute_root(&leaves);
///
/// let get_node = |level: u32, index: u64| -> Option<Hash> {
///     if level == 0 && (index as usize) < leaves.len() {
///         Some(leaves[index as usize])
///     } else {
///         None
///     }
/// };
///
/// let proof = generate_inclusion_proof(0, 2, get_node).unwrap();
/// assert!(verify_inclusion(&leaves[0], &proof, &root).unwrap());
/// ```
pub fn verify_inclusion(
    leaf_hash: &Hash,
    proof: &InclusionProof,
    expected_root: &Hash,
) -> AtlResult<bool> {
    // Handle empty tree
    if proof.tree_size == 0 {
        return Err(AtlError::InvalidTreeSize { size: 0, reason: "tree cannot be empty" });
    }

    // Validate leaf index
    if proof.leaf_index >= proof.tree_size {
        return Err(AtlError::LeafIndexOutOfBounds {
            index: proof.leaf_index,
            tree_size: proof.tree_size,
        });
    }

    // Single leaf tree
    if proof.tree_size == 1 {
        // Single-leaf tree with non-empty path is structurally invalid
        if !proof.path.is_empty() {
            return Err(AtlError::InvalidProofStructure {
                reason: format!(
                    "single-leaf tree (size 1) must have empty proof path, got {} hashes",
                    proof.path.len()
                ),
            });
        }
        return Ok(leaf_hash == expected_root);
    }

    // INVARIANT 4: Path length bounded by tree depth
    // For a tree of size n > 1, maximum depth is ceil(log2(n)) = 64 - leading_zeros(n-1)
    // SAFETY: leading_zeros() returns 0..=64, so (64 - leading_zeros) is at most 64, fits in usize.
    #[allow(clippy::cast_possible_truncation)]
    let max_depth = (64 - (proof.tree_size - 1).leading_zeros()) as usize;
    if proof.path.len() > max_depth {
        return Err(AtlError::InvalidProofStructure {
            reason: format!(
                "path length {} exceeds maximum depth {} for tree size {}",
                proof.path.len(),
                max_depth,
                proof.tree_size
            ),
        });
    }

    // Reconstruct root from leaf to root using proof path
    // Path is in leaf-to-root order (siblings from bottom up)
    let mut hash = *leaf_hash;
    let mut proof_idx = 0;

    // Build list of (index, size, is_left) for each level
    let mut levels = Vec::new();
    let mut idx = proof.leaf_index;
    let mut sz = proof.tree_size;

    while sz > 1 {
        let k = largest_power_of_2_less_than(sz);
        let is_left = idx < k;
        levels.push((idx, sz, is_left));

        if is_left {
            sz = k;
        } else {
            idx = idx
                .checked_sub(k)
                .ok_or(AtlError::ArithmeticOverflow { operation: "verify inclusion: idx - k" })?;
            sz = sz
                .checked_sub(k)
                .ok_or(AtlError::ArithmeticOverflow { operation: "verify inclusion: sz - k" })?;
        }
    }

    // Process levels from leaf to root
    for i in (0..levels.len()).rev() {
        if proof_idx >= proof.path.len() {
            return Ok(false);
        }

        let (_idx, _sz, is_left) = levels[i];

        if is_left {
            hash = hash_children(&hash, &proof.path[proof_idx]);
        } else {
            hash = hash_children(&proof.path[proof_idx], &hash);
        }
        proof_idx += 1;
    }

    // INVARIANT 5: All path hashes must be consumed
    if proof_idx != proof.path.len() {
        return Err(AtlError::InvalidProofStructure {
            reason: format!(
                "proof path not fully consumed: used {} of {} hashes",
                proof_idx,
                proof.path.len()
            ),
        });
    }

    // Constant-time comparison to prevent timing attacks
    Ok(use_constant_time_eq(&hash, expected_root))
}

/// Constant-time equality comparison for hashes
///
/// Uses constant-time comparison to prevent timing side-channel attacks
/// when verifying proofs.
pub fn use_constant_time_eq(a: &Hash, b: &Hash) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
