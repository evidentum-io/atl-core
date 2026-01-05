//! Merkle root computation
//!
//! Implements RFC 6962 algorithm for computing Merkle tree root from leaf hashes.

use sha2::{Digest, Sha256};

use super::crypto::Hash;
use super::helpers::largest_power_of_2_less_than;

/// Compute root hash from a slice of leaf hashes
///
/// Uses the RFC 6962 algorithm for computing Merkle tree root.
/// The algorithm recursively splits the tree into left and right subtrees
/// at the largest power of 2 less than the tree size.
///
/// # Arguments
/// * `leaves` - Slice of leaf hashes in order
///
/// # Returns
/// * Root hash, or hash of empty string for empty tree
///
/// # Example
///
/// ```
/// use atl_core::core::merkle::{compute_root, hash_children};
///
/// // Single leaf
/// let leaves = vec![[42u8; 32]];
/// let root = compute_root(&leaves);
/// assert_eq!(root, leaves[0]);
///
/// // Two leaves
/// let leaves = vec![[0u8; 32], [1u8; 32]];
/// let root = compute_root(&leaves);
/// let expected = hash_children(&leaves[0], &leaves[1]);
/// assert_eq!(root, expected);
/// ```
#[must_use]
pub fn compute_root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => {
            // Empty tree: hash of empty string
            Sha256::digest([]).into()
        }
        1 => {
            // Single leaf is the root
            leaves[0]
        }
        n => {
            // Split at largest power of 2 less than n
            // SAFETY: `n` is usize (from slice.len()), so the result of
            // largest_power_of_2_less_than(n as u64) is always < n, hence fits in usize.
            // On 32-bit platforms, n <= usize::MAX (~4B), so k < n fits in usize.
            #[allow(clippy::cast_possible_truncation)]
            let k = largest_power_of_2_less_than(n as u64) as usize;
            let left_root = compute_root(&leaves[0..k]);
            let right_root = compute_root(&leaves[k..]);
            super::crypto::hash_children(&left_root, &right_root)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::merkle::hash_children;

    #[test]
    fn test_compute_root_empty() {
        let root = compute_root(&[]);
        let expected: Hash = Sha256::digest([]).into();
        assert_eq!(root, expected);
    }

    #[test]
    fn test_compute_root_single() {
        let leaf = [42u8; 32];
        let root = compute_root(&[leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_compute_root_two() {
        let leaves = [[0u8; 32], [1u8; 32]];
        let root = compute_root(&leaves);
        let expected = hash_children(&leaves[0], &leaves[1]);
        assert_eq!(root, expected);
    }
}
