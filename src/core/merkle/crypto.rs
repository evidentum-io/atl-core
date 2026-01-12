//! Cryptographic hash functions for RFC 6962 Merkle trees
//!
//! This module provides the core hash functions for computing leaf and node
//! hashes according to RFC 6962 (Certificate Transparency).

use sha2::{Digest, Sha256};

/// A 32-byte SHA256 hash value
pub type Hash = [u8; 32];

/// Leaf prefix for RFC 6962 compliance
pub const LEAF_PREFIX: u8 = 0x00;

/// Node prefix for RFC 6962 compliance
pub const NODE_PREFIX: u8 = 0x01;

/// Domain separator for genesis leaf (tree chaining)
pub const GENESIS_DOMAIN: &[u8] = b"ATL-CHAIN-v1";

/// Compute leaf hash from payload and metadata hashes
///
/// Implements ATL-specific leaf hash construction:
/// ```text
/// leaf_hash = SHA256(0x00 || payload_hash || metadata_hash)
/// ```
///
/// # Arguments
/// * `payload_hash` - SHA256 of document payload
/// * `metadata_hash` - SHA256 of JCS-canonicalized metadata
///
/// # Returns
/// * 32-byte leaf hash
///
/// # Example
///
/// ```
/// use atl_core::core::merkle::compute_leaf_hash;
///
/// let payload = [0u8; 32];
/// let metadata = [1u8; 32];
/// let leaf_hash = compute_leaf_hash(&payload, &metadata);
/// assert_eq!(leaf_hash.len(), 32);
/// ```
#[must_use]
pub fn compute_leaf_hash(payload_hash: &Hash, metadata_hash: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(payload_hash);
    hasher.update(metadata_hash);
    hasher.finalize().into()
}

/// Compute hash of two child nodes
///
/// Implements RFC 6962 node hash:
/// ```text
/// node_hash = SHA256(0x01 || left_hash || right_hash)
/// ```
///
/// # Arguments
/// * `left` - Left child hash
/// * `right` - Right child hash
///
/// # Returns
/// * 32-byte node hash
///
/// # Example
///
/// ```
/// use atl_core::core::merkle::hash_children;
///
/// let left = [0u8; 32];
/// let right = [1u8; 32];
/// let node_hash = hash_children(&left, &right);
/// assert_eq!(node_hash.len(), 32);
/// ```
#[must_use]
pub fn hash_children(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Compute genesis leaf hash for tree chaining
///
/// Creates a cryptographic link from a new tree to its predecessor.
/// The genesis leaf is inserted as the first entry of the new tree.
///
/// # Formula
/// ```text
/// genesis_hash = SHA256(0x00 || "ATL-CHAIN-v1" || prev_root_hash || prev_tree_size_le)
/// ```
///
/// # Arguments
/// * `prev_root_hash` - Root hash of the closed (previous) tree
/// * `prev_tree_size` - Number of leaves in the closed tree
///
/// # Returns
/// 32-byte genesis leaf hash
///
/// # Example
///
/// ```
/// use atl_core::compute_genesis_leaf_hash;
///
/// let prev_root = [0xab; 32];
/// let prev_size = 1000u64;
/// let genesis = compute_genesis_leaf_hash(&prev_root, prev_size);
/// assert_eq!(genesis.len(), 32);
/// ```
#[must_use]
pub fn compute_genesis_leaf_hash(prev_root_hash: &Hash, prev_tree_size: u64) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(GENESIS_DOMAIN);
    hasher.update(prev_root_hash);
    hasher.update(prev_tree_size.to_le_bytes());
    hasher.finalize().into()
}
