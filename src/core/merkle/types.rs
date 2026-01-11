//! Merkle tree data types
//!
//! Core data structures for ATL Merkle tree implementation.

use super::crypto::{compute_leaf_hash, Hash};

/// Represents a leaf in the Merkle tree
///
/// An ATL leaf consists of two hashes:
/// - `payload_hash`: SHA256 of the document
/// - `metadata_hash`: SHA256 of JCS-canonicalized metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    /// SHA256 of the document payload
    pub payload_hash: Hash,
    /// SHA256 of the JCS-canonicalized metadata
    pub metadata_hash: Hash,
}

impl Leaf {
    /// Create a new leaf from payload and metadata hashes
    #[must_use]
    pub const fn new(payload_hash: Hash, metadata_hash: Hash) -> Self {
        Self { payload_hash, metadata_hash }
    }

    /// Compute the leaf hash: SHA256(0x00 || `payload_hash` || `metadata_hash`)
    ///
    /// This follows RFC 6962 with ATL-specific leaf construction.
    #[must_use]
    pub fn hash(&self) -> Hash {
        compute_leaf_hash(&self.payload_hash, &self.metadata_hash)
    }
}

/// Tree head (root hash + tree size)
///
/// Represents a snapshot of the tree at a specific size.
/// The root hash commits to all leaves up to that size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeHead {
    /// Current root hash
    pub root_hash: Hash,
    /// Number of leaves in tree
    pub tree_size: u64,
}
