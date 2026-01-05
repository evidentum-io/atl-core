//! RFC 6962 Merkle tree operations
//!
//! This module provides pure cryptographic functions for Merkle tree
//! computation and verification per RFC 6962.

mod crypto;
pub use crypto::{Hash, LEAF_PREFIX, NODE_PREFIX, compute_leaf_hash, hash_children};

mod types;
pub use types::{Leaf, TreeHead};

mod consistency;
mod helpers;
mod inclusion;
mod root;

#[cfg(test)]
mod tests;

pub use consistency::{ConsistencyProof, generate_consistency_proof, verify_consistency};
pub use helpers::{compute_subtree_root, is_power_of_two, largest_power_of_2_less_than};
pub use inclusion::{InclusionProof, generate_inclusion_proof, verify_inclusion};
pub use root::compute_root;
