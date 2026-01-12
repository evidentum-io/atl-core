//! RFC 6962 Merkle tree operations
//!
//! This module provides pure cryptographic functions for Merkle tree
//! computation and verification per RFC 6962.

mod crypto;
pub use crypto::{
    compute_genesis_leaf_hash, compute_leaf_hash, hash_children, Hash, GENESIS_DOMAIN, LEAF_PREFIX,
    NODE_PREFIX,
};

mod types;
pub use types::{Leaf, TreeHead};

mod consistency;
mod helpers;
mod inclusion;
mod root;

#[cfg(test)]
mod tests;

pub use consistency::{generate_consistency_proof, verify_consistency, ConsistencyProof};
pub use helpers::{compute_subtree_root, is_power_of_two, largest_power_of_2_less_than};
pub use inclusion::{generate_inclusion_proof, verify_inclusion, InclusionProof};
pub use root::compute_root;
