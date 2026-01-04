//! Property-based tests for atl-core using proptest
//!
//! These tests verify invariants that must hold for all inputs.

use atl_core::core::jcs::{canonicalize, canonicalize_and_hash};
use atl_core::core::merkle::{
    compute_leaf_hash, compute_root, generate_inclusion_proof, verify_inclusion, Hash,
};
use proptest::prelude::*;

// ========== Property Tests ==========

#[test]
fn prop_leaf_hash_is_deterministic() {
    proptest!(|(payload: [u8; 32], metadata: [u8; 32])| {
        let hash1 = compute_leaf_hash(&payload, &metadata);
        let hash2 = compute_leaf_hash(&payload, &metadata);
        prop_assert_eq!(hash1, hash2);
    });
}

#[test]
fn prop_root_is_deterministic() {
    proptest!(|(leaves: Vec<[u8; 32]>)| {
        if leaves.is_empty() {
            return Ok(());
        }
        let root1 = compute_root(&leaves);
        let root2 = compute_root(&leaves);
        prop_assert_eq!(root1, root2);
    });
}

#[test]
fn prop_single_leaf_equals_root() {
    proptest!(|(leaf: [u8; 32])| {
        let root = compute_root(&[leaf]);
        prop_assert_eq!(root, leaf);
    });
}

#[test]
fn prop_valid_proof_always_verifies() {
    proptest!(|(leaves: Vec<[u8; 32]>)| {
        if leaves.is_empty() {
            return Ok(());
        }

        let tree_size = leaves.len() as u64;
        let leaf_index = 0u64;
        let root = compute_root(&leaves);

        #[allow(clippy::cast_possible_truncation)]
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_inclusion_proof(leaf_index, tree_size, get_node)?;
        prop_assert!(verify_inclusion(&leaves[0], &proof, &root));
    });
}

#[test]
fn prop_proof_size_is_logarithmic() {
    proptest!(|(leaves: Vec<[u8; 32]>)| {
        if leaves.is_empty() {
            return Ok(());
        }

        let tree_size = leaves.len() as u64;
        let leaf_index = 0u64;

        #[allow(clippy::cast_possible_truncation)]
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_inclusion_proof(leaf_index, tree_size, get_node)?;

        let max_proof_size = if tree_size <= 1 {
            0
        } else {
            (64 - tree_size.leading_zeros()) as usize
        };

        prop_assert!(
            proof.path.len() <= max_proof_size,
            "Proof size {} exceeds max {}",
            proof.path.len(),
            max_proof_size
        );
    });
}

#[test]
fn prop_jcs_is_idempotent() {
    proptest!(|(json_str: String)| {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&format!("{{\"key\":\"{json_str}\"}}")) {
            let once = canonicalize(&json);
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&once) {
                let twice = canonicalize(&parsed);
                prop_assert_eq!(once, twice);
            }
        }
    });
}

#[test]
fn prop_jcs_hash_is_deterministic() {
    proptest!(|(value: i64)| {
        let json = serde_json::json!({"value": value});
        let hash1 = canonicalize_and_hash(&json);
        let hash2 = canonicalize_and_hash(&json);
        prop_assert_eq!(hash1, hash2);
    });
}

#[test]
fn prop_jcs_no_whitespace() {
    proptest!(|(value: i64)| {
        let json = serde_json::json!({"value": value});
        let canonical = canonicalize(&json);
        prop_assert!(!canonical.contains(' '));
        prop_assert!(!canonical.contains('\n'));
        prop_assert!(!canonical.contains('\t'));
    });
}

#[test]
fn prop_hash_output_is_32_bytes() {
    proptest!(|(payload: [u8; 32], metadata: [u8; 32])| {
        let hash = compute_leaf_hash(&payload, &metadata);
        prop_assert_eq!(hash.len(), 32);
    });
}

#[test]
fn prop_root_output_is_32_bytes() {
    proptest!(|(leaves: Vec<[u8; 32]>)| {
        if leaves.is_empty() {
            return Ok(());
        }
        let root = compute_root(&leaves);
        prop_assert_eq!(root.len(), 32);
    });
}

#[test]
fn prop_empty_tree_has_deterministic_root() {
    use sha2::{Digest, Sha256};

    let root1 = compute_root(&[]);
    let root2 = compute_root(&[]);
    let expected: Hash = Sha256::digest([]).into();

    assert_eq!(root1, root2);
    assert_eq!(root1, expected);
}
