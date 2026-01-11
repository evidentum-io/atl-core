//! Property-based tests for atl-core using proptest
//!
//! These tests verify invariants that must hold for all inputs.

use atl_core::core::jcs::{canonicalize, canonicalize_and_hash};
use atl_core::core::merkle::{
    compute_leaf_hash, compute_root, generate_consistency_proof, generate_inclusion_proof,
    verify_consistency, verify_inclusion, ConsistencyProof, Hash,
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
        prop_assert!(verify_inclusion(&leaves[0], &proof, &root).unwrap());
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

        #[allow(clippy::cast_possible_truncation)]
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

// ========== Consistency Proof Property Tests ==========

#[test]
fn prop_consistency_proof_roundtrip() {
    proptest!(ProptestConfig::with_cases(10000), |(
        from_size in 1u64..100,
        additional in 1u64..100,
    )| {
        let to_size = from_size + additional;

        let leaves: Vec<Hash> = (0..to_size)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        #[allow(clippy::cast_possible_truncation)]
        let old_root = compute_root(&leaves[..from_size as usize]);
        let new_root = compute_root(&leaves);

        #[allow(clippy::cast_possible_truncation)]
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_consistency_proof(from_size, to_size, get_node)?;
        // Note: verify_consistency returns AtlResult<bool>
        prop_assert!(
            verify_consistency(&proof, &old_root, &new_root).unwrap(),
            "Roundtrip failed for {} -> {}",
            from_size, to_size
        );
    });
}

#[test]
fn prop_consistency_proof_wrong_old_root_detected() {
    proptest!(ProptestConfig::with_cases(5000), |(
        from_size in 1u64..50,
        additional in 1u64..50,
        wrong_byte: u8,
    )| {
        let to_size = from_size + additional;

        let leaves: Vec<Hash> = (0..to_size)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        #[allow(clippy::cast_possible_truncation)]
        let old_root = compute_root(&leaves[..from_size as usize]);
        let new_root = compute_root(&leaves);

        // Create wrong old root
        let mut wrong_old_root = old_root;
        wrong_old_root[0] = wrong_old_root[0].wrapping_add(wrong_byte.saturating_add(1));

        #[allow(clippy::cast_possible_truncation)]
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_consistency_proof(from_size, to_size, get_node)?;

        // Must fail with wrong old root - note: returns AtlResult<bool>
        prop_assert!(
            !verify_consistency(&proof, &wrong_old_root, &new_root).unwrap(),
            "Should reject wrong old root for {} -> {}",
            from_size, to_size
        );
    });
}

#[test]
fn prop_consistency_proof_wrong_new_root_detected() {
    proptest!(ProptestConfig::with_cases(5000), |(
        from_size in 1u64..50,
        additional in 1u64..50,
        wrong_byte: u8,
    )| {
        let to_size = from_size + additional;

        let leaves: Vec<Hash> = (0..to_size)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        #[allow(clippy::cast_possible_truncation)]
        let old_root = compute_root(&leaves[..from_size as usize]);
        let new_root = compute_root(&leaves);

        // Create wrong new root
        let mut wrong_new_root = new_root;
        wrong_new_root[0] = wrong_new_root[0].wrapping_add(wrong_byte.saturating_add(1));

        #[allow(clippy::cast_possible_truncation)]
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_consistency_proof(from_size, to_size, get_node)?;

        // Must fail with wrong new root - note: returns AtlResult<bool>
        prop_assert!(
            !verify_consistency(&proof, &old_root, &wrong_new_root).unwrap(),
            "Should reject wrong new root for {} -> {}",
            from_size, to_size
        );
    });
}

#[test]
fn prop_consistency_proof_size_logarithmic() {
    proptest!(ProptestConfig::with_cases(5000), |(
        from_size in 1u64..1000,
        additional in 1u64..1000,
    )| {
        let to_size = from_size + additional;

        let leaves: Vec<Hash> = (0..to_size)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        #[allow(clippy::cast_possible_truncation)]
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_consistency_proof(from_size, to_size, get_node)?;

        // Proof size should be O(log n)
        // Upper bound: 2 * log2(to_size) + 1
        #[allow(clippy::cast_possible_truncation)]
        let max_size = if to_size <= 1 {
            1
        } else {
            ((64 - to_size.leading_zeros()) as usize) * 2 + 1
        };

        prop_assert!(
            proof.path.len() <= max_size,
            "Proof size {} exceeds max {} for {} -> {}",
            proof.path.len(), max_size, from_size, to_size
        );
    });
}

#[test]
fn prop_consistency_proof_tamper_detected() {
    proptest!(ProptestConfig::with_cases(5000), |(
        from_size in 2u64..50,
        additional in 1u64..50,
        tamper_idx: usize,
        tamper_byte: u8,
    )| {
        let to_size = from_size + additional;

        let leaves: Vec<Hash> = (0..to_size)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        #[allow(clippy::cast_possible_truncation)]
        let old_root = compute_root(&leaves[..from_size as usize]);
        let new_root = compute_root(&leaves);

        #[allow(clippy::cast_possible_truncation)]
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let mut proof = generate_consistency_proof(from_size, to_size, get_node)?;

        // Skip if proof is empty (can't tamper)
        if proof.path.is_empty() {
            return Ok(());
        }

        // Tamper with a hash
        let idx = tamper_idx % proof.path.len();
        proof.path[idx][0] = proof.path[idx][0].wrapping_add(tamper_byte.saturating_add(1));

        // Note: verify_consistency returns AtlResult<bool>
        prop_assert!(
            !verify_consistency(&proof, &old_root, &new_root).unwrap(),
            "Tampered proof should fail for {} -> {}",
            from_size, to_size
        );
    });
}

#[test]
fn prop_consistency_same_size_same_root() {
    proptest!(ProptestConfig::with_cases(5000), |(
        size in 1u64..100,
    )| {
        let leaves: Vec<Hash> = (0..size)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        let root = compute_root(&leaves);

        let proof = ConsistencyProof {
            from_size: size,
            to_size: size,
            path: vec![],
        };

        // Note: verify_consistency returns AtlResult<bool>
        prop_assert!(
            verify_consistency(&proof, &root, &root).unwrap(),
            "Same size/root should pass for size {}",
            size
        );
    });
}

#[test]
fn prop_consistency_same_size_different_root_fails() {
    proptest!(ProptestConfig::with_cases(5000), |(
        size in 1u64..100,
        diff_byte: u8,
    )| {
        let root1 = [0u8; 32];
        let mut root2 = root1;
        root2[0] = diff_byte.saturating_add(1);

        let proof = ConsistencyProof {
            from_size: size,
            to_size: size,
            path: vec![],
        };

        // Note: verify_consistency returns AtlResult<bool>
        prop_assert!(
            !verify_consistency(&proof, &root1, &root2).unwrap(),
            "Same size/different root should fail for size {}",
            size
        );
    });
}
