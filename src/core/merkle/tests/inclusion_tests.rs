//! Inclusion proof tests
//!
//! Tests for generating and verifying inclusion proofs.

use crate::core::merkle::helpers::{is_power_of_two, largest_power_of_2_less_than};
use crate::core::merkle::inclusion::{
    generate_inclusion_proof, use_constant_time_eq, verify_inclusion, InclusionProof,
};
use crate::core::merkle::{compute_root, Hash, TreeHead};
use crate::AtlError;

// Test constants
const ZERO_HASH: Hash = [0u8; 32];
const ONE_HASH: Hash = [1u8; 32];
const TWO_HASH: Hash = [2u8; 32];

#[test]
fn test_largest_power_of_2() {
    assert_eq!(largest_power_of_2_less_than(1), 0);
    assert_eq!(largest_power_of_2_less_than(2), 1);
    assert_eq!(largest_power_of_2_less_than(3), 2);
    assert_eq!(largest_power_of_2_less_than(4), 2);
    assert_eq!(largest_power_of_2_less_than(5), 4);
    assert_eq!(largest_power_of_2_less_than(7), 4);
    assert_eq!(largest_power_of_2_less_than(8), 4);
    assert_eq!(largest_power_of_2_less_than(9), 8);
    assert_eq!(largest_power_of_2_less_than(16), 8);
}

#[test]
fn test_inclusion_proof_single_leaf() {
    let leaves = [ZERO_HASH];
    let get_node = |level: u32, index: u64| -> Option<Hash> {
        if level == 0 && index == 0 {
            Some(leaves[0])
        } else {
            None
        }
    };

    let proof = generate_inclusion_proof(0, 1, get_node).unwrap();
    assert_eq!(proof.leaf_index, 0);
    assert_eq!(proof.tree_size, 1);
    assert!(proof.path.is_empty());

    let root = compute_root(&leaves);
    assert!(verify_inclusion(&leaves[0], &proof, &root).unwrap());
}

#[test]
fn test_inclusion_proof_two_leaves() {
    let leaves = [ZERO_HASH, ONE_HASH];
    let root = compute_root(&leaves);

    let get_node = |level: u32, index: u64| -> Option<Hash> {
        if level == 0 && (index as usize) < leaves.len() {
            Some(leaves[index as usize])
        } else {
            None
        }
    };

    // Proof for leaf 0
    let proof = generate_inclusion_proof(0, 2, get_node).unwrap();
    assert_eq!(proof.path.len(), 1);
    assert_eq!(proof.path[0], leaves[1]);
    assert!(verify_inclusion(&leaves[0], &proof, &root).unwrap());

    // Proof for leaf 1
    let proof = generate_inclusion_proof(1, 2, get_node).unwrap();
    assert_eq!(proof.path.len(), 1);
    assert_eq!(proof.path[0], leaves[0]);
    assert!(verify_inclusion(&leaves[1], &proof, &root).unwrap());
}

#[test]
fn test_inclusion_proof_three_leaves() {
    let leaves = [ZERO_HASH, ONE_HASH, TWO_HASH];
    let root = compute_root(&leaves);

    let get_node = |level: u32, index: u64| -> Option<Hash> {
        if level == 0 && (index as usize) < leaves.len() {
            Some(leaves[index as usize])
        } else {
            None
        }
    };

    // Proof for each leaf
    for i in 0..3 {
        let proof = generate_inclusion_proof(i, 3, get_node).unwrap();
        assert!(
            verify_inclusion(&leaves[i as usize], &proof, &root).unwrap(),
            "Failed verification for leaf {i}"
        );
    }
}

#[test]
fn test_inclusion_proof_invalid() {
    let leaves = [ZERO_HASH, ONE_HASH];
    let root = compute_root(&leaves);

    let proof = InclusionProof {
        leaf_index: 0,
        tree_size: 2,
        path: vec![[99u8; 32]], // Wrong sibling
    };

    assert!(!verify_inclusion(&leaves[0], &proof, &root).unwrap());
}

#[test]
fn test_inclusion_proof_invalid_index() {
    let get_node = |_: u32, _: u64| -> Option<Hash> { None };

    let result = generate_inclusion_proof(5, 3, get_node);
    assert!(matches!(result, Err(AtlError::LeafIndexOutOfBounds { .. })));
}

#[test]
fn test_inclusion_proof_zero_size() {
    let get_node = |_: u32, _: u64| -> Option<Hash> { None };

    let result = generate_inclusion_proof(0, 0, get_node);
    assert!(matches!(result, Err(AtlError::InvalidArgument(_))));
}

#[test]
fn test_constant_time_eq() {
    assert!(use_constant_time_eq(&ZERO_HASH, &ZERO_HASH));
    assert!(!use_constant_time_eq(&ZERO_HASH, &ONE_HASH));

    let hash1 = [0u8; 32];
    let mut hash2 = [0u8; 32];
    hash2[31] = 1;
    assert!(!use_constant_time_eq(&hash1, &hash2));
}

#[test]
fn test_tree_head_struct() {
    let tree_head = TreeHead { root_hash: ZERO_HASH, tree_size: 42 };
    assert_eq!(tree_head.root_hash, ZERO_HASH);
    assert_eq!(tree_head.tree_size, 42);
}

#[test]
fn test_proof_size_is_log_n() {
    // For tree of size 8, max proof length is 3 (log2(8))
    let leaves: Vec<Hash> = (0..8).map(|i| [i; 32]).collect();
    let get_node = |level: u32, index: u64| -> Option<Hash> {
        if level == 0 && (index as usize) < leaves.len() {
            Some(leaves[index as usize])
        } else {
            None
        }
    };

    for i in 0..8 {
        let proof = generate_inclusion_proof(i, 8, get_node).unwrap();
        assert!(
            proof.path.len() <= 3,
            "Proof for leaf {} has length {}, expected <= 3",
            i,
            proof.path.len()
        );
    }
}

#[test]
fn test_inclusion_proof_roundtrip_various_sizes() {
    for tree_size in 1..=10 {
        let leaves: Vec<Hash> = (0..tree_size).map(|i| [i as u8; 32]).collect();
        let root = compute_root(&leaves);

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        for (leaf_idx, leaf) in leaves.iter().enumerate() {
            let proof =
                generate_inclusion_proof(leaf_idx as u64, tree_size as u64, get_node).unwrap();
            assert!(
                verify_inclusion(leaf, &proof, &root).unwrap(),
                "Failed for tree_size={tree_size}, leaf_idx={leaf_idx}"
            );
        }
    }
}

#[test]
fn test_verify_inclusion_zero_tree_size() {
    let proof = InclusionProof { leaf_index: 0, tree_size: 0, path: vec![] };
    let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
    assert!(matches!(result, Err(AtlError::InvalidTreeSize { .. })));
}

#[test]
fn test_verify_inclusion_index_out_of_bounds() {
    let proof = InclusionProof { leaf_index: 5, tree_size: 3, path: vec![] };
    let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
    assert!(matches!(result, Err(AtlError::LeafIndexOutOfBounds { .. })));
}

#[test]
fn test_verify_inclusion_single_leaf_with_path_errors() {
    let proof = InclusionProof {
        leaf_index: 0,
        tree_size: 1,
        path: vec![[1u8; 32]], // Should be empty!
    };
    let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
    assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
}

#[test]
fn test_verify_inclusion_excessive_path_length() {
    // Tree size 4 -> max depth 2
    let proof = InclusionProof {
        leaf_index: 0,
        tree_size: 4,
        path: vec![ONE_HASH; 10], // Way too many
    };
    let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
    assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
}

#[test]
fn test_verify_inclusion_path_not_fully_consumed() {
    // Create a proof with extra hashes that won't be consumed
    let proof = InclusionProof {
        leaf_index: 0,
        tree_size: 2,
        path: vec![ONE_HASH, TWO_HASH], // Only 1 hash should be needed for tree size 2
    };
    let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
    assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
}

#[test]
fn test_verify_inclusion_boundary_path_length() {
    // Tree size 8 -> max depth 3
    // This tests the exact boundary
    let leaves: Vec<Hash> = (0..8).map(|i| [i; 32]).collect();
    let root = compute_root(&leaves);

    let get_node = |level: u32, index: u64| -> Option<Hash> {
        if level == 0 && (index as usize) < leaves.len() {
            Some(leaves[index as usize])
        } else {
            None
        }
    };

    let proof = generate_inclusion_proof(0, 8, get_node).unwrap();
    assert!(proof.path.len() <= 3); // Max depth for size 8

    let result = verify_inclusion(&leaves[0], &proof, &root).unwrap();
    assert!(result);
}

#[test]
fn test_max_depth_calculation() {
    // Test the max depth formula: ceil(log2(n)) = 64 - leading_zeros(n-1)
    // Tree size 1 -> max depth 0
    assert_eq!(64 - (1u64 - 1).leading_zeros(), 0);

    // Tree size 2 -> max depth 1
    assert_eq!((64 - (2u64 - 1).leading_zeros()) as usize, 1);

    // Tree size 3, 4 -> max depth 2
    assert_eq!((64 - (3u64 - 1).leading_zeros()) as usize, 2);
    assert_eq!((64 - (4u64 - 1).leading_zeros()) as usize, 2);

    // Tree size 5..8 -> max depth 3
    assert_eq!((64 - (5u64 - 1).leading_zeros()) as usize, 3);
    assert_eq!((64 - (7u64 - 1).leading_zeros()) as usize, 3);
    assert_eq!((64 - (8u64 - 1).leading_zeros()) as usize, 3);

    // Tree size 9 -> max depth 4
    assert_eq!((64 - (9u64 - 1).leading_zeros()) as usize, 4);

    // Tree size 1000 -> max depth 10
    assert_eq!((64 - (1000u64 - 1).leading_zeros()) as usize, 10);
}

#[test]
fn test_verify_inclusion_max_depth_boundaries() {
    // Test various tree sizes at power-of-2 boundaries
    for tree_size in [2u64, 3, 4, 5, 7, 8, 9, 15, 16, 17] {
        let leaves: Vec<Hash> = (0..tree_size).map(|i| [i as u8; 32]).collect();
        let root = compute_root(&leaves);

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let max_depth = (64 - (tree_size - 1).leading_zeros()) as usize;

        // Generate and verify valid proof
        let proof = generate_inclusion_proof(0, tree_size, get_node).unwrap();
        assert!(proof.path.len() <= max_depth);
        assert!(verify_inclusion(&leaves[0], &proof, &root).unwrap());

        // Create proof with excessive path length
        let mut excessive_path = proof.path.clone();
        excessive_path.extend(vec![ZERO_HASH; max_depth + 1]);
        let bad_proof = InclusionProof { leaf_index: 0, tree_size, path: excessive_path };
        let result = verify_inclusion(&leaves[0], &bad_proof, &root);
        assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
    }
}

#[test]
fn test_checked_arithmetic_no_overflow_normal_case() {
    // Normal case should not overflow
    let leaves: Vec<Hash> = (0..8).map(|i| [i; 32]).collect();

    let get_node = |level: u32, index: u64| -> Option<Hash> {
        if level == 0 && (index as usize) < leaves.len() {
            Some(leaves[index as usize])
        } else {
            None
        }
    };

    // Should succeed without overflow
    let proof = generate_inclusion_proof(3, 8, get_node);
    assert!(proof.is_ok());
}

#[test]
fn test_arithmetic_overflow_error_type() {
    // Verify the error type can be constructed
    let err = AtlError::ArithmeticOverflow { operation: "test operation" };
    assert!(err.to_string().contains("arithmetic overflow"));
    assert!(err.to_string().contains("test operation"));
}

// ========== Boundary and Overflow Tests ==========
// Category 1: verify_inclusion Error Cases

#[test]
fn test_verify_inclusion_error_zero_tree_size() {
    let proof = InclusionProof { leaf_index: 0, tree_size: 0, path: vec![] };
    let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
    assert!(matches!(result, Err(AtlError::InvalidTreeSize { size: 0, .. })));
}

#[test]
fn test_verify_inclusion_error_leaf_index_equals_tree_size() {
    let proof = InclusionProof {
        leaf_index: 5,
        tree_size: 5, // leaf_index must be < tree_size
        path: vec![],
    };
    let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
    assert!(matches!(result, Err(AtlError::LeafIndexOutOfBounds { index: 5, tree_size: 5 })));
}

#[test]
fn test_verify_inclusion_error_leaf_index_greater_than_tree_size() {
    let proof = InclusionProof { leaf_index: 100, tree_size: 10, path: vec![] };
    let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
    assert!(matches!(result, Err(AtlError::LeafIndexOutOfBounds { index: 100, tree_size: 10 })));
}

#[test]
fn test_verify_inclusion_error_single_leaf_nonempty_path() {
    let proof = InclusionProof { leaf_index: 0, tree_size: 1, path: vec![ONE_HASH] };
    let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
    assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
}

#[test]
fn test_verify_inclusion_error_excessive_path_length() {
    // tree_size = 8 -> max depth = 3
    let proof = InclusionProof {
        leaf_index: 0,
        tree_size: 8,
        path: vec![[0u8; 32]; 10], // Way more than 3
    };
    let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
    assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
}

#[test]
fn test_verify_inclusion_ok_false_wrong_hash() {
    // Valid structure but wrong sibling hash
    let proof = InclusionProof {
        leaf_index: 0,
        tree_size: 2,
        path: vec![[99u8; 32]], // Wrong hash
    };
    let result = verify_inclusion(&ZERO_HASH, &proof, &[42u8; 32]);
    // Should be Ok(false), not Err
    assert!(!result.unwrap());
}

// Category 4: Path Length Boundaries

#[test]
fn test_verify_inclusion_path_length_exact_for_power_of_2() {
    // tree_size = 2^n -> max depth = n
    for n in 1..=10 {
        let tree_size = 1u64 << n;
        let max_depth = n;

        // Path length = max_depth should be OK (structurally)
        let proof = InclusionProof { leaf_index: 0, tree_size, path: vec![[0u8; 32]; max_depth] };
        let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
        // Should not error on structure, may return Ok(false) due to wrong hashes
        assert!(result.is_ok(), "tree_size={tree_size} should accept path length {max_depth}");

        // Path length = max_depth + 1 should error
        let proof_too_long =
            InclusionProof { leaf_index: 0, tree_size, path: vec![[0u8; 32]; max_depth + 1] };
        let result_too_long = verify_inclusion(&ZERO_HASH, &proof_too_long, &ZERO_HASH);
        let exceeded_depth = max_depth + 1;
        assert!(
            result_too_long.is_err(),
            "tree_size={tree_size} should reject path length {exceeded_depth}"
        );
    }
}

#[test]
fn test_verify_inclusion_path_length_exact_for_non_power_of_2() {
    // tree_size = 5 -> ceil(log2(5)) = 3
    let proof = InclusionProof { leaf_index: 0, tree_size: 5, path: vec![[0u8; 32]; 3] };
    let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
    assert!(result.is_ok());

    // tree_size = 5, path length 4 should error
    let proof_too_long = InclusionProof { leaf_index: 0, tree_size: 5, path: vec![[0u8; 32]; 4] };
    let result_too_long = verify_inclusion(&ZERO_HASH, &proof_too_long, &ZERO_HASH);
    assert!(result_too_long.is_err());
}

// Category 3: Boundary Values

#[test]
fn test_verify_inclusion_boundary_max_u64_tree_size() {
    // Can't actually create such a tree, but verify error handling
    let proof = InclusionProof { leaf_index: 0, tree_size: u64::MAX, path: vec![] };
    // Should not panic - either Err or Ok(false) is acceptable
    let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
    assert!(result.is_err() || !result.unwrap(), "Should either error or return false");
}

#[test]
fn test_verify_inclusion_boundary_max_leaf_index() {
    let proof = InclusionProof { leaf_index: u64::MAX, tree_size: u64::MAX, path: vec![] };
    // Should not panic - with leaf_index == tree_size, must error
    let result = verify_inclusion(&ZERO_HASH, &proof, &ZERO_HASH);
    assert!(matches!(result, Err(AtlError::LeafIndexOutOfBounds { .. })));
}

// Category 5: Error Message Quality

#[test]
fn test_error_messages_are_descriptive() {
    // InvalidTreeSize
    let err = AtlError::InvalidTreeSize { size: 0, reason: "test reason" };
    let msg = err.to_string();
    assert!(msg.contains('0'), "Should contain size");
    assert!(msg.contains("test reason"), "Should contain reason");

    // ArithmeticOverflow
    let err = AtlError::ArithmeticOverflow { operation: "test op" };
    let msg = err.to_string();
    assert!(msg.contains("test op"), "Should contain operation");

    // InvalidProofStructure
    let err = AtlError::InvalidProofStructure { reason: "test structure".to_string() };
    let msg = err.to_string();
    assert!(msg.contains("test structure"), "Should contain reason");
}

#[test]
fn test_is_power_of_two() {
    // Zero case (different from std)
    assert!(!is_power_of_two(0));

    // Powers of two
    assert!(is_power_of_two(1));
    assert!(is_power_of_two(2));
    assert!(is_power_of_two(4));
    assert!(is_power_of_two(8));
    assert!(is_power_of_two(16));
    assert!(is_power_of_two(32));
    assert!(is_power_of_two(64));
    assert!(is_power_of_two(1 << 32));
    assert!(is_power_of_two(1 << 63));

    // Non-powers of two
    assert!(!is_power_of_two(3));
    assert!(!is_power_of_two(5));
    assert!(!is_power_of_two(6));
    assert!(!is_power_of_two(7));
    assert!(!is_power_of_two(9));
    assert!(!is_power_of_two(15));
    assert!(!is_power_of_two(17));
    assert!(!is_power_of_two(u64::MAX));
}
