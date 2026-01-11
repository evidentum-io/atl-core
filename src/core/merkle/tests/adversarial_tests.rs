//! Adversarial input tests
//!
//! Tests for detecting malicious or crafted inputs that attempt to exploit
//! vulnerabilities in proof verification.

use crate::core::merkle::consistency::{
    generate_consistency_proof, verify_consistency, ConsistencyProof,
};
use crate::core::merkle::{compute_root, Hash};
use crate::AtlError;

#[test]
fn test_adversarial_arbitrary_hashes_rejected() {
    // Simplified impl would accept: power-of-2 with first hash == old_root
    // + reasonable length

    let from_size = 4u64; // Power of 2
    let to_size = 8u64;

    // Correct roots
    let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
    let old_root = compute_root(&leaves[..4]);
    let new_root = compute_root(&leaves);

    // Malicious proof: correct first hash (old_root) but wrong other hashes
    let malicious_proof = ConsistencyProof {
        from_size,
        to_size,
        path: vec![
            old_root,   // First hash matches old_root (bypasses simplified check)
            [0xde; 32], // Random hash
            [0xad; 32], // Random hash
        ],
    };

    // RFC 9162 implementation must reject this - note: returns AtlResult<bool>
    assert!(
        !verify_consistency(&malicious_proof, &old_root, &new_root).unwrap(),
        "Should reject proof with arbitrary hashes"
    );
}

#[test]
fn test_adversarial_correct_length_wrong_content() {
    // Generate a valid proof, then replace all hashes with random data
    // while keeping length "reasonable"

    let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
    let old_root = compute_root(&leaves[..4]);
    let new_root = compute_root(&leaves);

    let get_node = |level: u32, index: u64| -> Option<Hash> {
        if level == 0 && (index as usize) < leaves.len() {
            Some(leaves[index as usize])
        } else {
            None
        }
    };

    let valid_proof = generate_consistency_proof(4, 8, get_node).unwrap();

    // Create malicious proof with same length but random content
    let malicious_proof = ConsistencyProof {
        from_size: 4,
        to_size: 8,
        path: valid_proof.path.iter().map(|_| [0xba; 32]).collect(),
    };

    // Note: verify_consistency returns AtlResult<bool>
    assert!(
        !verify_consistency(&malicious_proof, &old_root, &new_root).unwrap(),
        "Should reject proof with random content"
    );
}

#[test]
fn test_adversarial_replay_different_tree() {
    // Generate proof for one tree, try to use it on different tree

    // Tree A: leaves 0..8
    let leaves_a: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
    let _old_root_a = compute_root(&leaves_a[..4]);
    let _new_root_a = compute_root(&leaves_a);

    let get_node_a = |level: u32, index: u64| -> Option<Hash> {
        if level == 0 && (index as usize) < leaves_a.len() {
            Some(leaves_a[index as usize])
        } else {
            None
        }
    };

    let proof_a = generate_consistency_proof(4, 8, get_node_a).unwrap();

    // Tree B: different leaves (same sizes)
    let leaves_b: Vec<Hash> = (100..108).map(|i| [i as u8; 32]).collect();
    let old_root_b = compute_root(&leaves_b[..4]);
    let new_root_b = compute_root(&leaves_b);

    // Try to use proof from tree A on tree B - note: returns AtlResult<bool>
    assert!(
        !verify_consistency(&proof_a, &old_root_b, &new_root_b).unwrap(),
        "Should reject proof from different tree"
    );
}

#[test]
fn test_adversarial_replay_different_sizes() {
    // Generate proof for (4 -> 8), try to use it for (3 -> 7)

    let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();

    let get_node = |level: u32, index: u64| -> Option<Hash> {
        if level == 0 && (index as usize) < leaves.len() {
            Some(leaves[index as usize])
        } else {
            None
        }
    };

    let proof_4_8 = generate_consistency_proof(4, 8, get_node).unwrap();

    // Compute roots for different sizes
    let old_root_3 = compute_root(&leaves[..3]);
    let new_root_7 = compute_root(&leaves[..7]);

    // Modify proof to claim different sizes
    let replayed_proof = ConsistencyProof { from_size: 3, to_size: 7, path: proof_4_8.path };

    // Note: verify_consistency returns AtlResult<bool>
    assert!(
        !verify_consistency(&replayed_proof, &old_root_3, &new_root_7).unwrap(),
        "Should reject proof with wrong sizes"
    );
}

#[test]
#[allow(clippy::cast_possible_truncation)]
fn test_adversarial_boundary_sizes() {
    // Test sizes that might cause edge cases in bit operations

    let boundary_cases = [
        (1, 2),     // Minimum non-trivial
        (63, 64),   // Near power of 2
        (64, 65),   // Just past power of 2
        (127, 128), // Near power of 2
        (128, 129), // Just past power of 2
        (255, 256), // Near power of 2
        (256, 257), // Just past power of 2
    ];

    for (from, to) in boundary_cases {
        let leaves: Vec<Hash> = (0u64..to)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        let old_root = compute_root(&leaves[..from as usize]);
        let new_root = compute_root(&leaves);

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_consistency_proof(from, to, get_node).unwrap();

        // Valid proof should pass - note: returns AtlResult<bool>
        assert!(
            verify_consistency(&proof, &old_root, &new_root).unwrap(),
            "Valid proof failed for {from} -> {to}"
        );

        // Tampered proof should fail
        if !proof.path.is_empty() {
            let mut tampered = proof.clone();
            tampered.path[0][0] ^= 0xff;
            // Note: verify_consistency returns AtlResult<bool>
            assert!(
                !verify_consistency(&tampered, &old_root, &new_root).unwrap(),
                "Tampered proof should fail for {from} -> {to}"
            );
        }
    }
}

#[test]
#[allow(clippy::cast_possible_truncation)]
fn test_adversarial_all_ones_size() {
    // Sizes like 0b111111 (all ones in binary) stress bit manipulation

    let all_ones_cases = [
        (3, 7),   // 0b11 -> 0b111
        (7, 15),  // 0b111 -> 0b1111
        (15, 31), // 0b1111 -> 0b11111
        (31, 63), // 0b11111 -> 0b111111
    ];

    for (from, to) in all_ones_cases {
        let leaves: Vec<Hash> = (0u64..to)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        let old_root = compute_root(&leaves[..from as usize]);
        let new_root = compute_root(&leaves);

        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        let proof = generate_consistency_proof(from, to, get_node).unwrap();

        // Note: verify_consistency returns AtlResult<bool>
        assert!(
            verify_consistency(&proof, &old_root, &new_root).unwrap(),
            "All-ones boundary failed for {from} -> {to}"
        );
    }
}

#[test]
fn test_adversarial_zero_from_size_with_path() {
    // from_size = 0 with non-empty path returns Err(InvalidProofStructure)
    // NOTE: Spec incorrectly said InvalidTreeSize, but actual behavior is InvalidProofStructure

    let proof = ConsistencyProof {
        from_size: 0,
        to_size: 8,
        path: vec![[0xaa; 32], [0xbb; 32]], // Non-empty path
    };

    // With Safe Merkle API, from_size == 0 with non-empty path returns InvalidProofStructure
    let result = verify_consistency(&proof, &[0u8; 32], &[0u8; 32]);
    // Should return Err(InvalidProofStructure), not InvalidTreeSize
    assert!(matches!(result, Err(AtlError::InvalidProofStructure { .. })));
}

#[test]
fn test_adversarial_very_long_proof() {
    // Proof way longer than O(log n) should be rejected

    let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
    let old_root = compute_root(&leaves[..4]);
    let new_root = compute_root(&leaves);

    let malicious_proof = ConsistencyProof {
        from_size: 4,
        to_size: 8,
        path: vec![[0xaa; 32]; 100], // Way too many hashes
    };

    // Very long proof should be rejected (either Ok(false) or Err)
    let result = verify_consistency(&malicious_proof, &old_root, &new_root);
    assert!(
        matches!(result, Ok(false) | Err(AtlError::InvalidProofStructure { .. })),
        "Should reject overly long proof"
    );
}

#[test]
fn test_adversarial_duplicate_hashes() {
    // Proof with all same hashes

    let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
    let old_root = compute_root(&leaves[..4]);
    let new_root = compute_root(&leaves);

    let get_node = |level: u32, index: u64| -> Option<Hash> {
        if level == 0 && (index as usize) < leaves.len() {
            Some(leaves[index as usize])
        } else {
            None
        }
    };

    let valid_proof = generate_consistency_proof(4, 8, get_node).unwrap();

    // Replace all hashes with the same value
    let malicious_proof =
        ConsistencyProof { from_size: 4, to_size: 8, path: vec![old_root; valid_proof.path.len()] };

    // Note: verify_consistency returns AtlResult<bool>
    assert!(
        !verify_consistency(&malicious_proof, &old_root, &new_root).unwrap(),
        "Should reject proof with all duplicate hashes"
    );
}

#[test]
fn test_regression_simplified_impl_vulnerability() {
    // This test documents the exact vulnerability that existed in the
    // simplified implementation and ensures it's fixed.

    // The simplified impl (lines 670-691) did:
    // 1. Check path not empty
    // 2. If power-of-2 from_size: check path[0] == old_root
    // 3. Check path.len() <= 2 * log2(to_size)
    // 4. Return true (!)

    // Attack: For from_size=4 (power of 2), to_size=8
    // Construct proof where path[0] = old_root but rest is garbage

    let from_size = 4u64;
    let to_size = 8u64;

    let leaves: Vec<Hash> = (0..8).map(|i| [i as u8; 32]).collect();
    let old_root = compute_root(&leaves[..4]);
    let new_root = compute_root(&leaves);

    // This proof would have passed the old simplified check:
    // - path not empty: yes
    // - from_size is power of 2: yes, and path[0] == old_root: yes
    // - path.len() (3) <= 2 * log2(8) = 6: yes
    // - return true!
    let attack_proof = ConsistencyProof {
        from_size,
        to_size,
        path: vec![
            old_root,   // Passes simplified check
            [0x00; 32], // Garbage
            [0x00; 32], // Garbage
        ],
    };

    // RFC 9162 implementation MUST reject this - note: returns AtlResult<bool>
    assert!(
        !verify_consistency(&attack_proof, &old_root, &new_root).unwrap(),
        "CRITICAL: Simplified implementation vulnerability not fixed!"
    );
}
