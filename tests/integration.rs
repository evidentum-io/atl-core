//! Integration tests for atl-core
//!
//! These tests verify end-to-end workflows using only the public API.

use atl_core::core::checkpoint::{compute_key_id, Checkpoint, CheckpointJson, CheckpointVerifier};
use atl_core::core::jcs::{canonicalize, canonicalize_and_hash};
use atl_core::core::merkle::{
    compute_leaf_hash, compute_root, generate_inclusion_proof, verify_inclusion, Hash,
};
use atl_core::core::receipt::{format_hash, format_signature, Receipt, RECEIPT_SPEC_VERSION};
use atl_core::AtlError;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::json;
use uuid::Uuid;

// ========== Helper Functions ==========

/// Generate a test Ed25519 key pair
fn generate_test_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Create a minimal valid checkpoint with signature
fn create_test_checkpoint(signing_key: &SigningKey) -> Checkpoint {
    let origin = [1u8; 32];
    let tree_size = 1u64;
    let timestamp = 1_704_067_200_000_000_000u64;
    let root_hash = [2u8; 32];

    // Create wire format blob
    let mut blob = [0u8; 98];
    blob[0..18].copy_from_slice(b"ATL-Protocol-v1-CP");
    blob[18..50].copy_from_slice(&origin);
    blob[50..58].copy_from_slice(&tree_size.to_le_bytes());
    blob[58..66].copy_from_slice(&timestamp.to_le_bytes());
    blob[66..98].copy_from_slice(&root_hash);

    // Sign the blob
    let signature = signing_key.sign(&blob);
    let signature_bytes: [u8; 64] = signature.to_bytes();

    // Compute key_id
    let verifying_key = signing_key.verifying_key();
    let key_id = compute_key_id(&verifying_key.to_bytes());

    Checkpoint::new(origin, tree_size, timestamp, root_hash, signature_bytes, key_id)
}

/// Create a test receipt with valid structure
fn create_test_receipt(signing_key: &SigningKey) -> Receipt {
    let entry_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
    let payload_hash = [0xaa; 32];
    let metadata = json!({"filename": "test.pdf"});
    let metadata_hash = canonicalize_and_hash(&metadata);

    // Compute leaf hash
    let leaf_hash = compute_leaf_hash(&payload_hash, &metadata_hash);

    // Single leaf tree
    let root_hash = leaf_hash;

    // Create checkpoint with correct root_hash
    let origin = [1u8; 32];
    let tree_size = 1u64;
    let timestamp = 1_704_067_200_000_000_000u64;

    // Create wire format blob with CORRECT root_hash
    let mut blob = [0u8; 98];
    blob[0..18].copy_from_slice(b"ATL-Protocol-v1-CP");
    blob[18..50].copy_from_slice(&origin);
    blob[50..58].copy_from_slice(&tree_size.to_le_bytes());
    blob[58..66].copy_from_slice(&timestamp.to_le_bytes());
    blob[66..98].copy_from_slice(&root_hash);

    // Sign the blob
    let signature = signing_key.sign(&blob);
    let signature_bytes: [u8; 64] = signature.to_bytes();

    // Compute key_id
    let verifying_key = signing_key.verifying_key();
    let key_id = compute_key_id(&verifying_key.to_bytes());

    let checkpoint =
        Checkpoint::new(origin, tree_size, timestamp, root_hash, signature_bytes, key_id);

    use atl_core::core::jcs::canonicalize_and_hash;
    let metadata_hash = format_hash(&canonicalize_and_hash(&metadata));

    Receipt {
        spec_version: RECEIPT_SPEC_VERSION.to_string(),
        upgrade_url: None,
        entry: atl_core::core::receipt::ReceiptEntry {
            id: entry_id,
            payload_hash: format_hash(&payload_hash),
            metadata_hash,
            metadata,
        },
        proof: atl_core::core::receipt::ReceiptProof {
            tree_size: 1,
            root_hash: format_hash(&root_hash),
            inclusion_path: vec![],
            leaf_index: 0,
            checkpoint: CheckpointJson {
                origin: format_hash(&checkpoint.origin),
                tree_size: checkpoint.tree_size,
                root_hash: format_hash(&checkpoint.root_hash),
                timestamp: checkpoint.timestamp,
                signature: format_signature(&checkpoint.signature),
                key_id: format_hash(&checkpoint.key_id),
            },
            consistency_proof: None,
        },
        super_proof: Some(atl_core::core::receipt::SuperProof {
            genesis_super_root: format_hash(&root_hash),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: format_hash(&root_hash),
            inclusion: vec![],
            consistency_to_origin: vec![],
        }),
        anchors: vec![],
    }
}

// ========== Integration Tests ==========

#[test]
fn test_end_to_end_single_entry() {
    // Generate keypair
    let (signing_key, verifying_key) = generate_test_keypair();

    // Create test data
    let payload_hash = [0xaa; 32];
    let metadata = json!({"filename": "document.pdf", "size": 1024});

    // Step 1: Canonicalize metadata
    let metadata_canonical = canonicalize(&metadata);
    assert!(!metadata_canonical.is_empty());

    // Step 2: Hash metadata
    let metadata_hash = canonicalize_and_hash(&metadata);
    assert_eq!(metadata_hash.len(), 32);

    // Step 3: Compute leaf hash
    let leaf_hash = compute_leaf_hash(&payload_hash, &metadata_hash);

    // Step 4: Compute root (single leaf)
    let root = compute_root(&[leaf_hash]);
    assert_eq!(root, leaf_hash); // Single leaf is the root

    // Step 5: Create checkpoint
    let checkpoint = create_test_checkpoint(&signing_key);

    // Step 6: Verify checkpoint signature
    let verifier = CheckpointVerifier::from_bytes(&verifying_key.to_bytes()).unwrap();
    checkpoint.verify(&verifier).unwrap();
}

#[test]
fn test_end_to_end_multiple_entries() {
    // Create multiple entries
    let entries = [
        ([0xaa; 32], json!({"filename": "doc1.pdf"})),
        ([0xbb; 32], json!({"filename": "doc2.pdf"})),
        ([0xcc; 32], json!({"filename": "doc3.pdf"})),
    ];

    // Compute leaf hashes
    let leaf_hashes: Vec<Hash> = entries
        .iter()
        .map(|(payload, metadata)| {
            let metadata_hash = canonicalize_and_hash(metadata);
            compute_leaf_hash(payload, &metadata_hash)
        })
        .collect();

    // Compute root
    let root = compute_root(&leaf_hashes);

    // Generate inclusion proof for second entry
    #[allow(clippy::cast_possible_truncation)]
    let get_node = |level: u32, index: u64| -> Option<Hash> {
        if level == 0 && (index as usize) < leaf_hashes.len() {
            Some(leaf_hashes[index as usize])
        } else {
            None
        }
    };

    let proof = generate_inclusion_proof(1, 3, get_node).unwrap();

    // Verify inclusion proof
    assert!(verify_inclusion(&leaf_hashes[1], &proof, &root).unwrap());
}

#[test]
fn test_receipt_creation_and_verification() {
    // Generate keypair
    let (signing_key, _verifying_key) = generate_test_keypair();

    // Create receipt
    let receipt = create_test_receipt(&signing_key);

    // Serialize to JSON
    let json = receipt.to_json().unwrap();
    assert!(!json.is_empty());

    // Deserialize from JSON
    let restored = Receipt::from_json(&json).unwrap();

    // Verify fields match
    assert_eq!(receipt.entry.id, restored.entry.id);
    assert_eq!(receipt.proof.tree_size, restored.proof.tree_size);
    assert_eq!(receipt.proof.leaf_index, restored.proof.leaf_index);
}

#[test]
fn test_receipt_with_metadata_roundtrip() {
    let (signing_key, _verifying_key) = generate_test_keypair();

    // Create receipt with complex metadata
    let mut receipt = create_test_receipt(&signing_key);
    receipt.entry.metadata = json!({
        "filename": "important_contract.pdf",
        "size": 1_024_567,
        "created": "2026-01-15T10:30:00Z",
        "tags": ["important", "contract", "signed"],
        "nested": {
            "key1": "value1",
            "key2": 42
        }
    });

    // Serialize
    let json = receipt.to_json().unwrap();

    // Deserialize
    let restored = Receipt::from_json(&json).unwrap();

    // Verify metadata is preserved
    assert_eq!(receipt.entry.metadata["filename"], restored.entry.metadata["filename"]);
    assert_eq!(receipt.entry.metadata["nested"]["key1"], restored.entry.metadata["nested"]["key1"]);
}

#[test]
fn test_merkle_tree_various_sizes() {
    // Test trees of different sizes
    for size in [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32] {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let leaves: Vec<Hash> = (0..size).map(|i| [i as u8; 32]).collect();
        let root = compute_root(&leaves);

        // Generate and verify proof for each leaf
        #[allow(clippy::cast_possible_truncation)]
        let get_node = |level: u32, index: u64| -> Option<Hash> {
            if level == 0 && (index as usize) < leaves.len() {
                Some(leaves[index as usize])
            } else {
                None
            }
        };

        #[allow(clippy::cast_sign_loss)]
        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = generate_inclusion_proof(idx as u64, size as u64, get_node).unwrap();
            assert!(
                verify_inclusion(leaf, &proof, &root).unwrap(),
                "Failed for tree size {size}, leaf index {idx}"
            );
        }
    }
}

#[test]
fn test_jcs_canonicalization_deterministic() {
    // Test that canonicalization is deterministic
    let test_cases = vec![
        json!({"b": 2, "a": 1}),
        json!({"nested": {"z": 26, "a": 1}, "top": "value"}),
        json!([1, 2, 3, {"key": "value"}]),
        json!({"unicode": "café", "emoji": "😀"}),
    ];

    for case in test_cases {
        let result1 = canonicalize(&case);
        let result2 = canonicalize(&case);
        let result3 = canonicalize(&case);

        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }
}

#[test]
fn test_checkpoint_json_roundtrip() {
    let checkpoint_json = CheckpointJson {
        origin: format_hash(&[0x01; 32]),
        tree_size: 100,
        root_hash: format_hash(&[0x02; 32]),
        timestamp: 1_704_067_200_000_000_000,
        signature: format_signature(&[0x03; 64]),
        key_id: format_hash(&[0x04; 32]),
    };

    // Serialize to JSON
    let json_str = serde_json::to_string(&checkpoint_json).unwrap();

    // Deserialize
    let restored: CheckpointJson = serde_json::from_str(&json_str).unwrap();

    // Verify fields match
    assert_eq!(checkpoint_json.origin, restored.origin);
    assert_eq!(checkpoint_json.tree_size, restored.tree_size);
    assert_eq!(checkpoint_json.root_hash, restored.root_hash);
    assert_eq!(checkpoint_json.timestamp, restored.timestamp);
}

#[test]
fn test_invalid_receipt_version() {
    let json = r#"{
        "spec_version": "3.0.0",
        "entry": {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "metadata": {}
        },
        "proof": {
            "tree_size": 1,
            "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "inclusion_path": [],
            "leaf_index": 0,
            "checkpoint": {
                "origin": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "tree_size": 1,
                "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "timestamp": 0,
                "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "key_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            }
        },
        "super_proof": {
            "genesis_super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "data_tree_index": 0,
            "super_tree_size": 1,
            "super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "inclusion": [],
            "consistency_to_origin": []
        }
    }"#;

    let result = Receipt::from_json(json);
    assert!(matches!(result, Err(AtlError::UnsupportedReceiptVersion(_))));
}

#[test]
fn test_invalid_hash_format() {
    let json = r#"{
        "spec_version": "2.0.0",
        "entry": {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "payload_hash": "invalid:notahash",
            "metadata": {}
        },
        "proof": {
            "tree_size": 1,
            "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "inclusion_path": [],
            "leaf_index": 0,
            "checkpoint": {
                "origin": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "tree_size": 1,
                "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "timestamp": 0,
                "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "key_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            }
        },
        "super_proof": {
            "genesis_super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "data_tree_index": 0,
            "super_tree_size": 1,
            "super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "inclusion": [],
            "consistency_to_origin": []
        }
    }"#;

    let receipt = Receipt::from_json(json).unwrap();
    let result = receipt.payload_hash_bytes();
    assert!(matches!(result, Err(AtlError::InvalidHash(_))));
}

#[test]
fn test_inclusion_proof_invalid_index() {
    let leaves = [[0u8; 32], [1u8; 32]];
    #[allow(clippy::cast_possible_truncation)]
    let get_node = |level: u32, index: u64| -> Option<Hash> {
        if level == 0 && (index as usize) < leaves.len() {
            Some(leaves[index as usize])
        } else {
            None
        }
    };

    // Try to generate proof for out-of-bounds index
    let result = generate_inclusion_proof(5, 2, get_node);
    assert!(matches!(result, Err(AtlError::LeafIndexOutOfBounds { .. })));
}

#[test]
fn test_checkpoint_verification_wrong_key() {
    // Create checkpoint with one key
    let (signing_key, _) = generate_test_keypair();
    let checkpoint = create_test_checkpoint(&signing_key);

    // Try to verify with different key
    let wrong_key = SigningKey::from_bytes(&[99u8; 32]);
    let wrong_verifier =
        CheckpointVerifier::from_bytes(&wrong_key.verifying_key().to_bytes()).unwrap();

    let result = checkpoint.verify(&wrong_verifier);
    assert!(matches!(result, Err(AtlError::InvalidSignature(_))));
}

#[test]
fn test_empty_tree_handling() {
    use sha2::{Digest, Sha256};

    // Empty tree has a defined root
    let root = compute_root(&[]);
    assert_eq!(root.len(), 32);

    // Empty tree root is hash of empty string
    let expected: Hash = Sha256::digest([]).into();
    assert_eq!(root, expected);
}

#[test]
fn test_large_tree_proof_size() {
    // For a tree of 1000 leaves, proof should be ~10 hashes (log2(1000) ≈ 10)
    let tree_size = 1000;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let leaves: Vec<Hash> = (0..tree_size).map(|i| [(i % 256) as u8; 32]).collect();

    #[allow(clippy::cast_possible_truncation)]
    let get_node = |level: u32, index: u64| -> Option<Hash> {
        if level == 0 && (index as usize) < leaves.len() {
            Some(leaves[index as usize])
        } else {
            None
        }
    };

    #[allow(clippy::cast_sign_loss)]
    let proof = generate_inclusion_proof(500, tree_size as u64, get_node).unwrap();

    // Proof size should be O(log n)
    assert!(
        proof.path.len() <= 10,
        "Proof size {} exceeds expected ~10 for tree size 1000",
        proof.path.len()
    );
}

#[test]
fn test_receipt_metadata_canonicalization() {
    // Test that different key orders produce the same canonical form
    let metadata1 = json!({"z": 1, "a": 2, "m": 3});
    let metadata2 = json!({"a": 2, "m": 3, "z": 1});

    let canon1 = canonicalize(&metadata1);
    let canon2 = canonicalize(&metadata2);

    assert_eq!(canon1, canon2);
    assert_eq!(canon1, r#"{"a":2,"m":3,"z":1}"#);
}

#[test]
fn test_checkpoint_wire_format_size() {
    use atl_core::core::checkpoint::CHECKPOINT_BLOB_SIZE;

    assert_eq!(CHECKPOINT_BLOB_SIZE, 98);

    // Create a checkpoint and verify wire format
    let (signing_key, _) = generate_test_keypair();
    let checkpoint = create_test_checkpoint(&signing_key);

    let blob = checkpoint.to_bytes();
    assert_eq!(blob.len(), 98);

    // Verify magic bytes
    assert_eq!(&blob[0..18], b"ATL-Protocol-v1-CP");
}

#[test]
fn test_receipt_helpers() {
    let (signing_key, _) = generate_test_keypair();
    let receipt = create_test_receipt(&signing_key);

    // Test helper methods
    assert_eq!(receipt.spec_version(), "2.0.0");
    assert_eq!(receipt.entry_id().to_string(), "550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(receipt.tree_size(), 1);
    assert_eq!(receipt.leaf_index(), 0);
    assert!(!receipt.has_anchors());
    assert!(!receipt.has_consistency_proof());

    // Test hash parsing
    let payload_hash = receipt.payload_hash_bytes().unwrap();
    assert_eq!(payload_hash.len(), 32);

    let root_hash = receipt.root_hash_bytes().unwrap();
    assert_eq!(root_hash.len(), 32);

    let path = receipt.inclusion_path_bytes().unwrap();
    assert_eq!(path.len(), 0); // Single leaf, no path
}

#[test]
fn test_proof_verification_with_wrong_root() {
    let leaves = vec![[0u8; 32], [1u8; 32]];
    let _root = compute_root(&leaves);

    #[allow(clippy::cast_possible_truncation)]
    let get_node = |level: u32, index: u64| -> Option<Hash> {
        if level == 0 && (index as usize) < leaves.len() {
            Some(leaves[index as usize])
        } else {
            None
        }
    };

    let proof = generate_inclusion_proof(0, 2, get_node).unwrap();

    // Verify with wrong root
    let wrong_root = [99u8; 32];
    assert!(!verify_inclusion(&leaves[0], &proof, &wrong_root).unwrap());
}

#[test]
fn test_jcs_handles_unicode() {
    let value = json!({
        "café": "☕",
        "日本語": "テスト",
        "emoji": "😀🎉🔥"
    });

    let canonical = canonicalize(&value);

    // Should not escape non-ASCII Unicode
    assert!(canonical.contains("café"));
    assert!(canonical.contains("☕"));
    assert!(canonical.contains("日本語"));
    assert!(canonical.contains("😀"));
}

// ========== Public API Export Tests ==========
// Tests for verifying public API exports after signature changes

#[test]
fn test_public_api_exports() {
    use atl_core::{
        verify_consistency, verify_inclusion, AtlError, AtlResult, ConsistencyProof, Hash,
        InclusionProof,
    };

    // Helper functions to verify signatures compile
    fn check_verify_inclusion(leaf: &Hash, proof: &InclusionProof, root: &Hash) -> AtlResult<bool> {
        verify_inclusion(leaf, proof, root)
    }

    fn check_verify_consistency(
        proof: &ConsistencyProof,
        old_root: &Hash,
        new_root: &Hash,
    ) -> AtlResult<bool> {
        verify_consistency(proof, old_root, new_root)
    }

    // Verify error variants are accessible
    let _: AtlError = AtlError::InvalidTreeSize { size: 0, reason: "test" };
    let _: AtlError = AtlError::InvalidConsistencyBounds { from_size: 10, to_size: 5 };
    let _: AtlError = AtlError::ArithmeticOverflow { operation: "test" };
    let _: AtlError = AtlError::InvalidProofStructure { reason: "test".to_string() };

    // Test actual usage with Result<bool>
    let proof = InclusionProof { leaf_index: 0, tree_size: 1, path: vec![] };
    let hash: Hash = [0u8; 32];

    // This should compile with new Result<bool> return type
    let result: bool = check_verify_inclusion(&hash, &proof, &hash).unwrap();
    assert!(result);

    // Test error handling
    let proof = InclusionProof { leaf_index: 10, tree_size: 5, path: vec![] };
    let result = check_verify_inclusion(&hash, &proof, &hash);
    assert!(matches!(result, Err(AtlError::LeafIndexOutOfBounds { .. })));

    // Test consistency proof
    let consistency_proof = ConsistencyProof { from_size: 5, to_size: 5, path: vec![] };
    let _result: bool = check_verify_consistency(&consistency_proof, &hash, &hash).unwrap();
}

#[test]
fn test_verify_inclusion_returns_result() {
    use atl_core::{verify_inclusion, Hash, InclusionProof};

    // Valid single-leaf proof
    let proof = InclusionProof { leaf_index: 0, tree_size: 1, path: vec![] };
    let hash: Hash = [0u8; 32];

    // New signature returns Result<bool>
    let result = verify_inclusion(&hash, &proof, &hash);
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Invalid tree size returns error
    let proof = InclusionProof { leaf_index: 0, tree_size: 0, path: vec![] };
    let result = verify_inclusion(&hash, &proof, &hash);
    assert!(result.is_err());
}

#[test]
fn test_verify_consistency_returns_result() {
    use atl_core::{verify_consistency, ConsistencyProof, Hash};

    let root: Hash = [42u8; 32];

    // Valid same-size proof
    let proof = ConsistencyProof { from_size: 5, to_size: 5, path: vec![] };
    let result = verify_consistency(&proof, &root, &root);
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Invalid bounds returns error
    let proof = ConsistencyProof { from_size: 10, to_size: 5, path: vec![] };
    let result = verify_consistency(&proof, &root, &root);
    assert!(result.is_err());
}

// ========== RFC 9162 Consistency Verification Integration Tests ==========

#[test]
fn test_end_to_end_consistency_verification() {
    use atl_core::core::merkle::{
        compute_leaf_hash, compute_root, generate_consistency_proof, verify_consistency, Hash,
    };

    // Full workflow: create tree, grow it, verify consistency

    // Initial tree with 5 entries
    let initial_entries = [
        ([0xaa; 32], json!({"file": "doc1.pdf"})),
        ([0xbb; 32], json!({"file": "doc2.pdf"})),
        ([0xcc; 32], json!({"file": "doc3.pdf"})),
        ([0xdd; 32], json!({"file": "doc4.pdf"})),
        ([0xee; 32], json!({"file": "doc5.pdf"})),
    ];

    let initial_leaves: Vec<Hash> = initial_entries
        .iter()
        .map(|(payload, metadata)| {
            let metadata_hash = canonicalize_and_hash(metadata);
            compute_leaf_hash(payload, &metadata_hash)
        })
        .collect();

    let old_root = compute_root(&initial_leaves);

    // Grow tree to 10 entries
    let new_entries = [
        ([0x11; 32], json!({"file": "doc6.pdf"})),
        ([0x22; 32], json!({"file": "doc7.pdf"})),
        ([0x33; 32], json!({"file": "doc8.pdf"})),
        ([0x44; 32], json!({"file": "doc9.pdf"})),
        ([0x55; 32], json!({"file": "doc10.pdf"})),
    ];

    let mut all_leaves = initial_leaves;
    for (payload, metadata) in &new_entries {
        let metadata_hash = canonicalize_and_hash(metadata);
        all_leaves.push(compute_leaf_hash(payload, &metadata_hash));
    }

    let new_root = compute_root(&all_leaves);

    // Generate consistency proof
    #[allow(clippy::cast_possible_truncation)]
    let get_node = |level: u32, index: u64| -> Option<Hash> {
        if level == 0 && (index as usize) < all_leaves.len() {
            Some(all_leaves[index as usize])
        } else {
            None
        }
    };

    let proof = generate_consistency_proof(5, 10, get_node).unwrap();

    // Verify consistency
    assert!(verify_consistency(&proof, &old_root, &new_root).unwrap());

    // Verify tampering is detected
    let tampered_old_root = [0xff; 32];
    assert!(!verify_consistency(&proof, &tampered_old_root, &new_root).unwrap());
}

// ========== RFC 3161 Anchor Verification Integration Tests ==========

#[cfg(feature = "rfc3161-verify")]
const FREETSA_TOKEN: &str = "MIIVSQYJKoZIhvcNAQcCoIIVOjCCFTYCAQMxDzANBglghkgBZQMEAgMFADCCAYQGCyqGSIb3DQEJEAEEoIIBcwSCAW8wggFrAgEBBgQqAwQBMDEwDQYJYIZIAWUDBAIBBQAEIOI2G0BTqUXdHSQabIfa15i3/XRQYUuBWi2UcoPtNZRSAgQCV5LLGA8yMDI2MDEwNDIxNTc0M1oBAf+gggERpIIBDTCCAQkxETAPBgNVBAoTCEZyZWUgVFNBMQwwCgYDVQQLEwNUU0ExdjB0BgNVBA0TbVRoaXMgY2VydGlmaWNhdGUgZGlnaXRhbGx5IHNpZ25zIGRvY3VtZW50cyBhbmQgdGltZSBzdGFtcCByZXF1ZXN0cyBtYWRlIHVzaW5nIHRoZSBmcmVldHNhLm9yZyBvbmxpbmUgc2VydmljZXMxGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9yZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJV3VlcnpidXJnMQswCQYDVQQGEwJERTEPMA0GA1UECBMGQmF5ZXJuoIIQCDCCCAEwggXpoAMCAQICCQDB6YYWDajpgjANBgkqhkiG9w0BAQ0FADCBlTERMA8GA1UEChMIRnJlZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9yZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJV3VlcnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFMB4XDTE2MDMxMzAxNTczOVoXDTI2MDMxMTAxNTczOVowggEJMREwDwYDVQQKEwhGcmVlIFRTQTEMMAoGA1UECxMDVFNBMXYwdAYDVQQNE21UaGlzIGNlcnRpZmljYXRlIGRpZ2l0YWxseSBzaWducyBkb2N1bWVudHMgYW5kIHRpbWUgc3RhbXAgcmVxdWVzdHMgbWFkZSB1c2luZyB0aGUgZnJlZXRzYS5vcmcgb25saW5lIHNlcnZpY2VzMRgwFgYDVQQDEw93d3cuZnJlZXRzYS5vcmcxIjAgBgkqhkiG9w0BCQEWE2J1c2lsZXphc0BnbWFpbC5jb20xEjAQBgNVBAcTCVd1ZXJ6YnVyZzELMAkGA1UEBhMCREUxDzANBgNVBAgTBkJheWVybjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALWRBIxOSG806dwIYn/CN1FiI2mEuCyxML7/UXz8OPhLzlxlqHTasmIa4Lzn4zVj4O3pNP1fiCMVnweEiAgidGDB7YgmFwb0KBM0NZ37uBvRNT/BeWEK8ajIyGXcAOojs6ib5r0DuoWp7IJ9YFZZBeItalhO0TgK4VAoDO45fpigEvOARkAHhiRDvAd8uV9CGvMXEtloPNtt/7rzyLpbpWauUj1FnWF3NG1NhA4niGt8AcW4kNeKLie7qN0vmigS4VfWL5IcZZYlSAadzbfQbeGB3g6VcNZvhyIM4otiirVZBvPuDCEPcFHo9IWK+LmpLQnkavLZy6W/z60WjN9gRJGksGYDsRTK9wMfBl5+7vpTxXXzSQwFnS4y3cdqxNTExxBoO5f9G+WRvGEFUYbYj5oDkbMHtvke2VTao2+azWoeFKouSt8XRktU2xjbtv/jAIAkZUc3BDbOTne65d5v4PP51uf/vrRh55TpL7CVH4quYaQSzOmyEHRjXIvjJ64aD2tKZG6w+EY7xjv4RVMENdGegCUR7J9mw0lpUti+y2mwqk1MQfYFFf59y7iTGc3aWbpq6kvjzq5xjm/LbM19ufxQuxWxLzZlsKowconC5t1LERzki6LZ79taa5pQYGkzT7NPb8euMw8LNCCKrIDfMmb92QRlh2uiy4mNlQUxW257AgMBAAGjggHbMIIB1zAJBgNVHRMEAjAAMB0GA1UdDgQWBBRudgt7Tk+c4WDKbSzpJ6KilLN3NzAfBgNVHSMEGDAWgBT6VQ2MNGZRQ0z357OnbJWveuaklzALBgNVHQ8EBAMCBsAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwYwYIKwYBBQUHAQEEVzBVMCoGCCsGAQUFBzAChh5odHRwOi8vd3d3LmZyZWV0c2Eub3JnL3RzYS5jcnQwJwYIKwYBBQUHMAGGG2h0dHA6Ly93d3cuZnJlZXRzYS5vcmc6MjU2MDA3BgNVHR8EMDAuMCygKqAohiZodHRwOi8vd3d3LmZyZWV0c2Eub3JnL2NybC9yb290X2NhLmNybDCBxgYDVR0gBIG+MIG7MIG4BgEAMIGyMDMGCCsGAQUFBwIBFidodHRwOi8vd3d3LmZyZWV0c2Eub3JnL2ZyZWV0c2FfY3BzLmh0bWwwMgYIKwYBBQUHAgEWJmh0dHA6Ly93d3cuZnJlZXRzYS5vcmcvZnJlZXRzYV9jcHMucGRmMEcGCCsGAQUFBwICMDsaOUZyZWVUU0EgdHJ1c3RlZCB0aW1lc3RhbXBpbmcgU29mdHdhcmUgYXMgYSBTZXJ2aWNlIChTYWFTKTANBgkqhkiG9w0BAQ0FAAOCAgEApclE4sb6wKFNkwp/0KCxcrQfwUg8PpV8aKK82bl2TxqVAWH9ckctQaXu0nd4YgO1QiJA+zomzeF2CHtvsQEd9MwZ4lcapKBREJZl6UxG9QvSre5qxBN+JRslo52r2kUVFdj/ngcgno7CC3h09+Gg7efACTf+hKM0+LMmXO0tjtnfYTllg2d/6zgsHuOyPm6l8F3zDee5+JAF0lJm9hLznItPbaum17+6wZYyuQY3Mp9SpvBmoQ5D6qgfhJpsX+P+i16iMnX2h/IFLlAupsMHYqZozOB4cd2Ol+MVu6kp4lWJl3oKMSzpbFEGsUN8d58rNhsYKIjz7oojQ3T6Bj6VYZJif3xDEHOWXRJgko66AJ6ANCmuMkz5bwQjVPN7ylr93Hn3k0arOIv8efAdyYYSVOpswSmUEHa4PSBVbzvlEyaDfyh294M7Nw58PUEFI4J9T1NADHIhjXUin/EMb4iTqaOhwMQrtMiYwT30HH9lc7T8VlFZcaYQp7DShXyCJan7IE6s7KLolxqhr4eIairjxy/goKroQpgKd77xa5IRVFgJDZgrWUZgN2TnWgrT0RRUuZhvZ4uatq/oSXAzrjq/1OtDt7yd7miBWUnmSBWCqC54UnfyKCEH7+OQIA4FCKy46oLqJQUnbzydoqPTtK04u/iEK9o2/CRIKR9VjcAt0eAwggf/MIIF56ADAgECAgkAwemGFg2o6YAwDQYJKoZIhvcNAQENBQAwgZUxETAPBgNVBAoTCEZyZWUgVFNBMRAwDgYDVQQLEwdSb290IENBMRgwFgYDVQQDEw93d3cuZnJlZXRzYS5vcmcxIjAgBgkqhkiG9w0BCQEWE2J1c2lsZXphc0BnbWFpbC5jb20xEjAQBgNVBAcTCVd1ZXJ6YnVyZzEPMA0GA1UECBMGQmF5ZXJuMQswCQYDVQQGEwJERTAeFw0xNjAzMTMwMTUyMTNaFw00MTAzMDcwMTUyMTNaMIGVMREwDwYDVQQKEwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZyZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIwEAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2Ao4OMDLxERDZZM2pS50CeOGUKukTqqWZB82ml5OZW9msfjO62f43BNocAamNIa/j9ZGlnXBncFFnmY9QFnIuCrRish9DkXHSz8xFk/NzWveUpasxH2wBDHiY3jPXXEUQ7nb0vR0UmM8X0wPwal3Z95bMbKm2V6Vv4+pP77585rahjT41owzuX/Fw0c85ozPT/aiWTSLbaFsp5WG+iQ8KqEWHOy6Eqyarg5/+j63p0juzHmHSc8ybiAZJGF+r7PoFNGAKupAbYU4uhUWC3qIib8Gc199SvtUNh3fNmYjAU6P8fcMoegaKT/ErcTzZgDZm6VU4VFb/OPgCmM9rk4VukiR3SmbPHN0Rwvjv2FID10WLJWZLE+1jnN7U/4ET1sxTU9JylHPDwwcVfHIqpbXdC/stbDixuTdJyIHsYAJtCJUbOCS9cbrLzkc669Y28LkYtKLI/0aU8HRXry1vHPglVNF3D9ef9dMU3NEEzdyryUE4BW388Bfn64Vy/VL3AUTxiNoF9YI/WN0GKX5zh77S13LBPagmZgEEX+QS3XCYbAyYe6c0S5A3OHUW0ljniFtR+JaLfyYBITvEy0yF+P8LhK9qmIM3zfuBho9+zzHcpnFtfsLdgCwWcmKeXABSyzV90pqvxD9hWzsf+dThzgjHHHPh/rt9xWozYhMp6e1sIwIDAQABo4ICTjCCAkowDAYDVR0TBAUwAwEB/zAOBgNVHQ8BAf8EBAMCAcYwHQYDVR0OBBYEFPpVDYw0ZlFDTPfns6dsla965qSXMIHKBgNVHSMEgcIwgb+AFPpVDYw0ZlFDTPfns6dsla965qSXoYGbpIGYMIGVMREwDwYDVQQKEwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZyZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIwEAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREWCCQDB6YYWDajpgDAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vd3d3LmZyZWV0c2Eub3JnL3Jvb3RfY2EuY3JsMIHPBgNVHSAEgccwgcQwgcEGCisGAQQBgfIkAQEwgbIwMwYIKwYBBQUHAgEWJ2h0dHA6Ly93d3cuZnJlZXRzYS5vcmcvZnJlZXRzYV9jcHMuaHRtbDAyBggrBgEFBQcCARYmaHR0cDovL3d3dy5mcmVldHNhLm9yZy9mcmVldHNhX2Nwcy5wZGYwRwYIKwYBBQUHAgIwOxo5RnJlZVRTQSB0cnVzdGVkIHRpbWVzdGFtcGluZyBTb2Z0d2FyZSBhcyBhIFNlcnZpY2UgKFNhYVMpMDcGCCsGAQUFBwEBBCswKTAnBggrBgEFBQcwAYYbaHR0cDovL3d3dy5mcmVldHNhLm9yZzoyNTYwMA0GCSqGSIb3DQEBDQUAA4ICAQBor36/k4Vi70zrO1gL4vr2zDWiZ3KWLz2VkB+lYwyH0JGYmEzooGoz+KnCgu2fHLEaxsI+FxCO5O/Ob7KU3pXBMyYiVXJVIsphlx1KO394JQ37jUruwPsZWbFkEAUgucEOZMYmYuStTQq64imPyUj8Tpno2ea4/b5EBBIex8FCLqyyydcyjgc5bmC087uAOtSlVcgP77U/hed2SgqftK/DmfTNL1+/WHEFxggc89BTN7a7fRsBC3SfSIjJEvNpa6G2kC13t9/ARsBKDMHsT40YXi2lXft7wqIDbGIZJGpPmd27bx+Ck5jzuAPcCtkNy1m+9MJ8d0BLmQQ7eCcYZ5kRUsOZ8Sy/xMYlrcCWNVrkTjQhAOxRelAuLwb5QLjUNZm7wRVPiudhoLDVVftKE5HU80IK+NvxLy1925133OFTeAQHSvF15PLW1Vs0tdb33L3TFzCvVkgNTAz/FD+eg7wVGGbQug8LvcR/4nhkF2u9bBq4XfMl7fd3iJvERxvz+nPlbMWR6LFgzaeweGoewErDsk+i4o1dGeXkgATV4WaoPILsb9VPs4Xrr3EzqFtS3kbbUkThw0ro025xL5/ODUk9fT7dWGxhmOPsPm6WNG9BesnyIeCv8zqPagse9MAjYwt2raqNkUM4JezEHEmluYsYHH2jDpl6uVTHPCzYBa/amTGCA4owggOGAgEBMIGjMIGVMREwDwYDVQQKEwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZyZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIwEAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREUCCQDB6YYWDajpgjANBglghkgBZQMEAgMFAKCBuDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MDEwNDIxNTc0M1owKwYLKoZIhvcNAQkQAgwxHDAaMBgwFgQUkW2j2GDsyoLjS8WdF5Pn6WiHXxQwTwYJKoZIhvcNAQkEMUIEQCsLIk8yrYJ4TwA7A2fc0oaakKY4grkITn0HDdjkjoYpz3Nv0jVi5d1jAOGW2CW5SZ2OKV1HBJABalNvpSc4z84wDQYJKoZIhvcNAQEBBQAEggIAhrsaIj2cSGGI6VtkpFpWtOQnfTx+4yKofi3e8yOr/DU4stRbq5JRpAE3n4fDcbwFC37d4/UoIOGc6V2s2/n/EqvCRL7S5CKeBA+1e6I7r0ID7myjXAEg/nqqL/ew8hNAhesoodCvHKb3N3GTHpYr6JaGGjbRmcG+sY0yHP0dmDcUNu3tln4C0PY1dsLppxru++/jhTyZ/SPeRCbnvJ1y7jXkVg2HKItjM1XRMepfnuyRZJvuO/3VbPWXooaPewPlINPUkB/8jpi2PGhgeJilNJxQ7NPDc73E9EHrNHSlZfno6J+E6+yoYXnS9FNUewZrQOVPZAlsnQ2M9QVb+RCL3YY9NoVXoRlz0/U6iWOJj+zf1WcciTHPm8RfKn3SZpItp5dOJ6sFbR7QAPh6u9cCr4YcUv8DxgOvMHWyYUBHkyyffk+uBOuu1vqT05M5izhCnYdKB4hS0YSmLJM81WnlRI9Hyv2uqUdeiTGfiEJQIiWps9GAwLyBjwD/HuQ66f9Jz5iMAObF92D9+aUa5aW+zX1LEIf/3sBsnVudM+EIhGsmzlJqfGo9y8TQkuRlcjG4rVEkpBuqFOYTRDTG9ykdajBgQ64hfoSgvkSsteKeFlT7yeeOMrwKofCT/MixSIwXzg9JqvXt7fI8hnC19dncKWUV853YtvAikNj8GF1Fn7I=";

#[cfg(feature = "rfc3161-verify")]
#[test]
fn test_receipt_with_rfc3161_anchor_wrong_hash() {
    use atl_core::{verify_receipt, ReceiptAnchor};

    let (signing_key, verifying_key) = generate_test_keypair();
    let mut receipt = create_test_receipt(&signing_key);

    receipt.anchors = vec![ReceiptAnchor::Rfc3161 {
        target: "data_tree_root".to_string(),
        target_hash: receipt.proof.root_hash.clone(),
        tsa_url: "https://freetsa.org/tsr".to_string(),
        timestamp: "2026-01-04T21:57:43Z".to_string(),
        token_der: format!("base64:{FREETSA_TOKEN}"),
    }];

    let result = verify_receipt(&receipt, &verifying_key.to_bytes()).unwrap();

    assert!(result.is_valid);
    assert_eq!(result.anchor_results.len(), 1);

    let anchor_result = &result.anchor_results[0];
    assert_eq!(anchor_result.anchor_type, "rfc3161");
    assert!(!anchor_result.is_valid);
    assert!(anchor_result.error.is_some());
    assert!(anchor_result.error.as_ref().unwrap().contains("mismatch"));
}

#[cfg(feature = "rfc3161-verify")]
#[test]
fn test_receipt_with_rfc3161_anchor_malformed() {
    use atl_core::{verify_receipt, ReceiptAnchor};

    let (signing_key, verifying_key) = generate_test_keypair();
    let mut receipt = create_test_receipt(&signing_key);

    receipt.anchors = vec![ReceiptAnchor::Rfc3161 {
        target: "data_tree_root".to_string(),
        target_hash: receipt.proof.root_hash.clone(),
        tsa_url: "https://freetsa.org/tsr".to_string(),
        timestamp: "2026-01-04T21:57:43Z".to_string(),
        token_der: "base64:INVALID_DER_TOKEN".to_string(),
    }];

    let result = verify_receipt(&receipt, &verifying_key.to_bytes()).unwrap();

    assert!(result.is_valid);
    assert_eq!(result.anchor_results.len(), 1);

    let anchor_result = &result.anchor_results[0];
    assert_eq!(anchor_result.anchor_type, "rfc3161");
    assert!(!anchor_result.is_valid);
    assert!(anchor_result.error.is_some());
}

#[cfg(not(feature = "rfc3161-verify"))]
#[test]
fn test_receipt_with_rfc3161_anchor_feature_disabled() {
    use atl_core::{verify_receipt, ReceiptAnchor};

    let (signing_key, verifying_key) = generate_test_keypair();
    let mut receipt = create_test_receipt(&signing_key);

    receipt.anchors = vec![ReceiptAnchor::Rfc3161 {
        target: "data_tree_root".to_string(),
        target_hash: receipt.proof.root_hash.clone(),
        tsa_url: "https://freetsa.org/tsr".to_string(),
        timestamp: "2026-01-04T21:57:43Z".to_string(),
        token_der: "base64:AAAA".to_string(),
    }];

    let result = verify_receipt(&receipt, &verifying_key.to_bytes()).unwrap();

    assert!(result.is_valid);
    assert_eq!(result.anchor_results.len(), 1);

    let anchor_result = &result.anchor_results[0];
    assert_eq!(anchor_result.anchor_type, "rfc3161");
    assert!(!anchor_result.is_valid);
    assert!(anchor_result.error.as_ref().unwrap().contains("feature"));
}
