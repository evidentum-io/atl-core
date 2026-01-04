//! Integration tests for atl-core
//!
//! These tests verify end-to-end workflows using only the public API.

use atl_core::AtlError;
use atl_core::core::checkpoint::{Checkpoint, CheckpointJson, CheckpointVerifier, compute_key_id};
use atl_core::core::jcs::{canonicalize, canonicalize_and_hash};
use atl_core::core::merkle::{
    Hash, compute_leaf_hash, compute_root, generate_inclusion_proof, verify_inclusion,
};
use atl_core::core::receipt::{RECEIPT_SPEC_VERSION, Receipt, format_hash, format_signature};
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

    // Create checkpoint
    let checkpoint = create_test_checkpoint(signing_key);

    Receipt {
        spec_version: RECEIPT_SPEC_VERSION.to_string(),
        entry: atl_core::core::receipt::ReceiptEntry {
            id: entry_id,
            payload_hash: format_hash(&payload_hash),
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
    assert!(verify_inclusion(&leaf_hashes[1], &proof, &root));
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
                verify_inclusion(leaf, &proof, &root),
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
        "spec_version": "2.0.0",
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
        }
    }"#;

    let result = Receipt::from_json(json);
    assert!(matches!(result, Err(AtlError::UnsupportedReceiptVersion(_))));
}

#[test]
fn test_invalid_hash_format() {
    let json = r#"{
        "spec_version": "1.0.0",
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
    assert_eq!(receipt.spec_version(), "1.0.0");
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
    assert!(!verify_inclusion(&leaves[0], &proof, &wrong_root));
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
