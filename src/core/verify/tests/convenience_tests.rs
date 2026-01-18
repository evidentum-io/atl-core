//! Tests for convenience functions

use crate::core::checkpoint::{Checkpoint, CheckpointJson, CheckpointVerifier};
use crate::core::jcs::canonicalize_and_hash;
use crate::core::merkle::compute_leaf_hash;
use crate::core::receipt::{
    format_hash, format_signature, Receipt, ReceiptEntry, ReceiptProof, SuperProof,
};
use crate::core::verify::{
    verify_inclusion_only, verify_receipt_anchor_only, verify_receipt_json_anchor_only,
    verify_receipt_json_with_key, verify_receipt_json_with_key_and_options,
    verify_receipt_json_with_options, verify_receipt_with_key, verify_receipt_with_key_and_options,
    verify_receipt_with_options, SignatureMode, VerifyOptions,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use uuid::Uuid;

/// Create a minimal valid receipt for testing
fn create_test_receipt() -> (Receipt, [u8; 32]) {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let verifier = CheckpointVerifier::new(verifying_key);

    let payload_hash = [0xAAu8; 32];
    let metadata = json!({"test": "data"});
    let metadata_hash = canonicalize_and_hash(&metadata);
    let leaf_hash = compute_leaf_hash(&payload_hash, &metadata_hash);
    let root_hash = leaf_hash;

    let origin = [0xBBu8; 32];
    let tree_size = 1u64;
    let timestamp = 1_000_000u64;

    let mut checkpoint =
        Checkpoint::new(origin, tree_size, timestamp, root_hash, [0u8; 64], verifier.key_id());

    let blob = checkpoint.to_bytes();
    let signature = signing_key.sign(&blob);
    checkpoint.signature = signature.to_bytes();

    let receipt = Receipt {
        spec_version: "2.0.0".to_string(),
        upgrade_url: None,
        entry: ReceiptEntry {
            id: Uuid::nil(),
            payload_hash: format_hash(&payload_hash),
            metadata_hash: format_hash(&metadata_hash),
            metadata,
        },
        proof: ReceiptProof {
            leaf_index: 0,
            tree_size: 1,
            root_hash: format_hash(&root_hash),
            inclusion_path: vec![],
            checkpoint: CheckpointJson {
                origin: format_hash(&origin),
                tree_size,
                root_hash: format_hash(&root_hash),
                timestamp,
                signature: format_signature(&checkpoint.signature),
                key_id: format_hash(&verifier.key_id()),
            },
            consistency_proof: None,
        },
        super_proof: Some(SuperProof {
            genesis_super_root: format_hash(&root_hash),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: format_hash(&root_hash),
            inclusion: vec![],
            consistency_to_origin: vec![],
        }),
        anchors: vec![],
    };

    (receipt, verifying_key.to_bytes())
}

// ========== Anchor-Only Tests ==========

#[test]
fn test_verify_receipt_anchor_only() {
    let (receipt, _) = create_test_receipt();
    let result = verify_receipt_anchor_only(&receipt).unwrap();

    // Should succeed even without anchors (basic structure valid)
    assert!(result.inclusion_valid);
    assert!(result.super_inclusion_valid);
    assert!(result.super_consistency_valid);
}

#[test]
fn test_verify_receipt_with_options_skip_anchors() {
    let (receipt, _) = create_test_receipt();
    let options = VerifyOptions {
        skip_anchors: true,
        signature_mode: SignatureMode::Skip,
        ..Default::default()
    };

    let result = verify_receipt_with_options(&receipt, options).unwrap();
    assert!(result.inclusion_valid);
}

#[test]
fn test_verify_receipt_with_options_skip_consistency() {
    let (receipt, _) = create_test_receipt();
    let options = VerifyOptions { skip_consistency: true, ..Default::default() };

    let result = verify_receipt_with_options(&receipt, options).unwrap();
    assert!(result.inclusion_valid);
}

#[test]
fn test_verify_receipt_with_options_min_anchors() {
    let (receipt, _) = create_test_receipt();
    let options = VerifyOptions { min_valid_anchors: 1, ..Default::default() };

    let result = verify_receipt_with_options(&receipt, options).unwrap();
    // Will fail min_valid_anchors requirement since no anchors present
    assert!(!result.is_valid);
}

// ========== Key-Based Tests ==========

#[test]
fn test_verify_receipt_with_key() {
    let (receipt, public_key) = create_test_receipt();
    let result = verify_receipt_with_key(&receipt, &public_key).unwrap();

    assert!(result.signature_valid);
    assert!(result.inclusion_valid);
}

#[test]
fn test_verify_receipt_with_key_and_options_require_mode() {
    let (receipt, public_key) = create_test_receipt();
    let options = VerifyOptions { signature_mode: SignatureMode::Require, ..Default::default() };

    let result = verify_receipt_with_key_and_options(&receipt, &public_key, options).unwrap();
    assert!(result.signature_valid);
}

#[test]
fn test_verify_receipt_with_key_and_options_skip_mode() {
    let (receipt, public_key) = create_test_receipt();
    let options = VerifyOptions { signature_mode: SignatureMode::Skip, ..Default::default() };

    let result = verify_receipt_with_key_and_options(&receipt, &public_key, options).unwrap();
    // Signature should be skipped
    assert!(!result.signature_valid);
}

#[test]
fn test_verify_receipt_with_invalid_key() {
    let (receipt, _) = create_test_receipt();
    let wrong_key = [0xFFu8; 32];

    let result = verify_receipt_with_key(&receipt, &wrong_key).unwrap();
    assert!(!result.signature_valid);
}

// ========== JSON Variants Tests ==========

#[test]
fn test_verify_receipt_json_anchor_only() {
    let (receipt, _) = create_test_receipt();
    let json = receipt.to_json().unwrap();

    let result = verify_receipt_json_anchor_only(&json).unwrap();
    assert!(result.inclusion_valid);
}

#[test]
fn test_verify_receipt_json_with_options() {
    let (receipt, _) = create_test_receipt();
    let json = receipt.to_json().unwrap();
    let options = VerifyOptions { skip_anchors: true, ..Default::default() };

    let result = verify_receipt_json_with_options(&json, options).unwrap();
    assert!(result.inclusion_valid);
}

#[test]
fn test_verify_receipt_json_with_key() {
    let (receipt, public_key) = create_test_receipt();
    let json = receipt.to_json().unwrap();

    let result = verify_receipt_json_with_key(&json, &public_key).unwrap();
    assert!(result.signature_valid);
    assert!(result.inclusion_valid);
}

#[test]
fn test_verify_receipt_json_with_key_and_options() {
    let (receipt, public_key) = create_test_receipt();
    let json = receipt.to_json().unwrap();
    let options = VerifyOptions { signature_mode: SignatureMode::Require, ..Default::default() };

    let result = verify_receipt_json_with_key_and_options(&json, &public_key, options).unwrap();
    assert!(result.signature_valid);
}

#[test]
fn test_verify_receipt_json_invalid_json() {
    let result = verify_receipt_json_anchor_only("invalid json");
    assert!(result.is_err());
}

#[test]
fn test_verify_receipt_json_with_key_invalid_json() {
    let key = [0u8; 32];
    let result = verify_receipt_json_with_key("invalid json", &key);
    assert!(result.is_err());
}

// ========== Deprecated Functions Tests ==========

#[allow(deprecated)]
#[test]
fn test_verify_receipt_deprecated() {
    let (receipt, public_key) = create_test_receipt();
    let result = crate::core::verify::verify_receipt(&receipt, &public_key).unwrap();
    assert!(result.signature_valid);
}

#[allow(deprecated)]
#[test]
fn test_verify_receipt_json_deprecated() {
    let (receipt, public_key) = create_test_receipt();
    let json = receipt.to_json().unwrap();
    let result = crate::core::verify::verify_receipt_json(&json, &public_key).unwrap();
    assert!(result.signature_valid);
}

// ========== verify_inclusion_only Tests ==========

#[test]
fn test_verify_inclusion_only_valid() {
    let payload_hash = [0xAAu8; 32];
    let metadata = json!({"test": "data"});
    let metadata_hash = canonicalize_and_hash(&metadata);
    let leaf_hash = compute_leaf_hash(&payload_hash, &metadata_hash);

    // Single leaf tree: root = leaf
    let result = verify_inclusion_only(
        &payload_hash,
        &metadata,
        &[],        // Empty path for single leaf
        0,          // Leaf index
        1,          // Tree size
        &leaf_hash, // Expected root
    );

    assert!(result);
}

#[test]
fn test_verify_inclusion_only_invalid() {
    let payload_hash = [0xAAu8; 32];
    let metadata = json!({"test": "data"});
    let wrong_root = [0xFFu8; 32];

    let result = verify_inclusion_only(&payload_hash, &metadata, &[], 0, 1, &wrong_root);

    assert!(!result);
}

#[test]
fn test_verify_inclusion_only_with_path() {
    let payload_hash = [0xAAu8; 32];
    let metadata = json!({"data": "test"});

    // For a tree with 2 leaves, we need a sibling
    let sibling = [0xBBu8; 32];
    let path = vec![sibling];

    // Compute expected root
    let metadata_hash = canonicalize_and_hash(&metadata);
    let leaf_hash = compute_leaf_hash(&payload_hash, &metadata_hash);
    let root = crate::core::merkle::hash_children(&leaf_hash, &sibling);

    let result = verify_inclusion_only(&payload_hash, &metadata, &path, 0, 2, &root);

    assert!(result);
}

#[test]
fn test_verify_inclusion_only_zero_tree_size() {
    let payload_hash = [0u8; 32];
    let metadata = json!({});

    // Zero tree size should fail
    let result = verify_inclusion_only(
        &payload_hash,
        &metadata,
        &[],
        0,
        0, // Invalid: zero size
        &[0u8; 32],
    );

    assert!(!result);
}

#[test]
fn test_verify_inclusion_only_index_out_of_bounds() {
    let payload_hash = [0u8; 32];
    let metadata = json!({});

    // Index >= tree_size should fail
    let result = verify_inclusion_only(
        &payload_hash,
        &metadata,
        &[],
        5, // Index too large
        2, // Tree size
        &[0u8; 32],
    );

    assert!(!result);
}
