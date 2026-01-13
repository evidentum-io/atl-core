//! Core verification tests

use super::super::helpers::{reconstruct_leaf_hash, verify_anchor, verify_inclusion_proof};
use crate::core::checkpoint::{Checkpoint, CheckpointJson, CheckpointVerifier};
use crate::core::jcs::canonicalize_and_hash;
use crate::core::merkle::compute_leaf_hash;
use crate::core::receipt::{
    format_hash, format_signature, Receipt, ReceiptAnchor, ReceiptEntry, ReceiptProof,
};
use crate::core::verify::{
    verify_inclusion_only, verify_receipt, verify_receipt_json, AnchorVerificationResult,
    ReceiptVerifier, VerificationError, VerificationResult, VerifyOptions,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use uuid::Uuid;

/// Create a valid test receipt with proper signatures
fn create_test_receipt() -> (Receipt, [u8; 32], SigningKey) {
    // Generate signing key
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let verifying_key = signing_key.verifying_key();
    let verifier = CheckpointVerifier::new(verifying_key);

    // Create entry
    let payload_hash = [0xAAu8; 32];
    let metadata = json!({"test": "metadata"});
    let metadata_hash = canonicalize_and_hash(&metadata);
    let leaf_hash = compute_leaf_hash(&payload_hash, &metadata_hash);

    // Single leaf tree: root = leaf
    let root_hash = leaf_hash;

    // Create checkpoint
    let origin = [0xBBu8; 32];
    let tree_size = 1u64;
    let timestamp = 1_234_567_890u64;

    let mut checkpoint =
        Checkpoint::new(origin, tree_size, timestamp, root_hash, [0u8; 64], verifier.key_id());

    // Sign checkpoint
    let blob = checkpoint.to_bytes();
    let signature = signing_key.sign(&blob);
    checkpoint.signature = signature.to_bytes();

    // Create receipt
    let receipt = Receipt {
        spec_version: "1.0.0".to_string(),
        entry: ReceiptEntry { id: Uuid::nil(), payload_hash: format_hash(&payload_hash), metadata },
        proof: ReceiptProof {
            leaf_index: 0,
            tree_size: 1,
            root_hash: format_hash(&root_hash),
            inclusion_path: vec![], // Empty for single leaf
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
        anchors: vec![],
    };

    (receipt, verifying_key.to_bytes(), signing_key)
}

#[test]
fn test_valid_receipt_passes() {
    let (receipt, public_key, _) = create_test_receipt();
    let result = verify_receipt(&receipt, &public_key).unwrap();

    assert!(result.is_valid);
    assert!(result.inclusion_valid);
    assert!(result.signature_valid);
    assert!(result.errors.is_empty());
}

#[test]
fn test_tampered_payload_hash_fails() {
    let (mut receipt, public_key, _) = create_test_receipt();
    receipt.entry.payload_hash = format_hash(&[0xFFu8; 32]);

    let result = verify_receipt(&receipt, &public_key).unwrap();

    assert!(!result.is_valid);
    assert!(!result.inclusion_valid);
}

#[test]
fn test_tampered_metadata_fails() {
    let (mut receipt, public_key, _) = create_test_receipt();
    receipt.entry.metadata = json!({"tampered": true});

    let result = verify_receipt(&receipt, &public_key).unwrap();

    assert!(!result.is_valid);
    assert!(!result.inclusion_valid);
}

#[test]
fn test_tampered_signature_fails() {
    let (mut receipt, public_key, _) = create_test_receipt();

    // Tamper with signature
    let mut sig_bytes = [0u8; 64];
    sig_bytes[0] = 0xFF;
    receipt.proof.checkpoint.signature = format_signature(&sig_bytes);

    let result = verify_receipt(&receipt, &public_key).unwrap();

    assert!(!result.is_valid);
    assert!(!result.signature_valid);
}

#[test]
fn test_wrong_public_key_fails() {
    let (receipt, _, _) = create_test_receipt();
    let wrong_key = [99u8; 32];

    let result = verify_receipt(&receipt, &wrong_key);

    // Should fail at key_id mismatch or signature verification
    assert!(result.is_err() || !result.unwrap().is_valid());
}

#[test]
fn test_root_hash_mismatch_detected() {
    let (mut receipt, public_key, _) = create_test_receipt();
    receipt.proof.root_hash = format_hash(&[0xCCu8; 32]);
    // checkpoint.root_hash is different

    let result = verify_receipt(&receipt, &public_key).unwrap();

    assert!(!result.is_valid);
    assert!(result.errors.iter().any(|e| matches!(e, VerificationError::RootHashMismatch)));
}

#[test]
fn test_tree_size_mismatch_detected() {
    let (mut receipt, public_key, _) = create_test_receipt();
    receipt.proof.tree_size = 999;
    // checkpoint.tree_size is different (1)

    let result = verify_receipt(&receipt, &public_key).unwrap();

    assert!(!result.is_valid);
    assert!(result.errors.iter().any(|e| matches!(e, VerificationError::TreeSizeMismatch)));
}

#[test]
fn test_verify_inclusion_only() {
    let payload_hash = [1u8; 32];
    let metadata = json!({"key": "value"});
    let metadata_hash = canonicalize_and_hash(&metadata);
    let leaf_hash = compute_leaf_hash(&payload_hash, &metadata_hash);

    // Single leaf tree: root = leaf
    let result = verify_inclusion_only(
        &payload_hash,
        &metadata,
        &[],        // empty path for single leaf
        0,          // leaf_index
        1,          // tree_size
        &leaf_hash, // root == leaf for single entry
    );

    assert!(result);
}

#[test]
fn test_verification_result_methods() {
    let result = VerificationResult {
        is_valid: true,
        leaf_hash: [0; 32],
        root_hash: [0; 32],
        tree_size: 1,
        timestamp: 123_456,
        signature_valid: true,
        inclusion_valid: true,
        consistency_valid: None,
        anchor_results: vec![],
        errors: vec![],
    };

    assert!(result.is_valid());
    assert!(!result.has_valid_anchor());
    assert!(result.first_error().is_none());
    assert_eq!(result.errors().len(), 0);
}

#[test]
fn test_verification_result_with_errors() {
    let result = VerificationResult {
        is_valid: false,
        leaf_hash: [0; 32],
        root_hash: [0; 32],
        tree_size: 1,
        timestamp: 123_456,
        signature_valid: false,
        inclusion_valid: false,
        consistency_valid: None,
        anchor_results: vec![],
        errors: vec![VerificationError::SignatureFailed],
    };

    assert!(!result.is_valid());
    assert!(result.first_error().is_some());
    assert_eq!(result.errors().len(), 1);
}

#[test]
fn test_verification_result_with_anchors() {
    let mut result = VerificationResult {
        is_valid: true,
        leaf_hash: [0; 32],
        root_hash: [0; 32],
        tree_size: 1,
        timestamp: 123_456,
        signature_valid: true,
        inclusion_valid: true,
        consistency_valid: None,
        anchor_results: vec![],
        errors: vec![],
    };

    result.anchor_results.push(AnchorVerificationResult {
        anchor_type: "rfc3161".to_string(),
        is_valid: true,
        timestamp: Some(123_456),
        error: None,
    });

    assert!(result.has_valid_anchor());
}

#[test]
fn test_receipt_verifier_with_options() {
    let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    let verifier = CheckpointVerifier::new(signing_key.verifying_key());

    let options =
        VerifyOptions { skip_anchors: true, skip_consistency: true, min_valid_anchors: 0 };

    let _receipt_verifier = ReceiptVerifier::with_options(verifier, options);
    // Note: Cannot test private field directly - options.skip_anchors is private
    // This test verifies that with_options constructor accepts options parameter
}

#[test]
fn test_verify_receipt_json() {
    let (receipt, public_key, _) = create_test_receipt();
    let json = receipt.to_json().unwrap();

    let result = verify_receipt_json(&json, &public_key).unwrap();
    assert!(result.is_valid);
}

#[test]
fn test_invalid_json_returns_error() {
    let public_key = [42u8; 32];
    let result = verify_receipt_json("{invalid json", &public_key);
    assert!(result.is_err());
}

#[test]
fn test_reconstruct_leaf_hash() {
    let payload_hash = [0xAAu8; 32];
    let metadata = json!({"test": "value"});

    let payload_hash_str = format_hash(&payload_hash);
    let result = reconstruct_leaf_hash(&payload_hash_str, &metadata);

    assert!(result.is_ok());
    let leaf_hash = result.unwrap();
    assert_eq!(leaf_hash.len(), 32);
}

#[test]
fn test_reconstruct_leaf_hash_invalid_format() {
    let metadata = json!({"test": "value"});
    let result = reconstruct_leaf_hash("invalid_hash", &metadata);
    assert!(result.is_err());
}

#[test]
fn test_verify_anchor_rfc3161() {
    let anchor = ReceiptAnchor::Rfc3161 {
        target: "data_tree_root".to_string(),
        target_hash: format!("sha256:{}", hex::encode([0u8; 32])),
        tsa_url: "https://freetsa.org/tsr".to_string(),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        token_der: "base64:token".to_string(),
    };
    let root_hash = [0u8; 32];

    let result = verify_anchor(&anchor, &root_hash);
    assert_eq!(result.anchor_type, "rfc3161");

    #[cfg(feature = "rfc3161-verify")]
    {
        assert!(!result.is_valid);
        assert!(result.error.is_some());
    }

    #[cfg(not(feature = "rfc3161-verify"))]
    {
        assert!(!result.is_valid);
        assert_eq!(
            result.error.as_deref(),
            Some("RFC 3161 verification requires 'rfc3161-verify' feature")
        );
    }
}

#[test]
fn test_verify_anchor_bitcoin() {
    let anchor = ReceiptAnchor::BitcoinOts {
        target: "super_root".to_string(),
        target_hash: format!("sha256:{}", hex::encode([0u8; 32])),
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        bitcoin_block_height: 700_000,
        bitcoin_block_time: "2024-01-01T12:00:00Z".to_string(),
        ots_proof: "base64:proof".to_string(),
    };
    let root_hash = [0u8; 32];

    let result = verify_anchor(&anchor, &root_hash);
    assert_eq!(result.anchor_type, "bitcoin_ots");

    #[cfg(feature = "bitcoin-ots")]
    {
        // With feature enabled, invalid proof should fail verification
        assert!(!result.is_valid);
        assert!(result.error.is_some());
    }

    #[cfg(not(feature = "bitcoin-ots"))]
    {
        // Without feature, should fail with feature disabled error
        assert!(!result.is_valid);
        assert_eq!(
            result.error.as_deref(),
            Some("Bitcoin OTS verification requires 'bitcoin-ots' feature")
        );
    }
}

#[test]
fn test_verify_inclusion_only_zero_tree_size() {
    let payload_hash = [1u8; 32];
    let metadata = json!({"key": "value"});

    // Zero tree size should return false (not panic)
    let result = verify_inclusion_only(
        &payload_hash,
        &metadata,
        &[],
        0,
        0, // Invalid tree size
        &[0u8; 32],
    );
    assert!(!result);
}

#[test]
fn test_verify_inclusion_only_index_out_of_bounds() {
    let payload_hash = [1u8; 32];
    let metadata = json!({"key": "value"});

    // Index >= tree_size should return false
    let result = verify_inclusion_only(
        &payload_hash,
        &metadata,
        &[],
        10, // Index
        5,  // Tree size (index >= size)
        &[0u8; 32],
    );
    assert!(!result);
}

#[test]
fn test_verify_inclusion_proof_invalid_structure() {
    let proof = ReceiptProof {
        leaf_index: 0,
        tree_size: 0, // Invalid!
        root_hash: format_hash(&[0u8; 32]),
        inclusion_path: vec![],
        checkpoint: CheckpointJson {
            origin: format_hash(&[0u8; 32]),
            tree_size: 0,
            root_hash: format_hash(&[0u8; 32]),
            timestamp: 0,
            signature: format_signature(&[0u8; 64]),
            key_id: format_hash(&[0u8; 32]),
        },
        consistency_proof: None,
    };

    let leaf_hash = [0u8; 32];
    let result = verify_inclusion_proof(&leaf_hash, &proof);

    // Should return Err, not panic
    assert!(matches!(result, Err(VerificationError::InclusionProofFailed { .. })));
}
