//! Integration tests for lib.rs exports and constants

use atl_core::*;

// ========== Version Constants Tests ==========

#[test]
fn test_version_constant() {
    assert!(!VERSION.is_empty());
    assert!(VERSION.contains('.'));
}

#[test]
fn test_protocol_version_constant() {
    assert_eq!(PROTOCOL_VERSION, "2.0.0");
}

#[test]
fn test_receipt_version_constant() {
    assert_eq!(RECEIPT_VERSION, "2.0.0");
}

// ========== Merkle Exports Tests ==========

#[test]
fn test_merkle_constants_accessible() {
    assert_eq!(LEAF_PREFIX, 0x00);
    assert_eq!(NODE_PREFIX, 0x01);
    assert_eq!(GENESIS_DOMAIN, b"ATL-CHAIN-v1");
}

#[test]
fn test_merkle_functions_accessible() {
    let hash = [0u8; 32];
    let leaf = compute_leaf_hash(&hash, &hash);
    assert_eq!(leaf.len(), 32);

    let root = compute_root(&[leaf]);
    assert_eq!(root, leaf);

    let children = hash_children(&hash, &hash);
    assert_eq!(children.len(), 32);
}

#[test]
fn test_merkle_proof_accessible() {
    // Verify inclusion proof functions are accessible
    let hash = [0u8; 32];
    let proof = InclusionProof { leaf_index: 0, tree_size: 1, path: vec![] };
    assert!(verify_inclusion(&hash, &proof, &hash).is_ok());
}

#[test]
fn test_genesis_leaf_hash() {
    let root = [5u8; 32];
    let size = 10;
    let hash = compute_genesis_leaf_hash(&root, size);
    assert_eq!(hash.len(), 32);

    // Should be deterministic
    let hash2 = compute_genesis_leaf_hash(&root, size);
    assert_eq!(hash, hash2);
}

// ========== Checkpoint Exports Tests ==========

#[test]
fn test_checkpoint_constants() {
    assert_eq!(CHECKPOINT_MAGIC, b"ATL-Protocol-v1-CP");
    assert_eq!(CHECKPOINT_BLOB_SIZE, 98);
}

#[test]
fn test_checkpoint_id_functions() {
    use uuid::Uuid;

    let key_bytes = [42u8; 32];
    let key_id = compute_key_id(&key_bytes);
    assert_eq!(key_id.len(), 32);

    let uuid = Uuid::nil();
    let origin_id = compute_origin_id(&uuid);
    assert_eq!(origin_id.len(), 32);
}

// ========== Receipt Exports Tests ==========

#[test]
fn test_receipt_spec_version() {
    assert_eq!(RECEIPT_SPEC_VERSION, "2.0.0");
}

#[test]
fn test_anchor_target_constants() {
    assert_eq!(ANCHOR_TARGET_DATA_TREE_ROOT, "data_tree_root");
    assert_eq!(ANCHOR_TARGET_SUPER_ROOT, "super_root");
}

#[test]
fn test_receipt_tier_names() {
    assert_eq!(ReceiptTier::Lite.name(), "Receipt-Lite");
    assert_eq!(ReceiptTier::Full.name(), "Receipt-Full");
}

// ========== Verification Exports Tests ==========

#[test]
fn test_signature_mode_default() {
    let mode = SignatureMode::default();
    assert_eq!(mode, SignatureMode::Optional);
}

#[test]
fn test_signature_status_default() {
    let status = SignatureStatus::default();
    assert_eq!(status, SignatureStatus::Skipped);
}

#[test]
fn test_verify_options_default() {
    let options = VerifyOptions::default();
    assert_eq!(options.signature_mode, SignatureMode::Optional);
    assert!(!options.skip_anchors);
    assert!(!options.skip_consistency);
    assert_eq!(options.min_valid_anchors, 0);
}

// ========== JCS Export Tests ==========

#[test]
fn test_jcs_canonicalize() {
    let json = serde_json::json!({"b": 2, "a": 1});
    let canonical = canonicalize(&json);
    assert_eq!(canonical, r#"{"a":1,"b":2}"#);
}

#[test]
fn test_jcs_hash() {
    let json = serde_json::json!({"test": "data"});
    let hash = canonicalize_and_hash(&json);
    assert_eq!(hash.len(), 32);

    // Should be deterministic
    let hash2 = canonicalize_and_hash(&json);
    assert_eq!(hash, hash2);
}

// ========== Type Accessibility Tests ==========

#[test]
fn test_all_main_types_accessible() {
    // Merkle types
    let _: Hash = [0u8; 32];
    let _ = Leaf { payload_hash: [0u8; 32], metadata_hash: [1u8; 32] };
    let _ = TreeHead { tree_size: 1, root_hash: [0u8; 32] };
    let _ = InclusionProof { leaf_index: 0, tree_size: 1, path: vec![] };
    let _ = ConsistencyProof { from_size: 1, to_size: 2, path: vec![] };

    // Receipt types
    let _ = ReceiptTier::Full;

    // Verify types
    let _ = SignatureMode::Optional;
    let _ = SignatureStatus::Skipped;
}

#[test]
fn test_super_verification_result_accessible() {
    let result = SuperVerificationResult::valid([0u8; 32], [1u8; 32]);
    assert!(result.inclusion_valid);
    assert!(result.consistency_valid);
    assert_eq!(result.genesis_super_root, [0u8; 32]);
    assert_eq!(result.super_root, [1u8; 32]);
}

#[test]
fn test_anchor_verification_context_accessible() {
    let ctx = AnchorVerificationContext::new([0u8; 32], [1u8; 32]);
    assert!(ctx.expected_hash_for_target("data_tree_root").is_some());
    assert!(ctx.expected_hash_for_target("super_root").is_some());
}

// ========== Deprecated Functions Still Work ==========

#[allow(deprecated)]
#[test]
fn test_deprecated_exports_accessible() {
    // Just verify they compile and are accessible
    let _ = verify_receipt;
    let _ = verify_receipt_json;
}

// ========== Cross-Receipt Types ==========

#[test]
fn test_cross_receipt_result_methods() {
    let result = CrossReceiptVerificationResult {
        same_log_instance: true,
        history_consistent: true,
        genesis_super_root: [0u8; 32],
        receipt_a_index: 1,
        receipt_b_index: 2,
        receipt_a_super_tree_size: 5,
        receipt_b_super_tree_size: 10,
        errors: vec![],
    };

    assert!(result.is_valid());
    assert!(result.same_log_instance);
    assert!(result.history_consistent);
}

#[test]
fn test_cross_receipt_ordering() {
    use std::cmp::Ordering;

    let result = CrossReceiptVerificationResult {
        same_log_instance: true,
        history_consistent: true,
        genesis_super_root: [0u8; 32],
        receipt_a_index: 5,
        receipt_b_index: 10,
        receipt_a_super_tree_size: 10,
        receipt_b_super_tree_size: 15,
        errors: vec![],
    };

    let ordering = result.ordering();
    assert_eq!(ordering, Ordering::Less);
}

// ========== Feature-gated Tests ==========

#[cfg(feature = "bitcoin-ots")]
#[test]
fn test_ots_module_accessible() {
    use atl_core::ots::*;
    // Just verify the module and types are accessible when feature is enabled
    let _ = BITCOIN_TAG;
    let _ = PENDING_TAG;
}

#[cfg(feature = "rfc3161-verify")]
#[test]
fn test_rfc3161_types_accessible() {
    // Verify types are accessible when feature is enabled
    let _: Option<Rfc3161VerifyResult> = None;
    let _: Option<ParsedTimestampToken> = None;
}

// ========== Prelude Tests ==========

#[test]
fn test_prelude_exports() {
    use atl_core::prelude::*;

    // Verify main types are accessible via prelude
    let _ = ReceiptTier::Lite;
    let _ = SignatureMode::Optional;

    // Verify functions accessible
    let hash = canonicalize_and_hash(&serde_json::json!({}));
    assert_eq!(hash.len(), 32);

    // Verify more types
    let _ = SuperProof {
        genesis_super_root: String::new(),
        data_tree_index: 0,
        super_tree_size: 1,
        super_root: String::new(),
        inclusion: vec![],
        consistency_to_origin: vec![],
    };

    let _ = AnchorVerificationContext::new([0u8; 32], [1u8; 32]);
}

#[test]
fn test_prelude_verification_functions() {
    use atl_core::prelude::*;

    // Verify verification functions are accessible
    let _ = verify_super_inclusion;
    let _ = verify_consistency_to_origin;
    let _ = verify_cross_receipts;
    let _ = verify_receipt_anchor_only;
}

// ========== Error Types ==========

#[test]
fn test_error_types_accessible() {
    let _: AtlError = AtlError::InvalidHash("test".to_string());
    let _: AtlResult<()> = Ok(());
}

#[test]
fn test_verification_error_types() {
    let error = VerificationError::SignatureFailed;
    let s = format!("{error}");
    assert!(!s.is_empty());
}
