//! Tests for verification types

use crate::core::verify::{
    AnchorVerificationResult, SignatureMode, SignatureStatus, VerificationError,
    VerificationResult, VerifyOptions,
};

// ========== VerificationError Display Tests ==========

#[test]
fn test_verification_error_display_invalid_receipt() {
    let error = VerificationError::InvalidReceipt("malformed JSON".to_string());
    let s = format!("{error}");
    assert!(s.contains("Invalid receipt"));
    assert!(s.contains("malformed JSON"));
}

#[test]
fn test_verification_error_display_invalid_hash() {
    let error = VerificationError::InvalidHash {
        field: "root_hash".to_string(),
        message: "not valid hex".to_string(),
    };
    let s = format!("{error}");
    assert!(s.contains("Invalid hash"));
    assert!(s.contains("root_hash"));
    assert!(s.contains("not valid hex"));
}

#[test]
fn test_verification_error_display_signature_failed() {
    let error = VerificationError::SignatureFailed;
    let s = format!("{error}");
    assert!(s.contains("Signature verification failed"));
}

#[test]
fn test_verification_error_display_inclusion_proof_failed() {
    let error = VerificationError::InclusionProofFailed { reason: "path too short".to_string() };
    let s = format!("{error}");
    assert!(s.contains("Inclusion proof failed"));
    assert!(s.contains("path too short"));
}

#[test]
fn test_verification_error_display_consistency_proof_failed() {
    let error = VerificationError::ConsistencyProofFailed { reason: "size mismatch".to_string() };
    let s = format!("{error}");
    assert!(s.contains("Consistency proof failed"));
    assert!(s.contains("size mismatch"));
}

#[test]
fn test_verification_error_display_root_hash_mismatch() {
    let error = VerificationError::RootHashMismatch;
    let s = format!("{error}");
    assert!(s.contains("Root hash mismatch"));
}

#[test]
fn test_verification_error_display_tree_size_mismatch() {
    let error = VerificationError::TreeSizeMismatch;
    let s = format!("{error}");
    assert!(s.contains("Tree size mismatch"));
}

#[test]
fn test_verification_error_display_anchor_failed() {
    let error = VerificationError::AnchorFailed {
        anchor_type: "rfc3161".to_string(),
        reason: "signature invalid".to_string(),
    };
    let s = format!("{error}");
    assert!(s.contains("Anchor verification failed"));
    assert!(s.contains("rfc3161"));
    assert!(s.contains("signature invalid"));
}

#[test]
fn test_verification_error_display_super_inclusion_failed() {
    let error = VerificationError::SuperInclusionFailed { reason: "invalid proof".to_string() };
    let s = format!("{error}");
    assert!(s.contains("Super-Tree inclusion proof failed"));
    assert!(s.contains("invalid proof"));
}

#[test]
fn test_verification_error_display_super_consistency_failed() {
    let error = VerificationError::SuperConsistencyFailed { reason: "path mismatch".to_string() };
    let s = format!("{error}");
    assert!(s.contains("Super-Tree consistency proof failed"));
    assert!(s.contains("path mismatch"));
}

#[test]
fn test_verification_error_display_super_data_mismatch() {
    let error = VerificationError::SuperDataMismatch {
        field: "super_root".to_string(),
        expected: "aabbcc".to_string(),
        actual: "ddeeff".to_string(),
    };
    let s = format!("{error}");
    assert!(s.contains("Super-Tree data mismatch"));
    assert!(s.contains("super_root"));
    assert!(s.contains("aabbcc"));
    assert!(s.contains("ddeeff"));
}

#[test]
fn test_verification_error_display_missing_super_proof() {
    let error = VerificationError::MissingSuperProof;
    let s = format!("{error}");
    assert!(s.contains("Missing super_proof"));
}

#[test]
fn test_verification_error_display_unsupported_version() {
    let error = VerificationError::UnsupportedVersion("3.0.0".to_string());
    let s = format!("{error}");
    assert!(s.contains("Unsupported receipt version"));
    assert!(s.contains("3.0.0"));
}

#[test]
fn test_verification_error_display_metadata_hash_mismatch() {
    let error = VerificationError::MetadataHashMismatch {
        expected: "sha256:aabbcc".to_string(),
        actual: "sha256:ddeeff".to_string(),
    };
    let s = format!("{error}");
    assert!(s.contains("Metadata hash mismatch"));
    assert!(s.contains("aabbcc"));
    assert!(s.contains("ddeeff"));
}

#[test]
fn test_verification_error_display_no_trust_anchor() {
    let error = VerificationError::NoTrustAnchor;
    let s = format!("{error}");
    assert!(s.contains("No trust anchor available"));
}

// ========== VerificationError Equality Tests ==========

#[test]
fn test_verification_error_equality() {
    let e1 = VerificationError::SignatureFailed;
    let e2 = VerificationError::SignatureFailed;
    assert_eq!(e1, e2);

    let e3 = VerificationError::RootHashMismatch;
    assert_ne!(e1, e3);
}

#[test]
fn test_verification_error_clone() {
    let error =
        VerificationError::InvalidHash { field: "test".to_string(), message: "error".to_string() };
    let cloned = error.clone();
    assert_eq!(error, cloned);
}

// ========== VerificationResult Helper Methods Tests ==========

#[test]
fn test_verification_result_is_valid() {
    let result = VerificationResult {
        is_valid: true,
        leaf_hash: [0; 32],
        root_hash: [0; 32],
        tree_size: 1,
        timestamp: 0,
        signature_valid: false,
        signature_status: SignatureStatus::Skipped,
        inclusion_valid: true,
        consistency_valid: None,
        super_inclusion_valid: true,
        super_consistency_valid: true,
        genesis_super_root: [0; 32],
        super_root: [0; 32],
        data_tree_index: 0,
        super_tree_size: 1,
        anchor_results: vec![],
        errors: vec![],
    };

    assert!(result.is_valid());
}

#[test]
fn test_verification_result_has_valid_anchor() {
    let mut result = VerificationResult {
        is_valid: true,
        leaf_hash: [0; 32],
        root_hash: [0; 32],
        tree_size: 1,
        timestamp: 0,
        signature_valid: false,
        signature_status: SignatureStatus::Skipped,
        inclusion_valid: true,
        consistency_valid: None,
        super_inclusion_valid: true,
        super_consistency_valid: true,
        genesis_super_root: [0; 32],
        super_root: [0; 32],
        data_tree_index: 0,
        super_tree_size: 1,
        anchor_results: vec![],
        errors: vec![],
    };

    assert!(!result.has_valid_anchor());

    result.anchor_results.push(AnchorVerificationResult {
        anchor_type: "rfc3161".to_string(),
        is_valid: true,
        timestamp: Some(123_456),
        error: None,
    });

    assert!(result.has_valid_anchor());
}

#[test]
fn test_verification_result_first_error() {
    let mut result = VerificationResult {
        is_valid: false,
        leaf_hash: [0; 32],
        root_hash: [0; 32],
        tree_size: 1,
        timestamp: 0,
        signature_valid: false,
        signature_status: SignatureStatus::Failed,
        inclusion_valid: false,
        consistency_valid: None,
        super_inclusion_valid: true,
        super_consistency_valid: true,
        genesis_super_root: [0; 32],
        super_root: [0; 32],
        data_tree_index: 0,
        super_tree_size: 1,
        anchor_results: vec![],
        errors: vec![],
    };

    assert!(result.first_error().is_none());

    result.errors.push(VerificationError::SignatureFailed);
    result.errors.push(VerificationError::RootHashMismatch);

    assert!(result.first_error().is_some());
    assert_eq!(*result.first_error().unwrap(), VerificationError::SignatureFailed);
}

#[test]
fn test_verification_result_errors() {
    let result = VerificationResult {
        is_valid: false,
        leaf_hash: [0; 32],
        root_hash: [0; 32],
        tree_size: 1,
        timestamp: 0,
        signature_valid: false,
        signature_status: SignatureStatus::Failed,
        inclusion_valid: false,
        consistency_valid: None,
        super_inclusion_valid: true,
        super_consistency_valid: true,
        genesis_super_root: [0; 32],
        super_root: [0; 32],
        data_tree_index: 0,
        super_tree_size: 1,
        anchor_results: vec![],
        errors: vec![VerificationError::SignatureFailed, VerificationError::RootHashMismatch],
    };

    let errors = result.errors();
    assert_eq!(errors.len(), 2);
}

// ========== VerifyOptions Tests ==========

#[test]
fn test_verify_options_custom() {
    let options = VerifyOptions {
        signature_mode: SignatureMode::Require,
        skip_anchors: true,
        skip_consistency: true,
        min_valid_anchors: 2,
    };

    assert_eq!(options.signature_mode, SignatureMode::Require);
    assert!(options.skip_anchors);
    assert!(options.skip_consistency);
    assert_eq!(options.min_valid_anchors, 2);
}

#[test]
#[allow(clippy::redundant_clone)]
fn test_verify_options_clone() {
    let options = VerifyOptions {
        signature_mode: SignatureMode::Optional,
        skip_anchors: false,
        skip_consistency: false,
        min_valid_anchors: 1,
    };

    let cloned = options.clone();
    assert_eq!(cloned.signature_mode, SignatureMode::Optional);
    assert!(!cloned.skip_anchors);
}

// ========== AnchorVerificationResult Tests ==========

#[test]
fn test_anchor_verification_result_valid() {
    let result = AnchorVerificationResult {
        anchor_type: "bitcoin".to_string(),
        is_valid: true,
        timestamp: Some(987_654),
        error: None,
    };

    assert!(result.is_valid);
    assert_eq!(result.anchor_type, "bitcoin");
    assert_eq!(result.timestamp, Some(987_654));
    assert!(result.error.is_none());
}

#[test]
fn test_anchor_verification_result_invalid() {
    let result = AnchorVerificationResult {
        anchor_type: "rfc3161".to_string(),
        is_valid: false,
        timestamp: None,
        error: Some("signature verification failed".to_string()),
    };

    assert!(!result.is_valid);
    assert!(result.error.is_some());
}

#[test]
#[allow(clippy::redundant_clone)]
fn test_anchor_verification_result_clone() {
    let result = AnchorVerificationResult {
        anchor_type: "test".to_string(),
        is_valid: true,
        timestamp: Some(123),
        error: None,
    };

    let cloned = result.clone();
    assert_eq!(cloned.anchor_type, "test");
    assert!(cloned.is_valid);
}

// ========== VerificationResult Clone Tests ==========

#[test]
#[allow(clippy::redundant_clone)]
fn test_verification_result_clone() {
    let result = VerificationResult {
        is_valid: true,
        leaf_hash: [1; 32],
        root_hash: [2; 32],
        tree_size: 10,
        timestamp: 123_456,
        signature_valid: true,
        signature_status: SignatureStatus::Verified,
        inclusion_valid: true,
        consistency_valid: Some(true),
        super_inclusion_valid: true,
        super_consistency_valid: true,
        genesis_super_root: [3; 32],
        super_root: [4; 32],
        data_tree_index: 5,
        super_tree_size: 20,
        anchor_results: vec![],
        errors: vec![],
    };

    let cloned = result.clone();
    assert_eq!(cloned.tree_size, 10);
    assert_eq!(cloned.timestamp, 123_456);
    assert!(cloned.is_valid);
}
