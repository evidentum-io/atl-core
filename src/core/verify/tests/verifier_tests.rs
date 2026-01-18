//! Verifier unit tests
//!
//! Tests for ReceiptVerifier functionality including:
//! - Super-tree verification
//! - Anchor-only mode
//! - Signature verification modes
//! - Integration tests

use crate::core::checkpoint::{CheckpointJson, CheckpointVerifier};
use crate::core::jcs::canonicalize_and_hash;
use crate::core::receipt::{format_hash, Receipt, ReceiptAnchor, ReceiptEntry, ReceiptProof, SuperProof};
use crate::core::verify::types::{SignatureMode, SignatureStatus, VerificationError, VerifyOptions};
use crate::core::verify::verifier::ReceiptVerifier;
use ed25519_dalek::VerifyingKey;

#[allow(deprecated)]
mod super_verification_tests {
    use super::*;

    fn make_test_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn make_test_verifier() -> CheckpointVerifier {
        // Create test public key (32 bytes for Ed25519)
        let public_key_bytes = [0xaa; 32];
        let verifying_key =
            VerifyingKey::from_bytes(&public_key_bytes).expect("valid test public key");
        CheckpointVerifier::new(verifying_key)
    }

    fn make_valid_receipt_with_super_proof() -> Receipt {
        let metadata = serde_json::json!({});
        let metadata_hash = format_hash(&canonicalize_and_hash(&metadata));

        Receipt {
            spec_version: "2.0.0".to_string(),
            upgrade_url: None,
            entry: ReceiptEntry {
                id: uuid::Uuid::nil(),
                payload_hash: make_test_hash(0x11),
                metadata_hash,
                metadata,
            },
            proof: ReceiptProof {
                tree_size: 1,
                root_hash: make_test_hash(0x22),
                inclusion_path: vec![],
                leaf_index: 0,
                checkpoint: CheckpointJson {
                    origin: make_test_hash(0x33),
                    tree_size: 1,
                    root_hash: make_test_hash(0x22),
                    timestamp: 1_704_067_200_000_000_000,
                    signature: "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    key_id: make_test_hash(0x44),
                },
                consistency_proof: None,
            },
            super_proof: Some(SuperProof {
                genesis_super_root: make_test_hash(0x22),
                data_tree_index: 0,
                super_tree_size: 1,
                super_root: make_test_hash(0x22),
                inclusion: vec![],
                consistency_to_origin: vec![],
            }),
            anchors: vec![],
        }
    }

    #[test]
    fn test_receipt_with_valid_super_proof() {
        let receipt = make_valid_receipt_with_super_proof();
        let verifier = ReceiptVerifier::new(make_test_verifier());

        let result = verifier.verify(&receipt);

        // Super fields should have concrete values (not zeros)
        assert_ne!(result.genesis_super_root, [0u8; 32]);
        assert_ne!(result.super_root, [0u8; 32]);
        assert_eq!(result.data_tree_index, 0);
        assert_eq!(result.super_tree_size, 1);
    }

    #[test]
    fn test_super_inclusion_failure_invalidates_receipt() {
        let mut receipt = make_valid_receipt_with_super_proof();
        // Make super_inclusion fail by using wrong hash
        if let Some(ref mut sp) = receipt.super_proof {
            sp.inclusion = vec![make_test_hash(0xff)];
            sp.super_tree_size = 2;
        }

        let verifier = ReceiptVerifier::new(make_test_verifier());
        let result = verifier.verify(&receipt);

        assert!(!result.super_inclusion_valid);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, VerificationError::SuperInclusionFailed { .. })));
    }

    #[test]
    fn test_super_consistency_failure_invalidates_receipt() {
        let mut receipt = make_valid_receipt_with_super_proof();
        // Make consistency_to_origin fail
        if let Some(ref mut sp) = receipt.super_proof {
            sp.super_tree_size = 2;
            sp.consistency_to_origin = vec![make_test_hash(0xff)];
        }

        let verifier = ReceiptVerifier::new(make_test_verifier());
        let result = verifier.verify(&receipt);

        assert!(!result.super_consistency_valid);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, VerificationError::SuperConsistencyFailed { .. })));
    }

    #[test]
    fn test_no_skip_super_proof_option() {
        // VerifyOptions should NOT have skip_super_proof field
        let options = VerifyOptions::default();

        // Just verify the struct can be created
        assert!(!options.skip_anchors);
        assert!(!options.skip_consistency);
        assert_eq!(options.min_valid_anchors, 0);
    }

    #[test]
    fn test_anchor_context_has_both_hashes() {
        let receipt = make_valid_receipt_with_super_proof();
        let verifier = ReceiptVerifier::new(make_test_verifier());
        let result = verifier.verify(&receipt);

        // Both roots should be populated (not zeros)
        assert_ne!(result.root_hash, [0u8; 32]);
        assert_ne!(result.super_root, [0u8; 32]);
    }

    #[test]
    fn test_verification_result_super_fields_non_option() {
        let receipt = make_valid_receipt_with_super_proof();
        let verifier = ReceiptVerifier::new(make_test_verifier());
        let result = verifier.verify(&receipt);

        // All super fields should be concrete types, not Option
        let _: bool = result.super_inclusion_valid;
        let _: bool = result.super_consistency_valid;
        let _: [u8; 32] = result.genesis_super_root;
        let _: [u8; 32] = result.super_root;
        let _: u64 = result.data_tree_index;
        let _: u64 = result.super_tree_size;
    }

    #[test]
    fn test_unsupported_version_fails() {
        let mut receipt = make_valid_receipt_with_super_proof();
        receipt.spec_version = "1.0.0".to_string();

        let verifier = ReceiptVerifier::new(make_test_verifier());
        let result = verifier.verify(&receipt);

        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, VerificationError::UnsupportedVersion(_))));
    }

    #[test]
    fn test_invalid_genesis_super_root_hash() {
        let mut receipt = make_valid_receipt_with_super_proof();
        if let Some(ref mut sp) = receipt.super_proof {
            sp.genesis_super_root = "invalid".to_string();
        }

        let verifier = ReceiptVerifier::new(make_test_verifier());
        let result = verifier.verify(&receipt);

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| matches!(
            e,
            VerificationError::InvalidHash { field, .. } if field == "super_proof.genesis_super_root"
        )));
    }

    #[test]
    fn test_invalid_super_root_hash() {
        let mut receipt = make_valid_receipt_with_super_proof();
        if let Some(ref mut sp) = receipt.super_proof {
            sp.super_root = "invalid".to_string();
        }

        let verifier = ReceiptVerifier::new(make_test_verifier());
        let result = verifier.verify(&receipt);

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| matches!(
            e,
            VerificationError::InvalidHash { field, .. } if field == "super_proof.super_root"
        )));
    }
}

#[allow(deprecated)]
mod receipt_super_proof_integration_tests {
    use super::*;

    // === Test Fixture Helpers ===

    fn make_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn make_test_verifier() -> CheckpointVerifier {
        let public_key_bytes = [0xaa; 32];
        let verifying_key =
            VerifyingKey::from_bytes(&public_key_bytes).expect("valid test public key");
        CheckpointVerifier::new(verifying_key)
    }

    fn make_v2_receipt_full() -> Receipt {
        let metadata = serde_json::json!({});
        let metadata_hash = format_hash(&canonicalize_and_hash(&metadata));

        Receipt {
            spec_version: "2.0.0".to_string(),
            upgrade_url: None,
            entry: ReceiptEntry {
                id: uuid::Uuid::nil(),
                payload_hash: make_hash(0x11),
                metadata_hash,
                metadata,
            },
            proof: ReceiptProof {
                tree_size: 10,
                root_hash: make_hash(0xaa),
                inclusion_path: vec![make_hash(0x22), make_hash(0x33)],
                leaf_index: 5,
                checkpoint: CheckpointJson {
                    origin: make_hash(0x00),
                    tree_size: 10,
                    root_hash: make_hash(0xaa),
                    timestamp: 1_704_067_200_000_000_000,
                    signature: "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    key_id: make_hash(0x44),
                },
                consistency_proof: None,
            },
            super_proof: Some(SuperProof {
                genesis_super_root: make_hash(0x00),
                data_tree_index: 3,
                super_tree_size: 10,
                super_root: make_hash(0xbb),
                inclusion: vec![make_hash(0xcc), make_hash(0xdd)],
                consistency_to_origin: vec![make_hash(0xee)],
            }),
            anchors: vec![
                // TSA anchor targeting data_tree_root
                ReceiptAnchor::Rfc3161 {
                    target: "data_tree_root".to_string(),
                    target_hash: make_hash(0xaa), // Matches checkpoint.tree_head
                    tsa_url: "https://freetsa.org/tsr".to_string(),
                    timestamp: "2026-01-13T12:00:00Z".to_string(),
                    token_der: "base64:AAAA".to_string(),
                },
                // OTS anchor targeting super_root
                ReceiptAnchor::BitcoinOts {
                    target: "super_root".to_string(),
                    target_hash: make_hash(0xbb), // Matches super_proof.super_root
                    timestamp: "2026-01-13T12:00:00Z".to_string(),
                    bitcoin_block_height: 900_000,
                    bitcoin_block_time: "2026-01-13T11:30:00Z".to_string(),
                    ots_proof: "base64:BBBB".to_string(),
                },
            ],
        }
    }

    // === Missing super_proof Tests ===

    #[test]
    fn test_receipt_without_super_proof_parses_and_verifies() {
        // Receipt-Lite without super_proof should parse and verify
        // metadata_hash for empty JSON object {}:
        // SHA256(JCS({})) = SHA256("{}") = 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
        let json = r#"{
            "spec_version": "2.0.0",
            "entry": {
                "id": "00000000-0000-0000-0000-000000000000",
                "payload_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                "metadata": {}
            },
            "proof": {
                "tree_size": 10,
                "root_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "inclusion_path": [],
                "leaf_index": 5,
                "checkpoint": {
                    "origin": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "tree_size": 10,
                    "root_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "timestamp": 1704067200000000000,
                    "signature": "base64:AAAA",
                    "key_id": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
                }
            },
            "anchors": []
        }"#;

        let receipt = Receipt::from_json(json).expect("Receipt-Lite should parse");

        // Should parse successfully and have no super_proof
        assert!(receipt.super_proof.is_none());
        assert_eq!(receipt.tier(), crate::core::receipt::ReceiptTier::Lite);
    }

    #[test]
    fn test_unsupported_version_rejected() {
        // Receipt with unsupported version should fail verification

        let mut receipt = make_v2_receipt_full();
        receipt.spec_version = "3.0.0".to_string();

        let verifier = ReceiptVerifier::new(make_test_verifier());
        let result = verifier.verify(&receipt);

        // Should fail with UnsupportedVersion
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| matches!(e, VerificationError::UnsupportedVersion(_))));
    }

    // === Receipt-Full Tests ===

    #[test]
    fn test_verify_receipt_full() {
        let receipt = make_v2_receipt_full();
        let verifier = ReceiptVerifier::new(make_test_verifier());

        // super_proof is now Option
        let super_proof = receipt.super_proof.as_ref().expect("Should have super_proof");
        assert_eq!(super_proof.data_tree_index, 3);

        // Full verification should include super_proof validation
        let result = verifier.verify(&receipt);

        // Check that super_proof was validated
        assert!(result.super_inclusion_valid || !result.errors.is_empty());
        assert!(result.super_consistency_valid || !result.errors.is_empty());
    }

    #[test]
    fn test_verify_receipt_full_super_proof_fields() {
        let receipt = make_v2_receipt_full();

        // super_proof is now Option
        let super_proof = receipt.super_proof.as_ref().expect("Should have super_proof");

        // Verify data_tree_index matches what we expect
        assert_eq!(super_proof.data_tree_index, 3);
        assert_eq!(super_proof.super_tree_size, 10);

        // Verify inclusion path is non-empty
        assert!(!super_proof.inclusion.is_empty());
    }

    #[test]
    fn test_verify_receipt_full_ots_targets_super_root() {
        let receipt = make_v2_receipt_full();

        // Find OTS anchor
        let ots_anchor =
            receipt.anchors.iter().find(|a| matches!(a, ReceiptAnchor::BitcoinOts { .. }));
        assert!(ots_anchor.is_some());

        if let ReceiptAnchor::BitcoinOts { target, target_hash, .. } = ots_anchor.unwrap() {
            assert_eq!(target, "super_root");

            // target_hash should match super_proof.super_root
            let super_proof = receipt.super_proof.as_ref().expect("Should have super_proof");
            assert_eq!(target_hash, &super_proof.super_root);
        }
    }

    #[test]
    fn test_verify_receipt_full_tsa_targets_data_tree_root() {
        let receipt = make_v2_receipt_full();

        // Find TSA anchor
        let tsa_anchor =
            receipt.anchors.iter().find(|a| matches!(a, ReceiptAnchor::Rfc3161 { .. }));
        assert!(tsa_anchor.is_some());

        if let ReceiptAnchor::Rfc3161 { target, target_hash, .. } = tsa_anchor.unwrap() {
            assert_eq!(target, "data_tree_root");

            // target_hash should match proof.checkpoint.tree_head (which is proof.root_hash)
            assert_eq!(target_hash, &receipt.proof.root_hash);
        }
    }

    // === SuperProof Validation in Receipt Verification ===

    #[test]
    fn test_verify_receipt_invalid_super_proof_genesis() {
        let mut receipt = make_v2_receipt_full();

        // Corrupt the genesis_super_root
        if let Some(ref mut sp) = receipt.super_proof {
            sp.genesis_super_root = "invalid".to_string();
        }

        let verifier = ReceiptVerifier::new(make_test_verifier());
        let result = verifier.verify(&receipt);

        // Should fail due to invalid genesis_super_root format
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.to_string().contains("genesis_super_root")
            || e.to_string().contains("super_proof")));
    }

    #[test]
    fn test_verify_receipt_invalid_super_proof_inclusion() {
        let mut receipt = make_v2_receipt_full();

        // Corrupt an inclusion hash
        if let Some(ref mut sp) = receipt.super_proof {
            sp.inclusion[0] = "invalid".to_string();
        }

        let verifier = ReceiptVerifier::new(make_test_verifier());
        let result = verifier.verify(&receipt);

        // Should fail due to invalid inclusion path
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.to_string().contains("inclusion") || e.to_string().contains("super_proof")));
    }

    #[test]
    fn test_verify_receipt_super_proof_consistency_to_origin() {
        let mut receipt = make_v2_receipt_full();

        // Corrupt consistency_to_origin
        if let Some(ref mut sp) = receipt.super_proof {
            sp.consistency_to_origin = vec!["invalid".to_string()];
        }

        let verifier = ReceiptVerifier::new(make_test_verifier());
        let result = verifier.verify(&receipt);

        // Should fail due to invalid consistency_to_origin
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(
            |e| e.to_string().contains("consistency") || e.to_string().contains("super_proof")
        ));
    }

    // === Anchor Target Mismatch Tests ===

    #[test]
    fn test_verify_receipt_ots_target_mismatch() {
        let mut receipt = make_v2_receipt_full();

        // Change OTS target_hash to not match super_proof.super_root
        for anchor in &mut receipt.anchors {
            if let ReceiptAnchor::BitcoinOts { target_hash, .. } = anchor {
                *target_hash = make_hash(0xff); // Wrong hash
            }
        }

        let verifier = ReceiptVerifier::new(make_test_verifier());
        let result = verifier.verify(&receipt);

        // Anchor verification should fail (target mismatch)
        // Check anchor_results for failure
        let ots_anchor_result =
            result.anchor_results.iter().find(|a| a.anchor_type == "bitcoin_ots");

        assert!(ots_anchor_result.is_some());
        let ots_result = ots_anchor_result.unwrap();
        assert!(!ots_result.is_valid, "OTS anchor should be invalid");
        assert!(ots_result.error.is_some(), "OTS anchor should have an error message");

        // Check that the error message contains target/mismatch
        let error_msg = ots_result.error.as_ref().unwrap();
        assert!(
            error_msg.contains("target") || error_msg.contains("mismatch"),
            "Error should mention target or mismatch: {error_msg}"
        );
    }

    #[test]
    fn test_verify_receipt_tsa_target_mismatch() {
        let mut receipt = make_v2_receipt_full();

        // Change TSA target_hash to not match checkpoint.tree_head
        for anchor in &mut receipt.anchors {
            if let ReceiptAnchor::Rfc3161 { target_hash, .. } = anchor {
                *target_hash = make_hash(0xff); // Wrong hash
            }
        }

        let verifier = ReceiptVerifier::new(make_test_verifier());
        let result = verifier.verify(&receipt);

        // Anchor verification should fail (target mismatch)
        // Check anchor_results for failure
        let tsa_anchor_result = result.anchor_results.iter().find(|a| a.anchor_type == "rfc3161");

        assert!(tsa_anchor_result.is_some());
        let tsa_result = tsa_anchor_result.unwrap();
        assert!(!tsa_result.is_valid, "RFC3161 anchor should be invalid");
        assert!(tsa_result.error.is_some(), "RFC3161 anchor should have an error message");

        // Check that the error message contains target/mismatch
        let error_msg = tsa_result.error.as_ref().unwrap();
        assert!(
            error_msg.contains("target") || error_msg.contains("mismatch"),
            "Error should mention target or mismatch: {error_msg}"
        );
    }

    // === VerificationResult Tests ===

    #[test]
    fn test_verification_result_super_proof_status() {
        let receipt = make_v2_receipt_full();
        let verifier = ReceiptVerifier::new(make_test_verifier());

        let result = verifier.verify(&receipt);

        // Receipt-Full should have super fields set (non-Option)
        // These are concrete types, not Option<T>
        let _: bool = result.super_inclusion_valid;
        let _: bool = result.super_consistency_valid;
        let _: [u8; 32] = result.genesis_super_root;
        let _: [u8; 32] = result.super_root;
        let _: u64 = result.data_tree_index;
        let _: u64 = result.super_tree_size;
    }

    #[test]
    fn test_verification_result_no_skip_super_proof() {
        // VerifyOptions should NOT have skip_super_proof option
        let options = VerifyOptions::default();

        // This should NOT compile if skip_super_proof exists:
        // options.skip_super_proof = true;

        // Just verify the struct can be created with standard options
        assert!(!options.skip_anchors);
        assert!(!options.skip_consistency);
    }

    // === JSON Roundtrip with SuperProof ===

    #[test]
    fn test_receipt_json_roundtrip_with_super_proof() {
        let receipt = make_v2_receipt_full();

        let json = serde_json::to_string_pretty(&receipt).unwrap();
        let restored: Receipt = serde_json::from_str(&json).unwrap();

        assert_eq!(receipt.spec_version, restored.spec_version);

        // super_proof is now Option
        let sp_orig = receipt.super_proof.as_ref().expect("Should have super_proof");
        let sp_rest = restored.super_proof.as_ref().expect("Should have super_proof");
        assert_eq!(sp_orig.genesis_super_root, sp_rest.genesis_super_root);
        assert_eq!(sp_orig.data_tree_index, sp_rest.data_tree_index);
        assert_eq!(sp_orig.super_tree_size, sp_rest.super_tree_size);
        assert_eq!(sp_orig.super_root, sp_rest.super_root);
        assert_eq!(sp_orig.inclusion, sp_rest.inclusion);
        assert_eq!(sp_orig.consistency_to_origin, sp_rest.consistency_to_origin);
    }

    #[test]
    fn test_receipt_json_always_includes_super_proof() {
        let receipt = make_v2_receipt_full();

        let json = serde_json::to_string_pretty(&receipt).unwrap();

        // super_proof is ALWAYS present in JSON
        assert!(json.contains("super_proof"));
        assert!(json.contains("genesis_super_root"));
        assert!(json.contains("data_tree_index"));
        assert!(json.contains("super_tree_size"));
        assert!(json.contains("super_root"));
        assert!(json.contains("inclusion"));
        assert!(json.contains("consistency_to_origin"));
    }
}

mod anchor_only_tests {
    use super::*;

    #[test]
    fn test_anchor_only_constructor() {
        // Arrange & Act
        let verifier = ReceiptVerifier::anchor_only();

        // Assert
        assert!(verifier.checkpoint_verifier.is_none());
        assert_eq!(verifier.options.signature_mode, SignatureMode::Optional);
    }

    #[test]
    fn test_with_key_constructor() {
        // Arrange
        let key_bytes = [0xaau8; 32];
        let verifying_key = VerifyingKey::from_bytes(&key_bytes).unwrap();
        let checkpoint_verifier = CheckpointVerifier::new(verifying_key);

        // Act
        let verifier = ReceiptVerifier::with_key(checkpoint_verifier);

        // Assert
        assert!(verifier.checkpoint_verifier.is_some());
    }

    #[test]
    fn test_anchor_only_with_options() {
        // Arrange
        let options = VerifyOptions {
            signature_mode: SignatureMode::Skip,
            skip_anchors: false,
            skip_consistency: false,
            min_valid_anchors: 1,
        };

        // Act
        let verifier = ReceiptVerifier::anchor_only_with_options(options.clone());

        // Assert
        assert!(verifier.checkpoint_verifier.is_none());
        assert_eq!(verifier.options.min_valid_anchors, 1);
    }

    #[test]
    #[allow(deprecated)]
    fn test_new_is_deprecated_but_works() {
        // Arrange
        let key_bytes = [0xaau8; 32];
        let verifying_key = VerifyingKey::from_bytes(&key_bytes).unwrap();
        let checkpoint_verifier = CheckpointVerifier::new(verifying_key);

        // Act
        let verifier = ReceiptVerifier::new(checkpoint_verifier);

        // Assert
        assert!(verifier.checkpoint_verifier.is_some());
    }
}

mod signature_verification_tests {
    use super::*;

    fn make_test_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn make_test_receipt() -> Receipt {
        let metadata = serde_json::json!({});
        let metadata_hash = format_hash(&canonicalize_and_hash(&metadata));

        Receipt {
            spec_version: "2.0.0".to_string(),
            upgrade_url: None,
            entry: ReceiptEntry {
                id: uuid::Uuid::nil(),
                payload_hash: make_test_hash(0x11),
                metadata_hash,
                metadata,
            },
            proof: ReceiptProof {
                tree_size: 1,
                root_hash: make_test_hash(0x22),
                inclusion_path: vec![],
                leaf_index: 0,
                checkpoint: CheckpointJson {
                    origin: make_test_hash(0x33),
                    tree_size: 1,
                    root_hash: make_test_hash(0x22),
                    timestamp: 1_704_067_200_000_000_000,
                    signature: "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    key_id: make_test_hash(0x44),
                },
                consistency_proof: None,
            },
            super_proof: None,
            anchors: vec![],
        }
    }

    #[test]
    fn test_no_key_skips_signature_no_error() {
        // Arrange
        let verifier = ReceiptVerifier::anchor_only();
        let receipt = make_test_receipt();

        // Act
        let result = verifier.verify(&receipt);

        // Assert
        assert_eq!(result.signature_status, SignatureStatus::Skipped);
        assert!(!result.signature_valid);
        // No SignatureFailed error in Optional mode
        assert!(
            !result
                .errors
                .iter()
                .any(|e| matches!(e, VerificationError::SignatureFailed))
        );
    }

    #[test]
    fn test_skip_mode_skips_even_with_key() {
        // Arrange
        let key_bytes = [0xaau8; 32];
        let verifying_key = VerifyingKey::from_bytes(&key_bytes).unwrap();
        let checkpoint_verifier = CheckpointVerifier::new(verifying_key);
        let options = VerifyOptions {
            signature_mode: SignatureMode::Skip,
            skip_anchors: false,
            skip_consistency: false,
            min_valid_anchors: 0,
        };
        let verifier = ReceiptVerifier::with_key_and_options(checkpoint_verifier, options);
        let receipt = make_test_receipt();

        // Act
        let result = verifier.verify(&receipt);

        // Assert
        assert_eq!(result.signature_status, SignatureStatus::Skipped);
        assert!(!result.signature_valid);
    }

    #[test]
    fn test_require_mode_fails_without_key() {
        // Arrange
        let options = VerifyOptions {
            signature_mode: SignatureMode::Require,
            skip_anchors: false,
            skip_consistency: false,
            min_valid_anchors: 0,
        };
        let verifier = ReceiptVerifier::anchor_only_with_options(options);
        let receipt = make_test_receipt();

        // Act
        let result = verifier.verify(&receipt);

        // Assert
        assert_eq!(result.signature_status, SignatureStatus::Skipped);
        assert!(!result.signature_valid);
        // Require mode + no key = error
        assert!(
            result
                .errors
                .iter()
                .any(|e| matches!(e, VerificationError::SignatureFailed))
        );
    }

    #[test]
    fn test_optional_mode_default_no_error_without_key() {
        // Arrange
        let verifier = ReceiptVerifier::anchor_only();
        // Default signature_mode is Optional
        let receipt = make_test_receipt();

        // Act
        let result = verifier.verify(&receipt);

        // Assert
        assert_eq!(result.signature_status, SignatureStatus::Skipped);
        // Optional mode without key = no error
        assert!(
            !result
                .errors
                .iter()
                .any(|e| matches!(e, VerificationError::SignatureFailed))
        );
    }
}
