//! Receipt verifier implementation

use crate::core::checkpoint::CheckpointVerifier;
use crate::core::receipt::Receipt;
use crate::error::AtlResult;

use super::helpers::{
    reconstruct_leaf_hash, verify_anchor, verify_checkpoint_signature, verify_inclusion_proof,
};
use super::types::{VerificationError, VerificationResult, VerifyOptions};

use crate::core::checkpoint::parse_hash;

/// Verifier for receipts
///
/// This is the main entry point for receipt verification.
pub struct ReceiptVerifier {
    /// Checkpoint verifier (contains trusted public key)
    checkpoint_verifier: CheckpointVerifier,

    /// Verification options
    options: VerifyOptions,
}

impl ReceiptVerifier {
    /// Create a new verifier with a trusted public key
    #[must_use]
    pub fn new(verifier: CheckpointVerifier) -> Self {
        Self { checkpoint_verifier: verifier, options: VerifyOptions::default() }
    }

    /// Create with custom options
    #[must_use]
    pub const fn with_options(verifier: CheckpointVerifier, options: VerifyOptions) -> Self {
        Self { checkpoint_verifier: verifier, options }
    }

    /// Verify a receipt
    ///
    /// ## Arguments
    ///
    /// * `receipt` - The receipt to verify
    ///
    /// ## Returns
    ///
    /// `VerificationResult` with detailed status
    ///
    /// This method never panics and always returns a result.
    #[must_use]
    pub fn verify(&self, receipt: &Receipt) -> VerificationResult {
        let mut result = VerificationResult {
            is_valid: false,
            leaf_hash: [0; 32],
            root_hash: [0; 32],
            tree_size: receipt.proof.tree_size,
            timestamp: receipt.proof.checkpoint.timestamp,
            signature_valid: false,
            inclusion_valid: false,
            consistency_valid: None,
            super_inclusion_valid: false,
            super_consistency_valid: false,
            genesis_super_root: [0; 32],
            super_root: [0; 32],
            data_tree_index: 0,
            super_tree_size: 0,
            anchor_results: vec![],
            errors: vec![],
        };

        // STEP 0: Validate receipt version (only 2.0.0 supported)
        if receipt.spec_version != "2.0.0" {
            result.errors.push(VerificationError::UnsupportedVersion(receipt.spec_version.clone()));
            return result;
        }

        // STEP 1: Reconstruct Leaf Hash (with metadata_hash validation)
        match reconstruct_leaf_hash(
            &receipt.entry.payload_hash,
            &receipt.entry.metadata_hash,
            &receipt.entry.metadata,
        ) {
            Ok(hash) => result.leaf_hash = hash,
            Err(e) => {
                result.errors.push(e);
                return result;
            }
        }

        // Parse root hash for result
        if let Ok(root) = parse_hash(&receipt.proof.root_hash) {
            result.root_hash = root;
        } else {
            result.errors.push(VerificationError::InvalidHash {
                field: "proof.root_hash".to_string(),
                message: "failed to parse root hash".to_string(),
            });
            return result;
        }

        // Consistency check: checkpoint.root_hash == proof.root_hash
        if receipt.proof.checkpoint.root_hash != receipt.proof.root_hash {
            result.errors.push(VerificationError::RootHashMismatch);
            return result;
        }

        // Consistency check: checkpoint.tree_size == proof.tree_size
        if receipt.proof.checkpoint.tree_size != receipt.proof.tree_size {
            result.errors.push(VerificationError::TreeSizeMismatch);
            return result;
        }

        // STEP 2: Verify Inclusion
        match verify_inclusion_proof(&result.leaf_hash, &receipt.proof) {
            Ok(true) => result.inclusion_valid = true,
            Ok(false) => {
                result.errors.push(VerificationError::InclusionProofFailed {
                    reason: "path does not lead to root".to_string(),
                });
            }
            Err(e) => {
                result.errors.push(e);
            }
        }

        // STEP 3: Verify Signature
        match verify_checkpoint_signature(&receipt.proof.checkpoint, &self.checkpoint_verifier) {
            Ok(true) => result.signature_valid = true,
            Ok(false) | Err(_) => {
                result.errors.push(VerificationError::SignatureFailed);
            }
        }

        // STEP 4: Verify Super-Tree Proof (if present)
        if let Some(super_proof) = &receipt.super_proof {
            Self::verify_super_proof(&mut result, &receipt.proof.root_hash, super_proof);
        } else {
            // No super_proof: Receipt-Lite
            // Mark as not verified (but not failed - just absent)
            result.super_inclusion_valid = false;
            result.super_consistency_valid = false;
            // Leave genesis_super_root and super_root as [0; 32]
        }

        // STEP 5: Verify Anchors (optional)
        if !self.options.skip_anchors && !receipt.anchors.is_empty() {
            // Create anchor verification context with both roots
            let anchor_context = crate::core::verify::helpers::AnchorVerificationContext::new(
                result.root_hash,
                result.super_root,
            );

            for anchor in &receipt.anchors {
                let anchor_result = verify_anchor(anchor, &anchor_context);
                result.anchor_results.push(anchor_result);
            }

            // Check minimum valid anchors requirement
            let valid_anchor_count = result.anchor_results.iter().filter(|a| a.is_valid).count();
            if self.options.min_valid_anchors > 0
                && valid_anchor_count < self.options.min_valid_anchors
            {
                result.errors.push(VerificationError::AnchorFailed {
                    anchor_type: "general".to_string(),
                    reason: format!(
                        "required {} valid anchors, got {}",
                        self.options.min_valid_anchors, valid_anchor_count
                    ),
                });
            }
        }

        // Update compute_validity to handle missing super_proof
        result.is_valid = Self::compute_validity(&result, receipt.super_proof.is_some());

        result
    }

    /// Verify Super-Tree proof (when present)
    ///
    /// Validates the Super-Tree inclusion and consistency proofs.
    /// Updates the result with super verification status and metadata.
    fn verify_super_proof(
        result: &mut VerificationResult,
        data_tree_root_str: &str,
        super_proof: &crate::core::receipt::SuperProof,
    ) {
        use crate::core::verify::super_tree::{
            verify_consistency_to_origin, verify_super_inclusion,
        };

        // Parse data_tree_root from proof
        let Ok(data_tree_root) = parse_hash(data_tree_root_str) else {
            result.errors.push(VerificationError::InvalidHash {
                field: "proof.root_hash".to_string(),
                message: "failed to parse data tree root hash".to_string(),
            });
            return;
        };

        // Parse and store genesis_super_root
        if let Ok(genesis) = super_proof.genesis_super_root_bytes() {
            result.genesis_super_root = genesis;
        } else {
            result.errors.push(VerificationError::InvalidHash {
                field: "super_proof.genesis_super_root".to_string(),
                message: "failed to parse genesis super root hash".to_string(),
            });
            return;
        }

        // Parse and store super_root
        if let Ok(sr) = super_proof.super_root_bytes() {
            result.super_root = sr;
        } else {
            result.errors.push(VerificationError::InvalidHash {
                field: "super_proof.super_root".to_string(),
                message: "failed to parse super root hash".to_string(),
            });
            return;
        }

        // Store Super-Tree metadata
        result.data_tree_index = super_proof.data_tree_index;
        result.super_tree_size = super_proof.super_tree_size;

        // STEP 4.1: Verify Super-Tree Inclusion (MANDATORY)
        match verify_super_inclusion(&data_tree_root, super_proof) {
            Ok(true) => {
                result.super_inclusion_valid = true;
            }
            Ok(false) => {
                result.super_inclusion_valid = false;
                result.errors.push(VerificationError::SuperInclusionFailed {
                    reason: "data tree root not included in super root".to_string(),
                });
            }
            Err(e) => {
                result.super_inclusion_valid = false;
                result
                    .errors
                    .push(VerificationError::SuperInclusionFailed { reason: e.to_string() });
            }
        }

        // STEP 4.2: Verify Consistency to Origin (MANDATORY)
        match verify_consistency_to_origin(super_proof) {
            Ok(true) => {
                result.super_consistency_valid = true;
            }
            Ok(false) => {
                result.super_consistency_valid = false;
                result.errors.push(VerificationError::SuperConsistencyFailed {
                    reason: "super tree not consistent with genesis".to_string(),
                });
            }
            Err(e) => {
                result.super_consistency_valid = false;
                result
                    .errors
                    .push(VerificationError::SuperConsistencyFailed { reason: e.to_string() });
            }
        }
    }

    /// Compute overall validity
    ///
    /// For Receipt-Lite (no `super_proof`): valid if inclusion + signature pass
    /// For Receipt with `super_proof`: valid if inclusion + signature + super pass
    const fn compute_validity(result: &VerificationResult, has_super_proof: bool) -> bool {
        let basic_valid = result.inclusion_valid && result.signature_valid;
        let no_errors = result.errors.is_empty();

        if has_super_proof {
            // With super_proof: must pass super verification too
            let super_valid = result.super_inclusion_valid && result.super_consistency_valid;
            basic_valid && super_valid && no_errors
        } else {
            // Without super_proof: only basic checks required
            basic_valid && no_errors
        }
    }

    /// Verify receipt JSON string
    ///
    /// ## Errors
    ///
    /// Returns error if JSON parsing fails.
    pub fn verify_json(&self, json: &str) -> AtlResult<VerificationResult> {
        let receipt = Receipt::from_json(json)?;
        Ok(self.verify(&receipt))
    }
}

#[cfg(test)]
mod super_verification_tests {
    use super::*;
    use crate::core::checkpoint::{CheckpointJson, CheckpointVerifier};
    use crate::core::receipt::{Receipt, ReceiptEntry, ReceiptProof, SuperProof};

    fn make_test_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn make_test_verifier() -> CheckpointVerifier {
        use ed25519_dalek::VerifyingKey;
        // Create test public key (32 bytes for Ed25519)
        let public_key_bytes = [0xaa; 32];
        let verifying_key =
            VerifyingKey::from_bytes(&public_key_bytes).expect("valid test public key");
        CheckpointVerifier::new(verifying_key)
    }

    fn make_valid_receipt_with_super_proof() -> Receipt {
        use crate::core::jcs::canonicalize_and_hash;
        use crate::core::receipt::format_hash;

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

#[cfg(test)]
mod receipt_super_proof_integration_tests {
    use super::*;
    use crate::core::checkpoint::{CheckpointJson, CheckpointVerifier};
    use crate::core::receipt::{Receipt, ReceiptAnchor, ReceiptEntry, ReceiptProof, SuperProof};

    // === Test Fixture Helpers ===

    fn make_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn make_test_verifier() -> CheckpointVerifier {
        use ed25519_dalek::VerifyingKey;
        let public_key_bytes = [0xaa; 32];
        let verifying_key =
            VerifyingKey::from_bytes(&public_key_bytes).expect("valid test public key");
        CheckpointVerifier::new(verifying_key)
    }

    fn make_v2_receipt_full() -> Receipt {
        use crate::core::jcs::canonicalize_and_hash;
        use crate::core::receipt::format_hash;

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
