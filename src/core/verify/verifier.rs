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

        // STEP 1: Reconstruct Leaf Hash
        match reconstruct_leaf_hash(&receipt.entry.payload_hash, &receipt.entry.metadata) {
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

        // STEP 4: Verify Super-Tree Proof (MANDATORY - NO SKIP OPTION)
        Self::verify_super_proof(&mut result, &receipt.proof.root_hash, &receipt.super_proof);

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

        // Determine overall validity (includes MANDATORY super verification)
        result.is_valid = Self::compute_validity(&result);

        result
    }

    /// Verify Super-Tree proof (MANDATORY)
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

    /// Compute overall validity (includes MANDATORY super verification)
    ///
    /// A receipt is valid if:
    /// - Basic checks pass (inclusion + signature)
    /// - Super verification passes (inclusion + consistency)
    /// - No errors occurred
    const fn compute_validity(result: &VerificationResult) -> bool {
        // Basic validity: inclusion + signature
        let basic_valid = result.inclusion_valid && result.signature_valid;

        // Super proof validity (MANDATORY - both must be true)
        let super_valid = result.super_inclusion_valid && result.super_consistency_valid;

        // No errors
        let no_errors = result.errors.is_empty();

        basic_valid && super_valid && no_errors
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
        Receipt {
            spec_version: "2.0.0".to_string(),
            upgrade_url: None,
            entry: ReceiptEntry {
                id: uuid::Uuid::nil(),
                payload_hash: make_test_hash(0x11),
                metadata: serde_json::json!({}),
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
            super_proof: SuperProof {
                genesis_super_root: make_test_hash(0x22),
                data_tree_index: 0,
                super_tree_size: 1,
                super_root: make_test_hash(0x22),
                inclusion: vec![],
                consistency_to_origin: vec![],
            },
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
        receipt.super_proof.inclusion = vec![make_test_hash(0xff)];
        receipt.super_proof.super_tree_size = 2;

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
        receipt.super_proof.super_tree_size = 2;
        receipt.super_proof.consistency_to_origin = vec![make_test_hash(0xff)];

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
        receipt.super_proof.genesis_super_root = "invalid".to_string();

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
        receipt.super_proof.super_root = "invalid".to_string();

        let verifier = ReceiptVerifier::new(make_test_verifier());
        let result = verifier.verify(&receipt);

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| matches!(
            e,
            VerificationError::InvalidHash { field, .. } if field == "super_proof.super_root"
        )));
    }
}
