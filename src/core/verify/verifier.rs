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
            anchor_results: vec![],
            errors: vec![],
        };

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

        // STEP 4: Verify Anchors (optional)
        if !self.options.skip_anchors {
            for anchor in &receipt.anchors {
                let anchor_result = verify_anchor(anchor, &result.root_hash);
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

        // Determine overall validity
        result.is_valid =
            result.inclusion_valid && result.signature_valid && result.errors.is_empty();

        result
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
