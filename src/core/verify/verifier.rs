//! Receipt verifier implementation

use crate::core::checkpoint::CheckpointVerifier;
use crate::core::receipt::Receipt;
use crate::error::AtlResult;

use super::helpers::{
    reconstruct_leaf_hash, verify_anchor, verify_checkpoint_signature, verify_inclusion_proof,
};
use super::types::{VerificationError, VerificationResult, VerifyOptions};

use crate::core::checkpoint::parse_hash;

/// Verifier for ATL receipts
///
/// Supports two verification modes per ATL Protocol v2.0:
///
/// 1. **Anchor-only verification** (no key required):
///    ```rust,no_run
///    use atl_core::ReceiptVerifier;
///
///    # let receipt = todo!();
///    let verifier = ReceiptVerifier::anchor_only();
///    let result = verifier.verify(&receipt);
///    // Trust established via RFC 3161 or Bitcoin anchors
///    ```
///
/// 2. **Key-based verification** (optional additional integrity check):
///    ```rust,no_run
///    use atl_core::{CheckpointVerifier, ReceiptVerifier};
///
///    # let checkpoint_verifier = CheckpointVerifier::from_bytes(&[0u8; 32]).unwrap();
///    # let receipt = todo!();
///    let verifier = ReceiptVerifier::with_key(checkpoint_verifier);
///    let result = verifier.verify(&receipt);
///    // Additional checkpoint signature verification
///    ```
///
/// ## Trust Model
///
/// Per ATL Protocol v2.0 Section 1.2:
/// > "Verifiers do NOT need to trust the Log Operator. Trust is derived
/// > exclusively from external, independent anchors."
///
/// The checkpoint signature is an **integrity check**, not a trust anchor.
/// A receipt is valid if its anchors verify, regardless of signature status.
pub struct ReceiptVerifier {
    /// Optional checkpoint verifier (contains public key)
    ///
    /// When `None`, signature verification is skipped.
    pub(crate) checkpoint_verifier: Option<CheckpointVerifier>,

    /// Verification options
    pub(crate) options: VerifyOptions,
}

impl ReceiptVerifier {
    /// Create a verifier for anchor-only verification (no public key required)
    ///
    /// This is the recommended constructor for first-time verification of
    /// receipts from unknown Log Operators. Trust is established through
    /// external anchors (RFC 3161 TSA or Bitcoin OTS).
    ///
    /// ## Example
    ///
    /// ```rust
    /// use atl_core::ReceiptVerifier;
    ///
    /// let verifier = ReceiptVerifier::anchor_only();
    /// # let receipt = atl_core::Receipt::from_json(r#"{"spec_version":"2.0.0","entry":{"id":"00000000-0000-0000-0000-000000000000","payload_hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111","metadata_hash":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","metadata":{}},"proof":{"tree_size":1,"root_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","inclusion_path":[],"leaf_index":0,"checkpoint":{"origin":"sha256:0000000000000000000000000000000000000000000000000000000000000000","tree_size":1,"root_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestamp":1704067200000000000,"signature":"base64:AAAA","key_id":"sha256:4444444444444444444444444444444444444444444444444444444444444444"}},"anchors":[]}"#).unwrap();
    /// let result = verifier.verify(&receipt);
    ///
    /// if result.is_valid && result.has_valid_anchor() {
    ///     println!("Receipt verified via anchor!");
    /// }
    /// ```
    ///
    /// ## Protocol Reference
    ///
    /// ATL Protocol v2.0 Section 6.2:
    /// > "There is no requirement for out-of-band key distribution. A Verifier
    /// > encountering a receipt for the first time can fully validate it using
    /// > only the anchor verification."
    #[must_use]
    pub fn anchor_only() -> Self {
        Self { checkpoint_verifier: None, options: VerifyOptions::default() }
    }

    /// Create a verifier with a trusted public key
    ///
    /// Use this constructor when you have a known, trusted public key for
    /// the Log Operator. The signature provides an additional integrity check
    /// on top of anchor verification.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use atl_core::{CheckpointVerifier, ReceiptVerifier};
    ///
    /// # let key_bytes = [0u8; 32];
    /// let checkpoint_verifier = CheckpointVerifier::from_bytes(&key_bytes)?;
    /// let verifier = ReceiptVerifier::with_key(checkpoint_verifier);
    /// # Ok::<(), atl_core::AtlError>(())
    /// ```
    ///
    /// ## Note
    ///
    /// Per ATL Protocol v2.0, the signature is an **integrity check**, not
    /// a trust anchor. Even with a valid key, trust ultimately comes from
    /// the external anchors.
    #[must_use]
    pub fn with_key(verifier: CheckpointVerifier) -> Self {
        Self { checkpoint_verifier: Some(verifier), options: VerifyOptions::default() }
    }

    /// Create verifier with custom options (anchor-only)
    #[must_use]
    pub const fn anchor_only_with_options(options: VerifyOptions) -> Self {
        Self { checkpoint_verifier: None, options }
    }

    /// Create verifier with key and custom options
    #[must_use]
    pub const fn with_key_and_options(
        verifier: CheckpointVerifier,
        options: VerifyOptions,
    ) -> Self {
        Self { checkpoint_verifier: Some(verifier), options }
    }

    /// Create a new verifier with a trusted public key
    ///
    /// ## Deprecated
    ///
    /// Use [`anchor_only()`](Self::anchor_only) for anchor-only verification,
    /// or [`with_key()`](Self::with_key) for explicit key-based verification.
    ///
    /// This function is equivalent to `with_key()` but the name doesn't
    /// clearly communicate whether a key is required.
    #[deprecated(
        since = "0.5.0",
        note = "Use `ReceiptVerifier::anchor_only()` or `ReceiptVerifier::with_key()` instead"
    )]
    #[must_use]
    pub fn new(verifier: CheckpointVerifier) -> Self {
        Self::with_key(verifier)
    }

    /// Create with custom options
    ///
    /// ## Deprecated
    ///
    /// Use [`anchor_only_with_options()`](Self::anchor_only_with_options) or
    /// [`with_key_and_options()`](Self::with_key_and_options) instead.
    #[deprecated(
        since = "0.5.0",
        note = "Use `anchor_only_with_options()` or `with_key_and_options()` instead"
    )]
    #[must_use]
    pub const fn with_options(verifier: CheckpointVerifier, options: VerifyOptions) -> Self {
        Self::with_key_and_options(verifier, options)
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
        use super::types::SignatureStatus;

        let mut result = VerificationResult {
            is_valid: false,
            leaf_hash: [0; 32],
            root_hash: [0; 32],
            tree_size: receipt.proof.tree_size,
            timestamp: receipt.proof.checkpoint.timestamp,
            signature_valid: false,
            signature_status: SignatureStatus::Skipped,
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

        // STEP 3: Verify Signature (updated logic)
        self.verify_signature_step(&receipt.proof.checkpoint, &mut result);

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

        // Check trust anchor availability (before compute_validity)
        let has_anchor_trust = result.anchor_results.iter().any(|a| a.is_valid);
        let has_signature_trust = result.signature_status == SignatureStatus::Verified;

        if !has_anchor_trust && !has_signature_trust && result.errors.is_empty() {
            // Add informative error about missing trust anchor
            result.errors.push(VerificationError::NoTrustAnchor);
        }

        // Compute final validity
        result.is_valid =
            Self::compute_validity(&result, &self.options, receipt.super_proof.is_some());

        result
    }

    /// Verify checkpoint signature based on key availability and mode
    ///
    /// This method handles signature verification according to the configured
    /// `SignatureMode` and updates the `VerificationResult` accordingly.
    ///
    /// ## Logic
    ///
    /// - If no key provided: `signature_status = Skipped`, no error added
    /// - If `SignatureMode::Skip`: `signature_status = Skipped`
    /// - If key provided and mode is not Skip: attempt verification
    ///   - On success: `signature_status = Verified`, `signature_valid = true`
    ///   - On failure: `signature_status = Failed`, error added if `Require` mode
    ///   - On key mismatch: `signature_status = KeyMismatch`, error added if `Require` mode
    fn verify_signature_step(
        &self,
        checkpoint: &crate::core::checkpoint::CheckpointJson,
        result: &mut VerificationResult,
    ) {
        use super::types::{SignatureMode, SignatureStatus};

        // Case 1: No key provided -> skip
        let Some(verifier) = &self.checkpoint_verifier else {
            result.signature_status = SignatureStatus::Skipped;
            result.signature_valid = false;
            // In Require mode, add error for missing key
            if self.options.signature_mode == SignatureMode::Require {
                result.errors.push(VerificationError::SignatureFailed);
            }
            return;
        };

        // Case 2: Skip mode -> skip
        if self.options.signature_mode == SignatureMode::Skip {
            result.signature_status = SignatureStatus::Skipped;
            result.signature_valid = false;
            return;
        }

        // Case 3: Attempt verification
        match verify_checkpoint_signature(checkpoint, verifier) {
            Ok(true) => {
                result.signature_status = SignatureStatus::Verified;
                result.signature_valid = true;
            }
            Ok(false) => {
                // This shouldn't happen (verify returns Err on failure)
                result.signature_status = SignatureStatus::Failed;
                result.signature_valid = false;
                if self.options.signature_mode == SignatureMode::Require {
                    result.errors.push(VerificationError::SignatureFailed);
                }
            }
            Err(VerificationError::SignatureFailed) => {
                result.signature_status = SignatureStatus::Failed;
                result.signature_valid = false;
                if self.options.signature_mode == SignatureMode::Require {
                    result.errors.push(VerificationError::SignatureFailed);
                }
            }
            Err(_) => {
                // Key mismatch or other error
                result.signature_status = SignatureStatus::KeyMismatch;
                result.signature_valid = false;
                if self.options.signature_mode == SignatureMode::Require {
                    result.errors.push(VerificationError::SignatureFailed);
                }
            }
        }
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

    /// Compute overall validity according to ATL Protocol v2.0 trust model
    ///
    /// # Trust Model
    ///
    /// Per ATL Protocol v2.0 Section 1.2:
    /// > "Verifiers do NOT need to trust the Log Operator. Trust is derived
    /// > exclusively from external, independent anchors."
    ///
    /// # Validity Rules
    ///
    /// A receipt is valid if ALL of the following are true:
    ///
    /// 1. **Inclusion proof passes** - The entry is verifiably in the Merkle tree.
    ///
    /// 2. **Super-Tree proof passes (if present)** - For Receipt-Full, the data tree
    ///    is verifiably part of the Super-Tree with valid consistency to origin.
    ///
    /// 3. **Signature requirement met (based on mode)**:
    ///    - `Require`: `signature_status` must be `Verified`
    ///    - `Optional`: Any status is acceptable
    ///    - `Skip`: Any status is acceptable
    ///
    /// 4. **Trust anchor exists**:
    ///    - Either verified signature (in `Require` mode), OR
    ///    - At least one valid external anchor (RFC 3161 or Bitcoin OTS)
    ///
    /// 5. **No verification errors** - `result.errors` is empty.
    ///
    /// # Protocol Reference
    ///
    /// Section 5.2:
    /// > "Even if the checkpoint signature cannot be verified (unknown key),
    /// > the receipt MAY still be valid if anchor verification succeeds."
    ///
    /// Section 5.5:
    /// > "A receipt without any verified anchors SHOULD be treated as untrustworthy."
    fn compute_validity(
        result: &VerificationResult,
        options: &VerifyOptions,
        has_super_proof: bool,
    ) -> bool {
        use super::types::{SignatureMode, SignatureStatus};

        // Rule 1: Inclusion must pass
        if !result.inclusion_valid {
            return false;
        }

        // Rule 2: Super-Tree must pass (if present)
        if has_super_proof && (!result.super_inclusion_valid || !result.super_consistency_valid) {
            return false;
        }

        // Rule 3: Check signature based on mode
        if options.signature_mode == SignatureMode::Require
            && result.signature_status != SignatureStatus::Verified
        {
            return false;
        }

        // Rule 4: Trust anchor required
        // A verified signature (in any mode except Skip) is a trust anchor
        // Additionally, any valid external anchor also provides trust
        let has_signature_trust = result.signature_status == SignatureStatus::Verified;
        let has_anchor_trust = result.anchor_results.iter().any(|a| a.is_valid);

        if !has_signature_trust && !has_anchor_trust {
            // No trust anchor available
            return false;
        }

        // Rule 5: No errors
        result.errors.is_empty()
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
mod compute_validity_tests {
    use super::*;
    use crate::core::verify::types::{
        AnchorVerificationResult, SignatureMode, SignatureStatus, VerificationError,
        VerificationResult, VerifyOptions,
    };

    fn make_base_result() -> VerificationResult {
        VerificationResult {
            is_valid: false,
            leaf_hash: [0; 32],
            root_hash: [0; 32],
            tree_size: 1,
            timestamp: 1,
            signature_valid: false,
            signature_status: SignatureStatus::Skipped,
            inclusion_valid: true, // Start valid
            consistency_valid: None,
            super_inclusion_valid: true,
            super_consistency_valid: true,
            genesis_super_root: [0; 32],
            super_root: [0; 32],
            data_tree_index: 0,
            super_tree_size: 1,
            anchor_results: vec![],
            errors: vec![],
        }
    }

    fn make_valid_anchor() -> AnchorVerificationResult {
        AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            is_valid: true,
            timestamp: Some(1),
            error: None,
        }
    }

    fn make_invalid_anchor() -> AnchorVerificationResult {
        AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            is_valid: false,
            timestamp: Some(1),
            error: Some("failed".to_string()),
        }
    }

    // Rule 1: Inclusion must pass

    #[test]
    fn test_inclusion_false_always_invalid() {
        // Arrange
        let mut result = make_base_result();
        result.inclusion_valid = false;
        result.anchor_results.push(make_valid_anchor());
        let options = VerifyOptions::default();

        // Act
        let valid = ReceiptVerifier::compute_validity(&result, &options, false);

        // Assert
        assert!(!valid);
    }

    // Rule 2: Super-Tree must pass

    #[test]
    fn test_super_inclusion_false_invalid_when_has_proof() {
        // Arrange
        let mut result = make_base_result();
        result.super_inclusion_valid = false;
        result.anchor_results.push(make_valid_anchor());
        let options = VerifyOptions::default();

        // Act
        let valid = ReceiptVerifier::compute_validity(&result, &options, true);

        // Assert
        assert!(!valid);
    }

    #[test]
    fn test_super_consistency_false_invalid_when_has_proof() {
        // Arrange
        let mut result = make_base_result();
        result.super_consistency_valid = false;
        result.anchor_results.push(make_valid_anchor());
        let options = VerifyOptions::default();

        // Act
        let valid = ReceiptVerifier::compute_validity(&result, &options, true);

        // Assert
        assert!(!valid);
    }

    // Rule 3: Signature based on mode

    #[test]
    fn test_require_mode_needs_verified_signature() {
        // Arrange
        let mut result = make_base_result();
        result.signature_status = SignatureStatus::Skipped;
        result.anchor_results.push(make_valid_anchor());
        let options =
            VerifyOptions { signature_mode: SignatureMode::Require, ..Default::default() };

        // Act
        let valid = ReceiptVerifier::compute_validity(&result, &options, false);

        // Assert
        assert!(!valid); // Skipped != Verified
    }

    #[test]
    fn test_require_mode_verified_is_valid() {
        // Arrange
        let mut result = make_base_result();
        result.signature_status = SignatureStatus::Verified;
        result.signature_valid = true;
        // No anchor needed - verified signature is trust anchor
        let options =
            VerifyOptions { signature_mode: SignatureMode::Require, ..Default::default() };

        // Act
        let valid = ReceiptVerifier::compute_validity(&result, &options, false);

        // Assert
        assert!(valid);
    }

    #[test]
    fn test_optional_mode_verified_is_valid_without_anchor() {
        // Arrange
        let mut result = make_base_result();
        result.signature_status = SignatureStatus::Verified;
        result.signature_valid = true;
        // Verified signature is trust anchor in any mode
        let options =
            VerifyOptions { signature_mode: SignatureMode::Optional, ..Default::default() };

        // Act
        let valid = ReceiptVerifier::compute_validity(&result, &options, false);

        // Assert
        assert!(valid);
    }

    #[test]
    fn test_optional_mode_skipped_valid_with_anchor() {
        // Arrange
        let mut result = make_base_result();
        result.signature_status = SignatureStatus::Skipped;
        result.anchor_results.push(make_valid_anchor());
        let options =
            VerifyOptions { signature_mode: SignatureMode::Optional, ..Default::default() };

        // Act
        let valid = ReceiptVerifier::compute_validity(&result, &options, false);

        // Assert
        assert!(valid); // Protocol compliance: anchor is enough
    }

    #[test]
    fn test_optional_mode_failed_valid_with_anchor() {
        // Arrange
        let mut result = make_base_result();
        result.signature_status = SignatureStatus::Failed;
        result.anchor_results.push(make_valid_anchor());
        let options =
            VerifyOptions { signature_mode: SignatureMode::Optional, ..Default::default() };

        // Act
        let valid = ReceiptVerifier::compute_validity(&result, &options, false);

        // Assert
        assert!(valid); // Protocol: signature failure doesn't invalidate
    }

    #[test]
    fn test_skip_mode_valid_with_anchor() {
        // Arrange
        let mut result = make_base_result();
        result.signature_status = SignatureStatus::Skipped;
        result.anchor_results.push(make_valid_anchor());
        let options = VerifyOptions { signature_mode: SignatureMode::Skip, ..Default::default() };

        // Act
        let valid = ReceiptVerifier::compute_validity(&result, &options, false);

        // Assert
        assert!(valid);
    }

    // Rule 4: Trust anchor required

    #[test]
    fn test_no_anchor_no_signature_invalid() {
        // Arrange
        let mut result = make_base_result();
        result.signature_status = SignatureStatus::Skipped;
        // No anchors
        let options = VerifyOptions::default();

        // Act
        let valid = ReceiptVerifier::compute_validity(&result, &options, false);

        // Assert
        assert!(!valid); // No trust anchor
    }

    #[test]
    fn test_invalid_anchor_only_invalid() {
        // Arrange
        let mut result = make_base_result();
        result.signature_status = SignatureStatus::Skipped;
        result.anchor_results.push(make_invalid_anchor());
        let options = VerifyOptions::default();

        // Act
        let valid = ReceiptVerifier::compute_validity(&result, &options, false);

        // Assert
        assert!(!valid); // Invalid anchor doesn't count
    }

    // Rule 5: No errors

    #[test]
    fn test_errors_invalidate() {
        // Arrange
        let mut result = make_base_result();
        result.anchor_results.push(make_valid_anchor());
        result.errors.push(VerificationError::RootHashMismatch);
        let options = VerifyOptions::default();

        // Act
        let valid = ReceiptVerifier::compute_validity(&result, &options, false);

        // Assert
        assert!(!valid);
    }

    // Protocol compliance: key scenario

    #[test]
    fn test_protocol_compliance_anchor_only_verification() {
        // Scenario: First-time verifier with no knowledge of Log Operator
        // Protocol says this MUST work if anchors verify

        // Arrange
        let mut result = make_base_result();
        result.signature_status = SignatureStatus::Skipped; // No key provided
        result.signature_valid = false;
        result.anchor_results.push(make_valid_anchor()); // TSA anchor verifies
        let options = VerifyOptions::default(); // Optional mode

        // Act
        let valid = ReceiptVerifier::compute_validity(&result, &options, false);

        // Assert
        assert!(valid, "Protocol violation: anchor-only verification must work");
    }
}

#[cfg(test)]
mod no_trust_anchor_error_tests {
    use crate::core::verify::types::VerificationError;

    #[test]
    fn test_no_trust_anchor_error_display() {
        // Arrange
        let error = VerificationError::NoTrustAnchor;

        // Act
        let display = error.to_string();

        // Assert
        assert!(display.contains("trust") || display.contains("anchor"));
    }
}
