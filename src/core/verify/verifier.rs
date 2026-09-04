//! Receipt verifier implementation

use crate::core::checkpoint::CheckpointVerifier;
use crate::core::receipt::Receipt;
use crate::error::AtlResult;

use super::helpers::{reconstruct_leaf_hash, verify_checkpoint_signature, verify_inclusion_proof};
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
/// The checkpoint signature is an **integrity check**, not a trust anchor, and
/// never substitutes for one. A receipt is accepted when enough of its anchors
/// verify — `max(1, VerifyOptions::min_valid_anchors)`, Section 5.5's floor
/// being one — and nothing is wrong with the receipt itself, regardless of
/// signature status. Anchors that fail verification are reported but do not
/// enter that judgement; see
/// [`VerificationError::is_about_the_receipt`](super::types::VerificationError::is_about_the_receipt).
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
            tree_size: receipt.proof().tree_size,
            timestamp: receipt.proof().checkpoint.timestamp,
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

        // STEP 0: Validate receipt version.
        //
        // Delegated to `is_supported_spec_version` rather than compared
        // here: this gate and the one in `Receipt::from_json` are two doors
        // into the same building, and an inlined literal in each is how they
        // came to disagree with a caller's own gate.
        if !crate::core::receipt::is_supported_spec_version(receipt.spec_version()) {
            result
                .errors
                .push(VerificationError::UnsupportedVersion(receipt.spec_version().to_string()));
            return result;
        }

        // STEP 1: Reconstruct Leaf Hash (with metadata_hash validation)
        match reconstruct_leaf_hash(
            &receipt.entry().payload_hash,
            &receipt.entry().metadata_hash,
            &receipt.entry().metadata,
        ) {
            Ok(hash) => result.leaf_hash = hash,
            Err(e) => {
                result.errors.push(e);
                return result;
            }
        }

        // Parse root hash for result
        if let Ok(root) = parse_hash(&receipt.proof().root_hash) {
            result.root_hash = root;
        } else {
            result.errors.push(VerificationError::InvalidHash {
                field: "proof.root_hash".to_string(),
                message: "failed to parse root hash".to_string(),
            });
            return result;
        }

        // Consistency check: checkpoint.root_hash == proof.root_hash
        if receipt.proof().checkpoint.root_hash != receipt.proof().root_hash {
            result.errors.push(VerificationError::RootHashMismatch);
            return result;
        }

        // Consistency check: checkpoint.tree_size == proof.tree_size
        if receipt.proof().checkpoint.tree_size != receipt.proof().tree_size {
            result.errors.push(VerificationError::TreeSizeMismatch);
            return result;
        }

        // STEP 2: Verify Inclusion
        match verify_inclusion_proof(&result.leaf_hash, receipt.proof()) {
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
        self.verify_signature_step(&receipt.proof().checkpoint, &mut result);

        // STEP 4: Verify Super-Tree Proof (if present)
        if let Some(super_proof) = &receipt.super_proof() {
            Self::verify_super_proof(&mut result, &receipt.proof().root_hash, super_proof);
        } else {
            // No super_proof: Receipt-Lite
            // Mark as not verified (but not failed - just absent)
            result.super_inclusion_valid = false;
            result.super_consistency_valid = false;
            // Leave genesis_super_root and super_root as [0; 32]
        }

        // STEP 5: Verify Anchors (ATL v2.0 Section 5.5)
        //
        // The facts come from the one implementation of Section 5.5 this crate
        // has -- the same one `verify_receipt_anchors` publishes -- so the
        // verdict computed below and the facts a caller reads directly can
        // never disagree about what was checked.
        if !self.options.skip_anchors && !receipt.anchors().is_empty() {
            let facts = super::facts::verify_receipt_anchors(receipt, &self.options);

            // Every refutation reaches the receipt's own error list, wrapped
            // in `AnchorFinding` so that what it is about travels with it.
            //
            // It must be reported: an anchor that was checked and found false
            // is evidence that somebody interfered with the receipt, and until
            // 0.28 it produced no receipt-level error at all unless
            // `min_valid_anchors` happened to be set. `anchor_findings()`
            // exists so that "does not decide the verdict" cannot quietly
            // become "is not shown to anybody".
            //
            // It must NOT move any status of the receipt -- not the verdict,
            // and not "refuted versus merely unevaluated" either. The `anchors`
            // array is covered by neither the leaf hash nor the 98-byte
            // checkpoint blob, so anyone who relays a receipt can append an
            // anchor to it with no key at all -- but only an anchor that
            // *fails* verification, since minting one that passes needs a TSA
            // key and a caller-supplied trust root. Letting a failed anchor
            // veto acceptance would hand every relay a free denial of
            // verification; letting it flip `is_indeterminate` would hand them
            // a free accusation instead, which is the same defect wearing a
            // different hat. Section 5.5 sets a threshold -- "At least one anchor MUST be
            // verified" -- and has no term for the others. See
            // `VerificationError::is_about_the_receipt`.
            //
            // Inabilities are not pushed here at all: an anchor this crate
            // could not finish checking is not a finding, and the caller reads
            // the whole fact set through `verify_receipt_anchors` when it
            // wants them.
            for (index, anchor) in facts.iter().enumerate() {
                result.errors.extend(anchor.refutations().map(|finding| {
                    VerificationError::AnchorFinding {
                        index,
                        anchor_type: anchor.anchor_type().to_string(),
                        finding: Box::new(finding.clone()),
                    }
                }));
            }

            result.anchor_results =
                facts.iter().map(crate::core::verify::helpers::anchor_result_from_facts).collect();
        }

        // ATL v2.0 Section 5.5: "At least one anchor MUST be verified to
        // establish trust in the receipt."
        //
        // A verified checkpoint signature does not substitute, and no longer
        // pretends to. Section 5.4 step 2 says of it "This is an integrity
        // check, not a trust establishment", Section 5.6's own table rates a
        // receipt with no anchors as "internal consistency only", and Section
        // 1.2 states trust is derived "exclusively from external, independent
        // anchors". Counting the log operator's own signature as a trust
        // anchor contradicted all three -- and it is the operator's signature
        // that a transparency log exists to avoid having to believe.
        //
        // # Independent of the anchor array, and exactly one error
        //
        // This runs for every receipt that reaches it -- whatever its `anchors`
        // array holds and whatever else is already in `errors` -- and it is the
        // only place an unmet threshold is reported. Both properties are
        // load-bearing.
        //
        // "That reaches it" is not a weasel: `verify` returns before this point
        // on five receipt-level refutations (an unsupported `spec_version`, a
        // leaf hash that could not be reconstructed, an unparsable
        // `proof.root_hash`, and the two checkpoint-versus-proof mismatches).
        // Skipping the threshold there changes no status, and that is measured
        // rather than assumed: `an_early_return_reports_the_same_statuses_the_\
        // threshold_would` walks every one of those paths, with and without
        // anchors, and compares the statuses against the same result with
        // `NoTrustAnchor` appended. They are identical, because the receipt has
        // no parsed root and therefore no verified anchor either way, and
        // because adding a non-refutation to an error list that already has an
        // entry moves neither `is_valid` nor `is_indeterminate`. What it would
        // add is a suggestion to go and find an anchor, printed over a receipt
        // whose root does not even parse.
        //
        // The quorum check used to live inside the anchor block above, so a
        // receipt with no anchors never reached it: such a receipt got
        // `NoTrustAnchor`, and appending one rubbish anchor moved it into the
        // block and produced a *different* error instead. Since anybody can
        // append an anchor, the receipt's own error set was steerable by a
        // stranger. Nothing here may depend on how many anchors the array
        // happens to hold, nor on which other errors are already present --
        // the guard on `errors` that used to sit here was the same fragility
        // one step removed.
        //
        // It depends on `verified` and only on `verified`, and that dependence
        // is the point rather than an exception to it: a receipt with one
        // verified anchor is *supposed* to differ from one with none, which is
        // the entire reason anchors exist. What may not move the outcome is an
        // anchor that failed verification, and no counting of those happens
        // here.
        //
        // `min_valid_anchors` raises the threshold; it does not create a
        // second kind of failure, so it does not get a second error.
        let required = self.options.min_valid_anchors.max(1);
        let verified = result.anchor_results.iter().filter(|a| a.is_valid).count();
        if verified < required {
            // An inability: not enough was proved, nothing was disproved.
            // See `VerificationError::is_refutation`.
            result.errors.push(VerificationError::NoTrustAnchor { required, verified });
        }

        // The receipt's own bytes were never examined for RFC 8785 Section 3.1
        // duplicate property names. Pushed after the trust-anchor check so it
        // does not mask that diagnosis, and reported as an inability rather
        // than a finding: nothing about the receipt was disproved.
        let source_text_checked = receipt.source_text_was_checked();
        if !source_text_checked {
            result.errors.push(VerificationError::SourceTextNotChecked);
        }

        // Compute final validity
        result.is_valid = source_text_checked
            && Self::compute_validity(&result, &self.options, receipt.super_proof().is_some());

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
    /// 4. **Enough anchors are verified** — `max(1, min_valid_anchors)` of
    ///    them (ATL v2.0 Section 5.5, whose floor of one a caller may raise
    ///    but never lower). A verified checkpoint signature does not
    ///    substitute: Section 5.4 calls it "an integrity check, not a trust
    ///    establishment" and Section 1.2 derives trust "exclusively from
    ///    external, independent anchors".
    ///
    ///    A receipt with no anchors, one verified with `skip_anchors`, one
    ///    whose anchors were all left unresolved and one whose anchors were
    ///    all refuted fail this rule alike, and all of them fail it as
    ///    *inabilities* — reported as the single
    ///    `NoTrustAnchor { required, verified }`, never as a finding against
    ///    the receipt. Not enough was proved; nothing was disproved.
    ///
    /// 5. **Nothing is wrong with the receipt itself** - no error in
    ///    `result.errors` answers
    ///    [`VerificationError::is_about_the_receipt`].
    ///
    ///    Read that precisely. It does **not** say anchor findings are
    ///    unimportant, and it does not drop them: every refutation an anchor
    ///    produced is in `result.errors`, wrapped in
    ///    `VerificationError::AnchorFinding`, listed by
    ///    [`VerificationResult::anchor_findings`], and still a refutation *of
    ///    that anchor*. What it says is that such a finding cannot *subtract*
    ///    from Rule 4 -- nor move any other status: the same exclusion governs
    ///    [`VerificationResult::is_indeterminate`], because scoping only this
    ///    rule would leave a stranger able to relabel the receipt instead of
    ///    rejecting it.
    ///
    ///    The reason is structural. A receipt's `anchors` array is covered by
    ///    neither the leaf hash (`SHA256(0x00 || payload_hash ||
    ///    metadata_hash)`) nor the 98-byte checkpoint blob (origin, tree size,
    ///    timestamp, root hash). Nothing signs it and nothing hashes it, so
    ///    anybody through whose hands a receipt passes can append an anchor to
    ///    it without a key. If an appended anchor that *fails* verification
    ///    could veto the verdict, one malformed token would destroy the
    ///    verification of a receipt holding a flawless independent anchor -- a
    ///    denial of verification available to every relay, for free. An anchor
    ///    nobody could verify reports on itself and on nothing else; it cannot
    ///    undo an existence in time that another anchor established.
    ///
    ///    The converse is not claimed and must not be: an appended anchor that
    ///    *does* verify raises `verified` and can carry a receipt over the
    ///    Rule 4 threshold. That is what anchors are for. What is guaranteed
    ///    is one-sided -- an anchor that fails verification changes nothing
    ///    about the receipt -- and one-sided is exactly what a stranger with
    ///    no key can reach.
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

        // Rule 4: enough *verified* anchors, and nothing else counts.
        //
        // The threshold is `max(1, min_valid_anchors)` -- Section 5.5's floor,
        // which a caller may raise but never lower. Written the same way here
        // as at the site that reports it, so the verdict and the reported
        // `NoTrustAnchor { required, verified }` cannot disagree about what
        // was asked for.
        //
        // The log operator's own signature used to satisfy this, which made a
        // receipt with no external attestation at all -- the tier Section 5.6
        // rates "internal consistency only" -- indistinguishable from one a
        // TSA had timestamped. A transparency log exists precisely so that the
        // operator's word is not what a verifier has to believe.
        if result.anchor_results.iter().filter(|a| a.is_valid).count()
            < options.min_valid_anchors.max(1)
        {
            return false;
        }

        // Rule 5: nothing is wrong with the receipt itself.
        //
        // Anchor findings are excluded from this conjunct -- and from
        // `is_indeterminate`, which reads the same `receipt_errors()`, because
        // a status a stranger can flip is no better than a verdict a stranger
        // can flip. They are excluded from nothing else: they remain in
        // `errors`, they remain refutations *of their anchor*, and they remain
        // the caller's evidence that a receipt was interfered with. See the
        // rule's documentation above for why an anchor that failed
        // verification may not decide a verdict.
        !result.errors.iter().any(VerificationError::is_about_the_receipt)
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
            claimed_timestamp: Some(1),
            error: None,
        }
    }

    fn make_invalid_anchor() -> AnchorVerificationResult {
        AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            is_valid: false,
            // An invalid anchor establishes nothing, so it may only carry a
            // claim.
            timestamp: None,
            claimed_timestamp: Some(1),
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

    /// **The denial-of-verification case, and the rule that closes it.**
    ///
    /// A receipt's `anchors` array is authenticated by nothing: the leaf hash
    /// is `SHA256(0x00 || payload_hash || metadata_hash)` and the checkpoint
    /// blob is 98 bytes of origin, tree size, timestamp and root hash. Neither
    /// covers the anchors, so anybody who relays a receipt can append one
    /// without a key.
    ///
    /// A verdict that let an appended anchor which *fails* verification veto
    /// acceptance would therefore be destructible for free: one malformed
    /// token appended to a receipt holding a flawless independent anchor, and
    /// the receipt stops verifying. An anchor nobody could verify reports on
    /// itself and on nothing else; it cannot undo an existence in time that
    /// another anchor established, and it does not make the receipt refuted
    /// either — see [`VerificationResult::is_indeterminate`].
    ///
    /// So: **the verdict stands, and the finding is still reported.** Both
    /// halves are asserted here, because dropping the finding would conceal
    /// exactly the interference it is evidence of.
    ///
    /// This is a `compute_validity` test rather than an end-to-end one for a
    /// reason worth stating: reaching acceptance through `verify` needs a
    /// receipt whose Merkle root is a real timestamp token's `messageImprint`
    /// *and* whose leaf hash is that same root, which is a SHA-256 preimage.
    /// Minting a token over a root chosen by the test needs a TSA private key,
    /// which this crate deliberately has none of. The end-to-end complement --
    /// that appending an anchor which *fails* verification changes neither the
    /// verdict nor any receipt-level error, whatever the base verdict is -- is
    /// `an_unverified_appended_anchor_changes_no_status_of_the_receipt`.
    #[test]
    fn an_appended_refuted_anchor_does_not_veto_a_verified_one() {
        let appended = || VerificationError::AnchorFinding {
            index: 1,
            anchor_type: "rfc3161".to_string(),
            finding: Box::new(VerificationError::AnchorPayloadUndecodable {
                anchor_type: "rfc3161".to_string(),
                reason: "not a timestamp token".to_string(),
            }),
        };

        let mut result = make_base_result();
        result.anchor_results.push(make_valid_anchor());
        // Anyone at all can add these two lines to a receipt in transit.
        result.anchor_results.push(make_invalid_anchor());
        result.errors.push(appended());
        let options = VerifyOptions::default();

        assert!(
            ReceiptVerifier::compute_validity(&result, &options, false),
            "rubbish appended beside a verified anchor must not destroy the verdict"
        );

        // Reported, not swallowed -- and still a refutation *of the anchor*,
        // so a consumer can say that this token was checked and found false
        // rather than left unresolved. It does not make the *receipt* refuted:
        // `is_indeterminate` reads `receipt_errors()`, which excludes anchor
        // findings by construction.
        assert!(result.errors.iter().any(VerificationError::is_refutation));
        assert!(!appended().is_about_the_receipt());
        assert!(appended().is_refutation(), "the wrapper takes its kind from what it wraps");

        // The rule is about *additional* anchors, not about the threshold:
        // strip the verified one and the receipt is no longer accepted.
        result.anchor_results.remove(0);
        assert!(!ReceiptVerifier::compute_validity(&result, &options, false));
    }

    /// **The positive half of the anchor guarantee, where it can be stated
    /// exactly.**
    ///
    /// The invariant guarded elsewhere is one-sided: an anchor that *fails*
    /// verification changes no status of the receipt. Taken alone that is
    /// indistinguishable from a verifier in which anchors change nothing at
    /// all, so the other side has to be pinned too — a **verified** anchor
    /// raises the count and carries the receipt over the Section 5.5
    /// threshold, and one more of them clears a caller-raised quorum.
    ///
    /// Stated here rather than end-to-end because the end-to-end version needs
    /// timestamp tokens minted over roots the test chooses, one per anchor.
    /// This crate holds captured real tokens and no TSA key, so `required: 2`
    /// has no fixture and never will; the integration half that *is*
    /// expressible is
    /// `rfc3161_trust_store_integration_tests::a_verified_anchor_reaching_the_threshold_clears_the_finding`.
    #[test]
    fn reaching_the_quorum_with_a_second_verified_anchor_accepts_the_receipt() {
        let options = VerifyOptions { min_valid_anchors: 2, ..VerifyOptions::default() };

        // One verified anchor against a quorum of two: short, so not accepted.
        let mut result = make_base_result();
        result.anchor_results.push(make_valid_anchor());
        assert!(!ReceiptVerifier::compute_validity(&result, &options, false));

        // The second verified anchor is exactly what anchors are for.
        result.anchor_results.push(make_valid_anchor());
        assert!(
            ReceiptVerifier::compute_validity(&result, &options, false),
            "a verified anchor must be able to carry a receipt over the threshold"
        );

        // And the same two anchors satisfy the Section 5.5 floor on their own.
        assert!(ReceiptVerifier::compute_validity(&result, &VerifyOptions::default(), false));

        // A *third* anchor that failed verification changes none of it.
        result.anchor_results.push(make_invalid_anchor());
        result.errors.push(VerificationError::AnchorFinding {
            index: 2,
            anchor_type: "rfc3161".to_string(),
            finding: Box::new(VerificationError::AnchorPayloadUndecodable {
                anchor_type: "rfc3161".to_string(),
                reason: "not a timestamp token".to_string(),
            }),
        });
        assert!(ReceiptVerifier::compute_validity(&result, &options, false));
    }

    /// A receipt-level error still decides the verdict, and still makes the
    /// result *refuted* rather than unevaluated. Only anchor findings are
    /// excluded from either. Asserted next to the test above so the exclusion
    /// cannot be misread as "errors no longer matter".
    #[test]
    fn a_receipt_level_error_still_decides_the_verdict() {
        let mut result = make_base_result();
        result.anchor_results.push(make_valid_anchor());
        result.errors.push(VerificationError::MetadataHashMismatch {
            expected: "sha256:00".to_string(),
            actual: "sha256:11".to_string(),
        });

        assert!(!ReceiptVerifier::compute_validity(&result, &VerifyOptions::default(), false));
    }

    /// **ATL v2.0 Section 5.5, Rule 4.** An anchor that is present but not
    /// verified does not establish trust, however it came to be unverified.
    ///
    /// "Could not evaluate" is not "checked", and neither is "was checked and
    /// is false". The rule counts *verified* anchors and nothing else; which
    /// kind of not-verified an anchor is decides how the outcome is
    /// **described** (see `VerificationResult::is_indeterminate`), never
    /// whether trust was established.
    #[test]
    fn an_unverified_anchor_does_not_establish_trust() {
        let mut result = make_base_result();
        result.anchor_results.push(make_invalid_anchor());
        let options = VerifyOptions::default();

        assert!(!ReceiptVerifier::compute_validity(&result, &options, false));

        // And the same result with one verified anchor is accepted, so the
        // rule is a floor and not a blanket refusal.
        result.anchor_results.push(make_valid_anchor());
        assert!(ReceiptVerifier::compute_validity(&result, &options, false));
    }

    /// **ATL v2.0 Section 5.5.** A verified checkpoint signature is not a
    /// trust anchor, in any signature mode. Section 5.4 calls it "an
    /// integrity check, not a trust establishment"; Section 1.2 derives trust
    /// "exclusively from external, independent anchors"; Section 5.6 rates a
    /// receipt with no anchors as "internal consistency only".
    ///
    /// Until 0.28 this crate accepted such a receipt, which meant a log
    /// operator could produce evidence that verified against nothing but its
    /// own key -- the one thing a transparency log exists so a verifier need
    /// not believe.
    #[test]
    fn a_verified_signature_is_not_a_trust_anchor_in_any_mode() {
        for mode in [SignatureMode::Require, SignatureMode::Optional, SignatureMode::Skip] {
            let mut result = make_base_result();
            result.signature_status = SignatureStatus::Verified;
            result.signature_valid = true;
            let options = VerifyOptions { signature_mode: mode, ..Default::default() };

            assert!(
                !ReceiptVerifier::compute_validity(&result, &options, false),
                "{mode:?}: a signature alone must not establish trust"
            );

            // The same receipt with one verified anchor is accepted, so what
            // is being refused is the *substitution*, not the receipt.
            result.anchor_results.push(make_valid_anchor());
            assert!(
                ReceiptVerifier::compute_validity(&result, &options, false),
                "{mode:?}: one verified anchor satisfies Section 5.5"
            );
        }
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
        let error = VerificationError::NoTrustAnchor { required: 1, verified: 0 };

        // Act
        let display = error.to_string();

        // Assert
        assert!(display.contains("trust") || display.contains("anchor"));
    }
}
