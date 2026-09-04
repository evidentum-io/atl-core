//! Internal helper functions for receipt verification
//!
//! This module contains internal verification helper functions
//! that support the main verification logic in `ReceiptVerifier`.

use crate::core::checkpoint::{parse_hash, parse_signature, Checkpoint, CheckpointVerifier};
use crate::core::jcs::canonicalize_and_hash;
use crate::core::merkle::{compute_leaf_hash, verify_inclusion, InclusionProof};
#[cfg(test)]
use crate::core::receipt::ReceiptAnchor;
use crate::core::receipt::{format_hash, ANCHOR_TARGET_DATA_TREE_ROOT, ANCHOR_TARGET_SUPER_ROOT};

use super::{AnchorVerificationResult, VerificationError};

/// Hash type (32 bytes)
pub type Hash = [u8; 32];

/// Context for anchor verification
///
/// Contains the expected hash values for different anchor targets.
/// Both `data_tree_root` and `super_root` are REQUIRED for v2.0 receipts.
#[derive(Debug, Clone)]
pub struct AnchorVerificationContext {
    /// Data Tree root hash (from `proof.root_hash`) - REQUIRED
    pub data_tree_root: Hash,

    /// Super-Tree root hash (from `super_proof.super_root`) - REQUIRED
    pub super_root: Hash,

    /// Trust material for RFC 3161 anchor chain verification.
    ///
    /// `None` (the default) means an RFC 3161 anchor can, at best, reach
    /// `TerminalAnchor::Assumed` -- never `Trusted` -- regardless of how
    /// cryptographically sound the token is. This is never populated from
    /// anything found inside the receipt or the token itself; it only ever
    /// carries what the caller explicitly supplied via
    /// [`VerifyOptions::rfc3161_trust_store`](super::types::VerifyOptions::rfc3161_trust_store).
    #[cfg(feature = "rfc3161-verify")]
    pub rfc3161_trust_store: Option<crate::core::verify::anchors::rfc3161::TrustStore>,
}

impl AnchorVerificationContext {
    /// Create context for v2.0 receipt (mandatory fields)
    #[must_use]
    pub const fn new(data_tree_root: Hash, super_root: Hash) -> Self {
        Self {
            data_tree_root,
            super_root,
            #[cfg(feature = "rfc3161-verify")]
            rfc3161_trust_store: None,
        }
    }

    /// Attach caller-supplied RFC 3161 trust material.
    ///
    /// Never call this with a certificate extracted from the token being
    /// verified -- see the type-level note above.
    #[cfg(feature = "rfc3161-verify")]
    #[must_use]
    pub fn with_rfc3161_trust_store(
        mut self,
        store: crate::core::verify::anchors::rfc3161::TrustStore,
    ) -> Self {
        self.rfc3161_trust_store = Some(store);
        self
    }

    /// Get expected hash for target
    ///
    /// Returns the expected hash based on anchor target:
    /// - `"data_tree_root"` -> `self.data_tree_root`
    /// - `"super_root"` -> `self.super_root`
    #[must_use]
    #[allow(dead_code)] // Used in tests, may be used by future callers
    pub fn expected_hash_for_target(&self, target: &str) -> Option<&Hash> {
        match target {
            ANCHOR_TARGET_DATA_TREE_ROOT => Some(&self.data_tree_root),
            ANCHOR_TARGET_SUPER_ROOT => Some(&self.super_root),
            _ => None,
        }
    }
}

// ========== Internal Helper Functions ==========

/// Reconstruct leaf hash from payload hash, `metadata_hash`, and metadata
///
/// STEP 1 of verification algorithm:
/// 1. Decode `payload_hash` from "sha256:..."
/// 2. Compute `computed_metadata_hash` = SHA256(JCS(metadata))
/// 3. Decode and validate `metadata_hash` from receipt
/// 4. Compute `leaf_hash` = SHA256(0x00 || `payload_hash` || `metadata_hash`)
pub fn reconstruct_leaf_hash(
    payload_hash_str: &str,
    metadata_hash_str: &str,
    metadata: &serde_json::Value,
) -> Result<[u8; 32], VerificationError> {
    // Decode payload hash
    let payload_hash =
        parse_hash(payload_hash_str).map_err(|e| VerificationError::InvalidHash {
            field: "entry.payload_hash".to_string(),
            message: e.to_string(),
        })?;

    // Decode metadata hash from receipt
    let metadata_hash_from_receipt =
        parse_hash(metadata_hash_str).map_err(|e| VerificationError::InvalidHash {
            field: "entry.metadata_hash".to_string(),
            message: e.to_string(),
        })?;

    // Compute metadata hash via JCS.
    //
    // A refusal here is NOT a mismatch: nothing was compared. The metadata
    // breaks an RFC 8785 Section 3.1 input constraint, so no canonical form
    // and no hash exist. Mapping it onto `MetadataHashMismatch` would report
    // a contradiction that was never observed.
    let computed_metadata_hash = canonicalize_and_hash(metadata).map_err(|e| match e {
        crate::error::AtlError::JcsInputConstraint { path, reason } => {
            VerificationError::MetadataNotCanonicalizable {
                path: format!("/entry/metadata{path}"),
                reason,
            }
        }
        other => VerificationError::MetadataNotCanonicalizable {
            path: "/entry/metadata".to_string(),
            reason: other.to_string(),
        },
    })?;

    // Validate metadata hash matches
    if metadata_hash_from_receipt != computed_metadata_hash {
        return Err(VerificationError::MetadataHashMismatch {
            expected: metadata_hash_str.to_string(),
            actual: format_hash(&computed_metadata_hash),
        });
    }

    // Compute leaf hash: SHA256(0x00 || payload_hash || metadata_hash)
    Ok(compute_leaf_hash(&payload_hash, &computed_metadata_hash))
}

/// Verify inclusion proof
///
/// STEP 2 of verification algorithm:
/// Uses RFC 6962 path validation to verify the leaf is included in the tree.
pub fn verify_inclusion_proof(
    leaf_hash: &[u8; 32],
    proof: &crate::core::receipt::ReceiptProof,
) -> Result<bool, VerificationError> {
    // Parse inclusion path
    let path: Vec<[u8; 32]> =
        proof.inclusion_path.iter().map(|h| parse_hash(h)).collect::<Result<Vec<_>, _>>().map_err(
            |e| VerificationError::InvalidHash {
                field: "proof.inclusion_path".to_string(),
                message: e.to_string(),
            },
        )?;

    // Parse expected root
    let expected_root =
        parse_hash(&proof.root_hash).map_err(|e| VerificationError::InvalidHash {
            field: "proof.root_hash".to_string(),
            message: e.to_string(),
        })?;

    // Verify using Merkle module
    let inclusion_proof =
        InclusionProof { leaf_index: proof.leaf_index, tree_size: proof.tree_size, path };

    verify_inclusion(leaf_hash, &inclusion_proof, &expected_root)
        .map_err(|e| VerificationError::InclusionProofFailed { reason: e.to_string() })
}

/// Verify checkpoint signature
///
/// STEP 3 of verification algorithm:
/// Verifies the Ed25519 signature on the checkpoint using the trusted public key.
pub fn verify_checkpoint_signature(
    checkpoint: &crate::core::checkpoint::CheckpointJson,
    verifier: &CheckpointVerifier,
) -> Result<bool, VerificationError> {
    // Build Checkpoint from CheckpointJson
    let origin = parse_hash(&checkpoint.origin).map_err(|_| VerificationError::SignatureFailed)?;
    let root_hash =
        parse_hash(&checkpoint.root_hash).map_err(|_| VerificationError::SignatureFailed)?;
    let signature =
        parse_signature(&checkpoint.signature).map_err(|_| VerificationError::SignatureFailed)?;
    let key_id = parse_hash(&checkpoint.key_id).map_err(|_| VerificationError::SignatureFailed)?;

    let mut cp = Checkpoint::new(
        origin,
        checkpoint.tree_size,
        checkpoint.timestamp,
        root_hash,
        [0; 64],
        key_id,
    );
    cp.signature = signature;

    // Verify signature
    cp.verify(verifier).map(|()| true).map_err(|_| VerificationError::SignatureFailed)
}

/// Verify a single anchor
///
/// Updated for ATL Protocol v2.0 with MANDATORY target field validation.
///
/// # Arguments
///
/// * `anchor` - The anchor to verify
/// * `context` - Verification context with expected hashes
///
/// # v2.0 Target Validation (MANDATORY)
///
/// For RFC 3161 anchors:
/// - `target` MUST be `"data_tree_root"` (ERROR if absent or different)
/// - `target_hash` MUST match `context.data_tree_root` (ERROR if absent or mismatch)
///
/// For Bitcoin OTS anchors:
/// - `target` MUST be `"super_root"` (ERROR if absent or different)
/// - `target_hash` MUST match `context.super_root` (ERROR if absent or mismatch)
/// # One implementation, two shapes
///
/// The checks themselves live in [`super::facts::anchor_facts`], which reports
/// them as a fact set rather than a boolean. This function is the adapter that
/// keeps [`AnchorVerificationResult`]'s long-standing shape: there is no
/// second copy of ATL Section 5.5 behind it, so a defect fixed for
/// [`verify_receipt_anchors`](super::facts::verify_receipt_anchors) is fixed
/// here too.
///
/// The receipt-level verifier no longer routes through here -- it takes the
/// whole `Vec<AnchorFacts>` and projects each one -- so this remains as the
/// single-anchor entry point the tests exercise. It was never reachable from
/// outside the crate.
#[cfg(test)]
pub fn verify_anchor(
    anchor: &ReceiptAnchor,
    context: &AnchorVerificationContext,
) -> AnchorVerificationResult {
    // The root this anchor must pin to, taken from the context the caller
    // already resolved. `verify_receipt_anchors` resolves it from the receipt
    // instead; the pinning comparison itself is the same code either way.
    let expected_root = match anchor {
        ReceiptAnchor::Rfc3161 { .. } => Ok(context.data_tree_root),
        ReceiptAnchor::BitcoinOts { .. } => Ok(context.super_root),
    };

    #[allow(unused_mut)]
    let mut options = super::types::VerifyOptions::default();
    #[cfg(feature = "rfc3161-verify")]
    {
        options.rfc3161_trust_store = context.rfc3161_trust_store.clone();
    }

    let facts = super::facts::anchor_facts(anchor, expected_root, &options);
    anchor_result_from_facts(&facts)
}

/// Project an [`AnchorFacts`](super::facts::AnchorFacts) onto the
/// [`AnchorVerificationResult`] shape callers have had since 0.5.
///
/// # `is_valid` means [`AnchorFacts::is_verified`] and nothing looser
///
/// There is no carve-out. An anchor is `is_valid` when **every** check about
/// it came out verified; a refutation and an unfinished check both make it
/// `false`, and the fact set says which.
///
/// Up to and including 0.28 this projection tolerated one inability:
/// `atl-core` performs no I/O, so it never obtains the Bitcoin block header
/// whose Merkle root would confirm an OTS proof, and a `bitcoin_ots` anchor
/// was nevertheless reported `is_valid: true` on the strength of a proof
/// nothing had compared against a block. Preserving that for compatibility
/// would have kept a verdict the crate's own facts contradict, so it is gone.
/// A `bitcoin_ots` anchor is `is_valid: false` from this crate under every
/// input — see [`VerificationError::BitcoinBlockNotObtained`] — and a caller
/// that fetches headers resolves it on its own side.
pub(in crate::core) fn anchor_result_from_facts(
    facts: &super::facts::AnchorFacts,
) -> AnchorVerificationResult {
    let is_valid = facts.is_verified();

    let error = if is_valid { None } else { Some(anchor_error_from_facts(facts)) };

    AnchorVerificationResult {
        anchor_type: facts.anchor_type().to_string(),
        is_valid,
        // A time is established only by an anchor every one of whose checks
        // passed -- which a `bitcoin_ots` anchor never is here, because the
        // confirming block header was not fetched. The claim is never
        // discarded; it moves to `claimed_timestamp`.
        timestamp: facts.established_timestamp(),
        claimed_timestamp: facts.claimed_timestamp(),
        error,
    }
}

/// The human-readable elaboration [`AnchorVerificationResult::error`] has
/// always carried. Never load-bearing: branch on the facts, not on this text.
fn anchor_error_from_facts(facts: &super::facts::AnchorFacts) -> String {
    // An RFC 3161 token that decoded gets the dedicated prose, which explains
    // the fact set as a whole rather than listing it.
    #[cfg(feature = "rfc3161-verify")]
    if let super::facts::AnchorEvidence::Rfc3161(token_facts) = facts.evidence() {
        return super::anchors::rfc3161::summarize(token_facts);
    }

    let findings = facts.findings();
    if findings.is_empty() {
        return "verification did not reach aggregate success".to_string();
    }
    findings.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ")
}

/// Verify one RFC 3161 anchor given its fields, for the tests that exercise
/// ATL Section 5.5.1 steps 1-2 field by field.
///
/// A thin adapter over [`verify_anchor`]: it assembles the anchor and runs the
/// same code every caller runs. `tsa_url` is not part of any check, so a
/// placeholder is supplied.
#[cfg(test)]
fn verify_rfc3161_anchor(
    target: &str,
    target_hash: &str,
    timestamp: &str,
    token_der: &str,
    context: &AnchorVerificationContext,
) -> AnchorVerificationResult {
    verify_anchor(
        &ReceiptAnchor::Rfc3161 {
            target: target.to_string(),
            target_hash: target_hash.to_string(),
            tsa_url: String::new(),
            timestamp: timestamp.to_string(),
            token_der: token_der.to_string(),
        },
        context,
    )
}

/// The Bitcoin OTS counterpart of [`verify_rfc3161_anchor`], for the tests
/// that exercise ATL Section 5.5.2 steps 1-2 and step 5's height half.
#[cfg(test)]
fn verify_bitcoin_ots_anchor(
    target: &str,
    target_hash: &str,
    timestamp: &str,
    claimed_block_height: u64,
    ots_proof: &str,
    context: &AnchorVerificationContext,
) -> AnchorVerificationResult {
    verify_anchor(
        &ReceiptAnchor::BitcoinOts {
            target: target.to_string(),
            target_hash: target_hash.to_string(),
            timestamp: timestamp.to_string(),
            bitcoin_block_height: claimed_block_height,
            bitcoin_block_time: String::new(),
            ots_proof: ots_proof.to_string(),
        },
        context,
    )
}

#[cfg(test)]
mod rfc3161_target_tests {
    use super::*;

    fn make_test_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn hash_from_byte(byte: u8) -> Hash {
        [byte; 32]
    }

    fn make_context() -> AnchorVerificationContext {
        AnchorVerificationContext::new(
            hash_from_byte(0xaa), // data_tree_root
            hash_from_byte(0xbb), // super_root
        )
    }

    #[test]
    fn test_rfc3161_v2_correct_target() {
        let context = make_context();

        let result = verify_rfc3161_anchor(
            "data_tree_root",
            &make_test_hash(0xaa),
            "2026-01-13T12:00:00Z",
            "base64:AAAA",
            &context,
        );

        // Target validation should pass (actual TSA verification may fail)
        // Error should NOT mention target
        if !result.is_valid {
            let error = result.error.as_ref().unwrap();
            assert!(!error.contains("target must be"));
            assert!(!error.contains("target_hash mismatch"));
        }
    }

    #[test]
    fn test_rfc3161_wrong_target_fails() {
        let context = make_context();

        let result = verify_rfc3161_anchor(
            "super_root", // Wrong! Should be "data_tree_root"
            &make_test_hash(0xaa),
            "2026-01-13T12:00:00Z",
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("must be 'data_tree_root'"));
    }

    #[test]
    fn test_rfc3161_target_hash_mismatch_fails() {
        let context = make_context(); // expects 0xaa

        let result = verify_rfc3161_anchor(
            "data_tree_root",
            &make_test_hash(0xff), // Wrong hash!
            "2026-01-13T12:00:00Z",
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("target_hash mismatch"));
    }

    #[test]
    fn test_rfc3161_invalid_target_hash_format_fails() {
        let context = make_context();

        let result = verify_rfc3161_anchor(
            "data_tree_root",
            "invalid", // Bad format
            "2026-01-13T12:00:00Z",
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
        // The finding names the field, so a reader can see which of the two
        // hashes in play was the malformed one.
        assert!(result.error.unwrap().contains("anchor.target_hash"));
    }

    #[test]
    fn test_anchor_context_creation() {
        let context = AnchorVerificationContext::new(hash_from_byte(0xaa), hash_from_byte(0xbb));

        assert_eq!(context.expected_hash_for_target("data_tree_root"), Some(&hash_from_byte(0xaa)));
        assert_eq!(context.expected_hash_for_target("super_root"), Some(&hash_from_byte(0xbb)));
        assert_eq!(context.expected_hash_for_target("unknown"), None);
    }

    #[test]
    fn test_rfc3161_empty_target_fails() {
        let context = make_context();

        let result = verify_rfc3161_anchor(
            "", // Empty!
            &make_test_hash(0xaa),
            "2026-01-13T12:00:00Z",
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_bitcoin_ots_wrong_target_fails() {
        let context = make_context();

        let result = verify_bitcoin_ots_anchor(
            "data_tree_root", // Wrong! Should be "super_root"
            &make_test_hash(0xbb),
            "2026-01-13T12:00:00Z",
            0, // claimed block height: irrelevant to the target checks under test
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("must be 'super_root'"));
    }

    #[test]
    fn test_bitcoin_ots_target_hash_mismatch_fails() {
        let context = make_context(); // expects 0xbb for super_root

        let result = verify_bitcoin_ots_anchor(
            "super_root",
            &make_test_hash(0xff), // Wrong hash!
            "2026-01-13T12:00:00Z",
            0, // claimed block height: irrelevant to the target checks under test
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("target_hash mismatch"));
    }

    #[test]
    fn test_ots_v2_correct_super_root_target() {
        let context = make_context();

        // Valid v2.0 anchor targeting super_root
        let result = verify_bitcoin_ots_anchor(
            "super_root",
            &make_test_hash(0xbb), // Matches context.super_root
            "2026-01-13T12:00:00Z",
            0, // claimed block height: irrelevant to the target checks under test
            "base64:...",
            &context,
        );

        // Target validation should pass (actual OTS verification may fail)
        if !result.is_valid {
            let error = result.error.as_ref().unwrap();
            assert!(!error.contains("target must be"));
            assert!(!error.contains("target_hash mismatch"));
        }
    }

    #[test]
    fn test_ots_invalid_target_fails() {
        let context = make_context();

        let result = verify_bitcoin_ots_anchor(
            "invalid_target",
            &make_test_hash(0xbb),
            "2026-01-13T12:00:00Z",
            0, // claimed block height: irrelevant to the target checks under test
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("must be 'super_root'"));
    }

    #[test]
    fn test_ots_invalid_target_hash_format_fails() {
        let context = make_context();

        let result = verify_bitcoin_ots_anchor(
            "super_root",
            "invalid", // Bad format
            "2026-01-13T12:00:00Z",
            0, // claimed block height: irrelevant to the target checks under test
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
        // The finding names the field, so a reader can see which of the two
        // hashes in play was the malformed one.
        assert!(result.error.unwrap().contains("anchor.target_hash"));
    }

    #[test]
    fn test_ots_empty_target_fails() {
        let context = make_context();

        let result = verify_bitcoin_ots_anchor(
            "", // Empty!
            &make_test_hash(0xbb),
            "2026-01-13T12:00:00Z",
            0, // claimed block height: irrelevant to the target checks under test
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_ots_empty_target_hash_fails() {
        let context = make_context();

        let result = verify_bitcoin_ots_anchor(
            "super_root",
            "", // Empty!
            "2026-01-13T12:00:00Z",
            0, // claimed block height: irrelevant to the target checks under test
            "base64:AAAA",
            &context,
        );

        assert!(!result.is_valid);
        assert!(result.error.is_some());
    }
}

#[cfg(test)]
mod metadata_hash_tests {
    use super::*;
    use serde_json::json;

    fn make_test_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    #[test]
    fn test_reconstruct_leaf_hash_valid() {
        let metadata = json!({});
        let computed_hash = crate::core::jcs::canonicalize_and_hash(&metadata)
            .expect("metadata satisfies RFC 8785 Section 3.1");
        let metadata_hash_str = crate::core::receipt::format_hash(&computed_hash);
        let payload_hash_str = make_test_hash(0xaa);

        let result = reconstruct_leaf_hash(&payload_hash_str, &metadata_hash_str, &metadata);

        assert!(result.is_ok());
    }

    #[test]
    fn test_reconstruct_leaf_hash_metadata_mismatch() {
        let metadata = json!({});
        let wrong_hash = make_test_hash(0xff);
        let payload_hash_str = make_test_hash(0xaa);

        let result = reconstruct_leaf_hash(&payload_hash_str, &wrong_hash, &metadata);

        assert!(matches!(result, Err(VerificationError::MetadataHashMismatch { .. })));
    }

    #[test]
    fn test_reconstruct_leaf_hash_invalid_metadata_hash_format() {
        let metadata = json!({});
        let invalid_hash = "invalid";
        let payload_hash_str = make_test_hash(0xaa);

        let result = reconstruct_leaf_hash(&payload_hash_str, invalid_hash, &metadata);

        assert!(matches!(
            result,
            Err(VerificationError::InvalidHash { field, .. }) if field == "entry.metadata_hash"
        ));
    }

    #[test]
    fn test_reconstruct_leaf_hash_invalid_payload_hash_format() {
        let metadata = json!({});
        let computed_hash = crate::core::jcs::canonicalize_and_hash(&metadata)
            .expect("metadata satisfies RFC 8785 Section 3.1");
        let metadata_hash_str = crate::core::receipt::format_hash(&computed_hash);
        let invalid_payload = "invalid";

        let result = reconstruct_leaf_hash(invalid_payload, &metadata_hash_str, &metadata);

        assert!(matches!(
            result,
            Err(VerificationError::InvalidHash { field, .. }) if field == "entry.payload_hash"
        ));
    }

    #[test]
    fn test_reconstruct_leaf_hash_complex_metadata() {
        let metadata = json!({
            "filename": "test.pdf",
            "size": 1024,
            "tags": ["important", "signed"]
        });
        let computed_hash = crate::core::jcs::canonicalize_and_hash(&metadata)
            .expect("metadata satisfies RFC 8785 Section 3.1");
        let metadata_hash_str = crate::core::receipt::format_hash(&computed_hash);
        let payload_hash_str = make_test_hash(0xaa);

        let result = reconstruct_leaf_hash(&payload_hash_str, &metadata_hash_str, &metadata);

        assert!(result.is_ok());
    }

    #[test]
    fn test_reconstruct_leaf_hash_different_metadata_fails() {
        // Hash computed for one metadata
        let metadata1 = json!({"key": "value1"});
        let computed_hash1 = crate::core::jcs::canonicalize_and_hash(&metadata1)
            .expect("metadata satisfies RFC 8785 Section 3.1");
        let metadata_hash_str = crate::core::receipt::format_hash(&computed_hash1);

        // But we verify against different metadata
        let metadata2 = json!({"key": "value2"});
        let payload_hash_str = make_test_hash(0xaa);

        let result = reconstruct_leaf_hash(&payload_hash_str, &metadata_hash_str, &metadata2);

        assert!(matches!(result, Err(VerificationError::MetadataHashMismatch { .. })));
    }
}

/// ATL v2.0 §5.5.2 step 5, height half: the receipt's `bitcoin_block_height`
/// against the height the OTS proof itself attests to.
///
/// Exercised through [`verify_bitcoin_ots_anchor`] with a real
/// `OpenTimestamps` proof, because the comparison is only worth anything if
/// the height really is recoverable from proof bytes with no network access
/// — which is the entire reason this half of step 5 lives in this crate.
#[cfg(all(test, feature = "bitcoin-ots"))]
mod bitcoin_ots_claimed_height_tests {
    use super::*;
    use crate::core::ots::DetachedTimestampFile;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    /// A context whose super root is the fixture's start digest, so the
    /// anchor binds and the OTS checks are the ones under test.
    fn context_for(digest: [u8; 32]) -> AnchorVerificationContext {
        AnchorVerificationContext::new([0xaa; 32], digest)
    }

    /// The fixture proof, its start digest, and the height it attests to.
    fn fixture() -> (String, [u8; 32], u64) {
        let bytes = std::fs::read("test_data/ots/large-test.ots").expect("fixture readable");
        let file = DetachedTimestampFile::from_bytes(&bytes).expect("fixture parses");
        let digest: [u8; 32] =
            file.timestamp.start_digest.clone().try_into().expect("32-byte start digest");
        let attested = super::super::anchors::bitcoin_ots::verify_ots_anchor_impl(
            &STANDARD.encode(&bytes),
            &digest,
        )
        .expect("fixture proof verifies")
        .attestations
        .iter()
        .map(|a| a.block_height)
        .min()
        .expect("fixture carries a Bitcoin attestation");
        (STANDARD.encode(&bytes), digest, attested)
    }

    /// The height the receipt states and the height its proof attests to
    /// agree: **nothing is refuted on this ground**.
    ///
    /// The anchor is still not `is_valid`, and that is a different statement.
    /// No block header was obtained, so the OTS proof's Merkle root was never
    /// compared against one -- ATL v2.0 Section 5.5.2 step 4's "to the Bitcoin
    /// block". What this test pins is that the *height* comparison does not
    /// contribute a finding, and that the only thing standing between this
    /// anchor and acceptance is the unperformed lookup.
    #[test]
    fn a_matching_claimed_height_is_not_refuted() {
        let (proof, digest, attested) = fixture();

        let result = verify_bitcoin_ots_anchor(
            "super_root",
            &format_hash(&digest),
            "2026-01-13T12:00:00Z",
            attested,
            &proof,
            &context_for(digest),
        );

        assert!(!result.is_valid, "no block header was obtained, so nothing is confirmed");
        let error = result.error.expect("the unperformed check must be named");
        assert!(!error.contains("bitcoin_block_height mismatch"), "{error}");
        assert!(error.contains("no Bitcoin block header was obtained"), "{error}");
    }

    /// **The defect this check exists for.** A receipt may state any height
    /// it likes; the proof attests to one or more, and the claim must be one
    /// of them. This comparison is pure computation, so a verifier that
    /// skips it is republishing the receipt's own assertion as though it had
    /// been checked.
    #[test]
    fn a_claimed_height_the_proof_contradicts_is_refuted() {
        let (proof, digest, attested) = fixture();

        let result = verify_bitcoin_ots_anchor(
            "super_root",
            &format_hash(&digest),
            "2026-01-13T12:00:00Z",
            attested + 1,
            &proof,
            &context_for(digest),
        );

        assert!(!result.is_valid);
        let error = result.error.expect("a refutation must say what it refuted");
        assert!(error.contains("bitcoin_block_height mismatch"), "{error}");
        // The evidence for the refusal: what the proof does attest to.
        assert!(error.contains(&attested.to_string()), "{error}");
    }

    /// **A claim matching any attestation holds.** The rule is "match the
    /// proof" (§5.5.2 step 5), and a proof with several Bitcoin attestations
    /// attests to every one of them. Comparing against the lowest -- which
    /// this code once did, and which the specification nowhere asks for --
    /// refutes a receipt that named a block genuinely present in its own
    /// proof.
    #[test]
    fn any_attested_height_satisfies_the_claim() {
        use crate::core::ots::{attestation_for_claimed_height, BitcoinAttestation};

        let att = |h| BitcoinAttestation { block_height: h, merkle_path: vec![], timestamp: None };
        let proof = [att(932_897), att(932_910), att(1_000_000)];

        for claimed in [932_897, 932_910, 1_000_000] {
            assert_eq!(
                attestation_for_claimed_height(&proof, claimed).map(|a| a.block_height),
                Some(claimed),
                "a height the proof attests to must satisfy the claim"
            );
        }

        // Only a height attested by none of them is a mismatch -- including
        // one that merely sits between two attested heights.
        assert!(attestation_for_claimed_height(&proof, 932_900).is_none());
        assert!(attestation_for_claimed_height(&proof, 0).is_none());
        // And an empty proof attests to nothing at all.
        assert!(attestation_for_claimed_height(&[], 932_897).is_none());
    }

    /// No time is established here whatever the height comparison says: the
    /// block time is not in the proof, and this crate performs no I/O.
    #[test]
    fn no_block_time_is_ever_established_offline() {
        let (proof, digest, attested) = fixture();

        let result = verify_bitcoin_ots_anchor(
            "super_root",
            &format_hash(&digest),
            "2026-01-13T12:00:00Z",
            attested,
            &proof,
            &context_for(digest),
        );

        assert_eq!(result.timestamp, None);
        // The claim itself survives -- it is simply never presented as a
        // fact.
        assert!(result.claimed_timestamp.is_some());
    }
}

/// ATL v2.0 §4.2: which `spec_version` values this build admits.
#[cfg(test)]
mod spec_version_gate_tests {
    use crate::core::receipt::{is_supported_spec_version, RECEIPT_SPEC_VERSION};

    /// Every gate in this system must give the same answer, so there is one
    /// predicate and it matches exactly. `2.0.1` is the case that mattered:
    /// a caller admitting all of `2.x` while the verifier admitted only
    /// `2.0.0` turned an unimplemented revision into a defective receipt.
    #[test]
    fn only_the_revision_this_build_implements_is_accepted() {
        assert!(is_supported_spec_version(RECEIPT_SPEC_VERSION));
        assert!(!is_supported_spec_version("2.0.1"));
        assert!(!is_supported_spec_version("2.1.0"));
        assert!(!is_supported_spec_version("2"));
        assert!(!is_supported_spec_version("2."));
        assert!(!is_supported_spec_version("1.0.0"));
        assert!(!is_supported_spec_version("3.0.0"));
        assert!(!is_supported_spec_version(""));
    }
}
