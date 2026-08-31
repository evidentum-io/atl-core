//! Internal helper functions for receipt verification
//!
//! This module contains internal verification helper functions
//! that support the main verification logic in `ReceiptVerifier`.

use crate::core::checkpoint::{parse_hash, parse_signature, Checkpoint, CheckpointVerifier};
use crate::core::jcs::canonicalize_and_hash;
use crate::core::merkle::{compute_leaf_hash, verify_inclusion, InclusionProof};
use crate::core::receipt::{
    format_hash, ReceiptAnchor, ANCHOR_TARGET_DATA_TREE_ROOT, ANCHOR_TARGET_SUPER_ROOT,
};

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

    // Compute metadata hash via JCS
    let computed_metadata_hash = canonicalize_and_hash(metadata);

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
pub fn verify_anchor(
    anchor: &ReceiptAnchor,
    context: &AnchorVerificationContext,
) -> AnchorVerificationResult {
    match anchor {
        ReceiptAnchor::Rfc3161 { target, target_hash, timestamp, token_der, .. } => {
            verify_rfc3161_anchor(target, target_hash, timestamp, token_der, context)
        }
        ReceiptAnchor::BitcoinOts {
            target,
            target_hash,
            timestamp,
            bitcoin_block_height,
            ots_proof,
            ..
        } => verify_bitcoin_ots_anchor(
            target,
            target_hash,
            timestamp,
            *bitcoin_block_height,
            ots_proof,
            context,
        ),
    }
}

/// Verify RFC 3161 anchor with MANDATORY target validation
///
/// Per ATL Protocol v2.0 Section 5.5.1:
/// 1. Verify that `anchor.target` equals `"data_tree_root"` (REQUIRED)
/// 2. Verify that `anchor.target_hash` equals `proof.root_hash` (REQUIRED)
/// 3. Decode `token_der` (ASN.1 DER)
/// 4. Verify TSA signature
/// 5. Verify `MessageImprint` matches `target_hash`
///
/// NO FALLBACKS: Missing target or `target_hash` = ERROR.
fn verify_rfc3161_anchor(
    target: &str,
    target_hash: &str,
    timestamp: &str,
    token_der: &str,
    context: &AnchorVerificationContext,
) -> AnchorVerificationResult {
    use super::parse_iso8601_to_nanos;

    // 1. Validate target is "data_tree_root" (REQUIRED)
    if target != ANCHOR_TARGET_DATA_TREE_ROOT {
        return AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            is_valid: false,
            timestamp: None,
            claimed_timestamp: parse_iso8601_to_nanos(timestamp),
            error: Some(format!("RFC 3161 anchor target must be 'data_tree_root', got '{target}'")),
        };
    }

    // 2. Get expected hash for target
    let expected_root = &context.data_tree_root;

    // 3. Parse and validate target_hash (REQUIRED)
    let parsed_target_hash = match parse_hash_string(target_hash) {
        Ok(hash) => hash,
        Err(e) => {
            return AnchorVerificationResult {
                anchor_type: "rfc3161".to_string(),
                is_valid: false,
                timestamp: None,
                claimed_timestamp: parse_iso8601_to_nanos(timestamp),
                error: Some(format!("invalid target_hash format: {e}")),
            };
        }
    };

    // 4. Validate target_hash matches expected (REQUIRED)
    if !use_constant_time_eq(&parsed_target_hash, expected_root) {
        return AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            is_valid: false,
            timestamp: None,
            claimed_timestamp: parse_iso8601_to_nanos(timestamp),
            error: Some(format!(
                "target_hash mismatch: anchor has {target_hash}, expected {}",
                format_hash(expected_root)
            )),
        };
    }

    // 5. Proceed with cryptographic verification using expected_root. The
    // trust store, if any, comes only from the caller's VerifyOptions --
    // never from anything inside the receipt or the token.
    #[cfg(feature = "rfc3161-verify")]
    {
        verify_rfc3161_anchor_impl(
            timestamp,
            token_der,
            expected_root,
            context.rfc3161_trust_store.as_ref(),
        )
    }
    #[cfg(not(feature = "rfc3161-verify"))]
    {
        verify_rfc3161_anchor_impl(timestamp, token_der, expected_root)
    }
}

/// Constant-time hash comparison
fn use_constant_time_eq(a: &Hash, b: &Hash) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Parse hash string `"sha256:..."` to 32-byte array
fn parse_hash_string(s: &str) -> Result<Hash, String> {
    parse_hash(s).map_err(|e| e.to_string())
}

/// Verify RFC 3161 anchor implementation (with feature flag)
#[cfg(feature = "rfc3161-verify")]
pub fn verify_rfc3161_anchor_impl(
    timestamp: &str,
    token_der: &str,
    expected_root: &[u8; 32],
    trust_store: Option<&crate::core::verify::anchors::rfc3161::TrustStore>,
) -> AnchorVerificationResult {
    use super::anchors::rfc3161::verify_rfc3161_anchor_impl;
    verify_rfc3161_anchor_impl(timestamp, token_der, expected_root, trust_store)
}

/// Verify RFC 3161 anchor implementation (without feature flag)
#[cfg(not(feature = "rfc3161-verify"))]
pub fn verify_rfc3161_anchor_impl(
    timestamp: &str,
    _token_der: &str,
    _expected_root: &[u8; 32],
) -> AnchorVerificationResult {
    use super::parse_iso8601_to_nanos;

    AnchorVerificationResult {
        anchor_type: "rfc3161".to_string(),
        is_valid: false,
        // The feature is compiled out, so nothing was verified and nothing
        // is established -- least of all a time.
        timestamp: None,
        claimed_timestamp: parse_iso8601_to_nanos(timestamp),
        error: Some("RFC 3161 verification requires 'rfc3161-verify' feature".to_string()),
    }
}

/// Verify Bitcoin OTS anchor with MANDATORY target validation
///
/// Per ATL Protocol v2.0 Section 5.5.2:
/// 1. Verify that `anchor.target` equals `"super_root"` (REQUIRED)
/// 2. Verify that `anchor.target_hash` equals `super_proof.super_root` (REQUIRED)
/// 3. Decode `ots_proof` (`OpenTimestamps` binary format)
/// 4. Verify the OTS proof chain from `target_hash` to the Bitcoin block
/// 5. Verify that `bitcoin_block_height` and `bitcoin_block_time` match the
///    proof
///
/// # Step 5 splits in two, and only one half belongs in this crate
///
/// The height is carried by the proof itself -- an `OpenTimestamps` Bitcoin
/// attestation encodes it -- so `bitcoin_block_height` can be compared with
/// what the proof says by pure computation, and is compared here. A receipt
/// naming a height its own proof contradicts is **refuted**, not merely
/// unconfirmed.
///
/// The block *time* is nowhere in the proof. Establishing it means obtaining
/// the block header, which is I/O this crate does not perform, so the
/// `bitcoin_block_time` half of step 5 cannot be carried out here and is
/// deliberately not attempted: reporting a comparison that never ran is the
/// one thing worse than not running it. A caller that does fetch headers
/// (`atl-cli`) completes that half.
///
/// NO FALLBACKS: Missing target or `target_hash` = ERROR.
/// OTS anchors MUST target `"super_root"` (not `"data_tree_root"`).
fn verify_bitcoin_ots_anchor(
    target: &str,
    target_hash: &str,
    timestamp: &str,
    claimed_block_height: u64,
    ots_proof: &str,
    context: &AnchorVerificationContext,
) -> AnchorVerificationResult {
    use super::parse_iso8601_to_nanos;

    // 1. Validate target is "super_root" (REQUIRED)
    if target != ANCHOR_TARGET_SUPER_ROOT {
        return AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            is_valid: false,
            timestamp: None,
            claimed_timestamp: parse_iso8601_to_nanos(timestamp),
            error: Some(format!("Bitcoin OTS anchor target must be 'super_root', got '{target}'")),
        };
    }

    // 2. Get expected hash for target
    let expected_root = &context.super_root;

    // 3. Parse and validate target_hash (REQUIRED)
    let parsed_target_hash = match parse_hash_string(target_hash) {
        Ok(hash) => hash,
        Err(e) => {
            return AnchorVerificationResult {
                anchor_type: "bitcoin_ots".to_string(),
                is_valid: false,
                timestamp: None,
                claimed_timestamp: parse_iso8601_to_nanos(timestamp),
                error: Some(format!("invalid target_hash format: {e}")),
            };
        }
    };

    // 4. Validate target_hash matches expected (REQUIRED)
    if !use_constant_time_eq(&parsed_target_hash, expected_root) {
        return AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            is_valid: false,
            timestamp: None,
            claimed_timestamp: parse_iso8601_to_nanos(timestamp),
            error: Some(format!(
                "target_hash mismatch: anchor has {target_hash}, expected {}",
                format_hash(expected_root)
            )),
        };
    }

    // 5. Proceed with cryptographic verification using expected_root, and
    //    with the height the receipt claims for the proof to be checked
    //    against.
    verify_bitcoin_ots_anchor_impl(timestamp, ots_proof, expected_root, claimed_block_height)
}

/// Verify Bitcoin OTS anchor implementation (with feature flag)
#[cfg(feature = "bitcoin-ots")]
pub fn verify_bitcoin_ots_anchor_impl(
    timestamp: &str,
    ots_proof: &str,
    expected_root: &[u8; 32],
    claimed_block_height: u64,
) -> AnchorVerificationResult {
    use super::anchors::bitcoin_ots::verify_ots_anchor_impl;

    match verify_ots_anchor_impl(ots_proof, expected_root) {
        Ok(result) => {
            // ATL v2.0 §5.5.2 step 5, height half: the receipt states a
            // block height for this anchor, and the proof attests to one or
            // more. Comparing them needs no network, so an offline verifier
            // that skips it publishes an unchecked assertion of the
            // receipt's -- a receipt could name block 900000 while carrying
            // a proof that attests to 932897, and nothing would notice.
            //
            // The rule -- the claim holds if it matches ANY attestation --
            // lives in `attestation_for_claimed_height` and is not restated
            // here. It was once an inline `min()`, a criterion the
            // specification never sets, under which a receipt naming a
            // height genuinely present in its own proof could be declared
            // refuted.
            let attested = crate::core::ots::attestation_for_claimed_height(
                &result.attestations,
                claimed_block_height,
            );
            if attested.is_some() {
                return AnchorVerificationResult {
                    anchor_type: "bitcoin_ots".to_string(),
                    is_valid: true,
                    // This crate performs no I/O, so it never learns the
                    // confirming block's time -- and the receipt's own field
                    // is the anchor's claim, not the block's. Establishing
                    // it needs the network, and so does the
                    // `bitcoin_block_time` half of step 5.
                    timestamp: None,
                    claimed_timestamp: super::parse_iso8601_to_nanos(timestamp),
                    error: None,
                };
            }

            let heights = crate::core::ots::attested_block_heights(&result.attestations)
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            AnchorVerificationResult {
                anchor_type: "bitcoin_ots".to_string(),
                is_valid: false,
                timestamp: None,
                claimed_timestamp: super::parse_iso8601_to_nanos(timestamp),
                // Every attested height is named, not just one: a reader
                // told the claim matches nothing must be able to see what
                // the proof does attest to, or the finding is unauditable.
                error: Some(format!(
                    "bitcoin_block_height mismatch: receipt claims {claimed_block_height}, but \
                     its OTS proof attests to no such block (attested: [{heights}])"
                )),
            }
        }
        Err(e) => AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            is_valid: false,
            timestamp: None,
            claimed_timestamp: super::parse_iso8601_to_nanos(timestamp),
            error: Some(e.to_string()),
        },
    }
}

/// Verify Bitcoin OTS anchor implementation (without feature flag)
#[cfg(not(feature = "bitcoin-ots"))]
pub fn verify_bitcoin_ots_anchor_impl(
    timestamp: &str,
    _ots_proof: &str,
    _expected_root: &[u8; 32],
    _claimed_block_height: u64,
) -> AnchorVerificationResult {
    use super::parse_iso8601_to_nanos;

    AnchorVerificationResult {
        anchor_type: "bitcoin_ots".to_string(),
        is_valid: false,
        // The feature is compiled out, so nothing was verified and nothing
        // is established -- least of all a time.
        timestamp: None,
        claimed_timestamp: parse_iso8601_to_nanos(timestamp),
        error: Some("Bitcoin OTS verification requires 'bitcoin-ots' feature".to_string()),
    }
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
        assert!(result.error.unwrap().contains("invalid target_hash format"));
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
        assert!(result.error.unwrap().contains("invalid target_hash format"));
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
        let computed_hash = crate::core::jcs::canonicalize_and_hash(&metadata);
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
        let computed_hash = crate::core::jcs::canonicalize_and_hash(&metadata);
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
        let computed_hash = crate::core::jcs::canonicalize_and_hash(&metadata);
        let metadata_hash_str = crate::core::receipt::format_hash(&computed_hash);
        let payload_hash_str = make_test_hash(0xaa);

        let result = reconstruct_leaf_hash(&payload_hash_str, &metadata_hash_str, &metadata);

        assert!(result.is_ok());
    }

    #[test]
    fn test_reconstruct_leaf_hash_different_metadata_fails() {
        // Hash computed for one metadata
        let metadata1 = json!({"key": "value1"});
        let computed_hash1 = crate::core::jcs::canonicalize_and_hash(&metadata1);
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
/// Exercised through [`verify_bitcoin_ots_anchor_impl`] with a real
/// `OpenTimestamps` proof, because the comparison is only worth anything if
/// the height really is recoverable from proof bytes with no network access
/// — which is the entire reason this half of step 5 lives in this crate.
#[cfg(all(test, feature = "bitcoin-ots"))]
mod bitcoin_ots_claimed_height_tests {
    use super::*;
    use crate::core::ots::DetachedTimestampFile;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

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
    /// agree: nothing is refuted on this ground.
    #[test]
    fn a_matching_claimed_height_is_not_refuted() {
        let (proof, digest, attested) = fixture();

        let result =
            verify_bitcoin_ots_anchor_impl("2026-01-13T12:00:00Z", &proof, &digest, attested);

        assert!(result.is_valid, "{:?}", result.error);
    }

    /// **The defect this check exists for.** A receipt may state any height
    /// it likes; the proof attests to one or more, and the claim must be one
    /// of them. This comparison is pure computation, so a verifier that
    /// skips it is republishing the receipt's own assertion as though it had
    /// been checked.
    #[test]
    fn a_claimed_height_the_proof_contradicts_is_refuted() {
        let (proof, digest, attested) = fixture();

        let result =
            verify_bitcoin_ots_anchor_impl("2026-01-13T12:00:00Z", &proof, &digest, attested + 1);

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

        let result =
            verify_bitcoin_ots_anchor_impl("2026-01-13T12:00:00Z", &proof, &digest, attested);

        assert_eq!(result.timestamp, None);
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
