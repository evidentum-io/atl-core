//! Verification types and results
//!
//! This module contains the core types used in receipt verification:
//! - `VerificationResult`: Complete verification result with detailed status
//! - `AnchorVerificationResult`: Result of verifying a single anchor
//! - `VerificationError`: Detailed error types for verification failures
//! - `VerifyOptions`: Configuration options for verification
//! - `SignatureMode`: Controls signature verification behavior
//! - `SignatureStatus`: Result of signature verification attempt

/// Signature verification mode
///
/// Controls how the verifier handles checkpoint signature verification.
/// Per ATL Protocol v2.0, signature verification is an integrity check,
/// NOT a trust establishment mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureMode {
    /// Signature MUST verify successfully.
    ///
    /// Use this mode when you have a trusted public key and want to ensure
    /// the checkpoint was signed by that specific key.
    ///
    /// **Behavior:** Verification fails if signature is invalid or key unavailable.
    Require,

    /// Verify signature if key is available, skip otherwise.
    ///
    /// This is the **default** mode, matching ATL Protocol v2.0 trust model:
    /// "A Verifier encountering a receipt for the first time can fully validate
    /// it using only the anchor verification, without any prior knowledge of
    /// the Log Operator."
    ///
    /// **Behavior:**
    /// - If key provided: verify signature, record result in `signature_status`
    /// - If no key: skip signature verification, `signature_status = Skipped`
    #[default]
    Optional,

    /// Never verify signature, rely only on anchors.
    ///
    /// Use this mode for maximum performance when you trust anchors completely
    /// and don't care about checkpoint integrity beyond Merkle proofs.
    ///
    /// **Behavior:** Signature always skipped, `signature_status = Skipped`.
    Skip,
}

impl SignatureMode {
    /// Returns true if signature verification should be attempted
    #[must_use]
    pub const fn should_verify(&self) -> bool {
        matches!(self, Self::Require | Self::Optional)
    }

    /// Returns true if signature failure should cause overall failure
    #[must_use]
    pub const fn requires_success(&self) -> bool {
        matches!(self, Self::Require)
    }
}

/// Result of signature verification attempt
///
/// This enum provides detailed information about what happened during
/// signature verification, allowing callers to distinguish between
/// "signature invalid" and "signature not checked".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureStatus {
    /// Signature was verified and is valid.
    ///
    /// The checkpoint signature matches the provided public key.
    Verified,

    /// Signature was verified and is INVALID.
    ///
    /// The checkpoint signature does NOT match the provided public key.
    /// This could indicate:
    /// - Corrupted checkpoint data
    /// - Wrong public key provided
    /// - Malicious modification
    Failed,

    /// Signature was not verified.
    ///
    /// This occurs when:
    /// - No public key was provided (anchor-only verification)
    /// - `SignatureMode::Skip` was used
    /// - Key's `key_id` doesn't match checkpoint's `key_id` in Optional mode
    #[default]
    Skipped,

    /// Public key's `key_id` doesn't match checkpoint's `key_id`.
    ///
    /// The provided key is for a different signer than the one that
    /// signed this checkpoint. In `Require` mode this causes failure.
    /// In `Optional` mode this results in `Skipped` status.
    KeyMismatch,
}

impl SignatureStatus {
    /// Returns true if signature was successfully verified
    #[must_use]
    pub const fn is_verified(&self) -> bool {
        matches!(self, Self::Verified)
    }

    /// Returns true if verification was attempted (not skipped)
    #[must_use]
    pub const fn was_attempted(&self) -> bool {
        matches!(self, Self::Verified | Self::Failed | Self::KeyMismatch)
    }
}

/// Result of receipt verification
///
/// Contains detailed information about the verification process,
/// including success/failure status and any errors encountered.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct VerificationResult {
    /// Overall verification status (true if all critical checks passed)
    pub is_valid: bool,

    /// Reconstructed leaf hash from entry
    pub leaf_hash: [u8; 32],

    /// Root hash from proof
    pub root_hash: [u8; 32],

    /// Tree size from proof
    pub tree_size: u64,

    /// Timestamp from checkpoint (nanoseconds since Unix epoch)
    pub timestamp: u64,

    /// Signature verification passed
    ///
    /// **Deprecated:** Use `signature_status` for more detailed information.
    /// This field is `true` only when `signature_status == SignatureStatus::Verified`.
    pub signature_valid: bool,

    /// Detailed signature verification status
    ///
    /// Indicates what happened during signature verification:
    /// - `Verified`: Signature checked and valid
    /// - `Failed`: Signature checked and invalid
    /// - `Skipped`: Signature not checked (no key or skip mode)
    /// - `KeyMismatch`: Provided key doesn't match checkpoint's `key_id`
    pub signature_status: SignatureStatus,

    /// Inclusion proof verification passed
    pub inclusion_valid: bool,

    /// Consistency proof verification (if present)
    pub consistency_valid: Option<bool>,

    /// Super-Tree inclusion proof verification passed (MANDATORY in v2.0)
    pub super_inclusion_valid: bool,

    /// Super-Tree consistency to origin verification passed (MANDATORY in v2.0)
    pub super_consistency_valid: bool,

    /// Genesis super root (ALWAYS present in v2.0)
    pub genesis_super_root: [u8; 32],

    /// Super root (ALWAYS present in v2.0)
    pub super_root: [u8; 32],

    /// Data Tree index in Super-Tree (ALWAYS present in v2.0)
    pub data_tree_index: u64,

    /// Super-Tree size (ALWAYS present in v2.0)
    pub super_tree_size: u64,

    /// Anchor verification results
    pub anchor_results: Vec<AnchorVerificationResult>,

    /// Detailed errors (if any)
    pub errors: Vec<VerificationError>,
}

/// Result of verifying a single anchor
#[derive(Debug, Clone)]
pub struct AnchorVerificationResult {
    /// Anchor type (e.g., "rfc3161", "bitcoin")
    pub anchor_type: String,

    /// Verification passed
    pub is_valid: bool,

    /// The time this anchor **establishes**, in nanoseconds since the Unix
    /// epoch — `Some` only when [`Self::is_valid`] is `true`.
    ///
    /// A timestamp anchor exists to answer "when did this exist", so handing
    /// that number over unqualified for an anchor that did not verify is the
    /// single most misleading thing this type could do. It is therefore
    /// withheld rather than annotated: a consumer that reads it gets either
    /// an established time or nothing, and can never mistake the token's
    /// unverified claim for a verified fact.
    ///
    /// The claim itself is not discarded — see [`Self::claimed_timestamp`].
    pub timestamp: Option<u64>,

    /// The time the anchor **asserts**, in nanoseconds since the Unix epoch,
    /// regardless of whether anything about it was verified.
    ///
    /// Populated from the token's own `genTime` (or, failing that, the
    /// receipt's `timestamp` field) even when verification failed outright.
    /// This is attacker-controlled input until [`Self::is_valid`] holds:
    /// useful for diagnostics and for saying *what was claimed*, never
    /// admissible as when something existed.
    pub claimed_timestamp: Option<u64>,

    /// Error message if invalid
    pub error: Option<String>,
}

/// Detailed verification errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// Invalid receipt format
    InvalidReceipt(String),

    /// Hash format/decoding error
    InvalidHash {
        /// Field name containing the invalid hash
        field: String,
        /// Error message describing the issue
        message: String,
    },

    /// Signature verification failed
    SignatureFailed,

    /// Inclusion proof failed
    InclusionProofFailed {
        /// Reason for failure
        reason: String,
    },

    /// Consistency proof failed
    ConsistencyProofFailed {
        /// Reason for failure
        reason: String,
    },

    /// Root hash mismatch between checkpoint and proof
    RootHashMismatch,

    /// Tree size mismatch between checkpoint and proof
    TreeSizeMismatch,

    /// Anchor verification failed
    AnchorFailed {
        /// Type of anchor that failed
        anchor_type: String,
        /// Reason for failure
        reason: String,
    },

    /// Super-Tree inclusion proof failed (MANDATORY check)
    SuperInclusionFailed {
        /// Reason for failure
        reason: String,
    },

    /// Super-Tree consistency to origin failed (MANDATORY check)
    SuperConsistencyFailed {
        /// Reason for failure
        reason: String,
    },

    /// Super-Tree data mismatch
    SuperDataMismatch {
        /// Field that mismatched
        field: String,
        /// Expected value
        expected: String,
        /// Actual value
        actual: String,
    },

    /// Missing `super_proof` (required in v2.0)
    MissingSuperProof,

    /// Unsupported receipt version
    UnsupportedVersion(String),

    /// Metadata hash mismatch
    ///
    /// The `metadata_hash` in the receipt does not match the computed
    /// hash of the canonicalized metadata (JCS).
    MetadataHashMismatch {
        /// Expected hash (from receipt)
        expected: String,
        /// Actual hash (computed from metadata)
        actual: String,
    },

    /// The metadata has no RFC 8785 canonical form, so `metadata_hash` could
    /// not be computed at all.
    ///
    /// **This is not [`Self::MetadataHashMismatch`], and the difference is the
    /// whole reason the variant exists.** A mismatch is a refutation: the hash
    /// was computed and it disagrees with the receipt. This is an *inability*:
    /// the input breaks an RFC 8785 Section 3.1 constraint on canonicalization
    /// input, so there is no byte string to hash and nothing was compared. The
    /// receipt has not been shown to be wrong — it has not been checked.
    ///
    /// Reporting it as a mismatch would publish "this evidence is disproved"
    /// on the strength of a computation that never ran. See
    /// [`Self::is_refutation`].
    MetadataNotCanonicalizable {
        /// RFC 6901 JSON Pointer of the offending node, relative to the
        /// receipt root (e.g. `/entry/metadata/claims/0/amount`).
        path: String,
        /// Which RFC 8785 Section 3.1 constraint was broken.
        reason: String,
    },

    /// The receipt's source bytes were never checked for duplicate property
    /// names, so it cannot be confirmed.
    ///
    /// **Not a finding against the receipt.** RFC 8785 Section 3.1's
    /// prohibition on duplicate property names is a property of a byte stream;
    /// once JSON is parsed the duplicate is gone and no inspection recovers it.
    /// A `Receipt` that reached this crate through
    /// [`serde_json::from_value`], or that was assembled structurally, carries
    /// no record that its bytes were ever examined — and confirming it would
    /// mean asserting a constraint nobody checked.
    ///
    /// The holder resolves this by vouching for the bytes with
    /// [`SourceTextCheck::assume_duplicate_property_names_already_rejected`](crate::core::receipt::SourceTextCheck::assume_duplicate_property_names_already_rejected),
    /// or by parsing through
    /// [`Receipt::from_json`](crate::core::receipt::Receipt::from_json), which
    /// performs the check. See [`Self::is_refutation`].
    SourceTextNotChecked,

    /// No trust anchor available
    ///
    /// Verification found no source of trust:
    /// - No valid external anchors (RFC 3161 or Bitcoin OTS)
    /// - Signature not verified (no key, skipped, or failed in non-Require mode)
    ///
    /// Per ATL Protocol v2.0 Section 5.5:
    /// > "A receipt without any verified anchors SHOULD be treated as untrustworthy."
    NoTrustAnchor,
}

/// Options for verification
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Signature verification mode
    ///
    /// Controls whether and how checkpoint signatures are verified.
    /// Default: `SignatureMode::Optional` (verify if key available).
    ///
    /// Per ATL Protocol v2.0 Section 5.2:
    /// "Even if the checkpoint signature cannot be verified (unknown key),
    /// the receipt MAY still be valid if anchor verification succeeds."
    pub signature_mode: SignatureMode,

    /// Skip anchor verification
    pub skip_anchors: bool,

    /// Skip consistency proof verification
    pub skip_consistency: bool,

    /// Require at least this many valid anchors
    pub min_valid_anchors: usize,

    /// Trust material for RFC 3161 anchor chain verification.
    ///
    /// Per the trust model, this crate never derives a trust anchor from
    /// certificates that arrived inside the token itself -- `None` (the
    /// default) means every RFC 3161 anchor can, at best, reach
    /// [`TerminalAnchor::Assumed`](super::anchors::rfc3161::TerminalAnchor::Assumed),
    /// never `Trusted`, and therefore never contributes to
    /// [`AnchorVerificationResult::is_valid`]. Set this to a `TrustStore`
    /// obtained through an external, trusted channel (never by promoting a
    /// certificate found in the receipt itself) to allow RFC 3161 anchors
    /// to be trusted.
    #[cfg(feature = "rfc3161-verify")]
    pub rfc3161_trust_store: Option<super::anchors::rfc3161::TrustStore>,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidReceipt(msg) => write!(f, "Invalid receipt: {msg}"),
            Self::InvalidHash { field, message } => {
                write!(f, "Invalid hash in field '{field}': {message}")
            }
            Self::SignatureFailed => write!(f, "Signature verification failed"),
            Self::InclusionProofFailed { reason } => write!(f, "Inclusion proof failed: {reason}"),
            Self::ConsistencyProofFailed { reason } => {
                write!(f, "Consistency proof failed: {reason}")
            }
            Self::RootHashMismatch => write!(f, "Root hash mismatch between checkpoint and proof"),
            Self::TreeSizeMismatch => write!(f, "Tree size mismatch between checkpoint and proof"),
            Self::AnchorFailed { anchor_type, reason } => {
                write!(f, "Anchor verification failed ({anchor_type}): {reason}")
            }
            Self::SuperInclusionFailed { reason } => {
                write!(f, "Super-Tree inclusion proof failed: {reason}")
            }
            Self::SuperConsistencyFailed { reason } => {
                write!(f, "Super-Tree consistency proof failed: {reason}")
            }
            Self::SuperDataMismatch { field, expected, actual } => {
                write!(f, "Super-Tree data mismatch in {field}: expected {expected}, got {actual}")
            }
            Self::MissingSuperProof => write!(f, "Missing super_proof (required in v2.0)"),
            Self::UnsupportedVersion(version) => {
                write!(f, "Unsupported receipt version: {version}")
            }
            Self::MetadataHashMismatch { expected, actual } => {
                write!(f, "Metadata hash mismatch: expected {expected}, got {actual}")
            }
            Self::MetadataNotCanonicalizable { path, reason } => {
                write!(
                    f,
                    "Metadata has no RFC 8785 canonical form, so metadata_hash could not be \
                     computed (JSON Pointer {path:?}): {reason}"
                )
            }
            Self::SourceTextNotChecked => write!(
                f,
                "Receipt source bytes were never checked for duplicate property names \
                 (RFC 8785 Section 3.1): parse with Receipt::from_json, or vouch for the \
                 bytes with SourceTextCheck::assume_duplicate_property_names_already_rejected"
            ),
            Self::NoTrustAnchor => {
                write!(
                    f,
                    "No trust anchor available (no verified signature or valid external anchors)"
                )
            }
        }
    }
}

impl VerificationError {
    /// Whether this error is evidence **against** the receipt.
    ///
    /// Three of the variants are not. They record that this verifier could
    /// not finish, which is a fact about the verifier's reach, never a
    /// finding about the document:
    ///
    /// * [`Self::UnsupportedVersion`] — the receipt is written to a revision
    ///   this build has never implemented. Reporting it as defective would be
    ///   asserting a verification performed under rules never read.
    /// * [`Self::MetadataNotCanonicalizable`] — `metadata_hash` was never
    ///   computed, so it was never contradicted.
    /// * [`Self::NoTrustAnchor`] — nothing vouches for the checkpoint. The
    ///   absence of trust material disproves nothing.
    /// * [`Self::SourceTextNotChecked`] — the receipt's bytes were never
    ///   examined for duplicate property names, which is unknowable once JSON
    ///   has been parsed. Not knowing is not evidence.
    ///
    /// Every other variant is a genuine refutation: a hash that does not
    /// match, a proof path that does not lead to the root, a signature that
    /// fails, a field that cannot be a hash at all.
    ///
    /// This mirrors the distinction
    /// [`PathStatus`](super::anchors::rfc3161::PathStatus) draws for RFC 3161
    /// chains, where collapsing "could not check" into "invalid" is what once
    /// made this crate publish refuted evidence about tokens nothing had
    /// refuted.
    #[must_use]
    pub const fn is_refutation(&self) -> bool {
        !matches!(
            self,
            Self::UnsupportedVersion(_)
                | Self::MetadataNotCanonicalizable { .. }
                | Self::SourceTextNotChecked
                | Self::NoTrustAnchor
        )
    }
}

impl VerificationResult {
    /// Check if all critical verifications passed
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.is_valid
    }

    /// Whether the receipt was left **unverified** rather than shown to be bad.
    ///
    /// `is_valid == false` alone does not distinguish "this receipt is
    /// refuted" from "this build could not evaluate it". A caller that
    /// displays a verdict must ask this before saying anything against the
    /// receipt: when it is `true` and no error
    /// [refutes](VerificationError::is_refutation) the document, the honest
    /// report is *untrusted / not verified*, not *invalid*.
    ///
    /// Note this is only meaningful together with [`Self::is_valid`]: a result
    /// can be indeterminate and still carry refutations, in which case the
    /// refutations decide.
    #[must_use]
    pub fn is_indeterminate(&self) -> bool {
        !self.is_valid
            && !self.errors.is_empty()
            && !self.errors.iter().any(VerificationError::is_refutation)
    }

    /// Check if at least one anchor was verified
    #[must_use]
    pub fn has_valid_anchor(&self) -> bool {
        self.anchor_results.iter().any(|a| a.is_valid)
    }

    /// Get the first error (if any)
    #[must_use]
    pub fn first_error(&self) -> Option<&VerificationError> {
        self.errors.first()
    }

    /// Get all errors
    #[must_use]
    pub fn errors(&self) -> &[VerificationError] {
        &self.errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_mode() {
        assert_eq!(SignatureMode::default(), SignatureMode::Optional);
        assert!(SignatureMode::Require.should_verify());
        assert!(SignatureMode::Optional.should_verify());
        assert!(!SignatureMode::Skip.should_verify());
        assert!(SignatureMode::Require.requires_success());
        assert!(!SignatureMode::Optional.requires_success());
        assert!(!SignatureMode::Skip.requires_success());
        let mode = SignatureMode::Require;
        let cloned = mode;
        assert_eq!(mode, cloned);
        let copied: SignatureMode = mode;
        assert_eq!(mode, copied);
        assert!(format!("{mode:?}").contains("Require"));
    }

    #[test]
    fn test_signature_status() {
        assert_eq!(SignatureStatus::default(), SignatureStatus::Skipped);
        assert!(SignatureStatus::Verified.is_verified());
        assert!(!SignatureStatus::Failed.is_verified());
        assert!(!SignatureStatus::Skipped.is_verified());
        assert!(!SignatureStatus::KeyMismatch.is_verified());
        assert!(SignatureStatus::Verified.was_attempted());
        assert!(SignatureStatus::Failed.was_attempted());
        assert!(!SignatureStatus::Skipped.was_attempted());
        assert!(SignatureStatus::KeyMismatch.was_attempted());
        let status = SignatureStatus::Verified;
        let cloned = status;
        assert_eq!(status, cloned);
        let copied: SignatureStatus = status;
        assert_eq!(status, copied);
        assert!(format!("{status:?}").contains("Verified"));
    }

    #[test]
    fn test_verify_options_default() {
        let options = VerifyOptions::default();
        assert_eq!(options.signature_mode, SignatureMode::Optional);
    }

    #[test]
    fn test_verify_options_backwards_compatible() {
        let options = VerifyOptions {
            skip_anchors: true,
            skip_consistency: false,
            min_valid_anchors: 1,
            ..Default::default()
        };
        assert!(options.skip_anchors);
        assert!(!options.skip_consistency);
        assert_eq!(options.min_valid_anchors, 1);
        assert_eq!(options.signature_mode, SignatureMode::Optional);
    }

    #[test]
    fn test_verification_result_signature_status() {
        let result = VerificationResult {
            is_valid: false,
            leaf_hash: [0; 32],
            root_hash: [0; 32],
            tree_size: 0,
            timestamp: 0,
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
        assert_eq!(result.signature_status, SignatureStatus::Skipped);
        assert!(SignatureStatus::Verified.is_verified());
        assert!(!SignatureStatus::Failed.is_verified());
        assert!(!SignatureStatus::Skipped.is_verified());
        assert!(!SignatureStatus::KeyMismatch.is_verified());
    }
}
