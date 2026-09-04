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

    /// Too few anchors were verified to establish trust.
    ///
    /// Per ATL Protocol v2.0 Section 5.5:
    /// > "At least one anchor MUST be verified to establish trust in the
    /// > receipt. […] A receipt without any verified anchors SHOULD be treated
    /// > as untrustworthy."
    ///
    /// # One concept, one representation
    ///
    /// This is the **only** way this crate reports an unmet threshold. It
    /// covers a receipt with no anchors, a receipt whose every anchor was left
    /// unresolved, a receipt whose anchors were all refuted, a receipt
    /// verified with `skip_anchors`, and a caller-raised quorum
    /// ([`VerifyOptions::min_valid_anchors`]) that was not reached.
    ///
    /// Those used to be two errors — this one and an `AnchorFailed` aggregate
    /// — and the split was not merely redundant, it was forgeable. The quorum
    /// check ran only for receipts that presented at least one anchor, so
    /// appending an anchor to an unanchored receipt swapped which of the two
    /// appeared. Since the `anchors` array is authenticated by nothing, a
    /// stranger could therefore change the receipt's reported error set for
    /// free. `required` and `verified` say everything the split said, and
    /// neither can be moved downwards by anybody but the caller: `required` is
    /// the caller's own option (floored at Section 5.5's one), and `verified`
    /// counts anchors that reached a caller-supplied trust root, which no
    /// appended rubbish can become.
    ///
    /// **Not a refutation.** Nothing was disproved; not enough was proved. A
    /// verified checkpoint signature does not help — Section 5.4 calls it "an
    /// integrity check, not a trust establishment" and Section 1.2 derives
    /// trust "exclusively from external, independent anchors".
    NoTrustAnchor {
        /// How many verified anchors were needed:
        /// `max(1, VerifyOptions::min_valid_anchors)`. The Section 5.5 floor
        /// is one, and a caller may raise it but never lower it.
        required: usize,
        /// How many anchors actually verified.
        verified: usize,
    },

    // ================================================================
    // Anchor findings (ATL Protocol v2.0 Section 5.5)
    //
    // These are the outcomes of the per-anchor steps, reported one by one
    // instead of collapsed into a single `is_valid: bool`. They are what
    // [`AnchorFacts`](super::facts::AnchorFacts) carries, and each of them
    // answers [`Self::is_refutation`] for itself so that a consumer never has
    // to re-derive the refuted/indeterminate split.
    // ================================================================
    /// A finding about one of the receipt's **anchors**, not about the
    /// receipt itself.
    ///
    /// # Why the provenance is part of the type
    ///
    /// An ATL receipt does not authenticate its own anchors. The leaf hash is
    /// `SHA256(0x00 || payload_hash || metadata_hash)` and the checkpoint blob
    /// is 98 bytes of origin, tree size, timestamp and root hash — the
    /// `anchors` array appears in neither, so nothing signs it and nothing
    /// hashes it. **Anyone who relays a receipt can append an anchor to it,
    /// for free, without any key.**
    ///
    /// A finding against such an anchor therefore says something about that
    /// anchor and nothing whatever about the receipt. Letting it decide the
    /// receipt's verdict would hand every relay a denial of verification:
    /// append one malformed token and a receipt with a flawless independent
    /// anchor stops verifying. What a genuine anchor established is not undone
    /// by rubbish laid down beside it.
    ///
    /// Note the asymmetry, which is the whole shape of the guarantee. An
    /// anchor that **fails** verification can be produced by anyone, so it may
    /// change nothing. An anchor that **passes** requires a timestamp token
    /// over this receipt's own root, chaining to a trust root the *caller*
    /// supplied — so it is not something a stranger can add, and it is
    /// supposed to change the outcome. Anchors would be pointless otherwise.
    ///
    /// **This is not permission to ignore it.** An appended anchor is
    /// evidence of interference and every consumer must surface it — which is
    /// exactly why it travels in
    /// [`VerificationResult::errors`](VerificationResult::errors) rather than
    /// being dropped, and why it still answers [`Self::is_refutation`] for
    /// itself: a consumer can say of *that anchor* that it was checked and
    /// found false, as opposed to merely unresolved, without unwrapping
    /// anything.
    ///
    /// It does not follow that the **receipt** was refuted, and it must not.
    /// [`VerificationResult::is_indeterminate`] is computed over
    /// [`VerificationResult::receipt_errors`], from which this variant is
    /// excluded by construction, so a receipt carrying an appended finding
    /// stays *unattested* rather than becoming *refuted* — the whole point,
    /// since anybody could have appended it. Nor does the finding subtract
    /// from the ATL v2.0 Section 5.5 tally, which counts *verified* anchors
    /// and has no term for anything else. (Pinned by
    /// `a_receipt_whose_only_anchor_is_refuted_is_unattested_not_refuted`.)
    ///
    /// See [`Self::is_about_the_receipt`].
    AnchorFinding {
        /// Position of the anchor in the receipt's `anchors` array.
        index: usize,
        /// Wire name of the anchor type (`"rfc3161"`, `"bitcoin_ots"`).
        anchor_type: String,
        /// What was found about that anchor.
        finding: Box<VerificationError>,
    },

    /// `anchor.target` is not the value this anchor type mandates.
    ///
    /// ATL v2.0 Section 5.5.1 step 1 (`"data_tree_root"`) and Section 5.5.2
    /// step 1 (`"super_root"`). **A refutation**: the field was read and it is
    /// wrong.
    AnchorTargetInvalid {
        /// Wire name of the anchor type (`"rfc3161"`, `"bitcoin_ots"`).
        anchor_type: String,
        /// The target this anchor type is required to carry.
        expected: String,
        /// The target the anchor actually carries.
        actual: String,
    },

    /// `anchor.target_hash` is not the receipt root this anchor must pin to.
    ///
    /// ATL v2.0 Section 5.5.1 step 2 (`proof.root_hash`) and Section 5.5.2
    /// step 2 (`super_proof.super_root`). **A refutation**, and the most
    /// consequential one an anchor admits: the anchor's evidence is about some
    /// *other* data, so nothing it proves is about this receipt.
    AnchorTargetHashMismatch {
        /// Wire name of the anchor type.
        anchor_type: String,
        /// The receipt's own root, `sha256:` prefixed.
        expected: String,
        /// The `target_hash` the anchor carries, verbatim.
        actual: String,
    },

    /// The anchor's payload could not be decoded at all: an RFC 3161
    /// `token_der` that is not CMS `SignedData` wrapping a `TSTInfo`, or an
    /// `ots_proof` that is not a well-formed `OpenTimestamps` proof over the
    /// expected digest.
    ///
    /// ATL v2.0 Section 5.5.1 step 3 / Section 5.5.2 steps 3-4. **A
    /// refutation**: decoding was attempted on bytes that are present, and
    /// they are not what the anchor type requires.
    AnchorPayloadUndecodable {
        /// Wire name of the anchor type.
        anchor_type: String,
        /// What the decoder reported.
        reason: String,
    },

    /// This build cannot verify anchors of this type, because the Cargo
    /// feature that implements them is not enabled.
    ///
    /// **Not a refutation.** Nothing about the anchor was examined; the
    /// verifier simply has no implementation to examine it with. Reporting it
    /// as a defect would be asserting a verification performed by code that
    /// was compiled out. See [`Self::is_refutation`].
    AnchorTypeUnsupported {
        /// Wire name of the anchor type.
        anchor_type: String,
        /// The Cargo feature that would implement it.
        required_feature: String,
    },

    /// The `bitcoin_block_height` the receipt states is attested by no
    /// attestation in the receipt's own OTS proof.
    ///
    /// ATL v2.0 Section 5.5.2 step 5, height half. **A refutation**, and one
    /// that needs no network: the height is carried inside the proof, so the
    /// receipt's assertion and its own evidence can be compared by pure
    /// computation. The claim holds if it matches *any* attestation.
    BitcoinHeightContradictsProof {
        /// The height the receipt states.
        claimed: u64,
        /// Every height the proof attests to, in proof order.
        attested: Vec<u64>,
    },

    /// No Bitcoin block header was obtained, so the OTS proof's computed
    /// Merkle root was never compared against one, and the receipt's
    /// `bitcoin_block_time` was never compared either.
    ///
    /// ATL v2.0 Section 5.5.2 step 4 ("to the Bitcoin block") and step 5's
    /// time half. **Not a refutation** — it is this crate's defining
    /// constraint showing through: `atl-core` performs no I/O, so it can
    /// decode an OTS proof and check the height the proof itself carries, and
    /// nothing beyond that. A caller that fetches block headers completes the
    /// step; one that does not must not present the anchor as confirmed.
    BitcoinBlockNotObtained,

    /// The token's `MessageImprint` did not come out
    /// [`MessageImprint::Verified`](super::anchors::rfc3161::MessageImprint::Verified).
    ///
    /// The fact itself is the payload, so nothing is lost: `Mismatch` and
    /// `Malformed` are refutations, `Indeterminate` is an inability (the
    /// imprint names a hash algorithm this crate does not implement, so no
    /// comparison happened at all).
    #[cfg(feature = "rfc3161-verify")]
    Rfc3161MessageImprint(super::anchors::rfc3161::MessageImprint),

    /// The CMS `SignerInfo` signature did not come out
    /// [`CmsSignature::Verified`](super::anchors::rfc3161::CmsSignature::Verified).
    ///
    /// `Refuted` is a refutation; `Indeterminate` is an inability — an
    /// algorithm this crate does not implement asserts nothing about the
    /// signature.
    #[cfg(feature = "rfc3161-verify")]
    Rfc3161CmsSignature(super::anchors::rfc3161::CmsSignature),

    /// The signer certificate's `id-kp-timeStamping` Extended Key Usage did
    /// not come out
    /// [`TimestampingEku::Ok`](super::anchors::rfc3161::TimestampingEku::Ok).
    ///
    /// `Absent`, `Malformed`, `NotCritical` and `NotExclusive` were all
    /// *checked* and are refutations. `NotChecked` is an inability: no signer
    /// certificate was settled on, so the extension was never examined.
    #[cfg(feature = "rfc3161-verify")]
    Rfc3161TimestampingEku(super::anchors::rfc3161::TimestampingEku),

    /// Certificate-chain construction did not reach a valid complete path.
    ///
    /// Only [`PathStatus::Invalid`](super::anchors::rfc3161::PathStatus::Invalid)
    /// is a refutation — a candidate link was found and rejected. `Incomplete`
    /// (an issuer certificate is missing) and `Indeterminate` (cryptography
    /// this build does not implement, or the exploration depth limit) are
    /// inabilities.
    ///
    /// `valid_at_gen_time` is carried alongside because a `Complete` path that
    /// nonetheless reports `chain_valid_at_gen_time == false` would be a
    /// contradiction, and therefore a refutation. For every other status that
    /// flag is merely `false` because no complete path was built, which
    /// refutes nothing.
    #[cfg(feature = "rfc3161-verify")]
    Rfc3161CertificatePath {
        /// How chain construction terminated.
        status: super::anchors::rfc3161::PathStatus,
        /// `Rfc3161AnchorFacts::chain_valid_at_gen_time`.
        valid_at_gen_time: bool,
    },

    /// The certificate chain terminated somewhere no caller-supplied trust
    /// store names.
    ///
    /// **Not a refutation.** Every checkable fact may hold; what is missing is
    /// a reason to believe the terminal certificate. A cryptographically
    /// flawless token whose terminal nobody vouches for proves that some key
    /// signed it and no more.
    ///
    /// `terminal` is `None` in the (unreachable today) case of a path reported
    /// complete without naming a terminal at all, and never carries
    /// [`TerminalAnchor::Trusted`](super::anchors::rfc3161::TerminalAnchor::Trusted).
    #[cfg(feature = "rfc3161-verify")]
    Rfc3161TerminalNotTrusted {
        /// The certificate the chain terminated at, when it terminated.
        terminal: Option<super::anchors::rfc3161::TerminalAnchor>,
    },
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
            Self::NoTrustAnchor { required, verified } => write!(
                f,
                "trust not established: {verified} of the {required} verified anchor(s) ATL v2.0 \
                 Section 5.5 requires"
            ),
            Self::AnchorFinding { index, anchor_type, finding } => {
                write!(f, "anchor {index} ({anchor_type}): {finding}")
            }
            Self::AnchorTargetInvalid { anchor_type, expected, actual } => {
                write!(f, "{anchor_type} anchor target must be '{expected}', got '{actual}'")
            }
            Self::AnchorTargetHashMismatch { anchor_type, expected, actual } => write!(
                f,
                "{anchor_type} anchor target_hash mismatch: anchor has {actual}, expected \
                 {expected}"
            ),
            Self::AnchorPayloadUndecodable { anchor_type, reason } => {
                write!(f, "{anchor_type} anchor payload could not be decoded: {reason}")
            }
            Self::AnchorTypeUnsupported { anchor_type, required_feature } => write!(
                f,
                "{anchor_type} anchor verification is not compiled into this build: enable the \
                 '{required_feature}' feature"
            ),
            Self::BitcoinHeightContradictsProof { claimed, attested } => {
                let heights = attested.iter().map(u64::to_string).collect::<Vec<_>>().join(", ");
                write!(
                    f,
                    "bitcoin_block_height mismatch: receipt claims {claimed}, but its OTS proof \
                     attests to no such block (attested: [{heights}])"
                )
            }
            Self::BitcoinBlockNotObtained => write!(
                f,
                "no Bitcoin block header was obtained (this crate performs no I/O), so the OTS \
                 proof's merkle root was not compared against a block and bitcoin_block_time was \
                 not compared either"
            ),
            #[cfg(feature = "rfc3161-verify")]
            Self::Rfc3161MessageImprint(imprint) => match imprint {
                super::anchors::rfc3161::MessageImprint::Verified => {
                    write!(f, "messageImprint verified")
                }
                super::anchors::rfc3161::MessageImprint::Mismatch => write!(
                    f,
                    "messageImprint mismatch: the token attests to data other than the receipt's \
                     Data Tree root"
                ),
                super::anchors::rfc3161::MessageImprint::Malformed => write!(
                    f,
                    "messageImprint is malformed: its hash length contradicts the algorithm it \
                     names"
                ),
                super::anchors::rfc3161::MessageImprint::Indeterminate => write!(
                    f,
                    "messageImprint could not be compared with the receipt's Data Tree root \
                     (nothing was refuted): it names a hash algorithm this build does not \
                     implement"
                ),
            },
            #[cfg(feature = "rfc3161-verify")]
            Self::Rfc3161CmsSignature(signature) => match signature {
                super::anchors::rfc3161::CmsSignature::Verified => {
                    write!(f, "CMS signature verified")
                }
                super::anchors::rfc3161::CmsSignature::Refuted => {
                    write!(f, "CMS signature invalid")
                }
                super::anchors::rfc3161::CmsSignature::Indeterminate => write!(
                    f,
                    "CMS signature could not be checked (nothing was refuted): it uses an \
                     algorithm this build does not implement"
                ),
            },
            #[cfg(feature = "rfc3161-verify")]
            Self::Rfc3161TimestampingEku(eku) => match eku.reason() {
                Some(reason) => {
                    write!(f, "signer certificate's id-kp-timeStamping EKU is not usable: {reason}")
                }
                None => write!(f, "signer certificate's id-kp-timeStamping EKU is usable"),
            },
            #[cfg(feature = "rfc3161-verify")]
            Self::Rfc3161CertificatePath { status, valid_at_gen_time } => match status {
                super::anchors::rfc3161::PathStatus::Invalid => {
                    write!(f, "certificate chain invalid at genTime")
                }
                super::anchors::rfc3161::PathStatus::Incomplete => write!(
                    f,
                    "certificate chain incomplete: an issuer certificate is missing from the token"
                ),
                super::anchors::rfc3161::PathStatus::Indeterminate => write!(
                    f,
                    "certificate chain could not be evaluated (nothing was refuted): it uses \
                     cryptography this build does not implement, or path exploration hit its \
                     depth limit"
                ),
                super::anchors::rfc3161::PathStatus::Complete if !valid_at_gen_time => {
                    write!(f, "certificate chain completed but is not valid at genTime")
                }
                super::anchors::rfc3161::PathStatus::Complete => {
                    write!(f, "certificate chain complete and valid at genTime")
                }
            },
            #[cfg(feature = "rfc3161-verify")]
            Self::Rfc3161TerminalNotTrusted { terminal } => match terminal {
                Some(super::anchors::rfc3161::TerminalAnchor::Assumed {
                    sha256_fingerprint,
                    self_signature,
                }) => {
                    let fingerprint = hex::encode(sha256_fingerprint);
                    match self_signature {
                        super::anchors::rfc3161::SelfSignature::Verified => write!(
                            f,
                            "certificate chain terminates in a certificate no trust store names \
                             (sha256:{fingerprint})"
                        ),
                        super::anchors::rfc3161::SelfSignature::Unverifiable => write!(
                            f,
                            "certificate chain terminates in a self-issued certificate \
                             (sha256:{fingerprint}) whose own signature this build cannot check"
                        ),
                    }
                }
                Some(super::anchors::rfc3161::TerminalAnchor::Trusted { sha256_fingerprint }) => {
                    write!(
                        f,
                        "certificate chain terminates in a trusted anchor (sha256:{})",
                        hex::encode(sha256_fingerprint)
                    )
                }
                None => write!(f, "certificate chain reached no terminal certificate"),
            },
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
    /// * [`Self::NoTrustAnchor`] — too few anchors verified. The absence of
    ///   trust material disproves nothing.
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
    ///
    /// # The anchor findings answer for themselves
    ///
    /// Several of the anchor variants carry the three- or four-valued fact
    /// they report, so the question is settled by the fact rather than by the
    /// variant: `Rfc3161MessageImprint(Indeterminate)` is an inability while
    /// `Rfc3161MessageImprint(Mismatch)` is a refutation, and no consumer has
    /// to know which is which. That is the entire reason the fact travels
    /// inside the error instead of being flattened into a message.
    ///
    /// # Exhaustive on purpose
    ///
    /// The match lists every variant rather than ending in a wildcard. A
    /// wildcard would silently classify the next variant somebody adds, and
    /// the two possible silent answers are "this evidence is disproved" and
    /// "this evidence is merely unchecked" — neither is safe to guess.
    /// Not `const`: [`Self::AnchorFinding`] delegates to the finding it wraps,
    /// and a `Box` cannot be dereferenced in a constant context. The
    /// delegation is the point — an anchor finding's kind is decided by what
    /// was found, never by the fact that it was found on an anchor.
    #[must_use]
    pub fn is_refutation(&self) -> bool {
        match self {
            // Facts about this verifier's reach, never about the document.
            Self::UnsupportedVersion(_)
            | Self::MetadataNotCanonicalizable { .. }
            | Self::SourceTextNotChecked
            | Self::NoTrustAnchor { .. }
            // The anchor type's implementation is compiled out, so nothing
            // about the anchor was examined.
            | Self::AnchorTypeUnsupported { .. }
            // This crate performs no I/O, so no block header was ever fetched
            // to compare the OTS proof against.
            | Self::BitcoinBlockNotObtained => false,

            Self::InvalidReceipt(_)
            | Self::InvalidHash { .. }
            | Self::SignatureFailed
            | Self::InclusionProofFailed { .. }
            | Self::ConsistencyProofFailed { .. }
            | Self::RootHashMismatch
            | Self::TreeSizeMismatch
            | Self::SuperInclusionFailed { .. }
            | Self::SuperConsistencyFailed { .. }
            | Self::SuperDataMismatch { .. }
            | Self::MissingSuperProof
            | Self::MetadataHashMismatch { .. }
            | Self::AnchorTargetInvalid { .. }
            | Self::AnchorTargetHashMismatch { .. }
            | Self::AnchorPayloadUndecodable { .. }
            | Self::BitcoinHeightContradictsProof { .. } => true,

            // The payload decides. `Verified` is never emitted as a finding,
            // and is classified as "not a refutation" for the same reason
            // every other unrefuted state is.
            #[cfg(feature = "rfc3161-verify")]
            Self::Rfc3161MessageImprint(imprint) => imprint.is_refuted(),
            #[cfg(feature = "rfc3161-verify")]
            Self::Rfc3161CmsSignature(signature) => signature.is_refuted(),
            // `NotChecked` means no signer certificate was settled on, so the
            // extension was never examined; every other non-`Ok` state was.
            #[cfg(feature = "rfc3161-verify")]
            Self::Rfc3161TimestampingEku(eku) => !matches!(
                eku,
                super::anchors::rfc3161::TimestampingEku::Ok
                    | super::anchors::rfc3161::TimestampingEku::NotChecked
            ),
            // A candidate link found and rejected refutes; a path that could
            // not be built or evaluated does not. A `Complete` path that is
            // nonetheless invalid at genTime is a contradiction, so it does.
            #[cfg(feature = "rfc3161-verify")]
            Self::Rfc3161CertificatePath { status, valid_at_gen_time } => matches!(
                status,
                super::anchors::rfc3161::PathStatus::Invalid
            ) || (matches!(status, super::anchors::rfc3161::PathStatus::Complete)
                && !*valid_at_gen_time),
            // Nothing is refuted by the absence of a reason to believe a
            // certificate.
            #[cfg(feature = "rfc3161-verify")]
            Self::Rfc3161TerminalNotTrusted { .. } => false,

            // Whether an anchor finding is a refutation is decided by the
            // finding, exactly as it would be if it stood alone. Wrapping
            // records *what it is about*, never *how strong it is*.
            Self::AnchorFinding { finding, .. } => finding.is_refutation(),
        }
    }

    /// Whether this error is a statement about the **receipt**, as opposed to
    /// a statement about one of the anchors attached to it.
    ///
    /// Exactly one variant answers `false`: [`Self::AnchorFinding`].
    ///
    /// # What this distinction is for, and what it is not for
    ///
    /// It decides one thing only — whether the error takes part in the
    /// statuses `ReceiptVerifier::verify` reports about the receipt:
    /// [`VerificationResult::is_valid`] and
    /// [`VerificationResult::is_indeterminate`], both of which are computed
    /// over [`VerificationResult::receipt_errors`].
    ///
    /// ATL v2.0 Section 5.5 sets a *threshold* ("At least one anchor MUST be
    /// verified") and says nothing about anchors beyond those that meet it.
    /// Since the `anchors` array is covered by neither the leaf hash nor the
    /// checkpoint blob, anybody who handles a receipt can append an anchor to
    /// it; a rule that let an anchor which failed verification veto the
    /// verdict would be a denial of verification available to every relay, at
    /// no cost.
    ///
    /// The guarantee this buys is one-sided, and only the one side is
    /// claimed: an anchor that **fails** verification changes no status of the
    /// receipt. An anchor that **passes** raises the verified count and can
    /// carry the receipt over the threshold — as it must, since that is what
    /// anchors are for — and producing one needs a token over this receipt's
    /// root under a caller-supplied trust root, which is exactly what a
    /// stranger cannot do.
    ///
    /// **It is emphatically not a severity ranking, and not a licence to hide
    /// anchor findings.** An anchor that was checked and found false is
    /// evidence that somebody interfered with the receipt, it stays in
    /// [`VerificationResult::errors`], it still answers
    /// [`Self::is_refutation`] as a refutation *of that anchor*, and
    /// [`VerificationResult::anchor_findings`] lists it. A consumer that drops
    /// these on the floor because they do not gate the verdict is concealing
    /// exactly the tampering they exist to reveal.
    ///
    /// What such a finding does **not** do is describe the receipt. The
    /// receipt stays *unattested* rather than becoming *refuted*:
    /// [`VerificationResult::is_indeterminate`] reads
    /// [`VerificationResult::receipt_errors`] alone, which is precisely the
    /// line this predicate draws.
    #[must_use]
    pub const fn is_about_the_receipt(&self) -> bool {
        !matches!(self, Self::AnchorFinding { .. })
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
    /// receipt: when it is `true`, the honest report is *untrusted / not
    /// verified*, never *invalid*.
    ///
    /// # Only receipt-level errors are consulted
    ///
    /// The question asked is *"was **this receipt** shown to be wrong"*, so it
    /// is answered from the errors for which
    /// [`VerificationError::is_about_the_receipt`] holds, and from no others.
    ///
    /// An anchor finding is excluded for the same reason it does not gate
    /// [`Self::is_valid`]: a receipt's `anchors` array is covered by neither
    /// the leaf hash nor the checkpoint signature, so anybody who relays a
    /// receipt can append an entry to it without a key. If a refuted anchor
    /// could make this `false`, that same stranger could flip a receipt's
    /// reported status from "trust could not be established" to "this evidence
    /// is disproved" — an accusation manufactured for free against a document
    /// nothing had disproved. Fixing that for `is_valid` and leaving it here
    /// would have moved the defect one storey up rather than removing it.
    ///
    /// **The finding is still reported.** It stays in [`Self::errors`], it
    /// still answers [`VerificationError::is_refutation`] as a refutation of
    /// *the anchor*, and [`Self::anchor_findings`] lists it. What it does not
    /// do is speak for the receipt.
    ///
    /// Note the scope: this is about an anchor that **failed** verification,
    /// the only kind a stranger can produce. An anchor that verifies moves
    /// [`Self::is_valid`] — see [`VerificationError::is_about_the_receipt`].
    ///
    /// Only meaningful together with [`Self::is_valid`].
    #[must_use]
    pub fn is_indeterminate(&self) -> bool {
        let mut receipt_errors = self.receipt_errors().peekable();
        !self.is_valid
            && receipt_errors.peek().is_some()
            && !self.receipt_errors().any(VerificationError::is_refutation)
    }

    /// The errors that are statements about **the receipt** — the ones every
    /// status this type reports is computed from.
    ///
    /// A consumer building its own verdict should classify from these, not
    /// from [`Self::errors`], for the reason spelled out on
    /// [`Self::is_indeterminate`]: anything derived from the full list can be
    /// steered by whoever last handled the receipt, since appending an anchor
    /// that fails verification adds to it.
    pub fn receipt_errors(&self) -> impl Iterator<Item = &VerificationError> {
        self.errors.iter().filter(|e| e.is_about_the_receipt())
    }

    /// The findings about the receipt's **anchors**.
    ///
    /// Separated out so that "does not decide the verdict" cannot quietly
    /// become "is not shown to anybody". These are how a consumer learns that
    /// a receipt carries an anchor which was checked and found false — the
    /// signature of somebody having interfered with it — and a renderer that
    /// omits them is concealing the very thing they exist to reveal.
    pub fn anchor_findings(&self) -> impl Iterator<Item = &VerificationError> {
        self.errors.iter().filter(|e| !e.is_about_the_receipt())
    }

    /// Check if at least one anchor was verified
    ///
    /// Monotone in the anchor list by construction: each anchor is judged on
    /// its own, so appending one can neither create nor destroy another's
    /// verification.
    #[must_use]
    pub fn has_valid_anchor(&self) -> bool {
        self.anchor_results.iter().any(|a| a.is_valid)
    }

    /// Get the first error (if any)
    ///
    /// **Not a status.** This walks the whole list, anchor findings included,
    /// and their position depends on where in the `anchors` array they sit —
    /// which anybody handling the receipt controls. Use it for display, and
    /// [`Self::receipt_errors`] to decide anything.
    #[must_use]
    pub fn first_error(&self) -> Option<&VerificationError> {
        self.errors.first()
    }

    /// Get all errors
    ///
    /// Everything found, in the order it was found: receipt-level errors and
    /// anchor findings together. Both must be shown to a user; only the
    /// receipt-level ones may decide a verdict. See [`Self::receipt_errors`]
    /// and [`Self::anchor_findings`].
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
