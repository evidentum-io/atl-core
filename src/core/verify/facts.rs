//! Per-anchor facts: what ATL v2.0 Section 5.5 established about each anchor,
//! reported without a verdict.
//!
//! # Why this module exists
//!
//! [`ReceiptVerifier::verify`](super::verifier::ReceiptVerifier::verify)
//! collapses every anchor to
//! [`AnchorVerificationResult`](super::types::AnchorVerificationResult), whose
//! load-bearing field is a single `is_valid: bool`. That boolean cannot tell
//! a caller whether an anchor was **checked and found false** or **not checked
//! at all**, and those two call for opposite reactions: one is evidence
//! against the receipt, the other is a gap in the verifier.
//!
//! A caller that needs the distinction has had exactly one option: set
//! [`VerifyOptions::skip_anchors`](super::types::VerifyOptions::skip_anchors)
//! and re-implement Section 5.5 itself. That is not a duplicated hash
//! computation — the cryptography was always available through
//! [`verify_rfc3161_token`](super::anchors::rfc3161::verify_rfc3161_token) and
//! [`verify_ots_anchor_impl`](super::anchors::bitcoin_ots::verify_ots_anchor_impl)
//! — it is a duplicated *protocol orchestration*: binding the anchor to the
//! receipt's own root, deciding which facts refute and which merely fail to
//! confirm, and reducing them to an outcome. Two implementations of a
//! mandatory rule drift, and every defect fixed on one side stays open on the
//! other.
//!
//! [`verify_receipt_anchors`] is that orchestration, published as facts.
//!
//! # Three outcomes, one dictionary
//!
//! Every check that did not come out verified is recorded as a
//! [`VerificationError`], and
//! [`VerificationError::is_refutation`] splits them into the two kinds:
//!
//! * **refuted** — something checkable was checked and is false;
//! * **indeterminate** — nothing was refuted and a check could not be
//!   finished.
//!
//! No new vocabulary is introduced for this: the crate already draws the same
//! line in [`PathStatus`](super::anchors::rfc3161::PathStatus),
//! [`MessageImprint`](super::anchors::rfc3161::MessageImprint) and
//! [`CmsSignature`](super::anchors::rfc3161::CmsSignature), and those enums
//! travel inside the findings rather than being flattened away.
//!
//! **Any refutation outranks every inability.** [`AnchorFacts::is_refuted`]
//! is asked before [`AnchorFacts::is_indeterminate`] can be true, and the
//! findings are gathered in full before either is consulted — an inability met
//! first must never suppress a refutation found later, and a refutation must
//! never be manufactured out of an inability.

use crate::core::checkpoint::parse_hash;
use crate::core::receipt::{
    format_hash, Receipt, ReceiptAnchor, ANCHOR_TARGET_DATA_TREE_ROOT, ANCHOR_TARGET_SUPER_ROOT,
};

use super::iso8601::parse_iso8601_to_nanos;
use super::types::{VerificationError, VerifyOptions};

/// The complete fact set for one anchor, with no verdict formed.
///
/// Construct it only through [`verify_receipt_anchors`]. The fields are
/// private because the relationship between [`Self::findings`] and the three
/// predicates below is the type's whole contract; an assembled value could
/// claim an outcome its findings do not support.
#[derive(Debug, Clone)]
pub struct AnchorFacts {
    anchor_type: &'static str,
    claimed_timestamp: Option<u64>,
    evidence: AnchorEvidence,
    findings: Vec<VerificationError>,
}

impl AnchorFacts {
    /// Wire name of the anchor type: `"rfc3161"` or `"bitcoin_ots"`.
    #[must_use]
    pub const fn anchor_type(&self) -> &'static str {
        self.anchor_type
    }

    /// The time this anchor **asserts**, in nanoseconds since the Unix epoch.
    ///
    /// What the anchor claims, never what was established. For an RFC 3161
    /// anchor it is the token's own `genTime` — read out of the decoded
    /// `TSTInfo` before any signature is checked — falling back to the
    /// anchor's `timestamp` field when the token would not decode. For a
    /// `bitcoin_ots` anchor it is that `timestamp` field, which is all there
    /// is: the *confirming* time lives in a block header this crate never
    /// fetches. It is `None` only for an anchor whose `target` names the wrong
    /// root, which is rejected before any time is read.
    ///
    /// Attacker-controlled until [`Self::is_verified`] holds. Use
    /// [`Self::established_timestamp`] when a *fact* is wanted.
    #[must_use]
    pub const fn claimed_timestamp(&self) -> Option<u64> {
        self.claimed_timestamp
    }

    /// The time this anchor **establishes**, or `None`.
    ///
    /// `Some` only when [`Self::is_verified`] holds, so a consumer cannot
    /// mistake the anchor's claim for a verified fact by reading the wrong
    /// field. The claim itself is never discarded — see
    /// [`Self::claimed_timestamp`].
    #[must_use]
    pub fn established_timestamp(&self) -> Option<u64> {
        if self.is_verified() {
            self.claimed_timestamp
        } else {
            None
        }
    }

    /// The full fact set read out of the anchor's payload, when one was read.
    #[must_use]
    pub const fn evidence(&self) -> &AnchorEvidence {
        &self.evidence
    }

    /// Every check that did not come out verified, in the order the steps run.
    ///
    /// Empty exactly when [`Self::is_verified`] holds. Nothing here is
    /// collapsed: a consumer that wants to explain the outcome reads these,
    /// and a consumer that wants to classify it asks
    /// [`VerificationError::is_refutation`] of each.
    #[must_use]
    pub fn findings(&self) -> &[VerificationError] {
        &self.findings
    }

    /// The findings that are evidence **against** the anchor.
    pub fn refutations(&self) -> impl Iterator<Item = &VerificationError> {
        self.findings.iter().filter(|e| e.is_refutation())
    }

    /// The findings that record a check this verifier could not finish.
    pub fn inabilities(&self) -> impl Iterator<Item = &VerificationError> {
        self.findings.iter().filter(|e| !e.is_refutation())
    }

    /// Every check came out verified.
    ///
    /// For a `bitcoin_ots` anchor this is never `true` from this crate alone:
    /// confirming one means comparing the OTS proof's Merkle root against a
    /// block header, which is I/O `atl-core` does not perform, so
    /// [`VerificationError::BitcoinBlockNotObtained`] is always among the
    /// findings. That is the honest report, and it is why this predicate is
    /// not the same question as
    /// [`AnchorVerificationResult::is_valid`](super::types::AnchorVerificationResult::is_valid).
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.findings.is_empty()
    }

    /// At least one fact about this anchor was checked and is false.
    ///
    /// Ranks above [`Self::is_indeterminate`]: an anchor can carry both kinds
    /// of finding at once, and when it does, the refutation decides.
    #[must_use]
    pub fn is_refuted(&self) -> bool {
        self.findings.iter().any(VerificationError::is_refutation)
    }

    /// Nothing was refuted, and at least one check could not be finished.
    ///
    /// The three predicates partition: exactly one of [`Self::is_verified`],
    /// [`Self::is_refuted`] and this one holds for any `AnchorFacts`.
    #[must_use]
    pub fn is_indeterminate(&self) -> bool {
        !self.findings.is_empty() && !self.is_refuted()
    }
}

/// The facts read out of an anchor's payload.
///
/// [`Self::None`] is not "nothing is wrong": it means the payload was never
/// read, because the anchor did not bind to this receipt, would not decode, or
/// belongs to a type this build does not implement. The findings say which.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AnchorEvidence {
    /// No payload was read. See the findings for why.
    None,

    /// The complete fact set from this crate's RFC 3161 verifier.
    ///
    /// Boxed because it is by far the largest variant, and an
    /// [`AnchorFacts`] is held one per anchor in a `Vec`.
    #[cfg(feature = "rfc3161-verify")]
    Rfc3161(Box<super::anchors::rfc3161::Rfc3161AnchorFacts>),

    /// Everything a Bitcoin `OpenTimestamps` anchor establishes without a
    /// network.
    #[cfg(feature = "bitcoin-ots")]
    BitcoinOts(Box<BitcoinOtsAnchorFacts>),
}

/// Everything a `bitcoin_ots` anchor establishes by pure computation.
///
/// # What is deliberately absent
///
/// There is no field for the block's Merkle root, its time, or its hash.
/// `atl-core` performs no I/O, so it never obtains a block header, and a field
/// that would always be empty invites a reader to treat its emptiness as a
/// value. The corresponding finding —
/// [`VerificationError::BitcoinBlockNotObtained`] — says so in the one place a
/// consumer is already required to look.
#[cfg(feature = "bitcoin-ots")]
#[derive(Debug, Clone)]
pub struct BitcoinOtsAnchorFacts {
    /// Every block height the OTS proof attests to, in proof order.
    ///
    /// The evidence behind a height refutation: a reader told the receipt's
    /// claim matches nothing must be able to see what the proof does attest
    /// to, or the finding cannot be checked.
    pub attested_block_heights: Vec<u64>,

    /// The block height **the receipt states**, in its `bitcoin_block_height`
    /// field.
    ///
    /// The receipt's own assertion, published verbatim and never as an
    /// established fact.
    pub receipt_block_height: u64,

    /// The block time **the receipt states**, verbatim and unparsed.
    ///
    /// Kept exactly as written rather than normalised: this crate never
    /// compares it with anything (the block time exists only in a header), so
    /// the honest thing to hand on is the string itself.
    pub receipt_block_time: String,

    /// The attestation selected by the receipt's claimed height, if any.
    ///
    /// `None` when the proof did not decode, or when no attestation carries
    /// the height the receipt states — the refutation reported as
    /// [`VerificationError::BitcoinHeightContradictsProof`]. Picking some
    /// other attestation there (the lowest, say) would apply a rule ATL v2.0
    /// Section 5.5.2 nowhere states.
    pub attestation: Option<crate::core::ots::BitcoinAttestation>,

    /// The Merkle root the selected attestation's path computes to,
    /// `sha256:` prefixed and in Bitcoin's display (byte-reversed) order.
    ///
    /// This is the value a caller with network access compares against the
    /// block header at [`Self::receipt_block_height`]. It is *not* an
    /// established fact about Bitcoin: nothing here has seen a block.
    pub computed_block_merkle_root: Option<String>,
}

/// Establish the facts for every anchor the receipt presents, in receipt
/// order, forming no verdict.
///
/// This is ATL v2.0 Section 5.5 as a fact-producing operation: each anchor is
/// bound to the receipt's own root, its payload is decoded, and every check
/// the specification names is run and reported. What the outcome *means* —
/// how many verified anchors a caller demands, whether an untrusted terminal
/// is acceptable, what exit code to return — is the caller's policy and is
/// deliberately not decided here.
///
/// # Options
///
/// Only [`VerifyOptions::rfc3161_trust_store`] is consulted. Trust material
/// arrives from the caller and from nowhere else: a certificate found inside
/// the token being verified is never promoted to a trust anchor, so with no
/// store an RFC 3161 anchor can at best reach
/// [`TerminalAnchor::Assumed`](super::anchors::rfc3161::TerminalAnchor::Assumed)
/// and reports [`VerificationError::Rfc3161TerminalNotTrusted`].
///
/// [`VerifyOptions::skip_anchors`] is **not** consulted: this function is the
/// anchor step, and honouring a flag that asks to skip it would return an
/// empty result indistinguishable from a receipt with no anchors.
///
/// # Scope: Section 5.5 and only Section 5.5
///
/// **This function is not a whole-receipt verification, and a caller that
/// treats it as one will accept receipts nothing has checked.** It covers ATL
/// v2.0 Section 5.5 — the anchors — in full, and covers nothing else.
///
/// Sections 5.1 through 5.4 remain with
/// [`ReceiptVerifier::verify`](super::verifier::ReceiptVerifier::verify):
/// reconstructing the leaf hash and confirming `metadata_hash` (5.1), the
/// checkpoint's internal consistency and signature (5.2), the Merkle
/// inclusion proof (5.3), and the Super-Tree inclusion and
/// consistency-to-origin proofs (5.4). An anchor commits to a *root*; that
/// the entry in hand is under that root is what those sections establish, and
/// a verified anchor over a root the receipt cannot reach proves nothing
/// about the entry.
///
/// A verdict about a receipt therefore needs both calls. They are not merged
/// today because the receipt half already reports facts of its own
/// ([`VerificationResult::errors`](super::types::VerificationResult::errors)
/// plus [`VerificationError::is_refutation`]), and because
/// `ReceiptVerifier::verify` itself calls this function, so the two can never
/// disagree about what was checked.
///
/// # What no build of this crate can answer
///
/// Anything requiring I/O. A `bitcoin_ots` anchor always carries
/// [`VerificationError::BitcoinBlockNotObtained`], so it is always
/// [`AnchorFacts::is_indeterminate`] here; a caller that fetches block
/// headers resolves it. Revocation is likewise never checked.
///
/// # Examples
///
/// ```rust
/// use atl_core::{verify_receipt_anchors, Receipt, VerifyOptions};
///
/// # let json = r#"{"spec_version":"2.0.0","entry":{"id":"00000000-0000-0000-0000-000000000000","payload_hash":"sha256:1111111111111111111111111111111111111111111111111111111111111111","metadata_hash":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","metadata":{}},"proof":{"tree_size":1,"root_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","inclusion_path":[],"leaf_index":0,"checkpoint":{"origin":"sha256:0000000000000000000000000000000000000000000000000000000000000000","tree_size":1,"root_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestamp":1704067200000000000,"signature":"base64:AAAA","key_id":"sha256:4444444444444444444444444444444444444444444444444444444444444444"}},"anchors":[]}"#;
/// let receipt = Receipt::from_json(json)?;
///
/// for anchor in verify_receipt_anchors(&receipt, &VerifyOptions::default()) {
///     if anchor.is_refuted() {
///         // A fact about THIS ANCHOR was checked and is false. Report it:
///         // an anchor is something anybody who relayed the receipt could
///         // have appended, so a refuted one is evidence that somebody
///         // interfered. It is NOT evidence against the receipt -- see below.
///     } else if anchor.is_indeterminate() {
///         // Nothing was refuted; this check could not be finished. Do not
///         // present it as a broken anchor either.
///     }
/// }
///
/// // The receipt's own verdict is a separate question, and no anchor finding
/// // takes part in it: `ReceiptVerifier::verify`, read through
/// // `VerificationResult::receipt_errors`.
/// # Ok::<(), atl_core::AtlError>(())
/// ```
#[must_use]
pub fn verify_receipt_anchors(receipt: &Receipt, options: &VerifyOptions) -> Vec<AnchorFacts> {
    receipt
        .anchors()
        .iter()
        .map(|anchor| {
            let expected_root = expected_root_for(receipt, anchor);
            anchor_facts(anchor, expected_root, options)
        })
        .collect()
}

/// The receipt root this anchor type is required to pin to.
///
/// ATL v2.0 Section 5.5.1 step 2 names `proof.root_hash` and Section 5.5.2
/// step 2 names `super_proof.super_root`. Anything that stops the root from
/// being read at all is returned as the finding that will be reported against
/// the anchor: an anchor cannot be bound to a root the receipt does not
/// supply, and saying so is more use than a generic failure.
fn expected_root_for(
    receipt: &Receipt,
    anchor: &ReceiptAnchor,
) -> Result<[u8; 32], VerificationError> {
    match anchor {
        ReceiptAnchor::Rfc3161 { .. } => {
            parse_hash(&receipt.proof().root_hash).map_err(|e| VerificationError::InvalidHash {
                field: "proof.root_hash".to_string(),
                message: e.to_string(),
            })
        }
        ReceiptAnchor::BitcoinOts { .. } => {
            // No `super_proof` means there is no super root for a
            // `super_root` anchor to target, so the anchor cannot be bound to
            // this receipt at all.
            let super_proof = receipt.super_proof().ok_or(VerificationError::MissingSuperProof)?;
            parse_hash(&super_proof.super_root).map_err(|e| VerificationError::InvalidHash {
                field: "super_proof.super_root".to_string(),
                message: e.to_string(),
            })
        }
    }
}

/// Bind one anchor to `expected_root` and read whatever evidence it carries.
///
/// `expected_root` is the root the anchor must pin to, already resolved by the
/// caller: this function never derives it, so the pinning rule has exactly one
/// implementation and a caller with a differently-obtained root (the legacy
/// [`verify_anchor`](super::helpers::verify_anchor) path) runs the same code.
pub(in crate::core) fn anchor_facts(
    anchor: &ReceiptAnchor,
    expected_root: Result<[u8; 32], VerificationError>,
    options: &VerifyOptions,
) -> AnchorFacts {
    let anchor_type = anchor.anchor_type();

    // ATL v2.0 Section 5.5.1 steps 1-2 / Section 5.5.2 steps 1-2. Binding
    // comes before every cryptographic step, and a failure here stops the
    // anchor: without it a genuine token minted over unrelated data would be
    // read as evidence about this receipt.
    let expected_target = match anchor {
        ReceiptAnchor::Rfc3161 { .. } => ANCHOR_TARGET_DATA_TREE_ROOT,
        ReceiptAnchor::BitcoinOts { .. } => ANCHOR_TARGET_SUPER_ROOT,
    };
    if anchor.target() != expected_target {
        return rejected(
            anchor_type,
            None,
            VerificationError::AnchorTargetInvalid {
                anchor_type: anchor_type.to_string(),
                expected: expected_target.to_string(),
                actual: anchor.target().to_string(),
            },
        );
    }

    let expected_root = match expected_root {
        Ok(root) => root,
        Err(finding) => return rejected(anchor_type, None, finding),
    };

    let claimed_hash = match parse_hash(anchor.target_hash()) {
        Ok(hash) => hash,
        Err(e) => {
            return rejected(
                anchor_type,
                None,
                VerificationError::InvalidHash {
                    field: "anchor.target_hash".to_string(),
                    message: e.to_string(),
                },
            )
        }
    };

    if !constant_time_eq(&claimed_hash, &expected_root) {
        return rejected(
            anchor_type,
            None,
            VerificationError::AnchorTargetHashMismatch {
                anchor_type: anchor_type.to_string(),
                expected: format_hash(&expected_root),
                actual: anchor.target_hash().to_string(),
            },
        );
    }

    // The anchor is pinned to this receipt. Everything from here on is about
    // the anchor's own payload, and `expected_root` -- the receipt's root, now
    // proven equal to the anchor's claim -- is what the payload is checked
    // against, never the anchor's claim itself.
    match anchor {
        ReceiptAnchor::Rfc3161 { timestamp, token_der, .. } => {
            rfc3161_facts(timestamp, token_der, &expected_root, options)
        }
        ReceiptAnchor::BitcoinOts {
            timestamp,
            ots_proof,
            bitcoin_block_height,
            bitcoin_block_time,
            ..
        } => bitcoin_ots_facts(
            timestamp,
            ots_proof,
            &expected_root,
            *bitcoin_block_height,
            bitcoin_block_time,
        ),
    }
}

/// An anchor rejected before any payload was read.
fn rejected(
    anchor_type: &'static str,
    claimed_timestamp: Option<u64>,
    finding: VerificationError,
) -> AnchorFacts {
    AnchorFacts {
        anchor_type,
        claimed_timestamp,
        evidence: AnchorEvidence::None,
        findings: vec![finding],
    }
}

/// Constant-time 32-byte comparison.
///
/// These hashes are published inside the receipt and are not secret. The
/// comparison is constant-time all the same, because this crate compares no
/// digest with `==` anywhere, and a rule with an exception is a rule nobody
/// checks.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// ATL v2.0 Section 5.5.1 steps 3-5, plus certificate-path construction and
/// the RFC 3161 2.3 EKU rule.
#[cfg(feature = "rfc3161-verify")]
fn rfc3161_facts(
    timestamp: &str,
    token_der: &str,
    expected_root: &[u8; 32],
    options: &VerifyOptions,
) -> AnchorFacts {
    use super::anchors::rfc3161::{
        verify_rfc3161_token, MessageImprint, PathStatus, TerminalAnchor, TimestampingEku,
    };

    let facts = match verify_rfc3161_token(
        token_der,
        expected_root,
        options.rfc3161_trust_store.as_ref(),
    ) {
        Ok(facts) => facts,
        Err(e) => {
            return rejected(
                "rfc3161",
                parse_iso8601_to_nanos(timestamp),
                VerificationError::AnchorPayloadUndecodable {
                    anchor_type: "rfc3161".to_string(),
                    reason: e.to_string(),
                },
            )
        }
    };

    // Every fact is collected before any of them is weighed. An earlier
    // consumer of this fact set returned on the first non-verified fact it
    // met, which meant an inability encountered first silently suppressed a
    // refutation found later -- an `Indeterminate` imprint together with a
    // `Refuted` CMS signature came out as "nothing was refuted".
    let mut findings = Vec::new();

    if !matches!(facts.message_imprint, MessageImprint::Verified) {
        findings.push(VerificationError::Rfc3161MessageImprint(facts.message_imprint));
    }
    if !facts.cms_signature.is_verified() {
        findings.push(VerificationError::Rfc3161CmsSignature(facts.cms_signature));
    }
    if !matches!(facts.timestamping_eku, TimestampingEku::Ok) {
        findings.push(VerificationError::Rfc3161TimestampingEku(facts.timestamping_eku));
    }
    // `chain_valid_at_gen_time` is `false` whenever no complete path was
    // built, so it is only a contradiction -- and only then a refutation --
    // when the path did complete. Both halves travel in the finding so a
    // consumer never has to know that rule.
    if !matches!(facts.path_status, PathStatus::Complete) || !facts.chain_valid_at_gen_time {
        findings.push(VerificationError::Rfc3161CertificatePath {
            status: facts.path_status,
            valid_at_gen_time: facts.chain_valid_at_gen_time,
        });
    }
    // A terminal the caller does not vouch for is reported whatever the path
    // status: an `Indeterminate` path can still carry an `Assumed` terminal,
    // and both are things the caller may want to act on. Only a `Trusted`
    // terminal is silent.
    if !matches!(facts.terminal_anchor, Some(TerminalAnchor::Trusted { .. })) {
        findings
            .push(VerificationError::Rfc3161TerminalNotTrusted { terminal: facts.terminal_anchor });
    }

    AnchorFacts {
        anchor_type: "rfc3161",
        claimed_timestamp: facts.gen_time.or_else(|| parse_iso8601_to_nanos(timestamp)),
        evidence: AnchorEvidence::Rfc3161(Box::new(facts)),
        findings,
    }
}

/// The `rfc3161-verify` feature is compiled out, so nothing about the token
/// was examined.
#[cfg(not(feature = "rfc3161-verify"))]
fn rfc3161_facts(
    timestamp: &str,
    _token_der: &str,
    _expected_root: &[u8; 32],
    _options: &VerifyOptions,
) -> AnchorFacts {
    rejected(
        "rfc3161",
        parse_iso8601_to_nanos(timestamp),
        VerificationError::AnchorTypeUnsupported {
            anchor_type: "rfc3161".to_string(),
            required_feature: "rfc3161-verify".to_string(),
        },
    )
}

/// ATL v2.0 Section 5.5.2 steps 3-5, as far as a crate that performs no I/O
/// can carry them.
///
/// Step 5 splits by what the network is needed for. The height is *in* the
/// proof -- an `OpenTimestamps` Bitcoin attestation encodes it -- so comparing
/// it with the receipt's own field is pure computation and is done here; a
/// receipt whose stated height its own proof contradicts is **refuted**,
/// offline included. The block time is in no proof, and step 4's "to the
/// Bitcoin block" needs a header nobody here can fetch, so both are reported
/// as the one inability [`VerificationError::BitcoinBlockNotObtained`].
#[cfg(feature = "bitcoin-ots")]
fn bitcoin_ots_facts(
    timestamp: &str,
    ots_proof: &str,
    expected_root: &[u8; 32],
    receipt_block_height: u64,
    receipt_block_time: &str,
) -> AnchorFacts {
    use super::anchors::bitcoin_ots::verify_ots_anchor_impl;
    use crate::core::ots::{attestation_for_claimed_height, attested_block_heights};

    let bare =
        |attested: Vec<u64>, attestation, computed_block_merkle_root| BitcoinOtsAnchorFacts {
            attested_block_heights: attested,
            receipt_block_height,
            receipt_block_time: receipt_block_time.to_string(),
            attestation,
            computed_block_merkle_root,
        };

    let result = match verify_ots_anchor_impl(ots_proof, expected_root) {
        Ok(result) => result,
        Err(e) => {
            return AnchorFacts {
                anchor_type: "bitcoin_ots",
                claimed_timestamp: parse_iso8601_to_nanos(timestamp),
                // The receipt's own two claims are published for a damaged
                // anchor as well as a sound one: they are what a reader most
                // wants to see beside a proof that would not decode.
                evidence: AnchorEvidence::BitcoinOts(Box::new(bare(Vec::new(), None, None))),
                findings: vec![VerificationError::AnchorPayloadUndecodable {
                    anchor_type: "bitcoin_ots".to_string(),
                    reason: e.to_string(),
                }],
            };
        }
    };

    let attested = attested_block_heights(&result.attestations);

    // The claim holds if it matches ANY attestation. Comparing against the
    // lowest -- a criterion Section 5.5.2 nowhere states -- would refute a
    // receipt naming a block genuinely present in its own proof.
    let Some(attestation) =
        attestation_for_claimed_height(&result.attestations, receipt_block_height)
    else {
        return AnchorFacts {
            anchor_type: "bitcoin_ots",
            claimed_timestamp: parse_iso8601_to_nanos(timestamp),
            evidence: AnchorEvidence::BitcoinOts(Box::new(bare(attested.clone(), None, None))),
            findings: vec![
                VerificationError::BitcoinHeightContradictsProof {
                    claimed: receipt_block_height,
                    attested,
                },
                // The block was not obtained either. Reported alongside
                // rather than instead: a refutation settles the outcome, but
                // it does not make the unperformed check performed.
                VerificationError::BitcoinBlockNotObtained,
            ],
        };
    };

    // Bitcoin displays hashes byte-reversed relative to their internal form,
    // so the value published here is the one a block explorer's `merkle_root`
    // can be compared with directly.
    let computed_block_merkle_root = attestation.merkle_path.last().map(|last| {
        let mut reversed = *last;
        reversed.reverse();
        format!("sha256:{}", hex::encode(reversed))
    });

    let mut findings = Vec::new();
    if computed_block_merkle_root.is_none() {
        findings.push(VerificationError::AnchorPayloadUndecodable {
            anchor_type: "bitcoin_ots".to_string(),
            reason: "the selected Bitcoin attestation has an empty merkle path".to_string(),
        });
    }
    findings.push(VerificationError::BitcoinBlockNotObtained);

    AnchorFacts {
        anchor_type: "bitcoin_ots",
        // The anchor's own `timestamp` field: what it asserts, never what was
        // established. No block header was obtained, so nothing here is a
        // fact -- which is exactly why `established_timestamp` withholds it
        // until every check has passed. The receipt's separate claim about
        // the *block's* time travels as `receipt_block_time`.
        claimed_timestamp: parse_iso8601_to_nanos(timestamp),
        evidence: AnchorEvidence::BitcoinOts(Box::new(bare(
            attested,
            Some(attestation.clone()),
            computed_block_merkle_root,
        ))),
        findings,
    }
}

/// The `bitcoin-ots` feature is compiled out, so nothing about the proof was
/// examined.
#[cfg(not(feature = "bitcoin-ots"))]
fn bitcoin_ots_facts(
    timestamp: &str,
    _ots_proof: &str,
    _expected_root: &[u8; 32],
    _receipt_block_height: u64,
    _receipt_block_time: &str,
) -> AnchorFacts {
    rejected(
        "bitcoin_ots",
        parse_iso8601_to_nanos(timestamp),
        VerificationError::AnchorTypeUnsupported {
            anchor_type: "bitcoin_ots".to_string(),
            required_feature: "bitcoin-ots".to_string(),
        },
    )
}
