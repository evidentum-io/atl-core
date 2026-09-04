//! Tests for [`verify_receipt_anchors`] — the per-anchor fact set.
//!
//! Every anchor kind is exercised across all three outcomes, because the
//! three-way split is the whole reason this API exists and a suite that only
//! walks the happy path would not notice it collapsing back into two.
//!
//! * **verified** — no findings at all;
//! * **refuted** — something checkable was checked and is false;
//! * **indeterminate** — nothing was refuted and a check could not be
//!   finished.
//!
//! The rule those tests exist to protect is that **any refutation outranks
//! every inability**, in both directions: an inability must never be reported
//! as a refutation, and a refutation must never be concealed by an inability
//! that happens to sit beside it.

use crate::core::checkpoint::{compute_key_id, Checkpoint, CheckpointJson};
use crate::core::jcs::canonicalize_and_hash;
use crate::core::receipt::{
    format_hash, format_signature, Receipt, ReceiptAnchor, ReceiptBuilder, ReceiptEntry,
    ReceiptProof, SourceTextCheck, SuperProof, RECEIPT_SPEC_VERSION,
};
use crate::core::verify::facts::verify_receipt_anchors;
use crate::core::verify::{AnchorFacts, VerificationError, VerifyOptions};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

// ===========================================================================
// Fixtures
// ===========================================================================

/// A receipt whose Data Tree root and Super-Tree root are `root_hash`, and
/// which presents `anchors`.
///
/// The inclusion proof and the checkpoint signature are irrelevant here —
/// `verify_receipt_anchors` reads only the two roots and the anchors — so they
/// are left trivially self-consistent rather than separately constructed.
fn receipt_with(root_hash: [u8; 32], anchors: Vec<ReceiptAnchor>) -> Receipt {
    receipt_with_roots(&format_hash(&root_hash), Some(&format_hash(&root_hash)), anchors)
}

/// The same, with both roots supplied verbatim so a test can hand in a string
/// that is not a hash at all, or omit the `super_proof` entirely.
fn receipt_with_roots(
    root_hash: &str,
    super_root: Option<&str>,
    anchors: Vec<ReceiptAnchor>,
) -> Receipt {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let origin = [1u8; 32];
    let tree_size = 1u64;
    let timestamp = 1_704_067_200_000_000_000u64;
    let checkpoint_root = [0u8; 32];

    let mut blob = [0u8; 98];
    blob[0..18].copy_from_slice(b"ATL-Protocol-v1-CP");
    blob[18..50].copy_from_slice(&origin);
    blob[50..58].copy_from_slice(&tree_size.to_le_bytes());
    blob[58..66].copy_from_slice(&timestamp.to_le_bytes());
    blob[66..98].copy_from_slice(&checkpoint_root);
    let signature = signing_key.sign(&blob);
    let key_id = compute_key_id(&signing_key.verifying_key().to_bytes());
    let checkpoint = Checkpoint::new(
        origin,
        tree_size,
        timestamp,
        checkpoint_root,
        signature.to_bytes(),
        key_id,
    );

    let metadata = json!({});
    let metadata_hash = format_hash(
        &canonicalize_and_hash(&metadata).expect("metadata satisfies RFC 8785 Section 3.1"),
    );

    let super_proof = super_root.map(|sr| SuperProof {
        genesis_super_root: sr.to_string(),
        data_tree_index: 0,
        super_tree_size: 1,
        super_root: sr.to_string(),
        inclusion: vec![],
        consistency_to_origin: vec![],
    });

    ReceiptBuilder::new(
        RECEIPT_SPEC_VERSION.to_string(),
        ReceiptEntry {
            id: uuid::Uuid::nil(),
            payload_hash: format_hash(&[0xaa; 32]),
            metadata_hash,
            metadata,
        },
        ReceiptProof {
            tree_size: 1,
            root_hash: root_hash.to_string(),
            inclusion_path: vec![],
            leaf_index: 0,
            checkpoint: CheckpointJson {
                origin: format_hash(&checkpoint.origin),
                tree_size: checkpoint.tree_size,
                // Must equal `proof.root_hash` verbatim: `ReceiptVerifier`
                // rejects the receipt before the anchor step otherwise, and
                // these fixtures exist to reach the anchor step.
                root_hash: root_hash.to_string(),
                timestamp: checkpoint.timestamp,
                signature: format_signature(&checkpoint.signature),
                key_id: format_hash(&checkpoint.key_id),
            },
            consistency_proof: None,
        },
    )
    .super_proof_option(super_proof)
    .anchors(anchors)
    .build(SourceTextCheck::assume_duplicate_property_names_already_rejected())
}

/// A receipt whose **proofs genuinely hold**: the Merkle root is the entry's
/// own leaf hash in a one-leaf tree, and the Super-Tree is that same root at
/// index 0 of a one-entry tree, consistent with its own genesis.
///
/// Needed wherever the receipt-level verdict is under test: with the proofs
/// sound, whatever `ReceiptVerifier::verify` reports comes from the anchors
/// and from nothing else.
fn sound_receipt(anchors_for_root: impl Fn(&str) -> Vec<ReceiptAnchor>) -> Receipt {
    let payload_hash = [0xaa; 32];
    let metadata = json!({});
    let metadata_hash =
        canonicalize_and_hash(&metadata).expect("metadata satisfies RFC 8785 Section 3.1");
    // A one-leaf tree's root is its leaf hash, so this is the only root that
    // makes the inclusion proof check out with an empty path.
    let root = crate::core::merkle::compute_leaf_hash(&payload_hash, &metadata_hash);
    let root_hash = format_hash(&root);

    receipt_with_roots(&root_hash, Some(&root_hash), anchors_for_root(&root_hash))
}

fn rfc3161_anchor(target: &str, target_hash: &str, token_der: &str) -> ReceiptAnchor {
    ReceiptAnchor::Rfc3161 {
        target: target.to_string(),
        target_hash: target_hash.to_string(),
        tsa_url: "https://freetsa.org/tsr".to_string(),
        timestamp: "2026-01-04T21:57:43Z".to_string(),
        token_der: token_der.to_string(),
    }
}

fn bitcoin_anchor(
    target: &str,
    target_hash: &str,
    block_height: u64,
    ots_proof: &str,
) -> ReceiptAnchor {
    ReceiptAnchor::BitcoinOts {
        target: target.to_string(),
        target_hash: target_hash.to_string(),
        timestamp: "2026-01-04T21:57:43Z".to_string(),
        bitcoin_block_height: block_height,
        bitcoin_block_time: "2026-01-04T22:10:00Z".to_string(),
        ots_proof: ots_proof.to_string(),
    }
}

fn facts_for(receipt: &Receipt) -> Vec<AnchorFacts> {
    verify_receipt_anchors(receipt, &VerifyOptions::default())
}

/// Every `AnchorFacts` is in exactly one of the three states, always.
///
/// Asserted on every fixture rather than once, because the partition is a
/// property of the type and a state that satisfies two of the predicates
/// would be a contradiction wherever it appeared.
fn assert_partitioned(facts: &AnchorFacts) {
    let states = [facts.is_verified(), facts.is_refuted(), facts.is_indeterminate()];
    assert_eq!(
        states.iter().filter(|s| **s).count(),
        1,
        "verified/refuted/indeterminate must partition, got {states:?} for {:?}",
        facts.findings()
    );
}

// ===========================================================================
// Shape of the composition
// ===========================================================================

#[test]
fn one_fact_set_per_anchor_in_receipt_order() {
    let root = [0x11; 32];
    let receipt = receipt_with(
        root,
        vec![
            rfc3161_anchor("data_tree_root", &format_hash(&root), "base64:AAAA"),
            bitcoin_anchor("super_root", &format_hash(&root), 900_000, "base64:AAAA"),
        ],
    );

    let facts = facts_for(&receipt);

    assert_eq!(facts.len(), 2);
    assert_eq!(facts[0].anchor_type(), "rfc3161");
    assert_eq!(facts[1].anchor_type(), "bitcoin_ots");
}

#[test]
fn a_receipt_with_no_anchors_yields_no_facts() {
    let receipt = receipt_with([0x11; 32], vec![]);
    assert!(facts_for(&receipt).is_empty());
}

/// `skip_anchors` asks the *receipt* verifier not to run the anchor step. This
/// function **is** the anchor step, so honouring the flag would return an
/// empty list indistinguishable from a receipt that presents no anchors — a
/// caller would read "no anchors" where the truth is "you asked me not to
/// look".
#[test]
fn skip_anchors_is_not_consulted() {
    let root = [0x11; 32];
    let receipt =
        receipt_with(root, vec![rfc3161_anchor("data_tree_root", &format_hash(&root), "base64:A")]);

    let options = VerifyOptions { skip_anchors: true, ..Default::default() };
    assert_eq!(verify_receipt_anchors(&receipt, &options).len(), 1);
}

// ===========================================================================
// Binding: ATL v2.0 Section 5.5.1 steps 1-2 / Section 5.5.2 steps 1-2
//
// All refutations: each of these was read and is wrong.
// ===========================================================================

#[test]
fn a_wrong_target_refutes_the_anchor() {
    let root = [0x11; 32];
    for (anchor, expected_target) in [
        (rfc3161_anchor("super_root", &format_hash(&root), "base64:A"), "data_tree_root"),
        (bitcoin_anchor("data_tree_root", &format_hash(&root), 1, "base64:A"), "super_root"),
    ] {
        let receipt = receipt_with(root, vec![anchor]);
        let facts = &facts_for(&receipt)[0];

        assert_partitioned(facts);
        assert!(facts.is_refuted(), "{:?}", facts.findings());
        assert!(matches!(
            facts.findings(),
            [VerificationError::AnchorTargetInvalid { expected, .. }] if expected == expected_target
        ));
        // Nothing was read out of the payload, so there is nothing to report
        // about it -- and in particular no half-established fact set.
        assert!(matches!(facts.evidence(), crate::core::verify::AnchorEvidence::None));
    }
}

/// **The refutation that matters most.** A genuine, perfectly signed token
/// minted over unrelated data proves nothing about *this* receipt, and an
/// anchor that does not pin to the receipt's own root is exactly that.
#[test]
fn a_target_hash_that_is_not_the_receipts_root_refutes_the_anchor() {
    let root = [0x11; 32];
    let other = format_hash(&[0x22; 32]);
    for anchor in [
        rfc3161_anchor("data_tree_root", &other, "base64:A"),
        bitcoin_anchor("super_root", &other, 1, "base64:A"),
    ] {
        let receipt = receipt_with(root, vec![anchor]);
        let facts = &facts_for(&receipt)[0];

        assert_partitioned(facts);
        assert!(facts.is_refuted());
        assert!(matches!(facts.findings(), [VerificationError::AnchorTargetHashMismatch { .. }]));
    }
}

#[test]
fn a_malformed_target_hash_refutes_the_anchor() {
    let root = [0x11; 32];
    let receipt =
        receipt_with(root, vec![rfc3161_anchor("data_tree_root", "not-a-hash", "base64:A")]);
    let facts = &facts_for(&receipt)[0];

    assert_partitioned(facts);
    assert!(facts.is_refuted());
    assert!(matches!(
        facts.findings(),
        [VerificationError::InvalidHash { field, .. }] if field == "anchor.target_hash"
    ));
}

/// A `super_root` anchor on a receipt with no `super_proof` has nothing to
/// pin to. The finding names the missing structure rather than inventing a
/// mismatch against a root that does not exist.
#[test]
fn a_bitcoin_anchor_without_a_super_proof_is_refuted() {
    let root = format_hash(&[0x11; 32]);
    let receipt =
        receipt_with_roots(&root, None, vec![bitcoin_anchor("super_root", &root, 1, "b")]);
    let facts = &facts_for(&receipt)[0];

    assert_partitioned(facts);
    assert!(facts.is_refuted());
    assert!(matches!(facts.findings(), [VerificationError::MissingSuperProof]));
}

/// A receipt whose own root is not a hash cannot bind an anchor to anything.
/// Reported against the anchor, because that is where the caller asked the
/// question — and as a refutation, because the field was read and is wrong.
#[test]
fn a_receipt_root_that_is_not_a_hash_is_reported_against_the_anchor() {
    let receipt = receipt_with_roots(
        "sha256:zzzz",
        Some("sha256:zzzz"),
        vec![rfc3161_anchor("data_tree_root", &format_hash(&[0x11; 32]), "base64:A")],
    );
    let facts = &facts_for(&receipt)[0];

    assert_partitioned(facts);
    assert!(facts.is_refuted());
    assert!(matches!(
        facts.findings(),
        [VerificationError::InvalidHash { field, .. }] if field == "proof.root_hash"
    ));
}

// ===========================================================================
// Refutation always outranks inability
// ===========================================================================

/// The classifier is asked of the *set*, not of the first finding met. A
/// fact set carrying both kinds is refuted, whatever order they appear in.
#[test]
fn a_refutation_beside_an_inability_still_refutes() {
    let findings = [
        VerificationError::BitcoinBlockNotObtained,
        VerificationError::AnchorTargetHashMismatch {
            anchor_type: "bitcoin_ots".to_string(),
            expected: "sha256:00".to_string(),
            actual: "sha256:11".to_string(),
        },
    ];
    assert!(findings.iter().any(VerificationError::is_refutation));
    assert!(!findings[0].is_refutation(), "an unfetched block refutes nothing");
    assert!(findings[1].is_refutation());
}

/// Inabilities are never promoted, and refutations are never demoted. Both
/// halves are asserted here because the two mistakes are symmetrical and
/// fixing one is how the other gets introduced.
#[test]
fn the_new_findings_are_classified_the_way_the_docs_say() {
    let refutations = [
        VerificationError::AnchorTargetInvalid {
            anchor_type: "rfc3161".to_string(),
            expected: "data_tree_root".to_string(),
            actual: "super_root".to_string(),
        },
        VerificationError::AnchorTargetHashMismatch {
            anchor_type: "rfc3161".to_string(),
            expected: "sha256:00".to_string(),
            actual: "sha256:11".to_string(),
        },
        VerificationError::AnchorPayloadUndecodable {
            anchor_type: "rfc3161".to_string(),
            reason: "not DER".to_string(),
        },
        VerificationError::BitcoinHeightContradictsProof { claimed: 1, attested: vec![2, 3] },
    ];
    for error in &refutations {
        assert!(error.is_refutation(), "{error} must be a refutation");
        assert!(!error.to_string().is_empty());
    }

    let inabilities = [
        VerificationError::AnchorTypeUnsupported {
            anchor_type: "rfc3161".to_string(),
            required_feature: "rfc3161-verify".to_string(),
        },
        VerificationError::BitcoinBlockNotObtained,
    ];
    for error in &inabilities {
        assert!(!error.is_refutation(), "{error} must not be a refutation");
        assert!(!error.to_string().is_empty());
    }
}

// ===========================================================================
// RFC 3161: all three outcomes on a real token
// ===========================================================================

#[cfg(feature = "rfc3161-verify")]
mod rfc3161 {
    use super::{
        assert_partitioned, facts_for, receipt_with, rfc3161_anchor, verify_receipt_anchors,
    };
    use crate::core::receipt::format_hash;
    use crate::core::verify::anchors::rfc3161::{MessageImprint, TerminalAnchor, TrustStore};
    use crate::core::verify::tests::rfc3161_tests::{
        decode_freetsa_root_cert, FREETSA_HASH, FREETSA_TOKEN,
    };
    use crate::core::verify::{AnchorEvidence, VerificationError, VerifyOptions};

    fn freetsa_token() -> String {
        format!("base64:{FREETSA_TOKEN}")
    }

    /// **Refuted.** The token will not decode, so the bytes that are present
    /// are not what RFC 3161 requires. That is a checked fact about the
    /// anchor, not a gap in the verifier.
    #[test]
    fn an_undecodable_token_refutes_the_anchor() {
        let root = [0x11; 32];
        let receipt = receipt_with(
            root,
            vec![rfc3161_anchor("data_tree_root", &format_hash(&root), "base64:INVALID")],
        );
        let facts = &facts_for(&receipt)[0];

        assert_partitioned(facts);
        assert!(facts.is_refuted());
        assert!(matches!(facts.findings(), [VerificationError::AnchorPayloadUndecodable { .. }]));
        // The anchor's own asserted time survives a refutation, under a name
        // that cannot be mistaken for a fact.
        assert!(facts.claimed_timestamp().is_some());
        assert_eq!(facts.established_timestamp(), None);
    }

    /// **Refuted.** A real, correctly signed token whose `messageImprint`
    /// names data other than this receipt's root. The anchor binds (the
    /// receipt's root and the anchor's `target_hash` agree), so the
    /// refutation comes from the token itself.
    #[test]
    fn a_token_attesting_to_other_data_refutes_the_anchor() {
        let root = [0x11; 32];
        let receipt = receipt_with(
            root,
            vec![rfc3161_anchor("data_tree_root", &format_hash(&root), &freetsa_token())],
        );
        let facts = &facts_for(&receipt)[0];

        assert_partitioned(facts);
        assert!(facts.is_refuted(), "{:?}", facts.findings());
        assert!(facts.findings().iter().any(|e| matches!(
            e,
            VerificationError::Rfc3161MessageImprint(MessageImprint::Mismatch)
        )));
        // The full fact set is carried through, not collapsed.
        assert!(matches!(facts.evidence(), AnchorEvidence::Rfc3161(_)));
    }

    /// **Indeterminate.** Every cryptographic fact about this token holds;
    /// what is missing is any reason to believe the certificate the chain
    /// terminates at. Nothing here is evidence against the receipt, and
    /// reporting it as such is the defect this whole API exists to prevent.
    #[test]
    fn a_sound_token_with_no_trust_store_is_indeterminate_not_refuted() {
        let receipt = receipt_with(
            FREETSA_HASH,
            vec![rfc3161_anchor("data_tree_root", &format_hash(&FREETSA_HASH), &freetsa_token())],
        );
        let facts = &facts_for(&receipt)[0];

        assert_partitioned(facts);
        assert!(!facts.is_refuted(), "nothing was refuted: {:?}", facts.findings());
        assert!(facts.is_indeterminate());
        assert_eq!(facts.refutations().count(), 0);
        assert!(facts.findings().iter().any(|e| matches!(
            e,
            VerificationError::Rfc3161TerminalNotTrusted {
                terminal: Some(TerminalAnchor::Assumed { .. })
            }
        )));
        // Not verified, so no time is established -- but the token's own
        // genTime is still reported as a claim.
        assert_eq!(facts.established_timestamp(), None);
        assert!(facts.claimed_timestamp().is_some());
    }

    /// **Verified.** The same token and the same receipt, with FreeTSA's own
    /// root supplied by the caller. Every finding is gone, and only now is a
    /// time established.
    #[test]
    fn a_sound_token_with_the_matching_trust_store_is_verified() {
        let receipt = receipt_with(
            FREETSA_HASH,
            vec![rfc3161_anchor("data_tree_root", &format_hash(&FREETSA_HASH), &freetsa_token())],
        );
        let options = VerifyOptions {
            rfc3161_trust_store: Some(
                TrustStore::new().with_anchor_certificate(decode_freetsa_root_cert()),
            ),
            ..Default::default()
        };

        let facts = &verify_receipt_anchors(&receipt, &options)[0];

        assert_partitioned(facts);
        assert!(facts.is_verified(), "{:?}", facts.findings());
        assert!(facts.findings().is_empty());
        assert_eq!(facts.established_timestamp(), facts.claimed_timestamp());
        assert!(facts.established_timestamp().is_some());
    }

    /// Trust material comes from the caller and from nowhere else. The token
    /// carries its own root in its certificate set; supplying an unrelated
    /// store must not promote it.
    #[test]
    fn a_trust_store_that_names_nothing_in_the_chain_leaves_it_indeterminate() {
        let receipt = receipt_with(
            FREETSA_HASH,
            vec![rfc3161_anchor("data_tree_root", &format_hash(&FREETSA_HASH), &freetsa_token())],
        );
        let options =
            VerifyOptions { rfc3161_trust_store: Some(TrustStore::new()), ..Default::default() };

        let facts = &verify_receipt_anchors(&receipt, &options)[0];

        assert!(facts.is_indeterminate());
        assert!(!facts.is_refuted());
    }
}

/// Without the feature there is no implementation to examine the token with,
/// so nothing about it is asserted — an inability, never a refutation.
#[cfg(not(feature = "rfc3161-verify"))]
#[test]
fn an_rfc3161_anchor_is_indeterminate_when_the_feature_is_compiled_out() {
    let root = [0x11; 32];
    let receipt =
        receipt_with(root, vec![rfc3161_anchor("data_tree_root", &format_hash(&root), "base64:A")]);
    let facts = &facts_for(&receipt)[0];

    assert_partitioned(facts);
    assert!(facts.is_indeterminate());
    assert!(!facts.is_refuted());
    assert!(matches!(
        facts.findings(),
        [VerificationError::AnchorTypeUnsupported { required_feature, .. }]
            if required_feature == "rfc3161-verify"
    ));
}

// ===========================================================================
// Bitcoin OTS: all three outcomes on a real proof
// ===========================================================================

#[cfg(feature = "bitcoin-ots")]
mod bitcoin_ots {
    use super::{assert_partitioned, bitcoin_anchor, facts_for, receipt_with};
    use crate::core::ots::DetachedTimestampFile;
    use crate::core::receipt::format_hash;
    use crate::core::verify::{AnchorEvidence, VerificationError};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    /// The fixture proof, the digest it starts from, and a height it attests
    /// to.
    pub(super) fn fixture() -> (String, [u8; 32], u64) {
        let bytes = std::fs::read("test_data/ots/large-test.ots").expect("fixture readable");
        let file = DetachedTimestampFile::from_bytes(&bytes).expect("fixture parses");
        let digest: [u8; 32] =
            file.timestamp.start_digest.clone().try_into().expect("32-byte start digest");
        let encoded = STANDARD.encode(&bytes);
        let height =
            crate::core::verify::anchors::bitcoin_ots::verify_ots_anchor_impl(&encoded, &digest)
                .expect("fixture proof verifies")
                .attestations
                .first()
                .expect("fixture carries a Bitcoin attestation")
                .block_height;
        (encoded, digest, height)
    }

    /// **Indeterminate, and never anything better from this crate.**
    /// Everything computable holds: the proof decodes from the receipt's own
    /// super root, and the height the receipt states is one the proof attests
    /// to. What is missing is the block header, and obtaining it is I/O this
    /// crate does not perform.
    #[test]
    fn a_sound_proof_is_indeterminate_because_no_block_was_obtained() {
        let (proof, digest, height) = fixture();
        let receipt = receipt_with(
            digest,
            vec![bitcoin_anchor("super_root", &format_hash(&digest), height, &proof)],
        );
        let facts = &facts_for(&receipt)[0];

        assert_partitioned(facts);
        assert!(facts.is_indeterminate(), "{:?}", facts.findings());
        assert!(!facts.is_refuted());
        assert!(!facts.is_verified());
        assert!(matches!(facts.findings(), [VerificationError::BitcoinBlockNotObtained]));

        // The computed root is published so a caller with network access can
        // finish the comparison without re-deriving anything.
        let AnchorEvidence::BitcoinOts(bitcoin) = facts.evidence() else {
            panic!("a decoded proof must carry its fact set");
        };
        assert_eq!(bitcoin.receipt_block_height, height);
        assert!(bitcoin.attested_block_heights.contains(&height));
        assert!(bitcoin.attestation.is_some());
        let computed = bitcoin.computed_block_merkle_root.as_ref().expect("a computed root");
        assert!(computed.starts_with("sha256:"));
        assert_eq!(computed.len(), "sha256:".len() + 64);

        // No block, so no time -- whatever the receipt asserts.
        assert_eq!(facts.established_timestamp(), None);
    }

    /// **Refuted.** The proof will not decode from the receipt's super root.
    #[test]
    fn an_undecodable_proof_refutes_the_anchor() {
        let root = [0x11; 32];
        let receipt = receipt_with(
            root,
            vec![bitcoin_anchor("super_root", &format_hash(&root), 1, "base64:INVALID")],
        );
        let facts = &facts_for(&receipt)[0];

        assert_partitioned(facts);
        assert!(facts.is_refuted());
        assert!(matches!(facts.findings(), [VerificationError::AnchorPayloadUndecodable { .. }]));
    }

    /// **Refuted, and refuted with no network at all.** ATL v2.0 Section
    /// 5.5.2 step 5's height half: the receipt states a block height and its
    /// own proof attests to a set of them. A verifier that skips the
    /// comparison republishes the receipt's assertion as though it had been
    /// checked.
    ///
    /// This is also the case that proves refutation outranks inability on a
    /// *real* fact set: the block was not obtained either, so both kinds of
    /// finding are present, and the outcome must still be `refuted`.
    #[test]
    fn a_height_the_proof_contradicts_refutes_the_anchor_offline() {
        let (proof, digest, height) = fixture();
        let receipt = receipt_with(
            digest,
            vec![bitcoin_anchor("super_root", &format_hash(&digest), height + 1, &proof)],
        );
        let facts = &facts_for(&receipt)[0];

        assert_partitioned(facts);
        assert!(facts.is_refuted());
        assert!(!facts.is_indeterminate(), "a refutation must not be reported as an inability");

        assert!(facts.findings().iter().any(|e| matches!(
            e,
            VerificationError::BitcoinHeightContradictsProof { claimed, attested }
                if *claimed == height + 1 && attested.contains(&height)
        )));
        // The unperformed check is still reported: a refutation settles the
        // outcome, it does not make an unfetched block fetched.
        assert!(facts
            .findings()
            .iter()
            .any(|e| matches!(e, VerificationError::BitcoinBlockNotObtained)));
        assert_eq!(facts.inabilities().count(), 1);
        assert_eq!(facts.refutations().count(), 1);

        // The evidence for the refutation travels with it.
        let AnchorEvidence::BitcoinOts(bitcoin) = facts.evidence() else {
            panic!("the receipt's own claims must be published for a refuted anchor too");
        };
        assert_eq!(bitcoin.receipt_block_height, height + 1);
        assert!(bitcoin.attested_block_heights.contains(&height));
        // No attestation was selected, so no root was computed from one.
        assert!(bitcoin.attestation.is_none());
        assert!(bitcoin.computed_block_merkle_root.is_none());
    }

    /// A `bitcoin_ots` anchor is never `is_verified()` from this crate, under
    /// any input. Pinned as a test because the alternative — reporting one as
    /// confirmed — was this crate's own behaviour up to 0.28 and is the kind
    /// of overclaim that returns quietly.
    #[test]
    fn no_bitcoin_anchor_is_ever_verified_without_a_block() {
        let (proof, digest, height) = fixture();
        for claimed in [height, height + 1] {
            let receipt = receipt_with(
                digest,
                vec![bitcoin_anchor("super_root", &format_hash(&digest), claimed, &proof)],
            );
            assert!(!facts_for(&receipt)[0].is_verified());
        }
    }
}

/// Without the feature there is no implementation to examine the proof with.
#[cfg(not(feature = "bitcoin-ots"))]
#[test]
fn a_bitcoin_anchor_is_indeterminate_when_the_feature_is_compiled_out() {
    let root = [0x11; 32];
    let receipt =
        receipt_with(root, vec![bitcoin_anchor("super_root", &format_hash(&root), 1, "base64:A")]);
    let facts = &facts_for(&receipt)[0];

    assert_partitioned(facts);
    assert!(facts.is_indeterminate());
    assert!(!facts.is_refuted());
    assert!(matches!(
        facts.findings(),
        [VerificationError::AnchorTypeUnsupported { required_feature, .. }]
            if required_feature == "bitcoin-ots"
    ));
}

// ===========================================================================
// The receipt-level verdict, ATL v2.0 Section 5.5
//
// `verify_receipt_anchors` forms no verdict; `ReceiptVerifier::verify` does.
// These tests pin the three rules that verdict now obeys, on the same
// fixtures, so the facts and the verdict cannot be shown to disagree.
// ===========================================================================

mod receipt_verdict {
    #[cfg(feature = "bitcoin-ots")]
    use super::{bitcoin_anchor, receipt_with};
    use super::{rfc3161_anchor, sound_receipt};
    use crate::core::receipt::{format_hash, ReceiptAnchor};
    use crate::core::verify::{
        ReceiptVerifier, VerificationError, VerificationResult, VerifyOptions,
    };

    /// Every status this crate reports about a receipt, plus the receipt-level
    /// errors those statuses are computed from.
    ///
    /// Deliberately excludes `errors()` as a whole and `anchor_results`: those
    /// two *must* change when an anchor is added, because the finding has to
    /// reach the reader. Everything else must not.
    fn statuses(result: &VerificationResult) -> (bool, bool, bool, Vec<String>) {
        (
            result.is_valid(),
            result.is_indeterminate(),
            result.has_valid_anchor(),
            result.receipt_errors().map(ToString::to_string).collect(),
        )
    }

    /// Anchors a stranger could append to a receipt in transit. Each is
    /// refuted by this crate, and none of them requires a key, a signature or
    /// any access to the log.
    fn rubbish_anchors() -> Vec<(&'static str, ReceiptAnchor)> {
        vec![
            ("wrong target", rfc3161_anchor("super_root", &format_hash(&[0x22; 32]), "base64:A")),
            (
                "target_hash naming another root",
                rfc3161_anchor("data_tree_root", &format_hash(&[0x22; 32]), "base64:A"),
            ),
            ("malformed target_hash", rfc3161_anchor("data_tree_root", "not-a-hash", "base64:A")),
            (
                "bitcoin anchor on a receipt that has a super_proof",
                ReceiptAnchor::BitcoinOts {
                    target: "super_root".to_string(),
                    target_hash: format_hash(&[0x22; 32]),
                    timestamp: "2026-01-04T21:57:43Z".to_string(),
                    bitcoin_block_height: 1,
                    bitcoin_block_time: "2026-01-04T22:10:00Z".to_string(),
                    ots_proof: "base64:A".to_string(),
                },
            ),
        ]
    }

    /// **The invariant, in the only form that is both true and worth
    /// anything: an anchor that FAILS verification changes no status of the
    /// receipt.**
    ///
    /// A receipt's `anchors` array is covered by neither the leaf hash
    /// (`SHA256(0x00 || payload_hash || metadata_hash)`) nor the 98-byte
    /// checkpoint blob, so anybody through whose hands a receipt passes can
    /// append an entry to it with no key. Every property this crate reports
    /// about the receipt must therefore be untouched by *that* -- not merely
    /// `is_valid`, and not merely the values of the statuses but the very set
    /// of receipt-level errors they are computed from.
    ///
    /// # What is deliberately not claimed
    ///
    /// "Appending an anchor changes nothing" would be **false**, and stating
    /// it that way would be the same error one more time. An anchor that
    /// *passes* verification raises the verified count and can carry a receipt
    /// over the Section 5.5 threshold: at `min_valid_anchors: 2`, a receipt
    /// with one verified anchor reports
    /// `NoTrustAnchor { required: 2, verified: 1 }` and a second verified
    /// anchor clears it. That is not a leak in the guarantee, it is the
    /// purpose of anchors, and a verifier for which anchors changed nothing
    /// would be worthless.
    ///
    /// The guarantee is one-sided because the *capability* is: producing an
    /// anchor that verifies needs a timestamp token over this receipt's own
    /// root, chaining to a trust root the caller supplied. A stranger can
    /// append rubbish and nothing else. Every anchor in this test therefore
    /// fails verification, and the complement -- that a verified anchor
    /// changes exactly what it should -- is
    /// [`a_verified_anchor_reaching_the_threshold_clears_the_finding`] and
    /// `compute_validity_tests::reaching_the_quorum_with_a_second_verified_anchor_accepts_the_receipt`.
    ///
    /// # A guard that only checks the default configuration claims more than
    /// it verifies
    ///
    /// This is the lesson of the release rather than a footnote to it. The
    /// same defect was found four times, each time in a place the previous
    /// guard did not reach:
    ///
    /// 1. `is_valid` was decided by anchor findings — an appended anchor
    ///    destroyed the verdict.
    /// 2. `is_valid` was fixed and `is_indeterminate` was not, so an appended
    ///    anchor could still relabel the receipt "refuted".
    /// 3. Both were fixed and the *test* still ran only at
    ///    `min_valid_anchors == 0`, where the quorum branch is unreachable —
    ///    so it never saw that appending an anchor to an unanchored receipt
    ///    moved it into that branch and swapped `NoTrustAnchor` for a
    ///    different receipt-level error.
    /// 4. The matrix was widened and the *claim* was still too broad: it said
    ///    "appending an anchor", while every anchor it appended was one that
    ///    failed verification. A true test under a false headline.
    ///
    /// Each round the assertion was true and each round it was narrower than
    /// the property it was taken to establish. So the matrix below varies
    /// everything a caller can set that could reach this code — the quorum,
    /// the shape of the receipt, the kind of rubbish appended, the position it
    /// is appended at — and the doc comment states exactly what that buys and
    /// no more. A future option that can reach the anchor path belongs in the
    /// matrix; a future claim about anchors belongs against this list.
    #[test]
    fn an_unverified_appended_anchor_changes_no_status_of_the_receipt() {
        // Receipts a stranger might be handed. The unanchored one is not a
        // corner case: it is where round 3 hid, because it is the only shape
        // for which appending changes whether the anchor block runs at all.
        let bases: Vec<(&str, Vec<ReceiptAnchor>)> = vec![
            ("no anchors of its own", vec![]),
            (
                "one anchor of its own",
                vec![rfc3161_anchor("data_tree_root", &format_hash(&[0x33; 32]), "base64:A")],
            ),
        ];

        // 0 and 1 are the same threshold (Section 5.5 floors it at one); 2 is
        // a caller genuinely asking for more than the specification does.
        for quorum in [0usize, 1, 2] {
            let verify = |anchors: Vec<ReceiptAnchor>| {
                let options =
                    VerifyOptions { min_valid_anchors: quorum, ..VerifyOptions::default() };
                ReceiptVerifier::anchor_only_with_options(options)
                    .verify(&sound_receipt(|_r| anchors.clone()))
            };

            for (base_name, base) in &bases {
                let untouched = verify(base.clone());
                let expected = statuses(&untouched);
                assert!(
                    !untouched.has_valid_anchor(),
                    "the premise of this test: none of its anchors verify"
                );

                for (rubbish_name, rubbish) in rubbish_anchors() {
                    for (position, label) in [(base.len(), "appended"), (0, "prepended")] {
                        let mut anchors = base.clone();
                        anchors.insert(position, rubbish.clone());
                        let tampered = verify(anchors);

                        assert_eq!(
                            statuses(&tampered),
                            expected,
                            "quorum {quorum}, {base_name}: a {label} anchor ({rubbish_name}) \
                             moved a status"
                        );

                        // ... and it is not swallowed.
                        assert_eq!(
                            tampered.anchor_findings().count(),
                            untouched.anchor_findings().count() + 1,
                            "quorum {quorum}, {base_name}: the {label} anchor ({rubbish_name}) \
                             must be reported"
                        );
                        assert_eq!(tampered.anchor_results.len(), base.len() + 1);
                    }
                }
            }
        }
    }

    /// The unmet threshold has **one** representation, whatever made it unmet
    /// and whatever the receipt looks like.
    ///
    /// Two of them is what let a stranger swap the receipt's error set: the
    /// quorum aggregate was produced only for receipts that presented an
    /// anchor, so appending one to an unanchored receipt replaced
    /// `NoTrustAnchor` with a different error. `min_valid_anchors` raises the
    /// threshold; it does not create a second kind of failure.
    /// One case for [`an_unmet_threshold_has_a_single_representation`].
    struct ThresholdCase {
        name: &'static str,
        quorum: usize,
        anchors: Vec<ReceiptAnchor>,
        expected_required: usize,
    }

    #[test]
    fn an_unmet_threshold_has_a_single_representation() {
        let refuted =
            || vec![rfc3161_anchor("data_tree_root", &format_hash(&[0x22; 32]), "base64:A")];
        let cases = vec![
            ThresholdCase { name: "no anchors", quorum: 0, anchors: vec![], expected_required: 1 },
            ThresholdCase {
                name: "no anchors, quorum 2",
                quorum: 2,
                anchors: vec![],
                expected_required: 2,
            },
            ThresholdCase {
                name: "one refuted anchor",
                quorum: 0,
                anchors: refuted(),
                expected_required: 1,
            },
            ThresholdCase {
                name: "one refuted anchor, quorum 2",
                quorum: 2,
                anchors: refuted(),
                expected_required: 2,
            },
        ];

        for ThresholdCase { name, quorum, anchors, expected_required } in cases {
            let options = VerifyOptions { min_valid_anchors: quorum, ..VerifyOptions::default() };
            let result = ReceiptVerifier::anchor_only_with_options(options)
                .verify(&sound_receipt(|_r| anchors.clone()));

            let threshold: Vec<_> = result
                .receipt_errors()
                .filter(|e| matches!(e, VerificationError::NoTrustAnchor { .. }))
                .collect();
            assert_eq!(threshold.len(), 1, "{name}: exactly one report of the threshold");
            assert_eq!(
                threshold[0],
                &VerificationError::NoTrustAnchor { required: expected_required, verified: 0 },
                "{name}"
            );
            // Not enough was proved; nothing was disproved.
            assert!(!threshold[0].is_refutation(), "{name}");
            // The receipt's own facts hold, so the outcome is unattested.
            assert!(
                result.is_indeterminate(),
                "{name}: {:?}",
                result.receipt_errors().collect::<Vec<_>>()
            );
        }
    }

    /// **A receipt whose only anchor is refuted is *unattested*, not
    /// refuted.**
    ///
    /// This test asserted the opposite one revision ago, and the reversal is
    /// the point rather than a detail.
    ///
    /// What was checked and found false is an anchor -- an unauthenticated
    /// attachment that anybody handling the receipt could have put there. The
    /// receipt's own facts are untouched: its leaf hash, its inclusion proof
    /// and its Super-Tree proofs all hold. Saying "this receipt is refuted"
    /// would publish a finding against a document nothing has disproved, on
    /// the strength of a byte string a stranger controls.
    ///
    /// So the honest report is the one a stranger cannot manufacture: **trust
    /// could not be established** (Section 5.5's threshold is unmet, zero
    /// verified anchors), with the anchor finding shown loudly beside it.
    ///
    /// # Is there a case where a refuted anchor *should* refute the receipt?
    ///
    /// No, and the reason is uniform rather than case-by-case. Every anchor
    /// refutation this crate can produce is reachable by appending: a wrong
    /// `target`, a `target_hash` naming another root, a payload that will not
    /// decode, a genuine token whose `messageImprint` is for other data, a
    /// Bitcoin anchor whose stated height its own proof contradicts. The
    /// observation therefore never distinguishes "the receipt was altered"
    /// from "somebody appended rubbish", and a verdict may not rest on a
    /// distinction the evidence does not support.
    ///
    /// Nothing is lost by this: an attacker who alters the receipt so that
    /// genuine anchors stop matching has to change `proof.root_hash`, and that
    /// is caught at receipt level by the checkpoint comparison and the
    /// inclusion proof, both of which are covered by the leaf hash.
    #[test]
    fn a_receipt_whose_only_anchor_is_refuted_is_unattested_not_refuted() {
        let receipt = sound_receipt(|_root| {
            vec![rfc3161_anchor("data_tree_root", &format_hash(&[0x22; 32]), "base64:A")]
        });

        let result = ReceiptVerifier::anchor_only().verify(&receipt);

        assert!(result.inclusion_valid, "the receipt's own proofs hold");
        assert!(result.super_inclusion_valid && result.super_consistency_valid);

        assert!(!result.is_valid, "Section 5.5's threshold is unmet: zero verified anchors");
        assert!(
            result.is_indeterminate(),
            "nothing about the *receipt* was refuted: {:?}",
            result.receipt_errors().collect::<Vec<_>>()
        );

        // The only thing said about the receipt is that trust was not
        // established -- which is the one answer a stranger cannot change.
        assert_eq!(
            result.receipt_errors().collect::<Vec<_>>(),
            [&VerificationError::NoTrustAnchor { required: 1, verified: 0 }]
        );

        // And the finding is reported in full, with its provenance.
        assert!(result.anchor_findings().any(|e| matches!(
            e,
            VerificationError::AnchorFinding { index: 0, anchor_type, finding }
                if anchor_type == "rfc3161"
                    && matches!(**finding, VerificationError::AnchorTargetHashMismatch { .. })
        )));
        // It is a refutation *of the anchor*, and says so.
        assert!(result.anchor_findings().all(VerificationError::is_refutation));
    }

    /// **A receipt with no anchors at all.**
    ///
    /// ATL v2.0 Section 5.5 is a MUST -- "At least one anchor MUST be verified
    /// to establish trust in the receipt" -- and zero anchors yield zero
    /// verified anchors, so it cannot be met. Section 5.6's table rates this
    /// tier "internal consistency only", which is exactly what a sound Merkle
    /// proof establishes and no more: membership in a tree, not that the tree
    /// existed at any particular time. The whole claim an ATL receipt carries
    /// is temporal, and nothing here attests to it.
    ///
    /// The outcome is `is_indeterminate()`, never refuted. Nothing about such
    /// a receipt was shown false; what is absent is external attestation, and
    /// absence of evidence *for* is not evidence *against*.
    #[test]
    fn a_receipt_with_no_anchors_is_unattested_not_refuted() {
        let receipt = sound_receipt(|_root| vec![]);

        let result = ReceiptVerifier::anchor_only().verify(&receipt);

        assert!(result.inclusion_valid);
        assert!(result.super_inclusion_valid && result.super_consistency_valid);
        assert!(result.anchor_results.is_empty());

        assert!(!result.is_valid, "Section 5.5's threshold cannot be met by zero anchors");
        assert!(result.is_indeterminate(), "nothing was refuted");
        assert_eq!(
            result.errors(),
            [VerificationError::NoTrustAnchor { required: 1, verified: 0 }]
        );
        assert!(!VerificationError::NoTrustAnchor { required: 1, verified: 0 }.is_refutation());
    }

    /// **The justification for the threshold check not being reached on every
    /// path, measured rather than assumed.**
    ///
    /// `ReceiptVerifier::verify` returns early on five receipt-level
    /// refutations, before the Section 5.5 threshold is evaluated. That is
    /// only defensible if it changes nothing, so this walks every one of those
    /// paths -- with and without anchors -- and compares the statuses against
    /// the same result with `NoTrustAnchor` appended, which is what an
    /// unconditional check would have produced.
    ///
    /// They must be identical. The receipt has no parsed root, so it has no
    /// verified anchor either way; and adding a non-refutation to an error
    /// list that already has an entry moves neither `is_valid` nor
    /// `is_indeterminate`. Should a future early return break that, this fails
    /// and the check has to become unconditional in fact and not only in
    /// wording.
    #[test]
    fn an_early_return_reports_the_same_statuses_the_threshold_would() {
        use crate::core::receipt::test_support::tamper;

        let rubbish = || rfc3161_anchor("data_tree_root", &format_hash(&[0x22; 32]), "base64:A");

        // One tamper per early return in `verify`, in source order. The
        // `spec_version` gate is exercised too: `Receipt::from_json` refuses
        // such a document, but `ReceiptBuilder` and plain `serde` do not.
        /// One receipt-level breakage: a name and the tamper that produces it.
        type Breakage = (&'static str, fn(&mut crate::core::receipt::test_support::ReceiptParts));

        let breakages: Vec<Breakage> = vec![
            ("unsupported spec_version", |p| p.spec_version = "9.9.9".to_string()),
            ("leaf hash unreconstructable", |p| {
                p.entry.payload_hash = "not-a-hash".to_string();
            }),
            ("metadata_hash mismatch", |p| {
                p.entry.metadata_hash = format_hash(&[0x44; 32]);
            }),
            ("proof.root_hash unparsable", |p| {
                p.proof.root_hash = "sha256:zz".to_string();
                p.proof.checkpoint.root_hash = "sha256:zz".to_string();
            }),
            ("checkpoint root mismatch", |p| {
                p.proof.checkpoint.root_hash = format_hash(&[0xbb; 32]);
            }),
            ("checkpoint tree_size mismatch", |p| p.proof.checkpoint.tree_size = 2),
        ];

        for (name, break_it) in breakages {
            for anchors in [vec![], vec![rubbish()]] {
                let sound = sound_receipt(|_r| anchors.clone());
                let broken = tamper(&sound, break_it);

                let actual = ReceiptVerifier::anchor_only().verify(&broken);
                assert!(!actual.is_valid, "{name}: the fixture must be refused");

                // What the unconditional variant would have produced.
                let mut hypothetical = actual.clone();
                hypothetical
                    .errors
                    .push(VerificationError::NoTrustAnchor { required: 1, verified: 0 });

                assert_eq!(
                    (actual.is_valid(), actual.is_indeterminate(), actual.has_valid_anchor()),
                    (
                        hypothetical.is_valid(),
                        hypothetical.is_indeterminate(),
                        hypothetical.has_valid_anchor()
                    ),
                    "{name} ({} anchors): skipping the threshold changed a status",
                    anchors.len()
                );
            }
        }
    }

    /// A receipt-level refutation still makes the result refuted -- the
    /// exclusion is about anchors and about nothing else.
    #[test]
    fn a_receipt_level_refutation_still_makes_the_result_refuted() {
        // A sound receipt with a refuted anchor, then broken at receipt level
        // by a metadata hash that does not match its metadata.
        let receipt = sound_receipt(|_root| {
            vec![rfc3161_anchor("data_tree_root", &format_hash(&[0x22; 32]), "base64:A")]
        });
        let broken = crate::core::receipt::test_support::tamper(&receipt, |parts| {
            parts.entry.metadata_hash = format_hash(&[0x44; 32]);
        });

        let result = ReceiptVerifier::anchor_only().verify(&broken);

        assert!(!result.is_valid);
        assert!(
            !result.is_indeterminate(),
            "the receipt itself was checked and is wrong: {:?}",
            result.receipt_errors().collect::<Vec<_>>()
        );
        assert!(result.receipt_errors().any(VerificationError::is_refutation));
    }

    /// **An unresolved anchor denies trust and refutes nothing.**
    ///
    /// The receipt's own root is the OTS proof's start digest, so the anchor
    /// binds, decodes and its height checks out -- everything this crate can
    /// compute. What is missing is the block header, which it never fetches.
    ///
    /// Two things must hold at once, and they pull in opposite directions:
    /// the anchor must not count towards Section 5.5, and it must contribute
    /// **no finding against the receipt**. The only receipt-level error
    /// present is the fixture's own inclusion failure -- an artefact of
    /// pinning the root to the OTS digest rather than to the entry's leaf
    /// hash, which cannot be done for both at once.
    #[cfg(feature = "bitcoin-ots")]
    #[test]
    fn an_unresolved_anchor_denies_trust_without_refuting_anything() {
        let (proof, digest, height) = super::bitcoin_ots::fixture();
        let receipt = receipt_with(
            digest,
            vec![bitcoin_anchor("super_root", &format_hash(&digest), height, &proof)],
        );

        let result = ReceiptVerifier::anchor_only().verify(&receipt);

        assert!(!result.anchor_results[0].is_valid, "no block header, so nothing is confirmed");
        assert!(!result.is_valid, "zero verified anchors cannot meet Section 5.5's threshold");
        assert_eq!(result.anchor_findings().count(), 0, "nothing was refuted");
        assert!(
            result.receipt_errors().all(|e| matches!(
                e,
                // The fixture's own defect, explained above.
                VerificationError::InclusionProofFailed { .. }
                    // The threshold, unmet -- which is the whole point of the
                    // anchor being unresolved, and an inability.
                    | VerificationError::NoTrustAnchor { .. }
            )),
            "an unfinished check is not a finding against the receipt: {:?}",
            result.receipt_errors().collect::<Vec<_>>()
        );
        assert!(
            result
                .receipt_errors()
                .filter(|e| e.is_refutation())
                .all(|e| matches!(e, VerificationError::InclusionProofFailed { .. })),
            "the anchor contributed no refutation"
        );
    }
}
