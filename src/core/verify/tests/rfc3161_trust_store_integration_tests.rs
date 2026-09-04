//! Integration test: `TrustStore` reaches RFC 3161 anchor verification
//! through the full public `ReceiptVerifier`/`VerifyOptions` path, not just
//! the low-level `verify_rfc3161_token` API.
//!
//! Before this was wired up, `VerifyOptions` had no place to put trust
//! material at all, so an RFC 3161 anchor verified through
//! `ReceiptVerifier::verify` could never become `Trusted` -- Receipt-level
//! TSA trust was structurally unreachable through the public API. This
//! test proves the wiring: the same real, correctly-signed FreeTSA token
//! reaches `AnchorVerificationResult::is_valid == true` when
//! `VerifyOptions::rfc3161_trust_store` carries FreeTSA's own root
//! certificate (obtained here from the token itself only because this is a
//! *test fixture*, exactly as `rfc3161_tests.rs` already does for the
//! lower-level API -- never something the crate does automatically; see
//! the module-level trust-model docs on `TrustStore`), and stays
//! unverified without it.

#![cfg(feature = "rfc3161-verify")]

use super::rfc3161_tests::{decode_freetsa_root_cert, FREETSA_HASH, FREETSA_TOKEN};
use crate::core::checkpoint::{compute_key_id, Checkpoint, CheckpointJson};
use crate::core::jcs::canonicalize_and_hash;
use crate::core::receipt::ReceiptBuilder;
use crate::core::receipt::{
    format_hash, Receipt, ReceiptAnchor, ReceiptEntry, ReceiptProof, SuperProof,
    RECEIPT_SPEC_VERSION,
};
use crate::core::verify::anchors::rfc3161::TrustStore;
use crate::core::verify::{ReceiptVerifier, VerifyOptions};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

/// A receipt whose Data Tree root (and therefore the RFC 3161 anchor's
/// `target_hash`) is FreeTSA's real, verified `MessageImprint`. Inclusion
/// and the checkpoint signature are irrelevant to what this test checks
/// (only `anchor_results[0]`), so they are left trivially self-consistent
/// rather than separately validated.
fn make_receipt_anchored_to_freetsa() -> Receipt {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let root_hash = FREETSA_HASH;

    let origin = [1u8; 32];
    let tree_size = 1u64;
    let timestamp = 1_704_067_200_000_000_000u64;

    let mut blob = [0u8; 98];
    blob[0..18].copy_from_slice(b"ATL-Protocol-v1-CP");
    blob[18..50].copy_from_slice(&origin);
    blob[50..58].copy_from_slice(&tree_size.to_le_bytes());
    blob[58..66].copy_from_slice(&timestamp.to_le_bytes());
    blob[66..98].copy_from_slice(&root_hash);
    let signature = signing_key.sign(&blob);
    let key_id = compute_key_id(&signing_key.verifying_key().to_bytes());

    let checkpoint =
        Checkpoint::new(origin, tree_size, timestamp, root_hash, signature.to_bytes(), key_id);

    let metadata = json!({});
    let metadata_hash = format_hash(
        &canonicalize_and_hash(&metadata).expect("metadata satisfies RFC 8785 Section 3.1"),
    );

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
            root_hash: format_hash(&root_hash),
            inclusion_path: vec![],
            leaf_index: 0,
            checkpoint: CheckpointJson {
                origin: format_hash(&checkpoint.origin),
                tree_size: checkpoint.tree_size,
                root_hash: format_hash(&checkpoint.root_hash),
                timestamp: checkpoint.timestamp,
                signature: crate::core::receipt::format_signature(&checkpoint.signature),
                key_id: format_hash(&checkpoint.key_id),
            },
            consistency_proof: None,
        })
    .super_proof_option(Some(SuperProof {
        genesis_super_root: format_hash(&root_hash),
        data_tree_index: 0,
        super_tree_size: 1,
        super_root: format_hash(&root_hash),
        inclusion: vec![],
        consistency_to_origin: vec![],
    }))
    .anchors(vec![ReceiptAnchor::Rfc3161 {
        target: "data_tree_root".to_string(),
        target_hash: format_hash(&root_hash),
        tsa_url: "https://freetsa.org/tsr".to_string(),
        timestamp: "2026-01-04T21:57:43Z".to_string(),
        token_der: format!("base64:{FREETSA_TOKEN}"),
    }])
    .upgrade_url_option(None).build(crate::core::receipt::SourceTextCheck::assume_duplicate_property_names_already_rejected())
}

#[test]
fn rfc3161_anchor_is_untrusted_through_receipt_verifier_without_trust_store() {
    let receipt = make_receipt_anchored_to_freetsa();
    let verifier = ReceiptVerifier::anchor_only();
    let result = verifier.verify(&receipt);

    assert_eq!(result.anchor_results.len(), 1);
    let anchor = &result.anchor_results[0];
    assert_eq!(anchor.anchor_type, "rfc3161");
    assert!(
        !anchor.is_valid,
        "without a TrustStore, the RFC 3161 anchor must not be valid through the public API either"
    );
}

#[test]
fn rfc3161_anchor_becomes_trusted_through_receipt_verifier_with_trust_store() {
    let receipt = make_receipt_anchored_to_freetsa();
    let store = TrustStore::new().with_anchor_certificate(decode_freetsa_root_cert());
    let options = VerifyOptions { rfc3161_trust_store: Some(store), ..Default::default() };
    let verifier = ReceiptVerifier::anchor_only_with_options(options);

    let result = verifier.verify(&receipt);

    assert_eq!(result.anchor_results.len(), 1);
    let anchor = &result.anchor_results[0];
    assert_eq!(anchor.anchor_type, "rfc3161");
    assert!(
        anchor.is_valid,
        "with FreeTSA's own root supplied via VerifyOptions, the anchor must verify: {:?}",
        anchor.error
    );
}

/// The trust store never leaks into a *different* verifier instance or
/// receipt: creating one `ReceiptVerifier` with a trust store and another
/// without must not cross-contaminate results.
#[test]
fn trust_store_is_scoped_to_the_options_it_was_configured_on() {
    let receipt = make_receipt_anchored_to_freetsa();

    let trusting_options = VerifyOptions {
        rfc3161_trust_store: Some(
            TrustStore::new().with_anchor_certificate(decode_freetsa_root_cert()),
        ),
        ..Default::default()
    };
    let trusting = ReceiptVerifier::anchor_only_with_options(trusting_options);
    let bare = ReceiptVerifier::anchor_only();

    assert!(trusting.verify(&receipt).anchor_results[0].is_valid);
    assert!(!bare.verify(&receipt).anchor_results[0].is_valid);
}

/// **The other half of the guarantee: a verified anchor changes exactly what
/// it should.**
///
/// Its sibling
/// `facts_tests::receipt_verdict::an_unverified_appended_anchor_changes_no_status_of_the_receipt`
/// shows that an anchor which fails verification moves nothing. On its own
/// that would be indistinguishable from a verifier in which anchors do not
/// matter at all — two very different worlds. This test is the other side: the
/// same receipt, the same real FreeTSA token, and the *only* difference being
/// whether the caller supplied the trust root that lets the anchor verify.
///
/// With it, `has_valid_anchor()` becomes true and `NoTrustAnchor` disappears:
/// ATL v2.0 Section 5.5's threshold is reached. Without it, both go the other
/// way. Nothing else about the receipt differs.
///
/// # Why `is_valid` itself is not asserted here
///
/// This fixture cannot reach acceptance, and the reason is worth stating so
/// the assertion is not read as weaker than it is. The anchor pins
/// `proof.root_hash` to the token's `messageImprint`, a fixed value in a real
/// captured token; a receipt whose Merkle root is that value would have to be
/// one whose leaf hash inverts to it. Minting a token over a root this test
/// chooses needs a TSA private key, which this crate deliberately has none of.
/// So the base inclusion proof fails here by construction, and the `is_valid`
/// half is pinned where it can be stated exactly —
/// `verifier::compute_validity_tests::reaching_the_quorum_with_a_second_verified_anchor_accepts_the_receipt`,
/// which also covers `required: 2`, needing a second independent token this
/// crate does not have.
#[test]
fn a_verified_anchor_reaching_the_threshold_clears_the_finding() {
    use crate::core::verify::VerificationError;

    let receipt = make_receipt_anchored_to_freetsa();
    let no_trust_root = || {
        !ReceiptVerifier::anchor_only()
            .verify(&receipt)
            .errors()
            .iter()
            .any(|e| matches!(e, VerificationError::NoTrustAnchor { .. }))
    };

    // Without the trust root: the anchor does not verify, and the threshold
    // is reported unmet, naming both numbers.
    let without = ReceiptVerifier::anchor_only().verify(&receipt);
    assert!(!without.has_valid_anchor());
    assert!(!no_trust_root(), "the threshold must be reported unmet");
    assert!(without
        .errors()
        .iter()
        .any(|e| matches!(e, VerificationError::NoTrustAnchor { required: 1, verified: 0 })));

    // With it -- the single change -- the anchor verifies and the finding is
    // gone. An anchor that passes verification is *supposed* to move this.
    let store = TrustStore::new().with_anchor_certificate(decode_freetsa_root_cert());
    let options = VerifyOptions { rfc3161_trust_store: Some(store), ..Default::default() };
    let with = ReceiptVerifier::anchor_only_with_options(options).verify(&receipt);

    assert!(with.anchor_results[0].is_valid, "{:?}", with.anchor_results[0].error);
    assert!(with.has_valid_anchor());
    assert!(
        !with.errors().iter().any(|e| matches!(e, VerificationError::NoTrustAnchor { .. })),
        "one verified anchor meets Section 5.5: {:?}",
        with.errors()
    );
    // Nothing else moved: the fixture's own inclusion failure is untouched.
    assert_eq!(without.inclusion_valid, with.inclusion_valid);
}

/// The same receipt without the trust store: the anchor is unresolved, and
/// **the receipt's error list stays free of anchor findings**.
///
/// That is the rule under test. An anchor whose terminal certificate nobody
/// vouches for refutes nothing, so nothing about it may be published as
/// evidence against the receipt; only its absence from the verified tally may
/// count, and that is `NoTrustAnchor`'s job. (This fixture's base inclusion
/// proof fails for the reason given on the test above, which is why the error
/// list is not simply asserted empty.)
#[test]
fn an_unresolved_anchor_contributes_no_finding_against_the_receipt() {
    let receipt = make_receipt_anchored_to_freetsa();
    let result = ReceiptVerifier::anchor_only().verify(&receipt);

    assert!(!result.anchor_results[0].is_valid, "no trust store, so no verified anchor");
    assert!(!result.is_valid);

    assert_eq!(
        result.anchor_findings().count(),
        0,
        "an unvouched-for terminal certificate refutes nothing: {:?}",
        result.errors()
    );
}
