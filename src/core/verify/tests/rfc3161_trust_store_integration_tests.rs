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
