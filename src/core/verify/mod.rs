//! Receipt verification module
//!
//! This module provides verification for ATL v2.0 receipts including:
//! - Entry hash reconstruction
//! - Merkle inclusion proof verification
//! - Checkpoint signature verification
//! - Anchor verification (RFC 3161, Bitcoin OTS) with mandatory target fields
//! - Super-Tree verification (mandatory)
//! - Cross-receipt verification
//!
//! **v2.0 Only**: All receipts must have valid `super_proof`.

pub mod iso8601;
pub use iso8601::{is_leap_year, parse_iso8601_to_nanos};

pub mod types;
pub use types::{
    AnchorVerificationResult, SignatureMode, SignatureStatus, VerificationError,
    VerificationResult, VerifyOptions,
};

pub(in crate::core) mod helpers;
pub use helpers::AnchorVerificationContext;

pub mod anchors;

pub mod super_tree;
pub use super_tree::{
    verify_consistency_to_origin, verify_cross_receipts, verify_super_inclusion,
    CrossReceiptVerificationResult, SuperVerificationResult,
};

#[cfg(feature = "rfc3161-verify")]
pub use anchors::rfc3161::{ParsedTimestampToken, Rfc3161VerifyResult};

#[cfg(feature = "bitcoin-ots")]
pub use anchors::bitcoin_ots::{verify_ots_anchor_impl, OtsVerifyResult};

pub mod verifier;
pub use verifier::ReceiptVerifier;

pub mod convenience;
pub use convenience::{
    // Inclusion-only utility
    verify_inclusion_only,
    // Anchor-only (recommended)
    verify_receipt_anchor_only,
    verify_receipt_json_anchor_only,
    // Key-based
    verify_receipt_json_with_key,
    verify_receipt_json_with_key_and_options,
    verify_receipt_json_with_options,
    verify_receipt_with_key,
    verify_receipt_with_key_and_options,
    verify_receipt_with_options,
};

// Deprecated (still exported for backwards compatibility)
#[allow(deprecated)]
pub use convenience::{verify_receipt, verify_receipt_json};

#[cfg(test)]
mod tests;
