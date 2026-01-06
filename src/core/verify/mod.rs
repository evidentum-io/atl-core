//! Receipt verification and anchor validation
//!
//! This module provides the `ReceiptVerifier` for validating ATL receipts
//! and anchor verification (RFC 3161 timestamps, Bitcoin OTS).

pub mod iso8601;
pub use iso8601::{is_leap_year, parse_iso8601_to_nanos};

pub mod types;
pub use types::{AnchorVerificationResult, VerificationError, VerificationResult, VerifyOptions};

pub(in crate::core) mod helpers;

pub mod anchors;

#[cfg(feature = "rfc3161-verify")]
pub use anchors::rfc3161::{ParsedTimestampToken, Rfc3161VerifyResult};

#[cfg(feature = "bitcoin-ots")]
pub use anchors::bitcoin_ots::{OtsVerifyResult, verify_ots_anchor_impl};

pub mod verifier;
pub use verifier::ReceiptVerifier;

pub mod convenience;
pub use convenience::{verify_inclusion_only, verify_receipt, verify_receipt_json};

#[cfg(test)]
mod tests;
