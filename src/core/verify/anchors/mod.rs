//! Anchor verification implementations
//!
//! This module provides verification for different anchor types:
//! - RFC 3161 Time-Stamp Protocol (TSA)
//! - Bitcoin OTS (`OpenTimestamps`)

// Submodules
#[cfg(feature = "rfc3161-verify")]
pub mod rfc3161;

#[cfg(feature = "bitcoin-ots")]
pub mod bitcoin_ots;

// Re-exports for convenience
#[cfg(feature = "rfc3161-verify")]
pub use rfc3161::{
    ParsedTimestampToken, PathStatus, Revocation, Rfc3161AnchorFacts, Rfc3161VerifyResult,
    SignerFacts, TerminalAnchor, TrustStore,
};

#[cfg(feature = "bitcoin-ots")]
pub use bitcoin_ots::{verify_ots_anchor_impl, OtsVerifyResult};

// Re-export internal functions for testing and library use
#[cfg(feature = "rfc3161-verify")]
pub use rfc3161::{
    extract_gen_time_nanos, parse_rfc3161_token, verify_rfc3161_anchor_impl, verify_rfc3161_hash,
    verify_rfc3161_token,
};
