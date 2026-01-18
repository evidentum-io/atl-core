//! Prelude: Common imports for ATL verification
//!
//! Import this module for the most common verification use cases:
//!
//! ```rust,ignore
//! use atl_core::prelude::*;
//!
//! // Anchor-based verification (recommended)
//! let verifier = ReceiptVerifier::anchor_only();
//! let result = verifier.verify(&receipt);
//! ```
//!
//! ## What's Included
//!
//! - `Receipt`, `ReceiptTier`, `SuperProof` - Receipt types
//! - `ReceiptVerifier` - Main verification API
//! - `VerificationResult` - Result types
//! - `SignatureMode`, `SignatureStatus` - Configuration types
//! - `CheckpointVerifier` - Optional signature verification
//!
//! ## Trust Model (v2.0)
//!
//! ATL Protocol v2.0 uses **anchor-based trust**. You don't need the Log Operator's
//! public key to verify receipts - trust comes from external anchors (RFC 3161 TSA
//! or Bitcoin OTS). All receipts must have valid `super_proof`.

// Errors
pub use crate::error::{AtlError, AtlResult};

// Receipt types (v2.0)
pub use crate::core::receipt::{
    Receipt,
    ReceiptAnchor,
    ReceiptEntry,
    ReceiptProof,
    ReceiptTier, // Mandatory in v2.0
    SuperProof,
    RECEIPT_SPEC_VERSION,
};

// Verification (v2.0)
pub use crate::core::verify::{
    // Super-Tree verification (mandatory in v2.0)
    verify_consistency_to_origin,
    verify_cross_receipts,
    // Anchor-only verification (recommended, no key required)
    verify_receipt_anchor_only,
    verify_receipt_json_anchor_only,
    // Key-based verification (if you have the key)
    verify_receipt_json_with_key,
    verify_receipt_json_with_options,
    verify_receipt_with_key,
    verify_receipt_with_options,
    verify_super_inclusion,
    // Types
    CrossReceiptVerificationResult,
    ReceiptVerifier,
    SignatureMode,
    SignatureStatus,
    VerificationResult,
    VerifyOptions,
};

// Checkpoint
pub use crate::core::checkpoint::{Checkpoint, CheckpointVerifier};

// Merkle (most commonly used)
pub use crate::core::merkle::{verify_consistency, verify_inclusion, Hash};

// Convenience functions
pub use crate::core::jcs::{canonicalize, canonicalize_and_hash};
pub use crate::core::merkle::compute_leaf_hash;

// Version constants
pub use crate::{PROTOCOL_VERSION, RECEIPT_VERSION, VERSION};

// Re-export uuid for convenience (Receipt.entry.id is Uuid)
pub use uuid::Uuid;
