//! Convenient re-exports for common use cases
//!
//! Import everything commonly needed with:
//! ```rust,ignore
//! use atl_core::prelude::*;
//! ```
//!
//! **v2.0 Only**: All receipts must have valid `super_proof`.

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
    verify_consistency_to_origin,
    verify_cross_receipts,
    verify_receipt,
    // Super-Tree verification (mandatory in v2.0)
    verify_super_inclusion,
    CrossReceiptVerificationResult,
    ReceiptVerifier,
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
