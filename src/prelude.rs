//! Convenient re-exports for common use cases.
//!
//! ```rust,ignore
//! use atl_core::prelude::*;
//! ```
//!
//! This imports all commonly needed types for receipt verification.

// Errors
pub use crate::error::{AtlError, AtlResult};

// Core crypto types
pub use crate::core::checkpoint::{Checkpoint, CheckpointVerifier};
pub use crate::core::merkle::{ConsistencyProof, Hash, InclusionProof, TreeHead};
pub use crate::core::receipt::{Receipt, ReceiptEntry, ReceiptProof, SuperProof};
pub use crate::core::verify::{verify_receipt, VerificationResult};

// Convenience functions
pub use crate::core::jcs::{canonicalize, canonicalize_and_hash};
pub use crate::core::merkle::{compute_leaf_hash, verify_inclusion};

// Re-export uuid for convenience (Receipt.entry.id is Uuid)
pub use uuid::Uuid;
