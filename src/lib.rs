//! # atl-core
//!
//! Pure cryptographic library for ATL Protocol v1 (Anchored Transparency Log).
//!
//! atl-core provides cryptographic primitives for **verifying** transparency log
//! receipts. It contains NO I/O operations.
//!
//! ## What atl-core Provides
//!
//! - **Merkle tree operations** per RFC 6962
//! - **Checkpoint verification** with Ed25519
//! - **Receipt parsing** and structure validation
//! - **Offline verification** of evidence receipts
//! - **JCS canonicalization** per RFC 8785
//!
//! ## What atl-core Does NOT Provide
//!
//! - Storage backends (see atl-server)
//! - HTTP server (see atl-server)
//! - Anchoring clients (see atl-server)
//! - Receipt generation (see atl-server)
//!
//! ## Quick Start: Verify a Receipt
//!
//! ```rust,ignore
//! use atl_core::prelude::*;
//!
//! // Load receipt from .atl file
//! let receipt_json = std::fs::read_to_string("document.pdf.atl")?;
//! let receipt = Receipt::from_json(&receipt_json)?;
//!
//! // Verify with trusted public key
//! let trusted_key: [u8; 32] = /* your trusted public key */;
//! let result = verify_receipt(&receipt, &trusted_key)?;
//!
//! if result.is_valid {
//!     println!("Receipt is valid!");
//!     println!("Entry ID: {}", receipt.entry.id);
//!     println!("Tree size: {}", receipt.proof.tree_size);
//! } else {
//!     println!("Verification failed:");
//!     for error in &result.errors {
//!         println!("  - {:?}", error);
//!     }
//! }
//! ```
//!
//! ## Architecture
//!
//! ```text
//! atl-core (this)     Pure cryptography, no I/O
//!     ^
//!     |
//! atl-server          Storage + HTTP + Anchoring + Receipt generation
//!     ^
//!     |
//! atl-cli             CLI verifier (uses atl-core directly)
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]
#![deny(unsafe_code)]

// ============================================================================
// Core Module
// ============================================================================

/// Core cryptographic operations (pure, no I/O)
pub mod core;

// ============================================================================
// Error Types
// ============================================================================

mod error;
pub use error::{AtlError, AtlResult};

// ============================================================================
// Prelude (common imports)
// ============================================================================

/// Convenient re-exports for common use cases
pub mod prelude;

// ============================================================================
// Re-exports at crate root for convenience
// ============================================================================

// Merkle tree types and functions
pub use core::merkle::{
    compute_leaf_hash, compute_root, generate_consistency_proof, generate_inclusion_proof,
    hash_children, verify_consistency, verify_inclusion, ConsistencyProof, Hash, InclusionProof,
    Leaf, TreeHead, LEAF_PREFIX, NODE_PREFIX,
};

// Checkpoint types and functions
pub use core::checkpoint::{
    compute_key_id, compute_origin_id, Checkpoint, CheckpointJson, CheckpointVerifier,
    CHECKPOINT_BLOB_SIZE, CHECKPOINT_MAGIC,
};

// Receipt types
pub use core::receipt::{
    Receipt, ReceiptAnchor, ReceiptConsistencyProof, ReceiptEntry, ReceiptProof,
    RECEIPT_SPEC_VERSION,
};

// Verification types and functions
pub use core::verify::{
    verify_receipt, verify_receipt_json, AnchorVerificationResult, ReceiptVerifier,
    VerificationError, VerificationResult, VerifyOptions,
};

// RFC 3161 timestamp verification (feature-gated)
#[cfg(feature = "rfc3161-verify")]
pub use core::verify::{ParsedTimestampToken, Rfc3161VerifyResult};

// JCS canonicalization
pub use core::jcs::{canonicalize, canonicalize_and_hash};

// OTS (OpenTimestamps) parsing (feature-gated)
#[cfg(feature = "bitcoin-ots")]
pub use core::ots;

// ============================================================================
// Version Information
// ============================================================================

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// ATL Protocol version implemented
pub const PROTOCOL_VERSION: &str = "1.0.0";

/// Receipt specification version
pub const RECEIPT_VERSION: &str = "1.0.0";
