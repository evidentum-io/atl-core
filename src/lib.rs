//! # atl-core
//!
//! Pure cryptographic library for ATL Protocol v2.0 (Anchored Transparency Log).
//!
//! atl-core provides cryptographic primitives for **verifying** transparency log
//! receipts. It contains NO I/O operations.
//!
//! ## What atl-core Provides
//!
//! - **Merkle tree operations** per RFC 6962
//! - **Checkpoint verification** (signature as integrity check)
//! - **Receipt parsing** and structure validation
//! - **Anchor-based verification** (RFC 3161 TSA, Bitcoin OTS)
//! - **Offline verification** of evidence receipts
//! - **JCS canonicalization** per RFC 8785
//!
//! ## Trust Model (ATL Protocol v2.0)
//!
//! Trust is established through **external anchors**, not the Log Operator's
//! signature. A receipt is trustworthy if:
//!
//! 1. The Merkle inclusion proof is valid
//! 2. At least one external anchor verifies (RFC 3161 or Bitcoin)
//!
//! The Log Operator's signature is an optional integrity check, not a trust anchor.
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
//! ATL Protocol v2.0 uses **anchor-based trust**. You don't need a public key
//! to verify a receipt - trust is established through external anchors
//! (RFC 3161 TSA or Bitcoin OTS).
//!
//! ### Recommended: Anchor-Based Verification
//!
//! ```rust,ignore
//! use atl_core::prelude::*;
//!
//! // Load receipt from .atl file
//! let receipt_json = std::fs::read_to_string("document.pdf.atl")?;
//! let receipt = Receipt::from_json(&receipt_json)?;
//!
//! // Verify using external anchors (no key required)
//! let verifier = ReceiptVerifier::anchor_only();
//! let result = verifier.verify(&receipt);
//!
//! if result.is_valid {
//!     println!("Receipt verified via external anchor!");
//!     println!("Entry ID: {}", receipt.entry.id);
//!     if result.has_valid_anchor() {
//!         println!("Trust established via anchors");
//!     }
//! } else {
//!     println!("Verification failed:");
//!     for error in &result.errors {
//!         println!("  - {:?}", error);
//!     }
//! }
//! ```
//!
//! ### Optional: With Public Key (Integrity Check)
//!
//! If you have the Log Operator's public key, you can add signature verification
//! as an additional integrity check:
//!
//! ```rust,ignore
//! use atl_core::prelude::*;
//!
//! let receipt = Receipt::from_json(&json)?;
//!
//! // Optional: verify signature for integrity (not trust)
//! let known_key: [u8; 32] = /* Log Operator's public key */;
//! let checkpoint_verifier = CheckpointVerifier::from_bytes(&known_key)?;
//! let verifier = ReceiptVerifier::with_key(checkpoint_verifier);
//! let result = verifier.verify(&receipt);
//!
//! if result.signature_valid() {
//!     println!("Signature valid (integrity check passed)");
//! }
//! // Trust still comes from anchors
//! if result.is_valid && result.has_valid_anchor() {
//!     println!("Receipt is trustworthy");
//! }
//! ```
//!
//! ## Trust Model
//!
//! Per ATL Protocol v2.0:
//!
//! > "Verifiers do NOT need to trust the Log Operator. Trust is derived
//! > exclusively from external, independent anchors."
//!
//! | Component | Purpose |
//! |-----------|---------|
//! | Merkle Proof | Proves entry is in the tree |
//! | Signature | Integrity check (optional) |
//! | RFC 3161 Anchor | **Trust** - independent timestamp |
//! | Bitcoin Anchor | **Trust** - immutable blockchain proof |
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
// Transitive dependencies bring multiple versions - not actionable in library code
#![allow(clippy::multiple_crate_versions)]

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
    compute_genesis_leaf_hash, compute_leaf_hash, compute_root, generate_consistency_proof,
    generate_inclusion_proof, hash_children, verify_consistency, verify_inclusion,
    ConsistencyProof, Hash, InclusionProof, Leaf, TreeHead, GENESIS_DOMAIN, LEAF_PREFIX,
    NODE_PREFIX,
};

// Checkpoint types and functions
pub use core::checkpoint::{
    compute_key_id, compute_origin_id, Checkpoint, CheckpointJson, CheckpointVerifier,
    CHECKPOINT_BLOB_SIZE, CHECKPOINT_MAGIC,
};

// Receipt types (v2.0)
pub use core::receipt::{
    Receipt,
    ReceiptAnchor,
    ReceiptConsistencyProof,
    ReceiptEntry,
    ReceiptProof,
    ReceiptTier,
    // Super-Tree types (mandatory in v2.0)
    SuperProof,
    // Anchor target constants (mandatory in v2.0)
    ANCHOR_TARGET_DATA_TREE_ROOT,
    ANCHOR_TARGET_SUPER_ROOT,
    RECEIPT_SPEC_VERSION,
};

// Verification types and functions (v2.0)
pub use core::verify::{
    // Super-Tree verification (mandatory in v2.0)
    verify_consistency_to_origin,
    verify_cross_receipts,
    // Anchor-only verification (recommended)
    verify_receipt_anchor_only,
    verify_receipt_json_anchor_only,
    // Key-based verification
    verify_receipt_json_with_key,
    verify_receipt_json_with_key_and_options,
    verify_receipt_json_with_options,
    verify_receipt_with_key,
    verify_receipt_with_key_and_options,
    verify_receipt_with_options,
    verify_super_inclusion,
    // Types
    AnchorVerificationContext,
    AnchorVerificationResult,
    CrossReceiptVerificationResult,
    ReceiptVerifier,
    SignatureMode,
    SignatureStatus,
    SuperVerificationResult,
    VerificationError,
    VerificationResult,
    VerifyOptions,
};

// Deprecated (still exported for backwards compatibility)
#[allow(deprecated)]
pub use core::verify::{verify_receipt, verify_receipt_json};

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
///
/// Version 2.0.0 introduces:
/// - Super-Tree architecture for global chain consistency
/// - Two-tier anchoring (TSA -> Data Tree Root, OTS -> Super Root)
/// - Cross-receipt verification without server access
/// - Mandatory `super_proof` field in receipts
/// - Mandatory `target` and `target_hash` fields in anchors
///
pub const PROTOCOL_VERSION: &str = "2.0.0";

/// Receipt specification version
///
/// Version 2.0.0:
/// - Mandatory `super_proof` field
/// - Optional `upgrade_url` field
/// - Mandatory `target` and `target_hash` fields in anchors
pub const RECEIPT_VERSION: &str = "2.0.0";

// ============================================================================
// Export Tests
// ============================================================================

#[cfg(test)]
mod export_tests {
    // Test that all types are accessible from crate root
    use crate::{
        verify_consistency_to_origin, verify_cross_receipts, verify_super_inclusion,
        AnchorVerificationContext, CrossReceiptVerificationResult, ReceiptTier, SuperProof,
        SuperVerificationResult, ANCHOR_TARGET_DATA_TREE_ROOT, ANCHOR_TARGET_SUPER_ROOT,
    };

    #[test]
    fn test_super_proof_accessible() {
        let _: fn() -> SuperProof = || SuperProof {
            genesis_super_root: String::new(),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: String::new(),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };
    }

    #[test]
    fn test_receipt_tier_accessible() {
        let tier = ReceiptTier::Full;
        assert_eq!(tier.name(), "Receipt-Full");
    }

    #[test]
    fn test_anchor_targets_accessible() {
        assert_eq!(ANCHOR_TARGET_DATA_TREE_ROOT, "data_tree_root");
        assert_eq!(ANCHOR_TARGET_SUPER_ROOT, "super_root");
    }

    #[test]
    fn test_verification_context_accessible() {
        let ctx = AnchorVerificationContext::new([0u8; 32], [0u8; 32]);
        assert!(ctx.expected_hash_for_target("data_tree_root").is_some());
        assert!(ctx.expected_hash_for_target("super_root").is_some());
    }

    #[test]
    fn test_super_verification_result_fields_non_option() {
        // Verify SuperVerificationResult fields are concrete types
        let result = SuperVerificationResult::valid([0u8; 32], [0u8; 32]);
        let _: bool = result.inclusion_valid;
        let _: bool = result.consistency_valid;
        let _: [u8; 32] = result.genesis_super_root;
        let _: [u8; 32] = result.super_root;
    }

    #[test]
    fn test_verify_functions_accessible() {
        // Just check that functions are accessible
        let _ = verify_super_inclusion;
        let _ = verify_consistency_to_origin;
        let _ = verify_cross_receipts;
    }

    #[test]
    fn test_cross_receipt_result_accessible() {
        let result = CrossReceiptVerificationResult {
            same_log_instance: true,
            history_consistent: true,
            genesis_super_root: [0u8; 32],
            receipt_a_index: 5,
            receipt_b_index: 10,
            receipt_a_super_tree_size: 10,
            receipt_b_super_tree_size: 15,
            errors: vec![],
        };
        assert!(result.is_valid());
    }
}

#[cfg(test)]
mod prelude_tests {
    use crate::prelude::*;

    #[test]
    fn test_prelude_includes_super_types() {
        // These should compile if prelude exports are correct
        let tier = ReceiptTier::Lite;
        let _ = tier;
        let proof_fn: fn() -> SuperProof = || SuperProof {
            genesis_super_root: String::new(),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: String::new(),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };
        let _ = proof_fn;
    }

    #[test]
    fn test_prelude_includes_cross_receipt_result() {
        let result = CrossReceiptVerificationResult {
            same_log_instance: true,
            history_consistent: true,
            genesis_super_root: [0u8; 32],
            receipt_a_index: 5,
            receipt_b_index: 10,
            receipt_a_super_tree_size: 10,
            receipt_b_super_tree_size: 15,
            errors: vec![],
        };
        assert!(result.is_valid());
    }

    #[test]
    fn test_prelude_includes_verification_functions() {
        // Just check that functions are accessible from prelude
        let _ = verify_super_inclusion;
        let _ = verify_consistency_to_origin;
        let _ = verify_cross_receipts;
    }
}
