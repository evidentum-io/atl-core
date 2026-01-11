//! Core cryptographic operations (pure, no I/O)
//!
//! This module provides the core building blocks for ATL:
//! - **merkle**: RFC 6962 Merkle tree operations (inclusion/consistency proofs)
//! - **verify**: Receipt verification and anchor validation (RFC 3161, Bitcoin OTS)
//! - **checkpoint**: Checkpoint parsing and verification
//! - **receipt**: Receipt types and serialization
//! - **jcs**: JSON Canonicalization Scheme (RFC 8785)

pub mod checkpoint;
pub mod jcs;
pub mod merkle;
pub mod receipt;
pub mod verify;

#[cfg(feature = "bitcoin-ots")]
pub mod ots;

// Re-export commonly used types for ergonomic API

// Checkpoint operations
pub use checkpoint::{
    compute_key_id, compute_origin_id, parse_hash, parse_signature, Checkpoint, CheckpointJson,
    CheckpointVerifier,
};

// JSON Canonicalization Scheme
pub use jcs::{canonicalize, canonicalize_and_hash};

// Merkle tree operations (RFC 6962)
pub use merkle::{
    // Leaf/node hashing
    compute_leaf_hash,
    // Root computation
    compute_root,
    // Utility functions
    compute_subtree_root,
    generate_consistency_proof,
    // Proof generation
    generate_inclusion_proof,
    hash_children,
    is_power_of_two,
    largest_power_of_2_less_than,
    verify_consistency,
    // Proof verification
    verify_inclusion,
    ConsistencyProof,
    // Core types
    Hash,
    InclusionProof,
    Leaf,
    TreeHead,
    // Constants
    LEAF_PREFIX,
    NODE_PREFIX,
};

// Receipt types and formatting
pub use receipt::{
    format_hash, format_signature, parse_base64_signature, Receipt, ReceiptAnchor,
    ReceiptConsistencyProof, ReceiptEntry, ReceiptProof, RECEIPT_SPEC_VERSION,
};

// Receipt verification
pub use verify::{
    // ISO 8601 parsing
    iso8601::{is_leap_year, parse_iso8601_to_nanos},
    // Verification functions
    verify_receipt,
    verify_receipt_json,
    // Main verifier and result types
    AnchorVerificationResult,
    ReceiptVerifier,
    VerificationError,
    VerificationResult,
    VerifyOptions,
};

// RFC 3161 timestamp verification (feature-gated)
#[cfg(feature = "rfc3161-verify")]
pub use verify::{ParsedTimestampToken, Rfc3161VerifyResult};
