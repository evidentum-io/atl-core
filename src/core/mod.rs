//! Core cryptographic operations (pure, no I/O)

pub mod checkpoint;
pub mod jcs;
pub mod merkle;
pub mod receipt;
pub mod verify;

// Re-export commonly used types
pub use checkpoint::{
    Checkpoint, CheckpointJson, CheckpointVerifier, compute_key_id, compute_origin_id, parse_hash,
    parse_signature,
};
pub use jcs::{canonicalize, canonicalize_and_hash};
pub use merkle::{Hash, InclusionProof, compute_leaf_hash, verify_inclusion};
pub use receipt::{
    RECEIPT_SPEC_VERSION, Receipt, ReceiptAnchor, ReceiptConsistencyProof, ReceiptEntry,
    ReceiptProof, format_hash, format_signature, parse_base64_signature,
};
pub use verify::{
    AnchorVerificationResult, ReceiptVerifier, VerificationError, VerificationResult,
    VerifyOptions, verify_receipt, verify_receipt_json,
};
