//! Core cryptographic operations (pure, no I/O)

pub mod checkpoint;
pub mod jcs;
pub mod merkle;
pub mod receipt;
pub mod verify;

// Re-export commonly used types
pub use checkpoint::{
    compute_key_id, compute_origin_id, parse_hash, parse_signature, Checkpoint, CheckpointJson,
    CheckpointVerifier,
};
pub use jcs::{canonicalize, canonicalize_and_hash};
pub use merkle::{compute_leaf_hash, verify_inclusion, Hash, InclusionProof};
pub use receipt::{
    format_hash, format_signature, parse_base64_signature, Receipt, ReceiptAnchor,
    ReceiptConsistencyProof, ReceiptEntry, ReceiptProof, RECEIPT_SPEC_VERSION,
};
pub use verify::{
    verify_receipt, verify_receipt_json, AnchorVerificationResult, ReceiptVerifier,
    VerificationError, VerificationResult, VerifyOptions,
};
