//! Verification types and results
//!
//! This module contains the core types used in receipt verification:
//! - `VerificationResult`: Complete verification result with detailed status
//! - `AnchorVerificationResult`: Result of verifying a single anchor
//! - `VerificationError`: Detailed error types for verification failures
//! - `VerifyOptions`: Configuration options for verification

/// Result of receipt verification
///
/// Contains detailed information about the verification process,
/// including success/failure status and any errors encountered.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct VerificationResult {
    /// Overall verification status (true if all critical checks passed)
    pub is_valid: bool,

    /// Reconstructed leaf hash from entry
    pub leaf_hash: [u8; 32],

    /// Root hash from proof
    pub root_hash: [u8; 32],

    /// Tree size from proof
    pub tree_size: u64,

    /// Timestamp from checkpoint (nanoseconds since Unix epoch)
    pub timestamp: u64,

    /// Signature verification passed
    pub signature_valid: bool,

    /// Inclusion proof verification passed
    pub inclusion_valid: bool,

    /// Consistency proof verification (if present)
    pub consistency_valid: Option<bool>,

    /// Super-Tree inclusion proof verification passed (MANDATORY in v2.0)
    pub super_inclusion_valid: bool,

    /// Super-Tree consistency to origin verification passed (MANDATORY in v2.0)
    pub super_consistency_valid: bool,

    /// Genesis super root (ALWAYS present in v2.0)
    pub genesis_super_root: [u8; 32],

    /// Super root (ALWAYS present in v2.0)
    pub super_root: [u8; 32],

    /// Data Tree index in Super-Tree (ALWAYS present in v2.0)
    pub data_tree_index: u64,

    /// Super-Tree size (ALWAYS present in v2.0)
    pub super_tree_size: u64,

    /// Anchor verification results
    pub anchor_results: Vec<AnchorVerificationResult>,

    /// Detailed errors (if any)
    pub errors: Vec<VerificationError>,
}

/// Result of verifying a single anchor
#[derive(Debug, Clone)]
pub struct AnchorVerificationResult {
    /// Anchor type (e.g., "rfc3161", "bitcoin")
    pub anchor_type: String,

    /// Verification passed
    pub is_valid: bool,

    /// Timestamp from anchor (if available)
    pub timestamp: Option<u64>,

    /// Error message if invalid
    pub error: Option<String>,
}

/// Detailed verification errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// Invalid receipt format
    InvalidReceipt(String),

    /// Hash format/decoding error
    InvalidHash {
        /// Field name containing the invalid hash
        field: String,
        /// Error message describing the issue
        message: String,
    },

    /// Signature verification failed
    SignatureFailed,

    /// Inclusion proof failed
    InclusionProofFailed {
        /// Reason for failure
        reason: String,
    },

    /// Consistency proof failed
    ConsistencyProofFailed {
        /// Reason for failure
        reason: String,
    },

    /// Root hash mismatch between checkpoint and proof
    RootHashMismatch,

    /// Tree size mismatch between checkpoint and proof
    TreeSizeMismatch,

    /// Anchor verification failed
    AnchorFailed {
        /// Type of anchor that failed
        anchor_type: String,
        /// Reason for failure
        reason: String,
    },

    /// Super-Tree inclusion proof failed (MANDATORY check)
    SuperInclusionFailed {
        /// Reason for failure
        reason: String,
    },

    /// Super-Tree consistency to origin failed (MANDATORY check)
    SuperConsistencyFailed {
        /// Reason for failure
        reason: String,
    },

    /// Super-Tree data mismatch
    SuperDataMismatch {
        /// Field that mismatched
        field: String,
        /// Expected value
        expected: String,
        /// Actual value
        actual: String,
    },

    /// Missing `super_proof` (required in v2.0)
    MissingSuperProof,

    /// Unsupported receipt version
    UnsupportedVersion(String),
}

/// Options for verification
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Skip anchor verification
    pub skip_anchors: bool,

    /// Skip consistency proof verification
    pub skip_consistency: bool,

    /// Require at least this many valid anchors
    pub min_valid_anchors: usize,
}

impl VerificationResult {
    /// Check if all critical verifications passed
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.is_valid
    }

    /// Check if at least one anchor was verified
    #[must_use]
    pub fn has_valid_anchor(&self) -> bool {
        self.anchor_results.iter().any(|a| a.is_valid)
    }

    /// Get the first error (if any)
    #[must_use]
    pub fn first_error(&self) -> Option<&VerificationError> {
        self.errors.first()
    }

    /// Get all errors
    #[must_use]
    pub fn errors(&self) -> &[VerificationError] {
        &self.errors
    }
}
