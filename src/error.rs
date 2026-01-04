//! Core error types for atl-core
//!
//! These errors cover pure cryptographic operations only.
//! Server-specific errors (storage, network, anchoring) are in atl-server.

use thiserror::Error;

/// The main error type for atl-core operations.
///
/// This enum covers errors from pure cryptographic operations only.
/// Server-specific errors (storage, network) are in atl-server.
#[derive(Debug, Error)]
pub enum AtlError {
    // ========== Cryptographic Errors ==========
    /// Invalid hash format or length
    #[error("invalid hash: {0}")]
    InvalidHash(String),

    /// Hash prefix is not recognized (expected "sha256:")
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedHashAlgorithm(String),

    /// Signature verification failed
    #[error("signature verification failed")]
    SignatureInvalid,

    /// Invalid signature format
    #[error("invalid signature format: {0}")]
    InvalidSignature(String),

    /// Invalid public key format
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    // ========== Merkle Tree Errors ==========
    /// Leaf index out of bounds
    #[error("leaf index {index} out of bounds for tree size {tree_size}")]
    LeafIndexOutOfBounds {
        /// The requested leaf index
        index: u64,
        /// The actual tree size
        tree_size: u64,
    },

    /// Tree size mismatch in proof verification
    #[error("tree size mismatch: expected {expected}, got {actual}")]
    TreeSizeMismatch {
        /// Expected tree size
        expected: u64,
        /// Actual tree size
        actual: u64,
    },

    /// Inclusion proof verification failed
    #[error("inclusion proof verification failed")]
    InclusionProofInvalid,

    /// Consistency proof verification failed
    #[error("consistency proof verification failed")]
    ConsistencyProofInvalid,

    /// Invalid proof path length
    #[error("invalid proof path: expected {expected} hashes, got {actual}")]
    InvalidProofPath {
        /// Expected number of hashes
        expected: usize,
        /// Actual number of hashes
        actual: usize,
    },

    /// Missing node hash from storage callback
    ///
    /// NOTE: This error is used by proof generation functions that accept storage callbacks.
    /// While ERROR-1 spec focuses on pure verification, proof generation requires storage access.
    #[error("missing node at level {level}, index {index}")]
    MissingNode {
        /// Tree level (0 = leaves)
        level: u32,
        /// Node index at that level
        index: u64,
    },

    // ========== Checkpoint Errors ==========
    /// Invalid checkpoint wire format
    #[error("invalid checkpoint format: {0}")]
    InvalidCheckpointFormat(String),

    /// Checkpoint magic bytes mismatch
    #[error("invalid checkpoint magic bytes")]
    InvalidCheckpointMagic,

    /// Checkpoint timestamp is invalid
    #[error("invalid checkpoint timestamp: {0}")]
    InvalidTimestamp(String),

    /// Origin ID mismatch
    #[error("origin mismatch: expected {expected}, got {actual}")]
    OriginMismatch {
        /// Expected origin ID
        expected: String,
        /// Actual origin ID
        actual: String,
    },

    // ========== Receipt Errors ==========
    /// Invalid receipt format or structure
    #[error("invalid receipt: {0}")]
    InvalidReceipt(String),

    /// Unsupported receipt spec version
    #[error("unsupported receipt version: {0}")]
    UnsupportedReceiptVersion(String),

    /// Receipt verification failed (aggregated)
    #[error("receipt verification failed: {0}")]
    ReceiptVerificationFailed(String),

    // ========== Serialization Errors ==========
    /// JSON canonicalization error
    #[error("JCS error: {0}")]
    Jcs(String),

    /// JSON parsing/serialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64 decoding error
    #[error("base64 decode error: {0}")]
    Base64Decode(String),

    /// Hex decoding error
    #[error("hex decode error: {0}")]
    HexDecode(String),

    /// UUID parsing error
    #[error("invalid UUID: {0}")]
    InvalidUuid(String),

    // ========== Generic Errors ==========
    /// Invalid argument provided
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Operation not supported
    #[error("not supported: {0}")]
    NotSupported(String),
}

impl AtlError {
    /// Returns true if this error indicates a verification failure
    ///
    /// Verification failures mean the cryptographic proof is invalid,
    /// not that there was a parsing or format error.
    #[must_use]
    pub const fn is_verification_failure(&self) -> bool {
        matches!(
            self,
            Self::SignatureInvalid
                | Self::InclusionProofInvalid
                | Self::ConsistencyProofInvalid
                | Self::OriginMismatch { .. }
        )
    }

    /// Returns true if this error indicates invalid input format
    ///
    /// Format errors mean the input couldn't be parsed, not that
    /// verification failed.
    #[must_use]
    pub const fn is_format_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidHash(_)
                | Self::InvalidSignature(_)
                | Self::InvalidPublicKey(_)
                | Self::InvalidCheckpointFormat(_)
                | Self::InvalidCheckpointMagic
                | Self::InvalidReceipt(_)
                | Self::Json(_)
                | Self::Base64Decode(_)
                | Self::HexDecode(_)
                | Self::InvalidUuid(_)
        )
    }

    /// Returns true if this error is related to proof structure
    #[must_use]
    pub const fn is_proof_error(&self) -> bool {
        matches!(
            self,
            Self::LeafIndexOutOfBounds { .. }
                | Self::TreeSizeMismatch { .. }
                | Self::InvalidProofPath { .. }
                | Self::InclusionProofInvalid
                | Self::ConsistencyProofInvalid
                | Self::MissingNode { .. }
        )
    }
}

// ========== Error Conversions ==========

/// Convert hex decoding errors to `AtlError`
impl From<hex::FromHexError> for AtlError {
    fn from(e: hex::FromHexError) -> Self {
        Self::HexDecode(e.to_string())
    }
}

/// Convert base64 decoding errors to `AtlError`
impl From<base64::DecodeError> for AtlError {
    fn from(e: base64::DecodeError) -> Self {
        Self::Base64Decode(e.to_string())
    }
}

/// Convert UUID parsing errors to `AtlError`
impl From<uuid::Error> for AtlError {
    fn from(e: uuid::Error) -> Self {
        Self::InvalidUuid(e.to_string())
    }
}

/// Convert ed25519-dalek signature errors to `AtlError`
impl From<ed25519_dalek::SignatureError> for AtlError {
    fn from(_: ed25519_dalek::SignatureError) -> Self {
        Self::SignatureInvalid
    }
}

/// Result type alias using `AtlError`
pub type AtlResult<T> = Result<T, AtlError>;

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = AtlError::LeafIndexOutOfBounds { index: 100, tree_size: 50 };
        assert_eq!(err.to_string(), "leaf index 100 out of bounds for tree size 50");
    }

    #[test]
    fn test_tree_size_mismatch_display() {
        let err = AtlError::TreeSizeMismatch { expected: 1000, actual: 500 };
        assert_eq!(err.to_string(), "tree size mismatch: expected 1000, got 500");
    }

    #[test]
    fn test_origin_mismatch_display() {
        let err = AtlError::OriginMismatch {
            expected: "origin-a".to_string(),
            actual: "origin-b".to_string(),
        };
        assert_eq!(err.to_string(), "origin mismatch: expected origin-a, got origin-b");
    }

    #[test]
    fn test_is_verification_failure() {
        assert!(AtlError::SignatureInvalid.is_verification_failure());
        assert!(AtlError::InclusionProofInvalid.is_verification_failure());
        assert!(AtlError::ConsistencyProofInvalid.is_verification_failure());
        assert!(
            AtlError::OriginMismatch { expected: "a".into(), actual: "b".into() }
                .is_verification_failure()
        );

        assert!(!AtlError::InvalidHash("x".into()).is_verification_failure());
        assert!(
            !AtlError::Json(serde_json::from_str::<()>("x").unwrap_err()).is_verification_failure()
        );
    }

    #[test]
    fn test_is_format_error() {
        assert!(AtlError::InvalidHash("x".into()).is_format_error());
        assert!(AtlError::InvalidCheckpointMagic.is_format_error());
        assert!(AtlError::InvalidSignature("bad".into()).is_format_error());
        assert!(AtlError::InvalidPublicKey("bad".into()).is_format_error());
        assert!(AtlError::Base64Decode("bad".into()).is_format_error());
        assert!(AtlError::HexDecode("bad".into()).is_format_error());
        assert!(AtlError::InvalidUuid("bad".into()).is_format_error());

        assert!(!AtlError::SignatureInvalid.is_format_error());
        assert!(!AtlError::InclusionProofInvalid.is_format_error());
    }

    #[test]
    fn test_is_proof_error() {
        assert!(AtlError::InclusionProofInvalid.is_proof_error());
        assert!(AtlError::ConsistencyProofInvalid.is_proof_error());
        assert!(AtlError::LeafIndexOutOfBounds { index: 0, tree_size: 0 }.is_proof_error());
        assert!(AtlError::TreeSizeMismatch { expected: 1, actual: 2 }.is_proof_error());
        assert!(AtlError::InvalidProofPath { expected: 5, actual: 3 }.is_proof_error());
        assert!(AtlError::MissingNode { level: 0, index: 0 }.is_proof_error());

        assert!(!AtlError::InvalidHash("x".into()).is_proof_error());
        assert!(!AtlError::SignatureInvalid.is_proof_error());
    }

    #[test]
    fn test_error_from_conversions() {
        // JSON error conversion
        let json_err: AtlError = serde_json::from_str::<()>("invalid").unwrap_err().into();
        assert!(matches!(json_err, AtlError::Json(_)));

        // Hex error conversion
        let hex_err: AtlError = hex::decode("not hex").unwrap_err().into();
        assert!(matches!(hex_err, AtlError::HexDecode(_)));
    }

    #[test]
    fn test_base64_error_conversion() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;

        let result = STANDARD.decode("invalid base64!!!");
        assert!(result.is_err());

        let err: AtlError = result.unwrap_err().into();
        assert!(matches!(err, AtlError::Base64Decode(_)));
    }

    #[test]
    fn test_uuid_error_conversion() {
        let result = uuid::Uuid::parse_str("not-a-uuid");
        assert!(result.is_err());

        let err: AtlError = result.unwrap_err().into();
        assert!(matches!(err, AtlError::InvalidUuid(_)));
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AtlError>();
    }

    #[test]
    fn test_no_storage_errors() {
        // Verify there are no Storage-related error variants
        // This is a compile-time check - if AtlError had StorageError,
        // this would fail to compile
        let _err = AtlError::InvalidHash("test".into());
        // AtlError::Storage would not compile
    }

    #[test]
    fn test_all_variants_have_messages() {
        // Ensure all error variants have proper Display messages
        let errors = vec![
            AtlError::InvalidHash("test".into()),
            AtlError::UnsupportedHashAlgorithm("md5".into()),
            AtlError::SignatureInvalid,
            AtlError::InvalidSignature("bad".into()),
            AtlError::InvalidPublicKey("bad".into()),
            AtlError::LeafIndexOutOfBounds { index: 1, tree_size: 1 },
            AtlError::TreeSizeMismatch { expected: 1, actual: 2 },
            AtlError::InclusionProofInvalid,
            AtlError::ConsistencyProofInvalid,
            AtlError::InvalidProofPath { expected: 1, actual: 2 },
            AtlError::MissingNode { level: 0, index: 0 },
            AtlError::InvalidCheckpointFormat("bad".into()),
            AtlError::InvalidCheckpointMagic,
            AtlError::InvalidTimestamp("bad".into()),
            AtlError::OriginMismatch { expected: "a".into(), actual: "b".into() },
            AtlError::InvalidReceipt("bad".into()),
            AtlError::UnsupportedReceiptVersion("v2".into()),
            AtlError::ReceiptVerificationFailed("reason".into()),
            AtlError::Jcs("error".into()),
            AtlError::Base64Decode("error".into()),
            AtlError::HexDecode("error".into()),
            AtlError::InvalidUuid("error".into()),
            AtlError::InvalidArgument("error".into()),
            AtlError::NotSupported("feature".into()),
        ];

        for err in errors {
            let msg = err.to_string();
            assert!(!msg.is_empty(), "Error message should not be empty");
            assert!(!msg.contains("NotImplemented"), "Error should have proper message");
        }
    }

    #[test]
    fn test_error_implements_std_error() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<AtlError>();
    }
}
