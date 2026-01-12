//! Error types for OTS module operations

use std::io;
use std::string::FromUtf8Error;

/// Maximum recursion depth for timestamp operations
pub const RECURSION_LIMIT: usize = 256;

/// Maximum length of a pending attestation URI
pub const MAX_URI_LEN: usize = 1000;

/// Maximum length of operation data (append/prepend)
pub const MAX_OP_LENGTH: usize = 4096;

/// OTS magic bytes
pub const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";

/// Supported major version
pub const VERSION: usize = 1;

/// Error type for OTS module operations
#[derive(Debug)]
pub enum OtsError {
    /// File doesn't start with OTS magic bytes
    InvalidMagic(Vec<u8>),

    /// Unsupported OTS file version (only v1 supported)
    UnsupportedVersion(usize),

    /// Recursion limit exceeded during timestamp parsing
    RecursionLimitExceeded,

    /// Digest length doesn't match expected value
    InvalidDigestLength {
        /// Expected digest length
        expected: usize,
        /// Actual digest length
        actual: usize,
    },

    /// Start digest in proof doesn't match expected root hash
    StartDigestMismatch {
        /// Expected hash value
        expected: String,
        /// Actual hash value in proof
        actual: String,
    },

    /// Proof contains only pending attestations (needs upgrade)
    PendingOnly {
        /// Calendar URIs where proof can be upgraded
        uris: Vec<String>,
    },

    /// Unrecognized operation tag
    InvalidOperation(u8),

    /// Unrecognized digest type tag
    InvalidDigestType(u8),

    /// Invalid character in pending attestation URI
    InvalidUriChar(char),

    /// Byte vector length out of valid range
    InvalidLength {
        /// Minimum allowed length
        min: usize,
        /// Maximum allowed length
        max: usize,
        /// Actual length
        actual: usize,
    },

    /// Unexpected data after end of timestamp
    TrailingData,

    /// I/O error during parsing
    IoError(io::Error),

    /// UTF-8 decoding error
    Utf8Error(FromUtf8Error),

    /// Builder error: no attestation added (timestamp must end with attestation)
    NoAttestation,

    /// Builder error: unclosed fork (started fork but never ended)
    UnclosedFork,

    /// Builder error: fork without branches
    EmptyFork,

    /// Builder error: end fork called without matching fork
    UnmatchedEndFork,

    /// No pending attestation found in timestamp (already upgraded)
    NoPendingAttestation,
}

impl std::fmt::Display for OtsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic(bytes) => write!(
                f,
                "invalid OTS magic bytes: expected OpenTimestamps header, got {} bytes",
                bytes.len()
            ),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported OTS version: {version} (only version 1 is supported)")
            }
            Self::RecursionLimitExceeded => {
                write!(f, "recursion limit exceeded (max {RECURSION_LIMIT})")
            }
            Self::InvalidDigestLength { expected, actual } => {
                write!(f, "invalid digest length: expected {expected} bytes, got {actual}")
            }
            Self::StartDigestMismatch { expected, actual } => {
                write!(f, "start digest mismatch: expected {expected}, got {actual}")
            }
            Self::PendingOnly { uris } => {
                write!(
                    f,
                    "proof contains only pending attestations (upgrade at: {})",
                    uris.join(", ")
                )
            }
            Self::InvalidOperation(tag) => {
                write!(f, "invalid operation tag: 0x{tag:02x}")
            }
            Self::InvalidDigestType(tag) => {
                write!(f, "invalid digest type tag: 0x{tag:02x}")
            }
            Self::InvalidUriChar(ch) => {
                write!(f, "invalid character in URI: {ch:?}")
            }
            Self::InvalidLength { min, max, actual } => {
                write!(f, "invalid length: expected {min}..{max} bytes, got {actual}")
            }
            Self::TrailingData => {
                write!(f, "unexpected trailing data after timestamp")
            }
            Self::IoError(err) => {
                write!(f, "I/O error: {err}")
            }
            Self::Utf8Error(err) => {
                write!(f, "UTF-8 decoding error: {err}")
            }
            Self::NoAttestation => {
                write!(f, "timestamp must end with at least one attestation")
            }
            Self::UnclosedFork => {
                write!(f, "unclosed fork: fork() called without matching end_fork()")
            }
            Self::EmptyFork => {
                write!(f, "fork must have at least two branches")
            }
            Self::UnmatchedEndFork => {
                write!(f, "end_fork() called without matching fork()")
            }
            Self::NoPendingAttestation => {
                write!(f, "no pending attestation found in timestamp (already upgraded)")
            }
        }
    }
}

impl std::error::Error for OtsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(err) => Some(err),
            Self::Utf8Error(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for OtsError {
    fn from(err: io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<FromUtf8Error> for OtsError {
    fn from(err: FromUtf8Error) -> Self {
        Self::Utf8Error(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_error_display() {
        let err = OtsError::InvalidMagic(vec![0x00, 0x01]);
        assert!(err.to_string().contains("magic"));

        let err = OtsError::UnsupportedVersion(2);
        assert!(err.to_string().contains('2'));

        let err = OtsError::PendingOnly { uris: vec!["https://calendar.example.com".into()] };
        assert!(err.to_string().contains("pending"));
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<OtsError>();
    }

    #[test]
    fn test_constants() {
        assert_eq!(RECURSION_LIMIT, 256);
        assert_eq!(MAX_URI_LEN, 1000);
        assert_eq!(MAX_OP_LENGTH, 4096);
        assert_eq!(MAGIC.len(), 31);
        assert_eq!(VERSION, 1);
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "test");
        let ots_err: OtsError = io_err.into();
        assert!(matches!(ots_err, OtsError::IoError(_)));
    }

    #[test]
    fn test_error_from_utf8() {
        let invalid_utf8 = vec![0xFF, 0xFE];
        let utf8_err = String::from_utf8(invalid_utf8).unwrap_err();
        let ots_err: OtsError = utf8_err.into();
        assert!(matches!(ots_err, OtsError::Utf8Error(_)));
    }

    #[test]
    fn test_error_implements_std_error() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<OtsError>();
    }

    #[test]
    fn test_all_error_variants_have_messages() {
        let errors = vec![
            OtsError::InvalidMagic(vec![0x00]),
            OtsError::UnsupportedVersion(2),
            OtsError::RecursionLimitExceeded,
            OtsError::InvalidDigestLength { expected: 32, actual: 16 },
            OtsError::StartDigestMismatch { expected: "aabb".into(), actual: "ccdd".into() },
            OtsError::PendingOnly { uris: vec!["https://calendar.example.com".into()] },
            OtsError::InvalidOperation(0xFF),
            OtsError::InvalidDigestType(0xFF),
            OtsError::InvalidUriChar('\0'),
            OtsError::InvalidLength { min: 1, max: 100, actual: 200 },
            OtsError::TrailingData,
            OtsError::IoError(io::Error::new(io::ErrorKind::UnexpectedEof, "test")),
            OtsError::NoAttestation,
            OtsError::UnclosedFork,
            OtsError::EmptyFork,
            OtsError::UnmatchedEndFork,
            OtsError::NoPendingAttestation,
        ];

        for err in errors {
            let msg = err.to_string();
            assert!(!msg.is_empty(), "Error message should not be empty");
        }
    }

    #[test]
    fn test_error_source() {
        let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "test");
        let ots_err = OtsError::IoError(io_err);
        assert!(ots_err.source().is_some());

        let ots_err = OtsError::InvalidMagic(vec![0x00]);
        assert!(ots_err.source().is_none());
    }
}
