//! Bitcoin attestation extraction from `OpenTimestamps` proofs
//!
//! This module provides functionality to extract Bitcoin attestations and their
//! merkle paths from OTS files. It validates that proofs match expected document
//! hashes and returns structured attestation data.

use super::attestation::Attestation;
use super::error::OtsError;
use super::ser::DetachedTimestampFile;
use super::timestamp::{Step, StepData};

/// Result of extracting a Bitcoin attestation from OTS proof
///
/// Contains the block height where the timestamp was anchored,
/// the merkle path from document hash to `OP_RETURN`, and optionally
/// the block timestamp (filled by CLI/server after Bitcoin RPC lookup).
///
/// # Examples
///
/// ```rust,ignore
/// use atl_core::ots::extract_bitcoin_attestations;
///
/// let ots_bytes = std::fs::read("document.ots")?;
/// let doc_hash = [0xaa; 32]; // SHA256 of document
///
/// let attestations = extract_bitcoin_attestations(&ots_bytes, &doc_hash)?;
/// for att in attestations {
///     println!("Block: {}, Path length: {}", att.block_height, att.path_len());
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinAttestation {
    /// Bitcoin block height where merkle root was anchored
    pub block_height: u64,

    /// Merkle path from document hash to Bitcoin `OP_RETURN`
    ///
    /// Each element is a 32-byte hash representing intermediate digest
    /// outputs from hash operations in the OTS proof chain.
    pub merkle_path: Vec<[u8; 32]>,

    /// Block timestamp in nanoseconds (always None from core)
    ///
    /// This field is populated by CLI/server after Bitcoin RPC lookup.
    /// The core library does not perform blockchain queries.
    pub timestamp: Option<u64>,
}

impl BitcoinAttestation {
    /// Returns `true` if block timestamp has been populated
    ///
    /// # Examples
    ///
    /// ```
    /// # use atl_core::ots::BitcoinAttestation;
    /// let att = BitcoinAttestation {
    ///     block_height: 100,
    ///     merkle_path: vec![],
    ///     timestamp: None,
    /// };
    /// assert!(!att.has_timestamp());
    ///
    /// let att = BitcoinAttestation {
    ///     block_height: 100,
    ///     merkle_path: vec![],
    ///     timestamp: Some(123_4567890),
    /// };
    /// assert!(att.has_timestamp());
    /// ```
    #[must_use]
    pub const fn has_timestamp(&self) -> bool {
        self.timestamp.is_some()
    }

    /// Returns the number of elements in the merkle path
    ///
    /// # Examples
    ///
    /// ```
    /// # use atl_core::ots::BitcoinAttestation;
    /// let att = BitcoinAttestation {
    ///     block_height: 100,
    ///     merkle_path: vec![[0xaa; 32], [0xbb; 32]],
    ///     timestamp: None,
    /// };
    /// assert_eq!(att.path_len(), 2);
    /// ```
    #[must_use]
    pub const fn path_len(&self) -> usize {
        self.merkle_path.len()
    }
}

/// Extract all Bitcoin attestations from an OTS proof
///
/// Parses the OTS file, validates that the start digest matches the expected
/// document hash, and traverses the proof tree to collect all Bitcoin attestations
/// with their merkle paths.
///
/// # Arguments
///
/// * `ots_bytes` - Raw bytes of `.ots` file
/// * `expected_root` - SHA256 hash of the document being verified
///
/// # Returns
///
/// * `Ok(Vec<BitcoinAttestation>)` - All Bitcoin attestations found (may be empty)
/// * `Err(OtsError::StartDigestMismatch)` - Proof is for different document
/// * `Err(OtsError::PendingOnly { uris })` - No Bitcoin attestations, only pending
/// * `Err(OtsError::InvalidMagic)` - Not a valid OTS file
/// * `Err(OtsError::InvalidDigestLength)` - Digest length mismatch
///
/// # Examples
///
/// ```rust,ignore
/// use atl_core::ots::extract_bitcoin_attestations;
///
/// let ots_bytes = std::fs::read("document.ots")?;
/// let doc_hash = sha256(&document_bytes);
///
/// match extract_bitcoin_attestations(&ots_bytes, &doc_hash) {
///     Ok(attestations) => {
///         for att in attestations {
///             println!("Found Bitcoin attestation at block {}", att.block_height);
///         }
///     }
///     Err(OtsError::PendingOnly { uris }) => {
///         println!("Proof not yet confirmed. Upgrade at: {:?}", uris);
///     }
///     Err(e) => {
///         eprintln!("Error: {}", e);
///     }
/// }
/// ```
///
/// # Errors
///
/// Returns various [`OtsError`] variants depending on the failure mode:
/// - File format errors (invalid magic, unsupported version)
/// - Digest validation errors (wrong document hash)
/// - Proof state errors (only pending attestations available)
pub fn extract_bitcoin_attestations(
    ots_bytes: &[u8],
    expected_root: &[u8; 32],
) -> Result<Vec<BitcoinAttestation>, OtsError> {
    // Parse OTS file
    let file = DetachedTimestampFile::from_bytes(ots_bytes)?;

    // Validate start digest matches expected root
    validate_start_digest(&file.timestamp.start_digest, expected_root)?;

    // Initialize extraction context
    let mut ctx = ExtractionContext {
        path: Vec::new(),
        bitcoin_attestations: Vec::new(),
        pending_uris: Vec::new(),
    };

    // Traverse the timestamp tree
    traverse_step(&mut ctx, &file.timestamp.first_step);

    // Check if we found any Bitcoin attestations
    if ctx.bitcoin_attestations.is_empty() && !ctx.pending_uris.is_empty() {
        return Err(OtsError::PendingOnly { uris: ctx.pending_uris });
    }

    Ok(ctx.bitcoin_attestations)
}

/// Internal context for tracking extraction state during tree traversal
struct ExtractionContext {
    /// Current merkle path (32-byte outputs from hash operations)
    path: Vec<[u8; 32]>,
    /// Collected Bitcoin attestations
    bitcoin_attestations: Vec<BitcoinAttestation>,
    /// Collected pending URIs
    pending_uris: Vec<String>,
}

/// Recursively traverse a step and collect attestations
///
/// This function walks the timestamp proof tree, building up merkle paths
/// from hash operation outputs and collecting Bitcoin attestations.
fn traverse_step(ctx: &mut ExtractionContext, step: &Step) {
    match &step.data {
        StepData::Fork => {
            // Traverse all branches, each with a copy of the current path
            for branch in &step.next {
                // Save current path state
                let saved_path = ctx.path.clone();

                // Traverse this branch
                traverse_step(ctx, branch);

                // Restore path state for next branch
                ctx.path = saved_path;
            }
        }

        StepData::Op(_) => {
            // Add output to path if it's 32 bytes (hash output)
            // We only track 32-byte digests in the merkle path
            if step.output.len() == 32 {
                // Safe unwrap: we just checked length is 32
                #[allow(clippy::expect_used)]
                let hash: [u8; 32] =
                    step.output.clone().try_into().expect("output length checked to be 32");
                ctx.path.push(hash);
            }

            // Op steps always have exactly one child
            // Safety: Op steps are guaranteed by parser to have exactly 1 child
            if let Some(next_step) = step.next.first() {
                traverse_step(ctx, next_step);
            }
        }

        StepData::Attestation(Attestation::Bitcoin { height }) => {
            // Found a Bitcoin attestation - record it with current path
            ctx.bitcoin_attestations.push(BitcoinAttestation {
                block_height: *height,
                merkle_path: ctx.path.clone(),
                timestamp: None, // Core library doesn't populate this
            });
        }

        StepData::Attestation(Attestation::Pending { uri }) => {
            // Found a pending attestation - collect URI for error reporting
            ctx.pending_uris.push(uri.clone());
        }

        StepData::Attestation(Attestation::Unknown { .. }) => {
            // Ignore unknown attestations (forward compatibility)
            // Future attestation types are silently skipped
        }
    }
}

/// Validate that the start digest matches expected document hash
///
/// # Errors
///
/// Returns [`OtsError::InvalidDigestLength`] if digest length is not 32 bytes.
/// Returns [`OtsError::StartDigestMismatch`] if digest doesn't match expected.
fn validate_start_digest(actual: &[u8], expected: &[u8; 32]) -> Result<(), OtsError> {
    // Check length first
    if actual.len() != 32 {
        return Err(OtsError::InvalidDigestLength { expected: 32, actual: actual.len() });
    }

    // Check content
    if actual != expected {
        return Err(OtsError::StartDigestMismatch {
            expected: hex::encode(expected),
            actual: hex::encode(actual),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a test OTS file with known structure
    fn create_test_ots_with_bitcoin(height: u64) -> Vec<u8> {
        use crate::core::ots::op::Op;
        use crate::core::ots::ser::DigestType;
        use crate::core::ots::timestamp::{Step, StepData, Timestamp};

        let start_digest = vec![0xaa; 32];

        // Create: start -> SHA256 -> Bitcoin attestation
        let sha256_output = Op::Sha256.execute(&start_digest);

        let bitcoin_att = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height }),
            output: sha256_output.clone(),
            next: vec![],
        };

        let sha256_step =
            Step { data: StepData::Op(Op::Sha256), output: sha256_output, next: vec![bitcoin_att] };

        let timestamp = Timestamp { start_digest, first_step: sha256_step };

        let file = DetachedTimestampFile { digest_type: DigestType::Sha256, timestamp };

        file.to_bytes().expect("serialization failed")
    }

    // Helper to create OTS file with only pending attestation
    fn create_test_ots_pending() -> Vec<u8> {
        use crate::core::ots::ser::DigestType;
        use crate::core::ots::timestamp::{Step, StepData, Timestamp};

        let start_digest = vec![0xbb; 32];

        let pending_att = Step {
            data: StepData::Attestation(Attestation::Pending {
                uri: "https://calendar.example.com".to_string(),
            }),
            output: start_digest.clone(),
            next: vec![],
        };

        let timestamp = Timestamp { start_digest, first_step: pending_att };

        let file = DetachedTimestampFile { digest_type: DigestType::Sha256, timestamp };

        file.to_bytes().expect("serialization failed")
    }

    #[test]
    fn test_extract_with_bitcoin_attestation() {
        let ots_bytes = create_test_ots_with_bitcoin(123_456);
        let expected_root = [0xaa; 32];

        let result = extract_bitcoin_attestations(&ots_bytes, &expected_root);

        assert!(result.is_ok(), "Expected successful extraction");
        let attestations = result.unwrap();

        assert_eq!(attestations.len(), 1);
        assert_eq!(attestations[0].block_height, 123_456);
        assert_eq!(attestations[0].path_len(), 1); // One SHA256 operation
        assert!(!attestations[0].has_timestamp());
    }

    #[test]
    fn test_wrong_document_hash() {
        let ots_bytes = create_test_ots_with_bitcoin(100);
        let wrong_root = [0xff; 32]; // Wrong hash

        let result = extract_bitcoin_attestations(&ots_bytes, &wrong_root);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::StartDigestMismatch { .. }));
    }

    #[test]
    fn test_pending_only_error() {
        let ots_bytes = create_test_ots_pending();
        let expected_root = [0xbb; 32];

        let result = extract_bitcoin_attestations(&ots_bytes, &expected_root);

        assert!(result.is_err());
        match result.unwrap_err() {
            OtsError::PendingOnly { uris } => {
                assert_eq!(uris.len(), 1);
                assert_eq!(uris[0], "https://calendar.example.com");
            }
            e => panic!("Expected PendingOnly error, got: {e:?}"),
        }
    }

    #[test]
    fn test_invalid_ots_file() {
        // Create data with enough bytes to get past magic check but wrong magic
        let mut garbage = vec![0u8; 50];
        garbage[0..23].copy_from_slice(b"this is not an ots file");

        let expected_root = [0xcc; 32];

        let result = extract_bitcoin_attestations(&garbage, &expected_root);

        assert!(result.is_err());
        // Can be InvalidMagic or IoError depending on how far parsing gets
        assert!(matches!(result.unwrap_err(), OtsError::InvalidMagic(_) | OtsError::IoError(_)));
    }

    #[test]
    fn test_merkle_path_structure() {
        let ots_bytes = create_test_ots_with_bitcoin(100);
        let expected_root = [0xaa; 32];

        let attestations = extract_bitcoin_attestations(&ots_bytes, &expected_root).unwrap();

        assert_eq!(attestations.len(), 1);

        // Verify merkle path elements are 32 bytes
        for hash in &attestations[0].merkle_path {
            assert_eq!(hash.len(), 32);
        }

        // Check that path contains the SHA256 output
        assert_eq!(attestations[0].merkle_path.len(), 1);
    }

    #[test]
    fn test_bitcoin_attestation_helpers() {
        let att = BitcoinAttestation {
            block_height: 123_456,
            merkle_path: vec![[0xaa; 32], [0xbb; 32], [0xcc; 32]],
            timestamp: None,
        };

        assert!(!att.has_timestamp());
        assert_eq!(att.path_len(), 3);

        let att_with_ts = BitcoinAttestation {
            block_height: 123_456,
            merkle_path: vec![],
            timestamp: Some(123_4567890),
        };

        assert!(att_with_ts.has_timestamp());
        assert_eq!(att_with_ts.path_len(), 0);
    }

    #[test]
    fn test_extract_from_real_small_test() {
        let ots_data = include_bytes!("../../../test_data/ots/small-test.ots");

        // Parse to get start digest
        let file = DetachedTimestampFile::from_bytes(ots_data).unwrap();
        let start_digest: [u8; 32] =
            file.timestamp.start_digest.try_into().expect("start digest should be 32 bytes");

        let result = extract_bitcoin_attestations(ots_data, &start_digest);

        // This file should have pending attestations (not yet confirmed)
        // or Bitcoin attestations depending on the actual file content
        match result {
            Ok(attestations) => {
                println!("Found {} Bitcoin attestations", attestations.len());
                for att in attestations {
                    println!("  Block: {}, Path length: {}", att.block_height, att.path_len());
                }
            }
            Err(OtsError::PendingOnly { uris }) => {
                println!("Pending attestations only: {uris:?}");
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }
    }

    #[test]
    fn test_extract_from_real_large_test() {
        let ots_data = include_bytes!("../../../test_data/ots/large-test.ots");

        // Parse to get start digest
        let file = DetachedTimestampFile::from_bytes(ots_data).unwrap();
        let start_digest: [u8; 32] =
            file.timestamp.start_digest.try_into().expect("start digest should be 32 bytes");

        let result = extract_bitcoin_attestations(ots_data, &start_digest);

        // This file should have pending attestations (not yet confirmed)
        // or Bitcoin attestations depending on the actual file content
        match result {
            Ok(attestations) => {
                println!("Found {} Bitcoin attestations", attestations.len());
                for att in attestations {
                    println!("  Block: {}, Path length: {}", att.block_height, att.path_len());
                }
            }
            Err(OtsError::PendingOnly { uris }) => {
                println!("Pending attestations only: {uris:?}");
            }
            Err(e) => panic!("Unexpected error: {e:?}"),
        }
    }

    #[test]
    fn test_multiple_bitcoin_attestations() {
        use crate::core::ots::ser::DigestType;
        use crate::core::ots::timestamp::{Step, StepData, Timestamp};

        let start_digest = vec![0xdd; 32];

        // Create fork with two Bitcoin attestations
        let att1 = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height: 100 }),
            output: start_digest.clone(),
            next: vec![],
        };

        let att2 = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height: 200 }),
            output: start_digest.clone(),
            next: vec![],
        };

        let fork =
            Step { data: StepData::Fork, output: start_digest.clone(), next: vec![att1, att2] };

        let timestamp = Timestamp { start_digest: start_digest.clone(), first_step: fork };

        let file = DetachedTimestampFile { digest_type: DigestType::Sha256, timestamp };

        let ots_bytes = file.to_bytes().unwrap();
        let expected_root: [u8; 32] = start_digest.try_into().unwrap();

        let result = extract_bitcoin_attestations(&ots_bytes, &expected_root).unwrap();

        assert_eq!(result.len(), 2);

        let heights: Vec<u64> = result.iter().map(|att| att.block_height).collect();
        assert!(heights.contains(&100));
        assert!(heights.contains(&200));
    }

    #[test]
    fn test_bitcoin_attestation_clone_and_eq() {
        let att1 = BitcoinAttestation {
            block_height: 100,
            merkle_path: vec![[0xaa; 32]],
            timestamp: None,
        };

        let att2 = att1.clone();
        assert_eq!(att1, att2);

        let att3 = BitcoinAttestation {
            block_height: 200,
            merkle_path: vec![[0xaa; 32]],
            timestamp: None,
        };
        assert_ne!(att1, att3);
    }

    #[test]
    fn test_bitcoin_attestation_debug() {
        let att = BitcoinAttestation {
            block_height: 123_456,
            merkle_path: vec![[0xaa; 32]],
            timestamp: Some(123_4567890),
        };

        let debug_str = format!("{att:?}");
        assert!(debug_str.contains("123_456"));
        assert!(debug_str.contains("BitcoinAttestation"));
    }

    #[test]
    fn test_empty_attestations_valid() {
        use crate::core::ots::ser::DigestType;
        use crate::core::ots::timestamp::{Step, StepData, Timestamp};

        // Create OTS with unknown attestation (neither Bitcoin nor Pending)
        let start_digest = vec![0xee; 32];

        let unknown_att = Step {
            data: StepData::Attestation(Attestation::Unknown { tag: [0x01; 8], data: vec![0x42] }),
            output: start_digest.clone(),
            next: vec![],
        };

        let timestamp = Timestamp { start_digest: start_digest.clone(), first_step: unknown_att };

        let file = DetachedTimestampFile { digest_type: DigestType::Sha256, timestamp };

        let ots_bytes = file.to_bytes().unwrap();
        let expected_root: [u8; 32] = start_digest.try_into().unwrap();

        // Should return empty Vec (not an error)
        let result = extract_bitcoin_attestations(&ots_bytes, &expected_root).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_validate_start_digest_wrong_length() {
        let short_digest = vec![0xaa; 16];
        let expected = [0xaa; 32];

        let result = validate_start_digest(&short_digest, &expected);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OtsError::InvalidDigestLength { expected: 32, actual: 16 }
        ));
    }
}
