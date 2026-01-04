//! Offline verification algorithm
//!
//! Verifies receipts using ONLY:
//! 1. The receipt JSON
//! 2. A trusted public key
//!
//! No network access, no storage access required.

use crate::core::checkpoint::{CheckpointVerifier, parse_hash};
use crate::core::jcs::canonicalize_and_hash;
use crate::core::merkle::{InclusionProof, compute_leaf_hash, verify_inclusion};
use crate::core::receipt::{Receipt, ReceiptAnchor};
use crate::error::AtlResult;

/// Result of receipt verification
///
/// Contains detailed information about the verification process,
/// including success/failure status and any errors encountered.
#[derive(Debug, Clone)]
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

/// Verifier for receipts
///
/// This is the main entry point for receipt verification.
pub struct ReceiptVerifier {
    /// Checkpoint verifier (contains trusted public key)
    checkpoint_verifier: CheckpointVerifier,

    /// Verification options
    options: VerifyOptions,
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

impl ReceiptVerifier {
    /// Create a new verifier with a trusted public key
    #[must_use]
    pub fn new(verifier: CheckpointVerifier) -> Self {
        Self { checkpoint_verifier: verifier, options: VerifyOptions::default() }
    }

    /// Create with custom options
    #[must_use]
    pub const fn with_options(verifier: CheckpointVerifier, options: VerifyOptions) -> Self {
        Self { checkpoint_verifier: verifier, options }
    }

    /// Verify a receipt
    ///
    /// ## Arguments
    ///
    /// * `receipt` - The receipt to verify
    ///
    /// ## Returns
    ///
    /// `VerificationResult` with detailed status
    ///
    /// This method never panics and always returns a result.
    #[must_use]
    pub fn verify(&self, receipt: &Receipt) -> VerificationResult {
        let mut result = VerificationResult {
            is_valid: false,
            leaf_hash: [0; 32],
            root_hash: [0; 32],
            tree_size: receipt.proof.tree_size,
            timestamp: receipt.proof.checkpoint.timestamp,
            signature_valid: false,
            inclusion_valid: false,
            consistency_valid: None,
            anchor_results: vec![],
            errors: vec![],
        };

        // STEP 1: Reconstruct Leaf Hash
        match reconstruct_leaf_hash(&receipt.entry.payload_hash, &receipt.entry.metadata) {
            Ok(hash) => result.leaf_hash = hash,
            Err(e) => {
                result.errors.push(e);
                return result;
            }
        }

        // Parse root hash for result
        if let Ok(root) = parse_hash(&receipt.proof.root_hash) {
            result.root_hash = root;
        } else {
            result.errors.push(VerificationError::InvalidHash {
                field: "proof.root_hash".to_string(),
                message: "failed to parse root hash".to_string(),
            });
            return result;
        }

        // Consistency check: checkpoint.root_hash == proof.root_hash
        if receipt.proof.checkpoint.root_hash != receipt.proof.root_hash {
            result.errors.push(VerificationError::RootHashMismatch);
            return result;
        }

        // Consistency check: checkpoint.tree_size == proof.tree_size
        if receipt.proof.checkpoint.tree_size != receipt.proof.tree_size {
            result.errors.push(VerificationError::TreeSizeMismatch);
            return result;
        }

        // STEP 2: Verify Inclusion
        match verify_inclusion_proof(&result.leaf_hash, &receipt.proof) {
            Ok(true) => result.inclusion_valid = true,
            Ok(false) => {
                result.errors.push(VerificationError::InclusionProofFailed {
                    reason: "path does not lead to root".to_string(),
                });
            }
            Err(e) => {
                result.errors.push(e);
            }
        }

        // STEP 3: Verify Signature
        match verify_checkpoint_signature(&receipt.proof.checkpoint, &self.checkpoint_verifier) {
            Ok(true) => result.signature_valid = true,
            Ok(false) | Err(_) => {
                result.errors.push(VerificationError::SignatureFailed);
            }
        }

        // STEP 4: Verify Anchors (optional)
        if !self.options.skip_anchors {
            for anchor in &receipt.anchors {
                let anchor_result = verify_anchor(anchor, &result.root_hash);
                result.anchor_results.push(anchor_result);
            }

            // Check minimum valid anchors requirement
            let valid_anchor_count = result.anchor_results.iter().filter(|a| a.is_valid).count();
            if self.options.min_valid_anchors > 0
                && valid_anchor_count < self.options.min_valid_anchors
            {
                result.errors.push(VerificationError::AnchorFailed {
                    anchor_type: "general".to_string(),
                    reason: format!(
                        "required {} valid anchors, got {}",
                        self.options.min_valid_anchors, valid_anchor_count
                    ),
                });
            }
        }

        // Determine overall validity
        result.is_valid =
            result.inclusion_valid && result.signature_valid && result.errors.is_empty();

        result
    }

    /// Verify receipt JSON string
    ///
    /// ## Errors
    ///
    /// Returns error if JSON parsing fails.
    pub fn verify_json(&self, json: &str) -> AtlResult<VerificationResult> {
        let receipt = Receipt::from_json(json)?;
        Ok(self.verify(&receipt))
    }
}

// ========== RFC 3161 Verification Functions ==========

#[cfg(feature = "rfc3161-verify")]
use cryptographic_message_syntax::asn1::rfc3161::TstInfo;

#[cfg(feature = "rfc3161-verify")]
#[allow(dead_code)]
const MAX_TOKEN_SIZE: usize = 65536;

#[cfg(feature = "rfc3161-verify")]
#[allow(dead_code)]
const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";

/// Parsed RFC 3161 timestamp token
///
/// Contains the decoded `TSTInfo` structure and raw DER bytes.
#[cfg(feature = "rfc3161-verify")]
pub struct ParsedTimestampToken {
    /// Decoded `TSTInfo` structure from RFC 3161
    pub tst_info: TstInfo,
    /// Raw DER-encoded `TSTInfo` bytes
    pub raw_tst_info: Vec<u8>,
}

/// Result of RFC 3161 hash verification
///
/// Contains verification status and extracted token information.
#[cfg(feature = "rfc3161-verify")]
pub struct Rfc3161VerifyResult {
    /// Whether the hash comparison succeeded
    pub hash_valid: bool,
    /// OID of the hash algorithm used in the token
    pub algorithm_oid: String,
    /// Hex-encoded hash value from the token
    pub token_hash: String,
    /// Generation time from token (nanoseconds since Unix epoch)
    pub gen_time: Option<u64>,
}

/// Parse an RFC 3161 timestamp token from base64-encoded DER
///
/// Decodes a timestamp token in the format `"base64:..."` and extracts
/// the `TSTInfo` structure.
///
/// ## Arguments
///
/// * `token_der` - Base64-encoded token with `"base64:"` prefix
///
/// ## Returns
///
/// Parsed token containing `TSTInfo` and raw DER bytes
///
/// ## Errors
///
/// Returns `Rfc3161ParseError` if:
/// - Token does not have `"base64:"` prefix
/// - Base64 decoding fails
/// - Token size exceeds 65536 bytes
/// - CMS `SignedData` parsing fails
/// - `TSTInfo` decoding fails
#[cfg(feature = "rfc3161-verify")]
#[allow(dead_code)]
fn parse_rfc3161_token(token_der: &str) -> crate::error::AtlResult<ParsedTimestampToken> {
    use crate::error::AtlError;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use cryptographic_message_syntax::SignedData;

    let token_b64 = token_der
        .strip_prefix("base64:")
        .ok_or_else(|| AtlError::Rfc3161ParseError("missing base64: prefix".to_string()))?;

    let token_bytes = STANDARD
        .decode(token_b64)
        .map_err(|e| AtlError::Rfc3161ParseError(format!("base64 decode failed: {e}")))?;

    if token_bytes.len() > MAX_TOKEN_SIZE {
        return Err(AtlError::Rfc3161ParseError(format!(
            "token size {} exceeds maximum {}",
            token_bytes.len(),
            MAX_TOKEN_SIZE
        )));
    }

    let signed_data = SignedData::parse_ber(&token_bytes)
        .map_err(|e| AtlError::Rfc3161ParseError(format!("CMS parse failed: {e}")))?;

    let raw_tst_info = signed_data
        .signed_content()
        .ok_or_else(|| AtlError::Rfc3161ParseError("no encapsulated content".to_string()))?
        .to_vec();

    let tst_info = {
        use bcder::decode::Constructed;
        Constructed::decode(raw_tst_info.as_ref(), bcder::Mode::Der, |cons| {
            TstInfo::take_from(cons)
        })
        .map_err(|e| AtlError::Rfc3161ParseError(format!("TSTInfo decode failed: {e}")))?
    };

    Ok(ParsedTimestampToken { tst_info, raw_tst_info })
}

/// Verify RFC 3161 hash against expected root hash
///
/// Extracts the `MessageImprint` from the parsed token and verifies:
/// 1. Hash algorithm is SHA-256
/// 2. Hash value matches the expected root
///
/// ## Arguments
///
/// * `parsed` - Parsed timestamp token
/// * `expected_root` - Expected SHA-256 hash (32 bytes)
///
/// ## Returns
///
/// Verification result with hash validation status
///
/// ## Errors
///
/// Returns error if:
/// - `Rfc3161UnsupportedAlgorithm` - Hash algorithm is not SHA-256
/// - `Rfc3161ParseError` - Hash length is not 32 bytes
/// - `Rfc3161HashMismatch` - Hash value does not match expected root
#[cfg(feature = "rfc3161-verify")]
#[allow(dead_code)]
fn verify_rfc3161_hash(
    parsed: &ParsedTimestampToken,
    expected_root: &[u8; 32],
) -> crate::error::AtlResult<Rfc3161VerifyResult> {
    use crate::error::AtlError;
    use subtle::ConstantTimeEq;

    let message_imprint = &parsed.tst_info.message_imprint;

    let algo_oid = message_imprint.hash_algorithm.algorithm.to_string();
    if algo_oid != SHA256_OID {
        return Err(AtlError::Rfc3161UnsupportedAlgorithm(format!(
            "expected SHA-256 ({SHA256_OID}), got {algo_oid}"
        )));
    }

    let token_hash_bytes = message_imprint.hashed_message.to_bytes();
    if token_hash_bytes.len() != 32 {
        return Err(AtlError::Rfc3161ParseError(format!(
            "invalid hash length: expected 32 bytes, got {}",
            token_hash_bytes.len()
        )));
    }

    let mut token_hash_array = [0u8; 32];
    token_hash_array.copy_from_slice(&token_hash_bytes);

    let hash_valid: bool = token_hash_array.ct_eq(expected_root).into();

    if !hash_valid {
        return Err(AtlError::Rfc3161HashMismatch {
            token_hash: hex::encode(token_hash_array),
            expected_hash: hex::encode(expected_root),
        });
    }

    Ok(Rfc3161VerifyResult {
        hash_valid: true,
        algorithm_oid: algo_oid,
        token_hash: hex::encode(token_hash_array),
        gen_time: extract_gen_time_nanos(&parsed.tst_info),
    })
}

/// Extract generation time from `TSTInfo`
///
/// Converts the `GeneralizedTime` from the token into nanoseconds since Unix epoch.
/// Returns `None` if the time cannot be parsed.
#[cfg(feature = "rfc3161-verify")]
fn extract_gen_time_nanos(tst_info: &TstInfo) -> Option<u64> {
    let gen_time = &tst_info.gen_time;

    let time_string = gen_time.to_string();

    if time_string.len() < 14 {
        return None;
    }

    let year = time_string[0..4].parse::<i32>().ok()?;
    let month = time_string[4..6].parse::<u32>().ok()?;
    let day = time_string[6..8].parse::<u32>().ok()?;
    let hour = time_string[8..10].parse::<u32>().ok()?;
    let minute = time_string[10..12].parse::<u32>().ok()?;
    let second = time_string[12..14].parse::<u32>().ok()?;

    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || hour >= 24
        || minute >= 60
        || second >= 60
    {
        return None;
    }

    let max_day = if month == 2 && is_leap_year(year) {
        29
    } else {
        DAYS_IN_MONTH[usize::try_from(month - 1).ok()?]
    };
    if day < 1 || day > max_day {
        return None;
    }

    let days_since_epoch = days_since_unix_epoch(year, month, day)?;

    let total_seconds = u64::from(days_since_epoch) * 86400
        + u64::from(hour) * 3600
        + u64::from(minute) * 60
        + u64::from(second);

    Some(total_seconds * 1_000_000_000)
}

// ========== Internal Helper Functions ==========

/// Reconstruct leaf hash from payload hash and metadata
///
/// STEP 1 of verification algorithm:
/// 1. Decode `payload_hash` from "sha256:..."
/// 2. Compute `metadata_hash` = SHA256(JCS(metadata))
/// 3. Compute `leaf_hash` = SHA256(0x00 || `payload_hash` || `metadata_hash`)
fn reconstruct_leaf_hash(
    payload_hash_str: &str,
    metadata: &serde_json::Value,
) -> Result<[u8; 32], VerificationError> {
    // Decode payload hash
    let payload_hash =
        parse_hash(payload_hash_str).map_err(|e| VerificationError::InvalidHash {
            field: "entry.payload_hash".to_string(),
            message: e.to_string(),
        })?;

    // Compute metadata hash via JCS
    let metadata_hash = canonicalize_and_hash(metadata);

    // Compute leaf hash: SHA256(0x00 || payload_hash || metadata_hash)
    Ok(compute_leaf_hash(&payload_hash, &metadata_hash))
}

/// Verify inclusion proof
///
/// STEP 2 of verification algorithm:
/// Uses RFC 6962 path validation to verify the leaf is included in the tree.
fn verify_inclusion_proof(
    leaf_hash: &[u8; 32],
    proof: &crate::core::receipt::ReceiptProof,
) -> Result<bool, VerificationError> {
    // Parse inclusion path
    let path: Vec<[u8; 32]> =
        proof.inclusion_path.iter().map(|h| parse_hash(h)).collect::<Result<Vec<_>, _>>().map_err(
            |e| VerificationError::InvalidHash {
                field: "proof.inclusion_path".to_string(),
                message: e.to_string(),
            },
        )?;

    // Parse expected root
    let expected_root =
        parse_hash(&proof.root_hash).map_err(|e| VerificationError::InvalidHash {
            field: "proof.root_hash".to_string(),
            message: e.to_string(),
        })?;

    // Verify using Merkle module
    let inclusion_proof =
        InclusionProof { leaf_index: proof.leaf_index, tree_size: proof.tree_size, path };

    verify_inclusion(leaf_hash, &inclusion_proof, &expected_root)
        .map_err(|e| VerificationError::InclusionProofFailed { reason: e.to_string() })
}

/// Verify checkpoint signature
///
/// STEP 3 of verification algorithm:
/// Verifies the Ed25519 signature on the checkpoint using the trusted public key.
fn verify_checkpoint_signature(
    checkpoint: &crate::core::checkpoint::CheckpointJson,
    verifier: &CheckpointVerifier,
) -> Result<bool, VerificationError> {
    use crate::core::checkpoint::{Checkpoint, parse_signature};

    // Build Checkpoint from CheckpointJson
    let origin = parse_hash(&checkpoint.origin).map_err(|_| VerificationError::SignatureFailed)?;
    let root_hash =
        parse_hash(&checkpoint.root_hash).map_err(|_| VerificationError::SignatureFailed)?;
    let signature =
        parse_signature(&checkpoint.signature).map_err(|_| VerificationError::SignatureFailed)?;
    let key_id = parse_hash(&checkpoint.key_id).map_err(|_| VerificationError::SignatureFailed)?;

    let mut cp = Checkpoint::new(
        origin,
        checkpoint.tree_size,
        checkpoint.timestamp,
        root_hash,
        [0; 64],
        key_id,
    );
    cp.signature = signature;

    // Verify signature
    cp.verify(verifier).map(|()| true).map_err(|_| VerificationError::SignatureFailed)
}

/// Verify a single anchor
///
/// STEP 4 of verification algorithm:
/// Verifies RFC 3161 timestamp tokens cryptographically.
/// Bitcoin anchors still use basic presence check (requires online verification).
fn verify_anchor(anchor: &ReceiptAnchor, expected_root: &[u8; 32]) -> AnchorVerificationResult {
    match anchor {
        ReceiptAnchor::Rfc3161 { timestamp, token_der } => {
            verify_rfc3161_anchor_impl(timestamp, token_der, expected_root)
        }
        ReceiptAnchor::BitcoinOts { bitcoin_block_height, .. } => AnchorVerificationResult {
            anchor_type: "bitcoin_ots".to_string(),
            is_valid: true,
            timestamp: Some(*bitcoin_block_height),
            error: None,
        },
    }
}

/// Verify RFC 3161 anchor implementation (with feature flag)
#[cfg(feature = "rfc3161-verify")]
fn verify_rfc3161_anchor_impl(
    timestamp: &str,
    token_der: &str,
    expected_root: &[u8; 32],
) -> AnchorVerificationResult {
    let parsed = match parse_rfc3161_token(token_der) {
        Ok(p) => p,
        Err(e) => {
            return AnchorVerificationResult {
                anchor_type: "rfc3161".to_string(),
                is_valid: false,
                timestamp: parse_iso8601_to_nanos(timestamp),
                error: Some(e.to_string()),
            };
        }
    };

    match verify_rfc3161_hash(&parsed, expected_root) {
        Ok(result) => {
            let ts = result.gen_time.or_else(|| parse_iso8601_to_nanos(timestamp));
            AnchorVerificationResult {
                anchor_type: "rfc3161".to_string(),
                is_valid: true,
                timestamp: ts,
                error: None,
            }
        }
        Err(e) => AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            is_valid: false,
            timestamp: parse_iso8601_to_nanos(timestamp),
            error: Some(e.to_string()),
        },
    }
}

/// Verify RFC 3161 anchor implementation (without feature flag)
#[cfg(not(feature = "rfc3161-verify"))]
fn verify_rfc3161_anchor_impl(
    timestamp: &str,
    _token_der: &str,
    _expected_root: &[u8; 32],
) -> AnchorVerificationResult {
    AnchorVerificationResult {
        anchor_type: "rfc3161".to_string(),
        is_valid: false,
        timestamp: parse_iso8601_to_nanos(timestamp),
        error: Some("RFC 3161 verification requires 'rfc3161-verify' feature".to_string()),
    }
}

/// Days in each month (non-leap year)
const DAYS_IN_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Parse ISO 8601 timestamp to nanoseconds (simple implementation)
///
/// Supports basic format: `YYYY-MM-DDTHH:MM:SSZ`
///
/// Returns nanoseconds since Unix epoch (1970-01-01T00:00:00Z).
fn parse_iso8601_to_nanos(timestamp: &str) -> Option<u64> {
    // Expected format: YYYY-MM-DDTHH:MM:SSZ
    if timestamp.len() != 20 || !timestamp.ends_with('Z') {
        return None;
    }

    let parts: Vec<&str> = timestamp[..19].split('T').collect();
    if parts.len() != 2 {
        return None;
    }

    // Parse date part: YYYY-MM-DD
    let date_parts: Vec<&str> = parts[0].split('-').collect();
    if date_parts.len() != 3 {
        return None;
    }
    let year = date_parts[0].parse::<i32>().ok()?;
    let month = date_parts[1].parse::<u32>().ok()?;
    let day = date_parts[2].parse::<u32>().ok()?;

    // Parse time part: HH:MM:SS
    let time_parts: Vec<&str> = parts[1].split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hour = time_parts[0].parse::<u32>().ok()?;
    let minute = time_parts[1].parse::<u32>().ok()?;
    let second = time_parts[2].parse::<u32>().ok()?;

    // Validate ranges
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || hour >= 24
        || minute >= 60
        || second >= 60
    {
        return None;
    }

    // Validate day of month
    let max_day = if month == 2 && is_leap_year(year) {
        29
    } else {
        DAYS_IN_MONTH[usize::try_from(month - 1).ok()?]
    };
    if day < 1 || day > max_day {
        return None;
    }

    // Days since Unix epoch (1970-01-01)
    let days_since_epoch = days_since_unix_epoch(year, month, day)?;

    // Total seconds since epoch
    let total_seconds = u64::from(days_since_epoch) * 86400
        + u64::from(hour) * 3600
        + u64::from(minute) * 60
        + u64::from(second);

    // Convert to nanoseconds
    Some(total_seconds * 1_000_000_000)
}

/// Calculate days since Unix epoch (1970-01-01)
fn days_since_unix_epoch(year: i32, month: u32, day: u32) -> Option<u32> {
    // Calculate days from year 1970 to the given year
    let mut days = 0u32;

    // Add days for complete years
    for y in 1970..year {
        days = days.checked_add(if is_leap_year(y) { 366 } else { 365 })?;
    }

    // Add days for complete months in the given year
    for m in 1..month {
        let days_in_m = if m == 2 && is_leap_year(year) {
            29
        } else {
            DAYS_IN_MONTH[usize::try_from(m - 1).ok()?]
        };
        days = days.checked_add(days_in_m)?;
    }

    // Add remaining days
    days = days.checked_add(day - 1)?;

    Some(days)
}

/// Check if a year is a leap year
const fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

// ========== Convenience Functions ==========

/// Convenience function: verify a receipt with a public key
///
/// ## Arguments
///
/// * `receipt` - The receipt to verify
/// * `public_key` - Trusted Ed25519 public key (32 bytes)
///
/// ## Returns
///
/// `VerificationResult` with detailed status
///
/// ## Errors
///
/// Returns error if the public key is invalid.
pub fn verify_receipt(receipt: &Receipt, public_key: &[u8; 32]) -> AtlResult<VerificationResult> {
    let verifier = CheckpointVerifier::from_bytes(public_key)?;
    let receipt_verifier = ReceiptVerifier::new(verifier);
    Ok(receipt_verifier.verify(receipt))
}

/// Convenience function: verify receipt JSON with a public key
///
/// ## Arguments
///
/// * `json` - Receipt JSON string
/// * `public_key` - Trusted Ed25519 public key (32 bytes)
///
/// ## Errors
///
/// Returns error if JSON parsing or public key is invalid.
pub fn verify_receipt_json(json: &str, public_key: &[u8; 32]) -> AtlResult<VerificationResult> {
    let receipt = Receipt::from_json(json)?;
    verify_receipt(&receipt, public_key)
}

/// Verify just the inclusion proof (without signature)
///
/// Useful for testing or when signature is verified separately.
///
/// ## Arguments
///
/// * `payload_hash` - SHA256 hash of the payload (32 bytes)
/// * `metadata` - Entry metadata (arbitrary JSON)
/// * `inclusion_path` - Sibling hashes along the path
/// * `leaf_index` - Index of the leaf in the tree
/// * `tree_size` - Size of the tree
/// * `expected_root` - Expected root hash (32 bytes)
///
/// ## Returns
///
/// `true` if the inclusion proof is valid, `false` otherwise.
#[must_use]
pub fn verify_inclusion_only(
    payload_hash: &[u8; 32],
    metadata: &serde_json::Value,
    inclusion_path: &[[u8; 32]],
    leaf_index: u64,
    tree_size: u64,
    expected_root: &[u8; 32],
) -> bool {
    // Compute metadata hash
    let metadata_hash = canonicalize_and_hash(metadata);

    // Compute leaf hash
    let leaf_hash = compute_leaf_hash(payload_hash, &metadata_hash);

    // Create inclusion proof
    let proof = InclusionProof { leaf_index, tree_size, path: inclusion_path.to_vec() };

    // Verify
    verify_inclusion(&leaf_hash, &proof, expected_root).unwrap_or(false)
}

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::checkpoint::Checkpoint;
    use crate::core::checkpoint::CheckpointJson;
    use crate::core::receipt::{
        Receipt, ReceiptEntry, ReceiptProof, format_hash, format_signature,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use uuid::Uuid;

    /// Create a valid test receipt with proper signatures
    fn create_test_receipt() -> (Receipt, [u8; 32], SigningKey) {
        // Generate signing key
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let verifier = CheckpointVerifier::new(verifying_key);

        // Create entry
        let payload_hash = [0xAAu8; 32];
        let metadata = json!({"test": "metadata"});
        let metadata_hash = canonicalize_and_hash(&metadata);
        let leaf_hash = compute_leaf_hash(&payload_hash, &metadata_hash);

        // Single leaf tree: root = leaf
        let root_hash = leaf_hash;

        // Create checkpoint
        let origin = [0xBBu8; 32];
        let tree_size = 1u64;
        let timestamp = 1_234_567_890u64;

        let mut checkpoint =
            Checkpoint::new(origin, tree_size, timestamp, root_hash, [0u8; 64], verifier.key_id());

        // Sign checkpoint
        let blob = checkpoint.to_bytes();
        let signature = signing_key.sign(&blob);
        checkpoint.signature = signature.to_bytes();

        // Create receipt
        let receipt = Receipt {
            spec_version: "1.0.0".to_string(),
            entry: ReceiptEntry {
                id: Uuid::nil(),
                payload_hash: format_hash(&payload_hash),
                metadata,
            },
            proof: ReceiptProof {
                leaf_index: 0,
                tree_size: 1,
                root_hash: format_hash(&root_hash),
                inclusion_path: vec![], // Empty for single leaf
                checkpoint: CheckpointJson {
                    origin: format_hash(&origin),
                    tree_size,
                    root_hash: format_hash(&root_hash),
                    timestamp,
                    signature: format_signature(&checkpoint.signature),
                    key_id: format_hash(&verifier.key_id()),
                },
                consistency_proof: None,
            },
            anchors: vec![],
        };

        (receipt, verifying_key.to_bytes(), signing_key)
    }

    #[test]
    fn test_valid_receipt_passes() {
        let (receipt, public_key, _) = create_test_receipt();
        let result = verify_receipt(&receipt, &public_key).unwrap();

        assert!(result.is_valid);
        assert!(result.inclusion_valid);
        assert!(result.signature_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_tampered_payload_hash_fails() {
        let (mut receipt, public_key, _) = create_test_receipt();
        receipt.entry.payload_hash = format_hash(&[0xFFu8; 32]);

        let result = verify_receipt(&receipt, &public_key).unwrap();

        assert!(!result.is_valid);
        assert!(!result.inclusion_valid);
    }

    #[test]
    fn test_tampered_metadata_fails() {
        let (mut receipt, public_key, _) = create_test_receipt();
        receipt.entry.metadata = json!({"tampered": true});

        let result = verify_receipt(&receipt, &public_key).unwrap();

        assert!(!result.is_valid);
        assert!(!result.inclusion_valid);
    }

    #[test]
    fn test_tampered_signature_fails() {
        let (mut receipt, public_key, _) = create_test_receipt();

        // Tamper with signature
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0] = 0xFF;
        receipt.proof.checkpoint.signature = format_signature(&sig_bytes);

        let result = verify_receipt(&receipt, &public_key).unwrap();

        assert!(!result.is_valid);
        assert!(!result.signature_valid);
    }

    #[test]
    fn test_wrong_public_key_fails() {
        let (receipt, _, _) = create_test_receipt();
        let wrong_key = [99u8; 32];

        let result = verify_receipt(&receipt, &wrong_key);

        // Should fail at key_id mismatch or signature verification
        assert!(result.is_err() || !result.unwrap().is_valid());
    }

    #[test]
    fn test_root_hash_mismatch_detected() {
        let (mut receipt, public_key, _) = create_test_receipt();
        receipt.proof.root_hash = format_hash(&[0xCCu8; 32]);
        // checkpoint.root_hash is different

        let result = verify_receipt(&receipt, &public_key).unwrap();

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| matches!(e, VerificationError::RootHashMismatch)));
    }

    #[test]
    fn test_tree_size_mismatch_detected() {
        let (mut receipt, public_key, _) = create_test_receipt();
        receipt.proof.tree_size = 999;
        // checkpoint.tree_size is different (1)

        let result = verify_receipt(&receipt, &public_key).unwrap();

        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| matches!(e, VerificationError::TreeSizeMismatch)));
    }

    #[test]
    fn test_verify_inclusion_only() {
        let payload_hash = [1u8; 32];
        let metadata = json!({"key": "value"});
        let metadata_hash = canonicalize_and_hash(&metadata);
        let leaf_hash = compute_leaf_hash(&payload_hash, &metadata_hash);

        // Single leaf tree: root = leaf
        let result = verify_inclusion_only(
            &payload_hash,
            &metadata,
            &[],        // empty path for single leaf
            0,          // leaf_index
            1,          // tree_size
            &leaf_hash, // root == leaf for single entry
        );

        assert!(result);
    }

    #[test]
    fn test_verification_result_methods() {
        let result = VerificationResult {
            is_valid: true,
            leaf_hash: [0; 32],
            root_hash: [0; 32],
            tree_size: 1,
            timestamp: 123_456,
            signature_valid: true,
            inclusion_valid: true,
            consistency_valid: None,
            anchor_results: vec![],
            errors: vec![],
        };

        assert!(result.is_valid());
        assert!(!result.has_valid_anchor());
        assert!(result.first_error().is_none());
        assert_eq!(result.errors().len(), 0);
    }

    #[test]
    fn test_verification_result_with_errors() {
        let result = VerificationResult {
            is_valid: false,
            leaf_hash: [0; 32],
            root_hash: [0; 32],
            tree_size: 1,
            timestamp: 123_456,
            signature_valid: false,
            inclusion_valid: false,
            consistency_valid: None,
            anchor_results: vec![],
            errors: vec![VerificationError::SignatureFailed],
        };

        assert!(!result.is_valid());
        assert!(result.first_error().is_some());
        assert_eq!(result.errors().len(), 1);
    }

    #[test]
    fn test_verification_result_with_anchors() {
        let mut result = VerificationResult {
            is_valid: true,
            leaf_hash: [0; 32],
            root_hash: [0; 32],
            tree_size: 1,
            timestamp: 123_456,
            signature_valid: true,
            inclusion_valid: true,
            consistency_valid: None,
            anchor_results: vec![],
            errors: vec![],
        };

        result.anchor_results.push(AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            is_valid: true,
            timestamp: Some(123_456),
            error: None,
        });

        assert!(result.has_valid_anchor());
    }

    #[test]
    fn test_receipt_verifier_with_options() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifier = CheckpointVerifier::new(signing_key.verifying_key());

        let options =
            VerifyOptions { skip_anchors: true, skip_consistency: true, min_valid_anchors: 0 };

        let receipt_verifier = ReceiptVerifier::with_options(verifier, options);
        assert!(receipt_verifier.options.skip_anchors);
    }

    #[test]
    fn test_verify_receipt_json() {
        let (receipt, public_key, _) = create_test_receipt();
        let json = receipt.to_json().unwrap();

        let result = verify_receipt_json(&json, &public_key).unwrap();
        assert!(result.is_valid);
    }

    #[test]
    fn test_invalid_json_returns_error() {
        let public_key = [42u8; 32];
        let result = verify_receipt_json("{invalid json", &public_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_reconstruct_leaf_hash() {
        let payload_hash = [0xAAu8; 32];
        let metadata = json!({"test": "value"});

        let payload_hash_str = format_hash(&payload_hash);
        let result = reconstruct_leaf_hash(&payload_hash_str, &metadata);

        assert!(result.is_ok());
        let leaf_hash = result.unwrap();
        assert_eq!(leaf_hash.len(), 32);
    }

    #[test]
    fn test_reconstruct_leaf_hash_invalid_format() {
        let metadata = json!({"test": "value"});
        let result = reconstruct_leaf_hash("invalid_hash", &metadata);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_anchor_rfc3161() {
        let anchor = ReceiptAnchor::Rfc3161 {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            token_der: "base64:token".to_string(),
        };
        let root_hash = [0u8; 32];

        let result = verify_anchor(&anchor, &root_hash);
        assert_eq!(result.anchor_type, "rfc3161");

        #[cfg(feature = "rfc3161-verify")]
        {
            assert!(!result.is_valid);
            assert!(result.error.is_some());
        }

        #[cfg(not(feature = "rfc3161-verify"))]
        {
            assert!(!result.is_valid);
            assert_eq!(
                result.error.as_deref(),
                Some("RFC 3161 verification requires 'rfc3161-verify' feature")
            );
        }
    }

    #[test]
    fn test_verify_anchor_bitcoin() {
        let anchor = ReceiptAnchor::BitcoinOts {
            bitcoin_block_height: 700_000,
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            ots_proof: "base64:proof".to_string(),
        };
        let root_hash = [0u8; 32];

        let result = verify_anchor(&anchor, &root_hash);
        assert_eq!(result.anchor_type, "bitcoin_ots");
        assert!(result.is_valid); // Basic presence check
    }

    #[test]
    fn test_parse_iso8601_to_nanos_valid() {
        // Unix epoch
        assert_eq!(parse_iso8601_to_nanos("1970-01-01T00:00:00Z"), Some(0));

        // Example timestamp: 2026-01-15T10:31:00Z
        assert_eq!(
            parse_iso8601_to_nanos("2026-01-15T10:31:00Z"),
            Some(1_768_473_060 * 1_000_000_000)
        );

        // Leap year test: 2024-02-29T12:00:00Z
        assert_eq!(
            parse_iso8601_to_nanos("2024-02-29T12:00:00Z"),
            Some(1_709_208_000 * 1_000_000_000)
        );
    }

    #[test]
    fn test_parse_iso8601_to_nanos_invalid() {
        // Invalid format
        assert_eq!(parse_iso8601_to_nanos("2026-01-15"), None);
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T10:31:00"), None); // Missing Z
        assert_eq!(parse_iso8601_to_nanos("invalid"), None);

        // Invalid date
        assert_eq!(parse_iso8601_to_nanos("2026-13-01T00:00:00Z"), None); // Month 13
        assert_eq!(parse_iso8601_to_nanos("2026-02-30T00:00:00Z"), None); // Feb 30
        assert_eq!(parse_iso8601_to_nanos("1969-01-01T00:00:00Z"), None); // Before epoch

        // Invalid time
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T25:00:00Z"), None); // Hour 25
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T10:60:00Z"), None); // Minute 60
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T10:31:60Z"), None); // Second 60
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap_year(2000)); // Divisible by 400
        assert!(is_leap_year(2024)); // Divisible by 4, not by 100
        assert!(!is_leap_year(1900)); // Divisible by 100, not by 400
        assert!(!is_leap_year(2023)); // Not divisible by 4
    }

    #[test]
    fn test_days_since_unix_epoch() {
        // 1970-01-01
        assert_eq!(days_since_unix_epoch(1970, 1, 1), Some(0));

        // 1970-01-02
        assert_eq!(days_since_unix_epoch(1970, 1, 2), Some(1));

        // 1971-01-01 (365 days after epoch)
        assert_eq!(days_since_unix_epoch(1971, 1, 1), Some(365));

        // 2000-01-01 (leap years: 1972, 1976, ..., 1996; non-leap: 1900, 2100)
        // 30 years * 365 + 7 leap years (1972-1996) = 10957 days
        assert_eq!(days_since_unix_epoch(2000, 1, 1), Some(10957));
    }

    #[test]
    fn test_verify_inclusion_only_zero_tree_size() {
        let payload_hash = [1u8; 32];
        let metadata = json!({"key": "value"});

        // Zero tree size should return false (not panic)
        let result = verify_inclusion_only(
            &payload_hash,
            &metadata,
            &[],
            0,
            0, // Invalid tree size
            &[0u8; 32],
        );
        assert!(!result);
    }

    #[test]
    fn test_verify_inclusion_only_index_out_of_bounds() {
        let payload_hash = [1u8; 32];
        let metadata = json!({"key": "value"});

        // Index >= tree_size should return false
        let result = verify_inclusion_only(
            &payload_hash,
            &metadata,
            &[],
            10, // Index
            5,  // Tree size (index >= size)
            &[0u8; 32],
        );
        assert!(!result);
    }

    #[test]
    fn test_verify_inclusion_proof_invalid_structure() {
        let proof = ReceiptProof {
            leaf_index: 0,
            tree_size: 0, // Invalid!
            root_hash: format_hash(&[0u8; 32]),
            inclusion_path: vec![],
            checkpoint: CheckpointJson {
                origin: format_hash(&[0u8; 32]),
                tree_size: 0,
                root_hash: format_hash(&[0u8; 32]),
                timestamp: 0,
                signature: format_signature(&[0u8; 64]),
                key_id: format_hash(&[0u8; 32]),
            },
            consistency_proof: None,
        };

        let leaf_hash = [0u8; 32];
        let result = verify_inclusion_proof(&leaf_hash, &proof);

        // Should return Err, not panic
        assert!(matches!(result, Err(VerificationError::InclusionProofFailed { .. })));
    }
}

#[cfg(all(test, feature = "rfc3161-verify"))]
mod rfc3161_tests {
    use super::*;

    const FREETSA_TOKEN: &str = "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";

    const FREETSA_HASH: [u8; 32] = [
        0xe2, 0x36, 0x1b, 0x40, 0x53, 0xa9, 0x45, 0xdd, 0x1d, 0x24, 0x1a, 0x6c, 0x87, 0xda, 0xd7,
        0x98, 0xb7, 0xfd, 0x74, 0x50, 0x61, 0x4b, 0x81, 0x5a, 0x2d, 0x94, 0x72, 0x83, 0xed, 0x35,
        0x94, 0x52,
    ];

    #[test]
    fn test_parse_real_freetsa_token() {
        let token = format!("base64:{}", FREETSA_TOKEN);
        let result = parse_rfc3161_token(&token);
        assert!(result.is_ok(), "Should parse real FreeTSA token: {:?}", result.err());
    }

    #[test]
    fn test_verify_real_freetsa_token_valid_hash() {
        let token = format!("base64:{}", FREETSA_TOKEN);
        let parsed = parse_rfc3161_token(&token).expect("Failed to parse token");
        let result = verify_rfc3161_hash(&parsed, &FREETSA_HASH);
        assert!(result.is_ok(), "Should verify with correct hash: {:?}", result.err());
        assert!(result.unwrap().hash_valid, "Hash should be valid");
    }

    #[test]
    fn test_verify_real_freetsa_token_wrong_hash() {
        let token = format!("base64:{}", FREETSA_TOKEN);
        let parsed = parse_rfc3161_token(&token).expect("Failed to parse token");
        let wrong_hash = [0xFF; 32];
        let result = verify_rfc3161_hash(&parsed, &wrong_hash);
        assert!(
            matches!(result, Err(crate::error::AtlError::Rfc3161HashMismatch { .. })),
            "Should fail with hash mismatch error"
        );
    }

    #[test]
    fn test_extract_gentime_from_real_token() {
        let token = format!("base64:{}", FREETSA_TOKEN);
        let parsed = parse_rfc3161_token(&token).expect("Failed to parse token");
        let gen_time = extract_gen_time_nanos(&parsed.tst_info);
        assert!(gen_time.is_some(), "Should extract genTime");

        let nanos = gen_time.unwrap();
        assert!(nanos > 1704067200_000_000_000, "Timestamp should be after 2024-01-01");
    }

    #[test]
    fn test_verify_rfc3161_anchor_integration() {
        let timestamp = "2026-01-04T21:57:43Z";
        let token = format!("base64:{}", FREETSA_TOKEN);

        let result = verify_rfc3161_anchor_impl(timestamp, &token, &FREETSA_HASH);

        assert_eq!(result.anchor_type, "rfc3161");
        assert!(result.is_valid, "Anchor should be valid with correct hash");
        assert!(result.timestamp.is_some(), "Should have timestamp");
        assert!(result.error.is_none(), "Should have no error");
    }

    #[test]
    fn test_rfc3161_missing_base64_prefix() {
        let result = parse_rfc3161_token("MIIKvAYJKoZ...");
        assert!(matches!(result, Err(crate::error::AtlError::Rfc3161ParseError(_))));
    }

    #[test]
    fn test_rfc3161_invalid_base64() {
        let result = parse_rfc3161_token("base64:!!!invalid!!!");
        assert!(matches!(result, Err(crate::error::AtlError::Rfc3161ParseError(_))));
    }

    #[test]
    fn test_rfc3161_empty_base64() {
        let result = parse_rfc3161_token("base64:");
        assert!(matches!(result, Err(crate::error::AtlError::Rfc3161ParseError(_))));
    }

    #[test]
    fn test_rfc3161_invalid_der_random_bytes() {
        use base64::Engine;
        let random = base64::engine::general_purpose::STANDARD.encode(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let result = parse_rfc3161_token(&format!("base64:{}", random));
        assert!(matches!(result, Err(crate::error::AtlError::Rfc3161ParseError(_))));
    }

    #[test]
    fn test_rfc3161_truncated_der() {
        use base64::Engine;
        let truncated = base64::engine::general_purpose::STANDARD.encode(&[0x30, 0x82, 0x0A, 0x7C]);
        let result = parse_rfc3161_token(&format!("base64:{}", truncated));
        assert!(matches!(result, Err(crate::error::AtlError::Rfc3161ParseError(_))));
    }

    #[test]
    fn test_rfc3161_token_too_large() {
        use base64::Engine;
        let huge = base64::engine::general_purpose::STANDARD.encode(&vec![0x30; 100_000]);
        let result = parse_rfc3161_token(&format!("base64:{}", huge));
        assert!(result.is_err());
    }

    #[test]
    fn test_rfc3161_no_panic_on_arbitrary_input() {
        let inputs =
            ["", "base64:", "base64:A", "base64:AAAA", "base64:////////////", "notbase64:AAAA"];

        for input in inputs {
            let result = std::panic::catch_unwind(|| {
                let _ = parse_rfc3161_token(input);
            });
            assert!(result.is_ok(), "Panicked on input: {}", input);
        }
    }
}

#[cfg(all(test, not(feature = "rfc3161-verify")))]
mod rfc3161_feature_disabled_tests {
    use super::*;

    #[test]
    fn test_rfc3161_feature_disabled() {
        let anchor = ReceiptAnchor::Rfc3161 {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            token_der: "base64:AAAA".to_string(),
        };
        let result = verify_anchor(&anchor, &[0u8; 32]);
        assert!(!result.is_valid);
        assert!(result.error.as_ref().unwrap().contains("feature"));
    }
}
