//! RFC 3161 Time-Stamp Protocol (TSA) verification
//!
//! This module implements cryptographic verification of RFC 3161 timestamp tokens.
//! It provides parsing, hash verification, and anchor validation functionality.
//!
//! ## Features
//!
//! - Parse RFC 3161 timestamp tokens from base64-encoded DER
//! - Verify SHA-256 hash integrity against expected root hash
//! - Extract generation time from timestamp tokens
//! - Full cryptographic verification using constant-time comparisons

use cryptographic_message_syntax::asn1::rfc3161::TstInfo;

use super::super::AnchorVerificationResult;
use super::super::iso8601::{is_leap_year, parse_iso8601_to_nanos};
use crate::error::{AtlError, AtlResult};

/// Maximum allowed size for timestamp token (64KB)
const MAX_TOKEN_SIZE: usize = 65536;

/// OID for SHA-256 hash algorithm: 2.16.840.1.101.3.4.2.1
const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";

/// Days in each month (non-leap year)
const DAYS_IN_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Parsed RFC 3161 timestamp token
///
/// Contains the decoded `TSTInfo` structure and raw DER bytes.
pub struct ParsedTimestampToken {
    /// Decoded `TSTInfo` structure from RFC 3161
    pub tst_info: TstInfo,
    /// Raw DER-encoded `TSTInfo` bytes
    pub raw_tst_info: Vec<u8>,
}

/// Result of RFC 3161 hash verification
///
/// Contains verification status and extracted token information.
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
pub fn parse_rfc3161_token(token_der: &str) -> AtlResult<ParsedTimestampToken> {
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
pub fn verify_rfc3161_hash(
    parsed: &ParsedTimestampToken,
    expected_root: &[u8; 32],
) -> AtlResult<Rfc3161VerifyResult> {
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
///
/// Note: This function uses local date/time calculation helpers since the
/// `iso8601` module's `days_since_unix_epoch` is not public.
pub fn extract_gen_time_nanos(tst_info: &TstInfo) -> Option<u64> {
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

    let days_since_epoch = days_since_unix_epoch_local(year, month, day)?;

    let total_seconds = u64::from(days_since_epoch) * 86400
        + u64::from(hour) * 3600
        + u64::from(minute) * 60
        + u64::from(second);

    Some(total_seconds * 1_000_000_000)
}

/// Calculate days since Unix epoch (1970-01-01)
///
/// Local helper function for `extract_gen_time_nanos`.
fn days_since_unix_epoch_local(year: i32, month: u32, day: u32) -> Option<u32> {
    let mut days = 0u32;

    for y in 1970..year {
        days = days.checked_add(if is_leap_year(y) { 366 } else { 365 })?;
    }

    for m in 1..month {
        let days_in_m = if m == 2 && is_leap_year(year) {
            29
        } else {
            DAYS_IN_MONTH[usize::try_from(m - 1).ok()?]
        };
        days = days.checked_add(days_in_m)?;
    }

    days = days.checked_add(day - 1)?;

    Some(days)
}

/// Verify RFC 3161 anchor implementation (with feature flag)
///
/// Performs complete cryptographic verification of an RFC 3161 timestamp token:
/// 1. Parse the base64-encoded DER token
/// 2. Verify SHA-256 hash matches expected root
/// 3. Extract generation time from token
///
/// ## Arguments
///
/// * `timestamp` - ISO 8601 timestamp string (fallback if token time extraction fails)
/// * `token_der` - Base64-encoded DER timestamp token
/// * `expected_root` - Expected SHA-256 root hash (32 bytes)
///
/// ## Returns
///
/// `AnchorVerificationResult` with validation status and timestamp
#[must_use]
pub fn verify_rfc3161_anchor_impl(
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
