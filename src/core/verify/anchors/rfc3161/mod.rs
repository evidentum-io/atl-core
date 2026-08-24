//! RFC 3161 Time-Stamp Protocol (TSA) verification
//!
//! This module verifies RFC 3161 timestamp tokens end to end: parsing,
//! `MessageImprint` hash verification, **CMS `SignerInfo` signature
//! verification**, **X.509 certificate chain construction and validation**,
//! and Extended Key Usage checking. It returns *facts*, not a verdict --
//! see [`Rfc3161AnchorFacts`].
//!
//! ## Trust
//!
//! This crate ships no identities. Trust material (anchor certificates,
//! SPKI pins, extra intermediates) is supplied by the caller through
//! [`TrustStore`], obtained via some channel this crate has no opinion
//! about. Without one, the best any token can achieve is
//! [`TerminalAnchor::Assumed`] -- the chain is cryptographically and
//! structurally sound, but nobody vouches for its root.
//!
//! ## Algorithms
//!
//! RSA PKCS#1 v1.5 (bare `rsaEncryption` and composite
//! `shaNNNWithRSAEncryption` OIDs) with SHA-256/384/512, and ECDSA on
//! P-384/P-256. See [`algorithms`] for the exact OID-resolution rules.
//!
//! ## Pure Rust, no OpenSSL
//!
//! `atl-core` sets `#![forbid(unsafe_code)]`, which rules out OpenSSL FFI.
//! This module is built entirely on the RustCrypto `formats`
//! (`der`/`spki`/`const-oid`/`x509-cert`/`cms`/`x509-tsp`) and `signatures`
//! (`rsa`/`ecdsa`/`p384`/`p256`) ecosystems.

mod algorithms;
mod chain;
mod cms_verify;
mod ess;
mod result;
mod trust_store;

pub use result::{
    PathStatus, Revocation, Rfc3161AnchorFacts, Sha256Digest, SignerFacts, TerminalAnchor,
};
pub use trust_store::TrustStore;

use der::{Decode, Encode};
use x509_cert::Certificate;

use super::super::AnchorVerificationResult;
use crate::error::{AtlError, AtlResult};

/// Maximum allowed size for a timestamp token (64KB). Bounds parsing cost
/// and certificate-chain search space against adversarial input.
const MAX_TOKEN_SIZE: usize = 65536;

/// OID for SHA-256 hash algorithm: 2.16.840.1.101.3.4.2.1
const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";

/// A parsed RFC 3161 timestamp token: the decoded CMS structures plus the
/// raw bytes of the encapsulated `TSTInfo` content (needed, byte for byte,
/// to verify the `message-digest` signed attribute).
pub struct ParsedTimestampToken {
    /// The outer CMS `SignedData` structure.
    pub signed_data: cms::signed_data::SignedData,
    /// Decoded `TSTInfo` structure.
    pub tst_info: x509_tsp::TstInfo,
    /// Raw DER-encoded `TSTInfo` bytes (the `eContent` OCTET STRING's
    /// contents, exactly as encoded).
    pub raw_tst_info: Vec<u8>,
}

/// Result of RFC 3161 `MessageImprint` hash verification.
pub struct Rfc3161VerifyResult {
    /// Whether the hash comparison succeeded.
    pub hash_valid: bool,
    /// OID of the hash algorithm used in the token.
    pub algorithm_oid: String,
    /// Hex-encoded hash value from the token.
    pub token_hash: String,
    /// Generation time from token (nanoseconds since Unix epoch).
    pub gen_time: Option<u64>,
}

/// Parse an RFC 3161 timestamp token from base64-encoded DER.
///
/// Decodes a timestamp token in the format `"base64:..."`, verifies it is a
/// CMS `SignedData` wrapping a `TSTInfo`, and returns both.
///
/// ## Errors
///
/// Returns [`AtlError::Rfc3161ParseError`] if the token does not have the
/// `"base64:"` prefix, base64 decoding fails, the token exceeds
/// [`MAX_TOKEN_SIZE`], or any of the CMS `ContentInfo`/`SignedData`/`TSTInfo`
/// structures fail to decode.
pub fn parse_rfc3161_token(token_der: &str) -> AtlResult<ParsedTimestampToken> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use const_oid::db::rfc5911::ID_SIGNED_DATA;

    let token_b64 = token_der
        .strip_prefix("base64:")
        .ok_or_else(|| AtlError::Rfc3161ParseError("missing base64: prefix".to_string()))?;

    let token_bytes = STANDARD
        .decode(token_b64)
        .map_err(|e| AtlError::Rfc3161ParseError(format!("base64 decode failed: {e}")))?;

    if token_bytes.len() > MAX_TOKEN_SIZE {
        return Err(AtlError::Rfc3161ParseError(format!(
            "token size {} exceeds maximum {MAX_TOKEN_SIZE}",
            token_bytes.len(),
        )));
    }

    let content_info = ContentInfo::from_der(&token_bytes)
        .map_err(|e| AtlError::Rfc3161ParseError(format!("CMS ContentInfo parse failed: {e}")))?;

    if content_info.content_type != ID_SIGNED_DATA {
        return Err(AtlError::Rfc3161ParseError(format!(
            "expected id-signedData content type, got {}",
            content_info.content_type
        )));
    }

    let signed_data_der = content_info
        .content
        .to_der()
        .map_err(|e| AtlError::Rfc3161ParseError(format!("re-encoding content failed: {e}")))?;
    let signed_data = SignedData::from_der(&signed_data_der)
        .map_err(|e| AtlError::Rfc3161ParseError(format!("CMS SignedData parse failed: {e}")))?;

    let econtent = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| AtlError::Rfc3161ParseError("no encapsulated content".to_string()))?;

    // eContent is `[0] EXPLICIT OCTET STRING`; `econtent` here is the `Any`
    // holding that OCTET STRING, so decode one layer to get its raw bytes.
    let raw_tst_info: Vec<u8> = econtent
        .decode_as::<der::asn1::OctetString>()
        .map_err(|e| AtlError::Rfc3161ParseError(format!("eContent is not an OCTET STRING: {e}")))?
        .into_bytes();

    let tst_info = x509_tsp::TstInfo::from_der(&raw_tst_info)
        .map_err(|e| AtlError::Rfc3161ParseError(format!("TSTInfo decode failed: {e}")))?;

    Ok(ParsedTimestampToken { signed_data, tst_info, raw_tst_info })
}

/// Verify RFC 3161 `MessageImprint` against an expected root hash.
///
/// Extracts the `MessageImprint` from the parsed token and verifies the
/// hash algorithm is SHA-256 and the hash value matches `expected_root`.
///
/// ## Errors
///
/// Returns [`AtlError::Rfc3161UnsupportedAlgorithm`] if the hash algorithm
/// is not SHA-256, [`AtlError::Rfc3161ParseError`] if the hash length is
/// wrong, or [`AtlError::Rfc3161HashMismatch`] if the hash does not match.
pub fn verify_rfc3161_hash(
    parsed: &ParsedTimestampToken,
    expected_root: &[u8; 32],
) -> AtlResult<Rfc3161VerifyResult> {
    use subtle::ConstantTimeEq;

    let message_imprint = &parsed.tst_info.message_imprint;

    let algo_oid = message_imprint.hash_algorithm.oid.to_string();
    if algo_oid != SHA256_OID {
        return Err(AtlError::Rfc3161UnsupportedAlgorithm(format!(
            "expected SHA-256 ({SHA256_OID}), got {algo_oid}"
        )));
    }

    let token_hash_bytes = message_imprint.hashed_message.as_bytes();
    if token_hash_bytes.len() != 32 {
        return Err(AtlError::Rfc3161ParseError(format!(
            "invalid hash length: expected 32 bytes, got {}",
            token_hash_bytes.len()
        )));
    }

    let mut token_hash_array = [0u8; 32];
    token_hash_array.copy_from_slice(token_hash_bytes);

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

/// Extract generation time from `TSTInfo`, as nanoseconds since the Unix
/// epoch.
///
/// Returns `None` if the timestamp is outside the range representable as
/// `u64` nanoseconds since epoch (year ~2554 and beyond).
#[must_use]
pub fn extract_gen_time_nanos(tst_info: &x509_tsp::TstInfo) -> Option<u64> {
    let seconds = tst_info.gen_time.to_unix_duration().as_secs();
    seconds.checked_mul(1_000_000_000)
}

/// Verify an RFC 3161 timestamp token against an expected root hash and
/// (optionally) caller-supplied trust material.
///
/// This is the complete, honest verification: `MessageImprint` matching,
/// CMS `SignerInfo` signature verification (content-type, message-digest,
/// ESS signing-certificate binding, cryptographic signature), certificate
/// chain construction and validation *at `genTime`*, and Extended Key Usage
/// checking. See [`Rfc3161AnchorFacts`] for exactly what is and is not
/// asserted, and [`TrustStore`] for how to supply trust material -- without
/// one, `terminal_anchor` can be `Assumed` at best, never `Trusted`.
///
/// ## Errors
///
/// Returns [`AtlError::Rfc3161ParseError`] only for hard structural parse
/// failures (the token cannot even be decoded as CMS `SignedData` wrapping
/// a `TSTInfo`). Everything downstream of a successful parse -- a missing
/// signer certificate, a broken chain, an algorithm this crate does not
/// implement -- is reported as facts inside `Ok(_)`, never as `Err`.
pub fn verify_rfc3161_token(
    token_der: &str,
    expected_root: &[u8; 32],
    trust_store: Option<&TrustStore>,
) -> AtlResult<Rfc3161AnchorFacts> {
    let parsed = parse_rfc3161_token(token_der)?;
    Ok(verify_parsed_token(&parsed, expected_root, trust_store))
}

fn verify_parsed_token(
    parsed: &ParsedTimestampToken,
    expected_root: &[u8; 32],
    trust_store: Option<&TrustStore>,
) -> Rfc3161AnchorFacts {
    let empty_store = TrustStore::new();
    let trust_store = trust_store.unwrap_or(&empty_store);

    let imprint_matches_root = verify_rfc3161_hash(parsed, expected_root).is_ok();
    let gen_time_nanos = extract_gen_time_nanos(&parsed.tst_info);

    let certificates: Vec<Certificate> = parsed
        .signed_data
        .certificates
        .iter()
        .flat_map(|set| set.0.iter())
        .filter_map(|choice| match choice {
            cms::cert::CertificateChoices::Certificate(cert) => Some(cert.clone()),
            cms::cert::CertificateChoices::Other(_) => None,
        })
        .collect();

    let signer_infos = parsed.signed_data.signer_infos.0.as_slice();
    if signer_infos.len() != 1 {
        return facts_with_diagnostic(
            gen_time_nanos,
            imprint_matches_root,
            format!("expected exactly one SignerInfo, found {}", signer_infos.len()),
        );
    }
    let signer_info = &signer_infos[0];

    let Some(signer_cert) = chain::find_signer_certificate(&certificates, &signer_info.sid) else {
        return facts_with_diagnostic(
            gen_time_nanos,
            imprint_matches_root,
            "signer certificate (per SignerInfo.sid) not found in token's certificate set"
                .to_string(),
        );
    };

    let econtent_type = parsed.signed_data.encap_content_info.econtent_type;
    let cms_result = cms_verify::verify_signer_info(
        signer_info,
        signer_cert,
        econtent_type,
        &parsed.raw_tst_info,
    );
    let cms_signature_valid = cms_result.is_ok();

    let timestamping_eku_ok = chain::check_timestamping_eku(signer_cert);

    let signer = build_signer_facts(signer_cert);

    let (path_status, terminal_anchor, chain_valid_at_gen_time) = match gen_time_nanos {
        Some(nanos) => {
            let gen_time = std::time::Duration::from_nanos(nanos);
            let chain_result =
                chain::verify_chain(signer_cert, gen_time, &certificates, trust_store);
            (chain_result.status, chain_result.terminal, chain_result.chain_valid_at_gen_time)
        }
        None => (PathStatus::Incomplete, None, false),
    };

    let diagnostic =
        if cms_signature_valid { None } else { cms_result.err().map(|e| e.to_string()) };

    Rfc3161AnchorFacts {
        imprint_matches_root,
        cms_signature_valid,
        chain_valid_at_gen_time,
        timestamping_eku_ok,
        gen_time: gen_time_nanos,
        signer,
        terminal_anchor,
        path_status,
        revocation: result::Revocation::NotChecked,
        diagnostic,
    }
}

fn facts_with_diagnostic(
    gen_time: Option<u64>,
    imprint_matches_root: bool,
    diagnostic: String,
) -> Rfc3161AnchorFacts {
    Rfc3161AnchorFacts {
        imprint_matches_root,
        cms_signature_valid: false,
        chain_valid_at_gen_time: false,
        timestamping_eku_ok: false,
        gen_time,
        signer: None,
        terminal_anchor: None,
        path_status: PathStatus::Invalid,
        revocation: result::Revocation::NotChecked,
        diagnostic: Some(diagnostic),
    }
}

fn build_signer_facts(cert: &Certificate) -> Option<SignerFacts> {
    let spki_sha256 = chain::cert_spki_sha256(cert)?;
    Some(SignerFacts {
        subject: cert.tbs_certificate.subject.to_string(),
        issuer: cert.tbs_certificate.issuer.to_string(),
        serial_hex: hex::encode_upper(cert.tbs_certificate.serial_number.as_bytes()),
        spki_sha256,
    })
}

/// Verify an RFC 3161 anchor and adapt the result into the crate's generic
/// [`AnchorVerificationResult`] shape used by the receipt-level verifier.
///
/// This is a **backwards-compatible adapter**, not the primary API: it
/// collapses [`Rfc3161AnchorFacts`] down to a single `is_valid: bool` via
/// [`Rfc3161AnchorFacts::is_fully_valid`], which is `false` whenever
/// `trust_store` is `None` (there being no `TrustStore` plumbed through the
/// receipt-level `VerifyOptions` yet -- callers who need `Trusted` anchoring
/// should call [`verify_rfc3161_token`] directly with a `TrustStore`).
#[must_use]
pub fn verify_rfc3161_anchor_impl(
    timestamp: &str,
    token_der: &str,
    expected_root: &[u8; 32],
) -> AnchorVerificationResult {
    use super::super::iso8601::parse_iso8601_to_nanos;

    match verify_rfc3161_token(token_der, expected_root, None) {
        Ok(facts) => {
            let ts = facts.gen_time.or_else(|| parse_iso8601_to_nanos(timestamp));
            let error = if facts.is_fully_valid() { None } else { Some(summarize(&facts)) };
            AnchorVerificationResult {
                anchor_type: "rfc3161".to_string(),
                is_valid: facts.is_fully_valid(),
                timestamp: ts,
                error,
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

/// Render a compact human-readable summary of why `facts` did not reach
/// full aggregate success, for [`AnchorVerificationResult::error`].
fn summarize(facts: &Rfc3161AnchorFacts) -> String {
    let mut reasons = Vec::new();
    if !facts.imprint_matches_root {
        reasons.push("messageImprint mismatch: does not match expected root".to_string());
    }
    if !facts.cms_signature_valid {
        let detail = facts.diagnostic.as_deref().unwrap_or("CMS signature invalid");
        reasons.push(format!("CMS signature invalid: {detail}"));
    }
    if !facts.chain_valid_at_gen_time {
        reasons.push(format!("certificate chain invalid at genTime ({:?})", facts.path_status));
    }
    if !facts.timestamping_eku_ok {
        reasons
            .push("signer certificate lacks exclusive critical id-kp-timeStamping EKU".to_string());
    }
    match &facts.terminal_anchor {
        Some(TerminalAnchor::Assumed { sha256_fingerprint }) => {
            reasons.push(format!(
                "trust anchor not established: chain terminates in an unverified self-signed \
                 certificate (fingerprint {}); this NEVER counts as a valid anchor -- supply a \
                 TrustStore",
                hex::encode(sha256_fingerprint)
            ));
        }
        None => reasons.push("no terminal anchor reached".to_string()),
        Some(TerminalAnchor::Trusted { .. }) => {}
    }
    if reasons.is_empty() {
        "verification did not reach aggregate success".to_string()
    } else {
        reasons.join("; ")
    }
}
