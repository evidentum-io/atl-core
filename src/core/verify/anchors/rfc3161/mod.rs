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
//! P-384/P-256. **Not implemented**: P-521, RSA-PSS. See [`algorithms`] for
//! the exact OID-resolution rules and what happens to an unsupported
//! algorithm (a clean rejection, not a silent mismatch).
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
    CmsSignature, MessageImprint, PathStatus, Revocation, Rfc3161AnchorFacts, SelfSignature,
    Sha256Digest, SignerFacts, TerminalAnchor, TimestampingEku,
};
pub use trust_store::TrustStore;

use der::{Decode, Encode};
use x509_cert::Certificate;

use super::super::AnchorVerificationResult;
use crate::error::{AtlError, AtlResult};

/// Maximum allowed size for a timestamp token (64KB). Bounds parsing cost
/// and certificate-chain search space against adversarial input.
const MAX_TOKEN_SIZE: usize = 65536;

/// Upper bound on per-candidate signer diagnostics. An adversarial
/// certificate set can hold many certificates sharing one `SignerInfo.sid`;
/// the prose exists for humans, and a handful says what a longer list would.
const MAX_SIGNER_DIAGNOSTICS: usize = 4;

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
    /// Whether the hash comparison succeeded. Always `true`: this struct is
    /// only produced on the success path, and a failed comparison is
    /// reported as [`AtlError::Rfc3161HashMismatch`] instead. Kept as an
    /// explicit field so the success is stated rather than implied.
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
/// ## A narrow `genTime` profile -- this is not full RFC 3161 support
///
/// RFC 3161's `TSTInfo.genTime` is a `GeneralizedTime`, and RFC 3161
/// explicitly permits (does not require) a fractional-seconds component on
/// it, with canonical constraints on how it's expressed. DER itself does
/// not forbid fractional seconds on `GeneralizedTime` -- the restriction
/// this module actually inherits is narrower and comes from one specific
/// dependency: the `der` crate's [`GeneralizedTime`](der::asn1::GeneralizedTime)
/// type implements the *PKIX* profile from RFC 5280 §4.1.2.5.2 ("GeneralizedTime
/// values MUST NOT include fractional seconds"), because that crate is built
/// primarily for X.509 certificates, not RFC 3161 tokens. This module reuses
/// that same type for `TSTInfo.genTime` rather than maintaining a second,
/// RFC-3161-flavored `GeneralizedTime` decoder, so it inherits the RFC 5280
/// restriction along with it -- a real deliberate trade-off (one decoder,
/// one dependency), but a genuine gap against the RFC 3161 grammar, not a
/// DER limitation. A token whose `genTime` carries fractional seconds is
/// rejected here as a consequence, and rejected cleanly: this function
/// returns [`AtlError::Rfc3161ParseError`] naming `GeneralizedTime` in the
/// message (via the underlying `TSTInfo decode failed: ...` wrapping), not a
/// panic or an opaque failure -- see `fractional_seconds_gen_time_is_rejected_cleanly`
/// in `rfc3161_adversarial_tests.rs` for a token exercising exactly this.
/// None of the tokens in this crate's real-world test corpus
/// (`rfc3161_corpus_tests.rs`) use fractional seconds; if a real TSA that
/// does turns up, supporting it (either a custom decoder for this one field,
/// or upstreaming RFC 3161 support to `der`) is a deliberate follow-up, not
/// a side effect of this module quietly claiming more RFC 3161 coverage than
/// it has.
///
/// ## Errors
///
/// Returns [`AtlError::Rfc3161ParseError`] if the token does not have the
/// `"base64:"` prefix, base64 decoding fails, the token exceeds
/// [`MAX_TOKEN_SIZE`], or any of the CMS `ContentInfo`/`SignedData`/`TSTInfo`
/// structures fail to decode (including a `genTime` with fractional
/// seconds; see above).
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

    let message_imprint = classify_message_imprint(&verify_rfc3161_hash(parsed, expected_root));
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
        // A checked structural fact is false: RFC 3161 admits exactly one
        // signer, and this crate never picks "the best" of several. A
        // refutation.
        return facts_with_diagnostic(
            gen_time_nanos,
            message_imprint,
            result::CmsSignature::Refuted,
            format!("expected exactly one SignerInfo, found {}", signer_infos.len()),
        );
    }
    let signer_info = &signer_infos[0];

    let econtent_type = parsed.signed_data.encap_content_info.econtent_type;
    let selection = select_signer(&certificates, signer_info, econtent_type, &parsed.raw_tst_info);
    let cms_signature = selection.cms_signature;

    // No established signer means no certificate whose EKU, identity or
    // certificate path may honestly be reported. Those fields describe "the
    // certificate that produced the CMS signature"; filling them from an
    // unverified candidate would put a falsehood in the type itself.
    let Some(signer_cert) = selection.certificate else {
        return facts_with_diagnostic(
            gen_time_nanos,
            message_imprint,
            cms_signature,
            selection.diagnostic.unwrap_or_else(|| {
                "no signer certificate could be established for this token".to_string()
            }),
        );
    };

    let timestamping_eku = chain::check_timestamping_eku(signer_cert);

    let signer = build_signer_facts(signer_cert);

    let (path_status, terminal_anchor, chain_valid_at_gen_time, chain_diagnostic) =
        match gen_time_nanos {
            Some(nanos) => {
                let gen_time = std::time::Duration::from_nanos(nanos);
                let chain_result =
                    chain::verify_chain(signer_cert, gen_time, &certificates, trust_store);
                (
                    chain_result.status,
                    chain_result.terminal,
                    chain_result.chain_valid_at_gen_time,
                    chain_result.diagnostic,
                )
            }
            // No usable `genTime` means certificate validity cannot be
            // evaluated at the only instant that matters, so the chain was
            // never examined at all -- an inability, not a refutation.
            None => (
                PathStatus::Indeterminate,
                None,
                false,
                Some(
                    "TSTInfo.genTime is not representable, so no certificate could be checked \
                     against it"
                        .to_string(),
                ),
            ),
        };

    let diagnostic = selection.diagnostic;

    Rfc3161AnchorFacts {
        message_imprint,
        cms_signature,
        chain_valid_at_gen_time,
        timestamping_eku_ok: timestamping_eku.is_ok(),
        timestamping_eku,
        gen_time: gen_time_nanos,
        signer,
        terminal_anchor,
        path_status,
        revocation: result::Revocation::NotChecked,
        diagnostic,
        chain_diagnostic,
    }
}

/// Which `MessageImprint` state a [`verify_rfc3161_hash`] outcome means.
///
/// The distinction that matters: an unrecognised hash algorithm means the
/// comparison **never happened**, so it cannot have "not matched". Reporting
/// it as a mismatch was a false public fact -- the token may be perfectly
/// good and merely use an algorithm this crate has not implemented.
///
/// An unrecognised error variant defaults to `Indeterminate`, not `Refuted`:
/// the safe direction for something this function does not understand is to
/// claim nothing, never to claim a refutation it cannot support.
fn classify_message_imprint(result: &AtlResult<Rfc3161VerifyResult>) -> result::MessageImprint {
    match result {
        Ok(_) => result::MessageImprint::Verified,
        // The algorithm is not implemented here, so no comparison was made.
        Err(AtlError::Rfc3161UnsupportedAlgorithm(_)) => result::MessageImprint::Indeterminate,
        // The comparison ran and the values differ.
        Err(AtlError::Rfc3161HashMismatch { .. }) => result::MessageImprint::Mismatch,
        // The imprint's own hash length contradicts the algorithm it names,
        // so no comparison could even be attempted. A checked fact coming
        // out false -- but a structural one, not a mismatch. Reporting it as
        // "does not match the expected root" would explain a proven defect
        // with a cause that is not true of it.
        Err(AtlError::Rfc3161ParseError(_)) => result::MessageImprint::Malformed,
        Err(_) => result::MessageImprint::Indeterminate,
    }
}

/// The outcome of deciding who signed this token.
struct SignerSelection<'a> {
    /// The **established** signer -- `Some` only when a candidate verified
    /// completely. Deliberately an `Option`: `SignerFacts`, the timestamping
    /// EKU and the certificate chain are all documented as facts about the
    /// certificate that *produced the CMS signature*, and publishing them
    /// for a candidate that failed verification would make the type itself
    /// lie. A footnote telling consumers to read `cms_signature` first does
    /// not repair that -- this whole rework exists to teach consumers to
    /// trust the facts, not the footnotes.
    certificate: Option<&'a Certificate>,
    cms_signature: result::CmsSignature,
    diagnostic: Option<String>,
}

/// Choose the CMS signer by **verification**, not by position in the
/// certificate set, and never over-claim when nothing verifies.
///
/// `SignerInfo.sid` names the signer by issuer+serial or by
/// `SubjectKeyIdentifier`, and neither is unique across a certificate set
/// that is not covered by the signature (RFC 5652 5.1). Taking the first
/// match let anyone drop a certificate carrying the real signer's issuer and
/// serial -- but a different key -- earlier into the set: that impostor was
/// selected, failed verification, and a wholly valid token was published as
/// **refuted evidence** while the genuine signer sat unexamined in the same
/// set.
///
/// # Why "every candidate failed" is not a refutation
///
/// The same unauthenticated set that lets an attacker *add* a certificate
/// lets them *remove* one. A token whose genuine signer certificate has been
/// deleted, leaving only a same-SID impostor, would -- if "all candidates
/// failed" meant `Refuted` -- be reported as disproved evidence, when in
/// truth its signature was never checked against anything. That is the same
/// over-claim as the absent-certificate case, which is already
/// `Indeterminate` because RFC 5652 5.1 permits the signer certificate to be
/// conveyed out of band. Two spellings of "we do not have the certificate"
/// must not produce opposite verdicts, so both are `Indeterminate`. The
/// diagnostic still records that candidates existed and how each failed.
///
/// # What can still be refuted
///
/// Everything checkable from `SignerInfo` and the encapsulated content --
/// `content-type`, `message-digest`, signed-attribute cardinality, the
/// presence of an ESS binding, CMS Algorithm Protection -- is
/// certificate-independent, so its failure *is* a property of the token
/// regardless of which certificate a caller might try. Those checks run once
/// up front (see [`cms_verify::verify_signed_attributes`]) and a failure
/// there is a genuine refutation. A tampered `message-digest` is therefore
/// still caught as forgery, not softened into "cannot tell".
fn select_signer<'a>(
    certificates: &'a [Certificate],
    signer_info: &'a cms::signed_data::SignerInfo,
    econtent_type: der::asn1::ObjectIdentifier,
    raw_tst_info: &[u8],
) -> SignerSelection<'a> {
    // Certificate-independent half: a failure here refutes the token itself.
    let signed_attrs =
        match cms_verify::verify_signed_attributes(signer_info, econtent_type, raw_tst_info) {
            Ok(attrs) => attrs,
            Err(err) => {
                return SignerSelection {
                    certificate: None,
                    cms_signature: cms_verify::classify(&err),
                    diagnostic: Some(err.to_string()),
                }
            }
        };

    // Certificate-dependent half: try every candidate; a failure means only
    // "not this certificate".
    let mut diagnostics: Vec<String> = Vec::new();
    // Counted separately from `diagnostics`, which is capped: reporting the
    // capped length as the number of candidates tried would understate what
    // was actually examined.
    let mut tried = 0usize;

    for candidate in chain::signer_certificate_candidates(certificates, &signer_info.sid) {
        match cms_verify::verify_signer_binding(signer_info, signed_attrs, candidate) {
            Ok(()) => {
                return SignerSelection {
                    certificate: Some(candidate),
                    cms_signature: result::CmsSignature::Verified,
                    diagnostic: None,
                }
            }
            Err(err) => {
                tried += 1;
                if diagnostics.len() < MAX_SIGNER_DIAGNOSTICS {
                    diagnostics.push(err.to_string());
                }
            }
        }
    }

    let diagnostic = if tried == 0 {
        "signer certificate (per SignerInfo.sid) not found in token's certificate set".to_string()
    } else {
        format!(
            "no certificate matching SignerInfo.sid verified ({tried} candidates tried, the \
             genuine signer may be absent from this unsigned certificate set): {}",
            diagnostics.join("; ")
        )
    };

    SignerSelection {
        certificate: None,
        cms_signature: result::CmsSignature::Indeterminate,
        diagnostic: Some(diagnostic),
    }
}

fn facts_with_diagnostic(
    gen_time: Option<u64>,
    message_imprint: result::MessageImprint,
    cms_signature: result::CmsSignature,
    diagnostic: String,
) -> Rfc3161AnchorFacts {
    Rfc3161AnchorFacts {
        message_imprint,
        cms_signature,
        chain_valid_at_gen_time: false,
        timestamping_eku_ok: false,
        // The EKU check never ran -- there is no settled signer certificate
        // to run it against. Saying `Absent` here would report a fact about
        // a certificate nobody looked at.
        timestamping_eku: result::TimestampingEku::NotChecked,
        gen_time,
        signer: None,
        terminal_anchor: None,
        // No signer certificate was established, so no certificate path was
        // ever explored -- not "we ran out of certificates" (`Incomplete`)
        // and certainly not "a path was checked and failed" (`Invalid`), but
        // "this was never evaluated". The refutation, when there is one,
        // lives in the CMS facts and in `diagnostic`.
        path_status: PathStatus::Indeterminate,
        revocation: result::Revocation::NotChecked,
        diagnostic: Some(diagnostic),
        chain_diagnostic: None,
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
/// This is an **adapter**, not the primary API: it collapses
/// [`Rfc3161AnchorFacts`] down to a single `is_valid: bool` via
/// [`Rfc3161AnchorFacts::is_fully_valid`], which is `false` whenever
/// `trust_store` is `None`. `TrustStore` *is* plumbed all the way through
/// the receipt-level `VerifyOptions` (see
/// `VerifyOptions::rfc3161_trust_store` and
/// `AnchorVerificationContext::with_rfc3161_trust_store`) -- callers going
/// through `ReceiptVerifier` get `Trusted` anchoring by configuring that
/// field; this function's `trust_store` parameter is exactly what
/// `helpers::verify_rfc3161_anchor` forwards from there. Calling
/// [`verify_rfc3161_token`] directly remains the richer option when the
/// full fact set (not just `is_valid`) is wanted.
#[must_use]
pub fn verify_rfc3161_anchor_impl(
    timestamp: &str,
    token_der: &str,
    expected_root: &[u8; 32],
    trust_store: Option<&TrustStore>,
) -> AnchorVerificationResult {
    use super::super::iso8601::parse_iso8601_to_nanos;

    match verify_rfc3161_token(token_der, expected_root, trust_store) {
        Ok(facts) => {
            let claimed = facts.gen_time.or_else(|| parse_iso8601_to_nanos(timestamp));
            let is_valid = facts.is_fully_valid();
            let error = if is_valid { None } else { Some(summarize(&facts)) };
            AnchorVerificationResult {
                anchor_type: "rfc3161".to_string(),
                is_valid,
                // The token's `genTime` becomes an *established* time only
                // once every fact holds and the chain reached a configured
                // trust anchor. Until then it is a claim, and a timestamp
                // anchor's whole purpose makes handing that over
                // unqualified the most misleading thing this adapter could
                // do.
                timestamp: if is_valid { claimed } else { None },
                claimed_timestamp: claimed,
                error,
            }
        }
        Err(e) => AnchorVerificationResult {
            anchor_type: "rfc3161".to_string(),
            is_valid: false,
            timestamp: None,
            claimed_timestamp: parse_iso8601_to_nanos(timestamp),
            error: Some(e.to_string()),
        },
    }
}

/// `": <detail>"`, or the empty string when there is no detail to append.
fn detail_suffix(detail: Option<&str>) -> String {
    detail.map_or_else(String::new, |d| format!(": {d}"))
}

/// Render a compact human-readable summary of why `facts` did not reach
/// full aggregate success, for [`AnchorVerificationResult::error`].
fn summarize(facts: &Rfc3161AnchorFacts) -> String {
    let mut reasons = Vec::new();
    match facts.message_imprint {
        result::MessageImprint::Verified => {}
        result::MessageImprint::Mismatch => {
            reasons.push("messageImprint mismatch: does not match expected root".to_string());
        }
        result::MessageImprint::Malformed => {
            reasons.push(
                "messageImprint is malformed: its hash length contradicts the algorithm it names"
                    .to_string(),
            );
        }
        // No comparison took place, so nothing about the root is asserted.
        result::MessageImprint::Indeterminate => {
            reasons.push(
                "messageImprint could not be compared (nothing was refuted): its hash algorithm \
                 is not one this crate implements"
                    .to_string(),
            );
        }
    }
    match facts.cms_signature {
        result::CmsSignature::Verified => {}
        result::CmsSignature::Refuted => {
            let detail = facts.diagnostic.as_deref().unwrap_or("CMS signature invalid");
            reasons.push(format!("CMS signature invalid: {detail}"));
        }
        result::CmsSignature::Indeterminate => {
            let detail = facts.diagnostic.as_deref().unwrap_or("reason unavailable");
            reasons.push(format!(
                "CMS signature could not be evaluated (nothing was refuted): {detail}"
            ));
        }
    }
    // Only `Invalid` is a refutation; the other two non-`Complete` statuses
    // describe this verifier's limits and must not be worded as damage to
    // the token.
    match facts.path_status {
        PathStatus::Invalid => reasons.push(format!(
            "certificate chain refuted at genTime{}",
            detail_suffix(facts.chain_diagnostic.as_deref())
        )),
        PathStatus::Indeterminate => reasons.push(format!(
            "certificate chain could not be evaluated{}",
            detail_suffix(facts.chain_diagnostic.as_deref())
        )),
        PathStatus::Incomplete => reasons.push(format!(
            "certificate chain incomplete: an issuer certificate is missing{}",
            detail_suffix(facts.chain_diagnostic.as_deref())
        )),
        PathStatus::Complete => {}
    }
    if let Some(reason) = facts.timestamping_eku.reason() {
        reasons.push(format!("signer certificate's timestamping EKU is not usable: {reason}"));
    }
    match &facts.terminal_anchor {
        Some(TerminalAnchor::Assumed { sha256_fingerprint, self_signature }) => {
            let self_signature = match self_signature {
                result::SelfSignature::Verified => "self-signature verified",
                result::SelfSignature::Unverifiable => "self-signature NOT verifiable here",
            };
            reasons.push(format!(
                "trust anchor not established: chain terminates in a self-issued certificate \
                 nobody vouched for ({self_signature}, fingerprint {}); this NEVER counts as a \
                 valid anchor -- supply a TrustStore",
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

#[cfg(test)]
mod signer_selection_tests {
    //! Adversarial tests for **which** certificate is chosen as the CMS
    //! signer.
    //!
    //! A CMS `SignedData` certificate set is not covered by the signature
    //! (RFC 5652 5.1), and `SignerInfo.sid` -- issuer+serial or
    //! `SubjectKeyIdentifier` -- is not unique across an attacker-supplied
    //! set. Picking the first match therefore handed a stranger a way to
    //! discredit somebody else's perfectly valid token: drop in a
    //! certificate carrying the real signer's issuer and serial but a
    //! different key, and the impostor is selected, fails verification, and
    //! the token is published as refuted evidence.
    //!
    //! The impostor here is built from real material -- FreeTSA's own root
    //! certificate, relabelled with the signer's issuer and serial. It is a
    //! well-formed certificate with a genuine (but wrong) key, which is
    //! exactly what makes it a convincing decoy.

    use der::Encode;
    use x509_cert::Certificate;

    use super::*;
    use crate::core::verify::tests::rfc3161_tests::{FREETSA_HASH, FREETSA_TOKEN};

    fn parsed_token() -> ParsedTimestampToken {
        parse_rfc3161_token(&format!("base64:{FREETSA_TOKEN}")).expect("real token parses")
    }

    fn certificates_of(parsed: &ParsedTimestampToken) -> Vec<Certificate> {
        parsed
            .signed_data
            .certificates
            .iter()
            .flat_map(|set| set.0.iter())
            .filter_map(|choice| match choice {
                cms::cert::CertificateChoices::Certificate(cert) => Some(cert.clone()),
                cms::cert::CertificateChoices::Other(_) => None,
            })
            .collect()
    }

    /// A well-formed certificate bearing `real_signer`'s issuer and serial
    /// (so it matches the same `SignerInfo.sid`) but holding a different
    /// public key, taken from another real certificate in the same token.
    fn impostor_for(real_signer: &Certificate, donor: &Certificate) -> Certificate {
        let mut impostor = donor.clone();
        impostor.tbs_certificate.issuer = real_signer.tbs_certificate.issuer.clone();
        impostor.tbs_certificate.serial_number = real_signer.tbs_certificate.serial_number.clone();
        impostor
    }

    /// **The regression.** The impostor stands FIRST in the certificate
    /// list. Selection must still find the genuine signer and report
    /// `Verified`, because a candidate that fails is simply not the signer
    /// -- it says nothing about the token.
    #[test]
    fn an_impostor_placed_first_does_not_refute_a_valid_token() {
        let parsed = parsed_token();
        let certificates = certificates_of(&parsed);
        let signer_info = &parsed.signed_data.signer_infos.0.as_slice()[0];
        let econtent_type = parsed.signed_data.encap_content_info.econtent_type;

        let real_signer = chain::signer_certificate_candidates(&certificates, &signer_info.sid)
            .next()
            .expect("the real token names its own signer")
            .clone();
        let donor = certificates
            .iter()
            .find(|c| {
                c.tbs_certificate.subject_public_key_info
                    != real_signer.tbs_certificate.subject_public_key_info
            })
            .expect("the token carries a second, differently-keyed certificate")
            .clone();
        let impostor = impostor_for(&real_signer, &donor);

        // Sanity: the impostor really does match the same SID, otherwise
        // this test would pass for the wrong reason.
        let with_impostor = vec![impostor.clone(), real_signer.clone()];
        let candidates: Vec<_> =
            chain::signer_certificate_candidates(&with_impostor, &signer_info.sid).collect();
        assert_eq!(candidates.len(), 2, "the impostor must match the same SignerInfo.sid");
        assert_eq!(
            candidates[0].tbs_certificate.subject_public_key_info,
            impostor.tbs_certificate.subject_public_key_info,
            "the impostor must be the FIRST candidate for this test to mean anything"
        );

        let selection =
            select_signer(&with_impostor, signer_info, econtent_type, &parsed.raw_tst_info);

        assert_eq!(
            selection.cms_signature,
            result::CmsSignature::Verified,
            "a stranger's certificate in an unsigned certificate set must not refute a valid token"
        );
        assert_eq!(
            selection
                .certificate
                .expect("a verified signer")
                .tbs_certificate
                .subject_public_key_info,
            real_signer.tbs_certificate.subject_public_key_info,
            "the genuine signer must be the one selected"
        );
    }

    /// **The impostor alone -- the genuine signer removed from the set --
    /// must NOT be a refutation.**
    ///
    /// The same unauthenticated certificate set that lets an attacker add a
    /// certificate lets them delete one. Reporting `Refuted` here would say
    /// the token was disproved when its signature was never checked against
    /// anything: exactly the over-claim the absent-certificate case already
    /// avoids. Two spellings of "we do not have the certificate" must not
    /// give opposite verdicts.
    #[test]
    fn an_impostor_alone_is_indeterminate_not_refuted() {
        let parsed = parsed_token();
        let certificates = certificates_of(&parsed);
        let signer_info = &parsed.signed_data.signer_infos.0.as_slice()[0];
        let econtent_type = parsed.signed_data.encap_content_info.econtent_type;

        let real_signer = chain::signer_certificate_candidates(&certificates, &signer_info.sid)
            .next()
            .expect("signer present")
            .clone();
        let donor = certificates
            .iter()
            .find(|c| {
                c.tbs_certificate.subject_public_key_info
                    != real_signer.tbs_certificate.subject_public_key_info
            })
            .expect("second certificate")
            .clone();
        let only_impostor = vec![impostor_for(&real_signer, &donor)];

        let selection =
            select_signer(&only_impostor, signer_info, econtent_type, &parsed.raw_tst_info);

        assert_eq!(
            selection.cms_signature,
            result::CmsSignature::Indeterminate,
            "a removed genuine signer must not be reported as a disproved signature"
        );
        assert!(
            selection.certificate.is_none(),
            "no signer was established, so none may be published"
        );
        // The fact that candidates existed and failed is still recorded --
        // it is useful, it just cannot be the verdict.
        let diagnostic = selection.diagnostic.expect("a diagnostic");
        assert!(
            diagnostic.contains("1 candidates tried"),
            "the diagnostic must record what was tried: {diagnostic}"
        );
    }

    /// A **certificate-independent** failure is still a refutation. The
    /// `message-digest` signed attribute is computed from the encapsulated
    /// content alone, so tampering with it is a property of the token no
    /// choice of certificate could excuse -- softening this into "cannot
    /// tell" would give up real forgery detection.
    #[test]
    fn a_tampered_message_digest_is_still_refuted() {
        let parsed = parsed_token();
        let certificates = certificates_of(&parsed);
        let signer_info = &parsed.signed_data.signer_infos.0.as_slice()[0];
        let econtent_type = parsed.signed_data.encap_content_info.econtent_type;

        // Flip the content the message-digest attribute commits to.
        let mut tampered = parsed.raw_tst_info.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;

        let selection = select_signer(&certificates, signer_info, econtent_type, &tampered);

        assert_eq!(
            selection.cms_signature,
            result::CmsSignature::Refuted,
            "a message-digest that does not cover the content is a property of the token itself"
        );
        assert!(selection.certificate.is_none());
    }

    /// No certificate matching the SID at all is `Indeterminate` with no
    /// established signer -- never a refutation. This is the case the
    /// impostor-only case above must agree with.
    #[test]
    fn no_candidate_at_all_is_not_a_refutation() {
        let parsed = parsed_token();
        let signer_info = &parsed.signed_data.signer_infos.0.as_slice()[0];
        let econtent_type = parsed.signed_data.encap_content_info.econtent_type;

        let selection = select_signer(&[], signer_info, econtent_type, &parsed.raw_tst_info);
        assert_eq!(selection.cms_signature, result::CmsSignature::Indeterminate);
        assert!(selection.certificate.is_none());
    }

    /// **Blocker regression: no established signer, no signer facts.** When
    /// nothing verifies, `signer`, the timestamping EKU and the certificate
    /// path must not be populated from an arbitrary candidate. `SignerFacts`
    /// documents the identity of the certificate that *produced the CMS
    /// signature*; a deterministic choice among unverified candidates is
    /// still an arbitrary one, and determinism does not make it true.
    #[test]
    fn an_unestablished_signer_publishes_no_signer_facts() {
        use base64::Engine;
        use cms::content_info::ContentInfo;
        use der::asn1::SetOfVec;

        let parsed = parsed_token();
        let certificates = certificates_of(&parsed);
        let signer_info = &parsed.signed_data.signer_infos.0.as_slice()[0];
        let real_signer = chain::signer_certificate_candidates(&certificates, &signer_info.sid)
            .next()
            .expect("signer present")
            .clone();
        let donor = certificates
            .iter()
            .find(|c| {
                c.tbs_certificate.subject_public_key_info
                    != real_signer.tbs_certificate.subject_public_key_info
            })
            .expect("second certificate")
            .clone();

        // Rebuild the token with the genuine signer REPLACED by the
        // impostor: a same-SID certificate is present, the real one is not.
        let choices: Vec<cms::cert::CertificateChoices> = certificates
            .iter()
            .filter(|c| {
                c.tbs_certificate.subject_public_key_info
                    != real_signer.tbs_certificate.subject_public_key_info
            })
            .cloned()
            .chain(std::iter::once(impostor_for(&real_signer, &donor)))
            .map(cms::cert::CertificateChoices::Certificate)
            .collect();

        let mut signed_data = parsed.signed_data.clone();
        signed_data.certificates = Some(cms::signed_data::CertificateSet(
            SetOfVec::try_from(choices).expect("set re-encodes"),
        ));
        let content_info = ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: der::Any::encode_from(&signed_data).expect("SignedData re-encodes"),
        };
        let der_bytes = content_info.to_der().expect("ContentInfo re-encodes");
        let token =
            format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(&der_bytes));

        let facts = verify_rfc3161_token(&token, &FREETSA_HASH, None).expect("token parses");

        assert_eq!(facts.cms_signature, result::CmsSignature::Indeterminate);
        assert!(facts.signer.is_none(), "no signer was established, so none may be published");
        assert_eq!(facts.timestamping_eku, result::TimestampingEku::NotChecked);
        assert_eq!(facts.path_status, PathStatus::Indeterminate);
        assert!(facts.terminal_anchor.is_none());
        assert!(!facts.chain_valid_at_gen_time);
        assert!(!facts.is_fully_valid());
    }

    /// An unrecognised `messageImprint` hash algorithm means **no
    /// comparison happened**, so it cannot be reported as a mismatch.
    ///
    /// ATL's documentation states a mandatory *minimum* of algorithm
    /// support, not a prohibition on the rest, so an algorithm this crate
    /// has not implemented is the verifier's limitation and not the token's
    /// defect.
    #[test]
    fn an_unsupported_imprint_algorithm_is_indeterminate_not_a_mismatch() {
        use crate::error::AtlError;

        let unsupported: AtlResult<Rfc3161VerifyResult> =
            Err(AtlError::Rfc3161UnsupportedAlgorithm("expected SHA-256, got 1.2.3".to_string()));
        assert_eq!(classify_message_imprint(&unsupported), result::MessageImprint::Indeterminate);

        let mismatch: AtlResult<Rfc3161VerifyResult> = Err(AtlError::Rfc3161HashMismatch {
            token_hash: "aa".to_string(),
            expected_hash: "bb".to_string(),
        });
        assert_eq!(classify_message_imprint(&mismatch), result::MessageImprint::Mismatch);

        // A hash whose length contradicts the algorithm it names is a
        // checked fact coming out false -- but a structural defect, NOT a
        // mismatch. Collapsing the two would explain a proven defect with a
        // cause that is not true of it.
        let malformed: AtlResult<Rfc3161VerifyResult> =
            Err(AtlError::Rfc3161ParseError("invalid hash length".to_string()));
        assert_eq!(classify_message_imprint(&malformed), result::MessageImprint::Malformed);
        assert!(result::MessageImprint::Malformed.is_refuted());
        assert!(result::MessageImprint::Mismatch.is_refuted());
        assert!(!result::MessageImprint::Indeterminate.is_refuted());

        let good: AtlResult<Rfc3161VerifyResult> = Ok(Rfc3161VerifyResult {
            hash_valid: true,
            algorithm_oid: SHA256_OID.to_string(),
            token_hash: String::new(),
            gen_time: None,
        });
        assert_eq!(classify_message_imprint(&good), result::MessageImprint::Verified);
    }

    /// The same thing end to end: a real token whose `messageImprint` names
    /// an algorithm this crate does not implement reports `Indeterminate`,
    /// never `Refuted`. (Rewriting the imprint necessarily breaks the
    /// `message-digest` signed attribute, so the CMS signature is refuted
    /// here -- the point is that the imprint fact stays honest and
    /// independent.)
    #[test]
    fn an_unsupported_imprint_algorithm_is_indeterminate_end_to_end() {
        use base64::Engine;
        use cms::content_info::ContentInfo;
        use der::asn1::OctetString;
        use der::Decode;

        let parsed = parsed_token();

        let mut tst_info = parsed.tst_info.clone();
        // SHA-1: a real, well-known digest OID that `DigestAlg::from_oid`
        // deliberately does not implement.
        tst_info.message_imprint.hash_algorithm.oid =
            der::asn1::ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
        let new_tst_der = tst_info.to_der().expect("TSTInfo re-encodes");

        let mut signed_data = parsed.signed_data.clone();
        signed_data.encap_content_info.econtent = Some(
            der::Any::encode_from(&OctetString::new(new_tst_der).expect("octet string"))
                .expect("eContent re-encodes"),
        );

        let content_info = ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: der::Any::encode_from(&signed_data).expect("SignedData re-encodes"),
        };
        let der_bytes = content_info.to_der().expect("ContentInfo re-encodes");
        let token =
            format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(&der_bytes));
        // Guard: the rewritten token must still be decodable, or this test
        // would pass without exercising anything.
        assert!(ContentInfo::from_der(&der_bytes).is_ok());

        let facts =
            verify_rfc3161_token(&token, &FREETSA_HASH, None).expect("rewritten token parses");

        assert_eq!(
            facts.message_imprint,
            result::MessageImprint::Indeterminate,
            "an imprint algorithm we cannot compute must not be reported as a mismatch"
        );
        // And the other half of the same token: rewriting the TSTInfo
        // necessarily breaks the `message-digest` signed attribute, which is
        // certificate-independent and therefore still a genuine refutation.
        // This is the end-to-end guarantee that treating "every candidate
        // failed" as indeterminate did not cost real forgery detection: a
        // token whose content no longer matches what was signed is still
        // reported as disproved, not as "cannot tell".
        assert_eq!(
            facts.cms_signature,
            result::CmsSignature::Refuted,
            "tampered content must still be refuted end to end"
        );
        assert!(!facts.is_fully_valid());
    }

    /// End to end, through the public API: a token whose certificate set has
    /// been enlarged with a same-SID impostor still verifies completely.
    #[test]
    fn a_token_with_an_injected_impostor_still_verifies_end_to_end() {
        use base64::Engine;
        use cms::cert::CertificateChoices;
        use cms::content_info::ContentInfo;
        use der::asn1::SetOfVec;

        let parsed = parsed_token();
        let certificates = certificates_of(&parsed);
        let signer_info = &parsed.signed_data.signer_infos.0.as_slice()[0];
        let real_signer = chain::signer_certificate_candidates(&certificates, &signer_info.sid)
            .next()
            .expect("signer present")
            .clone();
        let donor = certificates
            .iter()
            .find(|c| {
                c.tbs_certificate.subject_public_key_info
                    != real_signer.tbs_certificate.subject_public_key_info
            })
            .expect("second certificate")
            .clone();

        let mut choices: Vec<CertificateChoices> =
            certificates.iter().cloned().map(CertificateChoices::Certificate).collect();
        choices.push(CertificateChoices::Certificate(impostor_for(&real_signer, &donor)));

        let mut signed_data = parsed.signed_data.clone();
        signed_data.certificates = Some(cms::signed_data::CertificateSet(
            SetOfVec::try_from(choices).expect("certificate set re-encodes"),
        ));

        let content_info = ContentInfo {
            content_type: const_oid::db::rfc5911::ID_SIGNED_DATA,
            content: der::Any::encode_from(&signed_data).expect("SignedData re-encodes"),
        };
        let der_bytes = content_info.to_der().expect("ContentInfo re-encodes");
        let token =
            format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(&der_bytes));

        let facts = verify_rfc3161_token(&token, &FREETSA_HASH, None)
            .expect("the enlarged token still parses");

        assert_eq!(
            facts.cms_signature,
            result::CmsSignature::Verified,
            "injecting an unrelated certificate must not refute the token: {:?}",
            facts.diagnostic
        );
        assert!(facts.message_imprint.is_verified());
        let signer = facts.signer.expect("signer facts present");
        assert!(signer.subject.contains("www.freetsa.org"));
    }
}
