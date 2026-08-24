//! RFC 3161 verification tests

#![cfg(feature = "rfc3161-verify")]

use crate::core::verify::anchors::{
    extract_gen_time_nanos, parse_rfc3161_token, verify_rfc3161_anchor_impl, verify_rfc3161_hash,
    verify_rfc3161_token, TrustStore,
};
use crate::core::verify::{PathStatus, TerminalAnchor};

/// DER encoding of FreeTSA's own self-signed root certificate, extracted
/// from `FREETSA_TOKEN`'s own certificate set (`openssl pkcs7 -print_certs`).
/// Used only as caller-supplied `TrustStore` material in these tests --
/// this is exactly the kind of identity the trust model forbids baking into
/// the crate itself, so it lives in test code, not in `rfc3161/mod.rs`.
const FREETSA_ROOT_CERT_DER_B64: &str = "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";

const FREETSA_TOKEN: &str = "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";

const FREETSA_HASH: [u8; 32] = [
    0xe2, 0x36, 0x1b, 0x40, 0x53, 0xa9, 0x45, 0xdd, 0x1d, 0x24, 0x1a, 0x6c, 0x87, 0xda, 0xd7, 0x98,
    0xb7, 0xfd, 0x74, 0x50, 0x61, 0x4b, 0x81, 0x5a, 0x2d, 0x94, 0x72, 0x83, 0xed, 0x35, 0x94, 0x52,
];

#[test]
fn test_parse_real_freetsa_token() {
    let token = format!("base64:{FREETSA_TOKEN}");
    let result = parse_rfc3161_token(&token);
    assert!(result.is_ok(), "Should parse real FreeTSA token: {:?}", result.err());
}

#[test]
fn test_verify_real_freetsa_token_valid_hash() {
    let token = format!("base64:{FREETSA_TOKEN}");
    let parsed = parse_rfc3161_token(&token).expect("Failed to parse token");
    let result = verify_rfc3161_hash(&parsed, &FREETSA_HASH);
    assert!(result.is_ok(), "Should verify with correct hash: {:?}", result.err());
    assert!(result.unwrap().hash_valid, "Hash should be valid");
}

#[test]
fn test_verify_real_freetsa_token_wrong_hash() {
    let token = format!("base64:{FREETSA_TOKEN}");
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
    let token = format!("base64:{FREETSA_TOKEN}");
    let parsed = parse_rfc3161_token(&token).expect("Failed to parse token");
    let gen_time = extract_gen_time_nanos(&parsed.tst_info);
    assert!(gen_time.is_some(), "Should extract genTime");

    let nanos = gen_time.unwrap();
    assert!(nanos > 1_704_067_200_000_000_000, "Timestamp should be after 2024-01-01");
}

/// The legacy `AnchorVerificationResult` adapter is called with no
/// `TrustStore` (it has none to plumb through yet -- see module docs), so
/// per the trust model it must report `is_valid: false` even though every
/// other fact about this real, correctly-signed token holds. This is the
/// fix for the exact lie this module used to tell: a hash match alone used
/// to flip `is_valid` to `true` with no signature or chain verification at
/// all. It no longer does.
#[test]
fn test_verify_rfc3161_anchor_integration() {
    let timestamp = "2026-01-04T21:57:43Z";
    let token = format!("base64:{FREETSA_TOKEN}");

    let result = verify_rfc3161_anchor_impl(timestamp, &token, &FREETSA_HASH);

    assert_eq!(result.anchor_type, "rfc3161");
    assert!(
        !result.is_valid,
        "without a TrustStore, is_valid must be false even for a cryptographically sound token"
    );
    assert!(result.timestamp.is_some(), "Should have timestamp (from genTime)");
    assert!(result.error.is_some(), "Should explain why aggregate success was not reached");
    let error = result.error.unwrap();
    assert!(
        error.contains("trust anchor not established"),
        "error should explain the Assumed terminal anchor: {error}"
    );
}

fn decode_freetsa_root_cert() -> x509_cert::Certificate {
    use base64::Engine;
    use der::Decode;
    let der = base64::engine::general_purpose::STANDARD.decode(FREETSA_ROOT_CERT_DER_B64).unwrap();
    x509_cert::Certificate::from_der(&der).unwrap()
}

/// The full, rich `verify_rfc3161_token` API on the same real token: with no
/// `TrustStore`, the chain is cryptographically and structurally sound but
/// terminates `Assumed`, and nothing aggregates to success.
#[test]
fn test_verify_rfc3161_token_real_freetsa_without_trust_store_is_assumed() {
    let token = format!("base64:{FREETSA_TOKEN}");
    let facts = verify_rfc3161_token(&token, &FREETSA_HASH, None).expect("token parses");

    assert!(facts.imprint_matches_root);
    assert!(facts.cms_signature_valid, "{:?}", facts.diagnostic);
    assert!(facts.chain_valid_at_gen_time);
    assert!(facts.timestamping_eku_ok);
    assert_eq!(facts.path_status, PathStatus::Complete);
    assert!(matches!(facts.terminal_anchor, Some(TerminalAnchor::Assumed { .. })));
    assert!(!facts.is_fully_valid());

    let signer = facts.signer.expect("signer facts present");
    assert!(signer.subject.contains("www.freetsa.org"));
}

/// The same real token and the same real hash, but now the caller supplies
/// FreeTSA's own root certificate (extracted from the token itself) as a
/// trust anchor: the terminal anchor becomes `Trusted` at the very same
/// certificate, and the token now fully verifies.
#[test]
fn test_verify_rfc3161_token_real_freetsa_with_trust_store_is_trusted() {
    let token = format!("base64:{FREETSA_TOKEN}");
    let store = TrustStore::new().with_anchor_certificate(decode_freetsa_root_cert());

    let facts = verify_rfc3161_token(&token, &FREETSA_HASH, Some(&store)).expect("token parses");

    assert_eq!(facts.path_status, PathStatus::Complete);
    assert!(matches!(facts.terminal_anchor, Some(TerminalAnchor::Trusted { .. })));
    assert!(facts.is_fully_valid(), "with FreeTSA's own root pinned, this token must fully verify");
    assert_eq!(
        facts.gen_time,
        extract_gen_time_nanos(&parse_rfc3161_token(&token).unwrap().tst_info)
    );
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
    let random = base64::engine::general_purpose::STANDARD.encode([0xDE, 0xAD, 0xBE, 0xEF]);
    let result = parse_rfc3161_token(&format!("base64:{random}"));
    assert!(matches!(result, Err(crate::error::AtlError::Rfc3161ParseError(_))));
}

#[test]
fn test_rfc3161_truncated_der() {
    use base64::Engine;
    let truncated = base64::engine::general_purpose::STANDARD.encode([0x30, 0x82, 0x0A, 0x7C]);
    let result = parse_rfc3161_token(&format!("base64:{truncated}"));
    assert!(matches!(result, Err(crate::error::AtlError::Rfc3161ParseError(_))));
}

#[test]
fn test_rfc3161_token_too_large() {
    use base64::Engine;
    let huge = base64::engine::general_purpose::STANDARD.encode(vec![0x30; 100_000]);
    let result = parse_rfc3161_token(&format!("base64:{huge}"));
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
        assert!(result.is_ok(), "Panicked on input: {input}");
    }
}

#[cfg(not(feature = "rfc3161-verify"))]
mod rfc3161_feature_disabled_tests {
    use crate::core::receipt::ReceiptAnchor;
    use crate::core::verify::helpers::{verify_anchor, AnchorVerificationContext};

    #[test]
    fn test_rfc3161_feature_disabled() {
        let anchor = ReceiptAnchor::Rfc3161 {
            target: "data_tree_root".to_string(),
            target_hash: format!("sha256:{}", hex::encode([0u8; 32])),
            tsa_url: "https://freetsa.org/tsr".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            token_der: "base64:AAAA".to_string(),
        };
        let context = AnchorVerificationContext::new([0u8; 32], [1u8; 32]);
        let result = verify_anchor(&anchor, &context);
        assert!(!result.is_valid);
        assert!(result.error.as_ref().unwrap().contains("feature"));
    }
}
