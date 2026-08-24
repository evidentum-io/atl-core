//! Adversarial and edge-case RFC 3161 fixtures
//!
//! These are synthetic tokens generated offline with `openssl ca`/`openssl
//! ts` against a throwaway self-signed CA hierarchy that exists nowhere
//! else and is not, and must never become, a trust anchor baked into this
//! crate. They exist to prove specific properties the 16-token real-world
//! corpus (`rfc3161_corpus_tests.rs`) cannot exercise on its own:
//!
//! - **The forgery regression** (the reason this module exists at all): a
//!   complete, cryptographically correct, self-signed chain must never
//!   satisfy aggregate success just because the math checks out.
//! - A certificate that has expired by the time the test runs, but was
//!   valid at the token's own `genTime`, must still pass -- proving validity
//!   is checked against `genTime`, never wall-clock "now".
//! - An unrecognized *critical* extension must be rejected outright.
//! - A token missing an intermediate certificate can be bridged by a
//!   caller-supplied `TrustStore` intermediate, and fails closed without one.
#![cfg(feature = "rfc3161-verify")]

use crate::core::verify::anchors::rfc3161::{verify_rfc3161_token, TrustStore};
use crate::core::verify::{PathStatus, TerminalAnchor};
use der::Decode;
use x509_cert::Certificate;

// All four tokens below were requested against the same message imprint,
// so they share this expected root.
const FORGED_IMPRINT_HASH_HEX: &str =
    "38c138a16e7d0908b288b9b186b9cd62e49be560570ce1f334a7786b9e06bed7";

/// Full 3-certificate chain (root, CA=true, self-signed -- intermediate,
/// CA=true, pathlen:0 -- leaf, critical exclusive timeStamping EKU), and a
/// correctly-signed RFC 3161 token over an arbitrary imprint and genTime,
/// entirely self-contained and self-signed. Nothing here is, or must ever
/// become, a real trust anchor.
const FORGED_TOKEN_B64: &str = "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";

/// Same forged CA hierarchy; the leaf certificate's validity window is
/// `[genTime - 1 day, genTime + ~10 minutes]`, so by the time this test suite
/// runs it has long since "expired" by wall-clock time, while remaining
/// valid at the token's own `genTime`.
const EXPIRING_TOKEN_B64: &str = "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";

/// Same forged CA hierarchy; the leaf certificate carries an extra
/// unrecognized extension (`1.2.3.4.5.6.7.8.9`) marked critical.
const UNKNOWN_CRITICAL_EXT_TOKEN_B64: &str = "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";

/// Same forged CA hierarchy, but the token's own certificate set includes
/// *only* the leaf certificate -- the intermediate must be supplied
/// separately via `TrustStore::with_intermediate_certificate`.
const LEAF_ONLY_TOKEN_B64: &str = "MIIH8QYJKoZIhvcNAQcCoIIH4jCCB94CAQMxDzANBglghkgBZQMEAgEFADBoBgsqhkiG9w0BCRABBKBZBFcwVQIBAQYEKgMEATAxMA0GCWCGSAFlAwQCAQUABCA4wTihbn0JCLKIubGGuc1i5JvlYFcM4fM0p3hrnga+1wIBAxgPMjAyNjA4MjQwNTI3MzlaMAMCAQGgggSeMIIEmjCCAwKgAwIBAgIUXCtw3/PmuuEVXrlskLbFr+mY1G0wDQYJKoZIhvcNAQELBQAwUDEoMCYGA1UEAwwfQVRMIFRlc3QgRm9yZ2VkIEludGVybWVkaWF0ZSBDQTEkMCIGA1UECgwbQVRMIEFkdmVyc2FyaWFsIFRlc3QgQ29ycHVzMB4XDTI2MDgyNDA1MDc0MloXDTM2MDgyMTA1MDc0MlowRDEcMBoGA1UEAwwTQVRMIFRlc3QgRm9yZ2VkIFRTQTEkMCIGA1UECgwbQVRMIEFkdmVyc2FyaWFsIFRlc3QgQ29ycHVzMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAnJ5S2pIwxRTuRotcDn7zaNR2oLJRnnc1+wb0lkiFv2VkhtmXlyuegfy4IeunzAzIoDXwZ2s7wAl9u6yGx7z5EHjT4moLV91aNIcZ07WXRt950ltNFc7V5aRme1xc1EoF+DbVCp6v8MpxlqKA6hebNonIk+U18N5am3ZioSFdJsQmcgYBFm9sWWkzvaiY3dEy8QHb3hIsLFzOQxkNSCwuTHyw5/pv5M9Y7pWKSKiJDx0FDLCc5tFg34VtzS9ADSFEvX0V497qvBl6Pz6glJpAfXMf5k6B7MjJq9/iEc7kKFu6pVhAMvdDCY4AULM/eaJwvKbilOyE1Vtq1BGMCbbYLqDJ1ITW6U9ieqrPz93IZgv3LrjBRBZb9iiBkCFGr6e6Mil/sWWNFpsj56w6QCI2Ji8U6OMDpV2W4g7GkuB1Cf7UDn1w+2vHwEIGytqFlK9zKM18j5lVe2R3HeNYV2yq3dFcUehTe5Twy1LtIlQ9HrvwWOzzMeKFrUwrcrsvzMujAgMBAAGjeDB2MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgbAMB0GA1UdDgQWBBSAJrzbgR4F4LBAMtNHEfY2s7u66DAfBgNVHSMEGDAWgBRXu6bxx9705B/+SGVBIv4edn54fDANBgkqhkiG9w0BAQsFAAOCAYEASsF8JFNM8vsskzEKcCKnakKTQGk6MayVB0opd70C8f+VbBlmrnaTlOKhuKOqcM4gNs+gCS0T+W7T2zaQBoTekV613RbAe/EoDkySziw4XsZUEWBZkyl4A3lN9rITQlUR/Qg14GVSI9DmtfEiGyESamFRfb6AOdW58TMAazBGGRCQnDMQnfMf2d8lvBIjpn1Q95Bgzhg2Zepeom3UNkI1/46UkzsR4tRLZk7j0Hefcs018ynNxWdatI1EWd3GjtpjhysEgCtcBw7xTfsUQkpmPmOo9NQpb9xRyx8iNl/ZY/uNdO26erCY8rhG6lnvIGMNXfevb37bVcJ/MwK0nOYkRqA4Q2RmAGGMQuIpFQuybdxFILI5KgCcSs5mOKLy2QI2Fn/aDSiXqx3duF09b0lygd6d/sttsQAVv7B6a6A9bCo1abTw9OvJD8eb9NGHkQqxsELRLM2irJ3P8L3uBPeoNxxh5o1mfym8BAaWy/g3D9GHQmQ0WtVCnmIPvgAkOiqnMYICujCCArYCAQEwaDBQMSgwJgYDVQQDDB9BVEwgVGVzdCBGb3JnZWQgSW50ZXJtZWRpYXRlIENBMSQwIgYDVQQKDBtBVEwgQWR2ZXJzYXJpYWwgVGVzdCBDb3JwdXMCFFwrcN/z5rrhFV65bJC2xa/pmNRtMA0GCWCGSAFlAwQCAQUAoIGkMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjYwODI0MDUyNzM5WjAvBgkqhkiG9w0BCQQxIgQg0U/R0iamJF8WFgUDCmEOMp2/x5idu5IS4evXlz5FRtIwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgP9pWuIwG1NxP8IpYD2pm2ichQZ8mOk/VeUVl+YaRTAwwDQYJKoZIhvcNAQEBBQAEggGAkJUKt4E15FNUDq+wNqDFv7cJA10x0TMOuaC91Fmb3da3daE9hRPqufBbA9825qYi4j5xRQB/DTyrMwctKBzAG6Lytm/a+/4STJOQu1WD54QKaYvleM+0aJCaKbZWjEsrchi492DSMhYPVy+i+hJe9e0joR4Gm5K2ve2XpJqKDLVagZXD9vUIVRz954gT3+WQoMX8EbVhwH/pRGNZbzhr5+XfjS7AXRDpfdHycG8sFbkol6XBZ8vZTxGbR2zzlwKem074jCsIp/OWrY5ExHOkm+FfYDeGlbZ26hfq8PhuXBjHm+n0TxrtSuoLZIR1w+RfCkGfG2Ams0vHQ87XAbDLCyODT7/7foyJrdLS7qipUYhNMLIwFaxe/xMldjHwcutYXBtF/caIVz42wlpJsezDSZVshsH+HYrUkE5Ja1bkCeOVWjb0FO2bEYMDY/yGaUxAUAQJvEGe+jjT0+gLXNnkE3/qCbd9Y2FcgG3wn7+kIARWsnGG+n7Qqt6X18jl+l5W";

/// DER encoding of the forged root CA certificate (self-signed).
const FORGED_ROOT_CERT_DER_B64: &str = "MIIEgTCCAumgAwIBAgIUARkOOwEJ2sB9s0zfODbsaLeBgSgwDQYJKoZIhvcNAQELBQAwSDEgMB4GA1UEAwwXQVRMIFRlc3QgRm9yZ2VkIFJvb3QgQ0ExJDAiBgNVBAoMG0FUTCBBZHZlcnNhcmlhbCBUZXN0IENvcnB1czAeFw0yNjA4MjQwNTA3NDJaFw0zNjA4MjEwNTA3NDJaMEgxIDAeBgNVBAMMF0FUTCBUZXN0IEZvcmdlZCBSb290IENBMSQwIgYDVQQKDBtBVEwgQWR2ZXJzYXJpYWwgVGVzdCBDb3JwdXMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCpfslT3YSjFNVHwNxPHrrOfpSqgugiJw0fSbltY6e5tHakGHWulYXxihSKnfirYWVKtwdGSolKjA9lEvuPRQykolDnMsVdAuyfD6XY6maji+23RXr/VmciNZPoJRRZ3ftNADvcJbW7wo5/n0qTSaotRPg64FL9ZE0qNKVuEGJKxTOQ3Fm26FXgSwRX+hqWAgSCIsTZuQVOC+4snSoRzLHAR18PUWp2hPRh+EUVrIU/PioY8qo5P463KOswKnMHyWvTCD97kPU0crpXIJU4GdlOe8T+UnyLhIQxEPhhL07uUk6u+jm/Ud1fWj/qrpu6u/tV0PHYHzWOIUp3+gEBZpoG8Wc32wTtzxtnyVmsEr4UoNkv1J0uBo639m558/cmAkheTKmG2N00fxQxgdlXlRcIPes08chXGTQPYBShVELMuR+DL+VUfJj+N9X2gmu7aYgDXCS0lTDuKtLzb+t3eoWy6RK2VxHDuxz8r4QEZiaz4b6cWB42fnMO38GgBi5Ew3UCAwEAAaNjMGEwHwYDVR0jBBgwFoAUbT+dlyxj6sxg3L2MB98mm24MbsswDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFG0/nZcsY+rMYNy9jAffJptuDG7LMA0GCSqGSIb3DQEBCwUAA4IBgQBQSn60GeRKZOjM3D67VT4Do3pZeUflrpiej7IdKhYdTVt9uAUTH5T7/E6S1FRBBv7OvP+CJp3bK4U+z5GQ40ynvKHZ766Ud0gLRApZ7+nvzwi6l7+L5wbt8PTYRwqFWWDXoaYJ65fUaz5qf4JLxWY7yc86vb/HreQLbSSjsxCe7k5+cVJgfqro93gAgFajt20uGXfXvbtYGT/ZEpN20nqft/amPXTEz2VEYQ3MEDjMmAjdwOrhjxhZQ3+2TII5/Ekad/DwJWMQuf6Cubu2XlWffGKnT887dUPhx8QB1IlBhMzo7HzFxqahtPgfjG6fB9n2iP8P1OwnfObtpR22mdXf30mMou4wYt6YSvyK9+GiInRWEL6th8epZppu+h956HJ5QBNjbyWv1tYSlUYoSMHfb04ixMv31/GvGI810B4CVy91SUhY2Yf+xPNQ2DMfQZc9mmMBesBi9sxAcXlf6P8sLbENuZnJ+P2qXShiOW+6+D34Yi/d/uBQ46A7ehbV80k=";

/// DER encoding of the forged intermediate CA certificate.
const FORGED_INTER_CERT_DER_B64: &str = "MIIEjDCCAvSgAwIBAgIUOGInzkqKDodhP9OJegKRbVY8s9owDQYJKoZIhvcNAQELBQAwSDEgMB4GA1UEAwwXQVRMIFRlc3QgRm9yZ2VkIFJvb3QgQ0ExJDAiBgNVBAoMG0FUTCBBZHZlcnNhcmlhbCBUZXN0IENvcnB1czAeFw0yNjA4MjQwNTA3NDJaFw0zNjA4MjEwNTA3NDJaMFAxKDAmBgNVBAMMH0FUTCBUZXN0IEZvcmdlZCBJbnRlcm1lZGlhdGUgQ0ExJDAiBgNVBAoMG0FUTCBBZHZlcnNhcmlhbCBUZXN0IENvcnB1czCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALO/aT9pYsodJuKoMwyo8WR7BPoIjlQvpxvGG+klqQHuanjhL/ZX1sI+KZbAcNlEWnl2A/ZHRruZAENVRmvr/0uuI/qo5AvRhJ7bAQMTpPDNuJFXxXq7nvx9nloEGSZP9pjGfV3T1+I+mvojxivEb7ln6dhjDzMnNyV8t+O7xf5s6aHhxj9HT52vFqPWJ6LThSnhnI5T78fxYI6IMjkm7/PXEuwZJPCB87ZZG30emakIaGXwii4o2qCYOLEnsBATemmlqRe9ujeorMYQx7yHKYdTaCSSXruRtys3kmIoURblfUBXg2mU+SP7ksYhmzFUgFRDiWucbwZ4qRdjSp1jsWSGHoMWrmqmVdzqPeMPTtUhKj3ujm2lUkeHLIN47/Y1+n2M9LqVqouZDa34ygc9/zi5gJYQvB9U2vRUscK82y5ASGcA3saR0dCQ/xHPe5TLIZiNe9WoQ3LKIRHCM6vXsqnbXRIcdC48Se/E/WgPXR0+loLA2q4EOM/+knfYZCkRLwIDAQABo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUV7um8cfe9OQf/khlQSL+HnZ+eHwwHwYDVR0jBBgwFoAUbT+dlyxj6sxg3L2MB98mm24MbsswDQYJKoZIhvcNAQELBQADggGBAA9IcPu6IeJHZDrgD0yaelUeedRkEXWmyM6tgwyq3fP7Ey6vViakJjD2X70kZUIOk0oLoLBstYEDxBYmtq+gsYY0PcwgyLnGgFrQ0O6WqJMtEPA+1aPNg0SrwicSh+PcUAbYhUhjNWhgxwlV5sK0daWK6FX8L0wZY5dJrOnFn+pHxCKEwKVnLUt2lALX9Xdj4hGPaKT+mqB7Ez48r/LNHZ4kndSRZmMLRlEiWvHcFBJBGO7pytcBmvT2XvpyXbqtALGsKLLRmVSm2D6dHXPdRQTwT9WhC627JuRB9dfOmCIwRsChOfsXW6qbTrRkWqLZtIoPRqzKhRen+exJpdYaU4cDcoZ64v3woKakEjGXN61yfMW5KBqILPqV4RTQubmEI/jZc2awsnMeBBwMJAiIVMpAHlIuHgdSzeiJSqzjwqkbeLF1+kfDEUSF5gn7Oape+4TeiiB1/AgmgSVbasBvv+venFF2jZ3KLktcbC/cjjyzN+gI27mwQ035SeNBtW6Rnw==";

fn expected_root() -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(FORGED_IMPRINT_HASH_HEX, &mut out).unwrap();
    out
}

fn decode_cert(b64: &str) -> Certificate {
    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
    Certificate::from_der(&der).unwrap()
}

/// **The decisive regression test.** A complete, correctly-signed,
/// self-signed certificate chain -- root and intermediate both proper CAs,
/// leaf with a critical exclusive `id-kp-timeStamping` EKU, CMS signature
/// verifying cleanly over an arbitrary `MessageImprint` and `genTime` -- must
/// still produce a `TerminalAnchor::Assumed` and **zero** aggregate success.
/// Every individual fact below the trust line is deliberately asserted
/// `true` first, to prove this test fails for the *right* reason (no trust
/// anchor configured) and not by accident (a bug elsewhere in the pipeline).
#[test]
fn forgery_regression_self_signed_chain_never_satisfies_aggregate_success() {
    let token_der = format!("base64:{FORGED_TOKEN_B64}");
    let facts = verify_rfc3161_token(&token_der, &expected_root(), None)
        .expect("forged token parses as valid CMS/TSTInfo");

    // The forgery is "good": every fact independent of trust holds.
    assert!(facts.imprint_matches_root, "message imprint must match");
    assert!(facts.cms_signature_valid, "CMS signature must verify: {:?}", facts.diagnostic);
    assert!(facts.chain_valid_at_gen_time, "chain must be structurally/temporally valid");
    assert!(facts.timestamping_eku_ok, "leaf EKU must be correct");
    assert_eq!(facts.path_status, PathStatus::Complete);

    // And yet: no trust was established, and nothing aggregates to success.
    let fingerprint = match facts.terminal_anchor {
        Some(TerminalAnchor::Assumed { sha256_fingerprint }) => sha256_fingerprint,
        other => panic!("expected TerminalAnchor::Assumed, got {other:?}"),
    };
    assert_ne!(fingerprint, [0u8; 32]);
    assert!(
        !facts.is_fully_valid(),
        "a self-signed chain with no configured TrustStore must NEVER satisfy aggregate success"
    );
}

/// The identical forged token, but now the caller supplies the forged root
/// as a trust anchor. This is the *other* half of the regression test: the
/// exact same bytes that were correctly rejected above now correctly
/// succeed once (and only once) real trust material is supplied --
/// TrustStore is not a decoration, it is load-bearing.
#[test]
fn forgery_chain_becomes_trusted_once_its_root_is_pinned() {
    let token_der = format!("base64:{FORGED_TOKEN_B64}");
    let root_cert = decode_cert(FORGED_ROOT_CERT_DER_B64);
    let store = TrustStore::new().with_anchor_certificate(root_cert);

    let facts = verify_rfc3161_token(&token_der, &expected_root(), Some(&store)).unwrap();

    assert!(matches!(facts.terminal_anchor, Some(TerminalAnchor::Trusted { .. })));
    assert_eq!(facts.path_status, PathStatus::Complete);
    assert!(facts.is_fully_valid(), "with its root pinned, the same token must now succeed");
}

/// A certificate that is expired by wall-clock "now" (its validity window
/// ends mere minutes after it was issued) but was squarely valid at the
/// token's own `genTime` must pass -- proving certificate validity is
/// checked against `genTime`, not `SystemTime::now()`. This crate contains
/// no wall-clock read at all in the verification path; if it did, this test
/// would fail every time it ran (deterministically, not flakily) once past
/// the certificate's `notAfter`.
#[test]
fn certificate_expired_by_now_but_valid_at_gen_time_passes() {
    let token_der = format!("base64:{EXPIRING_TOKEN_B64}");
    let root_cert = decode_cert(FORGED_ROOT_CERT_DER_B64);
    let store = TrustStore::new().with_anchor_certificate(root_cert);

    let facts = verify_rfc3161_token(&token_der, &expected_root(), Some(&store)).unwrap();

    assert!(
        facts.chain_valid_at_gen_time,
        "certificate must validate at genTime even though it has since expired: {:?}",
        facts.diagnostic
    );
    assert!(facts.is_fully_valid());
}

/// A leaf certificate carrying an extension this crate does not recognize,
/// marked critical, must be rejected -- per RFC 5280, a certificate-using
/// system MUST reject a certificate with a critical extension it does not
/// understand.
#[test]
fn unrecognized_critical_extension_is_rejected() {
    let token_der = format!("base64:{UNKNOWN_CRITICAL_EXT_TOKEN_B64}");
    let root_cert = decode_cert(FORGED_ROOT_CERT_DER_B64);
    let store = TrustStore::new().with_anchor_certificate(root_cert);

    let facts = verify_rfc3161_token(&token_der, &expected_root(), Some(&store)).unwrap();

    assert!(!facts.chain_valid_at_gen_time, "unknown critical extension must invalidate the chain");
    assert_eq!(facts.path_status, PathStatus::Invalid);
    assert!(!facts.is_fully_valid());
    // The CMS signature itself is unaffected -- this is a chain-level
    // rejection, not a signature failure, and the two facts must stay
    // independent.
    assert!(facts.cms_signature_valid);
}

/// A token whose own certificate set contains *only* the leaf certificate.
/// Without any bridging material, chain construction correctly reports
/// `Incomplete` (a missing issuer is a different fact than a broken one).
#[test]
fn missing_intermediate_without_bridge_is_incomplete_not_invalid() {
    let token_der = format!("base64:{LEAF_ONLY_TOKEN_B64}");
    let root_cert = decode_cert(FORGED_ROOT_CERT_DER_B64);
    // Anchor is configured, but the intermediate needed to reach it is not
    // supplied -- there is a genuine gap, not a broken link.
    let store = TrustStore::new().with_anchor_certificate(root_cert);

    let facts = verify_rfc3161_token(&token_der, &expected_root(), Some(&store)).unwrap();

    assert_eq!(
        facts.path_status,
        PathStatus::Incomplete,
        "a missing issuer certificate must be Incomplete, not Invalid"
    );
    assert!(facts.terminal_anchor.is_none());
    assert!(!facts.is_fully_valid());
}

/// The same leaf-only token, but now the caller supplies the missing
/// intermediate via `TrustStore::with_intermediate_certificate`. This is the
/// exact mechanism the trust model requires for Sectigo/DigiCert-style
/// chains, where the token's own "root" is cross-signed by a legacy
/// certificate absent from the token: a bare SPKI-fingerprint set could
/// never substitute the missing certificate, but a `TrustStore` can.
#[test]
fn missing_intermediate_bridged_via_trust_store_reaches_trusted() {
    let token_der = format!("base64:{LEAF_ONLY_TOKEN_B64}");
    let root_cert = decode_cert(FORGED_ROOT_CERT_DER_B64);
    let inter_cert = decode_cert(FORGED_INTER_CERT_DER_B64);
    let store = TrustStore::new()
        .with_anchor_certificate(root_cert)
        .with_intermediate_certificate(inter_cert);

    let facts = verify_rfc3161_token(&token_der, &expected_root(), Some(&store)).unwrap();

    assert_eq!(facts.path_status, PathStatus::Complete);
    assert!(matches!(facts.terminal_anchor, Some(TerminalAnchor::Trusted { .. })));
    assert!(
        facts.is_fully_valid(),
        "caller-supplied intermediate must bridge the gap: {:?}",
        facts.diagnostic
    );
}

/// An SPKI pin works exactly like a full-certificate anchor for the same
/// forged root, including reaching the same fingerprint.
#[test]
fn spki_pin_is_equivalent_to_anchor_certificate() {
    let token_der = format!("base64:{FORGED_TOKEN_B64}");
    let root_cert = decode_cert(FORGED_ROOT_CERT_DER_B64);

    use der::Encode;
    use sha2::{Digest, Sha256};
    let spki_der = root_cert.tbs_certificate.subject_public_key_info.to_der().unwrap();
    let spki_pin: [u8; 32] = Sha256::digest(&spki_der).into();

    let store = TrustStore::new().with_anchor_spki_pin(spki_pin);
    let facts = verify_rfc3161_token(&token_der, &expected_root(), Some(&store)).unwrap();

    assert!(matches!(facts.terminal_anchor, Some(TerminalAnchor::Trusted { .. })));
    assert!(facts.is_fully_valid());
}
