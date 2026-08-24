//! Digest and signature algorithm dispatch
//!
//! Covers the algorithm matrix observed across real-world TSA tokens
//! (FreeTSA, Sectigo, DigiCert, GlobalSign): RSA PKCS#1 v1.5 (3072/4096-bit
//! keys, SHA-256/384/512, both the bare `rsaEncryption` OID and the
//! composite `shaNNNWithRSAEncryption` OIDs) and ECDSA on P-384 with a
//! SHA-512 digest. ECDSA on P-256 is also implemented (RustCrypto gives it
//! to us at no extra cost) even though it was not observed in the corpus and
//! has no dedicated test fixture yet.
//!
//! **Not implemented**: P-521 and RSA-PSS. Neither OID resolves in
//! [`resolve_digest`]/[`verify_signature`] below; a token using either is
//! rejected with [`SigVerifyError::UnsupportedSignatureAlgorithm`], not
//! silently mishandled. Add them deliberately (with fixtures) if a real TSA
//! is ever observed using them -- do not claim support without one.
//!
//! # The bare-`rsaEncryption` rule
//!
//! CMS lets a `SignerInfo.signatureAlgorithm` name the *cipher* alone
//! (`rsaEncryption`, 1.2.840.113549.1.1.1) and leave the digest to
//! `SignerInfo.digestAlgorithm`, or name a composite OID that fixes both
//! (`sha384WithRSAEncryption`, ...). Certificate signatures never use the
//! bare form (RFC 5280 always composites), so `digest_hint` is `None` for
//! chain-edge verification and `Some(SignerInfo.digest_alg)` for CMS
//! `SignerInfo` verification. A composite OID's fixed digest must match the
//! hint when one is supplied (otherwise the combination is nonsensical and
//! rejected), never derived from the certificate.

use der::Encode;
use ecdsa::signature::hazmat::PrehashVerifier;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::der::asn1::ObjectIdentifier;

/// Why signature verification could not even be attempted or definitively
/// failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SigVerifyError {
    /// The bare `rsaEncryption` OID was used without a digest hint (only
    /// legal for CMS `SignerInfo`, where the hint comes from
    /// `digestAlgorithm`).
    #[error("bare rsaEncryption signature algorithm requires a digest algorithm hint")]
    BareRsaRequiresDigestHint,
    /// A composite `shaNNNWithRSAEncryption` / `ecdsa-with-SHAnnn` OID's
    /// fixed digest does not match the supplied digest hint.
    #[error("signature algorithm fixes digest {fixed}, but digest hint is {hint}")]
    DigestAlgorithmMismatch {
        /// Digest fixed by the composite signature algorithm OID.
        fixed: String,
        /// Digest named separately (e.g. `SignerInfo.digestAlgorithm`).
        hint: String,
    },
    /// The signature algorithm OID is not one this crate implements.
    #[error("unsupported signature algorithm OID {0}")]
    UnsupportedSignatureAlgorithm(String),
    /// The digest algorithm OID is not one this crate implements.
    #[error("unsupported digest algorithm OID {0}")]
    UnsupportedDigestAlgorithm(String),
    /// The public key could not be decoded for this algorithm (wrong type,
    /// unsupported curve, malformed SPKI, ...).
    #[error("could not decode public key: {0}")]
    InvalidPublicKey(String),
    /// The signature bytes could not be decoded for this algorithm.
    #[error("could not decode signature: {0}")]
    InvalidSignatureEncoding(String),
    /// The cryptographic signature verification itself failed (the
    /// signature does not match the data under this key).
    #[error("signature verification failed")]
    SignatureInvalid,
    /// The `signatureAlgorithm` names one key family (e.g. ECDSA) but the
    /// `SubjectPublicKeyInfo` actually holds a key of a different family
    /// (e.g. RSA). This is the exact substitution a forger would attempt --
    /// declare `ecdsa-with-SHA512` while shipping an RSA key and an RSA
    /// signature, hoping the verifier dispatches on the OID it wants to see
    /// rather than the OID that matches the key it actually has. Rejected
    /// before any cryptographic verification is attempted.
    #[error("signature algorithm claims {claimed_family} but the public key is {actual_family}")]
    KeyFamilyMismatch {
        /// Key family implied by `signatureAlgorithm`.
        claimed_family: &'static str,
        /// Key family actually present in `SubjectPublicKeyInfo`.
        actual_family: &'static str,
    },
}

/// A supported message-digest algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlg {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl DigestAlg {
    /// Match a digest algorithm OID.
    pub(super) fn from_oid(oid: &ObjectIdentifier) -> Result<Self, SigVerifyError> {
        use const_oid::db::rfc5912::{ID_SHA_256, ID_SHA_384, ID_SHA_512};
        match *oid {
            ID_SHA_256 => Ok(Self::Sha256),
            ID_SHA_384 => Ok(Self::Sha384),
            ID_SHA_512 => Ok(Self::Sha512),
            other => Err(SigVerifyError::UnsupportedDigestAlgorithm(other.to_string())),
        }
    }

    /// Compute the digest of `data`.
    #[must_use]
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256, Sha384, Sha512};
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// The key family a `signatureAlgorithm` OID commits to.
///
/// This is deliberately its own type, checked against the actual
/// `SubjectPublicKeyInfo` before any cryptographic verification is
/// attempted (see [`verify_signature`]): dispatching purely on the SPKI's
/// key type while trusting the caller-controlled `signatureAlgorithm` for
/// the digest would let a forger declare `ecdsa-with-SHA512` over an RSA
/// key and RSA signature, and have it verified as "RSA/SHA-512" -- the
/// digest matches, the RSA math checks out, and the mismatch between what
/// was *claimed* and what was *signed with* is silently ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KeyFamily {
    Rsa,
    Ecdsa,
}

impl KeyFamily {
    const fn label(self) -> &'static str {
        match self {
            Self::Rsa => "RSA",
            Self::Ecdsa => "ECDSA",
        }
    }
}

/// Resolve a `SignerInfo`/certificate `signatureAlgorithm` OID into the key
/// family and digest it commits to, applying the bare-vs-composite RSA rule
/// and the "CMS Algorithm Protection" compatible cross-check for
/// ECDSA/composite-RSA OIDs (which always fix their own digest).
fn resolve_digest(
    sig_alg_oid: &ObjectIdentifier,
    digest_hint: Option<&AlgorithmIdentifierOwned>,
) -> Result<(KeyFamily, DigestAlg), SigVerifyError> {
    use const_oid::db::rfc5912::{
        ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512, RSA_ENCRYPTION,
        SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
    };

    let (family, fixed) = match *sig_alg_oid {
        RSA_ENCRYPTION => {
            // Bare rsaEncryption: the digest comes entirely from the hint.
            let hint = digest_hint.ok_or(SigVerifyError::BareRsaRequiresDigestHint)?;
            return Ok((KeyFamily::Rsa, DigestAlg::from_oid(&hint.oid)?));
        }
        SHA_256_WITH_RSA_ENCRYPTION => (KeyFamily::Rsa, DigestAlg::Sha256),
        SHA_384_WITH_RSA_ENCRYPTION => (KeyFamily::Rsa, DigestAlg::Sha384),
        SHA_512_WITH_RSA_ENCRYPTION => (KeyFamily::Rsa, DigestAlg::Sha512),
        ECDSA_WITH_SHA_256 => (KeyFamily::Ecdsa, DigestAlg::Sha256),
        ECDSA_WITH_SHA_384 => (KeyFamily::Ecdsa, DigestAlg::Sha384),
        ECDSA_WITH_SHA_512 => (KeyFamily::Ecdsa, DigestAlg::Sha512),
        other => return Err(SigVerifyError::UnsupportedSignatureAlgorithm(other.to_string())),
    };

    if let Some(hint) = digest_hint {
        let hinted = DigestAlg::from_oid(&hint.oid)?;
        if hinted != fixed {
            return Err(SigVerifyError::DigestAlgorithmMismatch {
                fixed: format!("{fixed:?}"),
                hint: format!("{hinted:?}"),
            });
        }
    }

    Ok((family, fixed))
}

/// Verify a signature over `signed_bytes` under `spki`, per `sig_alg`.
///
/// `digest_hint` is `Some(SignerInfo.digestAlgorithm)` for CMS `SignerInfo`
/// verification (needed to resolve a bare `rsaEncryption` OID) and `None`
/// for certificate chain-edge verification (where the bare form is not
/// legal per RFC 5280).
pub(super) fn verify_signature(
    spki: &SubjectPublicKeyInfoOwned,
    sig_alg: &AlgorithmIdentifierOwned,
    digest_hint: Option<&AlgorithmIdentifierOwned>,
    signed_bytes: &[u8],
    signature: &[u8],
) -> Result<(), SigVerifyError> {
    use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION};

    let (claimed_family, digest_alg) = resolve_digest(&sig_alg.oid, digest_hint)?;

    // The key family the SPKI actually holds, independent of what
    // `signatureAlgorithm` claims.
    let actual_family = match spki.algorithm.oid {
        RSA_ENCRYPTION => KeyFamily::Rsa,
        ID_EC_PUBLIC_KEY => KeyFamily::Ecdsa,
        other => {
            return Err(SigVerifyError::UnsupportedSignatureAlgorithm(format!(
                "unsupported public key algorithm {other}"
            )))
        }
    };

    // The two families MUST agree before any cryptographic verification is
    // attempted: dispatching on `actual_family` alone (as if the claimed
    // family didn't matter) would silently accept a signature algorithm
    // that names a different family than the key actually is.
    if claimed_family != actual_family {
        return Err(SigVerifyError::KeyFamilyMismatch {
            claimed_family: claimed_family.label(),
            actual_family: actual_family.label(),
        });
    }

    let digest = digest_alg.digest(signed_bytes);

    match actual_family {
        KeyFamily::Rsa => verify_rsa(spki, digest_alg, &digest, signature),
        KeyFamily::Ecdsa => verify_ecdsa(spki, &digest, signature),
    }
}

fn verify_rsa(
    spki: &SubjectPublicKeyInfoOwned,
    digest_alg: DigestAlg,
    digest: &[u8],
    signature: &[u8],
) -> Result<(), SigVerifyError> {
    use rsa::pkcs1v15::Pkcs1v15Sign;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::SignatureScheme;
    use rsa::RsaPublicKey;
    use sha2::{Sha256, Sha384, Sha512};

    let spki_der = spki.to_der().map_err(|e| SigVerifyError::InvalidPublicKey(e.to_string()))?;
    let public_key = RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| SigVerifyError::InvalidPublicKey(e.to_string()))?;

    let scheme = match digest_alg {
        DigestAlg::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
        DigestAlg::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
        DigestAlg::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
    };

    scheme.verify(&public_key, digest, signature).map_err(|_| SigVerifyError::SignatureInvalid)
}

fn verify_ecdsa(
    spki: &SubjectPublicKeyInfoOwned,
    digest: &[u8],
    signature: &[u8],
) -> Result<(), SigVerifyError> {
    // The curve lives in the SPKI algorithm parameters (namedCurve OID), not
    // in the signature algorithm -- ecdsa-with-SHA512 says nothing about
    // which curve, that's entirely determined by the key.
    use const_oid::db::rfc5912::{SECP_256_R_1, SECP_384_R_1};

    let params =
        spki.algorithm.parameters.as_ref().ok_or_else(|| {
            SigVerifyError::InvalidPublicKey("missing EC curve parameters".into())
        })?;
    let curve_oid: ObjectIdentifier = params
        .decode_as()
        .map_err(|e| SigVerifyError::InvalidPublicKey(format!("bad EC curve OID: {e}")))?;

    let spki_der = spki.to_der().map_err(|e| SigVerifyError::InvalidPublicKey(e.to_string()))?;

    match curve_oid {
        SECP_384_R_1 => {
            use ecdsa::der::Signature as DerSignature;
            use p384::ecdsa::VerifyingKey;
            use p384::pkcs8::DecodePublicKey;

            let key = VerifyingKey::from_public_key_der(&spki_der)
                .map_err(|e| SigVerifyError::InvalidPublicKey(e.to_string()))?;
            let sig = DerSignature::<p384::NistP384>::from_bytes(signature)
                .map_err(|e| SigVerifyError::InvalidSignatureEncoding(e.to_string()))?;
            key.verify_prehash(digest, &sig).map_err(|_| SigVerifyError::SignatureInvalid)
        }
        SECP_256_R_1 => {
            use ecdsa::der::Signature as DerSignature;
            use p256::ecdsa::VerifyingKey;
            use p256::pkcs8::DecodePublicKey;

            let key = VerifyingKey::from_public_key_der(&spki_der)
                .map_err(|e| SigVerifyError::InvalidPublicKey(e.to_string()))?;
            let sig = DerSignature::<p256::NistP256>::from_bytes(signature)
                .map_err(|e| SigVerifyError::InvalidSignatureEncoding(e.to_string()))?;
            key.verify_prehash(digest, &sig).map_err(|_| SigVerifyError::SignatureInvalid)
        }
        other => Err(SigVerifyError::UnsupportedSignatureAlgorithm(format!(
            "unsupported EC curve {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    //! Algorithm-family-confusion regression tests.
    //!
    //! The whole point of [`verify_signature`]'s family check is that it
    //! must reject a mismatch *before* attempting any cryptographic
    //! verification -- so these tests use syntactically-arbitrary signature
    //! bytes throughout. If the mismatch were not caught up front, an
    //! attacker who also controlled the signature bytes could try to craft
    //! something that verifies under the "wrong" scheme; catching the
    //! mismatch first means that possibility is foreclosed entirely,
    //! regardless of what the signature bytes contain.

    use super::*;
    use der::Decode;
    use x509_cert::Certificate;

    /// A real RSA (4096-bit) `SubjectPublicKeyInfo`, from the forged test
    /// CA hierarchy's root certificate (see `rfc3161_adversarial_tests.rs`
    /// for how it was generated -- reused here only for its key material,
    /// unrelated to any of that module's chain-building tests).
    const RSA_CERT_DER_B64: &str = "MIIEgTCCAumgAwIBAgIUARkOOwEJ2sB9s0zfODbsaLeBgSgwDQYJKoZIhvcNAQELBQAwSDEgMB4GA1UEAwwXQVRMIFRlc3QgRm9yZ2VkIFJvb3QgQ0ExJDAiBgNVBAoMG0FUTCBBZHZlcnNhcmlhbCBUZXN0IENvcnB1czAeFw0yNjA4MjQwNTA3NDJaFw0zNjA4MjEwNTA3NDJaMEgxIDAeBgNVBAMMF0FUTCBUZXN0IEZvcmdlZCBSb290IENBMSQwIgYDVQQKDBtBVEwgQWR2ZXJzYXJpYWwgVGVzdCBDb3JwdXMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCpfslT3YSjFNVHwNxPHrrOfpSqgugiJw0fSbltY6e5tHakGHWulYXxihSKnfirYWVKtwdGSolKjA9lEvuPRQykolDnMsVdAuyfD6XY6maji+23RXr/VmciNZPoJRRZ3ftNADvcJbW7wo5/n0qTSaotRPg64FL9ZE0qNKVuEGJKxTOQ3Fm26FXgSwRX+hqWAgSCIsTZuQVOC+4snSoRzLHAR18PUWp2hPRh+EUVrIU/PioY8qo5P463KOswKnMHyWvTCD97kPU0crpXIJU4GdlOe8T+UnyLhIQxEPhhL07uUk6u+jm/Ud1fWj/qrpu6u/tV0PHYHzWOIUp3+gEBZpoG8Wc32wTtzxtnyVmsEr4UoNkv1J0uBo639m558/cmAkheTKmG2N00fxQxgdlXlRcIPes08chXGTQPYBShVELMuR+DL+VUfJj+N9X2gmu7aYgDXCS0lTDuKtLzb+t3eoWy6RK2VxHDuxz8r4QEZiaz4b6cWB42fnMO38GgBi5Ew3UCAwEAAaNjMGEwHwYDVR0jBBgwFoAUbT+dlyxj6sxg3L2MB98mm24MbsswDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFG0/nZcsY+rMYNy9jAffJptuDG7LMA0GCSqGSIb3DQEBCwUAA4IBgQBQSn60GeRKZOjM3D67VT4Do3pZeUflrpiej7IdKhYdTVt9uAUTH5T7/E6S1FRBBv7OvP+CJp3bK4U+z5GQ40ynvKHZ766Ud0gLRApZ7+nvzwi6l7+L5wbt8PTYRwqFWWDXoaYJ65fUaz5qf4JLxWY7yc86vb/HreQLbSSjsxCe7k5+cVJgfqro93gAgFajt20uGXfXvbtYGT/ZEpN20nqft/amPXTEz2VEYQ3MEDjMmAjdwOrhjxhZQ3+2TII5/Ekad/DwJWMQuf6Cubu2XlWffGKnT887dUPhx8QB1IlBhMzo7HzFxqahtPgfjG6fB9n2iP8P1OwnfObtpR22mdXf30mMou4wYt6YSvyK9+GiInRWEL6th8epZppu+h956HJ5QBNjbyWv1tYSlUYoSMHfb04ixMv31/GvGI810B4CVy91SUhY2Yf+xPNQ2DMfQZc9mmMBesBi9sxAcXlf6P8sLbENuZnJ+P2qXShiOW+6+D34Yi/d/uBQ46A7ehbV80k=";

    /// A real ECDSA P-384 `SubjectPublicKeyInfo`, extracted from a real
    /// FreeTSA leaf certificate in the corpus used by
    /// `rfc3161_corpus_tests.rs`.
    const ECDSA_CERT_DER_B64: &str = "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";

    fn decode_spki(cert_der_b64: &str) -> SubjectPublicKeyInfoOwned {
        use base64::Engine;
        let der = base64::engine::general_purpose::STANDARD.decode(cert_der_b64).unwrap();
        let cert = Certificate::from_der(&der).unwrap();
        cert.tbs_certificate.subject_public_key_info
    }

    fn alg_id(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned { oid, parameters: None }
    }

    /// `signatureAlgorithm` claims ECDSA, but the key is RSA: rejected
    /// before any cryptographic verification, regardless of what the
    /// "signature" bytes contain.
    #[test]
    fn ecdsa_signature_algorithm_over_rsa_key_is_rejected() {
        use const_oid::db::rfc5912::ECDSA_WITH_SHA_256;

        let spki = decode_spki(RSA_CERT_DER_B64);
        let sig_alg = alg_id(ECDSA_WITH_SHA_256);

        let result = verify_signature(
            &spki,
            &sig_alg,
            None,
            b"arbitrary signed content",
            b"not a real signature",
        );

        assert_eq!(
            result,
            Err(SigVerifyError::KeyFamilyMismatch {
                claimed_family: "ECDSA",
                actual_family: "RSA",
            })
        );
    }

    /// `signatureAlgorithm` claims RSA, but the key is ECDSA: rejected the
    /// same way, in the opposite direction.
    #[test]
    fn rsa_signature_algorithm_over_ecdsa_key_is_rejected() {
        use const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION;

        let spki = decode_spki(ECDSA_CERT_DER_B64);
        let sig_alg = alg_id(SHA_256_WITH_RSA_ENCRYPTION);

        let result = verify_signature(
            &spki,
            &sig_alg,
            None,
            b"arbitrary signed content",
            b"not a real signature",
        );

        assert_eq!(
            result,
            Err(SigVerifyError::KeyFamilyMismatch {
                claimed_family: "RSA",
                actual_family: "ECDSA",
            })
        );
    }

    /// Sanity check that a *matching* family/key combination is not
    /// rejected by the family check itself (it still fails, because the
    /// signature bytes are garbage -- but for the right reason).
    #[test]
    fn matching_family_is_not_rejected_by_the_family_check() {
        use const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION;

        let spki = decode_spki(RSA_CERT_DER_B64);
        let sig_alg = alg_id(SHA_256_WITH_RSA_ENCRYPTION);

        let result = verify_signature(
            &spki,
            &sig_alg,
            None,
            b"arbitrary signed content",
            b"not a real signature",
        );

        // Must fail (the signature is garbage), but NOT with
        // KeyFamilyMismatch -- the families agree.
        assert_eq!(result, Err(SigVerifyError::SignatureInvalid));
    }
}
