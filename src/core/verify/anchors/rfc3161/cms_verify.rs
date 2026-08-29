//! CMS `SignerInfo` verification (RFC 5652 + RFC 2634/5035 ESS binding + RFC
//! 6211 CMS Algorithm Protection)
//!
//! Signed attributes are **required**: RFC 5652 5.3 requires
//! `content-type` and `message-digest` whenever signed attributes are used
//! at all (mandatory for content types other than `id-data`, which a
//! `TSTInfo` never is), and the ESS signing-certificate binding this module
//! also requires *is itself* a signed attribute -- a token with no signed
//! attributes has no way to satisfy it. A token that omits them is
//! rejected outright rather than falling back to signing the content
//! directly.
//!
//! # Two halves, with different evidential weight
//!
//! Verification is split across two entry points, and the split is not
//! organisational -- the halves mean different things when they fail.
//!
//! [`verify_signed_attributes`] checks what can be read from `SignerInfo`
//! and the encapsulated content alone. Its outcome is the same whichever
//! certificate a caller might try, so a failure here is a property of the
//! **token** and refuting on it is sound:
//!
//! 1. `content-type` is present exactly once and matches the encapsulated
//!    content type.
//! 2. `message-digest` is present exactly once and matches the actual
//!    digest of the encapsulated `TSTInfo` content (under
//!    `SignerInfo.digestAlgorithm`).
//! 3. An ESS signing-certificate attribute is *present* --
//!    `id-aa-signingCertificate` (v1) and/or `id-aa-signingCertificateV2`
//!    (v2) -- each at most once. At least one form MUST be present.
//! 4. `CMS Algorithm Protection` (RFC 6211), if present (at most once),
//!    agrees with `SignerInfo.digestAlgorithm`/`signatureAlgorithm`
//!    (observed on GlobalSign tokens).
//!
//! [`verify_signer_binding`] checks what depends on the candidate
//! certificate. A failure here means only "this certificate is not the
//! signer" -- never that the token is bad, because the genuine certificate
//! may be absent from an unauthenticated certificate set (RFC 5652 5.1):
//!
//! 5. The ESS signing-certificate hash matches the actual signer
//!    certificate. Every form that is present MUST match -- if both v1 and
//!    v2 are present, both are checked, so a matching v2 can never mask a
//!    mismatched v1.
//! 6. The cryptographic signature over the canonically re-encoded signed
//!    attributes verifies against that certificate's public key.
//!
//! Note that step 5's hash comparison therefore runs *after* step 4, in the
//! other function. See [`classify`] for how each failure maps onto
//! refuted-versus-indeterminate.

use cms::signed_data::SignerInfo;
use der::asn1::{ObjectIdentifier, OctetString};
use der::Encode;
use x509_cert::attr::Attribute;
use x509_cert::Certificate;

use super::algorithms::{verify_signature, DigestAlg, SigVerifyError};
use super::ess::{CmsAlgorithmProtection, SigningCertificate, SigningCertificateV2};
use super::result::CmsSignature;

/// Why CMS `SignerInfo` verification failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CmsVerifyError {
    /// The signed `content-type` attribute is missing, malformed, or does
    /// not match the encapsulated content type.
    #[error("content-type signed attribute missing or mismatched")]
    ContentTypeMismatch,
    /// The signed `message-digest` attribute is missing, malformed, or does
    /// not match the actual digest of the encapsulated content.
    #[error("message-digest signed attribute missing or mismatched")]
    MessageDigestMismatch,
    /// Neither ESS `signingCertificate` (v1) nor `signingCertificateV2` is
    /// present among the signed attributes.
    #[error("no ESS signing-certificate (v1 or v2) attribute present")]
    MissingEssBinding,
    /// The ESS signing-certificate attribute's hash does not match the
    /// actual signer certificate.
    #[error("ESS signing-certificate does not match the signer certificate")]
    EssBindingMismatch,
    /// The ESS signing-certificate attribute names a hash algorithm this
    /// crate does not implement, so the binding could not be evaluated
    /// either way. Deliberately distinct from [`Self::EssBindingMismatch`]:
    /// an unchecked binding is not a failed binding.
    #[error("ESS signing-certificate uses an unsupported hash algorithm: {0}")]
    EssBindingUnverifiable(String),
    /// A `CMS Algorithm Protection` attribute is present but disagrees with
    /// `SignerInfo.digestAlgorithm`/`signatureAlgorithm`.
    #[error("CMS Algorithm Protection attribute disagrees with SignerInfo algorithms")]
    AlgorithmProtectionMismatch,
    /// `SignerInfo` has no signed attributes at all. RFC 3161/CMS require
    /// them (they are where `content-type`, `message-digest`, and the ESS
    /// signing-certificate binding live); a token that omits them is
    /// rejected rather than falling back to signing the content directly.
    #[error("SignerInfo has no signed attributes (content-type/message-digest/ESS binding are all required)")]
    MissingSignedAttributes,
    /// A signed attribute required to appear at most once appears more
    /// than once. RFC 5652 5.3: "each type of attribute (as identified by
    /// its object identifier) MUST NOT occur more than once" - accepting a
    /// duplicate would leave which one governs verification ambiguous, and
    /// is exactly the kind of ambiguity a forger could exploit.
    #[error("signed attribute {0} occurs more than once")]
    DuplicateAttribute(String),
    /// A signed attribute was present but could not be DER-decoded as its
    /// expected type.
    #[error("malformed signed attribute: {0}")]
    MalformedAttribute(String),
    /// Signature verification itself failed.
    #[error(transparent)]
    Signature(#[from] SigVerifyError),
}

const ID_CONTENT_TYPE: ObjectIdentifier = const_oid::db::rfc5911::ID_CONTENT_TYPE;
const ID_MESSAGE_DIGEST: ObjectIdentifier = const_oid::db::rfc5911::ID_MESSAGE_DIGEST;
const ID_AA_SIGNING_CERTIFICATE: ObjectIdentifier =
    const_oid::db::rfc5911::ID_AA_SIGNING_CERTIFICATE;
const ID_AA_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    const_oid::db::rfc5911::ID_AA_SIGNING_CERTIFICATE_V_2;
/// `id-aa-cmsAlgorithmProtection` (RFC 6211), 1.2.840.113549.1.9.52. Not
/// present in `const-oid`'s generated database, so defined directly.
const ID_AA_CMS_ALGORITHM_PROTECTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.52");

/// Find a signed attribute by OID, enforcing that it occurs at most once.
///
/// Returns `Ok(None)` if absent, `Ok(Some(_))` if present exactly once, and
/// `Err(DuplicateAttribute)` if present more than once -- silently picking
/// "the first match" would leave a forger free to smuggle in a second,
/// conflicting copy of a required attribute.
fn find_attribute_at_most_once(
    attrs: &[Attribute],
    oid: ObjectIdentifier,
) -> Result<Option<&Attribute>, CmsVerifyError> {
    let mut matches = attrs.iter().filter(|a| a.oid == oid);
    let first = matches.next();
    if matches.next().is_some() {
        return Err(CmsVerifyError::DuplicateAttribute(oid.to_string()));
    }
    Ok(first)
}

/// Decode the sole value of a single-valued signed attribute.
///
/// Re-encodes the `Any` and decodes it as `T` directly (rather than
/// `Any::decode_as`, which additionally requires `T: Choice` -- a bound our
/// `Sequence`-derived ESS/CMS-Algorithm-Protection types do not carry).
fn single_value<T: der::DecodeOwned>(attr: &Attribute) -> Result<T, CmsVerifyError> {
    if attr.values.len() != 1 {
        return Err(CmsVerifyError::MalformedAttribute(format!(
            "attribute {} does not have exactly one value",
            attr.oid
        )));
    }
    let Some(any) = attr.values.get(0) else {
        // Unreachable given the length check above, but library code never
        // unwraps/expects on a path an attacker's input could in principle
        // still reach after a refactor.
        return Err(CmsVerifyError::MalformedAttribute(format!(
            "attribute {} has no value despite length check",
            attr.oid
        )));
    };
    let der_bytes = any
        .to_der()
        .map_err(|e| CmsVerifyError::MalformedAttribute(format!("{}: {e}", attr.oid)))?;
    T::from_der(&der_bytes)
        .map_err(|e| CmsVerifyError::MalformedAttribute(format!("{}: {e}", attr.oid)))
}

/// Validate every ESS signing-certificate attribute that is present --
/// never just the first one found. RFC 2634/5035 permit v1
/// (`id-aa-signingCertificate`), v2 (`id-aa-signingCertificateV2`), or both;
/// at least one MUST be present, and every one that is present MUST bind
/// the actual signer certificate. Checking v2 and returning early would let
/// a token carry a v2 attribute that matches alongside a v1 attribute that
/// does not -- silently accepting a binding that has, in fact, failed.
fn check_ess_binding(
    signed_attrs: &[Attribute],
    signer_cert_der: &[u8],
) -> Result<(), CmsVerifyError> {
    let v2 = find_attribute_at_most_once(signed_attrs, ID_AA_SIGNING_CERTIFICATE_V2)?;
    let v1 = find_attribute_at_most_once(signed_attrs, ID_AA_SIGNING_CERTIFICATE)?;

    if v1.is_none() && v2.is_none() {
        return Err(CmsVerifyError::MissingEssBinding);
    }

    if let Some(attr) = v2 {
        let sc: SigningCertificateV2 = single_value(attr)?;
        let first = sc.certs.first().ok_or(CmsVerifyError::EssBindingMismatch)?;
        let digest_alg = match &first.hash_algorithm {
            Some(alg) => DigestAlg::from_oid(&alg.oid)
                .map_err(|_| CmsVerifyError::EssBindingUnverifiable(alg.oid.to_string()))?,
            None => DigestAlg::Sha256, // RFC 5035 default
        };
        let expected = digest_alg.digest(signer_cert_der);
        if first.cert_hash.as_bytes() != expected.as_slice() {
            return Err(CmsVerifyError::EssBindingMismatch);
        }
    }

    if let Some(attr) = v1 {
        let sc: SigningCertificate = single_value(attr)?;
        let first = sc.certs.first().ok_or(CmsVerifyError::EssBindingMismatch)?;
        // RFC 2634 fixes SHA-1 for the v1 attribute.
        use sha1::{Digest, Sha1};
        let expected = Sha1::digest(signer_cert_der);
        if first.cert_hash.as_bytes() != expected.as_slice() {
            return Err(CmsVerifyError::EssBindingMismatch);
        }
    }

    Ok(())
}

fn check_algorithm_protection(
    signed_attrs: &[Attribute],
    signer_info: &SignerInfo,
) -> Result<(), CmsVerifyError> {
    let Some(attr) = find_attribute_at_most_once(signed_attrs, ID_AA_CMS_ALGORITHM_PROTECTION)?
    else {
        return Ok(()); // absent: nothing to cross-check
    };
    let protection: CmsAlgorithmProtection = single_value(attr)?;

    if protection.digest_algorithm.oid != signer_info.digest_alg.oid {
        return Err(CmsVerifyError::AlgorithmProtectionMismatch);
    }
    if let Some(sig_alg) = &protection.signature_algorithm {
        if sig_alg.oid != signer_info.signature_algorithm.oid {
            return Err(CmsVerifyError::AlgorithmProtectionMismatch);
        }
    }
    Ok(())
}

/// Split [`CmsVerifyError`] into "checked and false" and "could not check".
///
/// Only inabilities are [`CmsSignature::Indeterminate`]: algorithms this
/// crate does not implement. Note that unlike the certificate-edge path in
/// [`super::chain`], an unsupported **digest** algorithm is reachable here
/// and belongs on the indeterminate side -- CMS names its digest separately
/// (`SignerInfo.digestAlgorithm`), and without it the content digest cannot
/// be computed at all, so nothing about the signature was ever examined.
///
/// Everything else -- a missing, duplicated, malformed or mismatched signed
/// attribute, a failed ESS binding, an Algorithm Protection disagreement, or
/// a signature that simply does not verify -- is a genuine refutation.
pub(super) fn classify(err: &CmsVerifyError) -> CmsSignature {
    match err {
        CmsVerifyError::Signature(
            SigVerifyError::UnsupportedSignatureAlgorithm(_)
            | SigVerifyError::UnsupportedDigestAlgorithm(_),
        )
        | CmsVerifyError::EssBindingUnverifiable(_) => CmsSignature::Indeterminate,

        CmsVerifyError::Signature(
            SigVerifyError::BareRsaRequiresDigestHint
            | SigVerifyError::DigestAlgorithmMismatch { .. }
            | SigVerifyError::InvalidPublicKey(_)
            | SigVerifyError::InvalidSignatureEncoding(_)
            | SigVerifyError::SignatureInvalid
            | SigVerifyError::KeyFamilyMismatch { .. },
        )
        | CmsVerifyError::ContentTypeMismatch
        | CmsVerifyError::MessageDigestMismatch
        | CmsVerifyError::MissingEssBinding
        | CmsVerifyError::EssBindingMismatch
        | CmsVerifyError::AlgorithmProtectionMismatch
        | CmsVerifyError::MissingSignedAttributes
        | CmsVerifyError::DuplicateAttribute(_)
        | CmsVerifyError::MalformedAttribute(_) => CmsSignature::Refuted,
    }
}

/// Verify everything about a `SignerInfo` that does **not** depend on which
/// certificate is taken to be the signer, returning the signed attributes
/// for the certificate-dependent half.
///
/// # Why the split exists
///
/// A CMS certificate set is not covered by the signature (RFC 5652 5.1), so
/// no certificate drawn from it is known to be the signer's until its own
/// verification succeeds. That makes "every candidate failed" unable to
/// establish anything about the *signature* -- the genuine certificate may
/// simply have been removed.
///
/// The checks below are different: they read only `SignerInfo` and the
/// encapsulated content. Their outcome is the same whichever certificate a
/// caller might try, so a failure here **is** a property of the token
/// itself, and refuting on it stays sound. Keeping them apart is what lets
/// this crate still detect a tampered `message-digest` or a mismatched
/// `content-type` while refusing to over-claim about the signature.
///
/// `econtent_type` and `raw_content` are the `EncapsulatedContentInfo`'s
/// `eContentType` and the raw bytes of its `eContent` OCTET STRING (i.e. the
/// exact bytes the digest in `message-digest` is computed over).
pub(super) fn verify_signed_attributes<'a>(
    signer_info: &'a SignerInfo,
    econtent_type: ObjectIdentifier,
    raw_content: &[u8],
) -> Result<&'a cms::signed_data::SignedAttributes, CmsVerifyError> {
    let digest_alg = DigestAlg::from_oid(&signer_info.digest_alg.oid)?;
    let content_digest = digest_alg.digest(raw_content);

    // Signed attributes are mandatory: without them there is no
    // content-type/message-digest binding and, critically, no ESS
    // signing-certificate attribute at all -- there is nothing left to
    // verify the identity binding this module exists to check.
    let Some(signed_attrs) = &signer_info.signed_attrs else {
        return Err(CmsVerifyError::MissingSignedAttributes);
    };
    let attrs = signed_attrs.as_slice();

    let content_type_attr = find_attribute_at_most_once(attrs, ID_CONTENT_TYPE)?
        .ok_or(CmsVerifyError::ContentTypeMismatch)?;
    let declared_type: ObjectIdentifier = single_value(content_type_attr)?;
    if declared_type != econtent_type {
        return Err(CmsVerifyError::ContentTypeMismatch);
    }

    let digest_attr = find_attribute_at_most_once(attrs, ID_MESSAGE_DIGEST)?
        .ok_or(CmsVerifyError::MessageDigestMismatch)?;
    let declared_digest: OctetString = single_value(digest_attr)?;
    if declared_digest.as_bytes() != content_digest.as_slice() {
        return Err(CmsVerifyError::MessageDigestMismatch);
    }

    // An ESS signing-certificate attribute must be *present* and singular.
    // Whether its hash matches is certificate-dependent and belongs to
    // `verify_signer_binding`; whether one exists at all does not.
    let v2 = find_attribute_at_most_once(attrs, ID_AA_SIGNING_CERTIFICATE_V2)?;
    let v1 = find_attribute_at_most_once(attrs, ID_AA_SIGNING_CERTIFICATE)?;
    if v1.is_none() && v2.is_none() {
        return Err(CmsVerifyError::MissingEssBinding);
    }

    check_algorithm_protection(attrs, signer_info)?;

    Ok(signed_attrs)
}

/// Verify the half that **does** depend on the candidate certificate: the
/// ESS signing-certificate binding and the cryptographic signature.
///
/// A failure here means only "this certificate is not the signer". It never
/// establishes that the token's signature is bad, because the genuine
/// certificate may be absent from an unauthenticated certificate set -- see
/// [`verify_signed_attributes`].
pub(super) fn verify_signer_binding(
    signer_info: &SignerInfo,
    signed_attrs: &cms::signed_data::SignedAttributes,
    signer_cert: &Certificate,
) -> Result<(), CmsVerifyError> {
    let signer_cert_der =
        signer_cert.to_der().map_err(|e| CmsVerifyError::MalformedAttribute(e.to_string()))?;
    check_ess_binding(signed_attrs.as_slice(), &signer_cert_der)?;

    // RFC 5652 5.4: signed attributes are re-encoded as an ordinary SET OF
    // for the purposes of digesting/signing, not with the [0] IMPLICIT tag
    // used on the wire.
    let signed_bytes =
        signed_attrs.to_der().map_err(|e| CmsVerifyError::MalformedAttribute(e.to_string()))?;

    verify_signature(
        &signer_cert.tbs_certificate.subject_public_key_info,
        &signer_info.signature_algorithm,
        Some(&signer_info.digest_alg),
        &signed_bytes,
        signer_info.signature.as_bytes(),
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    //! Unit tests for signed-attribute cardinality and ESS binding,
    //! constructed directly from this crate's own types rather than
    //! hand-crafted DER bytes -- more direct, and immune to bit-rot in an
    //! external fixture file.

    use super::*;
    use der::asn1::SetOfVec;
    use der::Decode;
    use sha1::Sha1;
    use sha2::{Digest, Sha256};

    /// A minimal, syntactically valid "signer certificate" DER blob for
    /// hashing purposes. Its content doesn't matter -- these tests only
    /// need *some* fixed bytes to compute a correct vs. an incorrect
    /// `certHash` against.
    const FAKE_SIGNER_CERT_DER: &[u8] = b"not a real certificate, just bytes to hash";

    fn attr(oid: ObjectIdentifier, value: impl Encode) -> Attribute {
        let der = value.to_der().expect("test value encodes");
        let any = der::asn1::Any::from_der(&der).expect("re-decodes as Any");
        Attribute { oid, values: SetOfVec::try_from(vec![any]).expect("single value") }
    }

    fn signing_certificate_v2(cert_hash: &[u8]) -> SigningCertificateV2 {
        use super::super::ess::EssCertIdV2;
        SigningCertificateV2 {
            certs: vec![EssCertIdV2 {
                hash_algorithm: None, // RFC 5035 default: SHA-256
                cert_hash: OctetString::new(cert_hash.to_vec()).unwrap(),
                issuer_serial: None,
            }],
            policies: None,
        }
    }

    fn signing_certificate_v1(cert_hash: &[u8]) -> SigningCertificate {
        use super::super::ess::EssCertId;
        SigningCertificate {
            certs: vec![EssCertId {
                cert_hash: OctetString::new(cert_hash.to_vec()).unwrap(),
                issuer_serial: None,
            }],
            policies: None,
        }
    }

    #[test]
    fn missing_ess_binding_is_rejected() {
        // No id-aa-signingCertificate/V2 attribute at all -- just an
        // unrelated attribute, so signed_attrs isn't trivially empty.
        let unrelated = attr(ID_CONTENT_TYPE, ObjectIdentifier::new_unwrap("1.2.3.4"));
        let result = check_ess_binding(&[unrelated], FAKE_SIGNER_CERT_DER);
        assert_eq!(result, Err(CmsVerifyError::MissingEssBinding));
    }

    #[test]
    fn duplicate_ess_attribute_is_rejected() {
        let correct_hash = Sha256::digest(FAKE_SIGNER_CERT_DER);
        let a = attr(ID_AA_SIGNING_CERTIFICATE_V2, signing_certificate_v2(&correct_hash));
        // A second v2 attribute -- byte-distinct (different hash), but the
        // same attribute *type*, which is exactly what MUST NOT occur more
        // than once per RFC 5652 5.3.
        let wrong_hash: Vec<u8> = correct_hash.iter().map(|b| b ^ 0xFF).collect();
        let b = attr(ID_AA_SIGNING_CERTIFICATE_V2, signing_certificate_v2(&wrong_hash));

        let result = check_ess_binding(&[a, b], FAKE_SIGNER_CERT_DER);
        assert_eq!(
            result,
            Err(CmsVerifyError::DuplicateAttribute(ID_AA_SIGNING_CERTIFICATE_V2.to_string()))
        );
    }

    #[test]
    fn conflicting_v1_and_v2_is_rejected_even_though_v2_matches() {
        // v2 matches the real signer certificate...
        let correct_hash = Sha256::digest(FAKE_SIGNER_CERT_DER);
        let v2 = attr(ID_AA_SIGNING_CERTIFICATE_V2, signing_certificate_v2(&correct_hash));
        // ...but v1 is also present and does NOT match. A verifier that
        // checks v2 and stops (the bug this module's design guards
        // against) would wrongly accept this token.
        let wrong_sha1 = [0u8; 20];
        let v1 = attr(ID_AA_SIGNING_CERTIFICATE, signing_certificate_v1(&wrong_sha1));

        let result = check_ess_binding(&[v2, v1], FAKE_SIGNER_CERT_DER);
        assert_eq!(result, Err(CmsVerifyError::EssBindingMismatch));
    }

    #[test]
    fn both_v1_and_v2_matching_is_accepted() {
        let correct_sha256 = Sha256::digest(FAKE_SIGNER_CERT_DER);
        let correct_sha1 = Sha1::digest(FAKE_SIGNER_CERT_DER);
        let v2 = attr(ID_AA_SIGNING_CERTIFICATE_V2, signing_certificate_v2(&correct_sha256));
        let v1 = attr(ID_AA_SIGNING_CERTIFICATE, signing_certificate_v1(&correct_sha1));

        assert_eq!(check_ess_binding(&[v2, v1], FAKE_SIGNER_CERT_DER), Ok(()));
    }

    /// **The blocker regression.** An algorithm this crate does not
    /// implement must classify as `Indeterminate`, never `Refuted`. Under
    /// the old `is_ok()` collapse, a token from a TSA using P-521 or RSA-PSS
    /// -- both explicitly unimplemented in `algorithms` -- was published as
    /// "the signature is invalid", i.e. refuted evidence, on the strength of
    /// a check that never ran.
    #[test]
    fn unsupported_algorithms_are_indeterminate_not_refuted() {
        for err in [
            CmsVerifyError::Signature(SigVerifyError::UnsupportedSignatureAlgorithm(
                "1.2.840.113549.1.1.10".to_string(), // RSASSA-PSS
            )),
            CmsVerifyError::Signature(SigVerifyError::UnsupportedDigestAlgorithm(
                "2.16.840.1.101.3.4.2.4".to_string(), // SHA-224
            )),
            CmsVerifyError::Signature(SigVerifyError::UnsupportedSignatureAlgorithm(
                "unsupported EC curve 1.3.132.0.35".to_string(), // P-521
            )),
            CmsVerifyError::EssBindingUnverifiable("1.3.14.3.2.26".to_string()),
        ] {
            assert_eq!(
                classify(&err),
                CmsSignature::Indeterminate,
                "must not be reported as a refutation: {err}"
            );
        }
    }

    /// Everything that *was* checked and came out false stays a refutation
    /// -- the fix must not soften real failures into "cannot tell".
    #[test]
    fn checked_failures_stay_refutations() {
        for err in [
            CmsVerifyError::Signature(SigVerifyError::SignatureInvalid),
            CmsVerifyError::Signature(SigVerifyError::InvalidPublicKey("bad".to_string())),
            CmsVerifyError::Signature(SigVerifyError::InvalidSignatureEncoding("bad".to_string())),
            CmsVerifyError::Signature(SigVerifyError::KeyFamilyMismatch {
                claimed_family: "ECDSA",
                actual_family: "RSA",
            }),
            CmsVerifyError::Signature(SigVerifyError::BareRsaRequiresDigestHint),
            CmsVerifyError::ContentTypeMismatch,
            CmsVerifyError::MessageDigestMismatch,
            CmsVerifyError::MissingEssBinding,
            CmsVerifyError::EssBindingMismatch,
            CmsVerifyError::AlgorithmProtectionMismatch,
            CmsVerifyError::MissingSignedAttributes,
            CmsVerifyError::DuplicateAttribute("1.2.3".to_string()),
            CmsVerifyError::MalformedAttribute("1.2.3".to_string()),
        ] {
            assert_eq!(classify(&err), CmsSignature::Refuted, "must stay a refutation: {err}");
        }
    }

    /// An ESS binding whose hash algorithm is unimplemented must report
    /// "could not check", not "the binding is wrong". SHA-1 in an
    /// `ESSCertIDv2` is the realistic case.
    #[test]
    fn unsupported_ess_hash_algorithm_is_unverifiable_not_a_mismatch() {
        use super::super::ess::EssCertIdV2;
        use spki::AlgorithmIdentifierOwned;

        let sha1 = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
        let sc = SigningCertificateV2 {
            certs: vec![EssCertIdV2 {
                hash_algorithm: Some(AlgorithmIdentifierOwned { oid: sha1, parameters: None }),
                cert_hash: OctetString::new(vec![0u8; 20]).unwrap(),
                issuer_serial: None,
            }],
            policies: None,
        };
        let attrs = [attr(ID_AA_SIGNING_CERTIFICATE_V2, sc)];

        let err = check_ess_binding(&attrs, FAKE_SIGNER_CERT_DER).expect_err("must not verify");
        assert!(
            matches!(err, CmsVerifyError::EssBindingUnverifiable(_)),
            "an unimplemented hash must not masquerade as a binding mismatch: {err}"
        );
        assert_eq!(classify(&err), CmsSignature::Indeterminate);
    }

    #[test]
    fn duplicate_content_type_attribute_is_rejected() {
        let a = attr(ID_CONTENT_TYPE, ObjectIdentifier::new_unwrap("1.2.3.4"));
        let b = attr(ID_CONTENT_TYPE, ObjectIdentifier::new_unwrap("1.2.3.5"));
        let attrs = [a, b];
        let result = find_attribute_at_most_once(&attrs, ID_CONTENT_TYPE);
        assert_eq!(result, Err(CmsVerifyError::DuplicateAttribute(ID_CONTENT_TYPE.to_string())));
    }
}
