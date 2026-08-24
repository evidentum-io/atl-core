//! CMS `SignerInfo` verification (RFC 5652 + RFC 2634/5035 ESS binding + RFC
//! 6211 CMS Algorithm Protection)
//!
//! Verifies, in order:
//!
//! 1. The `content-type` signed attribute matches the encapsulated content
//!    type.
//! 2. The `message-digest` signed attribute matches the actual digest of
//!    the encapsulated `TSTInfo` content (under `SignerInfo.digestAlgorithm`).
//! 3. The signer certificate is bound via the ESS signing-certificate
//!    attribute (v1 `id-aa-signingCertificate` and/or v2
//!    `id-aa-signingCertificateV2`).
//! 4. If present, `CMS Algorithm Protection` (RFC 6211) agrees with
//!    `SignerInfo.digestAlgorithm`/`signatureAlgorithm` (observed on
//!    GlobalSign tokens).
//! 5. The cryptographic signature over the (canonically re-encoded) signed
//!    attributes -- or, if there are no signed attributes, over the content
//!    directly -- verifies against the signer certificate's public key.

use cms::signed_data::SignerInfo;
use der::asn1::{ObjectIdentifier, OctetString};
use der::Encode;
use x509_cert::attr::Attribute;
use x509_cert::Certificate;

use super::algorithms::{verify_signature, DigestAlg, SigVerifyError};
use super::ess::{CmsAlgorithmProtection, SigningCertificate, SigningCertificateV2};

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
    /// A `CMS Algorithm Protection` attribute is present but disagrees with
    /// `SignerInfo.digestAlgorithm`/`signatureAlgorithm`.
    #[error("CMS Algorithm Protection attribute disagrees with SignerInfo algorithms")]
    AlgorithmProtectionMismatch,
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

fn find_attribute(attrs: &[Attribute], oid: ObjectIdentifier) -> Option<&Attribute> {
    attrs.iter().find(|a| a.oid == oid)
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

fn check_ess_binding(
    signed_attrs: &[Attribute],
    signer_cert_der: &[u8],
) -> Result<(), CmsVerifyError> {
    if let Some(attr) = find_attribute(signed_attrs, ID_AA_SIGNING_CERTIFICATE_V2) {
        let sc: SigningCertificateV2 = single_value(attr)?;
        let first = sc.certs.first().ok_or(CmsVerifyError::EssBindingMismatch)?;
        let digest_alg = match &first.hash_algorithm {
            Some(alg) => {
                DigestAlg::from_oid(&alg.oid).map_err(|_| CmsVerifyError::EssBindingMismatch)?
            }
            None => DigestAlg::Sha256, // RFC 5035 default
        };
        let expected = digest_alg.digest(signer_cert_der);
        if first.cert_hash.as_bytes() == expected.as_slice() {
            return Ok(());
        }
        return Err(CmsVerifyError::EssBindingMismatch);
    }

    if let Some(attr) = find_attribute(signed_attrs, ID_AA_SIGNING_CERTIFICATE) {
        let sc: SigningCertificate = single_value(attr)?;
        let first = sc.certs.first().ok_or(CmsVerifyError::EssBindingMismatch)?;
        // RFC 2634 fixes SHA-1 for the v1 attribute.
        use sha1::{Digest, Sha1};
        let expected = Sha1::digest(signer_cert_der);
        if first.cert_hash.as_bytes() == expected.as_slice() {
            return Ok(());
        }
        return Err(CmsVerifyError::EssBindingMismatch);
    }

    Err(CmsVerifyError::MissingEssBinding)
}

fn check_algorithm_protection(
    signed_attrs: &[Attribute],
    signer_info: &SignerInfo,
) -> Result<(), CmsVerifyError> {
    let Some(attr) = find_attribute(signed_attrs, ID_AA_CMS_ALGORITHM_PROTECTION) else {
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

/// Verify a CMS `SignerInfo` against the encapsulated `TSTInfo` content and
/// the signer's certificate.
///
/// `econtent_type` and `raw_content` are the `EncapsulatedContentInfo`'s
/// `eContentType` and the raw bytes of its `eContent` OCTET STRING (i.e. the
/// exact bytes the digest in `message-digest` is computed over).
pub(super) fn verify_signer_info(
    signer_info: &SignerInfo,
    signer_cert: &Certificate,
    econtent_type: ObjectIdentifier,
    raw_content: &[u8],
) -> Result<(), CmsVerifyError> {
    let digest_alg = DigestAlg::from_oid(&signer_info.digest_alg.oid)?;
    let content_digest = digest_alg.digest(raw_content);

    let signed_bytes = match &signer_info.signed_attrs {
        Some(signed_attrs) => {
            let attrs = signed_attrs.as_slice();

            let content_type_attr = find_attribute(attrs, ID_CONTENT_TYPE)
                .ok_or(CmsVerifyError::ContentTypeMismatch)?;
            let declared_type: ObjectIdentifier = single_value(content_type_attr)?;
            if declared_type != econtent_type {
                return Err(CmsVerifyError::ContentTypeMismatch);
            }

            let digest_attr = find_attribute(attrs, ID_MESSAGE_DIGEST)
                .ok_or(CmsVerifyError::MessageDigestMismatch)?;
            let declared_digest: OctetString = single_value(digest_attr)?;
            if declared_digest.as_bytes() != content_digest.as_slice() {
                return Err(CmsVerifyError::MessageDigestMismatch);
            }

            let signer_cert_der = signer_cert
                .to_der()
                .map_err(|e| CmsVerifyError::MalformedAttribute(e.to_string()))?;
            check_ess_binding(attrs, &signer_cert_der)?;
            check_algorithm_protection(attrs, signer_info)?;

            // RFC 5652 5.4: signed attributes are re-encoded as an ordinary
            // SET OF for the purposes of digesting/signing, not with the
            // [0] IMPLICIT tag used on the wire.
            signed_attrs.to_der().map_err(|e| CmsVerifyError::MalformedAttribute(e.to_string()))?
        }
        None => raw_content.to_vec(),
    };

    verify_signature(
        &signer_cert.tbs_certificate.subject_public_key_info,
        &signer_info.signature_algorithm,
        Some(&signer_info.digest_alg),
        &signed_bytes,
        signer_info.signature.as_bytes(),
    )?;

    Ok(())
}
