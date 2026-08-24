//! ESS signing-certificate binding (RFC 2634 / RFC 5035) and CMS Algorithm
//! Protection (RFC 6211)
//!
//! Neither the `cms` nor `x509-cert` crates model these CMS signed
//! attributes, so their ASN.1 structures are defined here directly on top of
//! `der`. Only the fields this crate actually inspects are decoded
//! precisely; `IssuerSerial` and `policies` are captured as opaque `Any` so
//! decoding succeeds regardless of whether a token includes them, without
//! this crate needing to model `GeneralNames`/`PolicyInformation`.

use der::asn1::{Any, OctetString};
use der::Sequence;
use spki::AlgorithmIdentifierOwned;

/// `ESSCertID` (RFC 2634): binds a signer certificate via a SHA-1 hash. SHA-1
/// is fixed by the RFC for the v1 attribute; this crate does not choose it.
///
/// ```text
/// ESSCertID ::= SEQUENCE {
///     certHash        Hash,          -- SHA-1 hash of entire certificate
///     issuerSerial     IssuerSerial OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EssCertId {
    /// SHA-1 hash of the DER-encoded signer certificate.
    pub cert_hash: OctetString,
    /// `IssuerSerial`, unused for binding (the signer is already identified
    /// via CMS `SignerIdentifier`); captured opaquely so decoding succeeds.
    #[asn1(optional = "true")]
    pub issuer_serial: Option<Any>,
}

/// `SigningCertificate` (RFC 2634), the `id-aa-signingCertificate` attribute
/// value.
///
/// ```text
/// SigningCertificate ::= SEQUENCE {
///     certs        SEQUENCE OF ESSCertID,
///     policies     SEQUENCE OF PolicyInformation OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SigningCertificate {
    /// Certificate identifiers; per RFC 2634 the first entry identifies the
    /// signer's own certificate.
    pub certs: Vec<EssCertId>,
    /// Certificate policies, unused; captured opaquely so decoding succeeds.
    #[asn1(optional = "true")]
    pub policies: Option<Any>,
}

/// `ESSCertIDv2` (RFC 5035): binds a signer certificate via a hash under a
/// caller-chosen algorithm (default SHA-256 when the field is omitted).
///
/// ```text
/// ESSCertIDv2 ::= SEQUENCE {
///     hashAlgorithm    AlgorithmIdentifier DEFAULT {algorithm sha256},
///     certHash         Hash,
///     issuerSerial     IssuerSerial OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EssCertIdV2 {
    /// Hash algorithm used for `cert_hash`. Absent means SHA-256 (the RFC
    /// 5035 default); this crate applies that default explicitly rather
    /// than relying on DER default-omission semantics.
    #[asn1(optional = "true")]
    pub hash_algorithm: Option<AlgorithmIdentifierOwned>,
    /// Hash of the DER-encoded signer certificate, under `hash_algorithm`.
    pub cert_hash: OctetString,
    /// `IssuerSerial`, unused for binding; captured opaquely.
    #[asn1(optional = "true")]
    pub issuer_serial: Option<Any>,
}

/// `SigningCertificateV2` (RFC 5035), the `id-aa-signingCertificateV2`
/// attribute value.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SigningCertificateV2 {
    /// Certificate identifiers; the first entry identifies the signer's own
    /// certificate.
    pub certs: Vec<EssCertIdV2>,
    /// Certificate policies, unused; captured opaquely.
    #[asn1(optional = "true")]
    pub policies: Option<Any>,
}

/// `CMSAlgorithmProtection` (RFC 6211): binds `SignerInfo.digestAlgorithm`
/// and `SignerInfo.signatureAlgorithm` together inside the signed
/// attributes, so an attacker cannot silently downgrade either after the
/// fact. Observed on GlobalSign tokens.
///
/// ```text
/// CMSAlgorithmProtection ::= SEQUENCE {
///     digestAlgorithm         DigestAlgorithmIdentifier,
///     signatureAlgorithm  [1] SignatureAlgorithmIdentifier OPTIONAL,
///     macAlgorithm         [2] MessageAuthenticationCodeAlgorithm OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CmsAlgorithmProtection {
    /// The digest algorithm this attribute asserts.
    pub digest_algorithm: AlgorithmIdentifierOwned,
    /// The signature algorithm this attribute asserts, if present.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub signature_algorithm: Option<AlgorithmIdentifierOwned>,
    /// MAC algorithm, unused (CMS `SignedData` never uses this); captured so
    /// decoding does not reject a token that includes it.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub mac_algorithm: Option<AlgorithmIdentifierOwned>,
}
