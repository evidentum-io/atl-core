//! Certificate chain construction and validation
//!
//! Builds a certificate chain from a CMS signer certificate towards a trust
//! anchor, walking the *whole* chain (not just the leaf) and checking, at
//! every link: the issuer's signature over the subject, `BasicConstraints`,
//! `KeyUsage`, path length, unrecognized critical extensions, and validity
//! *at the timestamp's `genTime`* rather than at wall-clock "now".
//!
//! # Why not just check for a self-signed root?
//!
//! Several real-world TSA tokens (Sectigo, DigiCert) name a "root"
//! certificate that is not self-signed at all -- it is cross-signed by a
//! legacy root that is absent from the token entirely. Treating
//! self-signedness as the trust criterion would reject those tokens outright
//! and, symmetrically, would treat *any* self-signed certificate as
//! automatically trusted, which is precisely the forgery this module's
//! regression test exists to catch. Trust comes only from matching a
//! certificate against the caller-supplied [`super::TrustStore`]; whether a
//! certificate happens to be self-signed only matters for deciding where an
//! *unverified* chain naturally terminates (`TerminalAnchor::Assumed`).
//!
//! # All viable paths, not just the first one found
//!
//! A token's certificate set is a `SET OF` with no defined order, and
//! multiple certificates can share the same subject Name (cross-signed
//! intermediates). This module explores every issuer candidate at every
//! step (bounded, cycle-guarded) and reports the best outcome found, with
//! `Trusted` preferred over `Assumed` preferred over `Invalid` preferred
//! over `Incomplete`.

use std::time::Duration;

use cms::signed_data::SignerIdentifier;
use der::Encode;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509_cert::Certificate;

use super::algorithms::verify_signature;
use super::result::{PathStatus, Sha256Digest, TerminalAnchor};
use super::trust_store::TrustStore;

/// Maximum chain depth explored. Real chains are 2-4 certificates deep;
/// this bounds recursion against a pathological or adversarial certificate
/// set without needing a separate "did we loop" heuristic beyond the
/// per-path fingerprint guard already in place.
const MAX_CHAIN_DEPTH: usize = 16;

/// DER-encode a certificate, or `None` if it cannot be re-encoded (should
/// not happen for a certificate that was itself successfully decoded, but
/// this crate never panics on attacker-controlled input).
pub(super) fn cert_der_bytes(cert: &Certificate) -> Option<Vec<u8>> {
    cert.to_der().ok()
}

/// SHA-256 fingerprint over the full DER-encoded certificate.
pub(super) fn cert_fingerprint_sha256(cert: &Certificate) -> Option<Sha256Digest> {
    Some(sha256(&cert_der_bytes(cert)?))
}

/// SHA-256 hash of the DER-encoded `SubjectPublicKeyInfo`.
pub(super) fn cert_spki_sha256(cert: &Certificate) -> Option<Sha256Digest> {
    let spki_der = cert.tbs_certificate.subject_public_key_info.to_der().ok()?;
    Some(sha256(&spki_der))
}

fn sha256(data: &[u8]) -> Sha256Digest {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Locate the CMS signer's certificate among `pool`, matching by
/// `SignerIdentifier` (`issuerAndSerialNumber` or `subjectKeyIdentifier`).
pub(super) fn find_signer_certificate<'a>(
    pool: &'a [Certificate],
    sid: &SignerIdentifier,
) -> Option<&'a Certificate> {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => pool.iter().find(|cert| {
            cert.tbs_certificate.issuer == ias.issuer
                && cert.tbs_certificate.serial_number == ias.serial_number
        }),
        SignerIdentifier::SubjectKeyIdentifier(ski) => pool.iter().find(|cert| {
            cert.tbs_certificate
                .get::<x509_cert::ext::pkix::SubjectKeyIdentifier>()
                .ok()
                .flatten()
                .is_some_and(|(_, found)| found.0 == ski.0)
        }),
    }
}

/// The `id-kp-timeStamping` EKU is present, critical, and the *only*
/// asserted purpose. Per the observed corpus this is required on the signer
/// (leaf) certificate only; intermediates/roots may carry it non-critically
/// or not at all, both of which are legal and must not be rejected.
pub(super) fn check_timestamping_eku(cert: &Certificate) -> bool {
    use const_oid::db::rfc5280::ID_KP_TIME_STAMPING;

    let Ok(Some((critical, eku))) = cert.tbs_certificate.get::<ExtendedKeyUsage>() else {
        return false;
    };
    critical && eku.0.len() == 1 && eku.0[0] == ID_KP_TIME_STAMPING
}

/// A *critical* extension is tolerated only when this crate actually
/// applies its semantics somewhere in chain validation, for the role the
/// certificate carrying it plays. That set is deliberately small today:
/// `BasicConstraints` (CA/leaf distinction, `pathLenConstraint`, checked on
/// every non-leaf certificate), `KeyUsage` (`keyCertSign` on non-leaf
/// certificates via [`key_usage_allows_cert_signing`], `digitalSignature`/
/// `nonRepudiation` on the leaf via [`key_usage_allows_signing`]), and
/// `ExtendedKeyUsage` (the leaf's exclusive `id-kp-timeStamping`
/// requirement via [`super::check_timestamping_eku`], and
/// `id-kp-timeStamping`/`anyExtendedKeyUsage` on non-leaf certificates via
/// [`eku_permits_time_stamping_issuance`]). Naming an OID here without
/// actually enforcing its semantics *for every role that can carry it*
/// would recreate exactly the gap this whitelist exists to close -- a
/// certificate can be a leaf on one path and, in principle, is always
/// evaluated per its actual position in `walk()`, never assumed compliant
/// just because its extension's OID is recognized in the abstract.
///
/// RFC 5280 4.2: "a certificate-using system MUST reject the certificate if
/// it encounters a critical extension it does not recognize **or a critical
/// extension that it does recognize but is not able to process**." Knowing
/// an OID's name is not "processing" it: `NameConstraints`,
/// `PolicyConstraints`, `CertificatePolicies`, `PolicyMappings`,
/// `InhibitAnyPolicy`, `PrivateKeyUsagePeriod`, and every other extension
/// this module does not evaluate are therefore rejected when critical, even
/// though their OIDs are perfectly well known -- a critical
/// `NameConstraints` that excludes our leaf, silently ignored, would be
/// exactly the kind of hole this check exists to close. A non-critical
/// occurrence of any of these is fine either way: nothing here inspects
/// their content, so nothing here can silently violate a constraint it
/// never reads.
fn is_processed_critical_extension(oid: &der::asn1::ObjectIdentifier) -> bool {
    use const_oid::db::rfc5280::{ID_CE_BASIC_CONSTRAINTS, ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE};

    const PROCESSED: &[der::asn1::ObjectIdentifier] =
        &[ID_CE_BASIC_CONSTRAINTS, ID_CE_KEY_USAGE, ID_CE_EXT_KEY_USAGE];
    PROCESSED.contains(oid)
}

fn has_unprocessed_critical_extension(cert: &Certificate) -> bool {
    cert.tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .any(|ext| ext.critical && !is_processed_critical_extension(&ext.extn_id))
}

fn validity_covers(cert: &Certificate, gen_time: Duration) -> bool {
    let validity = cert.tbs_certificate.validity;
    let not_before = validity.not_before.to_unix_duration();
    let not_after = validity.not_after.to_unix_duration();
    not_before <= gen_time && gen_time <= not_after
}

/// `BasicConstraints` decoded from `cert`, if present and well-formed.
/// A duplicated or malformed extension is treated as absent-and-invalid by
/// the caller (chain construction rejects the link).
fn basic_constraints(cert: &Certificate) -> Result<Option<BasicConstraints>, ()> {
    cert.tbs_certificate.get::<BasicConstraints>().map(|opt| opt.map(|(_, bc)| bc)).map_err(|_| ())
}

fn key_usage_allows_cert_signing(cert: &Certificate) -> Result<bool, ()> {
    match cert.tbs_certificate.get::<KeyUsage>() {
        Ok(None) => Ok(true), // KeyUsage is optional; absence is not a rejection.
        Ok(Some((_, ku))) => Ok(ku.0.contains(KeyUsages::KeyCertSign)),
        Err(_) => Err(()),
    }
}

/// `KeyUsage`, if present on the *signer* (leaf) certificate, must permit
/// signing: `digitalSignature` and/or `nonRepudiation` (contentCommitment).
///
/// This is a **local policy of this crate**, derived from the `KeyUsage`
/// semantics of RFC 5280 4.2.1.3, not a requirement quoted from RFC 3161.
/// (RFC 3161 2.3 constrains the *extended* key usage -- the critical,
/// exclusive `id-kp-timeStamping` -- which is enforced separately on the
/// CMS signer; it does not impose this `KeyUsage` rule.)
///
/// Absence is not a rejection -- `KeyUsage` is optional -- but *presence
/// without either bit* means the certificate's own issuer has declared this
/// key may not be used to produce signatures at all, which this crate must
/// not silently accept just because it also happens to carry a timestamping
/// EKU.
///
/// Scope, stated precisely: this checks only that a signing bit is
/// *present*. It deliberately does **not** enforce exclusivity (that no
/// other `KeyUsage` bit is set); do not read this function as doing so.
fn key_usage_allows_signing(cert: &Certificate) -> Result<bool, ()> {
    match cert.tbs_certificate.get::<KeyUsage>() {
        Ok(None) => Ok(true),
        Ok(Some((_, ku))) => {
            Ok(ku.0.contains(KeyUsages::DigitalSignature)
                || ku.0.contains(KeyUsages::NonRepudiation))
        }
        Err(_) => Err(()),
    }
}

/// `ExtendedKeyUsage`, if present on a certificate *above* the leaf (an
/// intermediate or a trust-store-matched terminal), must include
/// `id-kp-timeStamping` or `anyExtendedKeyUsage` -- otherwise that CA has
/// declared its key is restricted to purposes that do not cover issuing
/// (directly or transitively) a timestamping certificate, per RFC 5280
/// 4.2.1.12 ("the certificate MUST only be used for one of the purposes
/// indicated"). Applied regardless of whether the extension is marked
/// critical: `EKU`'s "MUST only be used for" language does not hinge on
/// criticality, and this crate already promised (by including
/// `ExtendedKeyUsage` in the processed-critical-extension set) to actually
/// evaluate this extension's semantics wherever it appears in the chain,
/// not just on the leaf. Absence is not a rejection.
fn eku_permits_time_stamping_issuance(cert: &Certificate) -> Result<bool, ()> {
    use const_oid::db::rfc5280::ANY_EXTENDED_KEY_USAGE;
    use const_oid::db::rfc5280::ID_KP_TIME_STAMPING;

    match cert.tbs_certificate.get::<ExtendedKeyUsage>() {
        Ok(None) => Ok(true),
        Ok(Some((_, eku))) => Ok(eku
            .0
            .iter()
            .any(|oid| *oid == ID_KP_TIME_STAMPING || *oid == ANY_EXTENDED_KEY_USAGE)),
        Err(_) => Err(()),
    }
}

/// Verify that `issuer`'s public key produced `subject`'s signature over
/// `subject`'s TBS certificate.
fn issuer_signs_subject(issuer: &Certificate, subject: &Certificate) -> bool {
    let Ok(tbs_der) = subject.tbs_certificate.to_der() else { return false };
    verify_signature(
        &issuer.tbs_certificate.subject_public_key_info,
        &subject.signature_algorithm,
        None,
        &tbs_der,
        subject.signature.raw_bytes(),
    )
    .is_ok()
}

/// Outcome of exploring one candidate path from a given certificate upward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Trusted(Sha256Digest),
    Assumed(Sha256Digest),
    Invalid,
    Incomplete,
}

impl Outcome {
    /// Priority order for picking the best outcome among several candidate
    /// paths: a real trust anchor beats an unverified self-signed root
    /// beats a definite structural/cryptographic failure beats simply
    /// running out of certificates.
    const fn rank(self) -> u8 {
        match self {
            Self::Trusted(_) => 3,
            Self::Assumed(_) => 2,
            Self::Invalid => 1,
            Self::Incomplete => 0,
        }
    }

    fn best(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }
}

/// The parts of a chain walk that stay constant across the whole recursion,
/// bundled to keep [`walk`]'s argument count reasonable.
struct WalkCtx<'a> {
    gen_time: Duration,
    pool: &'a [Certificate],
    trust_store: &'a TrustStore,
}

/// Walk from `current` towards a trust anchor, exploring all viable issuer
/// candidates in `ctx.pool` and returning the best outcome found.
///
/// `visited` guards against certificate loops (a certificate appearing
/// twice on the same path); `intermediate_cas` counts CA certificates
/// already walked through, strictly between the signer and `current`, for
/// `pathLenConstraint` enforcement.
#[allow(clippy::too_many_lines)]
fn walk(
    ctx: &WalkCtx<'_>,
    current: &Certificate,
    is_leaf: bool,
    visited: &[Sha256Digest],
    intermediate_cas: u32,
    depth: usize,
) -> Outcome {
    if depth > MAX_CHAIN_DEPTH {
        return Outcome::Invalid;
    }
    let gen_time = ctx.gen_time;

    let Some(current_fp) = cert_fingerprint_sha256(current) else {
        return Outcome::Invalid;
    };

    // Structural/temporal checks that apply to every certificate on the
    // path, leaf included.
    if !validity_covers(current, gen_time) {
        return Outcome::Invalid;
    }
    if has_unprocessed_critical_extension(current) {
        return Outcome::Invalid;
    }

    if is_leaf {
        // The signer certificate's own key must actually be usable for
        // signing, if it says anything about the subject at all.
        match key_usage_allows_signing(current) {
            Ok(true) => {}
            Ok(false) | Err(()) => return Outcome::Invalid,
        }
    } else {
        // Everything above the leaf must be a CA per BasicConstraints, and
        // respect its own pathLenConstraint against the number of
        // intermediate CAs already consumed below it.
        match basic_constraints(current) {
            Ok(Some(bc)) if bc.ca => {
                if let Some(max_intermediates) = bc.path_len_constraint {
                    if intermediate_cas > u32::from(max_intermediates) {
                        return Outcome::Invalid;
                    }
                }
            }
            Ok(_) => return Outcome::Invalid, // not a CA, cannot issue certificates
            Err(()) => return Outcome::Invalid,
        }
        match key_usage_allows_cert_signing(current) {
            Ok(true) => {}
            Ok(false) | Err(()) => return Outcome::Invalid,
        }
        match eku_permits_time_stamping_issuance(current) {
            Ok(true) => {}
            Ok(false) | Err(()) => return Outcome::Invalid,
        }
    }

    // Trust match takes priority over the self-signed fallback: an anchor
    // pinned by the caller need not be self-signed at all (Sectigo/DigiCert
    // cross-signed "roots").
    if let Some(fingerprint) = ctx.trust_store.matching_anchor_fingerprint(current) {
        return Outcome::Trusted(fingerprint);
    }

    let is_self_signed = current.tbs_certificate.issuer == current.tbs_certificate.subject
        && issuer_signs_subject(current, current);
    if is_self_signed {
        return Outcome::Assumed(current_fp);
    }

    let mut next_visited = visited.to_vec();
    next_visited.push(current_fp);
    let next_intermediate_cas = if is_leaf { 0 } else { intermediate_cas + 1 };

    let name_candidates: Vec<&Certificate> = ctx
        .pool
        .iter()
        .chain(ctx.trust_store.candidate_certificates())
        .filter(|candidate| candidate.tbs_certificate.subject == current.tbs_certificate.issuer)
        .collect();

    if name_candidates.is_empty() {
        return Outcome::Incomplete;
    }

    let mut best = Outcome::Incomplete;
    let mut found_any_valid_edge = false;
    for candidate in name_candidates {
        let Some(candidate_fp) = cert_fingerprint_sha256(candidate) else { continue };
        if visited.contains(&candidate_fp) {
            continue; // cycle guard
        }
        if !issuer_signs_subject(candidate, current) {
            best = best.best(Outcome::Invalid);
            continue;
        }
        found_any_valid_edge = true;
        let outcome = walk(ctx, candidate, false, &next_visited, next_intermediate_cas, depth + 1);
        best = best.best(outcome);
    }

    if !found_any_valid_edge && matches!(best, Outcome::Incomplete) {
        // Every same-named candidate existed but failed signature
        // verification: that is evidence of a broken link, not merely
        // missing data.
        best = Outcome::Invalid;
    }

    best
}

/// Result of building and validating a certificate chain from the signer
/// certificate towards a trust anchor.
pub(super) struct ChainResult {
    pub(super) status: PathStatus,
    pub(super) terminal: Option<TerminalAnchor>,
    pub(super) chain_valid_at_gen_time: bool,
}

/// Build the best available certificate chain from `leaf` (the CMS signer
/// certificate) towards a trust anchor in `trust_store`, using `pool` (the
/// token's own certificate set plus `trust_store`'s intermediates/anchors)
/// as the universe of candidate issuers.
pub(super) fn verify_chain(
    leaf: &Certificate,
    gen_time: Duration,
    pool: &[Certificate],
    trust_store: &TrustStore,
) -> ChainResult {
    let ctx = WalkCtx { gen_time, pool, trust_store };
    let outcome = walk(&ctx, leaf, true, &[], 0, 0);

    match outcome {
        Outcome::Trusted(fp) => ChainResult {
            status: PathStatus::Complete,
            terminal: Some(TerminalAnchor::Trusted { sha256_fingerprint: fp }),
            chain_valid_at_gen_time: true,
        },
        Outcome::Assumed(fp) => ChainResult {
            status: PathStatus::Complete,
            terminal: Some(TerminalAnchor::Assumed { sha256_fingerprint: fp }),
            chain_valid_at_gen_time: true,
        },
        Outcome::Invalid => ChainResult {
            status: PathStatus::Invalid,
            terminal: None,
            chain_valid_at_gen_time: false,
        },
        Outcome::Incomplete => ChainResult {
            status: PathStatus::Incomplete,
            terminal: None,
            chain_valid_at_gen_time: false,
        },
    }
}

#[cfg(test)]
mod tests {
    //! Regression tests for role-aware `KeyUsage`/`ExtendedKeyUsage`
    //! enforcement, built from hand-constructed `Certificate` values
    //! (no signature relationship needed: both checks fire on `current`
    //! before `walk()` ever looks for an issuer candidate, so a
    //! syntactically-valid, self-consistent certificate is enough).

    use super::*;
    use der::asn1::{BitString, GeneralizedTime, ObjectIdentifier, OctetString};
    use der::{DateTime, Encode};
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::ext::Extension;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};
    use x509_cert::TbsCertificate;

    fn dummy_algorithm_identifier() -> AlgorithmIdentifierOwned {
        use const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION;
        AlgorithmIdentifierOwned { oid: SHA_256_WITH_RSA_ENCRYPTION, parameters: None }
    }

    fn dummy_spki() -> SubjectPublicKeyInfoOwned {
        use const_oid::db::rfc5912::RSA_ENCRYPTION;
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned { oid: RSA_ENCRYPTION, parameters: None },
            subject_public_key: BitString::new(0, vec![0u8]).unwrap(),
        }
    }

    fn test_gen_time() -> Duration {
        DateTime::new(2026, 1, 1, 0, 0, 0).unwrap().unix_duration()
    }

    fn extension(oid: ObjectIdentifier, critical: bool, value: impl Encode) -> Extension {
        Extension {
            extn_id: oid,
            critical,
            extn_value: OctetString::new(value.to_der().unwrap()).unwrap(),
        }
    }

    /// A syntactically-valid, self-consistent certificate (unsigned --
    /// nothing in these tests checks the signature) valid from 2000 to
    /// 2100, carrying exactly the given extensions.
    fn cert_with_extensions(extensions: Vec<Extension>) -> Certificate {
        let not_before = Time::GeneralTime(GeneralizedTime::from_date_time(
            DateTime::new(2000, 1, 1, 0, 0, 0).unwrap(),
        ));
        let not_after = Time::GeneralTime(GeneralizedTime::from_date_time(
            DateTime::new(2100, 1, 1, 0, 0, 0).unwrap(),
        ));

        let tbs_certificate = TbsCertificate {
            version: x509_cert::Version::V3,
            serial_number: SerialNumber::new(&[1]).unwrap(),
            signature: dummy_algorithm_identifier(),
            issuer: Name::default(),
            validity: Validity { not_before, not_after },
            subject: Name::default(),
            subject_public_key_info: dummy_spki(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };

        Certificate {
            tbs_certificate,
            signature_algorithm: dummy_algorithm_identifier(),
            signature: BitString::new(0, vec![0u8]).unwrap(),
        }
    }

    /// A leaf certificate whose `KeyUsage` is present, critical, and does
    /// *not* include `digitalSignature` or `nonRepudiation` (only
    /// `keyEncipherment`) must be rejected -- the certificate's own issuer
    /// has declared this key may not produce signatures at all.
    #[test]
    fn leaf_key_usage_without_signing_bits_is_rejected() {
        use const_oid::db::rfc5280::ID_CE_KEY_USAGE;

        let ku = KeyUsage(KeyUsages::KeyEncipherment.into());
        let leaf = cert_with_extensions(vec![extension(ID_CE_KEY_USAGE, true, ku)]);

        let empty_store = TrustStore::new();
        let ctx = WalkCtx { gen_time: test_gen_time(), pool: &[], trust_store: &empty_store };
        let outcome = walk(&ctx, &leaf, true, &[], 0, 0);

        assert_eq!(outcome, Outcome::Invalid);
    }

    /// A leaf certificate whose `KeyUsage` *does* include `digitalSignature`
    /// is not rejected by this check (sanity check for the positive case).
    /// It still can't reach `Trusted`/`Assumed`: issuer and subject are
    /// both the empty `Name` (so name-wise it looks self-signed), but the
    /// dummy zero-byte key/signature cannot possibly verify, so
    /// `is_self_signed` is false and there is no candidate issuer in an
    /// empty pool either -- `Incomplete`, not `Invalid`. The point of this
    /// test is specifically that it is *not* rejected for the KeyUsage
    /// reason the previous test checks.
    #[test]
    fn leaf_key_usage_with_digital_signature_passes_the_check() {
        use const_oid::db::rfc5280::ID_CE_KEY_USAGE;

        let ku = KeyUsage(KeyUsages::DigitalSignature.into());
        let leaf = cert_with_extensions(vec![extension(ID_CE_KEY_USAGE, true, ku)]);

        let empty_store = TrustStore::new();
        let ctx = WalkCtx { gen_time: test_gen_time(), pool: &[], trust_store: &empty_store };
        let outcome = walk(&ctx, &leaf, true, &[], 0, 0);

        assert_eq!(outcome, Outcome::Incomplete);
    }

    /// An intermediate certificate whose `ExtendedKeyUsage` is present,
    /// critical, and names only `id-kp-serverAuth` (neither
    /// `id-kp-timeStamping` nor `anyExtendedKeyUsage`) must be rejected --
    /// that CA has declared its key restricted to a purpose that does not
    /// cover issuing a timestamping certificate.
    #[test]
    fn intermediate_eku_without_timestamping_or_any_is_rejected() {
        use const_oid::db::rfc5280::{
            ID_CE_BASIC_CONSTRAINTS, ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE, ID_KP_SERVER_AUTH,
        };

        let bc = BasicConstraints { ca: true, path_len_constraint: None };
        let ku = KeyUsage(KeyUsages::KeyCertSign.into());
        let eku = ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH]);
        let intermediate = cert_with_extensions(vec![
            extension(ID_CE_BASIC_CONSTRAINTS, true, bc),
            extension(ID_CE_KEY_USAGE, true, ku),
            extension(ID_CE_EXT_KEY_USAGE, true, eku),
        ]);

        let empty_store = TrustStore::new();
        let ctx = WalkCtx { gen_time: test_gen_time(), pool: &[], trust_store: &empty_store };
        let outcome = walk(&ctx, &intermediate, false, &[], 0, 1);

        assert_eq!(outcome, Outcome::Invalid);
    }

    /// The same intermediate, but its `ExtendedKeyUsage` includes
    /// `id-kp-timeStamping`: the EKU check itself must not reject it (it
    /// still can't go further here -- empty pool, so `Incomplete` -- but
    /// crucially *not* rejected for the reason the previous test checks).
    #[test]
    fn intermediate_eku_with_timestamping_is_not_rejected_by_the_eku_check() {
        use const_oid::db::rfc5280::{
            ID_CE_BASIC_CONSTRAINTS, ID_CE_EXT_KEY_USAGE, ID_CE_KEY_USAGE, ID_KP_TIME_STAMPING,
        };

        let bc = BasicConstraints { ca: true, path_len_constraint: None };
        let ku = KeyUsage(KeyUsages::KeyCertSign.into());
        let eku = ExtendedKeyUsage(vec![ID_KP_TIME_STAMPING]);
        let intermediate = cert_with_extensions(vec![
            extension(ID_CE_BASIC_CONSTRAINTS, true, bc),
            extension(ID_CE_KEY_USAGE, true, ku),
            extension(ID_CE_EXT_KEY_USAGE, true, eku),
        ]);

        let empty_store = TrustStore::new();
        let ctx = WalkCtx { gen_time: test_gen_time(), pool: &[], trust_store: &empty_store };
        let outcome = walk(&ctx, &intermediate, false, &[], 0, 1);

        // No candidate issuer in an empty pool -- Incomplete, not Invalid.
        // The point is that it is NOT Invalid (which is what the EKU
        // check, if it wrongly fired, would produce).
        assert_eq!(outcome, Outcome::Incomplete);
    }
}
