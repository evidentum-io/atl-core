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
//! step (bounded, cycle-guarded) and *aggregates facts* across those paths.
//!
//! # Why the aggregation is not a ranking
//!
//! An earlier design ranked path outcomes linearly and reported the best
//! one, with `Invalid` ranked above `Incomplete`. That is unsound in both
//! directions, and the reason is that a candidate issuer is selected only by
//! Distinguished Name equality -- which proves nothing about who actually
//! issued the certificate. A CMS certificate set may legally carry
//! unrelated certificates (RFC 5652 5.1), so anyone can drop in a
//! same-named certificate whose signature does not check out; under a
//! ranking, that single planted certificate would declare the whole chain
//! *refuted* while a genuine, merely-unexplored alternative sat right next
//! to it.
//!
//! So [`walk`] collects independent facts instead -- did any path reach a
//! trust anchor, did any reach a name-self-issued terminal, did any get
//! refuted, did any run out of material, did any hit something this crate
//! cannot evaluate -- and [`verify_chain`] applies one rule on top:
//!
//! > **If a viable unexplored alternative exists, the outcome may not claim
//! > the chain is refuted.**
//!
//! Refuted paths are still kept, in the diagnostics, so a caller can say
//! *what* went wrong on them. They just may not out-vote an unknown.
//!
//! The defence against a planted certificate is therefore **ordering the
//! candidate set** (by `AuthorityKeyIdentifier` -> `SubjectKeyIdentifier`,
//! and by issuer/serial, where the certificates carry that data), not
//! ranking outcomes and not discarding candidates -- see
//! [`candidate_matches_authority_key_identifier`]. Every DN match is walked;
//! the signature, not the identifier, settles who the issuer was. The
//! aggregation rule depends on that: "an unexplored alternative forbids
//! claiming refutation" is only sound if the alternatives were really
//! explored.
//!
//! # Verified, refuted, undeterminable
//!
//! Every certificate-to-certificate edge yields one of three answers
//! ([`EdgeVerdict`]), never a bare boolean. "The signature does not verify"
//! and "this crate cannot evaluate this signature algorithm" are different
//! facts, and conflating them is what made a SHA-1-self-signed root -- 31 of
//! the 156 roots in macOS's system store sign themselves with SHA-1, DigiCert
//! Assured ID Root CA among them -- come out as *refuted evidence*.

use std::time::Duration;

use cms::signed_data::SignerIdentifier;
use der::Encode;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectKeyIdentifier,
};
use x509_cert::Certificate;

use super::algorithms::{verify_signature, SigVerifyError};
use super::result::{PathStatus, SelfSignature, Sha256Digest, TerminalAnchor, TimestampingEku};
use super::trust_store::TrustStore;

/// Maximum chain depth explored. Real chains are 2-4 certificates deep;
/// this bounds recursion against a pathological or adversarial certificate
/// set without needing a separate "did we loop" heuristic beyond the
/// per-path fingerprint guard already in place.
const MAX_CHAIN_DEPTH: usize = 16;

/// Upper bound on collected path diagnostics. The search is already bounded
/// by [`MAX_CHAIN_DEPTH`] and by the token size limit, but an adversarial
/// certificate set can still produce a combinatorial number of failing
/// edges; diagnostics are prose for humans, and a handful of them says
/// everything a longer list would.
const MAX_DIAGNOSTICS: usize = 8;

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

/// **Every** certificate in `pool` matching the CMS `SignerIdentifier`
/// (`issuerAndSerialNumber` or `subjectKeyIdentifier`) -- not just the first.
///
/// # Why this returns all of them
///
/// A CMS `SignedData` certificate set is **not covered by the signature**
/// and may legally carry certificates unrelated to the signer (RFC 5652
/// 5.1). Neither `issuerAndSerialNumber` nor `subjectKeyIdentifier` is
/// unique across an attacker-supplied set: anyone can add a certificate
/// bearing the same issuer and serial (or the same SKI) as the real signer
/// but holding a different key.
///
/// Returning the first match would therefore let a stranger's certificate,
/// placed earlier in the set, be picked as "the signer", fail signature or
/// ESS-binding verification, and have a wholly valid token published as
/// refuted evidence -- while the genuine signer sat in the same set,
/// unexamined. That is the "first candidate wins" defect this module already
/// removed from chain construction; the same reasoning applies one step
/// earlier, at the choice of signer.
///
/// The caller tries every candidate and settles the question by
/// verification, not by position -- see `verify_parsed_token`.
pub(super) fn signer_certificate_candidates<'a>(
    pool: &'a [Certificate],
    sid: &'a SignerIdentifier,
) -> impl Iterator<Item = &'a Certificate> + 'a {
    pool.iter().filter(move |cert| match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => {
            cert.tbs_certificate.issuer == ias.issuer
                && cert.tbs_certificate.serial_number == ias.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => cert
            .tbs_certificate
            .get::<x509_cert::ext::pkix::SubjectKeyIdentifier>()
            .ok()
            .flatten()
            .is_some_and(|(_, found)| found.0 == ski.0),
    })
}

/// Check RFC 3161 2.3's requirement that the signer (leaf) certificate's
/// `id-kp-timeStamping` EKU is present, critical, and the *only* asserted
/// purpose -- reporting **which way** the check failed, out of the four
/// distinguishable failures (absent, malformed, non-critical, non-exclusive)
/// rather than a single `false`.
///
/// Returning a single `false` for "absent", "malformed", "not critical" and
/// "wrong purpose" alike would hand the caller a fact it cannot act on:
/// a TSA that issued a signer certificate with no EKU at all and a
/// certificate whose EKU extension is duplicated are different problems.
///
/// Per the observed corpus this requirement applies to the signer
/// certificate only; intermediates and roots may carry the EKU
/// non-critically or not at all, both of which are legal and must not be
/// rejected (see [`eku_permits_time_stamping_issuance`] for what *is*
/// enforced above the leaf).
pub(super) fn check_timestamping_eku(cert: &Certificate) -> TimestampingEku {
    use const_oid::db::rfc5280::ID_KP_TIME_STAMPING;

    match cert.tbs_certificate.get::<ExtendedKeyUsage>() {
        Err(_) => TimestampingEku::Malformed,
        Ok(None) => TimestampingEku::Absent,
        Ok(Some((critical, eku))) => {
            let exclusive = eku.0.len() == 1 && eku.0[0] == ID_KP_TIME_STAMPING;
            // The content problem is reported ahead of the criticality
            // problem when a certificate manages both.
            match (exclusive, critical) {
                (true, true) => TimestampingEku::Ok,
                (false, _) => TimestampingEku::NotExclusive,
                (true, false) => TimestampingEku::NotCritical,
            }
        }
    }
}

/// A *critical* extension is tolerated only when this crate actually
/// applies its semantics somewhere in chain validation, for the role the
/// certificate carrying it plays. That set is deliberately small today:
/// `BasicConstraints` (CA/leaf distinction, `pathLenConstraint`, checked on
/// every non-leaf certificate, and *decoded* on the leaf as well -- see
/// [`walk`] for why the leaf's `cA` value itself is not a rejection),
/// `KeyUsage` (`keyCertSign` on non-leaf
/// certificates via [`key_usage_allows_cert_signing`], `digitalSignature`/
/// `nonRepudiation` on the leaf via [`key_usage_allows_signing`]), and
/// `ExtendedKeyUsage` (the leaf's exclusive `id-kp-timeStamping`
/// requirement via [`check_timestamping_eku`], and
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

/// The first critical extension this crate cannot process, if any.
fn unprocessed_critical_extension(cert: &Certificate) -> Option<der::asn1::ObjectIdentifier> {
    cert.tbs_certificate
        .extensions
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|ext| ext.critical && !is_processed_critical_extension(&ext.extn_id))
        .map(|ext| ext.extn_id)
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

/// The three -- not two -- possible answers to "did `issuer` sign
/// `subject`?".
///
/// A boolean cannot express the third one, and that is precisely the defect
/// this type exists to remove: `false` used to mean both "checked, and the
/// signature is wrong" (a refutation) and "could not check at all" (no
/// information whatsoever). Only the former may ever contribute to an
/// `Invalid` outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EdgeVerdict {
    /// The signature was checked under `issuer`'s public key and verifies.
    Verified,
    /// The signature was checked, or the certificate's own encoding was
    /// checked, and something is **wrong**: the signature does not verify,
    /// the signature bits or the `SubjectPublicKeyInfo` are malformed, the
    /// key does not decode, the EC parameters are broken, the signature
    /// algorithm names a different key family than the key actually is, the
    /// bare `rsaEncryption` OID is used where it is not legal, or
    /// `tbsCertificate.signature` disagrees with the outer
    /// `signatureAlgorithm`.
    Refuted(String),
    /// The signature could **not be evaluated**: an unsupported signature
    /// algorithm, an unsupported public-key algorithm, an unsupported curve,
    /// or an internal DER re-encoding failure. Asserts nothing about the
    /// signature -- in particular it is not evidence of forgery, and must
    /// never be reported as one.
    Undeterminable(String),
}

/// Map a [`SigVerifyError`] onto the refuted/undeterminable split.
///
/// Only the errors that mean *this crate does not implement the primitive*
/// are undeterminable. Note that `algorithms.rs` reports an unsupported
/// **public-key** algorithm and an unsupported **curve** through the same
/// [`SigVerifyError::UnsupportedSignatureAlgorithm`] variant as an
/// unsupported signature algorithm; all three are inabilities, so the single
/// arm below is correct rather than merely convenient.
///
/// [`SigVerifyError::UnsupportedDigestAlgorithm`] joins them. It is
/// unreachable on this path today -- a certificate signature always names a
/// composite OID that fixes its own digest (RFC 5280 never uses the bare
/// form), so [`issuer_signs_subject`] passes `digest_hint: None` and
/// `resolve_digest` never calls `DigestAlg::from_oid` for a certificate edge
/// -- but classifying it as an inability costs nothing and removes a
/// standing trap. An earlier draft put it on the refuted side, reasoning
/// that unreachable code cannot mislead; that left a future refactor one
/// small change away from silently turning "we cannot check this" back into
/// "this is forged". It now matches [`super::cms_verify::classify`], where
/// the same error *is* reachable and means exactly the same thing.
///
/// Everything else -- including [`SigVerifyError::InvalidPublicKey`], which
/// covers a malformed SPKI or broken EC parameters -- is a refutation.
fn classify_signature_error(err: &SigVerifyError) -> EdgeVerdict {
    match err {
        SigVerifyError::UnsupportedSignatureAlgorithm(_)
        | SigVerifyError::UnsupportedDigestAlgorithm(_) => {
            EdgeVerdict::Undeterminable(err.to_string())
        }
        SigVerifyError::BareRsaRequiresDigestHint
        | SigVerifyError::DigestAlgorithmMismatch { .. }
        | SigVerifyError::InvalidPublicKey(_)
        | SigVerifyError::InvalidSignatureEncoding(_)
        | SigVerifyError::SignatureInvalid
        | SigVerifyError::KeyFamilyMismatch { .. } => EdgeVerdict::Refuted(err.to_string()),
    }
}

/// Verify that `issuer`'s public key produced `subject`'s signature over
/// `subject`'s `tbsCertificate`.
///
/// Also enforces RFC 5280 4.1.1.2: `Certificate.signatureAlgorithm` and
/// `tbsCertificate.signature` "MUST contain the same algorithm identifier".
/// A certificate where they differ is malformed, and accepting it would mean
/// verifying under an algorithm the signed portion never committed to --
/// this crate previously did not check this at all.
fn issuer_signs_subject(issuer: &Certificate, subject: &Certificate) -> EdgeVerdict {
    if subject.tbs_certificate.signature != subject.signature_algorithm {
        return EdgeVerdict::Refuted(
            "tbsCertificate.signature differs from the outer signatureAlgorithm (RFC 5280 4.1.1.2)"
                .to_string(),
        );
    }

    let Ok(tbs_der) = subject.tbs_certificate.to_der() else {
        return EdgeVerdict::Undeterminable(
            "tbsCertificate could not be re-encoded to DER for signature verification".to_string(),
        );
    };

    match verify_signature(
        &issuer.tbs_certificate.subject_public_key_info,
        &subject.signature_algorithm,
        None,
        &tbs_der,
        subject.signature.raw_bytes(),
    ) {
        Ok(()) => EdgeVerdict::Verified,
        Err(err) => classify_signature_error(&err),
    }
}

/// Whether `subject`'s `AuthorityKeyIdentifier` positively points at
/// `candidate` -- used to **order** issuer candidates, never to discard them.
///
/// A CMS `SignedData` may legally carry certificates unrelated to the signer
/// (RFC 5652 5.1), so anyone can add a certificate whose subject Name equals
/// a real CA's. `AuthorityKeyIdentifier` (RFC 5280 4.2.1.1) is the field
/// X.509 provides for telling them apart:
///
/// - `keyIdentifier` compared against the candidate's `SubjectKeyIdentifier`;
/// - `authorityCertSerialNumber` against the candidate's serial number;
/// - `authorityCertIssuer`, when it is a single `directoryName`, against the
///   candidate's own issuer Name.
///
/// # Why this is a hint and not a filter
///
/// RFC 5280 4.2.1.1 is explicit that applications are **not required** to
/// match key identifiers when validating a path -- they are an efficiency
/// aid for finding the right certificate, not an authorisation rule. A
/// legitimate issuer that omits its `SubjectKeyIdentifier`, or whose
/// identifier was computed by a different method, must still be tried;
/// dropping it would manufacture a false `Incomplete` for a chain that
/// verifies perfectly well by signature.
///
/// Discarding candidates would also quietly undermine [`verify_chain`]'s
/// aggregation rule. "A refuted path may not out-vote an unexplored
/// alternative" is only sound if the alternatives were genuinely explored;
/// a filter that removed them before any signature check would leave the
/// rule true by vacuum. So every DN-matching candidate is walked, and this
/// function only decides which ones are walked *first* -- the signature is
/// what settles who the issuer was.
fn candidate_matches_authority_key_identifier(
    candidate: &Certificate,
    subject: &Certificate,
) -> bool {
    let Ok(Some((_, aki))) = subject.tbs_certificate.get::<AuthorityKeyIdentifier>() else {
        // Absent or malformed AKI: no preference to express, so no candidate
        // is preferred over another. (A malformed AKI on the *subject* is not
        // judged here; if the extension is critical,
        // `unprocessed_critical_extension` has already rejected it.)
        return false;
    };

    // Every identifier the AKI actually carries must agree for the candidate
    // to be *preferred*. Anything less is simply not a preference, which is
    // why disagreement and silence both return `false` here: neither is
    // evidence, and neither costs the candidate its turn in the walk.
    let mut expressed_any = false;

    if let Some(key_id) = aki.key_identifier.as_ref() {
        let Ok(Some((_, ski))) = candidate.tbs_certificate.get::<SubjectKeyIdentifier>() else {
            return false;
        };
        if ski.0.as_bytes() != key_id.as_bytes() {
            return false;
        }
        expressed_any = true;
    }

    if let Some(serial) = aki.authority_cert_serial_number.as_ref() {
        if candidate.tbs_certificate.serial_number != *serial {
            return false;
        }
        expressed_any = true;
    }

    if let Some(names) = aki.authority_cert_issuer.as_ref() {
        if let [GeneralName::DirectoryName(name)] = names.as_slice() {
            if candidate.tbs_certificate.issuer != *name {
                return false;
            }
            expressed_any = true;
        }
    }

    expressed_any
}

/// Sort issuer candidates so the ones `subject`'s `AuthorityKeyIdentifier`
/// points at are tried first.
///
/// **Ordering only -- the length of `candidates` never changes.** That is the
/// whole contract: a certificate planted in the token's certificate set
/// cannot displace the real issuer by being listed earlier, and a legitimate
/// issuer that expresses no matching identifier still gets walked and settled
/// by its signature. `sort_by_key` is stable, so relative order within each
/// group is preserved.
fn order_issuer_candidates(candidates: &mut [&Certificate], subject: &Certificate) {
    candidates
        .sort_by_key(|candidate| !candidate_matches_authority_key_identifier(candidate, subject));
}

/// Facts gathered while exploring every viable path upward from one
/// certificate.
///
/// Deliberately a *set of independent observations*, not a single ranked
/// outcome -- see this module's header for why a ranking is unsound. The
/// `saw_*` flags are sticky across the whole recursion: they record that
/// *somewhere* below this point a path was refuted, ran out of material, or
/// could not be evaluated.
#[derive(Debug, Clone, Default)]
struct Findings {
    /// A path reached a certificate the caller's trust store names.
    trusted: Option<Sha256Digest>,
    /// A path reached a name-self-issued certificate whose self-signature
    /// verifies.
    assumed_verified: Option<Sha256Digest>,
    /// A path reached a name-self-issued certificate whose self-signature
    /// this crate cannot evaluate.
    assumed_unverifiable: Option<Sha256Digest>,
    /// Some path was refuted (a checked fact was false).
    saw_refuted_path: bool,
    /// Some path could not be evaluated (unsupported cryptography, the depth
    /// limit, an internal encoding failure).
    saw_indeterminate_path: bool,
    /// Some path ran out of usable candidate issuers -- either none matched
    /// the issuer name, or every match was already on the path and was
    /// pruned by the cycle guard. Cycle pruning is recorded here, not as
    /// indeterminate: nothing failed to be *evaluated*, there was simply no
    /// unused certificate left to continue with.
    saw_incomplete_path: bool,
    /// Prose explaining the non-successful observations, capped at
    /// [`MAX_DIAGNOSTICS`].
    diagnostics: Vec<String>,
}

impl Findings {
    fn with_diagnostic(mut self, diagnostic: impl Into<String>) -> Self {
        self.push_diagnostic(diagnostic);
        self
    }

    fn push_diagnostic(&mut self, diagnostic: impl Into<String>) {
        if self.diagnostics.len() < MAX_DIAGNOSTICS {
            self.diagnostics.push(diagnostic.into());
        }
    }

    fn trusted(fingerprint: Sha256Digest) -> Self {
        Self { trusted: Some(fingerprint), ..Self::default() }
    }

    fn assumed_verified(fingerprint: Sha256Digest) -> Self {
        Self { assumed_verified: Some(fingerprint), ..Self::default() }
    }

    fn assumed_unverifiable(fingerprint: Sha256Digest, reason: impl Into<String>) -> Self {
        Self { assumed_unverifiable: Some(fingerprint), ..Self::default() }.with_diagnostic(reason)
    }

    fn refuted(reason: impl Into<String>) -> Self {
        Self { saw_refuted_path: true, ..Self::default() }.with_diagnostic(reason)
    }

    fn indeterminate(reason: impl Into<String>) -> Self {
        Self { saw_indeterminate_path: true, ..Self::default() }.with_diagnostic(reason)
    }

    fn incomplete(reason: impl Into<String>) -> Self {
        Self { saw_incomplete_path: true, ..Self::default() }.with_diagnostic(reason)
    }

    /// Fold a sub-path's findings into this one. Positive terminals are
    /// kept first-come (any one of them is equally a terminal); the `saw_*`
    /// facts accumulate.
    fn merge(&mut self, other: Self) {
        self.trusted = self.trusted.or(other.trusted);
        self.assumed_verified = self.assumed_verified.or(other.assumed_verified);
        self.assumed_unverifiable = self.assumed_unverifiable.or(other.assumed_unverifiable);
        self.saw_refuted_path |= other.saw_refuted_path;
        self.saw_indeterminate_path |= other.saw_indeterminate_path;
        self.saw_incomplete_path |= other.saw_incomplete_path;
        for diagnostic in other.diagnostics {
            self.push_diagnostic(diagnostic);
        }
    }

    fn diagnostic(&self) -> Option<String> {
        if self.diagnostics.is_empty() {
            None
        } else {
            Some(self.diagnostics.join("; "))
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
/// candidates in `ctx.pool` and returning the facts gathered across them.
///
/// `visited` guards against certificate loops (a certificate appearing
/// twice on the same path); `intermediate_cas` counts CA certificates
/// already walked through, strictly between the signer and `current`, for
/// `pathLenConstraint` enforcement.
///
/// # Order of checks, and where the trust-anchor exemption stops
///
/// For a certificate **above** the leaf, the trust-anchor match comes first,
/// ahead of its own validity period, `BasicConstraints`, `KeyUsage` and
/// `ExtendedKeyUsage`. RFC 5280 6.1 treats a trust anchor as an externally
/// supplied trusted *input* to path validation, not as a link of the path
/// being validated: the certification path proper begins below it. Checking
/// the anchor's own fields first would mean a root the verifier explicitly
/// designated -- an expired long-lived root, or a cross-signed "root" whose
/// own issuer is absent from the token -- silently stops working, which is a
/// decision belonging to whoever configured the trust store, not to this
/// crate.
///
/// For the **leaf** the order is reversed, and this is not a detail. The
/// signer certificate may still be pinned, but its validity at `gen_time`,
/// its critical extensions and its `KeyUsage` are checked *before* any trust
/// matching. A timestamp's whole claim is temporal; publishing `Complete`
/// and `chain_valid_at_gen_time = true` for a signer that had expired at
/// `gen_time`, merely because someone pinned it, would assert a fact nobody
/// verified. The exemption exists to let a caller nominate a *terminus*, not
/// to switch off the checks on the certificate the timestamp rests on.
///
/// Everything below an exempted anchor is still verified in full: the edge
/// into it is checked in the parent frame before this one is entered, so
/// pinning a root never softens a check on the certificates it vouches for.
fn walk(
    ctx: &WalkCtx<'_>,
    current: &Certificate,
    is_leaf: bool,
    visited: &[Sha256Digest],
    intermediate_cas: u32,
    depth: usize,
) -> Findings {
    if depth > MAX_CHAIN_DEPTH {
        // A limit this crate imposes on itself refutes nothing about the
        // token: it means the search stopped, not that the chain is bad.
        return Findings::indeterminate(format!(
            "certificate path exploration stopped at the depth limit of {MAX_CHAIN_DEPTH}"
        ));
    }
    let gen_time = ctx.gen_time;

    let Some(current_fp) = cert_fingerprint_sha256(current) else {
        return Findings::indeterminate(
            "certificate fingerprint could not be computed (DER re-encoding failed)",
        );
    };

    // A trust anchor ABOVE the leaf is an external input, evaluated before
    // anything about its own contents -- see this function's docs. The
    // signer certificate is excluded from that exemption on purpose: its
    // checks run first, below.
    if !is_leaf {
        if let Some(fingerprint) = ctx.trust_store.matching_anchor_fingerprint(current) {
            return Findings::trusted(fingerprint);
        }
    }

    // Structural/temporal checks that apply to every certificate on the
    // path, leaf included. Each of these is a checked fact coming out
    // false, so each is a refutation.
    if !validity_covers(current, gen_time) {
        return Findings::refuted("certificate is outside its validity period at genTime");
    }
    if let Some(oid) = unprocessed_critical_extension(current) {
        return Findings::refuted(format!(
            "certificate carries a critical extension this crate cannot process ({oid})"
        ));
    }

    if is_leaf {
        // `BasicConstraints` is in the processed-critical-extension
        // whitelist, so it must actually be decoded here too, not merely
        // named: a critical extension the crate promises to process but
        // never reads is exactly the hole that whitelist exists to close.
        //
        // Its *value* on the signer is deliberately not a rejection. A
        // signer certificate with `cA = true` is unusual and arguably
        // sloppy issuance, but RFC 3161 constrains the signer through the
        // exclusive critical `id-kp-timeStamping` EKU, not through
        // `BasicConstraints`; rejecting on `cA` would refuse real tokens
        // over a rule no specification imposes. A malformed or duplicated
        // extension, by contrast, is refuted.
        if basic_constraints(current).is_err() {
            return Findings::refuted(
                "signer certificate has a malformed or duplicated BasicConstraints extension",
            );
        }
        // The signer certificate's own key must actually be usable for
        // signing, if it says anything about the subject at all.
        match key_usage_allows_signing(current) {
            Ok(true) => {}
            Ok(false) => {
                return Findings::refuted(
                    "signer certificate's KeyUsage permits neither digitalSignature nor \
                     nonRepudiation",
                )
            }
            Err(()) => {
                return Findings::refuted(
                    "signer certificate has a malformed or duplicated KeyUsage extension",
                )
            }
        }

        // Only now may the signer be matched against the trust store. A
        // caller is free to pin the signer certificate itself, but pinning
        // it must not buy an exemption from the checks above: a timestamp's
        // entire claim is temporal, so reporting `chain_valid_at_gen_time =
        // true` and `Complete` for a signer that had already expired at
        // `genTime` would publish a fact nobody checked. The anchor
        // exemption exists so that a caller's designated *root* -- possibly
        // expired, possibly cross-signed by an absent legacy issuer -- keeps
        // working; it was never meant to reach the certificate whose
        // properties the timestamp actually rests on.
        if let Some(fingerprint) = ctx.trust_store.matching_anchor_fingerprint(current) {
            return Findings::trusted(fingerprint);
        }
    } else {
        // Everything above the leaf must be a CA per BasicConstraints, and
        // respect its own pathLenConstraint against the number of
        // intermediate CAs already consumed below it.
        match basic_constraints(current) {
            Ok(Some(bc)) if bc.ca => {
                if let Some(max_intermediates) = bc.path_len_constraint {
                    if intermediate_cas > u32::from(max_intermediates) {
                        return Findings::refuted(format!(
                            "pathLenConstraint {max_intermediates} exceeded: \
                             {intermediate_cas} intermediate CAs below this certificate"
                        ));
                    }
                }
            }
            Ok(_) => {
                return Findings::refuted(
                    "issuer certificate is not a CA per BasicConstraints, so it cannot issue \
                     certificates",
                )
            }
            Err(()) => {
                return Findings::refuted(
                    "issuer certificate has a malformed or duplicated BasicConstraints extension",
                )
            }
        }
        match key_usage_allows_cert_signing(current) {
            Ok(true) => {}
            Ok(false) => {
                return Findings::refuted("issuer certificate's KeyUsage lacks keyCertSign")
            }
            Err(()) => {
                return Findings::refuted(
                    "issuer certificate has a malformed or duplicated KeyUsage extension",
                )
            }
        }
        match eku_permits_time_stamping_issuance(current) {
            Ok(true) => {}
            Ok(false) => {
                return Findings::refuted(
                    "issuer certificate's ExtendedKeyUsage covers neither id-kp-timeStamping nor \
                     anyExtendedKeyUsage",
                )
            }
            Err(()) => {
                return Findings::refuted(
                    "issuer certificate has a malformed or duplicated ExtendedKeyUsage extension",
                )
            }
        }
    }

    // A terminus candidate: issuer and subject Distinguished Names are
    // equal. RFC 5280 3.2 calls this **self-issued**, and keeps it
    // deliberately distinct from *self-signed* (self-issued AND the
    // signature verifies under its own key). The distinction is the whole
    // point here: whether it is also self-signed is a separate question
    // with three possible answers, not two.
    if current.tbs_certificate.issuer == current.tbs_certificate.subject {
        return match issuer_signs_subject(current, current) {
            EdgeVerdict::Verified => Findings::assumed_verified(current_fp),
            EdgeVerdict::Undeterminable(reason) => Findings::assumed_unverifiable(
                current_fp,
                format!("self-issued terminal certificate's own signature could not be verified: {reason}"),
            ),
            // Equal names plus a self-signature that was checked and does
            // not hold is not a terminus at all -- marking it `Assumed`
            // would report a certificate as the root of the chain on the
            // strength of a signature known to be wrong.
            EdgeVerdict::Refuted(reason) => Findings::refuted(format!(
                "self-issued certificate's own signature is invalid: {reason}"
            )),
        };
    }

    let mut next_visited = visited.to_vec();
    next_visited.push(current_fp);
    let next_intermediate_cas = if is_leaf { 0 } else { intermediate_cas + 1 };

    let mut name_candidates: Vec<&Certificate> = ctx
        .pool
        .iter()
        .chain(ctx.trust_store.candidate_certificates())
        .filter(|candidate| candidate.tbs_certificate.subject == current.tbs_certificate.issuer)
        .collect();

    order_issuer_candidates(&mut name_candidates, current);

    if name_candidates.is_empty() {
        return Findings::incomplete(
            "no candidate issuer certificate available for this certificate's issuer name",
        );
    }

    let mut findings = Findings::default();
    let mut pruned_by_cycle = false;
    let mut explored_any = false;

    for candidate in name_candidates {
        let Some(candidate_fp) = cert_fingerprint_sha256(candidate) else {
            findings.saw_indeterminate_path = true;
            findings
                .push_diagnostic("issuer candidate skipped: its fingerprint could not be computed");
            continue;
        };
        if visited.contains(&candidate_fp) {
            // The guard proves only that this certificate already appears on
            // this path -- never that no genuine issuer with that name
            // exists. Pruning is a limit of the search, not a refutation.
            pruned_by_cycle = true;
            continue;
        }
        explored_any = true;
        match issuer_signs_subject(candidate, current) {
            EdgeVerdict::Verified => {
                findings.merge(walk(
                    ctx,
                    candidate,
                    false,
                    &next_visited,
                    next_intermediate_cas,
                    depth + 1,
                ));
            }
            EdgeVerdict::Refuted(reason) => {
                findings.saw_refuted_path = true;
                findings.push_diagnostic(format!(
                    "a same-named issuer candidate did not sign this certificate: {reason}"
                ));
            }
            EdgeVerdict::Undeterminable(reason) => {
                findings.saw_indeterminate_path = true;
                findings.push_diagnostic(format!(
                    "a same-named issuer candidate's signature could not be evaluated: {reason}"
                ));
            }
        }
    }

    if pruned_by_cycle && !explored_any {
        // Every candidate was already on this path. Nothing was checked and
        // found false, so this is missing material, not broken material.
        findings.saw_incomplete_path = true;
        findings.push_diagnostic(
            "CyclePruned: every candidate issuer already appears on this path, so the path \
             could not be extended",
        );
    }

    findings
}

/// Result of building and validating a certificate chain from the signer
/// certificate towards a trust anchor.
pub(super) struct ChainResult {
    pub(super) status: PathStatus,
    pub(super) terminal: Option<TerminalAnchor>,
    pub(super) chain_valid_at_gen_time: bool,
    pub(super) diagnostic: Option<String>,
}

/// Build the best available certificate chain from `leaf` (the CMS signer
/// certificate) towards a trust anchor in `trust_store`, using `pool` (the
/// token's own certificate set plus `trust_store`'s intermediates/anchors)
/// as the universe of candidate issuers.
///
/// # How the gathered facts become one status
///
/// In order, and the order is the argument:
///
/// 1. **A trust anchor was reached** -- the caller's own material vouches
///    for the chain. `Complete`/`Trusted`.
/// 2. **A name-self-issued terminal with a verified self-signature** --
///    structurally a complete chain, trusted by nobody. `Complete`/`Assumed`,
///    which no aggregate success may accept.
/// 3. **A name-self-issued terminal whose self-signature cannot be
///    evaluated** -- there is a terminus, but this crate cannot confirm it
///    signs itself. Reported honestly as `Indeterminate` with
///    `chain_valid_at_gen_time = false`: not a completed chain, and equally
///    not a refuted one.
/// 4. **Something could not be evaluated** anywhere in the search.
///    `Indeterminate`.
/// 5. **Something ran out of certificates.** `Incomplete`.
/// 6. **Only then** may a refutation stand: `Invalid`, and only because
///    steps 4 and 5 established that no viable unexplored alternative
///    remains. This is the rule stated in the module header, applied.
///
/// Diagnostics from refuted paths survive into `diagnostic` regardless of
/// which status wins, so a caller can explain what it saw without the status
/// having to overclaim.
pub(super) fn verify_chain(
    leaf: &Certificate,
    gen_time: Duration,
    pool: &[Certificate],
    trust_store: &TrustStore,
) -> ChainResult {
    let ctx = WalkCtx { gen_time, pool, trust_store };
    let findings = walk(&ctx, leaf, true, &[], 0, 0);
    let diagnostic = findings.diagnostic();

    let (status, terminal, chain_valid_at_gen_time) = if let Some(fp) = findings.trusted {
        (PathStatus::Complete, Some(TerminalAnchor::Trusted { sha256_fingerprint: fp }), true)
    } else if let Some(fp) = findings.assumed_verified {
        (
            PathStatus::Complete,
            Some(TerminalAnchor::Assumed {
                sha256_fingerprint: fp,
                self_signature: SelfSignature::Verified,
            }),
            true,
        )
    } else if let Some(fp) = findings.assumed_unverifiable {
        (
            PathStatus::Indeterminate,
            Some(TerminalAnchor::Assumed {
                sha256_fingerprint: fp,
                self_signature: SelfSignature::Unverifiable,
            }),
            false,
        )
    } else if findings.saw_indeterminate_path {
        (PathStatus::Indeterminate, None, false)
    } else if findings.saw_incomplete_path {
        (PathStatus::Incomplete, None, false)
    } else if findings.saw_refuted_path {
        (PathStatus::Invalid, None, false)
    } else {
        // Unreachable in practice: `walk` always records at least one fact.
        // Falling back to `Incomplete` keeps the "never claim a refutation
        // you cannot support" rule true even for a fact set this function
        // does not understand.
        (PathStatus::Incomplete, None, false)
    };

    ChainResult { status, terminal, chain_valid_at_gen_time, diagnostic }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the three-state edge verdict, the aggregation rule,
    //! and role-aware `BasicConstraints`/`KeyUsage`/`ExtendedKeyUsage`
    //! enforcement.
    //!
    //! The certificates here are hand-constructed rather than real, and
    //! carry no identity of any kind -- per ATL's trust model no root, name
    //! or fingerprint of a real authority belongs in `src/`. That costs
    //! nothing: every property exercised below is decided before any
    //! cryptographic operation reaches real key material. In particular an
    //! *unsupported* signature algorithm is rejected by
    //! `algorithms::resolve_digest` on the OID alone, so a certificate
    //! merely declaring `sha1WithRSAEncryption` reproduces the exact
    //! `Undeterminable` path that a real SHA-1-self-signed root takes,
    //! without embedding one.
    //!
    //! The `Verified` half of the terminal logic is covered end to end
    //! against real tokens in `rfc3161_corpus_tests.rs` and against a
    //! complete synthetic hierarchy in `rfc3161_adversarial_tests.rs`.

    use std::str::FromStr;

    use der::asn1::{BitString, GeneralizedTime, ObjectIdentifier, OctetString};
    use der::{DateTime, Encode};
    use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::ext::Extension;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};
    use x509_cert::TbsCertificate;

    use super::*;

    /// `sha1WithRSAEncryption`, 1.2.840.113549.1.1.5. Not implemented by
    /// this crate (see `algorithms`), which is exactly why it is useful
    /// here: it is the algorithm a large minority of still-valid roots use
    /// to sign themselves.
    const SHA1_WITH_RSA_ENCRYPTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.5");

    /// Ed25519, 1.3.101.112 -- a perfectly real public-key algorithm this
    /// crate does not implement, used to reach the "unsupported public key
    /// algorithm" branch of `verify_signature`.
    const ED_25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

    fn sha256_with_rsa() -> AlgorithmIdentifierOwned {
        use const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION;
        AlgorithmIdentifierOwned { oid: SHA_256_WITH_RSA_ENCRYPTION, parameters: None }
    }

    fn alg(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned { oid, parameters: None }
    }

    /// An RSA `SubjectPublicKeyInfo` whose key bits are a single zero byte:
    /// well-formed as ASN.1, impossible to decode as an RSA key. Reaching
    /// it means the edge is *refuted*, never undeterminable.
    fn undecodable_rsa_spki() -> SubjectPublicKeyInfoOwned {
        use const_oid::db::rfc5912::RSA_ENCRYPTION;
        SubjectPublicKeyInfoOwned {
            algorithm: alg(RSA_ENCRYPTION),
            subject_public_key: BitString::new(0, vec![0u8]).unwrap(),
        }
    }

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("test DN parses")
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

    /// A syntactically-valid certificate valid from 2000 to 2100, with the
    /// given DNs, signature algorithm, key and extensions. `tbsCertificate
    /// .signature` mirrors `signature_algorithm`, as RFC 5280 4.1.1.2
    /// requires, unless a test deliberately breaks it.
    struct CertBuilder {
        issuer: &'static str,
        subject: &'static str,
        sig_alg: AlgorithmIdentifierOwned,
        spki: SubjectPublicKeyInfoOwned,
        serial: u8,
        extensions: Vec<Extension>,
        validity: (DateTime, DateTime),
    }

    impl CertBuilder {
        fn new(issuer: &'static str, subject: &'static str) -> Self {
            Self {
                issuer,
                subject,
                sig_alg: sha256_with_rsa(),
                spki: undecodable_rsa_spki(),
                serial: 1,
                extensions: Vec::new(),
                validity: (
                    DateTime::new(2000, 1, 1, 0, 0, 0).unwrap(),
                    DateTime::new(2100, 1, 1, 0, 0, 0).unwrap(),
                ),
            }
        }

        fn validity(mut self, not_before: DateTime, not_after: DateTime) -> Self {
            self.validity = (not_before, not_after);
            self
        }

        fn sig_alg(mut self, sig_alg: AlgorithmIdentifierOwned) -> Self {
            self.sig_alg = sig_alg;
            self
        }

        fn spki(mut self, spki: SubjectPublicKeyInfoOwned) -> Self {
            self.spki = spki;
            self
        }

        fn serial(mut self, serial: u8) -> Self {
            self.serial = serial;
            self
        }

        fn ext(mut self, extension: Extension) -> Self {
            self.extensions.push(extension);
            self
        }

        fn build(self) -> Certificate {
            self.build_with_outer(None)
        }

        /// `outer` overrides `Certificate.signatureAlgorithm` while
        /// `tbsCertificate.signature` keeps `self.sig_alg`, producing the
        /// RFC 5280 4.1.1.2 mismatch.
        fn build_with_outer(self, outer: Option<AlgorithmIdentifierOwned>) -> Certificate {
            let not_before = Time::GeneralTime(GeneralizedTime::from_date_time(self.validity.0));
            let not_after = Time::GeneralTime(GeneralizedTime::from_date_time(self.validity.1));

            let outer_alg = outer.unwrap_or_else(|| self.sig_alg.clone());
            let extensions = if self.extensions.is_empty() { None } else { Some(self.extensions) };

            let tbs_certificate = TbsCertificate {
                version: x509_cert::Version::V3,
                serial_number: SerialNumber::new(&[self.serial]).unwrap(),
                signature: self.sig_alg,
                issuer: name(self.issuer),
                validity: Validity { not_before, not_after },
                subject: name(self.subject),
                subject_public_key_info: self.spki,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions,
            };

            Certificate {
                tbs_certificate,
                signature_algorithm: outer_alg,
                signature: BitString::new(0, vec![0u8]).unwrap(),
            }
        }
    }

    fn ca_extensions(cert: CertBuilder) -> CertBuilder {
        use const_oid::db::rfc5280::{ID_CE_BASIC_CONSTRAINTS, ID_CE_KEY_USAGE};
        let bc = BasicConstraints { ca: true, path_len_constraint: None };
        let ku = KeyUsage(KeyUsages::KeyCertSign.into());
        cert.ext(extension(ID_CE_BASIC_CONSTRAINTS, true, bc)).ext(extension(
            ID_CE_KEY_USAGE,
            true,
            ku,
        ))
    }

    fn walk_leaf(pool: &[Certificate], store: &TrustStore, leaf: &Certificate) -> Findings {
        let ctx = WalkCtx { gen_time: test_gen_time(), pool, trust_store: store };
        walk(&ctx, leaf, true, &[], 0, 0)
    }

    fn chain_of(pool: &[Certificate], store: &TrustStore, leaf: &Certificate) -> ChainResult {
        verify_chain(leaf, test_gen_time(), pool, store)
    }

    // ---------------------------------------------------------------
    // The three edge states
    // ---------------------------------------------------------------

    /// An unsupported *signature* algorithm is `Undeterminable`: this crate
    /// cannot evaluate the signature, and that is not evidence of anything.
    #[test]
    fn unsupported_signature_algorithm_is_undeterminable_not_refuted() {
        let subject = CertBuilder::new("CN=issuer", "CN=subject")
            .sig_alg(alg(SHA1_WITH_RSA_ENCRYPTION))
            .build();
        let issuer = CertBuilder::new("CN=issuer", "CN=issuer").build();

        let verdict = issuer_signs_subject(&issuer, &subject);
        assert!(
            matches!(verdict, EdgeVerdict::Undeterminable(_)),
            "unsupported signature algorithm must be Undeterminable, got {verdict:?}"
        );
    }

    /// An unsupported *public key* algorithm reaches `verify_signature`'s
    /// SPKI dispatch and comes back as the same error class -- which must
    /// also be `Undeterminable`, not a refutation. This is the arm easiest
    /// to miss, because `algorithms.rs` reports it through the variant
    /// named after *signature* algorithms.
    #[test]
    fn unsupported_public_key_algorithm_is_undeterminable_not_refuted() {
        let subject = CertBuilder::new("CN=issuer", "CN=subject").build();
        let issuer = CertBuilder::new("CN=issuer", "CN=issuer")
            .spki(SubjectPublicKeyInfoOwned {
                algorithm: alg(ED_25519),
                subject_public_key: BitString::new(0, vec![0u8; 32]).unwrap(),
            })
            .build();

        let verdict = issuer_signs_subject(&issuer, &subject);
        assert!(
            matches!(verdict, EdgeVerdict::Undeterminable(_)),
            "unsupported public key algorithm must be Undeterminable, got {verdict:?}"
        );
    }

    /// An undecodable public key is a *refutation*: the material was
    /// examined and is broken, which is a different fact from not being
    /// able to examine it.
    #[test]
    fn undecodable_public_key_is_refuted() {
        let subject = CertBuilder::new("CN=issuer", "CN=subject").build();
        let issuer = CertBuilder::new("CN=issuer", "CN=issuer").build();

        let verdict = issuer_signs_subject(&issuer, &subject);
        assert!(
            matches!(verdict, EdgeVerdict::Refuted(_)),
            "a malformed SPKI must be Refuted, got {verdict:?}"
        );
    }

    /// RFC 5280 4.1.1.2: `signatureAlgorithm` and `tbsCertificate.signature`
    /// MUST be the same algorithm identifier. A certificate where they
    /// differ is refuted before any cryptography is attempted -- otherwise
    /// the signature would be checked under an algorithm the signed portion
    /// never committed to.
    #[test]
    fn signature_algorithm_mismatch_with_tbs_is_refuted() {
        let subject = CertBuilder::new("CN=issuer", "CN=subject")
            .sig_alg(sha256_with_rsa())
            .build_with_outer(Some(alg(SHA1_WITH_RSA_ENCRYPTION)));
        let issuer = CertBuilder::new("CN=issuer", "CN=issuer").build();

        match issuer_signs_subject(&issuer, &subject) {
            EdgeVerdict::Refuted(reason) => {
                assert!(reason.contains("4.1.1.2"), "the reason should name the rule: {reason}")
            }
            other => panic!("expected Refuted, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------
    // Terminal handling: name-self-issued, three ways
    // ---------------------------------------------------------------

    /// A name-self-issued certificate whose self-signature this crate
    /// cannot evaluate -- the SHA-1 root case -- terminates the chain as
    /// `Assumed`/`Unverifiable` with `Indeterminate` status. It must NOT be
    /// `Invalid`: nothing has been refuted.
    #[test]
    fn self_issued_with_unverifiable_signature_is_indeterminate_not_invalid() {
        // Shaped like a leaf (no CA extensions): `verify_chain` starts at
        // the certificate it is handed, and the point under test is the
        // terminal logic, not the CA rules.
        let root =
            CertBuilder::new("CN=root", "CN=root").sig_alg(alg(SHA1_WITH_RSA_ENCRYPTION)).build();

        let store = TrustStore::new();
        let result = chain_of(&[], &store, &root);

        assert_eq!(result.status, PathStatus::Indeterminate);
        assert!(!result.chain_valid_at_gen_time);
        assert!(matches!(
            result.terminal,
            Some(TerminalAnchor::Assumed { self_signature: SelfSignature::Unverifiable, .. })
        ));
        assert!(result.diagnostic.is_some(), "the reason must survive into the diagnostic");
    }

    /// A certificate with equal DNs whose self-signature is checked and is
    /// *wrong* is not a terminus at all. Marking it `Assumed` would name it
    /// the root of the chain on the strength of a signature known to be bad.
    #[test]
    fn self_issued_with_refuted_signature_is_not_a_terminal_anchor() {
        // Same DNs, RSA/SHA-256 (supported), key bits that cannot decode:
        // the signature is evaluated and fails.
        let root = CertBuilder::new("CN=root", "CN=root").build();

        let store = TrustStore::new();
        let result = chain_of(&[], &store, &root);

        assert_eq!(result.status, PathStatus::Invalid);
        assert!(result.terminal.is_none(), "a bad self-signature must not yield a terminal");
    }

    // ---------------------------------------------------------------
    // Aggregation across alternative paths
    // ---------------------------------------------------------------

    /// The decisive aggregation test. Two same-named issuer candidates: one
    /// whose signature is refuted, one whose signature cannot be evaluated.
    /// Under the old linear ranking (`Invalid` beat `Incomplete`) the
    /// refuted one would have declared the whole chain broken. It may not:
    /// an unexplored viable alternative exists, so the outcome is
    /// `Indeterminate`.
    #[test]
    fn a_refuted_alternative_never_outvotes_an_unevaluated_one() {
        use const_oid::db::rfc5280::ID_CE_KEY_USAGE;

        let leaf = CertBuilder::new("CN=ca", "CN=leaf")
            .ext(extension(ID_CE_KEY_USAGE, true, KeyUsage(KeyUsages::DigitalSignature.into())))
            .build();

        // Candidate A: supported algorithm, undecodable key -> Refuted edge.
        let refuting_ca = ca_extensions(CertBuilder::new("CN=root", "CN=ca").serial(2)).build();
        // Candidate B: identical subject DN, but the leaf's signature
        // algorithm cannot be evaluated against it either way. To make the
        // *edge* undeterminable the subject's own algorithm must be the
        // unsupported one, so use a second leaf for that path.
        let unevaluatable_leaf = CertBuilder::new("CN=ca", "CN=leaf")
            .sig_alg(alg(SHA1_WITH_RSA_ENCRYPTION))
            .ext(extension(ID_CE_KEY_USAGE, true, KeyUsage(KeyUsages::DigitalSignature.into())))
            .build();

        let store = TrustStore::new();

        // Refuted alone, with no alternative: `Invalid` is allowed.
        let only_refuted = chain_of(std::slice::from_ref(&refuting_ca), &store, &leaf);
        assert_eq!(only_refuted.status, PathStatus::Invalid);

        // The same refuting candidate, but the edge cannot be evaluated:
        // nothing is refuted any more.
        let unevaluatable =
            chain_of(std::slice::from_ref(&refuting_ca), &store, &unevaluatable_leaf);
        assert_eq!(unevaluatable.status, PathStatus::Indeterminate);
        assert!(!unevaluatable.chain_valid_at_gen_time);
    }

    /// A path pruned only because its sole candidate issuer already appears
    /// on the path proves nothing about the token: the cycle guard forbids
    /// repeating a certificate, it does not establish that no genuine
    /// issuer with that name exists. `Incomplete`, never `Invalid`.
    #[test]
    fn cycle_pruning_is_not_a_refutation() {
        use const_oid::db::rfc5280::ID_CE_KEY_USAGE;

        let leaf = CertBuilder::new("CN=ca", "CN=leaf")
            .ext(extension(ID_CE_KEY_USAGE, true, KeyUsage(KeyUsages::DigitalSignature.into())))
            .build();
        let ca = ca_extensions(CertBuilder::new("CN=root", "CN=ca").serial(2)).build();
        let ca_fp = cert_fingerprint_sha256(&ca).unwrap();

        let store = TrustStore::new();
        let pool = [ca];
        let ctx = WalkCtx { gen_time: test_gen_time(), pool: &pool, trust_store: &store };
        // Pretend the only candidate has already been walked on this path.
        let findings = walk(&ctx, &leaf, true, &[ca_fp], 0, 0);

        assert!(findings.saw_incomplete_path, "cycle pruning must report missing material");
        assert!(!findings.saw_refuted_path, "cycle pruning must never refute");
        assert!(
            findings.diagnostic().unwrap().contains("CyclePruned"),
            "the pruning reason must be named"
        );
    }

    /// Hitting the depth limit is a limit of this crate's search, not a
    /// fact about the token.
    #[test]
    fn depth_limit_is_indeterminate_not_refuted() {
        let leaf = CertBuilder::new("CN=ca", "CN=leaf").build();
        let store = TrustStore::new();
        let ctx = WalkCtx { gen_time: test_gen_time(), pool: &[], trust_store: &store };

        let findings = walk(&ctx, &leaf, true, &[], 0, MAX_CHAIN_DEPTH + 1);

        assert!(findings.saw_indeterminate_path);
        assert!(!findings.saw_refuted_path);
    }

    // ---------------------------------------------------------------
    // Trust anchors are an external input
    // ---------------------------------------------------------------

    /// A **non-leaf** certificate the caller pinned terminates the chain even
    /// though it carries a critical extension this crate cannot process --
    /// RFC 5280 6.1 makes a trust anchor an input to path validation, not a
    /// link of the path. Without this, a caller's explicitly designated root
    /// could be rejected by rules meant for the certificates below it.
    ///
    /// The leaf is deliberately excluded from this exemption; see
    /// `a_pinned_leaf_still_fails_the_critical_extension_check`.
    #[test]
    fn a_pinned_non_leaf_anchor_is_evaluated_before_its_own_contents() {
        let unknown_critical = ObjectIdentifier::new_unwrap("1.2.3.4.5.6.7.8.9");
        let anchor = CertBuilder::new("CN=other", "CN=anchor")
            .ext(extension(unknown_critical, true, OctetString::new(vec![0u8]).unwrap()))
            .build();
        let anchor_fp = cert_fingerprint_sha256(&anchor).unwrap();

        let store = TrustStore::new().with_anchor_certificate(anchor.clone());
        let ctx = WalkCtx { gen_time: test_gen_time(), pool: &[], trust_store: &store };
        let findings = walk(&ctx, &anchor, false, &[], 0, 1);

        assert_eq!(findings.trusted, Some(anchor_fp));
        assert!(!findings.saw_refuted_path);
    }

    /// **Blocker regression: the anchor exemption must not reach the leaf.**
    /// A signer certificate that had already expired at `genTime` must not
    /// become `Trusted`/`Complete` merely because the caller pinned it. A
    /// timestamp's entire claim is temporal; reporting
    /// `chain_valid_at_gen_time = true` here would publish a fact nobody
    /// checked.
    #[test]
    fn a_pinned_leaf_still_fails_its_validity_check_at_gen_time() {
        let expired = CertBuilder::new("CN=ca", "CN=leaf")
            .validity(
                DateTime::new(2000, 1, 1, 0, 0, 0).unwrap(),
                // `test_gen_time()` is 2026-01-01, well past this.
                DateTime::new(2001, 1, 1, 0, 0, 0).unwrap(),
            )
            .build();

        let store = TrustStore::new().with_anchor_certificate(expired.clone());
        let result = chain_of(&[], &store, &expired);

        assert_ne!(result.status, PathStatus::Complete);
        assert!(
            !result.chain_valid_at_gen_time,
            "an expired signer must never report chain_valid_at_gen_time = true"
        );
        assert!(
            !matches!(result.terminal, Some(TerminalAnchor::Trusted { .. })),
            "pinning the signer must not exempt it from its own validity check"
        );
        assert_eq!(result.status, PathStatus::Invalid);
    }

    /// The same rule for an unprocessable critical extension on a pinned
    /// signer: RFC 5280 4.2 requires rejecting it, and pinning is not a way
    /// around that for the certificate the timestamp rests on.
    #[test]
    fn a_pinned_leaf_still_fails_the_critical_extension_check() {
        let unknown_critical = ObjectIdentifier::new_unwrap("1.2.3.4.5.6.7.8.9");
        let leaf = CertBuilder::new("CN=ca", "CN=leaf")
            .ext(extension(unknown_critical, true, OctetString::new(vec![0u8]).unwrap()))
            .build();

        let store = TrustStore::new().with_anchor_certificate(leaf.clone());
        let result = chain_of(&[], &store, &leaf);

        assert_eq!(result.status, PathStatus::Invalid);
        assert!(!result.chain_valid_at_gen_time);
        assert!(!matches!(result.terminal, Some(TerminalAnchor::Trusted { .. })));
    }

    /// And for `KeyUsage`: a pinned signer whose own issuer declared the key
    /// unusable for signing is still refuted.
    #[test]
    fn a_pinned_leaf_still_fails_the_key_usage_check() {
        use const_oid::db::rfc5280::ID_CE_KEY_USAGE;

        let leaf = CertBuilder::new("CN=ca", "CN=leaf")
            .ext(extension(ID_CE_KEY_USAGE, true, KeyUsage(KeyUsages::KeyEncipherment.into())))
            .build();

        let store = TrustStore::new().with_anchor_certificate(leaf.clone());
        let result = chain_of(&[], &store, &leaf);

        assert_eq!(result.status, PathStatus::Invalid);
        assert!(!matches!(result.terminal, Some(TerminalAnchor::Trusted { .. })));
    }

    /// Pinning the leaf is still *allowed* -- it is not forbidden, it is
    /// merely not an exemption. A signer that passes its own checks and is
    /// named by the trust store terminates the chain as `Trusted`.
    #[test]
    fn a_pinned_leaf_that_passes_its_own_checks_is_trusted() {
        use const_oid::db::rfc5280::ID_CE_KEY_USAGE;

        let leaf = CertBuilder::new("CN=ca", "CN=leaf")
            .ext(extension(ID_CE_KEY_USAGE, true, KeyUsage(KeyUsages::DigitalSignature.into())))
            .build();
        let leaf_fp = cert_fingerprint_sha256(&leaf).unwrap();

        let store = TrustStore::new().with_anchor_certificate(leaf.clone());
        let result = chain_of(&[], &store, &leaf);

        assert_eq!(result.status, PathStatus::Complete);
        assert!(result.chain_valid_at_gen_time);
        assert_eq!(result.terminal, Some(TerminalAnchor::Trusted { sha256_fingerprint: leaf_fp }));
    }

    /// The exemption itself is intact for a non-leaf terminal: an expired
    /// root the caller explicitly designated keeps working, which is what
    /// keeps cross-signed roots usable at all.
    #[test]
    fn a_pinned_non_leaf_anchor_keeps_its_exemption() {
        let expired_root = CertBuilder::new("CN=legacy", "CN=root")
            .validity(
                DateTime::new(2000, 1, 1, 0, 0, 0).unwrap(),
                DateTime::new(2001, 1, 1, 0, 0, 0).unwrap(),
            )
            .build();
        let root_fp = cert_fingerprint_sha256(&expired_root).unwrap();

        let store = TrustStore::new().with_anchor_certificate(expired_root.clone());
        let ctx = WalkCtx { gen_time: test_gen_time(), pool: &[], trust_store: &store };
        let findings = walk(&ctx, &expired_root, false, &[], 0, 1);

        assert_eq!(findings.trusted, Some(root_fp));
        assert!(!findings.saw_refuted_path);
    }

    // ---------------------------------------------------------------
    // Per-certificate rules
    // ---------------------------------------------------------------

    /// A leaf whose `KeyUsage` is present, critical, and includes neither
    /// `digitalSignature` nor `nonRepudiation` is refuted -- its own issuer
    /// declared the key may not produce signatures.
    #[test]
    fn leaf_key_usage_without_signing_bits_is_refuted() {
        use const_oid::db::rfc5280::ID_CE_KEY_USAGE;

        let leaf = CertBuilder::new("CN=ca", "CN=leaf")
            .ext(extension(ID_CE_KEY_USAGE, true, KeyUsage(KeyUsages::KeyEncipherment.into())))
            .build();

        let store = TrustStore::new();
        let findings = walk_leaf(&[], &store, &leaf);

        assert!(findings.saw_refuted_path);
    }

    /// The positive case: a leaf with `digitalSignature` is not refuted by
    /// that check. With an empty pool it simply runs out of candidates.
    #[test]
    fn leaf_key_usage_with_digital_signature_passes_the_check() {
        use const_oid::db::rfc5280::ID_CE_KEY_USAGE;

        let leaf = CertBuilder::new("CN=ca", "CN=leaf")
            .ext(extension(ID_CE_KEY_USAGE, true, KeyUsage(KeyUsages::DigitalSignature.into())))
            .build();

        let store = TrustStore::new();
        let findings = walk_leaf(&[], &store, &leaf);

        assert!(!findings.saw_refuted_path);
        assert!(findings.saw_incomplete_path);
    }

    /// `BasicConstraints` is in the processed-critical-extension whitelist,
    /// so a malformed one on the *leaf* must actually be caught -- the
    /// whitelist previously promised to process it there and never decoded
    /// it at all.
    #[test]
    fn malformed_basic_constraints_on_the_leaf_is_refuted() {
        use const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS;

        let leaf = CertBuilder::new("CN=ca", "CN=leaf")
            .ext(extension(
                ID_CE_BASIC_CONSTRAINTS,
                true,
                BasicConstraints { ca: false, path_len_constraint: None },
            ))
            .ext(extension(
                ID_CE_BASIC_CONSTRAINTS,
                false,
                BasicConstraints { ca: false, path_len_constraint: None },
            ))
            .build();

        let store = TrustStore::new();
        let findings = walk_leaf(&[], &store, &leaf);

        assert!(findings.saw_refuted_path, "a duplicated BasicConstraints must be refuted");
    }

    /// A signer certificate asserting `cA = true` is unusual but is NOT
    /// rejected: RFC 3161 constrains the signer through the exclusive
    /// critical `id-kp-timeStamping` EKU, not through `BasicConstraints`.
    /// This is a deliberate policy decision, recorded here so a future
    /// change to it is a change to a test, not a silent drift.
    #[test]
    fn a_leaf_asserting_ca_true_is_not_refuted() {
        use const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS;

        let bc = BasicConstraints { ca: true, path_len_constraint: None };
        let leaf = CertBuilder::new("CN=ca", "CN=leaf")
            .ext(extension(ID_CE_BASIC_CONSTRAINTS, true, bc))
            .build();

        let store = TrustStore::new();
        let findings = walk_leaf(&[], &store, &leaf);

        assert!(!findings.saw_refuted_path);
        assert!(findings.saw_incomplete_path);
    }

    /// An intermediate whose `ExtendedKeyUsage` names only
    /// `id-kp-serverAuth` is refuted: that CA declared its key restricted to
    /// a purpose that does not cover issuing a timestamping certificate.
    #[test]
    fn intermediate_eku_without_timestamping_or_any_is_refuted() {
        use const_oid::db::rfc5280::{ID_CE_EXT_KEY_USAGE, ID_KP_SERVER_AUTH};

        let intermediate = ca_extensions(CertBuilder::new("CN=root", "CN=ca"))
            .ext(extension(ID_CE_EXT_KEY_USAGE, true, ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH])))
            .build();

        let store = TrustStore::new();
        let ctx = WalkCtx { gen_time: test_gen_time(), pool: &[], trust_store: &store };
        let findings = walk(&ctx, &intermediate, false, &[], 0, 1);

        assert!(findings.saw_refuted_path);
    }

    /// The same intermediate with `id-kp-timeStamping` is not refuted by the
    /// EKU check (it still runs out of candidates -- the point is that it is
    /// not refuted).
    #[test]
    fn intermediate_eku_with_timestamping_is_not_refuted_by_the_eku_check() {
        use const_oid::db::rfc5280::{ID_CE_EXT_KEY_USAGE, ID_KP_TIME_STAMPING};

        let intermediate = ca_extensions(CertBuilder::new("CN=root", "CN=ca"))
            .ext(extension(ID_CE_EXT_KEY_USAGE, true, ExtendedKeyUsage(vec![ID_KP_TIME_STAMPING])))
            .build();

        let store = TrustStore::new();
        let ctx = WalkCtx { gen_time: test_gen_time(), pool: &[], trust_store: &store };
        let findings = walk(&ctx, &intermediate, false, &[], 0, 1);

        assert!(!findings.saw_refuted_path);
        assert!(findings.saw_incomplete_path);
    }

    // ---------------------------------------------------------------
    // Candidate ordering (never narrowing -- nothing is ever dropped)
    // ---------------------------------------------------------------

    /// `AuthorityKeyIdentifier` expresses a *preference*, and only when the
    /// candidate positively matches. A contradicting candidate and a silent
    /// one are both merely un-preferred -- neither is excluded, because
    /// RFC 5280 4.2.1.1 does not require applications to match key
    /// identifiers when validating a path, and a legitimate issuer that
    /// omits its `SubjectKeyIdentifier` must still get its turn.
    #[test]
    fn aki_expresses_a_preference_and_never_an_exclusion() {
        use const_oid::db::rfc5280::{
            ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_SUBJECT_KEY_IDENTIFIER,
        };

        let aki = AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(vec![1, 2, 3, 4]).unwrap()),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        };
        let subject = CertBuilder::new("CN=ca", "CN=leaf")
            .ext(extension(ID_CE_AUTHORITY_KEY_IDENTIFIER, false, aki))
            .build();

        let matching = CertBuilder::new("CN=root", "CN=ca")
            .ext(extension(
                ID_CE_SUBJECT_KEY_IDENTIFIER,
                false,
                SubjectKeyIdentifier(OctetString::new(vec![1, 2, 3, 4]).unwrap()),
            ))
            .build();
        let contradicting = CertBuilder::new("CN=root", "CN=ca")
            .serial(9)
            .ext(extension(
                ID_CE_SUBJECT_KEY_IDENTIFIER,
                false,
                SubjectKeyIdentifier(OctetString::new(vec![9, 9, 9, 9]).unwrap()),
            ))
            .build();
        let silent = CertBuilder::new("CN=root", "CN=ca").serial(7).build();

        assert!(candidate_matches_authority_key_identifier(&matching, &subject));
        assert!(!candidate_matches_authority_key_identifier(&contradicting, &subject));
        assert!(
            !candidate_matches_authority_key_identifier(&silent, &subject),
            "a candidate with no SKI expresses no preference either way"
        );

        // A subject with no AKI at all prefers nobody.
        let no_aki = CertBuilder::new("CN=ca", "CN=leaf").build();
        assert!(!candidate_matches_authority_key_identifier(&matching, &no_aki));
    }

    /// A serial number named by the AKI is honoured the same way: a match is
    /// a preference, a mismatch is merely the absence of one.
    #[test]
    fn aki_serial_expresses_a_preference() {
        use const_oid::db::rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER;

        let aki = AuthorityKeyIdentifier {
            key_identifier: None,
            authority_cert_issuer: None,
            authority_cert_serial_number: Some(SerialNumber::new(&[5]).unwrap()),
        };
        let subject = CertBuilder::new("CN=ca", "CN=leaf")
            .ext(extension(ID_CE_AUTHORITY_KEY_IDENTIFIER, false, aki))
            .build();

        let right = CertBuilder::new("CN=root", "CN=ca").serial(5).build();
        let wrong = CertBuilder::new("CN=root", "CN=ca").serial(6).build();

        assert!(candidate_matches_authority_key_identifier(&right, &subject));
        assert!(!candidate_matches_authority_key_identifier(&wrong, &subject));
    }

    /// **The regression for the filter-vs-hint distinction.** A legitimate
    /// issuer whose `SubjectKeyIdentifier` disagrees with the leaf's AKI
    /// must still be walked. Under the old hard filter it was dropped before
    /// any signature check, and the path came back as a false `Incomplete`
    /// -- and worse, the aggregation rule ("an unexplored alternative
    /// forbids claiming refutation") was left true only by vacuum.
    ///
    /// Here the AKI-contradicting candidate is the *only* candidate, and its
    /// edge is refuted, so the walk must reach `Invalid` -- proving the
    /// candidate was really examined rather than silently discarded.
    #[test]
    fn an_aki_contradicting_candidate_is_still_walked() {
        use const_oid::db::rfc5280::{
            ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_KEY_USAGE, ID_CE_SUBJECT_KEY_IDENTIFIER,
        };

        let aki = AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(vec![1, 2, 3, 4]).unwrap()),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        };
        let leaf = CertBuilder::new("CN=ca", "CN=leaf")
            .ext(extension(ID_CE_AUTHORITY_KEY_IDENTIFIER, false, aki))
            .ext(extension(ID_CE_KEY_USAGE, true, KeyUsage(KeyUsages::DigitalSignature.into())))
            .build();

        let contradicting_ca = ca_extensions(CertBuilder::new("CN=root", "CN=ca").serial(2))
            .ext(extension(
                ID_CE_SUBJECT_KEY_IDENTIFIER,
                false,
                SubjectKeyIdentifier(OctetString::new(vec![9, 9, 9, 9]).unwrap()),
            ))
            .build();

        let store = TrustStore::new();
        let result = chain_of(std::slice::from_ref(&contradicting_ca), &store, &leaf);

        assert_eq!(
            result.status,
            PathStatus::Invalid,
            "the AKI-contradicting candidate must be walked and settled by its signature, not \
             filtered out (which would have produced Incomplete)"
        );
    }

    /// AKI-matching candidates are ordered first, and -- the part that
    /// matters -- **nobody is dropped**. A certificate planted in the
    /// token's certificate set therefore cannot displace the real issuer by
    /// being listed earlier, while a legitimate issuer that expresses no
    /// matching identifier still gets its turn.
    #[test]
    fn aki_orders_candidates_without_removing_any() {
        use const_oid::db::rfc5280::{
            ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_SUBJECT_KEY_IDENTIFIER,
        };

        let aki = AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(vec![1, 2, 3, 4]).unwrap()),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        };
        let leaf = CertBuilder::new("CN=ca", "CN=leaf")
            .ext(extension(ID_CE_AUTHORITY_KEY_IDENTIFIER, false, aki))
            .build();

        let named = ca_extensions(CertBuilder::new("CN=root", "CN=ca").serial(2))
            .ext(extension(
                ID_CE_SUBJECT_KEY_IDENTIFIER,
                false,
                SubjectKeyIdentifier(OctetString::new(vec![1, 2, 3, 4]).unwrap()),
            ))
            .build();
        let planted = ca_extensions(CertBuilder::new("CN=root", "CN=ca").serial(3)).build();
        let contradicting = ca_extensions(CertBuilder::new("CN=root", "CN=ca").serial(4))
            .ext(extension(
                ID_CE_SUBJECT_KEY_IDENTIFIER,
                false,
                SubjectKeyIdentifier(OctetString::new(vec![9, 9, 9, 9]).unwrap()),
            ))
            .build();

        let named_fp = cert_fingerprint_sha256(&named).unwrap();

        // The AKI-named candidate is listed LAST on the way in.
        let mut candidates = vec![&planted, &contradicting, &named];
        order_issuer_candidates(&mut candidates, &leaf);

        assert_eq!(
            candidates.len(),
            3,
            "ordering must never drop a candidate -- the aggregation rule depends on every \
             DN match actually being walked"
        );
        assert_eq!(
            cert_fingerprint_sha256(candidates[0]).unwrap(),
            named_fp,
            "the AKI-named candidate must be tried first"
        );
        // The two un-preferred candidates keep their original relative order.
        assert_eq!(
            cert_fingerprint_sha256(candidates[1]).unwrap(),
            cert_fingerprint_sha256(&planted).unwrap()
        );
    }

    // ---------------------------------------------------------------
    // The timestamping EKU, decomposed
    // ---------------------------------------------------------------

    /// Absent, malformed, non-critical and non-exclusive are four different
    /// answers, not one `false`.
    #[test]
    fn timestamping_eku_reports_which_condition_failed() {
        use const_oid::db::rfc5280::{ID_CE_EXT_KEY_USAGE, ID_KP_SERVER_AUTH, ID_KP_TIME_STAMPING};

        let bare = CertBuilder::new("CN=ca", "CN=leaf").build();
        assert_eq!(check_timestamping_eku(&bare), TimestampingEku::Absent);

        let eku = ExtendedKeyUsage(vec![ID_KP_TIME_STAMPING]);
        let duplicated = CertBuilder::new("CN=ca", "CN=leaf")
            .ext(extension(ID_CE_EXT_KEY_USAGE, true, eku.clone()))
            .ext(extension(ID_CE_EXT_KEY_USAGE, true, eku.clone()))
            .build();
        assert_eq!(check_timestamping_eku(&duplicated), TimestampingEku::Malformed);

        let not_critical = CertBuilder::new("CN=ca", "CN=leaf")
            .ext(extension(ID_CE_EXT_KEY_USAGE, false, eku.clone()))
            .build();
        assert_eq!(check_timestamping_eku(&not_critical), TimestampingEku::NotCritical);

        let shared = ExtendedKeyUsage(vec![ID_KP_TIME_STAMPING, ID_KP_SERVER_AUTH]);
        let not_exclusive = CertBuilder::new("CN=ca", "CN=leaf")
            .ext(extension(ID_CE_EXT_KEY_USAGE, true, shared))
            .build();
        assert_eq!(check_timestamping_eku(&not_exclusive), TimestampingEku::NotExclusive);

        let good = CertBuilder::new("CN=ca", "CN=leaf")
            .ext(extension(ID_CE_EXT_KEY_USAGE, true, eku))
            .build();
        assert_eq!(check_timestamping_eku(&good), TimestampingEku::Ok);
        assert!(check_timestamping_eku(&good).is_ok());
        assert!(check_timestamping_eku(&bare).reason().is_some());
    }
}
