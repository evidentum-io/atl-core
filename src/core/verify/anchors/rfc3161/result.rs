//! Result types for RFC 3161 anchor verification
//!
//! These types report **facts**, not a verdict. In particular
//! [`TerminalAnchor::Assumed`] is a fact ("the chain resolves to a
//! name-self-issued certificate nobody vouched for"), never a success: no
//! aggregate success computation may treat `Assumed` as equivalent to
//! `Trusted`.
//!
//! Symmetrically, [`PathStatus::Incomplete`] and
//! [`PathStatus::Indeterminate`] are facts about *this verifier's* limits,
//! never about the token: neither may be reported as refuted evidence.
//!
//! Per ATL's trust model, no identity (TSA root, operator key, ...) lives in
//! this crate. Trust material is supplied by the caller via [`super::TrustStore`],
//! and when none is supplied the terminal anchor is honestly reported as
//! `Assumed` rather than silently treated as valid.

/// SHA-256 hash, used throughout for certificate/SPKI fingerprints.
pub type Sha256Digest = [u8; 32];

/// Identity facts about the certificate that produced the CMS signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerFacts {
    /// RFC 4514-ish display of the signer's subject Distinguished Name.
    pub subject: String,
    /// RFC 4514-ish display of the signer's issuer Distinguished Name.
    pub issuer: String,
    /// Certificate serial number, hex-encoded (no separators, uppercase).
    pub serial_hex: String,
    /// SHA-256 hash of the signer certificate's `SubjectPublicKeyInfo` (DER).
    pub spki_sha256: Sha256Digest,
}

/// Whether a name-self-issued terminal certificate's signature over itself
/// was actually checked.
///
/// The distinction exists because "the signature is wrong" and "this crate
/// cannot check this signature at all" are different facts, and collapsing
/// them is what let a SHA-1-self-signed root (still common: DigiCert Assured
/// ID Root CA and many other long-lived roots sign themselves with SHA-1) be
/// reported as refuted evidence. A self-signature this crate cannot evaluate
/// refutes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfSignature {
    /// The certificate's signature over its own `tbsCertificate` was checked
    /// and verified under its own public key.
    Verified,
    /// The signature could **not** be checked: its signature algorithm,
    /// public-key algorithm or curve is not one this crate implements (see
    /// [`super::algorithms`]). Nothing about the signature is asserted --
    /// neither that it is correct nor that it is not.
    Unverifiable,
}

/// Where certificate-chain construction terminated.
///
/// `Assumed` and `Trusted` are structurally identical (a fingerprint, plus
/// for `Assumed` the self-signature fact) on purpose: the only thing that
/// may distinguish "this token is anchored" from "this token merely names a
/// self-issued certificate nobody vouched for" is whether the fingerprint
/// was matched against caller-supplied trust material. Do not special-case
/// `Assumed` into a partial success anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalAnchor {
    /// The chain resolves to a **name-self-issued** certificate (its issuer
    /// and subject Distinguished Names are equal, RFC 5280 3.2) that was
    /// **not** matched against any caller-supplied [`super::TrustStore`].
    /// Nobody vouches for it. Never contributes to aggregate success.
    ///
    /// Whether that certificate actually *signs itself correctly* is a
    /// separate fact, reported in `self_signature`: with
    /// [`SelfSignature::Verified`] the self-signature was checked and holds;
    /// with [`SelfSignature::Unverifiable`] this crate could not evaluate it
    /// at all, and the accompanying [`PathStatus`] is
    /// [`PathStatus::Indeterminate`] rather than [`PathStatus::Complete`].
    /// A name-self-issued certificate whose self-signature is checked and
    /// *fails* is never reported here at all -- that is a refuted path.
    Assumed {
        /// SHA-256 fingerprint (over the full certificate DER) of the
        /// unverified self-issued certificate the chain terminated at.
        sha256_fingerprint: Sha256Digest,
        /// Whether that certificate's signature over itself was verified or
        /// merely uncheckable.
        self_signature: SelfSignature,
    },
    /// The chain resolves to a certificate matched against the caller's
    /// [`super::TrustStore`] (by full-certificate match or by SPKI pin), even
    /// if that certificate is itself not self-signed (e.g. a cross-signed
    /// intermediate acting as the operator's configured trust point).
    Trusted {
        /// SHA-256 fingerprint (over the full certificate DER) of the
        /// matched trust anchor.
        sha256_fingerprint: Sha256Digest,
    },
}

impl TerminalAnchor {
    /// The fingerprint of the terminal certificate, regardless of trust.
    #[must_use]
    pub const fn fingerprint(&self) -> &Sha256Digest {
        match self {
            Self::Assumed { sha256_fingerprint, .. } | Self::Trusted { sha256_fingerprint } => {
                sha256_fingerprint
            }
        }
    }

    /// True only for [`Self::Trusted`].
    #[must_use]
    pub const fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted { .. })
    }
}

/// Outcome of certificate-chain construction from the signer certificate
/// towards a trust anchor.
///
/// The four variants separate four genuinely different things, and the
/// separation is the whole point: **success**, **missing material**,
/// **inability to check**, and **refutation**. Collapsing the middle two
/// into `Invalid` is what made this crate report "the evidence is disproved"
/// about tokens nothing had disproved.
///
/// # Only `Invalid` is a refutation
///
/// `Incomplete` and `Indeterminate` both mean *this verifier could not
/// finish*, never *the token is bad*. A consumer that maps either of them to
/// a failure verdict is reintroducing the bug this enum exists to prevent.
/// Correspondingly, an outcome may only be `Invalid` when no viable
/// unexplored alternative path remains: a certificate set may contain
/// unrelated certificates (RFC 5652 5.1), and a same-named candidate whose
/// signature does not check out proves only that *that* certificate is not
/// the issuer -- never that the real issuer does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStatus {
    /// A path was built all the way to a terminal certificate (either
    /// name-self-issued with a *verified* self-signature, or
    /// trust-store-matched) with every link cryptographically and
    /// structurally valid.
    Complete,
    /// No cryptographic or structural violation was found, but chain
    /// construction could not be extended: no candidate issuer certificate
    /// was available, or every candidate already appeared on the path and
    /// was pruned by the cycle guard. Both mean a certificate is missing on
    /// the verifier's side. **Not a refutation** -- the cycle guard forbids
    /// repeating a certificate, it does not establish that no genuine
    /// issuer with that name exists.
    Incomplete,
    /// Chain construction could not be carried to a conclusion for a reason
    /// that says nothing about the token's validity: a signature this crate
    /// cannot evaluate (unsupported signature algorithm, public-key
    /// algorithm, or curve -- SHA-1-signed roots land here), the
    /// [`Self::Complete`]-blocking case of a name-self-issued terminal whose
    /// self-signature is unverifiable, the exploration depth limit, or an
    /// internal DER re-encoding failure. **Not a refutation.**
    ///
    /// A cycle-pruned path is [`Self::Incomplete`], not this: nothing about
    /// it could not be *evaluated*, there was simply no unused certificate
    /// left to continue with.
    Indeterminate,
    /// A candidate link was found and **refuted**: its signature was checked
    /// and does not verify, its encoding is malformed, the certificate was
    /// outside its validity period at `genTime`, or it violated
    /// `BasicConstraints`, `KeyUsage`, path length, or the
    /// unrecognized-critical-extension rule. Reported only when no viable
    /// unexplored alternative remains.
    Invalid,
}

/// Outcome of comparing the token's `MessageImprint` against the root hash
/// the caller asked about.
///
/// Four states. Three of them exist for the same reason [`CmsSignature`] has
/// three: the comparison needs the imprint's hash algorithm to be one this
/// crate implements, and when it is not, **no comparison happens at all** --
/// reporting that as a mismatch asserts the outcome of a check that never
/// ran. The fourth splits the refuted side, because "the values differ" and
/// "this is not a well-formed hash" are different proven defects and only
/// one of them is a mismatch.
///
/// ATL does not require SHA-256 in `messageImprint` -- its documentation
/// states a mandatory *minimum* of algorithm support, not a prohibition on
/// the rest -- so an unrecognised algorithm is this verifier's limitation,
/// not the token's defect. Hence [`Self::Indeterminate`] rather than a
/// refutation with a special reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageImprint {
    /// The imprint's hash algorithm is supported, and the hash equals the
    /// expected root.
    Verified,
    /// The comparison was performed and the values differ. **A refutation**
    /// -- and specifically a *mismatch*: the token attests to some other
    /// data.
    Mismatch,
    /// The imprint is structurally broken: its hash length contradicts the
    /// algorithm it names. **A refutation**, but emphatically not a
    /// mismatch -- no comparison could be attempted, because the value is
    /// not a well-formed hash in the first place. Kept apart from
    /// [`Self::Mismatch`] because reporting "does not match the expected
    /// root" here would explain a proven defect with the wrong cause, which
    /// is the same class of error as reporting an unchecked fact.
    Malformed,
    /// The imprint names a hash algorithm this crate does not implement, so
    /// no comparison was performed. Asserts nothing about the token.
    /// **Never a refutation.**
    Indeterminate,
}

impl MessageImprint {
    /// `true` only for [`Self::Verified`].
    #[must_use]
    pub const fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }

    /// `true` for the states that were checked and came out false -- the
    /// only ones that may be shown to a user as evidence against the token.
    #[must_use]
    pub const fn is_refuted(self) -> bool {
        matches!(self, Self::Mismatch | Self::Malformed)
    }
}

/// Outcome of CMS `SignerInfo` signature verification.
///
/// Three states, for the same reason [`PathStatus`] has four: "the signature
/// does not verify" and "this crate cannot evaluate this signature" are
/// different facts, and a boolean forces them into the same answer. That
/// conflation is not hypothetical here -- [`super::algorithms`] deliberately
/// does not implement P-521 or RSA-PSS, so a token from a TSA using either
/// would, under a boolean, be published as *refuted evidence*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmsSignature {
    /// The signature over the signed attributes verified against the signer
    /// certificate's public key, and every signed-attribute check
    /// (`content-type`, `message-digest`, ESS binding, CMS Algorithm
    /// Protection) passed.
    Verified,
    /// A checked fact is false: the signature does not verify, a required
    /// signed attribute is missing, duplicated, malformed or mismatched, the
    /// ESS binding names a different certificate, or the token carries
    /// something other than exactly one `SignerInfo`. **A refutation.**
    Refuted,
    /// The signature could **not be evaluated**: an unsupported signature,
    /// digest, or public-key algorithm, an unsupported curve, an ESS binding
    /// whose hash algorithm this crate does not implement, or no signer
    /// certificate to check against. Asserts nothing about the signature.
    /// **Never a refutation** -- a consumer must fail closed, not report
    /// broken evidence.
    Indeterminate,
}

impl CmsSignature {
    /// `true` only for [`Self::Verified`].
    #[must_use]
    pub const fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }

    /// `true` only for [`Self::Refuted`] -- the only state that may be
    /// presented to a user as evidence against the token.
    #[must_use]
    pub const fn is_refuted(self) -> bool {
        matches!(self, Self::Refuted)
    }
}

/// Why the signer certificate's `id-kp-timeStamping` Extended Key Usage
/// check came out the way it did.
///
/// RFC 3161 2.3 requires the extension to be present, critical, and the sole
/// asserted purpose. Four quite different things can make that check fail,
/// and a single `false` cannot tell a caller which -- "the TSA issued a
/// signer certificate with no EKU at all" and "the extension is duplicated
/// or malformed" call for different reactions.
///
/// A sixth state, [`Self::NotChecked`], is not a failure at all: it records
/// that the check never ran. A caller branching on a boolean cannot tell it
/// apart from `Absent` and will refute on a fact nobody examined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampingEku {
    /// Present, critical, and `id-kp-timeStamping` is the only purpose.
    Ok,
    /// The check never ran, because the token was rejected before a signer
    /// certificate was settled on. Deliberately distinct from [`Self::Absent`]:
    /// "we did not look" is not "there is nothing there".
    NotChecked,
    /// The extension is absent entirely.
    Absent,
    /// The extension is present more than once, or its contents do not
    /// decode as an `ExtendedKeyUsage`.
    Malformed,
    /// Present and correct in content, but not marked critical.
    NotCritical,
    /// Present and critical, but it does not assert `id-kp-timeStamping`
    /// exclusively (either a different purpose, or additional ones).
    NotExclusive,
}

impl TimestampingEku {
    /// `true` only for [`Self::Ok`].
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// A short explanation, or `None` when the check passed.
    #[must_use]
    pub const fn reason(self) -> Option<&'static str> {
        match self {
            Self::Ok => None,
            Self::NotChecked => Some(
                "the ExtendedKeyUsage was never examined: no signer certificate was settled on",
            ),
            Self::Absent => Some("no ExtendedKeyUsage extension on the signer certificate"),
            Self::Malformed => {
                Some("the ExtendedKeyUsage extension is duplicated or does not decode")
            }
            Self::NotCritical => Some(
                "the ExtendedKeyUsage extension is not marked critical, as RFC 3161 2.3 requires",
            ),
            Self::NotExclusive => {
                Some("id-kp-timeStamping is not the only purpose asserted by ExtendedKeyUsage")
            }
        }
    }
}

/// Revocation-checking status.
///
/// This crate performs no I/O (see the crate's design constraints), so it
/// can never itself check revocation. `NotChecked` is the only value today;
/// it exists as an explicit field (rather than silence) so callers cannot
/// mistake "we didn't check" for "we checked and it's fine".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Revocation {
    /// No revocation check was performed (no CRL/OCSP material was
    /// supplied). Verification proceeded on other grounds regardless.
    #[default]
    NotChecked,
}

/// The complete set of facts established while verifying an RFC 3161
/// timestamp token.
///
/// This is intentionally *not* a single `is_valid: bool`. Callers combine
/// these facts according to their own risk posture; [`Self::is_fully_valid`]
/// provides the conservative combination ATL itself uses.
#[derive(Debug, Clone)]
pub struct Rfc3161AnchorFacts {
    /// Whether the `MessageImprint` in the token's `TSTInfo` matched the
    /// expected root hash, contradicted it, or could not be compared at all.
    ///
    /// Three-valued on purpose -- see [`MessageImprint`]. An imprint whose
    /// hash algorithm this crate does not implement is
    /// [`MessageImprint::Indeterminate`], never a mismatch: the comparison
    /// never took place.
    pub message_imprint: MessageImprint,
    /// Whether the CMS `SignerInfo` signature verified, was refuted, or
    /// could not be evaluated at all: content-type and message-digest signed
    /// attributes, the ESS signing-certificate binding (v1 and/or v2), and
    /// the cryptographic signature over the signed attributes.
    ///
    /// Three-valued on purpose -- see [`CmsSignature`]. Only
    /// [`CmsSignature::Refuted`] may be reported as evidence against the
    /// token; [`CmsSignature::Indeterminate`] must fail closed without
    /// claiming anything.
    pub cms_signature: CmsSignature,
    /// Every certificate on the (best) constructed chain was structurally
    /// valid (signatures, `BasicConstraints`, `KeyUsage`, path length, no
    /// unrecognized critical extensions) and within its validity period *at
    /// `gen_time`*, not at wall-clock "now".
    ///
    /// # The exact boundary
    ///
    /// "Every certificate on the chain" means **from the signer certificate
    /// up to, but not including, a configured non-leaf terminal anchor**.
    /// RFC 5280 6.1 treats a trust anchor as an externally supplied trusted
    /// input rather than a link of the path being validated, so a
    /// certificate the caller pinned is not itself re-examined -- that is
    /// what keeps an expired-but-explicitly-designated root, and a
    /// cross-signed "root" whose own issuer is absent, usable at all. The
    /// edge *into* that anchor is verified in full, as is every certificate
    /// below it.
    ///
    /// The signer certificate is never exempted, pinned or not: its validity
    /// at `gen_time`, its critical extensions and its `KeyUsage` are checked
    /// before any trust matching is attempted. A timestamp's whole claim is
    /// temporal, so publishing `true` here for a signer that had expired at
    /// `gen_time` would assert a fact nobody checked.
    ///
    /// This is independent of *trust*: it is `true` for a chain terminating
    /// in `TerminalAnchor::Assumed { self_signature: Verified }` just as
    /// much as one terminating in `TerminalAnchor::Trusted`. It is `false`
    /// for `Assumed { self_signature: Unverifiable }`, and that is not a
    /// trust judgement either: there the terminal's own signature could not
    /// be evaluated, so the chain was never established as valid in the
    /// first place (the accompanying [`PathStatus`] is
    /// [`PathStatus::Indeterminate`]).
    pub chain_valid_at_gen_time: bool,
    /// The signer certificate carries the `id-kp-timeStamping` Extended Key
    /// Usage, marked critical, and it is the *only* purpose asserted.
    ///
    /// Exactly `timestamping_eku.is_ok()`; kept as a plain boolean for
    /// callers that only need the yes/no. Read [`Self::timestamping_eku`]
    /// when the reason matters.
    pub timestamping_eku_ok: bool,
    /// *Why* [`Self::timestamping_eku_ok`] came out the way it did.
    pub timestamping_eku: TimestampingEku,
    /// `TSTInfo.genTime`, as nanoseconds since the Unix epoch, if it could
    /// be parsed.
    ///
    /// This is what the token **claims**, read straight from the decoded
    /// `TSTInfo` before any signature is checked — it is not an established
    /// time. It is present even when [`Self::cms_signature`] is not
    /// `Verified`, because certificate validity has to be evaluated against
    /// *some* instant and this is the only one on offer. Treat it as an
    /// established timestamp only once [`Self::is_fully_valid`] holds.
    pub gen_time: Option<u64>,
    /// Identity of the CMS signer certificate, if one was found.
    pub signer: Option<SignerFacts>,
    /// Where chain construction terminated, if it terminated at all.
    pub terminal_anchor: Option<TerminalAnchor>,
    /// Whether chain construction completed, ran out of certificates, could
    /// not be evaluated, or hit a link that was checked and refuted. See
    /// [`PathStatus`] -- and note that only the last of the four is a
    /// refutation.
    pub path_status: PathStatus,
    /// Revocation-checking status (always `NotChecked` today; see
    /// [`Revocation`]).
    pub revocation: Revocation,
    /// Human-readable diagnostic for the first problem found, if any. Not
    /// part of the fact set proper -- purely for error messages.
    pub diagnostic: Option<String>,
    /// Human-readable diagnostics gathered while exploring certificate
    /// paths: the reasons alternative paths were refuted, could not be
    /// evaluated, or were pruned. Not part of the fact set proper -- purely
    /// for error messages, and deliberately kept even when the *reported*
    /// [`Self::path_status`] is not a refutation, so a caller can say why a
    /// path was not reached without the crate having to pretend it was
    /// disproved.
    pub chain_diagnostic: Option<String>,
}

impl Rfc3161AnchorFacts {
    /// ATL's conservative aggregate success: every fact holds **and** the
    /// chain resolved to a caller-configured [`TerminalAnchor::Trusted`]
    /// anchor.
    ///
    /// `TerminalAnchor::Assumed` never satisfies this, by construction: it
    /// is excluded because `path_status` must be `Complete` **and**
    /// `terminal_anchor` must specifically be `Trusted`.
    #[must_use]
    pub fn is_fully_valid(&self) -> bool {
        self.message_imprint.is_verified()
            && self.cms_signature.is_verified()
            && self.chain_valid_at_gen_time
            && self.timestamping_eku_ok
            && matches!(self.path_status, PathStatus::Complete)
            && matches!(self.terminal_anchor, Some(TerminalAnchor::Trusted { .. }))
    }
}
