//! Result types for RFC 3161 anchor verification
//!
//! These types report **facts**, not a verdict. In particular
//! [`TerminalAnchor::Assumed`] is a fact ("the chain resolves to an
//! unverified self-signed certificate"), never a success: no aggregate
//! success computation may treat `Assumed` as equivalent to `Trusted`.
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

/// Where certificate-chain construction terminated.
///
/// `Assumed` and `Trusted` are structurally identical (a fingerprint) on
/// purpose: the only thing that may distinguish "this token is anchored" from
/// "this token merely names a self-signed certificate nobody vouched for" is
/// whether the fingerprint was matched against caller-supplied trust
/// material. Do not special-case `Assumed` into a partial success anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalAnchor {
    /// The chain resolves to a self-signed certificate that was **not**
    /// matched against any caller-supplied [`super::TrustStore`]. The
    /// certificate correctly signs itself, but nobody vouches for it. Never
    /// contributes to aggregate success.
    Assumed {
        /// SHA-256 fingerprint (over the full certificate DER) of the
        /// unverified self-signed certificate the chain terminated at.
        sha256_fingerprint: Sha256Digest,
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
            Self::Assumed { sha256_fingerprint } | Self::Trusted { sha256_fingerprint } => {
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
/// `Incomplete` and `Invalid` are deliberately distinct: a chain that simply
/// cannot be extended because an issuer certificate is missing is a
/// different fact than a chain where a candidate link was found but failed
/// cryptographic or structural validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStatus {
    /// A path was built all the way to a terminal certificate (either
    /// self-signed or trust-store-matched) with every link cryptographically
    /// and structurally valid.
    Complete,
    /// No cryptographic or structural violation was found, but chain
    /// construction ran out of certificates before reaching a self-signed or
    /// trust-store-matched terminal (a missing issuer certificate).
    Incomplete,
    /// A candidate link was found but failed: signature verification,
    /// certificate validity period, `BasicConstraints`, `KeyUsage`, path
    /// length, or an unrecognized critical extension.
    Invalid,
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
    /// The `MessageImprint` in the token's `TSTInfo` matches the expected
    /// root hash the caller asked to verify.
    pub imprint_matches_root: bool,
    /// The CMS `SignerInfo` signature verified: content-type and
    /// message-digest signed attributes are correct, the signer certificate
    /// is bound via the ESS signing-certificate attribute (v1 and/or v2),
    /// and the cryptographic signature over the signed attributes (or, if
    /// absent, the content) verifies against the signer's public key.
    pub cms_signature_valid: bool,
    /// Every certificate on the (best) constructed chain -- from the signer
    /// certificate up to the terminal certificate -- was structurally valid
    /// (signatures, `BasicConstraints`, `KeyUsage`, path length, no
    /// unrecognized critical extensions) and within its validity period *at
    /// `gen_time`*, not at wall-clock "now".
    ///
    /// This is independent of trust: it is `true` for a chain that
    /// terminates in `TerminalAnchor::Assumed` just as much as one that
    /// terminates in `TerminalAnchor::Trusted`.
    pub chain_valid_at_gen_time: bool,
    /// The signer certificate carries the `id-kp-timeStamping` Extended Key
    /// Usage, marked critical, and it is the *only* purpose asserted.
    pub timestamping_eku_ok: bool,
    /// `TSTInfo.genTime`, as nanoseconds since the Unix epoch, if it could be
    /// parsed.
    pub gen_time: Option<u64>,
    /// Identity of the CMS signer certificate, if one was found.
    pub signer: Option<SignerFacts>,
    /// Where chain construction terminated, if it terminated at all.
    pub terminal_anchor: Option<TerminalAnchor>,
    /// Whether chain construction completed, ran out of certificates, or hit
    /// an invalid link.
    pub path_status: PathStatus,
    /// Revocation-checking status (always `NotChecked` today; see
    /// [`Revocation`]).
    pub revocation: Revocation,
    /// Human-readable diagnostic for the first problem found, if any. Not
    /// part of the fact set proper -- purely for error messages.
    pub diagnostic: Option<String>,
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
        self.imprint_matches_root
            && self.cms_signature_valid
            && self.chain_valid_at_gen_time
            && self.timestamping_eku_ok
            && matches!(self.path_status, PathStatus::Complete)
            && matches!(self.terminal_anchor, Some(TerminalAnchor::Trusted { .. }))
    }
}
