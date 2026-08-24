//! Caller-supplied trust material for RFC 3161 chain verification
//!
//! Per ATL's trust model, this crate ships **no** identities: no TSA roots,
//! no operator keys, no baked-in fingerprints. `atl-core` is a reference
//! implementation of a public protocol; Evidentum is just one operator of an
//! ATL log among others the protocol does not privilege. A [`TrustStore`] is
//! how a caller (an application, a CLI flag, a config file -- never this
//! crate) supplies the trust material it has obtained through some external,
//! trusted channel.
//!
//! A [`TrustStore`] holds two independent things:
//!
//! - **Anchors**: certificates or SPKI pins that terminate a chain
//!   successfully. Deliberately *not* required to be self-signed: several
//!   real-world TSA tokens (Sectigo, DigiCert) name a "root" certificate that
//!   is itself cross-signed by an absent legacy root. Pinning that
//!   already-present certificate as an anchor is the only way to trust such
//!   a chain without also being handed the missing legacy certificate.
//! - **Intermediates**: extra certificates the caller supplies to bridge a
//!   gap the token's own certificate set does not cover.

use x509_cert::Certificate;

use super::chain::{cert_der_bytes, cert_spki_sha256};
use super::result::Sha256Digest;

/// Caller-supplied trust material: anchors that terminate a chain
/// successfully, and extra intermediates to bridge missing links.
///
/// Empty by default (`TrustStore::new()` / `TrustStore::default()`), in
/// which case every chain terminates, at best, in
/// [`super::TerminalAnchor::Assumed`] -- never `Trusted`. This matches the
/// "no `TrustStore` => `Assumed`" requirement: there is no implicit trust
/// anchor anywhere in this crate.
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    anchor_certificates: Vec<Certificate>,
    anchor_spki_pins: Vec<Sha256Digest>,
    intermediate_certificates: Vec<Certificate>,
}

impl TrustStore {
    /// An empty trust store: no anchors, no intermediates. Every chain
    /// verified against it terminates, at best, in `Assumed`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a full certificate as a trust anchor.
    ///
    /// The certificate need not be self-signed: a chain terminates
    /// successfully as soon as it reaches a certificate equal to this one,
    /// regardless of who issued it.
    #[must_use]
    pub fn with_anchor_certificate(mut self, cert: Certificate) -> Self {
        self.anchor_certificates.push(cert);
        self
    }

    /// Pin a trust anchor by the SHA-256 hash of its `SubjectPublicKeyInfo`
    /// (DER-encoded).
    ///
    /// A chain terminates successfully as soon as it reaches *any*
    /// certificate whose SPKI hashes to this value.
    #[must_use]
    pub fn with_anchor_spki_pin(mut self, spki_sha256: Sha256Digest) -> Self {
        self.anchor_spki_pins.push(spki_sha256);
        self
    }

    /// Supply an extra intermediate certificate to bridge a gap the token's
    /// own certificate set does not cover.
    ///
    /// This does *not* make the certificate a trust anchor by itself: chain
    /// construction may walk through it, but the chain must still reach an
    /// anchor (or a self-signed certificate, yielding `Assumed`) to
    /// terminate.
    #[must_use]
    pub fn with_intermediate_certificate(mut self, cert: Certificate) -> Self {
        self.intermediate_certificates.push(cert);
        self
    }

    /// All certificates chain construction may walk through: intermediates
    /// plus anchor certificates (an anchor certificate is a perfectly valid
    /// issuer for a further-out chain too, though in practice it is usually
    /// the terminal node).
    pub(super) fn candidate_certificates(&self) -> impl Iterator<Item = &Certificate> {
        self.intermediate_certificates.iter().chain(self.anchor_certificates.iter())
    }

    /// If `cert` matches a configured anchor (full-certificate match or SPKI
    /// pin), return the certificate's own SHA-256 fingerprint.
    pub(super) fn matching_anchor_fingerprint(&self, cert: &Certificate) -> Option<Sha256Digest> {
        let der = cert_der_bytes(cert)?;

        let matches_full_cert = self
            .anchor_certificates
            .iter()
            .any(|anchor| cert_der_bytes(anchor).as_deref() == Some(der.as_slice()));

        let matches_pin = if self.anchor_spki_pins.is_empty() {
            false
        } else {
            let spki_hash = cert_spki_sha256(cert)?;
            self.anchor_spki_pins.contains(&spki_hash)
        };

        if matches_full_cert || matches_pin {
            Some(sha256(&der))
        } else {
            None
        }
    }
}

fn sha256(data: &[u8]) -> Sha256Digest {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
