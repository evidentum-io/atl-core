//! Digest and signature algorithm dispatch
//!
//! Covers the algorithm matrix observed across real-world TSA tokens
//! (FreeTSA, Sectigo, DigiCert, GlobalSign): RSA PKCS#1 v1.5 (3072/4096-bit
//! keys, SHA-256/384/512, both the bare `rsaEncryption` OID and the
//! composite `shaNNNWithRSAEncryption` OIDs) and ECDSA on P-384 with a
//! SHA-512 digest. P-256 is supported opportunistically (RustCrypto gives it
//! to us for free) even though it was not observed in the corpus.
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

/// Resolve a `SignerInfo`/certificate `signatureAlgorithm` OID into the
/// digest it commits to, applying the bare-vs-composite RSA rule and the
/// "CMS Algorithm Protection" compatible cross-check for ECDSA/composite-RSA
/// OIDs (which always fix their own digest).
fn resolve_digest(
    sig_alg_oid: &ObjectIdentifier,
    digest_hint: Option<&AlgorithmIdentifierOwned>,
) -> Result<DigestAlg, SigVerifyError> {
    use const_oid::db::rfc5912::{
        ECDSA_WITH_SHA_256, ECDSA_WITH_SHA_384, ECDSA_WITH_SHA_512, RSA_ENCRYPTION,
        SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION, SHA_512_WITH_RSA_ENCRYPTION,
    };

    let fixed = match *sig_alg_oid {
        RSA_ENCRYPTION => {
            // Bare rsaEncryption: the digest comes entirely from the hint.
            let hint = digest_hint.ok_or(SigVerifyError::BareRsaRequiresDigestHint)?;
            return DigestAlg::from_oid(&hint.oid);
        }
        SHA_256_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_256 => DigestAlg::Sha256,
        SHA_384_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_384 => DigestAlg::Sha384,
        SHA_512_WITH_RSA_ENCRYPTION | ECDSA_WITH_SHA_512 => DigestAlg::Sha512,
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

    Ok(fixed)
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

    let digest_alg = resolve_digest(&sig_alg.oid, digest_hint)?;
    let digest = digest_alg.digest(signed_bytes);

    match spki.algorithm.oid {
        RSA_ENCRYPTION => verify_rsa(spki, digest_alg, &digest, signature),
        ID_EC_PUBLIC_KEY => verify_ecdsa(spki, &digest, signature),
        other => Err(SigVerifyError::UnsupportedSignatureAlgorithm(format!(
            "unsupported public key algorithm {other}"
        ))),
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
