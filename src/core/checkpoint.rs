//! Checkpoint wire format and Ed25519 verification
//!
//! This module implements the ATL Protocol v1 checkpoint structure, which is a
//! cryptographic commitment to the state of the log at a specific point in time.
//!
//! ## Design Decision: Fixed Binary Wire Format
//!
//! The checkpoint is serialized to a **fixed 98-byte binary blob** that is signed.
//! This eliminates parser ambiguities and ensures cross-implementation compatibility.
//!
//! ## Wire Format (98 bytes)
//!
//! ```text
//! Offset  Size   Field         Encoding
//! ------  ----   -----         --------
//! 0       18     Magic Bytes   "ATL-Protocol-v1-CP" (ASCII)
//! 18      32     Origin ID     SHA256 of Instance UUID (binary)
//! 50      8      Tree Size     u64 little-endian
//! 58      8      Timestamp     u64 little-endian (Unix nanoseconds)
//! 66      32     Root Hash     SHA256 root of Merkle tree (binary)
//! ------  ----
//! Total:  98 bytes
//! ```
//!
//! The Ed25519 signature (64 bytes) is stored separately in the `Checkpoint` structure
//! and is NOT part of the signed blob.
//!
//! ## Signing and Verification
//!
//! **NOTE:** This module provides ONLY verification. Key generation and signing
//! operations are in `atl-server` (not in this pure cryptographic library).
//!
//! - `CheckpointVerifier`: Verifies signatures using Ed25519 public keys
//! - `CheckpointSigner`: (atl-server only) Signs checkpoints with Ed25519 private keys
//!
//! ## Example
//!
//! ```no_run
//! use atl_core::core::checkpoint::{Checkpoint, CheckpointVerifier, compute_key_id};
//! use ed25519_dalek::VerifyingKey;
//!
//! // Deserialize checkpoint from wire format
//! let checkpoint_bytes: [u8; 98] = [0; 98]; // received from network
//! let checkpoint = Checkpoint::from_bytes(&checkpoint_bytes)?;
//!
//! // Verify signature
//! let public_key_bytes: [u8; 32] = [0; 32]; // trusted public key
//! let verifier = CheckpointVerifier::from_bytes(&public_key_bytes)?;
//! checkpoint.verify(&verifier)?;
//!
//! # Ok::<(), atl_core::AtlError>(())
//! ```

use crate::error::{AtlError, AtlResult};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

// ========== Constants ==========

/// Magic bytes for checkpoint wire format (18 bytes ASCII)
pub const CHECKPOINT_MAGIC: &[u8; 18] = b"ATL-Protocol-v1-CP";

/// Total size of the checkpoint binary blob (without signature)
pub const CHECKPOINT_BLOB_SIZE: usize = 98;

// ========== Core Structures ==========

/// A checkpoint represents the cryptographic commitment to the log state.
///
/// This is equivalent to a "Signed Tree Head" (STH) in Certificate Transparency.
///
/// ## Invariants
///
/// - `origin` is SHA256 of the Instance UUID (32 bytes)
/// - `tree_size` is the number of entries in the log (0 for empty log)
/// - `timestamp` is Unix time in nanoseconds
/// - `root_hash` is the Merkle tree root hash (32 bytes)
/// - `signature` is Ed25519 signature over the 98-byte wire format (64 bytes)
/// - `key_id` is SHA256 of the signing public key (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// SHA256 of the Instance UUID
    pub origin: [u8; 32],

    /// Number of entries in the tree (0 for empty log)
    pub tree_size: u64,

    /// Unix timestamp in nanoseconds
    pub timestamp: u64,

    /// Root hash of the Merkle tree (SHA256)
    pub root_hash: [u8; 32],

    /// Ed25519 signature of the 98-byte wire format (64 bytes)
    pub signature: [u8; 64],

    /// SHA256 of the signing public key (32 bytes)
    pub key_id: [u8; 32],
}

/// JSON-serializable representation of a checkpoint
///
/// This is used for API responses. The wire format for signing is binary.
///
/// ## Format
///
/// ```json
/// {
///   "origin": "sha256:a1b2c3d4...",
///   "tree_size": 1000000,
///   "root_hash": "sha256:9f86d081...",
///   "timestamp": 1767225600000000000,
///   "signature": "base64:MEUCIQD...",
///   "key_id": "sha256:e5f6g7h8..."
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckpointJson {
    /// Format: "sha256:<64hex>"
    pub origin: String,

    /// Number of entries in the tree
    pub tree_size: u64,

    /// Format: "sha256:<64hex>"
    pub root_hash: String,

    /// Unix timestamp in nanoseconds
    pub timestamp: u64,

    /// Format: "base64:\<signature\>"
    pub signature: String,

    /// Format: "sha256:<64hex>"
    pub key_id: String,
}

/// Verifier for checkpoint Ed25519 signatures
///
/// This holds a public key for checkpoint signature verification.
/// The signature serves as an **integrity check** to ensure the checkpoint
/// fields have not been corrupted or tampered with.
///
/// ## Trust Model
///
/// Per ATL Protocol v2.0 Section 1.2:
/// > "Verifiers do NOT need to trust the Log Operator. Trust is derived
/// > exclusively from external, independent anchors."
///
/// The signature does NOT establish trust. Trust comes from external anchors
/// (RFC 3161 TSA or Bitcoin OTS). The signature provides an additional
/// integrity guarantee when the public key is known.
///
/// ## Usage
///
/// For most verification scenarios, you don't need this struct directly.
/// Use anchor-based verification for trust.
///
/// Use `CheckpointVerifier` only when you have a known public key and want
/// the additional integrity check:
///
/// ```rust,ignore
/// use atl_core::{CheckpointVerifier, ReceiptVerifier};
///
/// // Optional: add signature integrity check
/// let key_bytes: [u8; 32] = /* known public key */;
/// let cv = CheckpointVerifier::from_bytes(&key_bytes)?;
/// let verifier = ReceiptVerifier::with_key(cv);
/// ```
#[derive(Debug, Clone)]
pub struct CheckpointVerifier {
    verifying_key: VerifyingKey,
    key_id: [u8; 32],
}

// ========== Checkpoint Implementation ==========

impl Checkpoint {
    /// Create a new checkpoint with all fields
    ///
    /// ## Arguments
    ///
    /// - `origin`: SHA256 of the Instance UUID
    /// - `tree_size`: Number of entries in the log
    /// - `timestamp`: Unix timestamp in nanoseconds
    /// - `root_hash`: Merkle tree root hash
    /// - `signature`: Ed25519 signature (64 bytes)
    /// - `key_id`: SHA256 of the signing public key
    ///
    /// ## Note
    ///
    /// This constructor does NOT verify the signature. Use `verify()` to check
    /// the signature after construction.
    #[must_use]
    pub const fn new(
        origin: [u8; 32],
        tree_size: u64,
        timestamp: u64,
        root_hash: [u8; 32],
        signature: [u8; 64],
        key_id: [u8; 32],
    ) -> Self {
        Self { origin, tree_size, timestamp, root_hash, signature, key_id }
    }

    /// Serialize checkpoint to 98-byte binary wire format
    ///
    /// This produces the exact bytes that are signed by Ed25519.
    ///
    /// ## Wire Format Layout
    ///
    /// ```text
    /// [0..18]   Magic: "ATL-Protocol-v1-CP"
    /// [18..50]  Origin ID (32 bytes)
    /// [50..58]  Tree Size (u64 LE)
    /// [58..66]  Timestamp (u64 LE)
    /// [66..98]  Root Hash (32 bytes)
    /// ```
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CHECKPOINT_BLOB_SIZE] {
        let mut blob = [0u8; CHECKPOINT_BLOB_SIZE];

        // Magic bytes (0..18)
        blob[0..18].copy_from_slice(CHECKPOINT_MAGIC);

        // Origin ID (18..50)
        blob[18..50].copy_from_slice(&self.origin);

        // Tree size (50..58) - little endian
        blob[50..58].copy_from_slice(&self.tree_size.to_le_bytes());

        // Timestamp (58..66) - little endian
        blob[58..66].copy_from_slice(&self.timestamp.to_le_bytes());

        // Root hash (66..98)
        blob[66..98].copy_from_slice(&self.root_hash);

        blob
    }

    /// Parse checkpoint from 98-byte binary wire format
    ///
    /// ## Arguments
    ///
    /// - `bytes`: The 98-byte checkpoint blob (without signature)
    ///
    /// ## Errors
    ///
    /// Returns error if:
    /// - Blob size is not exactly 98 bytes
    /// - Magic bytes don't match "ATL-Protocol-v1-CP"
    ///
    /// ## Note
    ///
    /// This function creates a checkpoint with zeroed signature and `key_id`.
    /// You must call `set_signature()` and verify the checkpoint afterwards.
    pub fn from_bytes(bytes: &[u8]) -> AtlResult<Self> {
        // Validate size
        if bytes.len() != CHECKPOINT_BLOB_SIZE {
            return Err(AtlError::InvalidCheckpointFormat(format!(
                "expected {} bytes, got {}",
                CHECKPOINT_BLOB_SIZE,
                bytes.len()
            )));
        }

        // Validate magic bytes
        if &bytes[0..18] != CHECKPOINT_MAGIC {
            return Err(AtlError::InvalidCheckpointMagic);
        }

        // Parse origin (18..50)
        let origin: [u8; 32] = bytes[18..50]
            .try_into()
            .map_err(|_| AtlError::InvalidCheckpointFormat("invalid origin length".into()))?;

        // Parse tree size (50..58) - little endian
        let tree_size = u64::from_le_bytes(
            bytes[50..58]
                .try_into()
                .map_err(|_| AtlError::InvalidCheckpointFormat("invalid tree_size".into()))?,
        );

        // Parse timestamp (58..66) - little endian
        let timestamp = u64::from_le_bytes(
            bytes[58..66]
                .try_into()
                .map_err(|_| AtlError::InvalidCheckpointFormat("invalid timestamp".into()))?,
        );

        // Parse root hash (66..98)
        let root_hash: [u8; 32] = bytes[66..98]
            .try_into()
            .map_err(|_| AtlError::InvalidCheckpointFormat("invalid root_hash length".into()))?;

        // Signature and key_id must be provided separately
        Ok(Self {
            origin,
            tree_size,
            timestamp,
            root_hash,
            signature: [0u8; 64],
            key_id: [0u8; 32],
        })
    }

    /// Set the signature and `key_id` after parsing from bytes
    ///
    /// This is used when deserializing a checkpoint from network format.
    #[allow(clippy::missing_const_for_fn)]
    pub fn set_signature(&mut self, signature: [u8; 64], key_id: [u8; 32]) {
        self.signature = signature;
        self.key_id = key_id;
    }

    /// Convert checkpoint to JSON representation
    #[must_use]
    pub fn to_json(&self) -> CheckpointJson {
        CheckpointJson {
            origin: format_hash(&self.origin),
            tree_size: self.tree_size,
            root_hash: format_hash(&self.root_hash),
            timestamp: self.timestamp,
            signature: format_signature(&self.signature),
            key_id: format_hash(&self.key_id),
        }
    }

    /// Parse checkpoint from JSON representation
    ///
    /// ## Errors
    ///
    /// Returns error if any field has invalid format or length.
    pub fn from_json(json: &CheckpointJson) -> AtlResult<Self> {
        Ok(Self {
            origin: parse_hash(&json.origin)?,
            tree_size: json.tree_size,
            timestamp: json.timestamp,
            root_hash: parse_hash(&json.root_hash)?,
            signature: parse_signature(&json.signature)?,
            key_id: parse_hash(&json.key_id)?,
        })
    }

    /// Verify the checkpoint signature
    ///
    /// This reconstructs the 98-byte wire format and verifies the Ed25519 signature.
    ///
    /// ## Arguments
    ///
    /// - `verifier`: The trusted public key verifier
    ///
    /// ## Errors
    ///
    /// Returns error if:
    /// - Signature verification fails
    /// - Key ID doesn't match verifier's key ID
    pub fn verify(&self, verifier: &CheckpointVerifier) -> AtlResult<()> {
        // Verify key_id matches
        if self.key_id != verifier.key_id {
            return Err(AtlError::InvalidSignature(format!(
                "key_id mismatch: checkpoint has {}, verifier has {}",
                hex::encode(self.key_id),
                hex::encode(verifier.key_id)
            )));
        }

        // Reconstruct the signed blob
        let blob = self.to_bytes();

        // Verify signature
        verifier.verify(&blob, &self.signature)
    }

    /// Get origin as hex string with "sha256:" prefix
    #[must_use]
    pub fn origin_hex(&self) -> String {
        format_hash(&self.origin)
    }

    /// Get root hash as hex string with "sha256:" prefix
    #[must_use]
    pub fn root_hash_hex(&self) -> String {
        format_hash(&self.root_hash)
    }

    /// Get key ID as hex string with "sha256:" prefix
    #[must_use]
    pub fn key_id_hex(&self) -> String {
        format_hash(&self.key_id)
    }
}

// ========== CheckpointVerifier Implementation ==========

impl CheckpointVerifier {
    /// Create a verifier from an Ed25519 public key
    ///
    /// The `key_id` is automatically computed as SHA256 of the public key.
    ///
    /// ## Note
    ///
    /// This verifier is optional for receipt verification. ATL Protocol v2.0
    /// allows verification using only external anchors, without any public key.
    #[must_use]
    pub fn new(verifying_key: VerifyingKey) -> Self {
        let public_key_bytes = verifying_key.to_bytes();
        let key_id = compute_key_id(&public_key_bytes);
        Self { verifying_key, key_id }
    }

    /// Create a verifier from raw Ed25519 public key bytes (32 bytes)
    ///
    /// ## Errors
    ///
    /// Returns error if the key bytes are invalid.
    pub fn from_bytes(key_bytes: &[u8; 32]) -> AtlResult<Self> {
        let verifying_key = VerifyingKey::from_bytes(key_bytes)
            .map_err(|e| AtlError::InvalidPublicKey(e.to_string()))?;
        Ok(Self::new(verifying_key))
    }

    /// Get the key ID (SHA256 of the public key)
    ///
    /// ## Example
    ///
    /// ```
    /// use atl_core::core::checkpoint::{CheckpointVerifier, compute_key_id};
    /// use ed25519_dalek::SigningKey;
    ///
    /// let signing_key = SigningKey::from_bytes(&[42u8; 32]);
    /// let verifier = CheckpointVerifier::new(signing_key.verifying_key());
    /// let key_id = verifier.key_id();
    /// assert_eq!(key_id.len(), 32);
    /// ```
    #[must_use]
    pub const fn key_id(&self) -> [u8; 32] {
        self.key_id
    }

    /// Verify an Ed25519 signature against a checkpoint blob
    ///
    /// ## Arguments
    ///
    /// - `blob`: The 98-byte checkpoint wire format
    /// - `signature`: The 64-byte Ed25519 signature
    ///
    /// ## Errors
    ///
    /// Returns error if signature verification fails.
    pub fn verify(&self, blob: &[u8; CHECKPOINT_BLOB_SIZE], signature: &[u8; 64]) -> AtlResult<()> {
        let sig = Signature::from_bytes(signature);
        self.verifying_key.verify(blob, &sig).map_err(|_| AtlError::SignatureInvalid)
    }
}

// ========== Helper Functions ==========

/// Compute origin ID from Instance UUID
///
/// The origin ID is defined as `SHA256(uuid_bytes)` where `uuid_bytes`
/// is the 16-byte binary representation of the UUID.
///
/// ## Example
///
/// ```
/// use atl_core::core::checkpoint::compute_origin_id;
/// use uuid::Uuid;
///
/// let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
/// let origin = compute_origin_id(&uuid);
/// assert_eq!(origin.len(), 32);
/// ```
#[must_use]
pub fn compute_origin_id(instance_uuid: &uuid::Uuid) -> [u8; 32] {
    let uuid_bytes = instance_uuid.as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(uuid_bytes);
    hasher.finalize().into()
}

/// Compute key ID from Ed25519 public key
///
/// The key ID is defined as `SHA256(public_key_bytes)`.
///
/// ## Example
///
/// ```
/// use atl_core::core::checkpoint::compute_key_id;
///
/// let public_key = [0x42u8; 32];
/// let key_id = compute_key_id(&public_key);
/// assert_eq!(key_id.len(), 32);
/// ```
#[must_use]
pub fn compute_key_id(public_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    hasher.finalize().into()
}

/// Get current timestamp in nanoseconds since Unix epoch
///
/// ## Panics
///
/// Panics if system time is before Unix epoch (should never happen).
///
/// ## Note
///
/// The timestamp is clamped to `u64::MAX` nanoseconds (approximately year 2554).
/// This should be sufficient for all practical use cases.
#[must_use]
pub fn current_timestamp_nanos() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time before Unix epoch")
        .as_nanos();

    // Clamp to u64::MAX (approximately year 2554)
    // This should never happen in practice
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

// ========== String Format Helpers ==========

/// Format a 32-byte hash as "sha256:<64hex>"
///
/// ## Example
///
/// ```
/// use atl_core::core::checkpoint::format_hash;
///
/// let hash = [0xab; 32];
/// let formatted = format_hash(&hash);
/// assert!(formatted.starts_with("sha256:"));
/// assert_eq!(formatted.len(), 7 + 64); // "sha256:" + 64 hex chars
/// ```
#[must_use]
pub fn format_hash(hash: &[u8; 32]) -> String {
    format!("sha256:{}", hex::encode(hash))
}

/// Parse a "sha256:<64hex>" string to 32-byte array
///
/// ## Errors
///
/// Returns error if:
/// - Missing "sha256:" prefix
/// - Invalid hex encoding
/// - Wrong length (not 32 bytes)
pub fn parse_hash(s: &str) -> AtlResult<[u8; 32]> {
    let hex_str = s
        .strip_prefix("sha256:")
        .ok_or_else(|| AtlError::InvalidHash("missing sha256: prefix".into()))?;

    let bytes = hex::decode(hex_str).map_err(|e| AtlError::HexDecode(e.to_string()))?;

    bytes
        .try_into()
        .map_err(|_| AtlError::InvalidHash("invalid hash length, expected 32 bytes".into()))
}

/// Format a 64-byte Ed25519 signature as "base64:\<signature\>"
///
/// ## Example
///
/// ```
/// use atl_core::core::checkpoint::format_signature;
///
/// let sig = [0xcd; 64];
/// let formatted = format_signature(&sig);
/// assert!(formatted.starts_with("base64:"));
/// ```
#[must_use]
pub fn format_signature(sig: &[u8; 64]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    format!("base64:{}", STANDARD.encode(sig))
}

/// Parse a "base64:\<signature\>" string to 64-byte array
///
/// ## Errors
///
/// Returns error if:
/// - Missing "base64:" prefix
/// - Invalid base64 encoding
/// - Wrong length (not 64 bytes)
pub fn parse_signature(s: &str) -> AtlResult<[u8; 64]> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let b64_str = s
        .strip_prefix("base64:")
        .ok_or_else(|| AtlError::InvalidSignature("missing base64: prefix".into()))?;

    let bytes = STANDARD.decode(b64_str).map_err(|e| AtlError::Base64Decode(e.to_string()))?;

    bytes.try_into().map_err(|_| {
        AtlError::InvalidSignature("invalid signature length, expected 64 bytes".into())
    })
}

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn test_checkpoint_blob_size() {
        let checkpoint =
            Checkpoint::new([0u8; 32], 100, 1_234_567_890, [1u8; 32], [2u8; 64], [3u8; 32]);
        let blob = checkpoint.to_bytes();
        assert_eq!(blob.len(), CHECKPOINT_BLOB_SIZE);
        assert_eq!(blob.len(), 98);
    }

    #[test]
    fn test_magic_bytes() {
        let checkpoint = Checkpoint::new([0; 32], 0, 0, [0; 32], [0; 64], [0; 32]);
        let blob = checkpoint.to_bytes();
        assert_eq!(&blob[0..18], b"ATL-Protocol-v1-CP");
        assert_eq!(&blob[0..18], CHECKPOINT_MAGIC);
    }

    #[test]
    fn test_endianness() {
        let checkpoint = Checkpoint::new(
            [0; 32],
            0x0102_0304_0506_0708,
            0x0A0B_0C0D_0E0F_1011,
            [0; 32],
            [0; 64],
            [0; 32],
        );
        let blob = checkpoint.to_bytes();

        // Tree size is little-endian: least significant byte first
        assert_eq!(&blob[50..58], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);

        // Timestamp is little-endian
        assert_eq!(&blob[58..66], &[0x11, 0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A]);
    }

    #[test]
    fn test_wire_format_layout() {
        let origin = [0xAAu8; 32];
        let root_hash = [0xBBu8; 32];
        let checkpoint = Checkpoint::new(origin, 12345, 9_876_543_210, root_hash, [0; 64], [0; 32]);
        let blob = checkpoint.to_bytes();

        // Verify magic
        assert_eq!(&blob[0..18], CHECKPOINT_MAGIC);

        // Verify origin
        assert_eq!(&blob[18..50], &origin);

        // Verify tree_size
        assert_eq!(u64::from_le_bytes(blob[50..58].try_into().unwrap()), 12345);

        // Verify timestamp
        assert_eq!(u64::from_le_bytes(blob[58..66].try_into().unwrap()), 9_876_543_210);

        // Verify root_hash
        assert_eq!(&blob[66..98], &root_hash);
    }

    #[test]
    fn test_from_bytes_valid() {
        let origin = [0x11u8; 32];
        let root_hash = [0x22u8; 32];
        let checkpoint = Checkpoint::new(origin, 999, 123_456_789, root_hash, [0; 64], [0; 32]);
        let blob = checkpoint.to_bytes();

        let parsed = Checkpoint::from_bytes(&blob).unwrap();

        assert_eq!(parsed.origin, origin);
        assert_eq!(parsed.tree_size, 999);
        assert_eq!(parsed.timestamp, 123_456_789);
        assert_eq!(parsed.root_hash, root_hash);
        // Signature and key_id are zeroed after from_bytes
        assert_eq!(parsed.signature, [0u8; 64]);
        assert_eq!(parsed.key_id, [0u8; 32]);
    }

    #[test]
    fn test_from_bytes_invalid_size() {
        let too_short = vec![0u8; 50];
        let result = Checkpoint::from_bytes(&too_short);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidCheckpointFormat(_)));
    }

    #[test]
    fn test_from_bytes_invalid_magic() {
        let mut blob = [0u8; 98];
        blob[0..18].copy_from_slice(b"INVALID-MAGIC-XXXX");
        let result = Checkpoint::from_bytes(&blob);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidCheckpointMagic));
    }

    #[test]
    fn test_roundtrip_bytes() {
        let original = Checkpoint::new(
            [0x42; 32],
            987_654_321,
            1_234_567_890_123_456_789,
            [0x99; 32],
            [0xAA; 64],
            [0xBB; 32],
        );

        let blob = original.to_bytes();
        let mut parsed = Checkpoint::from_bytes(&blob).unwrap();
        parsed.set_signature(original.signature, original.key_id);

        assert_eq!(parsed, original);
    }

    #[test]
    fn test_compute_origin_id() {
        let uuid = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let origin = compute_origin_id(&uuid);

        // Verify it's SHA256 (32 bytes)
        assert_eq!(origin.len(), 32);

        // Verify deterministic
        let origin2 = compute_origin_id(&uuid);
        assert_eq!(origin, origin2);

        // Verify different UUID produces different origin
        let uuid2 = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap();
        let origin3 = compute_origin_id(&uuid2);
        assert_ne!(origin, origin3);
    }

    #[test]
    fn test_compute_key_id() {
        let public_key = [0x42u8; 32];
        let key_id = compute_key_id(&public_key);

        // Verify it's SHA256 (32 bytes)
        assert_eq!(key_id.len(), 32);

        // Verify deterministic
        let key_id2 = compute_key_id(&public_key);
        assert_eq!(key_id, key_id2);

        // Verify different key produces different key_id
        let public_key2 = [0x43u8; 32];
        let key_id3 = compute_key_id(&public_key2);
        assert_ne!(key_id, key_id3);
    }

    #[test]
    fn test_sign_and_verify() {
        // Generate a signing key
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let verifier = CheckpointVerifier::new(verifying_key);

        // Create checkpoint
        let mut checkpoint = Checkpoint::new(
            [0u8; 32],
            100,
            current_timestamp_nanos(),
            [1u8; 32],
            [0u8; 64],
            verifier.key_id,
        );

        // Sign the blob
        let blob = checkpoint.to_bytes();
        let signature = signing_key.sign(&blob);
        checkpoint.signature = signature.to_bytes();

        // Verify
        let result = checkpoint.verify(&verifier);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        // Generate two different keys
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let wrong_key = SigningKey::from_bytes(&[99u8; 32]);

        let verifying_key = signing_key.verifying_key();
        let verifier = CheckpointVerifier::new(verifying_key);

        let wrong_verifier = CheckpointVerifier::new(wrong_key.verifying_key());

        // Create and sign checkpoint with first key
        let mut checkpoint = Checkpoint::new(
            [0; 32],
            100,
            current_timestamp_nanos(),
            [1; 32],
            [0; 64],
            verifier.key_id,
        );

        let blob = checkpoint.to_bytes();
        let signature = signing_key.sign(&blob);
        checkpoint.signature = signature.to_bytes();

        // Verification with wrong key should fail
        let result = checkpoint.verify(&wrong_verifier);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_tampered_data_fails() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let verifier = CheckpointVerifier::new(verifying_key);

        // Create and sign checkpoint
        let mut checkpoint = Checkpoint::new(
            [0; 32],
            100,
            current_timestamp_nanos(),
            [1; 32],
            [0; 64],
            verifier.key_id,
        );

        let blob = checkpoint.to_bytes();
        let signature = signing_key.sign(&blob);
        checkpoint.signature = signature.to_bytes();

        // Tamper with tree_size
        checkpoint.tree_size = 999;

        // Verification should fail
        let result = checkpoint.verify(&verifier);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::SignatureInvalid));
    }

    #[test]
    fn test_verify_tampered_signature_fails() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let verifier = CheckpointVerifier::new(verifying_key);

        // Create and sign checkpoint
        let mut checkpoint = Checkpoint::new(
            [0; 32],
            100,
            current_timestamp_nanos(),
            [1; 32],
            [0; 64],
            verifier.key_id,
        );

        let blob = checkpoint.to_bytes();
        let signature = signing_key.sign(&blob);
        checkpoint.signature = signature.to_bytes();

        // Tamper with signature
        checkpoint.signature[0] ^= 0xFF;

        // Verification should fail
        let result = checkpoint.verify(&verifier);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::SignatureInvalid));
    }

    #[test]
    fn test_format_parse_hash() {
        let hash = [0xABu8; 32];
        let formatted = format_hash(&hash);

        assert!(formatted.starts_with("sha256:"));
        assert_eq!(formatted.len(), 7 + 64); // "sha256:" + 64 hex chars

        let parsed = parse_hash(&formatted).unwrap();
        assert_eq!(parsed, hash);
    }

    #[test]
    fn test_parse_hash_no_prefix() {
        let result = parse_hash("abcdef1234567890");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidHash(_)));
    }

    #[test]
    fn test_parse_hash_invalid_hex() {
        let result = parse_hash("sha256:not_hex!!!");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::HexDecode(_)));
    }

    #[test]
    fn test_parse_hash_wrong_length() {
        let result = parse_hash("sha256:abcd"); // too short
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidHash(_)));
    }

    #[test]
    fn test_format_parse_signature() {
        let sig = [0xCDu8; 64];
        let formatted = format_signature(&sig);

        assert!(formatted.starts_with("base64:"));

        let parsed = parse_signature(&formatted).unwrap();
        assert_eq!(parsed, sig);
    }

    #[test]
    fn test_parse_signature_no_prefix() {
        let result = parse_signature("MEUCIQD...");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::InvalidSignature(_)));
    }

    #[test]
    fn test_parse_signature_invalid_base64() {
        let result = parse_signature("base64:not valid base64!!!");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AtlError::Base64Decode(_)));
    }

    #[test]
    fn test_json_roundtrip() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let verifier = CheckpointVerifier::new(verifying_key);

        // Create and sign checkpoint
        let mut original =
            Checkpoint::new([0x42; 32], 12345, 9_876_543_210, [0x99; 32], [0; 64], verifier.key_id);

        let blob = original.to_bytes();
        let signature = signing_key.sign(&blob);
        original.signature = signature.to_bytes();

        // Convert to JSON and back
        let json = original.to_json();
        let restored = Checkpoint::from_json(&json).unwrap();

        assert_eq!(original, restored);
    }

    #[test]
    fn test_json_format() {
        let checkpoint =
            Checkpoint::new([0xAA; 32], 1000, 1_234_567_890, [0xBB; 32], [0xCC; 64], [0xDD; 32]);

        let json = checkpoint.to_json();

        assert!(json.origin.starts_with("sha256:"));
        assert_eq!(json.tree_size, 1000);
        assert!(json.root_hash.starts_with("sha256:"));
        assert_eq!(json.timestamp, 1_234_567_890);
        assert!(json.signature.starts_with("base64:"));
        assert!(json.key_id.starts_with("sha256:"));
    }

    #[test]
    fn test_checkpoint_verifier_from_bytes() {
        // Generate a valid Ed25519 public key
        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let key_bytes = verifying_key.to_bytes();

        let verifier = CheckpointVerifier::from_bytes(&key_bytes).unwrap();

        // Verify key_id is SHA256 of the key
        let expected_key_id = compute_key_id(&key_bytes);
        assert_eq!(verifier.key_id(), expected_key_id);
    }

    #[test]
    fn test_checkpoint_hex_methods() {
        let checkpoint =
            Checkpoint::new([0x12; 32], 100, 123_456, [0x34; 32], [0x56; 64], [0x78; 32]);

        let origin_hex = checkpoint.origin_hex();
        let root_hash_hex = checkpoint.root_hash_hex();
        let key_id_hex = checkpoint.key_id_hex();

        assert!(origin_hex.starts_with("sha256:"));
        assert!(root_hash_hex.starts_with("sha256:"));
        assert!(key_id_hex.starts_with("sha256:"));

        assert_eq!(origin_hex.len(), 7 + 64);
        assert_eq!(root_hash_hex.len(), 7 + 64);
        assert_eq!(key_id_hex.len(), 7 + 64);
    }

    #[test]
    fn test_current_timestamp_nanos() {
        let ts1 = current_timestamp_nanos();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let ts2 = current_timestamp_nanos();

        // Verify timestamp increases
        assert!(ts2 > ts1);

        // Verify timestamp is reasonable (after 2020, before 2100)
        let year_2020_nanos = 1_577_836_800_000_000_000u64;
        let year_2100_nanos = 4_102_444_800_000_000_000u64;
        assert!(ts1 > year_2020_nanos);
        assert!(ts1 < year_2100_nanos);
    }

    #[test]
    fn test_checkpoint_size_constants() {
        assert_eq!(CHECKPOINT_MAGIC.len(), 18);
        assert_eq!(CHECKPOINT_BLOB_SIZE, 98);

        // Verify wire format layout matches documentation
        // Magic: 18, Origin: 32, TreeSize: 8, Timestamp: 8, RootHash: 32
        assert_eq!(18 + 32 + 8 + 8 + 32, CHECKPOINT_BLOB_SIZE);
    }

    #[test]
    fn test_empty_tree_checkpoint() {
        // An empty tree (tree_size=0) should still be valid
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let verifier = CheckpointVerifier::new(verifying_key);

        let mut checkpoint = Checkpoint::new(
            [0; 32],
            0, // empty tree
            current_timestamp_nanos(),
            [0; 32], // empty tree root
            [0; 64],
            verifier.key_id,
        );

        let blob = checkpoint.to_bytes();
        let signature = signing_key.sign(&blob);
        checkpoint.signature = signature.to_bytes();

        assert!(checkpoint.verify(&verifier).is_ok());
    }

    #[test]
    fn test_checkpoint_equality() {
        let cp1 = Checkpoint::new([1; 32], 100, 123_456, [2; 32], [3; 64], [4; 32]);
        let cp2 = Checkpoint::new([1; 32], 100, 123_456, [2; 32], [3; 64], [4; 32]);
        let cp3 = Checkpoint::new([1; 32], 101, 123_456, [2; 32], [3; 64], [4; 32]);

        assert_eq!(cp1, cp2);
        assert_ne!(cp1, cp3);
    }

    #[test]
    fn test_checkpoint_clone() {
        let original = Checkpoint::new([1; 32], 100, 123_456, [2; 32], [3; 64], [4; 32]);
        let cloned = original.clone();

        assert_eq!(original, cloned);
    }

    #[test]
    fn test_verifier_clone() {
        // Generate a valid Ed25519 public key
        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let key_bytes = verifying_key.to_bytes();

        let verifier = CheckpointVerifier::from_bytes(&key_bytes).unwrap();
        let cloned = verifier.clone();

        assert_eq!(verifier.key_id(), cloned.key_id());
    }
}
