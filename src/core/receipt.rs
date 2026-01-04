//! Evidence Receipt v1.0.0 structures and parsing
//!
//! This module defines the Receipt data structures for ATL Protocol v1.0.0.
//! It provides ONLY:
//!
//! 1. **Data structures** for receipts
//! 2. **JSON serialization/deserialization**
//! 3. **Helper methods** for accessing receipt data
//!
//! ## What is NOT in this module
//!
//! - Receipt generation (see atl-server RECEIPT-GEN-1.md)
//! - Receipt verification (see VERIFY-1.md)
//! - Storage access (atl-server only)
//!
//! ## File Extension
//!
//! All receipts use the `.atl` extension (e.g., `contract.pdf.atl`).
//!
//! ## Example
//!
//! ```
//! use atl_core::core::receipt::Receipt;
//!
//! let json = r#"{
//!   "spec_version": "1.0.0",
//!   "entry": {
//!     "id": "550e8400-e29b-41d4-a716-446655440000",
//!     "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
//!     "metadata": {}
//!   },
//!   "proof": {
//!     "tree_size": 1,
//!     "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
//!     "inclusion_path": [],
//!     "leaf_index": 0,
//!     "checkpoint": {
//!       "origin": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
//!       "tree_size": 1,
//!       "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
//!       "timestamp": 1704067200000000000,
//!       "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
//!       "key_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
//!     }
//!   }
//! }"#;
//!
//! let receipt = Receipt::from_json(json).unwrap();
//! assert_eq!(receipt.spec_version(), "1.0.0");
//! ```

use crate::core::checkpoint::CheckpointJson;
use crate::core::merkle::Hash;
use crate::error::{AtlError, AtlResult};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ========== Constants ==========

/// Current receipt specification version
pub const RECEIPT_SPEC_VERSION: &str = "1.0.0";

// ========== Core Structures ==========

/// Evidence Receipt - self-contained proof of entry existence
///
/// A receipt contains all information needed to verify that an entry
/// exists in the transparency log. Verification requires only the
/// receipt and a trusted public key.
///
/// ## Invariants
///
/// - `spec_version` must be "1.0.0"
/// - `entry.id` is a valid UUID v4
/// - `entry.payload_hash` is in "sha256:..." format
/// - `proof.inclusion_path` contains "sha256:..." hashes
/// - `proof.checkpoint.signature` is in "base64:..." format
/// - `anchors` is optional and can be empty
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Specification version (always "1.0.0" for this implementation)
    pub spec_version: String,

    /// Entry information
    pub entry: ReceiptEntry,

    /// Cryptographic proof
    pub proof: ReceiptProof,

    /// External timestamp anchors (optional)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub anchors: Vec<ReceiptAnchor>,
}

/// Entry section of the receipt
///
/// Contains the entry ID, payload hash, and cleartext metadata.
/// The metadata is used for hash reconstruction during verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptEntry {
    /// Entry UUID (v4)
    pub id: Uuid,

    /// Payload hash ("sha256:...")
    pub payload_hash: String,

    /// Cleartext metadata (used for hash reconstruction during verification)
    pub metadata: serde_json::Value,
}

/// Proof section of the receipt
///
/// Contains the inclusion proof, root hash, and signed checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptProof {
    /// Tree size at time of proof
    pub tree_size: u64,

    /// Root hash ("sha256:...")
    pub root_hash: String,

    /// Inclusion path (list of "sha256:...")
    pub inclusion_path: Vec<String>,

    /// Leaf index (0-based)
    pub leaf_index: u64,

    /// Signed checkpoint
    pub checkpoint: CheckpointJson,

    /// Optional consistency proof from previous checkpoint
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub consistency_proof: Option<ReceiptConsistencyProof>,
}

/// Consistency proof within receipt
///
/// Proves that the tree at `from_tree_size` is a prefix of the current tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptConsistencyProof {
    /// Size of the older tree
    pub from_tree_size: u64,

    /// Proof path (list of "sha256:...")
    pub path: Vec<String>,
}

/// Anchor attestation in receipt
///
/// External timestamp anchors provide additional tamper-evidence.
/// These are optional and can be added after receipt generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ReceiptAnchor {
    /// RFC 3161 Time-Stamp Token
    #[serde(rename = "rfc3161")]
    Rfc3161 {
        /// ISO 8601 timestamp from TSA
        timestamp: String,

        /// DER-encoded `TimeStampResp` ("base64:...")
        token_der: String,
    },

    /// `OpenTimestamps` / Bitcoin anchor
    #[serde(rename = "bitcoin_ots")]
    BitcoinOts {
        /// ISO 8601 timestamp
        timestamp: String,

        /// Raw OTS proof file ("base64:...")
        ots_proof: String,

        /// Bitcoin block height
        bitcoin_block_height: u64,
    },
}

// ========== Receipt Implementation ==========

impl Receipt {
    /// Deserialize receipt from JSON string
    ///
    /// # Arguments
    ///
    /// * `json` - JSON string containing receipt
    ///
    /// # Returns
    ///
    /// * `Receipt` on success
    ///
    /// # Errors
    ///
    /// * `AtlError::InvalidReceipt` if JSON is malformed
    /// * `AtlError::UnsupportedReceiptVersion` if `spec_version` is not "1.0.0"
    ///
    /// # Example
    ///
    /// ```
    /// use atl_core::core::receipt::Receipt;
    ///
    /// let json = r#"{
    ///   "spec_version": "1.0.0",
    ///   "entry": {
    ///     "id": "550e8400-e29b-41d4-a716-446655440000",
    ///     "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ///     "metadata": {}
    ///   },
    ///   "proof": {
    ///     "tree_size": 1,
    ///     "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ///     "inclusion_path": [],
    ///     "leaf_index": 0,
    ///     "checkpoint": {
    ///       "origin": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    ///       "tree_size": 1,
    ///       "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ///       "timestamp": 1704067200000000000,
    ///       "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ///       "key_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    ///     }
    ///   }
    /// }"#;
    ///
    /// let receipt = Receipt::from_json(json).unwrap();
    /// assert_eq!(receipt.spec_version(), "1.0.0");
    /// ```
    pub fn from_json(json: &str) -> AtlResult<Self> {
        let receipt: Self =
            serde_json::from_str(json).map_err(|e| AtlError::InvalidReceipt(e.to_string()))?;

        // Validate spec version
        if receipt.spec_version != RECEIPT_SPEC_VERSION {
            return Err(AtlError::UnsupportedReceiptVersion(receipt.spec_version));
        }

        Ok(receipt)
    }

    /// Serialize receipt to JSON string (compact format)
    ///
    /// # Errors
    ///
    /// * `AtlError::InvalidReceipt` if serialization fails
    pub fn to_json(&self) -> AtlResult<String> {
        serde_json::to_string(self).map_err(|e| AtlError::InvalidReceipt(e.to_string()))
    }

    /// Serialize receipt to pretty-printed JSON
    ///
    /// # Errors
    ///
    /// * `AtlError::InvalidReceipt` if serialization fails
    pub fn to_json_pretty(&self) -> AtlResult<String> {
        serde_json::to_string_pretty(self).map_err(|e| AtlError::InvalidReceipt(e.to_string()))
    }

    /// Get the specification version
    #[must_use]
    pub fn spec_version(&self) -> &str {
        &self.spec_version
    }

    /// Get the entry ID
    #[must_use]
    pub const fn entry_id(&self) -> Uuid {
        self.entry.id
    }

    /// Get the payload hash as bytes
    ///
    /// Parses the "sha256:..." format and returns 32-byte hash.
    ///
    /// # Errors
    ///
    /// * `AtlError::InvalidHash` if hash format is invalid
    pub fn payload_hash_bytes(&self) -> AtlResult<Hash> {
        parse_hash_string(&self.entry.payload_hash)
    }

    /// Get the root hash as bytes
    ///
    /// # Errors
    ///
    /// * `AtlError::InvalidHash` if hash format is invalid
    pub fn root_hash_bytes(&self) -> AtlResult<Hash> {
        parse_hash_string(&self.proof.root_hash)
    }

    /// Get the inclusion path as bytes
    ///
    /// # Errors
    ///
    /// * `AtlError::InvalidHash` if any hash format is invalid
    pub fn inclusion_path_bytes(&self) -> AtlResult<Vec<Hash>> {
        self.proof.inclusion_path.iter().map(|h| parse_hash_string(h)).collect()
    }

    /// Check if receipt has anchors
    #[must_use]
    pub fn has_anchors(&self) -> bool {
        !self.anchors.is_empty()
    }

    /// Check if receipt has consistency proof
    #[must_use]
    pub const fn has_consistency_proof(&self) -> bool {
        self.proof.consistency_proof.is_some()
    }

    /// Get tree size from proof
    #[must_use]
    pub const fn tree_size(&self) -> u64 {
        self.proof.tree_size
    }

    /// Get leaf index
    #[must_use]
    pub const fn leaf_index(&self) -> u64 {
        self.proof.leaf_index
    }
}

// ========== Helper Functions ==========

/// Parse "sha256:..." format to 32-byte hash
///
/// # Arguments
///
/// * `s` - Hash string in "sha256:..." format
///
/// # Returns
///
/// * 32-byte hash array
///
/// # Errors
///
/// * `AtlError::InvalidHash` if missing prefix, invalid hex, or wrong length
fn parse_hash_string(s: &str) -> AtlResult<Hash> {
    let hex_str = s
        .strip_prefix("sha256:")
        .ok_or_else(|| AtlError::InvalidHash(format!("missing sha256: prefix in '{s}'")))?;

    let bytes = hex::decode(hex_str).map_err(|e| AtlError::InvalidHash(e.to_string()))?;

    if bytes.len() != 32 {
        return Err(AtlError::InvalidHash(format!("expected 32 bytes, got {}", bytes.len())));
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

/// Parse "base64:..." format to 64-byte signature
///
/// # Arguments
///
/// * `s` - Signature string in "base64:..." format
///
/// # Returns
///
/// * 64-byte signature array
///
/// # Errors
///
/// * `AtlError::InvalidSignature` if missing prefix, invalid base64, or wrong length
///
/// # Example
///
/// ```
/// use atl_core::core::receipt::parse_base64_signature;
/// use base64::Engine;
///
/// let sig = [0xcd; 64];
/// let encoded = format!("base64:{}", base64::engine::general_purpose::STANDARD.encode(sig));
/// let parsed = parse_base64_signature(&encoded).unwrap();
/// assert_eq!(parsed, sig);
/// ```
pub fn parse_base64_signature(s: &str) -> AtlResult<[u8; 64]> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let b64_str = s
        .strip_prefix("base64:")
        .ok_or_else(|| AtlError::InvalidSignature(format!("missing base64: prefix in '{s}'")))?;

    let bytes = STANDARD.decode(b64_str).map_err(|e| AtlError::InvalidSignature(e.to_string()))?;

    if bytes.len() != 64 {
        return Err(AtlError::InvalidSignature(format!("expected 64 bytes, got {}", bytes.len())));
    }

    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes);
    Ok(sig)
}

/// Format 32-byte hash as "sha256:..." string
///
/// # Example
///
/// ```
/// use atl_core::core::receipt::format_hash;
///
/// let hash = [0xab; 32];
/// let formatted = format_hash(&hash);
/// assert!(formatted.starts_with("sha256:"));
/// assert_eq!(formatted.len(), 7 + 64); // "sha256:" + 64 hex chars
/// ```
#[must_use]
pub fn format_hash(hash: &Hash) -> String {
    format!("sha256:{}", hex::encode(hash))
}

/// Format 64-byte signature as "base64:..." string
///
/// # Example
///
/// ```
/// use atl_core::core::receipt::format_signature;
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

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receipt_from_json() {
        let json = r#"{
            "spec_version": "1.0.0",
            "entry": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "metadata": {"filename": "test.pdf"}
            },
            "proof": {
                "tree_size": 100,
                "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "inclusion_path": [],
                "leaf_index": 42,
                "checkpoint": {
                    "origin": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "tree_size": 100,
                    "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "timestamp": 1704067200000000000,
                    "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "key_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                }
            }
        }"#;

        let receipt = Receipt::from_json(json).unwrap();

        assert_eq!(receipt.spec_version, "1.0.0");
        assert_eq!(receipt.entry.id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(receipt.proof.tree_size, 100);
        assert_eq!(receipt.proof.leaf_index, 42);
        assert!(receipt.anchors.is_empty());
    }

    #[test]
    fn test_receipt_roundtrip() {
        let original_json = r#"{
            "spec_version": "1.0.0",
            "entry": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "metadata": {}
            },
            "proof": {
                "tree_size": 1,
                "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "inclusion_path": [],
                "leaf_index": 0,
                "checkpoint": {
                    "origin": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "tree_size": 1,
                    "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "timestamp": 1704067200000000000,
                    "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "key_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                }
            }
        }"#;

        let receipt = Receipt::from_json(original_json).unwrap();
        let serialized = receipt.to_json().unwrap();
        let restored = Receipt::from_json(&serialized).unwrap();

        assert_eq!(receipt.entry.id, restored.entry.id);
        assert_eq!(receipt.proof.tree_size, restored.proof.tree_size);
    }

    #[test]
    fn test_unsupported_version() {
        let json = r#"{
            "spec_version": "2.0.0",
            "entry": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "metadata": {}
            },
            "proof": {
                "tree_size": 1,
                "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "inclusion_path": [],
                "leaf_index": 0,
                "checkpoint": {
                    "origin": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "tree_size": 1,
                    "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "timestamp": 0,
                    "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "key_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                }
            }
        }"#;

        let result = Receipt::from_json(json);
        assert!(matches!(result, Err(AtlError::UnsupportedReceiptVersion(_))));
    }

    #[test]
    fn test_parse_hash_string() {
        let hash_str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let hash = parse_hash_string(hash_str).unwrap();
        assert_eq!(hash, [0xaa; 32]);
    }

    #[test]
    fn test_parse_hash_missing_prefix() {
        let result = parse_hash_string("aaaa...");
        assert!(matches!(result, Err(AtlError::InvalidHash(_))));
    }

    #[test]
    fn test_parse_hash_invalid_hex() {
        let result = parse_hash_string("sha256:not_hex");
        assert!(matches!(result, Err(AtlError::InvalidHash(_))));
    }

    #[test]
    fn test_parse_hash_wrong_length() {
        let result = parse_hash_string("sha256:aabbcc");
        assert!(matches!(result, Err(AtlError::InvalidHash(_))));
    }

    #[test]
    fn test_format_hash() {
        let hash = [0xbb; 32];
        let formatted = format_hash(&hash);
        assert!(formatted.starts_with("sha256:"));
        assert_eq!(formatted.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn test_format_signature() {
        let sig = [0xcc; 64];
        let formatted = format_signature(&sig);
        assert!(formatted.starts_with("base64:"));
    }

    #[test]
    fn test_parse_signature() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;

        let sig = [0xcd; 64];
        let formatted = format!("base64:{}", STANDARD.encode(sig));
        let parsed = parse_base64_signature(&formatted).unwrap();
        assert_eq!(parsed, sig);
    }

    #[test]
    fn test_parse_signature_missing_prefix() {
        let result = parse_base64_signature("MEUCIQD...");
        assert!(matches!(result, Err(AtlError::InvalidSignature(_))));
    }

    #[test]
    fn test_parse_signature_invalid_base64() {
        let result = parse_base64_signature("base64:not valid base64!!!");
        assert!(matches!(result, Err(AtlError::InvalidSignature(_))));
    }

    #[test]
    fn test_anchors_omitted_when_empty() {
        let receipt = Receipt {
            spec_version: RECEIPT_SPEC_VERSION.to_string(),
            entry: ReceiptEntry {
                id: Uuid::nil(),
                payload_hash: "sha256:".to_string() + &"aa".repeat(32),
                metadata: serde_json::json!({}),
            },
            proof: ReceiptProof {
                tree_size: 1,
                root_hash: "sha256:".to_string() + &"bb".repeat(32),
                inclusion_path: vec![],
                leaf_index: 0,
                checkpoint: CheckpointJson {
                    origin: "sha256:".to_string() + &"cc".repeat(32),
                    tree_size: 1,
                    root_hash: "sha256:".to_string() + &"bb".repeat(32),
                    timestamp: 0,
                    signature: "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    key_id: "sha256:".to_string() + &"dd".repeat(32),
                },
                consistency_proof: None,
            },
            anchors: vec![],
        };

        let json = receipt.to_json().unwrap();
        assert!(!json.contains("\"anchors\""));
    }

    #[test]
    fn test_consistency_proof_omitted_when_none() {
        let receipt = Receipt {
            spec_version: RECEIPT_SPEC_VERSION.to_string(),
            entry: ReceiptEntry {
                id: Uuid::nil(),
                payload_hash: "sha256:".to_string() + &"aa".repeat(32),
                metadata: serde_json::json!({}),
            },
            proof: ReceiptProof {
                tree_size: 1,
                root_hash: "sha256:".to_string() + &"bb".repeat(32),
                inclusion_path: vec![],
                leaf_index: 0,
                checkpoint: CheckpointJson {
                    origin: "sha256:".to_string() + &"cc".repeat(32),
                    tree_size: 1,
                    root_hash: "sha256:".to_string() + &"bb".repeat(32),
                    timestamp: 0,
                    signature: "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    key_id: "sha256:".to_string() + &"dd".repeat(32),
                },
                consistency_proof: None,
            },
            anchors: vec![],
        };

        let json = receipt.to_json().unwrap();
        assert!(!json.contains("\"consistency_proof\""));
    }

    #[test]
    fn test_receipt_with_anchors() {
        let json = r#"{
            "spec_version": "1.0.0",
            "entry": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "metadata": {}
            },
            "proof": {
                "tree_size": 1,
                "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "inclusion_path": [],
                "leaf_index": 0,
                "checkpoint": {
                    "origin": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "tree_size": 1,
                    "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "timestamp": 0,
                    "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "key_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                }
            },
            "anchors": [
                {
                    "type": "rfc3161",
                    "timestamp": "2024-01-01T00:00:00Z",
                    "token_der": "base64:AAAA"
                }
            ]
        }"#;

        let receipt = Receipt::from_json(json).unwrap();
        assert!(receipt.has_anchors());
        assert_eq!(receipt.anchors.len(), 1);
        assert!(matches!(receipt.anchors[0], ReceiptAnchor::Rfc3161 { .. }));
    }

    #[test]
    fn test_receipt_with_consistency_proof() {
        let json = r#"{
            "spec_version": "1.0.0",
            "entry": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "metadata": {}
            },
            "proof": {
                "tree_size": 10,
                "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "inclusion_path": [],
                "leaf_index": 0,
                "checkpoint": {
                    "origin": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "tree_size": 10,
                    "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "timestamp": 0,
                    "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "key_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                },
                "consistency_proof": {
                    "from_tree_size": 5,
                    "path": ["sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"]
                }
            }
        }"#;

        let receipt = Receipt::from_json(json).unwrap();
        assert!(receipt.has_consistency_proof());
        let cp = receipt.proof.consistency_proof.as_ref().unwrap();
        assert_eq!(cp.from_tree_size, 5);
        assert_eq!(cp.path.len(), 1);
    }

    #[test]
    fn test_receipt_helper_methods() {
        let json = r#"{
            "spec_version": "1.0.0",
            "entry": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "metadata": {}
            },
            "proof": {
                "tree_size": 100,
                "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "inclusion_path": [
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                ],
                "leaf_index": 42,
                "checkpoint": {
                    "origin": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "tree_size": 100,
                    "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "timestamp": 0,
                    "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "key_id": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                }
            }
        }"#;

        let receipt = Receipt::from_json(json).unwrap();

        assert_eq!(receipt.spec_version(), "1.0.0");
        assert_eq!(receipt.entry_id().to_string(), "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(receipt.tree_size(), 100);
        assert_eq!(receipt.leaf_index(), 42);

        let payload_hash = receipt.payload_hash_bytes().unwrap();
        assert_eq!(payload_hash, [0xaa; 32]);

        let root_hash = receipt.root_hash_bytes().unwrap();
        assert_eq!(root_hash, [0xbb; 32]);

        let path = receipt.inclusion_path_bytes().unwrap();
        assert_eq!(path.len(), 1);
        assert_eq!(path[0], [0xcc; 32]);
    }

    #[test]
    fn test_invalid_json() {
        let json = "not valid json";
        let result = Receipt::from_json(json);
        assert!(matches!(result, Err(AtlError::InvalidReceipt(_))));
    }

    #[test]
    fn test_missing_fields() {
        let json = r#"{"spec_version": "1.0.0"}"#;
        let result = Receipt::from_json(json);
        assert!(matches!(result, Err(AtlError::InvalidReceipt(_))));
    }

    #[test]
    fn test_receipt_to_json_pretty() {
        let receipt = Receipt {
            spec_version: RECEIPT_SPEC_VERSION.to_string(),
            entry: ReceiptEntry {
                id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
                payload_hash: "sha256:".to_string() + &"aa".repeat(32),
                metadata: serde_json::json!({}),
            },
            proof: ReceiptProof {
                tree_size: 1,
                root_hash: "sha256:".to_string() + &"bb".repeat(32),
                inclusion_path: vec![],
                leaf_index: 0,
                checkpoint: CheckpointJson {
                    origin: "sha256:".to_string() + &"cc".repeat(32),
                    tree_size: 1,
                    root_hash: "sha256:".to_string() + &"bb".repeat(32),
                    timestamp: 0,
                    signature: "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    key_id: "sha256:".to_string() + &"dd".repeat(32),
                },
                consistency_proof: None,
            },
            anchors: vec![],
        };

        let pretty = receipt.to_json_pretty().unwrap();
        assert!(pretty.contains('\n')); // Pretty print includes newlines
        assert!(pretty.contains("spec_version"));
    }
}
