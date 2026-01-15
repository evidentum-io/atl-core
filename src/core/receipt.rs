//! Evidence Receipt v2.0.0 structures and parsing
//!
//! This module defines the Receipt data structures for ATL Protocol v2.0.0.
//! It provides ONLY:
//!
//! 1. **Data structures** for receipts
//! 2. **JSON serialization/deserialization**
//! 3. **Helper methods** for accessing receipt data
//!
//! ## What is NOT in this module
//!
//! - Receipt generation (server-side only)
//! - Storage access (server-side only)
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
//!   "spec_version": "2.0.0",
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
//!   },
//!   "super_proof": {
//!     "genesis_super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
//!     "data_tree_index": 0,
//!     "super_tree_size": 1,
//!     "super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
//!     "inclusion": [],
//!     "consistency_to_origin": []
//!   }
//! }"#;
//!
//! let receipt = Receipt::from_json(json).unwrap();
//! assert_eq!(receipt.spec_version(), "2.0.0");
//! ```

use crate::core::checkpoint::CheckpointJson;
use crate::core::merkle::Hash;
use crate::error::{AtlError, AtlResult};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ========== Constants ==========

/// Current receipt specification version
///
/// Version 2.0.0 is the only supported version:
/// - Optional `super_proof` for global chain consistency
/// - Mandatory `target` and `target_hash` in anchors
pub const RECEIPT_SPEC_VERSION: &str = "2.0.0";

/// Anchor target: Data Tree Root (for RFC 3161)
pub const ANCHOR_TARGET_DATA_TREE_ROOT: &str = "data_tree_root";

/// Anchor target: Super Root (for Bitcoin OTS)
pub const ANCHOR_TARGET_SUPER_ROOT: &str = "super_root";

// ========== Core Structures ==========

/// Evidence Receipt - self-contained proof of entry existence
///
/// A receipt contains all information needed to verify that an entry
/// exists in the transparency log. Verification requires only the
/// receipt and a trusted public key.
///
/// ## Receipt Tiers
///
/// | Tier | Name | Contents |
/// |------|------|----------|
/// | 1 | Receipt-Lite | Entry + Inclusion Proof + Checkpoint + Super Proof |
/// | 2 | Receipt-TSA | + TSA Anchor (on Data Tree Root) |
/// | 3 | Receipt-Full | + OTS Anchor (on Super Root) |
///
/// ## Version
///
/// - v2.0.0: Current version with mandatory `super_proof`
///
/// ## Invariants
///
/// - `spec_version` MUST be "2.0.0"
/// - `entry.id` is a valid UUID v4
/// - `entry.payload_hash` is in "sha256:..." format
/// - `proof.inclusion_path` contains "sha256:..." hashes
/// - `proof.checkpoint.signature` is in "base64:..." format
/// - `super_proof` is optional (None for Receipt-Lite)
/// - `anchors` is optional and can be empty
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Specification version (MUST be "2.0.0")
    pub spec_version: String,

    /// URL to request an upgraded receipt (optional)
    ///
    /// Clients can use this URL to fetch a receipt with additional anchors.
    /// If omitted, receipt cannot be upgraded.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub upgrade_url: Option<String>,

    /// Entry information
    pub entry: ReceiptEntry,

    /// Cryptographic proof linking entry to Data Tree root
    pub proof: ReceiptProof,

    /// Super-Tree proof for global chain consistency (optional)
    ///
    /// Present only after the Data Tree has been closed and added to Super-Tree.
    /// Receipts without `super_proof` are Receipt-Lite (valid but not fully anchored).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub super_proof: Option<SuperProof>,

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
/// External timestamp anchors provide tamper-evidence through independent
/// third-party timestamp services. ATL Protocol v2.0 requires the `target`
/// field to explicitly specify what the anchor is timestamping.
///
/// ## Two-Tier Anchoring (v2.0)
///
/// - **RFC 3161 (TSA)**: Anchors the Data Tree Root for immediate timestamps
/// - **Bitcoin OTS**: Anchors the Super Root for eternal immutability + global consistency
///
/// ## Mandatory Fields
///
/// All fields are mandatory. Receipts without `target` and `target_hash` fields
/// will fail to deserialize.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum ReceiptAnchor {
    /// RFC 3161 Time-Stamp Token
    ///
    /// TSA anchors MUST target the Data Tree Root.
    #[serde(rename = "rfc3161")]
    Rfc3161 {
        /// What this anchor timestamps: MUST be `"data_tree_root"`
        target: String,

        /// Hash of the target being timestamped
        /// Format: `"sha256:<hex>"`
        /// MUST equal `proof.root_hash`
        target_hash: String,

        /// TSA URL that issued the timestamp
        tsa_url: String,

        /// ISO 8601 timestamp from TSA
        timestamp: String,

        /// DER-encoded `TimeStampResp` (`"base64:..."`)
        token_der: String,
    },

    /// `OpenTimestamps` / Bitcoin anchor
    ///
    /// OTS anchors MUST target the Super Root.
    #[serde(rename = "bitcoin_ots")]
    BitcoinOts {
        /// What this anchor timestamps: MUST be `"super_root"`
        target: String,

        /// Hash of the target being timestamped
        /// Format: `"sha256:<hex>"`
        /// MUST equal `super_proof.super_root`
        target_hash: String,

        /// ISO 8601 timestamp
        timestamp: String,

        /// Bitcoin block height
        bitcoin_block_height: u64,

        /// ISO 8601 timestamp of Bitcoin block
        bitcoin_block_time: String,

        /// Raw OTS proof file ("base64:...")
        ots_proof: String,
    },
}

/// Super-Tree proof for global chain consistency
///
/// Contains cryptographic data proving that a Data Tree root is included
/// in the Super-Tree and that the Super-Tree history is consistent with
/// its genesis state.
///
/// ## Fields
///
/// - `genesis_super_root`: Hash of Super-Tree at size 1 (first Data Tree root).
///   Used as the immutable identifier for the log instance.
/// - `data_tree_index`: Position of this Data Tree in the Super-Tree (0-indexed).
/// - `super_tree_size`: Size of the Super-Tree when this proof was generated.
/// - `super_root`: The Super-Tree root hash that was anchored.
/// - `inclusion`: Merkle inclusion proof from Data Tree root to Super Root.
/// - `consistency_to_origin`: RFC 9162 consistency proof from size 1 to current size.
///
/// ## Example JSON
///
/// ```json
/// {
///   "genesis_super_root": "sha256:aabb...",
///   "data_tree_index": 150,
///   "super_tree_size": 152,
///   "super_root": "sha256:ccdd...",
///   "inclusion": ["sha256:...", ...],
///   "consistency_to_origin": ["sha256:...", ...]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SuperProof {
    /// Hash of Super-Tree at size 1 (first Data Tree's root)
    /// Format: "sha256:<hex>"
    pub genesis_super_root: String,

    /// Position of this Data Tree in the Super-Tree (0-indexed)
    pub data_tree_index: u64,

    /// Size of the Super-Tree at the time of anchoring
    pub super_tree_size: u64,

    /// The Super-Tree root hash that was anchored
    /// Format: "sha256:<hex>"
    pub super_root: String,

    /// Merkle inclusion proof from Data Tree root to Super Root
    /// Format: list of "sha256:<hex>"
    pub inclusion: Vec<String>,

    /// RFC 9162 consistency proof from Super-Tree size 1 to current size
    /// Format: list of "sha256:<hex>"
    pub consistency_to_origin: Vec<String>,
}

/// Receipt tier classification
///
/// Indicates the level of trust and completeness of a receipt.
/// All tiers have `super_proof` (mandatory in v2.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptTier {
    /// Receipt-Lite: Entry + Inclusion Proof + Checkpoint + Super Proof
    Lite,
    /// Receipt-TSA: + RFC 3161 timestamp anchor
    Tsa,
    /// Receipt-Full: + Bitcoin OTS anchor
    Full,
}

impl ReceiptTier {
    /// Get human-readable name
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Lite => "Receipt-Lite",
            Self::Tsa => "Receipt-TSA",
            Self::Full => "Receipt-Full",
        }
    }
}

// ========== ReceiptAnchor Implementation ==========

impl ReceiptAnchor {
    /// Get the anchor type as string
    #[must_use]
    pub const fn anchor_type(&self) -> &'static str {
        match self {
            Self::Rfc3161 { .. } => "rfc3161",
            Self::BitcoinOts { .. } => "bitcoin_ots",
        }
    }

    /// Get the target type (mandatory field)
    #[must_use]
    pub fn target(&self) -> &str {
        match self {
            Self::Rfc3161 { target, .. } | Self::BitcoinOts { target, .. } => target,
        }
    }

    /// Get the target hash (mandatory field)
    #[must_use]
    pub fn target_hash(&self) -> &str {
        match self {
            Self::Rfc3161 { target_hash, .. } | Self::BitcoinOts { target_hash, .. } => target_hash,
        }
    }

    /// Check if this anchor targets the `super_root`
    #[must_use]
    pub fn targets_super_root(&self) -> bool {
        self.target() == ANCHOR_TARGET_SUPER_ROOT
    }

    /// Check if this anchor targets the `data_tree_root`
    #[must_use]
    pub fn targets_data_tree_root(&self) -> bool {
        self.target() == ANCHOR_TARGET_DATA_TREE_ROOT
    }

    /// Get the timestamp string
    #[must_use]
    pub fn timestamp(&self) -> &str {
        match self {
            Self::Rfc3161 { timestamp, .. } | Self::BitcoinOts { timestamp, .. } => timestamp,
        }
    }
}

// ========== Receipt Implementation ==========

impl Receipt {
    /// Deserialize receipt from JSON string
    ///
    /// Only v2.0.0 receipts are supported.
    ///
    /// # Errors
    ///
    /// * `AtlError::InvalidReceipt` if JSON is malformed or missing required fields
    /// * `AtlError::UnsupportedReceiptVersion` if version is not "2.0.0"
    pub fn from_json(json: &str) -> AtlResult<Self> {
        let receipt: Self =
            serde_json::from_str(json).map_err(|e| AtlError::InvalidReceipt(e.to_string()))?;

        // Only accept v2.0.0 receipts
        if receipt.spec_version != "2.0.0" {
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
    pub const fn has_anchors(&self) -> bool {
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

    /// Get the receipt tier
    ///
    /// Returns the tier based on available anchors and `super_proof`:
    /// - Lite: No `super_proof` OR no anchors
    /// - TSA: Has `super_proof` + RFC 3161 anchor but no Bitcoin OTS
    /// - Full: Has `super_proof` + RFC 3161 + Bitcoin OTS anchors
    #[must_use]
    pub fn tier(&self) -> ReceiptTier {
        // Without super_proof, always Lite (regardless of anchors)
        if self.super_proof.is_none() {
            return ReceiptTier::Lite;
        }

        let has_tsa = self.anchors.iter().any(|a| matches!(a, ReceiptAnchor::Rfc3161 { .. }));
        let has_ots = self.anchors.iter().any(|a| matches!(a, ReceiptAnchor::BitcoinOts { .. }));

        match (has_tsa, has_ots) {
            (true, true) => ReceiptTier::Full,
            (true, false) => ReceiptTier::Tsa,
            _ => ReceiptTier::Lite,
        }
    }

    /// Get `super_proof` as reference (optional)
    ///
    /// Returns `None` for Receipt-Lite (entry in active tree).
    /// Returns `Some(&SuperProof)` after tree closure.
    #[must_use]
    pub const fn super_proof(&self) -> Option<&SuperProof> {
        self.super_proof.as_ref()
    }

    /// Get `genesis_super_root` (optional)
    ///
    /// Returns `None` if no `super_proof` present.
    #[must_use]
    pub fn genesis_super_root(&self) -> Option<&str> {
        self.super_proof.as_ref().map(|sp| sp.genesis_super_root.as_str())
    }

    /// Get `super_root` (optional)
    #[must_use]
    pub fn super_root(&self) -> Option<&str> {
        self.super_proof.as_ref().map(|sp| sp.super_root.as_str())
    }

    /// Get `data_tree_index` (optional)
    #[must_use]
    pub fn data_tree_index(&self) -> Option<u64> {
        self.super_proof.as_ref().map(|sp| sp.data_tree_index)
    }

    /// Get `super_tree_size` (optional)
    #[must_use]
    pub fn super_tree_size(&self) -> Option<u64> {
        self.super_proof.as_ref().map(|sp| sp.super_tree_size)
    }

    /// Check if receipt has `super_proof`
    #[must_use]
    pub const fn has_super_proof(&self) -> bool {
        self.super_proof.is_some()
    }
}

// ========== SuperProof Implementation ==========

impl SuperProof {
    /// Parse `genesis_super_root` to bytes
    ///
    /// # Errors
    ///
    /// Returns `AtlError::InvalidHash` if format is invalid
    pub fn genesis_super_root_bytes(&self) -> AtlResult<Hash> {
        parse_hash_string(&self.genesis_super_root)
    }

    /// Parse `super_root` to bytes
    ///
    /// # Errors
    ///
    /// Returns `AtlError::InvalidHash` if format is invalid
    pub fn super_root_bytes(&self) -> AtlResult<Hash> {
        parse_hash_string(&self.super_root)
    }

    /// Parse inclusion path to bytes
    ///
    /// # Errors
    ///
    /// Returns `AtlError::InvalidHash` if any hash format is invalid
    pub fn inclusion_path_bytes(&self) -> AtlResult<Vec<Hash>> {
        self.inclusion.iter().map(|h| parse_hash_string(h)).collect()
    }

    /// Parse `consistency_to_origin` path to bytes
    ///
    /// # Errors
    ///
    /// Returns `AtlError::InvalidHash` if any hash format is invalid
    pub fn consistency_to_origin_bytes(&self) -> AtlResult<Vec<Hash>> {
        self.consistency_to_origin.iter().map(|h| parse_hash_string(h)).collect()
    }

    /// Check if this is a genesis proof (`data_tree_index` == 0)
    #[must_use]
    pub const fn is_genesis(&self) -> bool {
        self.data_tree_index == 0
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

    fn make_test_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn make_test_super_proof() -> SuperProof {
        SuperProof {
            genesis_super_root: make_test_hash(0xaa),
            data_tree_index: 5,
            super_tree_size: 10,
            super_root: make_test_hash(0xbb),
            inclusion: vec![make_test_hash(0xcc)],
            consistency_to_origin: vec![make_test_hash(0xdd)],
        }
    }

    #[test]
    fn test_receipt_from_json() {
        let json = r#"{
            "spec_version": "2.0.0",
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
            },
            "super_proof": {
                "genesis_super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "data_tree_index": 5,
                "super_tree_size": 10,
                "super_root": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "inclusion": ["sha256:1111111111111111111111111111111111111111111111111111111111111111"],
                "consistency_to_origin": ["sha256:2222222222222222222222222222222222222222222222222222222222222222"]
            }
        }"#;

        let receipt = Receipt::from_json(json).unwrap();

        assert_eq!(receipt.spec_version, "2.0.0");
        assert_eq!(receipt.entry.id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(receipt.proof.tree_size, 100);
        assert_eq!(receipt.proof.leaf_index, 42);
        assert!(receipt.anchors.is_empty());
        assert_eq!(receipt.data_tree_index(), Some(5));
        assert_eq!(receipt.super_tree_size(), Some(10));
    }

    #[test]
    fn test_receipt_roundtrip() {
        let original_json = r#"{
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
                    "timestamp": 1704067200000000000,
                    "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "key_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                }
            },
            "super_proof": {
                "genesis_super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "data_tree_index": 0,
                "super_tree_size": 1,
                "super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "inclusion": [],
                "consistency_to_origin": []
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
        // v1.0.0 is now unsupported (but receipt is valid to test version check)
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
            "super_proof": {
                "genesis_super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "data_tree_index": 0,
                "super_tree_size": 1,
                "super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "inclusion": [],
                "consistency_to_origin": []
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
            upgrade_url: None,
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
            super_proof: Some(make_test_super_proof()),
            anchors: vec![],
        };

        let json = receipt.to_json().unwrap();
        assert!(!json.contains("\"anchors\""));
    }

    #[test]
    fn test_consistency_proof_omitted_when_none() {
        let receipt = Receipt {
            spec_version: RECEIPT_SPEC_VERSION.to_string(),
            upgrade_url: None,
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
            super_proof: Some(make_test_super_proof()),
            anchors: vec![],
        };

        let json = receipt.to_json().unwrap();
        assert!(!json.contains("\"consistency_proof\""));
    }

    #[test]
    fn test_receipt_with_anchors() {
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
            },
            "super_proof": {
                "genesis_super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "data_tree_index": 0,
                "super_tree_size": 1,
                "super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "inclusion": [],
                "consistency_to_origin": []
            },
            "anchors": [
                {
                    "type": "rfc3161",
                    "target": "data_tree_root",
                    "target_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "tsa_url": "https://freetsa.org/tsr",
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
            "spec_version": "2.0.0",
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
            },
            "super_proof": {
                "genesis_super_root": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "data_tree_index": 0,
                "super_tree_size": 1,
                "super_root": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "inclusion": [],
                "consistency_to_origin": []
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
            "spec_version": "2.0.0",
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
            },
            "super_proof": {
                "genesis_super_root": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "data_tree_index": 0,
                "super_tree_size": 1,
                "super_root": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "inclusion": [],
                "consistency_to_origin": []
            }
        }"#;

        let receipt = Receipt::from_json(json).unwrap();

        assert_eq!(receipt.spec_version(), "2.0.0");
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
            upgrade_url: None,
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
            super_proof: Some(make_test_super_proof()),
            anchors: vec![],
        };

        let pretty = receipt.to_json_pretty().unwrap();
        assert!(pretty.contains('\n')); // Pretty print includes newlines
        assert!(pretty.contains("spec_version"));
    }
}

#[cfg(test)]
mod receipt_v2_tests {
    use super::*;

    fn make_test_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    fn make_test_super_proof() -> SuperProof {
        SuperProof {
            genesis_super_root: make_test_hash(0xaa),
            data_tree_index: 5,
            super_tree_size: 10,
            super_root: make_test_hash(0xbb),
            inclusion: vec![make_test_hash(0xcc)],
            consistency_to_origin: vec![make_test_hash(0xdd)],
        }
    }

    #[test]
    fn test_receipt_without_super_proof_parses() {
        // Receipt-Lite: missing super_proof field - SHOULD SUCCEED
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
                    "timestamp": 1704067200000000000,
                    "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "key_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                }
            }
        }"#;

        let receipt = Receipt::from_json(json).expect("Receipt-Lite should parse");
        assert!(receipt.super_proof.is_none());
        assert!(!receipt.has_super_proof());
        assert_eq!(receipt.tier(), ReceiptTier::Lite);
    }

    #[test]
    fn test_receipt_with_null_super_proof() {
        // Receipt with explicit null super_proof
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
                    "timestamp": 1704067200000000000,
                    "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "key_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                }
            },
            "super_proof": null
        }"#;

        let receipt = Receipt::from_json(json).expect("Receipt with null super_proof should parse");
        assert!(receipt.super_proof.is_none());
    }

    #[test]
    fn test_receipt_with_super_proof_parses() {
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
                    "timestamp": 1704067200000000000,
                    "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "key_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                }
            },
            "super_proof": {
                "genesis_super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "data_tree_index": 5,
                "super_tree_size": 10,
                "super_root": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "inclusion": ["sha256:1111111111111111111111111111111111111111111111111111111111111111"],
                "consistency_to_origin": ["sha256:2222222222222222222222222222222222222222222222222222222222222222"]
            }
        }"#;

        let receipt = Receipt::from_json(json).expect("Receipt should parse");
        assert_eq!(receipt.spec_version, "2.0.0");
        assert_eq!(receipt.data_tree_index(), Some(5));
        assert_eq!(receipt.super_tree_size(), Some(10));
    }

    #[test]
    fn test_super_proof_accessors() {
        let receipt = Receipt {
            spec_version: "2.0.0".to_string(),
            upgrade_url: None,
            entry: ReceiptEntry {
                id: Uuid::nil(),
                payload_hash: make_test_hash(0xaa),
                metadata: serde_json::json!({}),
            },
            proof: ReceiptProof {
                tree_size: 1,
                root_hash: make_test_hash(0xbb),
                inclusion_path: vec![],
                leaf_index: 0,
                checkpoint: CheckpointJson {
                    origin: make_test_hash(0xcc),
                    tree_size: 1,
                    root_hash: make_test_hash(0xbb),
                    timestamp: 0,
                    signature: "base64:AAAA".to_string(),
                    key_id: make_test_hash(0xdd),
                },
                consistency_proof: None,
            },
            super_proof: Some(make_test_super_proof()),
            anchors: vec![],
        };

        // All accessors return Option
        assert_eq!(receipt.genesis_super_root(), Some(make_test_hash(0xaa).as_str()));
        assert_eq!(receipt.super_root(), Some(make_test_hash(0xbb).as_str()));
        assert_eq!(receipt.data_tree_index(), Some(5));
        assert_eq!(receipt.super_tree_size(), Some(10));
        assert!(receipt.has_super_proof());
    }

    #[test]
    fn test_tier_classification() {
        let base_receipt = Receipt {
            spec_version: "2.0.0".to_string(),
            upgrade_url: None,
            entry: ReceiptEntry {
                id: Uuid::nil(),
                payload_hash: make_test_hash(0xaa),
                metadata: serde_json::json!({}),
            },
            proof: ReceiptProof {
                tree_size: 1,
                root_hash: make_test_hash(0xbb),
                inclusion_path: vec![],
                leaf_index: 0,
                checkpoint: CheckpointJson {
                    origin: make_test_hash(0xcc),
                    tree_size: 1,
                    root_hash: make_test_hash(0xbb),
                    timestamp: 0,
                    signature: "base64:AAAA".to_string(),
                    key_id: make_test_hash(0xdd),
                },
                consistency_proof: None,
            },
            super_proof: Some(make_test_super_proof()),
            anchors: vec![],
        };

        // Lite: no anchors
        assert_eq!(base_receipt.tier(), ReceiptTier::Lite);

        // TSA: has RFC 3161 anchor
        let mut tsa_receipt = base_receipt.clone();
        tsa_receipt.anchors = vec![ReceiptAnchor::Rfc3161 {
            target: "data_tree_root".to_string(),
            target_hash: make_test_hash(0xbb),
            tsa_url: "https://freetsa.org/tsr".to_string(),
            timestamp: "2026-01-13T12:00:00Z".to_string(),
            token_der: "base64:AAAA".to_string(),
        }];
        assert_eq!(tsa_receipt.tier(), ReceiptTier::Tsa);

        // Full: has TSA + OTS
        let mut full_receipt = tsa_receipt;
        full_receipt.anchors.push(ReceiptAnchor::BitcoinOts {
            target: "super_root".to_string(),
            target_hash: make_test_hash(0xbb),
            timestamp: "2026-01-13T12:00:00Z".to_string(),
            bitcoin_block_height: 900_000,
            bitcoin_block_time: "2026-01-13T11:30:00Z".to_string(),
            ots_proof: "base64:BBBB".to_string(),
        });
        assert_eq!(full_receipt.tier(), ReceiptTier::Full);

        // Lite without super_proof (regardless of anchors)
        let mut lite_without_super = base_receipt;
        lite_without_super.super_proof = None;
        lite_without_super.anchors = vec![ReceiptAnchor::Rfc3161 {
            target: "data_tree_root".to_string(),
            target_hash: make_test_hash(0xbb),
            tsa_url: "https://freetsa.org/tsr".to_string(),
            timestamp: "2026-01-13T12:00:00Z".to_string(),
            token_der: "base64:AAAA".to_string(),
        }];
        assert_eq!(lite_without_super.tier(), ReceiptTier::Lite);
    }

    #[test]
    fn test_unsupported_version_rejected() {
        let json = r#"{
            "spec_version": "3.0.0",
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
            "super_proof": {
                "genesis_super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "data_tree_index": 0,
                "super_tree_size": 1,
                "super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "inclusion": [],
                "consistency_to_origin": []
            }
        }"#;

        let result = Receipt::from_json(json);
        assert!(matches!(result, Err(AtlError::UnsupportedReceiptVersion(_))));
    }

    #[test]
    fn test_super_proof_serialized_when_present() {
        let receipt = Receipt {
            spec_version: "2.0.0".to_string(),
            upgrade_url: None,
            entry: ReceiptEntry {
                id: Uuid::nil(),
                payload_hash: make_test_hash(0xaa),
                metadata: serde_json::json!({}),
            },
            proof: ReceiptProof {
                tree_size: 1,
                root_hash: make_test_hash(0xbb),
                inclusion_path: vec![],
                leaf_index: 0,
                checkpoint: CheckpointJson {
                    origin: make_test_hash(0xcc),
                    tree_size: 1,
                    root_hash: make_test_hash(0xbb),
                    timestamp: 0,
                    signature: "base64:AAAA".to_string(),
                    key_id: make_test_hash(0xdd),
                },
                consistency_proof: None,
            },
            super_proof: Some(make_test_super_proof()),
            anchors: vec![],
        };

        let json = receipt.to_json().unwrap();
        assert!(json.contains("\"super_proof\""), "super_proof must be in JSON when present");
    }

    #[test]
    fn test_receipt_tier_name() {
        assert_eq!(ReceiptTier::Lite.name(), "Receipt-Lite");
        assert_eq!(ReceiptTier::Tsa.name(), "Receipt-TSA");
        assert_eq!(ReceiptTier::Full.name(), "Receipt-Full");
    }
}

#[cfg(test)]
mod super_proof_tests {
    use super::*;

    fn make_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    // === Serialization Tests ===

    #[test]
    fn test_super_proof_json_roundtrip() {
        let proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 42,
            super_tree_size: 100,
            super_root: make_hash(0xbb),
            inclusion: vec![make_hash(0xcc), make_hash(0xdd)],
            consistency_to_origin: vec![make_hash(0xee)],
        };

        let json = serde_json::to_string(&proof).unwrap();
        let restored: SuperProof = serde_json::from_str(&json).unwrap();

        assert_eq!(proof, restored);
    }

    #[test]
    fn test_super_proof_json_field_names() {
        let proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 5,
            super_tree_size: 10,
            super_root: make_hash(0xbb),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let json = serde_json::to_string(&proof).unwrap();

        assert!(json.contains("\"genesis_super_root\""));
        assert!(json.contains("\"data_tree_index\""));
        assert!(json.contains("\"super_tree_size\""));
        assert!(json.contains("\"super_root\""));
        assert!(json.contains("\"inclusion\""));
        assert!(json.contains("\"consistency_to_origin\""));
    }

    #[test]
    fn test_super_proof_empty_paths() {
        let proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: make_hash(0xaa),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("\"inclusion\":[]"));
        assert!(json.contains("\"consistency_to_origin\":[]"));
    }

    // === Helper Method Tests ===

    #[test]
    fn test_genesis_super_root_bytes_valid() {
        let proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: make_hash(0xaa),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let bytes = proof.genesis_super_root_bytes().unwrap();
        assert_eq!(bytes, [0xaa; 32]);
    }

    #[test]
    fn test_genesis_super_root_bytes_invalid_prefix() {
        let proof = SuperProof {
            genesis_super_root: "md5:aabbccdd".to_string(),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: make_hash(0xaa),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        assert!(proof.genesis_super_root_bytes().is_err());
    }

    #[test]
    fn test_genesis_super_root_bytes_invalid_hex() {
        let proof = SuperProof {
            genesis_super_root: "sha256:not_hex".to_string(),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: make_hash(0xaa),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        assert!(proof.genesis_super_root_bytes().is_err());
    }

    #[test]
    fn test_genesis_super_root_bytes_wrong_length() {
        let proof = SuperProof {
            genesis_super_root: "sha256:aabbcc".to_string(),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: make_hash(0xaa),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        assert!(proof.genesis_super_root_bytes().is_err());
    }

    #[test]
    fn test_super_root_bytes_valid() {
        let proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 5,
            super_tree_size: 10,
            super_root: make_hash(0xbb),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        let bytes = proof.super_root_bytes().unwrap();
        assert_eq!(bytes, [0xbb; 32]);
    }

    #[test]
    fn test_inclusion_path_bytes_valid() {
        let proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 5,
            super_tree_size: 10,
            super_root: make_hash(0xbb),
            inclusion: vec![make_hash(0xcc), make_hash(0xdd), make_hash(0xee)],
            consistency_to_origin: vec![],
        };

        let path = proof.inclusion_path_bytes().unwrap();
        assert_eq!(path.len(), 3);
        assert_eq!(path[0], [0xcc; 32]);
        assert_eq!(path[1], [0xdd; 32]);
        assert_eq!(path[2], [0xee; 32]);
    }

    #[test]
    fn test_inclusion_path_bytes_with_invalid_element() {
        let proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 5,
            super_tree_size: 10,
            super_root: make_hash(0xbb),
            inclusion: vec![make_hash(0xcc), "invalid".to_string()],
            consistency_to_origin: vec![],
        };

        assert!(proof.inclusion_path_bytes().is_err());
    }

    #[test]
    fn test_consistency_to_origin_bytes_valid() {
        let proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 5,
            super_tree_size: 10,
            super_root: make_hash(0xbb),
            inclusion: vec![],
            consistency_to_origin: vec![make_hash(0xff)],
        };

        let path = proof.consistency_to_origin_bytes().unwrap();
        assert_eq!(path.len(), 1);
        assert_eq!(path[0], [0xff; 32]);
    }

    #[test]
    fn test_is_genesis_true() {
        let proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 0,
            super_tree_size: 1,
            super_root: make_hash(0xaa),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        assert!(proof.is_genesis());
    }

    #[test]
    fn test_is_genesis_false() {
        let proof = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 5,
            super_tree_size: 10,
            super_root: make_hash(0xbb),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };

        assert!(!proof.is_genesis());
    }

    // === Equality Tests ===

    #[test]
    fn test_super_proof_equality() {
        let proof1 = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 5,
            super_tree_size: 10,
            super_root: make_hash(0xbb),
            inclusion: vec![make_hash(0xcc)],
            consistency_to_origin: vec![make_hash(0xdd)],
        };
        let proof2 = proof1.clone();

        assert_eq!(proof1, proof2);
    }

    #[test]
    fn test_super_proof_inequality() {
        let proof1 = SuperProof {
            genesis_super_root: make_hash(0xaa),
            data_tree_index: 5,
            super_tree_size: 10,
            super_root: make_hash(0xbb),
            inclusion: vec![],
            consistency_to_origin: vec![],
        };
        let proof2 = SuperProof {
            genesis_super_root: make_hash(0xff), // Different!
            ..proof1.clone()
        };

        assert_ne!(proof1, proof2);
    }
}

#[cfg(test)]
mod anchor_target_tests {
    use super::*;

    fn make_test_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    #[test]
    fn test_rfc3161_with_mandatory_target() {
        let anchor = ReceiptAnchor::Rfc3161 {
            target: "data_tree_root".to_string(),
            target_hash: make_test_hash(0xaa),
            tsa_url: "https://freetsa.org/tsr".to_string(),
            timestamp: "2026-01-13T12:00:00Z".to_string(),
            token_der: "base64:AAAA".to_string(),
        };

        assert_eq!(anchor.anchor_type(), "rfc3161");
        assert_eq!(anchor.target(), "data_tree_root");
        assert_eq!(anchor.target_hash(), make_test_hash(0xaa));
        assert!(anchor.targets_data_tree_root());
        assert!(!anchor.targets_super_root());
    }

    #[test]
    fn test_bitcoin_ots_with_mandatory_super_root_target() {
        let anchor = ReceiptAnchor::BitcoinOts {
            target: "super_root".to_string(),
            target_hash: make_test_hash(0xbb),
            timestamp: "2026-01-13T12:00:00Z".to_string(),
            bitcoin_block_height: 900_000,
            bitcoin_block_time: "2026-01-13T11:30:00Z".to_string(),
            ots_proof: "base64:BBBB".to_string(),
        };

        assert_eq!(anchor.anchor_type(), "bitcoin_ots");
        assert_eq!(anchor.target(), "super_root");
        assert_eq!(anchor.target_hash(), make_test_hash(0xbb));
        assert!(anchor.targets_super_root());
        assert!(!anchor.targets_data_tree_root());
    }

    #[test]
    fn test_serialization_includes_all_fields() {
        let anchor = ReceiptAnchor::Rfc3161 {
            target: "data_tree_root".to_string(),
            target_hash: make_test_hash(0xaa),
            tsa_url: "https://freetsa.org/tsr".to_string(),
            timestamp: "2026-01-13T12:00:00Z".to_string(),
            token_der: "base64:AAAA".to_string(),
        };

        let json = serde_json::to_string(&anchor).unwrap();
        assert!(json.contains("\"target\""));
        assert!(json.contains("\"target_hash\""));
        assert!(json.contains("\"data_tree_root\""));
    }

    #[test]
    fn test_bitcoin_ots_no_tree_size_field() {
        // BitcoinOts should NOT have tree_size field
        let anchor = ReceiptAnchor::BitcoinOts {
            target: "super_root".to_string(),
            target_hash: make_test_hash(0xbb),
            timestamp: "2026-01-13T12:00:00Z".to_string(),
            bitcoin_block_height: 900_000,
            bitcoin_block_time: "2026-01-13T11:30:00Z".to_string(),
            ots_proof: "base64:BBBB".to_string(),
        };

        let json = serde_json::to_string(&anchor).unwrap();
        assert!(!json.contains("\"tree_size\""), "tree_size should not be present");
    }

    #[test]
    fn test_timestamp_accessor() {
        let rfc3161 = ReceiptAnchor::Rfc3161 {
            target: "data_tree_root".to_string(),
            target_hash: make_test_hash(0xaa),
            tsa_url: "https://freetsa.org/tsr".to_string(),
            timestamp: "2026-01-13T12:00:00Z".to_string(),
            token_der: "base64:AAAA".to_string(),
        };
        assert_eq!(rfc3161.timestamp(), "2026-01-13T12:00:00Z");

        let ots = ReceiptAnchor::BitcoinOts {
            target: "super_root".to_string(),
            target_hash: make_test_hash(0xbb),
            timestamp: "2026-01-13T13:00:00Z".to_string(),
            bitcoin_block_height: 900_000,
            bitcoin_block_time: "2026-01-13T11:30:00Z".to_string(),
            ots_proof: "base64:BBBB".to_string(),
        };
        assert_eq!(ots.timestamp(), "2026-01-13T13:00:00Z");
    }

    #[test]
    fn test_anchor_equality() {
        let anchor1 = ReceiptAnchor::Rfc3161 {
            target: "data_tree_root".to_string(),
            target_hash: make_test_hash(0xaa),
            tsa_url: "https://freetsa.org/tsr".to_string(),
            timestamp: "2026-01-13T12:00:00Z".to_string(),
            token_der: "base64:AAAA".to_string(),
        };
        let anchor2 = anchor1.clone();
        assert_eq!(anchor1, anchor2);
    }

    #[test]
    fn test_target_constants() {
        assert_eq!(ANCHOR_TARGET_DATA_TREE_ROOT, "data_tree_root");
        assert_eq!(ANCHOR_TARGET_SUPER_ROOT, "super_root");
    }

    // === Missing Target Field Tests ===

    #[test]
    fn test_rfc3161_missing_target_fails_parse() {
        // JSON without target fields - MUST FAIL to parse
        let json = r#"{
            "type": "rfc3161",
            "tsa_url": "https://freetsa.org/tsr",
            "timestamp": "2026-01-13T12:00:00Z",
            "token_der": "base64:AAAA"
        }"#;

        let result: Result<ReceiptAnchor, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Anchor JSON without target fields MUST fail to parse");
    }

    #[test]
    fn test_bitcoin_ots_missing_target_fails_parse() {
        // JSON without target fields - MUST FAIL
        let json = r#"{
            "type": "bitcoin_ots",
            "timestamp": "2026-01-13T12:00:00Z",
            "bitcoin_block_height": 900000,
            "bitcoin_block_time": "2026-01-13T11:30:00Z",
            "ots_proof": "base64:BBBB"
        }"#;

        let result: Result<ReceiptAnchor, _> = serde_json::from_str(json);
        assert!(result.is_err(), "Anchor JSON without target fields MUST fail to parse");
    }

    #[test]
    fn test_anchor_roundtrip() {
        let anchor = ReceiptAnchor::Rfc3161 {
            target: "data_tree_root".to_string(),
            target_hash: make_test_hash(0xaa),
            tsa_url: "https://freetsa.org/tsr".to_string(),
            timestamp: "2026-01-13T12:00:00Z".to_string(),
            token_der: "base64:AAAA".to_string(),
        };

        let json = serde_json::to_string(&anchor).unwrap();
        let restored: ReceiptAnchor = serde_json::from_str(&json).unwrap();

        assert_eq!(anchor.target(), restored.target());
        assert_eq!(anchor.target_hash(), restored.target_hash());
    }
}

#[cfg(test)]
mod receipt_tier_tests {
    use super::*;

    #[test]
    fn test_tier_names() {
        assert_eq!(ReceiptTier::Lite.name(), "Receipt-Lite");
        assert_eq!(ReceiptTier::Tsa.name(), "Receipt-TSA");
        assert_eq!(ReceiptTier::Full.name(), "Receipt-Full");
    }

    #[test]
    fn test_tier_equality() {
        assert_eq!(ReceiptTier::Full, ReceiptTier::Full);
        assert_ne!(ReceiptTier::Lite, ReceiptTier::Full);
    }

    #[test]
    fn test_tier_copy() {
        let tier = ReceiptTier::Tsa;
        let copied = tier; // Copy
        assert_eq!(tier, copied);
    }
}

#[cfg(test)]
mod receipt_parsing_tests {
    use super::*;

    #[allow(dead_code)]
    fn make_hash(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    #[test]
    fn test_receipt_without_super_proof_parses_as_lite() {
        // Receipt JSON without super_proof field - SHOULD SUCCEED (Receipt-Lite)
        let json = r#"{
            "spec_version": "2.0.0",
            "entry": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "metadata": {}
            },
            "proof": {
                "tree_size": 10,
                "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "inclusion_path": [],
                "leaf_index": 5,
                "checkpoint": {
                    "origin": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "tree_size": 10,
                    "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "timestamp": 1704067200000000000,
                    "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "key_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                }
            },
            "anchors": []
        }"#;

        let receipt = Receipt::from_json(json).expect("Receipt-Lite should parse");
        assert!(receipt.super_proof.is_none(), "super_proof should be None for Receipt-Lite");
        assert!(!receipt.has_super_proof());
        assert_eq!(receipt.tier(), ReceiptTier::Lite);
    }

    #[test]
    fn test_receipt_json_omits_none_super_proof() {
        // Test serialization omits None super_proof
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
                    "timestamp": 1704067200000000000,
                    "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "key_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                }
            },
            "anchors": []
        }"#;

        let receipt = Receipt::from_json(json).expect("Receipt-Lite should parse");
        let serialized = receipt.to_json().expect("Should serialize");

        // super_proof should not be in JSON when None
        assert!(!serialized.contains("super_proof"), "JSON should not contain super_proof field");
    }

    #[test]
    fn test_missing_target_in_anchor_is_error() {
        // Receipt with anchor missing target field - MUST FAIL
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
                    "timestamp": 1704067200000000000,
                    "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "key_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                }
            },
            "super_proof": {
                "genesis_super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "data_tree_index": 0,
                "super_tree_size": 1,
                "super_root": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "inclusion": [],
                "consistency_to_origin": []
            },
            "anchors": [{
                "type": "rfc3161",
                "tsa_url": "https://freetsa.org/tsr",
                "timestamp": "2026-01-13T12:00:00Z",
                "token_der": "base64:AAAA"
            }]
        }"#;

        let result = Receipt::from_json(json);
        assert!(result.is_err(), "Anchor without target field MUST fail to parse");
    }
}
