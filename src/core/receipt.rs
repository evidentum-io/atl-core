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
//!     "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
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
use crate::core::jcs::check_unique_property_names;
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

/// Whether this build implements the receipt revision `version` names.
///
/// **The single place the question is answered.** Every gate — this crate's
/// [`Receipt::from_json`], its verifier's step 0, and any consumer such as
/// `atl-cli` — must call this rather than compare a literal of its own, so
/// that two parts of one system cannot disagree about what they accept. They
/// did: a caller admitting every `2.x` while the verifier admitted only
/// `2.0.0` meant a `2.0.1` receipt got past the door and was then reported
/// as a defective receipt rather than an unimplemented revision.
///
/// # Exact match, and why
///
/// ATL v2.0 §4.2 defines `spec_version` as "REQUIRED: Protocol version.
/// Currently \"2.0.0\"" and says nothing further: it defines no
/// compatibility contract, no rule that a verifier must accept later
/// revisions of the same major version, and no rule about fields it does not
/// recognise. With no such contract written down, accepting `2.0.1` would
/// mean asserting a verification performed under rules this build has never
/// seen. So the accepted set is exactly what this build implements, and
/// anything else is an *inability* to verify — never a finding about the
/// receipt.
///
/// Widening this is a specification change first: §4.2 has to state the
/// compatibility rule before an implementation can rely on one.
///
/// # Examples
///
/// ```
/// use atl_core::{is_supported_spec_version, RECEIPT_SPEC_VERSION};
///
/// assert!(is_supported_spec_version(RECEIPT_SPEC_VERSION));
/// assert!(!is_supported_spec_version("2.0.1"));
/// assert!(!is_supported_spec_version("1.0.0"));
/// ```
#[must_use]
pub fn is_supported_spec_version(version: &str) -> bool {
    version == RECEIPT_SPEC_VERSION
}

/// Anchor target: Data Tree Root (for RFC 3161)
pub const ANCHOR_TARGET_DATA_TREE_ROOT: &str = "data_tree_root";

/// Anchor target: Super Root (for Bitcoin OTS)
pub const ANCHOR_TARGET_SUPER_ROOT: &str = "super_root";

// ========== Core Structures ==========

/// Whether a receipt's **source bytes** were examined for duplicate property
/// names, and therefore whether it may be confirmed at all.
///
/// # The constraint this exists for cannot be checked any other way
///
/// RFC 8785 Section 3.1 forbids duplicate property names, and that is a
/// property of a *byte stream*: once JSON has been parsed, the duplicate is
/// gone and no amount of inspection recovers it. `serde_json` keeps the last
/// occurrence, RFC 8259 Section 4 leaves the choice unpredictable, and two
/// conformant readers may therefore compute two different `metadata_hash`
/// values from identical bytes.
///
/// [`Receipt::from_json`] and [`Receipt::from_slice`] scan the text and refuse.
/// Nothing else can: `Receipt` derives `Deserialize` publicly, so
/// `serde_json::from_str`, `from_reader` and `from_value` all go around them,
/// and `from_value` is additionally handed a `Value` that an earlier parse
/// already flattened. **No API that accepts a parsed structure can check this
/// constraint.**
///
/// So the answer is provenance rather than inspection. A `Receipt` records
/// whether its own bytes were ever checked, and
/// [`ReceiptVerifier::verify`](crate::core::verify::ReceiptVerifier::verify)
/// declines to confirm one that carries no such record. That is not a finding
/// against the receipt — it is this crate declining to assert what it did not
/// check.
///
/// # How a *checked* value can be reached, exhaustively
///
/// From outside this crate there is exactly one producer:
/// [`Self::assume_duplicate_property_names_already_rejected`]. That is the
/// whole list, and it is enforced rather than asserted:
///
/// * the inner `bool` is private, so no struct literal can spell the checked
///   state, and [`Self::default`] is *unchecked*;
/// * the field on `Receipt` is `#[serde(skip)]`, so every deserialization path
///   — `from_str`, `from_reader`, `from_slice`, `from_value` — yields the
///   default;
/// * that field is **private**, so it cannot be assigned across from a receipt
///   that was checked;
/// * and **nothing hands the value back out**. [`Receipt::source_text_was_checked`]
///   answers a `bool`. `tests/lib_exports_tests.rs` pins that signature with a
///   coerced function pointer, so restoring a by-value getter is a build
///   failure.
///
/// The last point is not belt-and-braces. While the field was private but the
/// getter still returned `Self`, the gate was open in a shape that looks like
/// careful code rather than an attack:
///
/// ```text
/// ReceiptBuilder::new(r.spec_version, transformed_entry, r.proof).build(r.source_text_check())
/// ```
///
/// A pipeline "preserving provenance" while rebuilding a receipt would write
/// exactly that, and move a certification onto content it never covered.
///
/// Inside this crate, [`Receipt::from_json`] and [`Receipt::from_slice`]
/// produce the checked state via `performed()` after actually scanning the
/// bytes.
///
/// # What it attests, and what holds it to that
///
/// It attests to **the bytes a `Receipt` was parsed from**, at the moment it
/// was parsed. That is only worth something if the value cannot afterwards come
/// to hold *different* content, and it twice could:
///
/// * **By field assignment.** `Receipt`'s data fields were public, so
///
///   ```text
///   let mut carried = checked.clone();
///   carried.entry   = unchecked.entry;     // every crypto field consistent,
///   carried.proof   = unchecked.proof;     // metadata_hash agrees,
///   carried.anchors = unchecked.anchors;   // nothing left to catch
///   ```
///
///   confirmed a document nobody had checked. Every field of [`Receipt`] is now
///   private, readable only through shared-reference accessors
///   ([`Receipt::entry`], [`Receipt::proof`], [`Receipt::anchors`],
///   [`Receipt::super_proof`], [`Receipt::spec_version`],
///   [`Receipt::upgrade_url`]). No `&mut` accessor, no setter.
///
/// * **By method.** Privacy alone did not settle it: five builder methods on
///   `Receipt` reproduced the same assignment —
///
///   ```text
///   let carried = checked
///       .with_super_proof_option(unchecked.super_proof().cloned())
///       .with_anchors(unchecked.anchors().to_vec());
///   ```
///
///   — and anchors are the subject of verification, not decoration. **A public
///   method that takes a `Receipt` and returns a `Receipt` is a setter whatever
///   it is called**, so there are none: construction moved to
///   [`ReceiptBuilder`], which cannot be obtained from a `Receipt`, and which
///   settles provenance at [`ReceiptBuilder::build`] once every part is in
///   place.
///
/// `tests/lib_exports_tests.rs` pins the accessor return types and the builder
/// signatures. The last rule — "no such thing exists" — is a statement about
/// absence and cannot be pinned that way, so the same file **parses this one
/// with `syn`** and fails on anything that turns a `Receipt` into a `Receipt`:
/// methods in inherent *and* trait impls, free functions in this module (which
/// see the private fields, and which `core::receipt` being a public path makes
/// callable by a consumer), impls nested in inline `mod` blocks, and returns
/// hidden behind a `type` alias.
///
/// It is not complete and does not claim to be — the test lists what it does
/// not examine, without inferring safety from that list. Two earlier versions
/// did infer it and were wrong: a line-based scan that `rustfmt` defeated and
/// that never read trait impls, and then a comment asserting free functions
/// were safe "because they cannot touch private fields from another module",
/// when the module in question is this one.
///
/// `Clone` is deliberately kept: a clone carries the marker together with the
/// content it covers, consistently. What was dangerous was changing the content
/// afterwards, and there is now no way to do so.
///
/// The nested structs ([`ReceiptEntry`], [`ReceiptProof`], [`SuperProof`]) keep
/// public fields on purpose — they have to be assemblable to build a receipt —
/// and that costs nothing, because a `&ReceiptEntry` cannot be written through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SourceTextCheck(bool);

impl SourceTextCheck {
    /// The receipt's source bytes were checked for duplicate property names by
    /// this crate. Only reachable from within it.
    pub(crate) const fn performed() -> Self {
        Self(true)
    }

    /// **Escape hatch: asserts something this crate cannot verify.**
    ///
    /// Returns a value marking the receipt as though its source bytes had been
    /// checked, which makes it eligible for confirmation by
    /// [`ReceiptVerifier::verify`](crate::core::verify::ReceiptVerifier::verify).
    ///
    /// Call this **only** when the bytes really were checked — for example a
    /// log operator building a `Receipt` structurally at issuance, where no
    /// untrusted JSON text was ever involved, or a caller that ran
    /// [`check_unique_property_names`](crate::core::jcs::check_unique_property_names)
    /// over the source itself. Calling it to silence a verification error is
    /// asserting a fact about bytes nobody looked at, and the resulting
    /// `valid` verdict is then worth exactly what that assertion is worth.
    ///
    /// The name is deliberately unwieldy. There is no shorter alias, and there
    /// will not be one.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use atl_core::SourceTextCheck;
    ///
    /// // A receipt assembled in memory, from data that was never JSON text.
    /// let provenance = SourceTextCheck::assume_duplicate_property_names_already_rejected();
    /// assert!(provenance.is_checked());
    /// ```
    #[must_use]
    pub const fn assume_duplicate_property_names_already_rejected() -> Self {
        Self(true)
    }

    /// Whether the source bytes were checked.
    #[must_use]
    pub const fn is_checked(self) -> bool {
        self.0
    }
}

/// Evidence Receipt - self-contained proof of entry existence
///
/// # Read-only once built
///
/// Every field is private and is read through a shared-reference accessor.
/// There is no setter, no `&mut` accessor, and **no public method that takes a
/// `Receipt` and returns a `Receipt`** — such a method is a setter whatever it
/// is called.
///
/// Construction is [`Receipt::from_json`] / [`Receipt::from_slice`] (which
/// check the source bytes) or [`ReceiptBuilder`], a separate type that cannot
/// be obtained from a `Receipt` and that settles provenance last. A receipt
/// with different content is a *new* receipt, never an edited one — see
/// [`SourceTextCheck`] for why that is what makes the provenance marker mean
/// anything.
///
/// The nested structures keep public fields, because they must be assemblable
/// to build a receipt; a `&ReceiptEntry` cannot be written through, so that
/// costs nothing.
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
    /// Specification version (MUST be "2.0.0"). Read with [`Self::spec_version`].
    spec_version: String,

    /// URL to request an upgraded receipt (optional). Read with
    /// [`Self::upgrade_url`].
    ///
    /// Clients can use this URL to fetch a receipt with additional anchors.
    /// If omitted, receipt cannot be upgraded.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    upgrade_url: Option<String>,

    /// Entry information. Read with [`Self::entry`].
    entry: ReceiptEntry,

    /// Cryptographic proof linking entry to Data Tree root. Read with
    /// [`Self::proof`].
    proof: ReceiptProof,

    /// Super-Tree proof for global chain consistency (optional). Read with
    /// [`Self::super_proof`].
    ///
    /// Present only after the Data Tree has been closed and added to Super-Tree.
    /// Receipts without `super_proof` are Receipt-Lite (valid but not fully anchored).
    #[serde(default)]
    super_proof: Option<SuperProof>,

    /// External timestamp anchors (optional). Read with [`Self::anchors`].
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    anchors: Vec<ReceiptAnchor>,

    /// Whether this receipt's source bytes were checked for duplicate property
    /// names — see [`SourceTextCheck`], which explains why this is provenance
    /// and not an inspection.
    ///
    /// **Private, and that is the whole mechanism.** While it was public it was
    /// a `Copy` value on a public field, so
    /// `unchecked.source_text_check = checked.source_text_check` moved the
    /// marker from a receipt that had been checked onto one that had not —
    /// without naming the escape hatch, without any warning, and while the
    /// documentation claimed there were only two ways to obtain it. A gate that
    /// can be assigned across is not a gate.
    ///
    /// Read it with [`Receipt::source_text_check`]; set it by parsing text
    /// through [`Receipt::from_json`] / [`Receipt::from_slice`], or by passing
    /// it explicitly to [`ReceiptBuilder::build`].
    #[serde(skip)]
    source_text_check: SourceTextCheck,
}

/// Assembles a [`Receipt`] from parts, settling provenance last.
///
/// # Why construction lives in a separate type
///
/// A method that takes a `Receipt` and returns a `Receipt` is a setter,
/// whatever it is called. `Receipt` briefly had five of them —
/// `with_anchors`, `with_super_proof`, `with_super_proof_option`,
/// `with_upgrade_url`, `with_upgrade_url_option` — and they reproduced by
/// method exactly the field assignment that making the fields private had just
/// closed:
///
/// ```text
/// let carried = checked
///     .super_proof_option(unchecked.super_proof().cloned())
///     .anchors(unchecked.anchors().to_vec());
/// // carried.source_text_was_checked() == true
/// ```
///
/// The anchors and Super-Tree proof came off an unchecked receipt, the marker
/// stayed behind from the checked one, and anchors are not decoration — they
/// are the subject of verification.
///
/// So building is not something a `Receipt` can participate in. A
/// `ReceiptBuilder` cannot be obtained from a `Receipt`: there is no
/// `From<Receipt>`, no `into_builder`, no `Deref`. The only way to a `Receipt`
/// is [`ReceiptBuilder::build`], which consumes the builder.
///
/// # Provenance is the last thing decided, not the first
///
/// [`Self::build`] takes the [`SourceTextCheck`] once, when every part is
/// already in place. That ordering is deliberate: with a constructor that took
/// the marker first and accepted content afterwards, "assemble it, then vouch
/// for it" could not be expressed, and the marker could be settled before
/// anyone knew what it would end up covering. Call order is therefore
/// irrelevant to safety here — no arrangement of the setters below can produce
/// a `Receipt` without a fresh provenance decision at the end.
///
/// # Examples
///
/// ```rust
/// # use atl_core::{ReceiptBuilder, ReceiptEntry, ReceiptProof, SourceTextCheck};
/// # fn build(entry: ReceiptEntry, proof: ReceiptProof) -> atl_core::Receipt {
/// ReceiptBuilder::new("2.0.0".to_string(), entry, proof)
///     // ... optional parts ...
///     .build(
///         // This log assembled the receipt itself; no JSON text was involved.
///         SourceTextCheck::assume_duplicate_property_names_already_rejected(),
///     )
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ReceiptBuilder {
    spec_version: String,
    entry: ReceiptEntry,
    proof: ReceiptProof,
    super_proof: Option<SuperProof>,
    anchors: Vec<ReceiptAnchor>,
    upgrade_url: Option<String>,
}

impl ReceiptBuilder {
    /// Start from the three mandatory parts.
    #[must_use]
    pub const fn new(spec_version: String, entry: ReceiptEntry, proof: ReceiptProof) -> Self {
        Self {
            spec_version,
            entry,
            proof,
            super_proof: None,
            anchors: Vec::new(),
            upgrade_url: None,
        }
    }

    /// Attach a Super-Tree proof.
    #[must_use]
    pub fn super_proof(mut self, super_proof: SuperProof) -> Self {
        self.super_proof = Some(super_proof);
        self
    }

    /// Attach a Super-Tree proof that may be absent (Receipt-Lite).
    #[must_use]
    pub fn super_proof_option(mut self, super_proof: Option<SuperProof>) -> Self {
        self.super_proof = super_proof;
        self
    }

    /// Attach external timestamp anchors.
    #[must_use]
    pub fn anchors(mut self, anchors: Vec<ReceiptAnchor>) -> Self {
        self.anchors = anchors;
        self
    }

    /// Attach the upgrade URL.
    #[must_use]
    pub fn upgrade_url(mut self, upgrade_url: String) -> Self {
        self.upgrade_url = Some(upgrade_url);
        self
    }

    /// Attach an upgrade URL that may be absent.
    #[must_use]
    pub fn upgrade_url_option(mut self, upgrade_url: Option<String>) -> Self {
        self.upgrade_url = upgrade_url;
        self
    }

    /// Finish the receipt, stating the provenance of its bytes.
    ///
    /// Pass [`SourceTextCheck::assume_duplicate_property_names_already_rejected`]
    /// only when the bytes really were checked — for example a log operator
    /// building a receipt at issuance from data structures, where no untrusted
    /// JSON text was ever involved. Otherwise pass
    /// [`SourceTextCheck::default()`], and the receipt will not be confirmed by
    /// [`ReceiptVerifier::verify`](crate::core::verify::ReceiptVerifier::verify).
    ///
    /// This consumes the builder, so the marker is decided once, with every
    /// part already in place, and cannot be inherited from another receipt.
    #[must_use]
    pub fn build(self, source_text_check: SourceTextCheck) -> Receipt {
        Receipt {
            spec_version: self.spec_version,
            upgrade_url: self.upgrade_url,
            entry: self.entry,
            proof: self.proof,
            super_proof: self.super_proof,
            anchors: self.anchors,
            source_text_check,
        }
    }
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

    /// Metadata hash ("sha256:...")
    ///
    /// Pre-computed hash of canonicalized metadata (JCS).
    /// Verifiers MUST check this matches `SHA256(JCS(metadata))`.
    pub metadata_hash: String,

    /// Cleartext metadata (used for hash reconstruction during verification)
    ///
    /// Deserialized by `serde_json`'s own impl, which keeps the **last** of any
    /// repeated property name. RFC 8785 Section 3.1 forbids such a document,
    /// but the duplicate is a property of the byte stream and is gone by the
    /// time this field exists. It is refused on text by
    /// [`Receipt::from_json`] / [`Receipt::from_slice`]; a receipt that reached
    /// this crate any other way is instead declined by the verifier — see
    /// [`SourceTextCheck`].
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
    // TODO(v3.0): Remove this field. Data Tree consistency_proof is vestigial —
    // the CLI does not verify it, and real consistency guarantees come from
    // super_proof.consistency_to_origin (Super-Tree level). Removing requires
    // a breaking change to ReceiptProof, cascading to atl-server (receipt
    // generation, gRPC proto, DTO) and documentation. ~209 references across
    // atl-core, atl-server, atl-cli, protocol docs.
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
    /// Format: `"sha256:<hex>"`
    pub genesis_super_root: String,

    /// Position of this Data Tree in the Super-Tree (0-indexed)
    pub data_tree_index: u64,

    /// Size of the Super-Tree at the time of anchoring
    pub super_tree_size: u64,

    /// The Super-Tree root hash that was anchored
    /// Format: `"sha256:<hex>"`
    pub super_root: String,

    /// Merkle inclusion proof from Data Tree root to Super Root
    /// Format: list of `"sha256:<hex>"`
    pub inclusion: Vec<String>,

    /// RFC 9162 consistency proof from Super-Tree size 1 to current size
    /// Format: list of `"sha256:<hex>"`
    pub consistency_to_origin: Vec<String>,
}

// ========== ReceiptEntry Implementation ==========

impl ReceiptEntry {
    /// Get the metadata hash as bytes
    ///
    /// Parses the "sha256:..." format and returns 32-byte hash.
    ///
    /// # Errors
    ///
    /// * `AtlError::InvalidHash` if hash format is invalid
    pub fn metadata_hash_bytes(&self) -> AtlResult<Hash> {
        parse_hash_string(&self.metadata_hash)
    }
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
    /// Whether this receipt's source bytes were checked for duplicate property
    /// names.
    ///
    /// **Returns a `bool`, not a [`SourceTextCheck`], and that is deliberate.**
    /// Handing the marker out by value made it transferable again the moment
    /// the field became private, because the type is `Copy` and
    /// [`ReceiptBuilder::build`] accepts it:
    ///
    /// ```text
    /// let m = trusted.source_text_check();          // by value
    /// let forged = ReceiptBuilder::new(spec, bad_entry, bad_proof).build(m);
    /// ```
    ///
    /// The worry is not an attacker — an attacker calls the escape hatch
    /// anyway. It is ordinary code that looks careful, such as a pipeline
    /// rebuilding a receipt and "preserving provenance" while transforming the
    /// entry. Exporting only a `bool` means such a pipeline cannot carry the
    /// certification across by accident: to assert it, it must name
    /// [`SourceTextCheck::assume_duplicate_property_names_already_rejected`].
    ///
    /// See [`SourceTextCheck`] for what the answer does and does not attest to.
    #[must_use]
    pub const fn source_text_was_checked(&self) -> bool {
        self.source_text_check.is_checked()
    }

    /// Deserialize receipt from JSON string
    ///
    /// Only v2.0.0 receipts are supported.
    ///
    /// # Duplicate property names are refused, over the whole document
    ///
    /// RFC 8785 Section 3.1 -- which ATL v2.0 Section 2.3 pulls in for
    /// `metadata` -- says "JSON objects MUST NOT exhibit duplicate property
    /// names". `serde_json` keeps the last occurrence and discards the rest, so
    /// `{"x":1,"x":2}` becomes `{"x":2}` before any check on a parsed value
    /// could run, and `metadata_hash` is then computed over an object the
    /// sender did not write.
    ///
    /// **This is the only place the duplicate is still visible**, so the check
    /// runs here, on the raw text, before the typed parse:
    /// [`check_unique_property_names`] reports it as
    /// `AtlError::JcsInputConstraint` with a document-relative pointer.
    ///
    /// It follows that `serde_json::from_str::<Receipt>`, `from_reader` and
    /// `from_value` — which derive `Deserialize` makes reachable and which no
    /// constructor can intercept — cannot be protected this way at all. Those
    /// paths are handled by provenance instead: the resulting receipt carries
    /// [`SourceTextCheck::default()`] and the verifier declines to confirm it.
    ///
    /// It is applied to the **entire receipt**, not only to `entry.metadata`.
    /// Section 3.1 formally binds only the canonicalized subtree, but a
    /// receipt that states `metadata_hash` or `root_hash` twice is a document
    /// two readers can legitimately disagree about -- one verifies against the
    /// first value, another against the second, and they publish opposite
    /// verdicts over identical bytes. That is precisely the failure Section 3.1
    /// exists to prevent, and no reading of ATL v2.0 Section 4.2 makes such a
    /// receipt well-formed. Narrowing the scope to `metadata` would also mean
    /// finding that subtree in the raw text with a scanner of our own, whose
    /// idea of where `metadata` begins could disagree with `serde_json`'s.
    /// See [`check_unique_property_names`] for the full argument.
    ///
    /// # Errors
    ///
    /// * `AtlError::JcsInputConstraint` if any object in the document repeats
    ///   a property name
    /// * `AtlError::InvalidReceipt` if JSON is malformed or missing required fields
    /// * `AtlError::UnsupportedReceiptVersion` if version is not "2.0.0"
    pub fn from_json(json: &str) -> AtlResult<Self> {
        // Only the Section 3.1 verdict is taken from this pass. A document
        // that is not JSON at all is left to the typed parse below, so that a
        // malformed receipt keeps reporting itself as a malformed *receipt*
        // rather than as a canonicalization problem.
        if let Err(e @ AtlError::JcsInputConstraint { .. }) = check_unique_property_names(json) {
            return Err(e);
        }

        let mut receipt: Self =
            serde_json::from_str(json).map_err(|e| AtlError::InvalidReceipt(e.to_string()))?;

        // The one place the check above is actually performed on bytes, so the
        // one place this may be set. Everything `serde` produces is unchecked.
        receipt.source_text_check = SourceTextCheck::performed();

        // Only the revision this build implements -- see
        // `is_supported_spec_version` for why the match is exact, and for
        // why this must not be an inlined comparison of its own.
        if !is_supported_spec_version(receipt.spec_version()) {
            return Err(AtlError::UnsupportedReceiptVersion(receipt.spec_version().to_string()));
        }

        Ok(receipt)
    }

    /// Deserialize receipt from JSON bytes.
    ///
    /// The byte-oriented counterpart of [`Self::from_json`], with the same
    /// guarantees: duplicate property names are refused over the whole
    /// document, and the result carries
    /// [`SourceTextCheck::performed`]-grade provenance so it is eligible for
    /// confirmation.
    ///
    /// It exists so that a caller holding bytes — a file read, a socket, an
    /// HTTP body — has a checked path that is not `serde_json::from_slice`.
    /// That function bypasses this crate entirely and yields a receipt the
    /// verifier will decline to confirm.
    ///
    /// # Errors
    ///
    /// * `AtlError::InvalidReceipt` if the bytes are not UTF-8, if the JSON is
    ///   malformed, or if required fields are missing
    /// * `AtlError::JcsInputConstraint` if any object repeats a property name
    /// * `AtlError::UnsupportedReceiptVersion` if version is not "2.0.0"
    pub fn from_slice(bytes: &[u8]) -> AtlResult<Self> {
        let json = std::str::from_utf8(bytes)
            .map_err(|e| AtlError::InvalidReceipt(format!("receipt is not valid UTF-8: {e}")))?;
        Self::from_json(json)
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

    /// The entry this receipt attests to.
    ///
    /// Returns a **shared** reference. There is no `&mut` counterpart and no
    /// setter, by design — see the type-level note on why `Receipt` is
    /// read-only once built.
    #[must_use]
    pub const fn entry(&self) -> &ReceiptEntry {
        &self.entry
    }

    /// The inclusion proof and signed checkpoint.
    ///
    /// Shared reference only; see [`Self::entry`].
    #[must_use]
    pub const fn proof(&self) -> &ReceiptProof {
        &self.proof
    }

    /// The external timestamp anchors, possibly empty.
    ///
    /// Shared slice only. Adding an anchor to an existing receipt is not
    /// possible and is not an oversight: an anchor is evidence about a root,
    /// and appending one to a value whose provenance was already settled is
    /// exactly the mutation this type refuses. Build a new receipt with
    /// [`ReceiptBuilder`].
    #[must_use]
    pub fn anchors(&self) -> &[ReceiptAnchor] {
        &self.anchors
    }

    /// URL to request an upgraded receipt, if the issuer supplied one.
    #[must_use]
    pub fn upgrade_url(&self) -> Option<&str> {
        self.upgrade_url.as_deref()
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

/// Test-only reassembly of a [`Receipt`] from its parts.
///
/// Lives here rather than in each test module because several of them need it,
/// and because it documents the shape every caller now has to use: `Receipt`
/// exposes no setters and no `&mut` accessors, so changing one field means
/// building a new receipt.
#[cfg(test)]
pub(crate) mod test_support {
    use super::{
        Receipt, ReceiptAnchor, ReceiptBuilder, ReceiptEntry, ReceiptProof, SourceTextCheck,
        SuperProof,
    };

    /// The parts of a [`Receipt`], taken apart so a test can put back a modified one.
    ///
    /// `Receipt` is deliberately immutable in every field that feeds verification,
    /// so a "tampered" receipt is a *new* receipt assembled from altered parts —
    /// which is exactly what a caller outside this crate must now do. Tests go
    /// through the same path rather than a privileged one.
    pub struct ReceiptParts {
        pub spec_version: String,
        pub entry: ReceiptEntry,
        pub proof: ReceiptProof,
        pub super_proof: Option<SuperProof>,
        pub anchors: Vec<ReceiptAnchor>,
        pub upgrade_url: Option<String>,
    }

    impl ReceiptParts {
        /// Copy a receipt's parts out for modification.
        pub fn of(receipt: &Receipt) -> Self {
            Self {
                spec_version: receipt.spec_version().to_string(),
                entry: receipt.entry().clone(),
                proof: receipt.proof().clone(),
                super_proof: receipt.super_proof().cloned(),
                anchors: receipt.anchors().to_vec(),
                upgrade_url: receipt.upgrade_url().map(str::to_string),
            }
        }

        /// Reassemble, vouching for provenance the way a producer would.
        pub fn assemble(self) -> Receipt {
            ReceiptBuilder::new(self.spec_version, self.entry, self.proof)
                .super_proof_option(self.super_proof)
                .anchors(self.anchors)
                .upgrade_url_option(self.upgrade_url)
                .build(SourceTextCheck::assume_duplicate_property_names_already_rejected())
        }
    }

    /// Build a modified copy of `receipt`, the way a caller outside this crate must.
    ///
    /// `Receipt` has no setters and no `&mut` accessors, so "tamper with field X"
    /// is spelled as "take the parts, change one, put a new receipt together". The
    /// rebuilt receipt vouches for its own provenance, so these tests exercise the
    /// tampering they mean to and not the provenance gate by accident.
    pub fn tamper(receipt: &Receipt, mutate: impl FnOnce(&mut ReceiptParts)) -> Receipt {
        let mut parts = ReceiptParts::of(receipt);
        mutate(&mut parts);
        parts.assemble()
    }
}

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
                "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
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

        assert_eq!(receipt.spec_version(), "2.0.0");
        assert_eq!(receipt.entry().id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(receipt.proof().tree_size, 100);
        assert_eq!(receipt.proof().leaf_index, 42);
        assert!(receipt.anchors().is_empty());
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
                "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
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

        assert_eq!(receipt.entry().id, restored.entry.id);
        assert_eq!(receipt.proof().tree_size, restored.proof.tree_size);
    }

    #[test]
    fn test_unsupported_version() {
        // v1.0.0 is now unsupported (but receipt is valid to test version check)
        let json = r#"{
            "spec_version": "1.0.0",
            "entry": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
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
        let receipt = ReceiptBuilder::new(RECEIPT_SPEC_VERSION.to_string(), ReceiptEntry {
                id: Uuid::nil(),
                payload_hash: "sha256:".to_string() + &"aa".repeat(32),
                metadata_hash: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a".to_string(),
                metadata: serde_json::json!({}),
            }, ReceiptProof {
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
            }).super_proof_option(Some(make_test_super_proof())).anchors(vec![]).upgrade_url_option(None).build(SourceTextCheck::assume_duplicate_property_names_already_rejected());

        let json = receipt.to_json().unwrap();
        assert!(!json.contains("\"anchors\""));
    }

    #[test]
    fn test_consistency_proof_omitted_when_none() {
        let receipt = ReceiptBuilder::new(RECEIPT_SPEC_VERSION.to_string(), ReceiptEntry {
                id: Uuid::nil(),
                payload_hash: "sha256:".to_string() + &"aa".repeat(32),
                metadata_hash: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a".to_string(),
                metadata: serde_json::json!({}),
            }, ReceiptProof {
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
            }).super_proof_option(Some(make_test_super_proof())).anchors(vec![]).upgrade_url_option(None).build(SourceTextCheck::assume_duplicate_property_names_already_rejected());

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
                "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
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
        assert_eq!(receipt.anchors().len(), 1);
        assert!(matches!(receipt.anchors()[0], ReceiptAnchor::Rfc3161 { .. }));
    }

    #[test]
    fn test_receipt_with_consistency_proof() {
        let json = r#"{
            "spec_version": "2.0.0",
            "entry": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
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
        let cp = receipt.proof().consistency_proof.as_ref().unwrap();
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
                "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
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
        let receipt = ReceiptBuilder::new(RECEIPT_SPEC_VERSION.to_string(), ReceiptEntry {
                id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
                payload_hash: "sha256:".to_string() + &"aa".repeat(32),
                metadata_hash: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a".to_string(),
                metadata: serde_json::json!({}),
            }, ReceiptProof {
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
            }).super_proof_option(Some(make_test_super_proof())).anchors(vec![]).upgrade_url_option(None).build(SourceTextCheck::assume_duplicate_property_names_already_rejected());

        let pretty = receipt.to_json_pretty().unwrap();
        assert!(pretty.contains('\n')); // Pretty print includes newlines
        assert!(pretty.contains("spec_version"));
    }
}

#[cfg(test)]
mod receipt_v2_tests {
    use super::test_support::tamper;
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

    /// A receipt template with a `{metadata}` hole, so the duplicate-name
    /// tests differ from an accepted receipt in exactly one place.
    fn receipt_with_metadata(metadata: &str) -> String {
        format!(
            r#"{{
            "spec_version": "2.0.0",
            "entry": {{
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
                "metadata": {metadata}
            }},
            "proof": {{
                "tree_size": 1,
                "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "inclusion_path": [],
                "leaf_index": 0,
                "checkpoint": {{
                    "origin": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "tree_size": 1,
                    "root_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "timestamp": 1704067200000000000,
                    "signature": "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "key_id": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                }}
            }}
        }}"#
        )
    }

    /// The concrete hazard, in the place it does the most damage: two readers
    /// hashing two different metadata objects out of one byte sequence.
    #[test]
    fn test_duplicate_property_name_in_metadata_is_refused() {
        let json = receipt_with_metadata(r#"{"x":1,"x":2}"#);

        // serde_json alone would have taken it, silently, as {"x":2}.
        assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());

        match Receipt::from_json(&json) {
            Err(AtlError::JcsInputConstraint { path, reason }) => {
                assert_eq!(path, "/entry/metadata");
                assert!(reason.contains("duplicate"), "{reason}");
            }
            other => panic!("expected a Section 3.1 refusal, got {other:?}"),
        }
    }

    /// Outside `metadata` too: `metadata_hash` stated twice is a receipt two
    /// verifiers can legitimately reach opposite verdicts on.
    #[test]
    fn test_duplicate_property_name_outside_metadata_is_refused() {
        let json = receipt_with_metadata("{}").replacen(
            r#""metadata": {}"#,
            r#""metadata": {}, "metadata_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000""#,
            1,
        );

        match Receipt::from_json(&json) {
            Err(AtlError::JcsInputConstraint { path, .. }) => assert_eq!(path, "/entry"),
            other => panic!("expected a Section 3.1 refusal, got {other:?}"),
        }
    }

    /// The accepting side: the same name in different objects is not a
    /// duplicate, and a receipt full of repeated `root_hash` keys still parses.
    #[test]
    fn test_repeated_names_in_different_objects_are_not_duplicates() {
        let json = receipt_with_metadata(r#"{"a":{"k":1},"b":{"k":2},"c":[{"k":3},{"k":4}]}"#);
        let receipt = Receipt::from_json(&json).expect("distinct objects may share key names");
        assert_eq!(receipt.spec_version(), "2.0.0");
    }

    // ===== Paths that go around `from_json` =====

    /// **What raw `serde` does, stated plainly.** `Receipt` derives
    /// `Deserialize` publicly, so `from_str`/`from_reader`/`from_value` are
    /// reachable by any consumer and no constructor can intercept them. They
    /// collapse a duplicate to its last value, and nothing downstream can tell.
    ///
    /// This crate does not try to detect that at the field any more — see the
    /// module docs on `jcs` for why the hand-written visitor was removed. The
    /// document is accepted, and then **never confirmed**, because it carries
    /// no evidence that its bytes were examined.
    #[test]
    fn test_raw_serde_collapses_duplicates_but_yields_unconfirmable_receipts() {
        let json = receipt_with_metadata(r#"{"x":1,"x":2}"#);

        for (label, receipt) in [
            ("from_str", serde_json::from_str::<Receipt>(&json).unwrap()),
            ("from_reader", serde_json::from_reader::<_, Receipt>(json.as_bytes()).unwrap()),
        ] {
            // The duplicate is gone, silently -- this is `serde_json`, not us.
            assert_eq!(receipt.entry().metadata, serde_json::json!({"x": 2}), "{label}");
            assert!(
                !receipt.source_text_was_checked(),
                "{label} must not yield a confirmable receipt"
            );
        }

        // The text-scanning path refuses it outright, naming where.
        match Receipt::from_json(&json) {
            Err(AtlError::JcsInputConstraint { path, reason }) => {
                assert_eq!(path, "/entry/metadata");
                assert!(reason.contains("duplicate"), "{reason}");
            }
            other => panic!("expected a Section 3.1 refusal, got {other:?}"),
        }
    }

    /// Depth makes no difference to either half.
    #[test]
    fn test_duplicates_are_located_however_deep_and_never_confirmable() {
        let json = receipt_with_metadata(r#"{"a":{"b":[{"k":1},{"k":1,"k":2}]}}"#);

        let receipt = serde_json::from_str::<Receipt>(&json).expect("serde accepts it");
        assert!(!receipt.source_text_was_checked());

        match Receipt::from_json(&json) {
            Err(AtlError::JcsInputConstraint { path, .. }) => {
                assert_eq!(path, "/entry/metadata/a/b/1");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// Repeated names in *different* objects are not duplicates, on every path.
    #[test]
    fn test_metadata_that_merely_repeats_names_is_accepted_everywhere() {
        let json = receipt_with_metadata(r#"{"a":{"k":1},"b":{"k":2},"c":[{"k":3}]}"#);
        let expected = serde_json::json!({"a":{"k":1},"b":{"k":2},"c":[{"k":3}]});

        assert_eq!(serde_json::from_str::<Receipt>(&json).unwrap().entry.metadata, expected);
        let checked = Receipt::from_json(&json).expect("not duplicates");
        assert_eq!(checked.entry.metadata, expected);
        assert!(checked.source_text_was_checked());
    }

    /// Every JSON shape must survive deserialization into `metadata` unchanged.
    ///
    /// Trivial while `metadata` uses `serde_json`'s own impl, and pinned anyway:
    /// it is the baseline the `arbitrary-precision-audit` build is compared
    /// against, and the reason the hand-written visitor that once sat here was
    /// removed was that it silently failed exactly this under that feature.
    #[test]
    fn test_metadata_deserialization_preserves_every_json_shape() {
        let metadata = r#"{"nul":null,"t":true,"f":false,"i":-42,"u":18446744073709551615,
            "d":1.5,"neg0":-0.0,"s":"caf\u00e9 \ud83d\ude00","empty_obj":{},"empty_arr":[],
            "deep":[[[{"x":[1,{"y":null}]}]]]}"#;
        let json = receipt_with_metadata(metadata);

        let receipt = serde_json::from_str::<Receipt>(&json).expect("valid metadata");
        let reference: serde_json::Value = serde_json::from_str(metadata).expect("valid JSON");
        assert_eq!(receipt.entry().metadata, reference);
    }

    /// Duplicate *known* struct fields are refused by the derived
    /// `Deserialize`. Pinned rather than assumed, and deliberately not
    /// duplicated by hand: an implied guarantee is one nobody notices losing.
    #[test]
    fn test_derived_deserialize_refuses_duplicate_known_struct_fields() {
        let json = receipt_with_metadata("{}").replacen(
            r#""spec_version": "2.0.0","#,
            r#""spec_version": "2.0.0", "spec_version": "9.9.9","#,
            1,
        );

        let err = serde_json::from_str::<Receipt>(&json).expect_err("duplicate known field");
        assert!(err.to_string().contains("duplicate field"), "{err}");
        assert!(Receipt::from_json(&json).is_err());
    }

    // ===== The path no visitor can close =====

    /// **`from_value` cannot be fixed by inspection, and is not claimed to be.**
    /// It runs `Receipt::deserialize` over a `Value` that some earlier parse
    /// already flattened, so the duplicate is gone before this crate is
    /// involved. The replacement deserializer is handed a `Map` with no
    /// duplicate in it and honestly accepts it.
    ///
    /// What stops the verdict is provenance, not detection: the receipt records
    /// that its bytes were never checked, and the verifier declines to confirm
    /// it.
    #[test]
    fn test_from_value_accepts_the_flattened_document_but_records_no_provenance() {
        let json = receipt_with_metadata(r#"{"x":1,"x":2}"#);
        let flattened: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

        // The duplicate is already lost here -- nothing downstream can see it.
        assert_eq!(flattened["entry"]["metadata"], serde_json::json!({"x": 2}));

        let receipt: Receipt = serde_json::from_value(flattened).expect("nothing left to detect");
        assert!(
            !receipt.source_text_was_checked(),
            "from_value must never yield a receipt eligible for confirmation"
        );
    }

    #[test]
    fn test_from_slice_is_a_checked_path() {
        let json = receipt_with_metadata(r#"{"ok":1}"#);

        let receipt = Receipt::from_slice(json.as_bytes()).expect("valid receipt");
        assert!(receipt.source_text_was_checked());

        let dup = receipt_with_metadata(r#"{"x":1,"x":2}"#);
        assert!(matches!(
            Receipt::from_slice(dup.as_bytes()),
            Err(AtlError::JcsInputConstraint { .. })
        ));

        // Invalid UTF-8 is a malformed receipt, not a canonicalization problem.
        assert!(matches!(Receipt::from_slice(&[0xff, 0xfe]), Err(AtlError::InvalidReceipt(_))));
    }

    /// **The marker cannot be moved from one receipt to another.**
    ///
    /// While `source_text_check` was a public `Copy` field, this was enough to
    /// defeat the gate entirely, without naming the escape hatch:
    ///
    /// ```text
    /// let good = Receipt::from_json(any_valid_text)?;
    /// let mut bad: Receipt = serde_json::from_value(collapsed)?;
    /// bad.source_text_check = good.source_text_check;   // gate bypassed
    /// ```
    ///
    /// The field is now private, so that assignment does not compile and the
    /// only writes are `from_json`/`from_slice` (which check) and
    /// `ReceiptBuilder::build` (which demands the value by name). This test pins the
    /// half that *is* observable at runtime: obtaining a checked receipt does
    /// not make an unchecked one checked, and the marker does not travel
    /// through the data.
    #[test]
    fn test_the_marker_does_not_travel_between_receipts() {
        let good =
            Receipt::from_json(&receipt_with_metadata(r#"{"ok":1}"#)).expect("valid receipt");
        assert!(good.source_text_was_checked());

        // The classic transfer target: a document whose duplicate was already
        // lost, reached through `from_value`.
        let collapsed: serde_json::Value =
            serde_json::from_str(&receipt_with_metadata(r#"{"x":1,"x":2}"#)).unwrap();
        let bad: Receipt = serde_json::from_value(collapsed).expect("nothing left to detect");
        assert!(!bad.source_text_was_checked());

        // Carrying `good`'s data across does not carry its provenance: the only
        // way to build a `Receipt` from parts states the marker explicitly.
        let rebuilt =
            ReceiptBuilder::new(good.spec_version.clone(), good.entry.clone(), good.proof.clone())
                .build(SourceTextCheck::default());
        assert!(!rebuilt.source_text_was_checked());

        // And nothing hands the marker back out: the only public reader answers
        // `bool`, so there is no value to pass to `ReceiptBuilder::build`.
        let observed: bool = bad.source_text_was_checked();
        assert!(!observed);
    }

    /// **A rebuilt receipt does not inherit the provenance of its parts.**
    ///
    /// It used to be separable, and that was the last hole: `Receipt`'s data
    /// fields were public, so
    ///
    /// ```text
    /// let mut carried = checked.clone();
    /// carried.entry = unchecked.entry;     // every crypto field consistent,
    /// carried.proof = unchecked.proof;     // metadata_hash agrees,
    /// carried.anchors = unchecked.anchors; // nothing to catch
    /// // is_valid: true
    /// ```
    ///
    /// confirmed a document whose bytes nobody had checked, without touching
    /// [`SourceTextCheck`] at all. Every field of `Receipt` that feeds
    /// verification is now private behind a shared-reference accessor, so a
    /// receipt cannot be edited after it exists: changing anything means
    /// building a new one through [`ReceiptBuilder`], which demands a
    /// provenance answer of its own at [`ReceiptBuilder::build`].
    ///
    /// The compile-time half is pinned in `tests/lib_exports_tests.rs`; this is
    /// the runtime half — a rebuilt receipt carries the provenance it was
    /// *given*, not the one its parts came from.
    #[test]
    fn test_rebuilding_a_receipt_does_not_inherit_provenance() {
        let checked = Receipt::from_json(&receipt_with_metadata("{}")).expect("valid");
        assert!(checked.source_text_was_checked());

        let unchecked: Receipt =
            serde_json::from_str(&receipt_with_metadata(r#"{"x":1,"x":2}"#)).expect("parses");
        assert!(!unchecked.source_text_was_checked());

        // Taking the unchecked receipt's parts and rebuilding: the result is
        // only as trusted as the answer given here, and `ReceiptBuilder::build`
        // will not let that answer be omitted or copied from `checked`.
        let rebuilt = ReceiptBuilder::new(
            unchecked.spec_version().to_string(),
            unchecked.entry().clone(),
            unchecked.proof().clone(),
        )
        .anchors(unchecked.anchors().to_vec())
        .build(SourceTextCheck::default());
        assert!(!rebuilt.source_text_was_checked());

        // And the content of a checked receipt cannot be replaced in place at
        // all -- there is no accessor that would allow it. What a caller can do
        // is assemble a new receipt and vouch for it deliberately, which is a
        // statement about bytes they are making themselves.
        let vouched = ReceiptBuilder::new(
            unchecked.spec_version().to_string(),
            unchecked.entry().clone(),
            unchecked.proof().clone(),
        )
        .build(SourceTextCheck::assume_duplicate_property_names_already_rejected());
        assert!(vouched.source_text_was_checked());
    }

    /// Every `serde` entry point yields unchecked provenance; only parsing from
    /// text through this crate sets it.
    #[test]
    fn test_no_serde_path_can_set_the_provenance_marker() {
        let json = receipt_with_metadata(r#"{"ok":1}"#);

        for (label, receipt) in [
            ("from_str", serde_json::from_str::<Receipt>(&json).unwrap()),
            ("from_reader", serde_json::from_reader::<_, Receipt>(json.as_bytes()).unwrap()),
            ("from_slice", serde_json::from_slice::<Receipt>(json.as_bytes()).unwrap()),
            (
                "from_value",
                serde_json::from_value::<Receipt>(serde_json::from_str(&json).unwrap()).unwrap(),
            ),
        ] {
            assert!(!receipt.source_text_was_checked(), "{label} set the marker");
        }

        // And a round trip through this crate's own serializer does not carry
        // the marker across, because it is not part of the wire format.
        let checked = Receipt::from_json(&json).expect("valid receipt");
        assert!(checked.source_text_was_checked());
        let reserialized = checked.to_json().expect("serializes");
        assert!(!reserialized.contains("source_text_check"));
        assert!(Receipt::from_json(&reserialized).unwrap().source_text_was_checked());
    }

    /// The gap left open by design: a repeated *unknown* field. `serde` ignores
    /// unknown fields and does not track them, so the raw-`serde` path accepts
    /// it. That is recorded rather than closed — `deny_unknown_fields` would
    /// decide extensibility under ATL v2.0 Section 4.2, which is a
    /// specification question, not a canonicalization one.
    ///
    /// It is not exploitable for a *verdict*, and that is the point of this
    /// test: such a receipt has unchecked provenance, so the verifier refuses
    /// to confirm it regardless.
    #[test]
    fn test_duplicate_unknown_field_is_accepted_by_serde_but_never_confirmed() {
        let json = receipt_with_metadata("{}").replacen(
            r#""spec_version": "2.0.0","#,
            r#""spec_version": "2.0.0", "junk": 1, "junk": 2,"#,
            1,
        );

        let receipt = serde_json::from_str::<Receipt>(&json)
            .expect("if this now fails, the gap closed and this test should say so");
        assert!(
            !receipt.source_text_was_checked(),
            "the door that stays shut: no confirmation without checked bytes"
        );

        // And the text-scanning path refuses it outright.
        match Receipt::from_json(&json) {
            Err(AtlError::JcsInputConstraint { path, .. }) => assert_eq!(path, ""),
            other => panic!("from_json must refuse it, got {other:?}"),
        }
    }

    /// Malformed JSON must keep reporting itself as a malformed *receipt*: the
    /// Section 3.1 pass runs first and must not take over that diagnosis.
    #[test]
    fn test_malformed_json_is_still_an_invalid_receipt() {
        match Receipt::from_json("{not json") {
            Err(AtlError::InvalidReceipt(_)) => {}
            other => panic!("expected InvalidReceipt, got {other:?}"),
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
                "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
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
        assert!(receipt.super_proof().is_none());
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
                "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
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
        assert!(receipt.super_proof().is_none());
    }

    #[test]
    fn test_receipt_with_super_proof_parses() {
        let json = r#"{
            "spec_version": "2.0.0",
            "entry": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
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
        assert_eq!(receipt.spec_version(), "2.0.0");
        assert_eq!(receipt.data_tree_index(), Some(5));
        assert_eq!(receipt.super_tree_size(), Some(10));
    }

    #[test]
    fn test_super_proof_accessors() {
        let receipt = ReceiptBuilder::new(
            "2.0.0".to_string(),
            ReceiptEntry {
                id: Uuid::nil(),
                payload_hash: make_test_hash(0xaa),
                metadata_hash:
                    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
                        .to_string(),
                metadata: serde_json::json!({}),
            },
            ReceiptProof {
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
        )
        .super_proof_option(Some(make_test_super_proof()))
        .anchors(vec![])
        .upgrade_url_option(None)
        .build(SourceTextCheck::assume_duplicate_property_names_already_rejected());

        // All accessors return Option
        assert_eq!(receipt.genesis_super_root(), Some(make_test_hash(0xaa).as_str()));
        assert_eq!(receipt.super_root(), Some(make_test_hash(0xbb).as_str()));
        assert_eq!(receipt.data_tree_index(), Some(5));
        assert_eq!(receipt.super_tree_size(), Some(10));
        assert!(receipt.has_super_proof());
    }

    #[test]
    fn test_tier_classification() {
        let base_receipt = ReceiptBuilder::new(
            "2.0.0".to_string(),
            ReceiptEntry {
                id: Uuid::nil(),
                payload_hash: make_test_hash(0xaa),
                metadata_hash:
                    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
                        .to_string(),
                metadata: serde_json::json!({}),
            },
            ReceiptProof {
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
        )
        .super_proof_option(Some(make_test_super_proof()))
        .anchors(vec![])
        .upgrade_url_option(None)
        .build(SourceTextCheck::assume_duplicate_property_names_already_rejected());

        // Lite: no anchors
        assert_eq!(base_receipt.tier(), ReceiptTier::Lite);

        // TSA: has RFC 3161 anchor
        let tsa_receipt = base_receipt.clone();
        let tsa_receipt = tamper(&tsa_receipt, |p| {
            p.anchors = vec![ReceiptAnchor::Rfc3161 {
                target: "data_tree_root".to_string(),
                target_hash: make_test_hash(0xbb),
                tsa_url: "https://freetsa.org/tsr".to_string(),
                timestamp: "2026-01-13T12:00:00Z".to_string(),
                token_der: "base64:AAAA".to_string(),
            }]
        });
        assert_eq!(tsa_receipt.tier(), ReceiptTier::Tsa);

        // Full: has TSA + OTS
        let full_receipt = tamper(&tsa_receipt, |p| {
            p.anchors.push(ReceiptAnchor::BitcoinOts {
                target: "super_root".to_string(),
                target_hash: make_test_hash(0xbb),
                timestamp: "2026-01-13T12:00:00Z".to_string(),
                bitcoin_block_height: 900_000,
                bitcoin_block_time: "2026-01-13T11:30:00Z".to_string(),
                ots_proof: "base64:BBBB".to_string(),
            });
        });
        assert_eq!(full_receipt.tier(), ReceiptTier::Full);

        // Lite without super_proof (regardless of anchors)
        let lite_without_super = tamper(&base_receipt, |p| p.super_proof = None);
        let lite_without_super = tamper(&lite_without_super, |p| {
            p.anchors = vec![ReceiptAnchor::Rfc3161 {
                target: "data_tree_root".to_string(),
                target_hash: make_test_hash(0xbb),
                tsa_url: "https://freetsa.org/tsr".to_string(),
                timestamp: "2026-01-13T12:00:00Z".to_string(),
                token_der: "base64:AAAA".to_string(),
            }]
        });
        assert_eq!(lite_without_super.tier(), ReceiptTier::Lite);
    }

    #[test]
    fn test_unsupported_version_rejected() {
        let json = r#"{
            "spec_version": "3.0.0",
            "entry": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
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

        // The same door, for a later revision of the same major version --
        // the case that used to get past a caller's `2.x` gate and then be
        // reported as a defective receipt rather than an unimplemented
        // revision. ATL v2.0 §4.2 defines no compatibility rule to lean on.
        let later_minor =
            json.replace("\"spec_version\": \"3.0.0\"", "\"spec_version\": \"2.0.1\"");
        assert!(matches!(
            Receipt::from_json(&later_minor),
            Err(AtlError::UnsupportedReceiptVersion(v)) if v == "2.0.1"
        ));
    }

    #[test]
    fn test_super_proof_serialized_when_present() {
        let receipt = ReceiptBuilder::new(
            "2.0.0".to_string(),
            ReceiptEntry {
                id: Uuid::nil(),
                payload_hash: make_test_hash(0xaa),
                metadata_hash:
                    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
                        .to_string(),
                metadata: serde_json::json!({}),
            },
            ReceiptProof {
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
        )
        .super_proof_option(Some(make_test_super_proof()))
        .anchors(vec![])
        .upgrade_url_option(None)
        .build(SourceTextCheck::assume_duplicate_property_names_already_rejected());

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
                "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
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
        assert!(receipt.super_proof().is_none(), "super_proof should be None for Receipt-Lite");
        assert!(!receipt.has_super_proof());
        assert_eq!(receipt.tier(), ReceiptTier::Lite);
    }

    #[test]
    fn test_receipt_json_includes_null_super_proof() {
        // Test serialization includes super_proof: null when None (per v2.0 spec)
        let json = r#"{
            "spec_version": "2.0.0",
            "entry": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
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

        // super_proof MUST be present as null in JSON (v2.0 spec requirement)
        assert!(
            serialized.contains("\"super_proof\":null"),
            "JSON must contain super_proof field with null value"
        );
    }

    #[test]
    fn test_missing_target_in_anchor_is_error() {
        // Receipt with anchor missing target field - MUST FAIL
        let json = r#"{
            "spec_version": "2.0.0",
            "entry": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "payload_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "metadata_hash": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
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
