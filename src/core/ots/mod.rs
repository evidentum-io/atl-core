//! `OpenTimestamps` (OTS) binary format parsing
//!
//! This module provides parsing of `.ots` files and extraction of
//! Bitcoin attestations. It does NOT verify against Bitcoin blockchain.
//!
//! # Feature Flag
//!
//! This module requires the `bitcoin-ots` feature:
//!
//! ```toml
//! atl-core = { version = "0.4", features = ["bitcoin-ots"] }
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use atl_core::ots::extract_bitcoin_attestations;
//!
//! let ots_bytes = std::fs::read("document.ots")?;
//! let expected_root = /* sha256 of document */;
//!
//! let attestations = extract_bitcoin_attestations(&ots_bytes, &expected_root)?;
//! for att in attestations {
//!     println!("Block height: {}", att.block_height);
//! }
//! ```

mod attestation;
mod builder;
mod error;
mod extract;
mod op;
mod ser;
mod timestamp;

pub use attestation::{Attestation, BITCOIN_TAG, PENDING_TAG, TAG_SIZE};
pub use builder::TimestampBuilder;
pub use error::{MAGIC, MAX_OP_LENGTH, MAX_URI_LEN, OtsError, RECURSION_LIMIT, VERSION};
pub use extract::{BitcoinAttestation, extract_bitcoin_attestations};
pub use op::*;
pub use ser::{Deserializer, DetachedTimestampFile, DigestType, Serializer};
pub use timestamp::{Step, StepData, Timestamp};
