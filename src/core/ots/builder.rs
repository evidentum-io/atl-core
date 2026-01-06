//! Builder API for creating `OpenTimestamps` timestamp files
//!
//! This module provides a fluent builder interface for programmatically
//! constructing OTS timestamp files without manually building the tree structure.
//!
//! # Examples
//!
//! ```rust,ignore
//! use atl_core::ots::TimestampBuilder;
//!
//! let hash = [0xaa; 32];
//! let ots_bytes = TimestampBuilder::new(hash)
//!     .prepend(&[0x01, 0x02, 0x03])
//!     .sha256()
//!     .add_pending_attestation("https://alice.btc.calendar.opentimestamps.org")
//!     .build()?;
//! ```

use super::attestation::Attestation;
use super::error::OtsError;
use super::op::Op;
use super::ser::{DetachedTimestampFile, DigestType};
use super::timestamp::{Step, StepData, Timestamp};

/// Internal representation of builder operations
#[derive(Clone)]
enum BuilderOp {
    /// Cryptographic operation
    Op(Op),
    /// Attestation (leaf node)
    Attestation(Attestation),
    /// Fork with multiple branches
    Fork(Vec<Vec<Self>>),
}

/// Type alias for fork stack entry: (`parent_ops`, `sibling_branches`)
type ForkStackEntry = (Vec<BuilderOp>, Vec<Vec<BuilderOp>>);

/// Builder for creating OTS timestamp files programmatically
///
/// The builder provides a fluent interface for constructing timestamps
/// by chaining operations and attestations. It handles fork management
/// and validates the resulting timestamp structure.
///
/// # Examples
///
/// Simple timestamp with pending attestation:
///
/// ```rust,ignore
/// let hash = [0xaa; 32];
/// let ots_bytes = TimestampBuilder::new(hash)
///     .sha256()
///     .add_pending_attestation("https://calendar.example.org")
///     .build()?;
/// ```
///
/// Timestamp with fork and multiple attestations:
///
/// ```rust,ignore
/// let hash = [0xbb; 32];
/// let ots_bytes = TimestampBuilder::new(hash)
///     .sha256()
///     .fork()
///     .prepend(&[0x01])
///     .sha256()
///     .add_bitcoin_attestation(500000)
///     .fork()
///     .prepend(&[0x02])
///     .sha256()
///     .add_pending_attestation("https://calendar.example.org")
///     .end_fork()
///     .end_fork()
///     .build()?;
/// ```
pub struct TimestampBuilder {
    /// Initial document hash
    document_hash: Vec<u8>,
    /// Hash algorithm used for document
    digest_type: DigestType,
    /// Current operations being built
    ops: Vec<BuilderOp>,
    /// Stack of (`parent_ops`, `sibling_branches`) for fork handling
    fork_stack: Vec<ForkStackEntry>,
}

impl TimestampBuilder {
    /// Create new builder for SHA256-hashed document
    ///
    /// # Arguments
    ///
    /// * `document_hash` - SHA256 hash of the document being timestamped
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let hash = [0xaa; 32];
    /// let builder = TimestampBuilder::new(hash);
    /// ```
    #[must_use]
    pub fn new(document_hash: [u8; 32]) -> Self {
        Self::with_digest_type(document_hash.to_vec(), DigestType::Sha256)
    }

    /// Create builder with custom digest type
    ///
    /// # Arguments
    ///
    /// * `document_hash` - Document hash (length must match digest type)
    /// * `digest_type` - Hash algorithm used for document
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let hash = [0xbb; 20];
    /// let builder = TimestampBuilder::with_digest_type(
    ///     hash.to_vec(),
    ///     DigestType::Sha1
    /// );
    /// ```
    #[must_use]
    pub const fn with_digest_type(document_hash: Vec<u8>, digest_type: DigestType) -> Self {
        Self { document_hash, digest_type, ops: Vec::new(), fork_stack: Vec::new() }
    }

    /// Append data to current digest
    ///
    /// # Arguments
    ///
    /// * `data` - Bytes to append to the digest
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// builder.append(&[0x01, 0x02, 0x03]);
    /// ```
    #[must_use]
    pub fn append(mut self, data: &[u8]) -> Self {
        self.ops.push(BuilderOp::Op(Op::Append(data.to_vec())));
        self
    }

    /// Prepend data to current digest
    ///
    /// # Arguments
    ///
    /// * `data` - Bytes to prepend to the digest
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// builder.prepend(&[0x01, 0x02, 0x03]);
    /// ```
    #[must_use]
    pub fn prepend(mut self, data: &[u8]) -> Self {
        self.ops.push(BuilderOp::Op(Op::Prepend(data.to_vec())));
        self
    }

    /// Apply SHA256 hash operation
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// builder.sha256();
    /// ```
    #[must_use]
    pub fn sha256(mut self) -> Self {
        self.ops.push(BuilderOp::Op(Op::Sha256));
        self
    }

    /// Apply RIPEMD160 hash operation
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// builder.ripemd160();
    /// ```
    #[must_use]
    pub fn ripemd160(mut self) -> Self {
        self.ops.push(BuilderOp::Op(Op::Ripemd160));
        self
    }

    /// Apply SHA1 hash operation (legacy)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// builder.sha1();
    /// ```
    #[must_use]
    pub fn sha1(mut self) -> Self {
        self.ops.push(BuilderOp::Op(Op::Sha1));
        self
    }

    /// Reverse current digest bytes
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// builder.reverse();
    /// ```
    #[must_use]
    pub fn reverse(mut self) -> Self {
        self.ops.push(BuilderOp::Op(Op::Reverse));
        self
    }

    /// Hexlify current digest (convert to lowercase hex string)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// builder.hexlify();
    /// ```
    #[must_use]
    pub fn hexlify(mut self) -> Self {
        self.ops.push(BuilderOp::Op(Op::Hexlify));
        self
    }

    /// Add pending attestation (calendar server)
    ///
    /// # Arguments
    ///
    /// * `calendar_uri` - URI of the calendar server
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// builder.add_pending_attestation("https://alice.btc.calendar.opentimestamps.org");
    /// ```
    #[must_use]
    pub fn add_pending_attestation(mut self, calendar_uri: &str) -> Self {
        self.ops
            .push(BuilderOp::Attestation(Attestation::Pending { uri: calendar_uri.to_string() }));
        self
    }

    /// Add Bitcoin attestation
    ///
    /// # Arguments
    ///
    /// * `block_height` - Bitcoin block height where timestamp is anchored
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// builder.add_bitcoin_attestation(500000);
    /// ```
    #[must_use]
    pub fn add_bitcoin_attestation(mut self, block_height: u64) -> Self {
        self.ops.push(BuilderOp::Attestation(Attestation::Bitcoin { height: block_height }));
        self
    }

    /// Start a new fork
    ///
    /// Saves current operations and starts a fresh branch. Multiple calls
    /// to `fork()` create sibling branches. Call `end_fork()` to merge
    /// all branches back into the parent.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// builder
    ///     .sha256()
    ///     .fork()
    ///     .prepend(&[0x01])
    ///     .add_pending_attestation("https://alice.calendar.org")
    ///     .fork()
    ///     .prepend(&[0x02])
    ///     .add_pending_attestation("https://bob.calendar.org")
    ///     .end_fork()
    ///     .end_fork();
    /// ```
    #[must_use]
    pub fn fork(mut self) -> Self {
        // If we're already in a fork context, this starts a new sibling branch
        if let Some((_, branches)) = self.fork_stack.last_mut() {
            // Complete current branch and add it to the list
            let current_ops = std::mem::take(&mut self.ops);
            branches.push(current_ops);
        } else {
            // Starting a new fork - save parent ops and begin first branch
            let parent_ops = std::mem::take(&mut self.ops);
            self.fork_stack.push((parent_ops, vec![]));
        }
        self
    }

    /// End current fork and merge branches
    ///
    /// Collects all branches created since the last `fork()` call,
    /// creates a Fork node, and adds it to the parent branch.
    ///
    /// # Examples
    ///
    /// See [`fork()`](#method.fork) for examples.
    #[must_use]
    pub fn end_fork(mut self) -> Self {
        if let Some((mut parent_ops, mut branches)) = self.fork_stack.pop() {
            // Add current ops as the last branch
            let current_ops = std::mem::take(&mut self.ops);
            branches.push(current_ops);

            // Create Fork node with all branches
            parent_ops.push(BuilderOp::Fork(branches));

            // Restore parent ops
            self.ops = parent_ops;
        }
        // If stack is empty, this is an error (handled during validation)

        self
    }

    /// Validate and build the OTS file bytes
    ///
    /// # Returns
    ///
    /// Serialized OTS file bytes or validation error
    ///
    /// # Errors
    ///
    /// * [`OtsError::NoAttestation`] - No attestation added
    /// * [`OtsError::UnclosedFork`] - Fork not closed with `end_fork()`
    /// * [`OtsError::EmptyFork`] - Fork has no branches
    /// * [`OtsError::IoError`] - Serialization error
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let ots_bytes = builder.build()?;
    /// ```
    pub fn build(self) -> Result<Vec<u8>, OtsError> {
        let file = self.build_timestamp()?;
        file.to_bytes()
    }

    /// Build into a `DetachedTimestampFile` struct
    ///
    /// # Returns
    ///
    /// Constructed timestamp file or validation error
    ///
    /// # Errors
    ///
    /// * [`OtsError::NoAttestation`] - No attestation added
    /// * [`OtsError::UnclosedFork`] - Fork not closed with `end_fork()`
    /// * [`OtsError::EmptyFork`] - Fork has no branches
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let timestamp_file = builder.build_timestamp()?;
    /// ```
    pub fn build_timestamp(self) -> Result<DetachedTimestampFile, OtsError> {
        // Validate: all forks must be closed
        if !self.fork_stack.is_empty() {
            return Err(OtsError::UnclosedFork);
        }

        // Validate: must have at least one operation
        if self.ops.is_empty() {
            return Err(OtsError::NoAttestation);
        }

        // Validate: must have at least one attestation
        if !Self::has_attestation(&self.ops) {
            return Err(OtsError::NoAttestation);
        }

        // Build timestamp tree
        let first_step = Self::build_step(&self.ops, self.document_hash.clone())?;

        let timestamp = Timestamp { start_digest: self.document_hash, first_step };

        Ok(DetachedTimestampFile { digest_type: self.digest_type, timestamp })
    }

    /// Check if operations contain at least one attestation
    ///
    /// For forks, ALL branches must contain attestations (not just one)
    fn has_attestation(ops: &[BuilderOp]) -> bool {
        ops.iter().any(|op| match op {
            BuilderOp::Attestation(_) => true,
            BuilderOp::Fork(branches) => {
                // ALL branches must have attestations
                !branches.is_empty() && branches.iter().all(|branch| Self::has_attestation(branch))
            }
            BuilderOp::Op(_) => false,
        })
    }

    /// Recursively build a Step tree from builder operations
    fn build_step(ops: &[BuilderOp], input_digest: Vec<u8>) -> Result<Step, OtsError> {
        if ops.is_empty() {
            return Err(OtsError::NoAttestation);
        }

        match &ops[0] {
            BuilderOp::Op(op) => {
                // Execute operation to get output digest
                let output = op.execute(&input_digest);

                // Build next step recursively
                let next_step = Self::build_step(&ops[1..], output.clone())?;

                Ok(Step { data: StepData::Op(op.clone()), output, next: vec![next_step] })
            }

            BuilderOp::Attestation(att) => {
                // Terminal node
                Ok(Step {
                    data: StepData::Attestation(att.clone()),
                    output: input_digest,
                    next: vec![],
                })
            }

            BuilderOp::Fork(branches) => {
                // Validate: fork must have at least 2 branches
                if branches.len() < 2 {
                    return Err(OtsError::EmptyFork);
                }

                // Build each branch
                let next_steps = branches
                    .iter()
                    .map(|branch| Self::build_step(branch, input_digest.clone()))
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(Step { data: StepData::Fork, output: input_digest, next: next_steps })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_new() {
        let hash = [0xaa; 32];
        let builder = TimestampBuilder::new(hash);
        assert_eq!(builder.document_hash, hash.to_vec());
        assert_eq!(builder.digest_type, DigestType::Sha256);
    }

    #[test]
    fn test_simple_pending_timestamp() {
        let hash = [0xaa; 32];
        let ots_bytes = TimestampBuilder::new(hash)
            .prepend(&[0x01, 0x02, 0x03])
            .sha256()
            .add_pending_attestation("https://example.calendar.org")
            .build()
            .unwrap();

        // Verify output is valid OTS
        let parsed = DetachedTimestampFile::from_bytes(&ots_bytes);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_method_chaining() {
        let hash = [0xbb; 32];
        let ots_bytes = TimestampBuilder::new(hash)
            .append(&[0xff])
            .sha256()
            .prepend(&[0x00])
            .sha256()
            .add_pending_attestation("https://cal.example.org")
            .build()
            .unwrap();

        assert!(!ots_bytes.is_empty());
    }

    #[test]
    fn test_build_fails_without_attestation() {
        let hash = [0xcc; 32];
        let result = TimestampBuilder::new(hash).sha256().build();

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::NoAttestation));
    }

    #[test]
    fn test_fork_basic() {
        let hash = [0xdd; 32];
        let result = TimestampBuilder::new(hash)
            .sha256()
            .fork()
            .prepend(&[0x01])
            .sha256()
            .add_pending_attestation("https://alice.cal.org")
            .fork()
            .prepend(&[0x02])
            .sha256()
            .add_pending_attestation("https://bob.cal.org")
            .end_fork()
            .end_fork()
            .build();

        if let Err(e) = &result {
            eprintln!("Error: {e:?}");
        }
        let ots_bytes = result.unwrap();

        assert!(!ots_bytes.is_empty());
    }

    #[test]
    fn test_unclosed_fork_fails() {
        let hash = [0xee; 32];
        let result = TimestampBuilder::new(hash)
            .sha256()
            .fork()
            .add_pending_attestation("https://cal.org")
            .build();

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::UnclosedFork));
    }

    #[test]
    fn test_bitcoin_attestation() {
        let hash = [0x11; 32];
        let ots_bytes =
            TimestampBuilder::new(hash).sha256().add_bitcoin_attestation(500000).build().unwrap();

        assert!(!ots_bytes.is_empty());
    }

    #[test]
    fn test_roundtrip() {
        let hash = [0x22; 32];
        let ots_bytes = TimestampBuilder::new(hash)
            .prepend(&[0xde, 0xad])
            .sha256()
            .add_pending_attestation("https://alice.btc.calendar.opentimestamps.org")
            .build()
            .unwrap();

        // Parse back
        let parsed = DetachedTimestampFile::from_bytes(&ots_bytes).unwrap();

        // Serialize again
        let round_trip = parsed.to_bytes().unwrap();

        assert_eq!(ots_bytes, round_trip);
    }

    #[test]
    fn test_with_digest_type() {
        let hash = [0x33; 20];
        let builder = TimestampBuilder::with_digest_type(hash.to_vec(), DigestType::Sha1);
        assert_eq!(builder.digest_type, DigestType::Sha1);
    }

    #[test]
    fn test_all_operations() {
        let hash = [0x44; 32];
        let ots_bytes = TimestampBuilder::new(hash)
            .append(&[0x01])
            .prepend(&[0x02])
            .sha256()
            .sha1()
            .ripemd160()
            .reverse()
            .hexlify()
            .add_bitcoin_attestation(100000)
            .build()
            .unwrap();

        assert!(!ots_bytes.is_empty());
    }

    #[test]
    fn test_multiple_attestations_in_fork() {
        let hash = [0x55; 32];
        let ots_bytes = TimestampBuilder::new(hash)
            .sha256()
            .fork()
            .add_bitcoin_attestation(100000)
            .fork()
            .add_bitcoin_attestation(200000)
            .fork()
            .add_pending_attestation("https://calendar.example.org")
            .end_fork()
            .end_fork()
            .end_fork()
            .build()
            .unwrap();

        assert!(!ots_bytes.is_empty());
    }

    #[test]
    fn test_build_timestamp_struct() {
        let hash = [0x66; 32];
        let file = TimestampBuilder::new(hash)
            .sha256()
            .add_bitcoin_attestation(123456)
            .build_timestamp()
            .unwrap();

        assert_eq!(file.digest_type, DigestType::Sha256);
        assert_eq!(file.timestamp.start_digest, hash.to_vec());
    }

    #[test]
    fn test_empty_builder_fails() {
        let hash = [0x77; 32];
        let result = TimestampBuilder::new(hash).build();

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::NoAttestation));
    }

    #[test]
    fn test_complex_fork_tree() {
        let hash = [0x88; 32];
        // Create: SHA256 -> Fork(3 branches)
        //   Branch 1: Prepend(01) -> SHA256 -> Bitcoin(100000)
        //   Branch 2: Prepend(02) -> SHA256 -> Bitcoin(200000)
        //   Branch 3: Prepend(03) -> SHA256 -> Pending
        let ots_bytes = TimestampBuilder::new(hash)
            .sha256()
            .fork()
            .prepend(&[0x01])
            .sha256()
            .add_bitcoin_attestation(100000)
            .fork()
            .prepend(&[0x02])
            .sha256()
            .add_bitcoin_attestation(200000)
            .fork()
            .prepend(&[0x03])
            .sha256()
            .add_pending_attestation("https://calendar.example.org")
            .end_fork()
            .build()
            .unwrap();

        // Verify it parses
        let parsed = DetachedTimestampFile::from_bytes(&ots_bytes);
        assert!(parsed.is_ok());
    }
}
