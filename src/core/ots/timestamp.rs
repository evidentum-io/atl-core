//! Timestamp data structures for `OpenTimestamps` proofs
//!
//! This module defines the core timestamp tree structure that represents
//! the proof chain from document digest to attestations.

use std::io::{Read, Write};

use super::attestation::Attestation;
use super::error::{OtsError, RECURSION_LIMIT};
use super::op::Op;
use super::ser::{Deserializer, Serializer};

/// Data contained in a timestamp step
///
/// Each step in a timestamp proof chain can be one of three types:
/// - Fork: the proof splits into multiple parallel branches
/// - Op: a cryptographic operation is applied
/// - Attestation: proof is anchored to a verifiable source
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum StepData {
    /// Fork point where proof splits into multiple branches
    Fork,

    /// Cryptographic operation (hash, append, etc.)
    Op(Op),

    /// Final attestation (leaf node)
    Attestation(Attestation),
}

/// Single step in a timestamp proof chain
///
/// A step represents one node in the proof tree. It contains:
/// - The operation or attestation at this node
/// - The output digest after applying this step
/// - Zero or more child steps (next nodes in the proof)
///
/// # Structure Constraints
///
/// - Fork steps have N≥2 children (all branches)
/// - Op steps have exactly 1 child (next operation)
/// - Attestation steps have 0 children (leaf nodes)
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Step {
    /// The data at this step (Fork, Op, or Attestation)
    pub data: StepData,

    /// Digest value after applying this step
    pub output: Vec<u8>,

    /// Child steps (empty for Attestation, 1 for Op, N≥2 for Fork)
    pub next: Vec<Self>,
}

impl Step {
    /// Serializes this step to binary format
    ///
    /// # Arguments
    ///
    /// * `ser` - Serializer to write to
    ///
    /// # Returns
    ///
    /// Success or I/O error
    ///
    /// # Errors
    ///
    /// * [`OtsError::IoError`] - I/O error during serialization
    pub fn serialize<W: Write>(&self, ser: &mut Serializer<W>) -> Result<(), OtsError> {
        match &self.data {
            StepData::Fork => {
                // Write 0xff before each branch EXCEPT the last
                for (i, branch) in self.next.iter().enumerate() {
                    if i < self.next.len() - 1 {
                        ser.write_byte(0xff)?;
                    }
                    branch.serialize(ser)?;
                }
                Ok(())
            }

            StepData::Op(op) => {
                // Write operation
                op.serialize(ser)?;

                // Write next step (operations always have exactly one child)
                self.next[0].serialize(ser)
            }

            StepData::Attestation(att) => {
                // Write attestation (terminal node, no children)
                att.serialize(ser)
            }
        }
    }
}

/// Complete `OpenTimestamps` proof
///
/// A timestamp consists of a starting digest (the hash of the document
/// being timestamped) and a tree of operations leading to attestations.
///
/// The proof is verified by:
/// 1. Starting with `start_digest`
/// 2. Following the tree of operations
/// 3. Checking that attestations match expected values
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Timestamp {
    /// Starting digest (hash of the timestamped document)
    pub start_digest: Vec<u8>,

    /// Root of the proof tree
    pub first_step: Step,
}

impl Timestamp {
    /// Deserializes a timestamp from binary format
    ///
    /// # Arguments
    ///
    /// * `deser` - Deserializer to read from
    /// * `start_digest` - Initial digest value (document hash)
    ///
    /// # Returns
    ///
    /// Deserialized timestamp or error
    ///
    /// # Errors
    ///
    /// * [`OtsError::RecursionLimitExceeded`] - Proof tree exceeds maximum depth
    /// * [`OtsError::InvalidOperation`] - Unrecognized operation tag
    /// * [`OtsError::IoError`] - I/O error during deserialization
    pub fn deserialize<R: Read>(
        deser: &mut Deserializer<R>,
        start_digest: Vec<u8>,
    ) -> Result<Self, OtsError> {
        let first_step = deserialize_step(deser, start_digest.clone(), None, 0)?;
        Ok(Self { start_digest, first_step })
    }

    /// Deserialize a timestamp from raw calendar response bytes
    ///
    /// Calendar servers return raw operations without the OTS file header.
    /// This method parses those operations into a Timestamp structure.
    ///
    /// # Arguments
    ///
    /// * `start_digest` - The original document hash submitted to calendar
    /// * `response` - Raw calendar response bytes (operations only)
    ///
    /// # Returns
    ///
    /// Parsed `Timestamp` structure containing the proof chain from the
    /// start digest to one or more attestations.
    ///
    /// # Errors
    ///
    /// * [`OtsError::InvalidOperation`] - Unrecognized operation tag
    /// * [`OtsError::RecursionLimitExceeded`] - Proof tree too deep
    /// * [`OtsError::IoError`] - I/O error during parsing
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use atl_core::ots::Timestamp;
    ///
    /// let hash = [0xaa; 32];
    /// let calendar_response = /* bytes from calendar server */;
    /// let timestamp = Timestamp::from_calendar_response(
    ///     hash.to_vec(),
    ///     &calendar_response
    /// )?;
    /// ```
    pub fn from_calendar_response(
        start_digest: Vec<u8>,
        response: &[u8],
    ) -> Result<Self, OtsError> {
        let mut deser = Deserializer::new(response);
        Self::deserialize(&mut deser, start_digest)
    }

    /// Serializes this timestamp to binary format
    ///
    /// # Arguments
    ///
    /// * `ser` - Serializer to write to
    ///
    /// # Returns
    ///
    /// Success or I/O error
    ///
    /// # Errors
    ///
    /// * [`OtsError::IoError`] - I/O error during serialization
    pub fn serialize<W: Write>(&self, ser: &mut Serializer<W>) -> Result<(), OtsError> {
        self.first_step.serialize(ser)
    }
}

/// Recursively deserializes a single step and its children
///
/// # Arguments
///
/// * `deser` - Deserializer to read from
/// * `input_digest` - Digest value at the start of this step
/// * `tag` - Optional tag byte already read (for fork branches)
/// * `depth` - Current recursion depth (for limit enforcement)
///
/// # Returns
///
/// Deserialized step or error
///
/// # Errors
///
/// * [`OtsError::RecursionLimitExceeded`] - Exceeded maximum proof depth
/// * [`OtsError::InvalidOperation`] - Unrecognized operation tag
/// * [`OtsError::IoError`] - I/O error during deserialization
fn deserialize_step<R: Read>(
    deser: &mut Deserializer<R>,
    input_digest: Vec<u8>,
    tag: Option<u8>,
    depth: usize,
) -> Result<Step, OtsError> {
    // Enforce recursion limit to prevent stack overflow
    if depth >= RECURSION_LIMIT {
        return Err(OtsError::RecursionLimitExceeded);
    }

    // Read tag byte if not already provided
    let tag = match tag {
        Some(t) => t,
        None => deser.read_byte()?,
    };

    match tag {
        0x00 => {
            // Attestation (leaf node)
            let att = Attestation::deserialize(deser)?;
            Ok(Step { data: StepData::Attestation(att), output: input_digest, next: vec![] })
        }

        0xff => {
            // Fork - collect all branches
            let mut branches = Vec::new();

            // First branch (no 0xff prefix)
            branches.push(deserialize_step(deser, input_digest.clone(), None, depth + 1)?);

            // Continue reading while we see 0xff markers
            loop {
                let next_tag = deser.read_byte()?;
                if next_tag == 0xff {
                    // Another fork branch follows
                    branches.push(deserialize_step(deser, input_digest.clone(), None, depth + 1)?);
                } else {
                    // Last branch (no 0xff prefix)
                    branches.push(deserialize_step(
                        deser,
                        input_digest.clone(),
                        Some(next_tag),
                        depth + 1,
                    )?);
                    break;
                }
            }

            Ok(Step { data: StepData::Fork, output: input_digest, next: branches })
        }

        _ => {
            // Operation
            let op = Op::deserialize_with_tag(deser, tag)?;
            let output_digest = op.execute(&input_digest);
            let next_step = deserialize_step(deser, output_digest.clone(), None, depth + 1)?;

            Ok(Step { data: StepData::Op(op), output: output_digest, next: vec![next_step] })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bitcoin_attestation(height: u64) -> Step {
        Step {
            data: StepData::Attestation(Attestation::Bitcoin { height }),
            output: vec![0xaa; 32],
            next: vec![],
        }
    }

    #[test]
    fn test_attestation_step_serialize() {
        let step = make_bitcoin_attestation(123456);

        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        step.serialize(&mut ser).unwrap();

        // Should start with 0x00 (attestation marker)
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn test_op_step_serialize() {
        let child = make_bitcoin_attestation(100);
        let step =
            Step { data: StepData::Op(Op::Sha256), output: vec![0xbb; 32], next: vec![child] };

        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        step.serialize(&mut ser).unwrap();

        // Should start with SHA256 tag (0x08)
        assert_eq!(buf[0], 0x08);
    }

    #[test]
    fn test_fork_step_serialize() {
        let branch1 = make_bitcoin_attestation(100);
        let branch2 = make_bitcoin_attestation(200);
        let step =
            Step { data: StepData::Fork, output: vec![0xcc; 32], next: vec![branch1, branch2] };

        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        step.serialize(&mut ser).unwrap();

        // First branch should have 0xff prefix
        assert_eq!(buf[0], 0xff);
        // First branch attestation marker
        assert!(buf.contains(&0x00));
    }

    #[test]
    fn test_timestamp_round_trip_simple() {
        // Create simple timestamp: digest -> SHA256 -> attestation
        let start_digest = vec![0x01; 32];
        let sha256_output = Op::Sha256.execute(&start_digest);

        let attestation_step = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height: 123456 }),
            output: sha256_output.clone(),
            next: vec![],
        };

        let op_step = Step {
            data: StepData::Op(Op::Sha256),
            output: sha256_output,
            next: vec![attestation_step],
        };

        let timestamp = Timestamp { start_digest: start_digest.clone(), first_step: op_step };

        // Serialize
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        timestamp.serialize(&mut ser).unwrap();

        // Deserialize
        let mut deser = Deserializer::new(&buf[..]);
        let result = Timestamp::deserialize(&mut deser, start_digest).unwrap();

        assert_eq!(result, timestamp);
    }

    #[test]
    fn test_timestamp_round_trip_with_fork() {
        // Create timestamp with fork: digest -> fork -> [att1, att2]
        let start_digest = vec![0x02; 32];

        let att1 = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height: 100 }),
            output: start_digest.clone(),
            next: vec![],
        };

        let att2 = Step {
            data: StepData::Attestation(Attestation::Pending {
                uri: "https://calendar.example.com".to_string(),
            }),
            output: start_digest.clone(),
            next: vec![],
        };

        let fork_step =
            Step { data: StepData::Fork, output: start_digest.clone(), next: vec![att1, att2] };

        let timestamp = Timestamp { start_digest: start_digest.clone(), first_step: fork_step };

        // Serialize
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        timestamp.serialize(&mut ser).unwrap();

        // Deserialize
        let mut deser = Deserializer::new(&buf[..]);
        let result = Timestamp::deserialize(&mut deser, start_digest).unwrap();

        assert_eq!(result, timestamp);
    }

    #[test]
    fn test_recursion_limit_exceeded() {
        // Build a very deep chain exceeding recursion limit
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);

        // Write RECURSION_LIMIT + 5 SHA256 operations
        for _ in 0..(RECURSION_LIMIT + 5) {
            ser.write_byte(0x08).unwrap(); // SHA256 tag
        }

        // Write final attestation
        let att = Attestation::Bitcoin { height: 100 };
        att.serialize(&mut ser).unwrap();

        // Try to deserialize - should hit recursion limit
        let start_digest = vec![0x03; 32];
        let mut deser = Deserializer::new(&buf[..]);
        let result = Timestamp::deserialize(&mut deser, start_digest);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::RecursionLimitExceeded));
    }

    #[test]
    fn test_fork_with_three_branches() {
        let start_digest = vec![0x04; 32];

        let att1 = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height: 100 }),
            output: start_digest.clone(),
            next: vec![],
        };

        let att2 = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height: 200 }),
            output: start_digest.clone(),
            next: vec![],
        };

        let att3 = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height: 300 }),
            output: start_digest.clone(),
            next: vec![],
        };

        let fork_step = Step {
            data: StepData::Fork,
            output: start_digest.clone(),
            next: vec![att1, att2, att3],
        };

        let timestamp = Timestamp { start_digest: start_digest.clone(), first_step: fork_step };

        // Serialize
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        timestamp.serialize(&mut ser).unwrap();

        // Check format: 0xff att1 0xff att2 att3 (no 0xff before last)
        assert_eq!(buf[0], 0xff);

        // Deserialize
        let mut deser = Deserializer::new(&buf[..]);
        let result = Timestamp::deserialize(&mut deser, start_digest).unwrap();

        assert_eq!(result, timestamp);
    }

    #[test]
    fn test_nested_forks() {
        // Create timestamp with nested forks
        let start_digest = vec![0x05; 32];

        let att1 = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height: 100 }),
            output: start_digest.clone(),
            next: vec![],
        };

        let att2 = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height: 200 }),
            output: start_digest.clone(),
            next: vec![],
        };

        let inner_fork =
            Step { data: StepData::Fork, output: start_digest.clone(), next: vec![att1, att2] };

        let att3 = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height: 300 }),
            output: start_digest.clone(),
            next: vec![],
        };

        let outer_fork = Step {
            data: StepData::Fork,
            output: start_digest.clone(),
            next: vec![inner_fork, att3],
        };

        let timestamp = Timestamp { start_digest: start_digest.clone(), first_step: outer_fork };

        // Serialize and deserialize
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        timestamp.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let result = Timestamp::deserialize(&mut deser, start_digest).unwrap();

        assert_eq!(result, timestamp);
    }

    #[test]
    fn test_step_clone_and_eq() {
        let step1 = make_bitcoin_attestation(100);
        let step2 = step1.clone();
        assert_eq!(step1, step2);

        let step3 = make_bitcoin_attestation(200);
        assert_ne!(step1, step3);
    }

    #[test]
    fn test_step_data_variants() {
        let fork = StepData::Fork;
        assert!(matches!(fork, StepData::Fork));

        let op = StepData::Op(Op::Sha256);
        assert!(matches!(op, StepData::Op(_)));

        let att = StepData::Attestation(Attestation::Bitcoin { height: 100 });
        assert!(matches!(att, StepData::Attestation(_)));
    }

    #[test]
    fn test_timestamp_debug() {
        let start_digest = vec![0x01; 32];
        let step = make_bitcoin_attestation(100);
        let timestamp = Timestamp { start_digest, first_step: step };

        let debug_str = format!("{timestamp:?}");
        assert!(debug_str.contains("Timestamp"));
    }

    #[test]
    fn test_complex_chain() {
        // Build a complex chain: digest -> append -> sha256 -> fork -> [att1, att2]
        let start_digest = vec![0x06; 32];

        let after_append = Op::Append(vec![0xff]).execute(&start_digest);
        let after_sha256 = Op::Sha256.execute(&after_append);

        let att1 = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height: 100 }),
            output: after_sha256.clone(),
            next: vec![],
        };

        let att2 = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height: 200 }),
            output: after_sha256.clone(),
            next: vec![],
        };

        let fork =
            Step { data: StepData::Fork, output: after_sha256.clone(), next: vec![att1, att2] };

        let sha256_step =
            Step { data: StepData::Op(Op::Sha256), output: after_sha256, next: vec![fork] };

        let append_step = Step {
            data: StepData::Op(Op::Append(vec![0xff])),
            output: after_append,
            next: vec![sha256_step],
        };

        let timestamp = Timestamp { start_digest: start_digest.clone(), first_step: append_step };

        // Round-trip
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        timestamp.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let result = Timestamp::deserialize(&mut deser, start_digest).unwrap();

        assert_eq!(result, timestamp);
    }

    #[test]
    fn test_from_calendar_response_simple() {
        // Build a simple calendar response: Prepend -> SHA256 -> PendingAttestation
        let hash = [0xaa; 32];

        // Build response manually using Serializer
        let mut response_buf = Vec::new();
        let mut ser = Serializer::new(&mut response_buf);

        // Write Prepend operation with data
        ser.write_byte(0xf1).unwrap(); // Prepend tag
        ser.write_bytes(&[0xde, 0xad, 0xbe, 0xef]).unwrap(); // Prepend data

        // Write SHA256 operation
        ser.write_byte(0x08).unwrap(); // SHA256 tag

        // Write PendingAttestation
        let att = Attestation::Pending { uri: "https://calendar.example.com".to_string() };
        att.serialize(&mut ser).unwrap();

        // Parse response
        let result = Timestamp::from_calendar_response(hash.to_vec(), &response_buf);
        assert!(result.is_ok(), "Failed to parse calendar response: {:?}", result.err());

        let timestamp = result.unwrap();
        assert_eq!(timestamp.start_digest, hash);

        // Verify structure: first step should be Prepend
        if let StepData::Op(Op::Prepend(data)) = &timestamp.first_step.data {
            assert_eq!(data, &[0xde, 0xad, 0xbe, 0xef]);
        } else {
            panic!("Expected Prepend operation, got {:?}", timestamp.first_step.data);
        }
    }

    #[test]
    fn test_from_calendar_response_empty() {
        let hash = [0xaa; 32];
        let result = Timestamp::from_calendar_response(hash.to_vec(), &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_calendar_response_invalid_tag() {
        let hash = [0xaa; 32];
        let response = [0xfe]; // Invalid tag
        let result = Timestamp::from_calendar_response(hash.to_vec(), &response);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::InvalidOperation(0xfe)));
    }
}
