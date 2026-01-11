//! Cryptographic operations for `OpenTimestamps` proofs
//!
//! This module defines the [`Op`] enum representing the cryptographic
//! operations that can be performed in an OTS proof chain.

use std::io::{Read, Write};

use super::error::{OtsError, MAX_OP_LENGTH};
use super::ser::{Deserializer, Serializer};

/// Cryptographic operation in an OTS proof chain
///
/// Operations are applied sequentially to transform message digests
/// during proof verification. Each operation has a tag byte used
/// for binary serialization.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Op {
    /// SHA-1 hash operation (tag: 0x02)
    Sha1,

    /// SHA-256 hash operation (tag: 0x08)
    Sha256,

    /// RIPEMD-160 hash operation (tag: 0x03)
    Ripemd160,

    /// Append data to the end of message (tag: 0xf0)
    Append(Vec<u8>),

    /// Prepend data to the beginning of message (tag: 0xf1)
    Prepend(Vec<u8>),

    /// Reverse byte order (tag: 0xf2)
    Reverse,

    /// Convert to lowercase hexadecimal string (tag: 0xf3)
    Hexlify,
}

impl Op {
    /// Returns the tag byte for this operation
    ///
    /// Tag bytes are used in the binary serialization format
    /// to identify operation types.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Sha1 => 0x02,
            Self::Sha256 => 0x08,
            Self::Ripemd160 => 0x03,
            Self::Append(_) => 0xf0,
            Self::Prepend(_) => 0xf1,
            Self::Reverse => 0xf2,
            Self::Hexlify => 0xf3,
        }
    }

    /// Executes the operation on input data
    ///
    /// # Arguments
    ///
    /// * `input` - Input bytes to transform
    ///
    /// # Returns
    ///
    /// Transformed output bytes
    ///
    /// # Examples
    ///
    /// ```
    /// use atl_core::ots::Op;
    ///
    /// let op = Op::Sha256;
    /// let result = op.execute(b"hello");
    /// assert_eq!(result.len(), 32); // SHA-256 produces 32 bytes
    ///
    /// let op = Op::Append(vec![0x01, 0x02]);
    /// let result = op.execute(b"hello");
    /// assert_eq!(result, b"hello\x01\x02");
    /// ```
    #[must_use]
    pub fn execute(&self, input: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => {
                use bitcoin_hashes::{sha1, Hash};
                sha1::Hash::hash(input).to_byte_array().to_vec()
            }
            Self::Sha256 => {
                use bitcoin_hashes::{sha256, Hash};
                sha256::Hash::hash(input).to_byte_array().to_vec()
            }
            Self::Ripemd160 => {
                use bitcoin_hashes::{ripemd160, Hash};
                ripemd160::Hash::hash(input).to_byte_array().to_vec()
            }
            Self::Append(data) => {
                let mut result = input.to_vec();
                result.extend_from_slice(data);
                result
            }
            Self::Prepend(data) => {
                let mut result = data.clone();
                result.extend_from_slice(input);
                result
            }
            Self::Reverse => {
                let mut result = input.to_vec();
                result.reverse();
                result
            }
            Self::Hexlify => hex::encode(input).into_bytes(),
        }
    }

    /// Deserializes an operation from binary format given a tag byte
    ///
    /// # Arguments
    ///
    /// * `deser` - Deserializer to read from
    /// * `tag` - Operation tag byte (already read from stream)
    ///
    /// # Returns
    ///
    /// Deserialized operation or error
    ///
    /// # Errors
    ///
    /// Returns [`OtsError::InvalidOperation`] if the tag is not recognized.
    /// Returns [`OtsError::InvalidLength`] if binary operation data is invalid.
    /// Returns [`OtsError::IoError`] on I/O errors.
    pub fn deserialize_with_tag<R: Read>(
        deser: &mut Deserializer<R>,
        tag: u8,
    ) -> Result<Self, OtsError> {
        match tag {
            0x02 => Ok(Self::Sha1),
            0x08 => Ok(Self::Sha256),
            0x03 => Ok(Self::Ripemd160),
            0xf0 => {
                let data = deser.read_bytes(1, MAX_OP_LENGTH)?;
                Ok(Self::Append(data))
            }
            0xf1 => {
                let data = deser.read_bytes(1, MAX_OP_LENGTH)?;
                Ok(Self::Prepend(data))
            }
            0xf2 => Ok(Self::Reverse),
            0xf3 => Ok(Self::Hexlify),
            _ => Err(OtsError::InvalidOperation(tag)),
        }
    }

    /// Serializes this operation to binary format
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
    /// Returns [`OtsError::IoError`] on I/O errors during serialization.
    pub fn serialize<W: Write>(&self, ser: &mut Serializer<W>) -> Result<(), OtsError> {
        ser.write_byte(self.tag())?;

        match self {
            Self::Append(data) | Self::Prepend(data) => {
                ser.write_bytes(data)?;
            }
            // Unary operations have no additional data
            Self::Sha1 | Self::Sha256 | Self::Ripemd160 | Self::Reverse | Self::Hexlify => {}
        }

        Ok(())
    }
}

impl std::fmt::Display for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha1 => write!(f, "SHA1()"),
            Self::Sha256 => write!(f, "SHA256()"),
            Self::Ripemd160 => write!(f, "RIPEMD160()"),
            Self::Append(data) => write!(f, "Append({})", hex::encode(data)),
            Self::Prepend(data) => write!(f, "Prepend({})", hex::encode(data)),
            Self::Reverse => write!(f, "Reverse()"),
            Self::Hexlify => write!(f, "Hexlify()"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_values() {
        assert_eq!(Op::Sha1.tag(), 0x02);
        assert_eq!(Op::Sha256.tag(), 0x08);
        assert_eq!(Op::Ripemd160.tag(), 0x03);
        assert_eq!(Op::Append(vec![]).tag(), 0xf0);
        assert_eq!(Op::Prepend(vec![]).tag(), 0xf1);
        assert_eq!(Op::Reverse.tag(), 0xf2);
        assert_eq!(Op::Hexlify.tag(), 0xf3);
    }

    #[test]
    fn test_execute_sha256() {
        let op = Op::Sha256;
        let result = op.execute(b"hello");
        let expected =
            hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
                .expect("valid hex");
        assert_eq!(result, expected);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_execute_sha1() {
        let op = Op::Sha1;
        let result = op.execute(b"hello");
        let expected = hex::decode("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d").expect("valid hex");
        assert_eq!(result, expected);
        assert_eq!(result.len(), 20);
    }

    #[test]
    fn test_execute_ripemd160() {
        let op = Op::Ripemd160;
        let result = op.execute(b"hello");
        let expected = hex::decode("108f07b8382412612c048d07d13f814118445acd").expect("valid hex");
        assert_eq!(result, expected);
        assert_eq!(result.len(), 20);
    }

    #[test]
    fn test_execute_append() {
        let op = Op::Append(vec![0x01, 0x02]);
        let result = op.execute(b"hello");
        assert_eq!(result, b"hello\x01\x02");
    }

    #[test]
    fn test_execute_prepend() {
        let op = Op::Prepend(vec![0x01, 0x02]);
        let result = op.execute(b"hello");
        assert_eq!(result, b"\x01\x02hello");
    }

    #[test]
    fn test_execute_reverse() {
        let op = Op::Reverse;
        let result = op.execute(b"hello");
        assert_eq!(result, b"olleh");
    }

    #[test]
    fn test_execute_hexlify() {
        let op = Op::Hexlify;
        let result = op.execute(&[0x01, 0x02, 0xff]);
        assert_eq!(result, b"0102ff");
    }

    #[test]
    fn test_display_unary_ops() {
        assert_eq!(Op::Sha1.to_string(), "SHA1()");
        assert_eq!(Op::Sha256.to_string(), "SHA256()");
        assert_eq!(Op::Ripemd160.to_string(), "RIPEMD160()");
        assert_eq!(Op::Reverse.to_string(), "Reverse()");
        assert_eq!(Op::Hexlify.to_string(), "Hexlify()");
    }

    #[test]
    fn test_display_binary_ops() {
        let op = Op::Append(vec![0xaa, 0xbb]);
        assert_eq!(op.to_string(), "Append(aabb)");

        let op = Op::Prepend(vec![0xcc, 0xdd]);
        assert_eq!(op.to_string(), "Prepend(ccdd)");
    }

    #[test]
    fn test_clone_and_eq() {
        let op1 = Op::Append(vec![0x01, 0x02]);
        let op2 = op1.clone();
        assert_eq!(op1, op2);

        let op3 = Op::Append(vec![0x03, 0x04]);
        assert_ne!(op1, op3);
    }

    #[test]
    fn test_debug() {
        let op = Op::Sha256;
        let debug_str = format!("{op:?}");
        assert!(debug_str.contains("Sha256"));
    }
}
