//! Serialization and deserialization for `OpenTimestamps` binary format
//!
//! This module provides low-level primitives for reading and writing
//! OTS timestamp files according to the binary specification.

use std::fmt;
use std::io::{Read, Write};

use super::attestation::Attestation;
use super::error::OtsError;
use super::timestamp::{Step, StepData, Timestamp};
use super::{MAGIC, VERSION};

/// Cryptographic digest algorithms supported by `OpenTimestamps`
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DigestType {
    /// SHA-1 hash (20 bytes), tag 0x02
    Sha1,
    /// SHA-256 hash (32 bytes), tag 0x08
    Sha256,
    /// RIPEMD-160 hash (20 bytes), tag 0x03
    Ripemd160,
    /// Keccak-256 hash (32 bytes), tag 0x67
    Keccak256,
}

impl DigestType {
    /// Create a `DigestType` from a tag byte
    ///
    /// # Errors
    ///
    /// Returns `OtsError::InvalidDigestType` if the tag is not recognized
    pub const fn from_tag(tag: u8) -> Result<Self, OtsError> {
        match tag {
            0x02 => Ok(Self::Sha1),
            0x03 => Ok(Self::Ripemd160),
            0x08 => Ok(Self::Sha256),
            0x67 => Ok(Self::Keccak256),
            _ => Err(OtsError::InvalidDigestType(tag)),
        }
    }

    /// Convert the digest type to its tag byte
    #[must_use]
    pub const fn to_tag(self) -> u8 {
        match self {
            Self::Sha1 => 0x02,
            Self::Ripemd160 => 0x03,
            Self::Sha256 => 0x08,
            Self::Keccak256 => 0x67,
        }
    }

    /// Get the length in bytes of this digest type
    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha1 | Self::Ripemd160 => 20,
            Self::Sha256 | Self::Keccak256 => 32,
        }
    }
}

impl fmt::Display for DigestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha1 => f.write_str("SHA1"),
            Self::Sha256 => f.write_str("SHA256"),
            Self::Ripemd160 => f.write_str("RIPEMD160"),
            Self::Keccak256 => f.write_str("KECCAK256"),
        }
    }
}

/// Standard deserializer for OTS timestamp files
pub struct Deserializer<R: Read> {
    reader: R,
}

impl<R: Read> Deserializer<R> {
    /// Constructs a new deserializer from a reader
    #[must_use]
    pub const fn new(reader: R) -> Self {
        Self { reader }
    }

    /// Extracts the underlying reader from the deserializer
    #[must_use]
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Reads the magic bytes and checks that they match the expected value
    ///
    /// # Errors
    ///
    /// Returns `OtsError::InvalidMagic` if the magic bytes don't match
    pub fn read_magic(&mut self) -> Result<(), OtsError> {
        let recv_magic = self.read_fixed_bytes(MAGIC.len())?;
        if recv_magic == MAGIC {
            Ok(())
        } else {
            Err(OtsError::InvalidMagic(recv_magic))
        }
    }

    /// Reads the version and checks that it matches the expected value
    ///
    /// # Errors
    ///
    /// Returns `OtsError::UnsupportedVersion` if the version is not supported
    pub fn read_version(&mut self) -> Result<(), OtsError> {
        let recv_version = self.read_uint()?;
        if recv_version == VERSION {
            Ok(())
        } else {
            Err(OtsError::UnsupportedVersion(recv_version))
        }
    }

    /// Reads a single byte from the reader
    ///
    /// # Errors
    ///
    /// Returns an error if the read operation fails
    pub fn read_byte(&mut self) -> Result<u8, OtsError> {
        let mut byte = [0];
        self.reader.read_exact(&mut byte)?;
        Ok(byte[0])
    }

    /// Deserializes an unsigned integer using LEB128 variable-length encoding
    ///
    /// # Errors
    ///
    /// Returns an error if the read operation fails
    pub fn read_uint(&mut self) -> Result<usize, OtsError> {
        let mut ret = 0;
        let mut shift = 0;

        loop {
            let byte = self.read_byte()?;
            // Bottom 7 bits are value bits
            ret |= ((byte & 0x7f) as usize) << shift;
            // Top bit (MSB) is continuation flag: 0 = final byte, 1 = more bytes follow
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }

        Ok(ret)
    }

    /// Deserializes a fixed number of bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the read operation fails
    pub fn read_fixed_bytes(&mut self, n: usize) -> Result<Vec<u8>, OtsError> {
        let mut ret = vec![0; n];
        self.reader.read_exact(&mut ret)?;
        Ok(ret)
    }

    /// Deserializes a variable number of bytes with length prefix
    ///
    /// # Errors
    ///
    /// Returns `OtsError::InvalidLength` if the length is out of range
    pub fn read_bytes(&mut self, min: usize, max: usize) -> Result<Vec<u8>, OtsError> {
        let n = self.read_uint()?;
        if n < min || n > max {
            return Err(OtsError::InvalidLength { min, max, actual: n });
        }
        self.read_fixed_bytes(n)
    }

    /// Check that there is no trailing data after the timestamp
    ///
    /// # Errors
    ///
    /// Returns `OtsError::TrailingData` if there is data after the end
    pub fn check_eof(&mut self) -> Result<(), OtsError> {
        let mut buf = [0u8; 1];
        match self.reader.read(&mut buf) {
            Ok(0) => Ok(()),
            Ok(_) => Err(OtsError::TrailingData),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(()),
            Err(e) => Err(OtsError::IoError(e)),
        }
    }
}

/// Standard serializer for OTS timestamp files
pub struct Serializer<W: Write> {
    writer: W,
}

impl<W: Write> Serializer<W> {
    /// Constructs a new serializer from a writer
    #[must_use]
    pub const fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Extracts the underlying writer from the serializer
    #[must_use]
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Writes the magic bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails
    pub fn write_magic(&mut self) -> Result<(), OtsError> {
        self.write_fixed_bytes(MAGIC)
    }

    /// Writes the major version
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails
    pub fn write_version(&mut self) -> Result<(), OtsError> {
        self.write_uint(VERSION)
    }

    /// Writes a single byte to the writer
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails
    pub fn write_byte(&mut self, byte: u8) -> Result<(), OtsError> {
        self.writer.write_all(&[byte])?;
        Ok(())
    }

    /// Write an unsigned integer using LEB128 variable-length encoding
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails
    #[allow(clippy::cast_possible_truncation)]
    pub fn write_uint(&mut self, mut n: usize) -> Result<(), OtsError> {
        if n == 0 {
            self.write_byte(0x00)
        } else {
            while n > 0 {
                if n > 0x7f {
                    // More bytes to come: set MSB to 1
                    self.write_byte((n as u8) | 0x80)?;
                } else {
                    // Final byte: MSB is 0
                    self.write_byte(n as u8)?;
                }
                n >>= 7;
            }
            Ok(())
        }
    }

    /// Write a fixed number of bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails
    pub fn write_fixed_bytes(&mut self, data: &[u8]) -> Result<(), OtsError> {
        self.writer.write_all(data)?;
        Ok(())
    }

    /// Write a variable number of bytes with length prefix
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails
    pub fn write_bytes(&mut self, data: &[u8]) -> Result<(), OtsError> {
        self.write_uint(data.len())?;
        self.write_fixed_bytes(data)
    }
}

/// Complete detached timestamp file
///
/// A detached timestamp file contains:
/// - Magic bytes and version
/// - Digest algorithm type
/// - Complete timestamp proof tree
///
/// This is the top-level structure for `.ots` files.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DetachedTimestampFile {
    /// Digest algorithm used for the document hash
    pub digest_type: DigestType,

    /// Complete timestamp proof
    pub timestamp: Timestamp,
}

impl DetachedTimestampFile {
    /// Parses a detached timestamp file from bytes
    ///
    /// # Arguments
    ///
    /// * `bytes` - Complete `.ots` file contents
    ///
    /// # Returns
    ///
    /// Parsed timestamp file or error
    ///
    /// # Errors
    ///
    /// * [`OtsError::InvalidMagic`] - File doesn't start with OTS magic bytes
    /// * [`OtsError::UnsupportedVersion`] - Unsupported file version
    /// * [`OtsError::InvalidDigestType`] - Unrecognized digest algorithm
    /// * [`OtsError::TrailingData`] - Extra data after timestamp
    /// * [`OtsError::IoError`] - I/O error during parsing
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use atl_core::ots::DetachedTimestampFile;
    ///
    /// let ots_data = std::fs::read("document.ots")?;
    /// let file = DetachedTimestampFile::from_bytes(&ots_data)?;
    /// println!("Digest type: {}", file.digest_type);
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OtsError> {
        Self::from_reader(bytes)
    }

    /// Parses a detached timestamp file from a reader
    ///
    /// # Arguments
    ///
    /// * `reader` - Reader providing `.ots` file contents
    ///
    /// # Returns
    ///
    /// Parsed timestamp file or error
    ///
    /// # Errors
    ///
    /// * [`OtsError::InvalidMagic`] - File doesn't start with OTS magic bytes
    /// * [`OtsError::UnsupportedVersion`] - Unsupported file version
    /// * [`OtsError::InvalidDigestType`] - Unrecognized digest algorithm
    /// * [`OtsError::TrailingData`] - Extra data after timestamp
    /// * [`OtsError::IoError`] - I/O error during parsing
    pub fn from_reader<R: Read>(reader: R) -> Result<Self, OtsError> {
        let mut deser = Deserializer::new(reader);

        // Read and verify magic bytes
        deser.read_magic()?;

        // Read and verify version
        deser.read_version()?;

        // Read digest type
        let digest_type = DigestType::from_tag(deser.read_byte()?)?;

        // Read start digest
        let start_digest = deser.read_fixed_bytes(digest_type.digest_len())?;

        // Parse timestamp tree
        let timestamp = Timestamp::deserialize(&mut deser, start_digest)?;

        // Verify no trailing data
        deser.check_eof()?;

        Ok(Self { digest_type, timestamp })
    }

    /// Serializes this timestamp file to a writer
    ///
    /// # Arguments
    ///
    /// * `writer` - Writer to output `.ots` file contents
    ///
    /// # Returns
    ///
    /// Success or I/O error
    ///
    /// # Errors
    ///
    /// * [`OtsError::IoError`] - I/O error during serialization
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use atl_core::ots::DetachedTimestampFile;
    /// use std::fs::File;
    ///
    /// let file = /* ... */;
    /// let mut output = File::create("output.ots")?;
    /// file.to_writer(&mut output)?;
    /// ```
    pub fn to_writer<W: Write>(&self, writer: W) -> Result<(), OtsError> {
        let mut ser = Serializer::new(writer);

        // Write magic bytes
        ser.write_magic()?;

        // Write version
        ser.write_version()?;

        // Write digest type
        ser.write_byte(self.digest_type.to_tag())?;

        // Write start digest
        ser.write_fixed_bytes(&self.timestamp.start_digest)?;

        // Write timestamp tree
        self.timestamp.serialize(&mut ser)
    }

    /// Serializes this timestamp file to bytes
    ///
    /// # Returns
    ///
    /// Serialized `.ots` file contents or I/O error
    ///
    /// # Errors
    ///
    /// * [`OtsError::IoError`] - I/O error during serialization
    pub fn to_bytes(&self) -> Result<Vec<u8>, OtsError> {
        let mut buf = Vec::new();
        self.to_writer(&mut buf)?;
        Ok(buf)
    }

    /// Creates a `DetachedTimestampFile` from a SHA256 hash and calendar response
    ///
    /// This is the primary method for creating OTS timestamps from calendar
    /// server responses. Calendar servers accept document hashes and return
    /// raw operation chains (pending attestations).
    ///
    /// # Arguments
    ///
    /// * `hash` - 32-byte SHA256 hash of the document
    /// * `calendar_response` - Raw bytes from calendar server
    ///
    /// # Returns
    ///
    /// Complete timestamp file ready for serialization.
    ///
    /// # Errors
    ///
    /// * [`OtsError::InvalidOperation`] - Invalid operation in response
    /// * [`OtsError::RecursionLimitExceeded`] - Response too deeply nested
    /// * [`OtsError::IoError`] - I/O error during parsing
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use atl_core::ots::DetachedTimestampFile;
    ///
    /// let document_hash: [u8; 32] = sha256(document);
    /// let response = calendar_client.submit(&document_hash).await?;
    ///
    /// let ots_file = DetachedTimestampFile::from_calendar_response(
    ///     document_hash,
    ///     &response
    /// )?;
    ///
    /// // Serialize to .ots format
    /// let ots_bytes = ots_file.to_bytes()?;
    /// std::fs::write("document.ots", &ots_bytes)?;
    /// ```
    pub fn from_calendar_response(
        hash: [u8; 32],
        calendar_response: &[u8],
    ) -> Result<Self, OtsError> {
        Self::from_calendar_response_with_digest_type(
            hash.to_vec(),
            calendar_response,
            DigestType::Sha256,
        )
    }

    /// Creates a `DetachedTimestampFile` from hash, calendar response, and digest type
    ///
    /// Use this method when working with non-SHA256 hashes.
    ///
    /// # Arguments
    ///
    /// * `hash` - Document hash (length must match `digest_type`)
    /// * `calendar_response` - Raw bytes from calendar server
    /// * `digest_type` - Hash algorithm used for document
    ///
    /// # Returns
    ///
    /// Complete timestamp file ready for serialization.
    ///
    /// # Errors
    ///
    /// * [`OtsError::InvalidDigestLength`] - Hash length doesn't match digest type
    /// * [`OtsError::InvalidOperation`] - Invalid operation in response
    /// * [`OtsError::RecursionLimitExceeded`] - Response too deeply nested
    /// * [`OtsError::IoError`] - I/O error during parsing
    pub fn from_calendar_response_with_digest_type(
        hash: Vec<u8>,
        calendar_response: &[u8],
        digest_type: DigestType,
    ) -> Result<Self, OtsError> {
        // Validate hash length
        if hash.len() != digest_type.digest_len() {
            return Err(OtsError::InvalidDigestLength {
                expected: digest_type.digest_len(),
                actual: hash.len(),
            });
        }

        // Parse calendar response into timestamp
        let timestamp = Timestamp::from_calendar_response(hash, calendar_response)?;

        Ok(Self { digest_type, timestamp })
    }

    /// Upgrade a pending timestamp with calendar response
    ///
    /// Finds the first pending attestation in the timestamp tree, parses the
    /// calendar response as a new timestamp, and replaces the pending attestation
    /// with the completed proof chain.
    ///
    /// # Arguments
    ///
    /// * `original` - The original timestamp file with pending attestation
    /// * `calendar_response` - Raw bytes from calendar server upgrade endpoint
    ///
    /// # Returns
    ///
    /// New timestamp file with the pending attestation replaced by Bitcoin attestation.
    ///
    /// # Errors
    ///
    /// * [`OtsError::InvalidOperation`] - No pending attestation found or invalid response
    /// * [`OtsError::RecursionLimitExceeded`] - Response too deeply nested
    /// * [`OtsError::IoError`] - I/O error during parsing
    pub fn upgrade_from_calendar_response(
        original: &Self,
        calendar_response: &[u8],
    ) -> Result<Self, OtsError> {
        let mut upgraded = original.clone();

        // Find and upgrade pending attestation
        let found = Self::upgrade_step(&mut upgraded.timestamp.first_step, calendar_response)?;

        if !found {
            return Err(OtsError::NoPendingAttestation);
        }

        Ok(upgraded)
    }

    /// Recursively find and upgrade pending attestation in a step
    fn upgrade_step(step: &mut Step, calendar_response: &[u8]) -> Result<bool, OtsError> {
        match &step.data {
            StepData::Attestation(Attestation::Pending { .. }) => {
                // Found pending attestation - parse calendar response
                // The commitment is step.output - this is what calendar uses as start_digest
                let new_timestamp =
                    Timestamp::from_calendar_response(step.output.clone(), calendar_response)?;

                // Replace this step with the new timestamp chain
                step.data = new_timestamp.first_step.data.clone();
                step.next.clone_from(&new_timestamp.first_step.next);

                Ok(true)
            }
            StepData::Fork | StepData::Op(_) => {
                // Recurse into children
                for child in &mut step.next {
                    if Self::upgrade_step(child, calendar_response)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            // Already complete or unknown attestation
            StepData::Attestation(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leb128_round_trip() {
        let test_values = [0, 127, 128, 16384];

        for val in test_values {
            let mut buf = Vec::new();
            let mut ser = Serializer::new(&mut buf);
            ser.write_uint(val).unwrap();

            let mut deser = Deserializer::new(&buf[..]);
            let result = deser.read_uint().unwrap();
            assert_eq!(result, val, "Round-trip failed for value {val}");
        }
    }

    #[test]
    fn test_leb128_extended_values() {
        let test_values = [127, 128, 255, 256, 16383, 16384, 65535, 65536];

        for val in test_values {
            let mut buf = Vec::new();
            let mut ser = Serializer::new(&mut buf);
            ser.write_uint(val).unwrap();

            let mut deser = Deserializer::new(&buf[..]);
            let result = deser.read_uint().unwrap();
            assert_eq!(result, val, "Failed round-trip for value {val}");
        }
    }

    #[test]
    fn test_leb128_zero() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_uint(0).unwrap();
        assert_eq!(buf, vec![0x00]);

        let mut deser = Deserializer::new(&buf[..]);
        assert_eq!(deser.read_uint().unwrap(), 0);
    }

    #[test]
    fn test_magic_valid() {
        let mut deser = Deserializer::new(MAGIC);
        assert!(deser.read_magic().is_ok());
    }

    #[test]
    fn test_magic_invalid() {
        let bad_magic = b"\x00WrongMagic\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let mut deser = Deserializer::new(&bad_magic[..]);
        let result = deser.read_magic();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::InvalidMagic(_)));
    }

    #[test]
    fn test_version_valid() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_uint(VERSION).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        assert!(deser.read_version().is_ok());
    }

    #[test]
    fn test_version_invalid() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_uint(2).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let result = deser.read_version();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::UnsupportedVersion(2)));
    }

    #[test]
    fn test_read_bytes_in_range() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_uint(5).unwrap();
        ser.write_fixed_bytes(&[1, 2, 3, 4, 5]).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let result = deser.read_bytes(1, 10).unwrap();
        assert_eq!(result, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_read_bytes_below_min() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_uint(5).unwrap();
        ser.write_fixed_bytes(&[1, 2, 3, 4, 5]).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let result = deser.read_bytes(10, 20);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OtsError::InvalidLength { min: 10, max: 20, actual: 5 }
        ));
    }

    #[test]
    fn test_read_bytes_above_max() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_uint(50).unwrap();
        ser.write_fixed_bytes(&[0u8; 50]).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let result = deser.read_bytes(1, 10);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OtsError::InvalidLength { min: 1, max: 10, actual: 50 }
        ));
    }

    #[test]
    fn test_check_eof_empty() {
        let data = b"";
        let mut deser = Deserializer::new(&data[..]);
        let result = deser.check_eof();
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_eof_with_trailing_data() {
        let data = b"extra data";
        let mut deser = Deserializer::new(&data[..]);
        let result = deser.check_eof();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::TrailingData));
    }

    #[test]
    fn test_digest_type_from_tag_valid() {
        assert_eq!(DigestType::from_tag(0x02).unwrap(), DigestType::Sha1);
        assert_eq!(DigestType::from_tag(0x03).unwrap(), DigestType::Ripemd160);
        assert_eq!(DigestType::from_tag(0x08).unwrap(), DigestType::Sha256);
        assert_eq!(DigestType::from_tag(0x67).unwrap(), DigestType::Keccak256);
    }

    #[test]
    fn test_digest_type_from_tag_invalid() {
        assert!(DigestType::from_tag(0xFF).is_err());
        assert!(matches!(
            DigestType::from_tag(0xFF).unwrap_err(),
            OtsError::InvalidDigestType(0xFF)
        ));
    }

    #[test]
    fn test_digest_type_to_tag() {
        assert_eq!(DigestType::Sha1.to_tag(), 0x02);
        assert_eq!(DigestType::Ripemd160.to_tag(), 0x03);
        assert_eq!(DigestType::Sha256.to_tag(), 0x08);
        assert_eq!(DigestType::Keccak256.to_tag(), 0x67);
    }

    #[test]
    fn test_digest_type_round_trip() {
        for digest_type in
            [DigestType::Sha1, DigestType::Sha256, DigestType::Ripemd160, DigestType::Keccak256]
        {
            let tag = digest_type.to_tag();
            assert_eq!(DigestType::from_tag(tag).unwrap(), digest_type);
        }
    }

    #[test]
    fn test_digest_type_len() {
        assert_eq!(DigestType::Sha1.digest_len(), 20);
        assert_eq!(DigestType::Ripemd160.digest_len(), 20);
        assert_eq!(DigestType::Sha256.digest_len(), 32);
        assert_eq!(DigestType::Keccak256.digest_len(), 32);
    }

    #[test]
    fn test_digest_type_display() {
        assert_eq!(format!("{}", DigestType::Sha1), "SHA1");
        assert_eq!(format!("{}", DigestType::Sha256), "SHA256");
        assert_eq!(format!("{}", DigestType::Ripemd160), "RIPEMD160");
        assert_eq!(format!("{}", DigestType::Keccak256), "KECCAK256");
    }

    #[test]
    fn test_read_fixed_bytes_empty() {
        let data = b"";
        let mut deser = Deserializer::new(&data[..]);
        let result = deser.read_fixed_bytes(0).unwrap();
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_write_fixed_bytes_empty() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_fixed_bytes(&[]).unwrap();
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_deserializer_into_inner() {
        let data = b"test data";
        let deser = Deserializer::new(&data[..]);
        let _reader = deser.into_inner();
    }

    #[test]
    fn test_serializer_into_inner() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        ser.write_byte(0x42).unwrap();
        let writer = ser.into_inner();
        assert_eq!(*writer, vec![0x42]);
    }

    #[test]
    fn test_write_bytes_with_prefix() {
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        let data = vec![1, 2, 3, 4, 5];
        ser.write_bytes(&data).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let len = deser.read_uint().unwrap();
        assert_eq!(len, 5);
        let result = deser.read_fixed_bytes(len).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_detached_timestamp_file_round_trip() {
        use crate::core::ots::attestation::Attestation;
        use crate::core::ots::timestamp::{Step, StepData, Timestamp};

        // Create a simple timestamp file
        let start_digest = vec![0xaa; 32];

        let attestation_step = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height: 123_456 }),
            output: start_digest.clone(),
            next: vec![],
        };

        let timestamp = Timestamp { start_digest, first_step: attestation_step };

        let file = DetachedTimestampFile { digest_type: DigestType::Sha256, timestamp };

        // Serialize
        let bytes = file.to_bytes().unwrap();

        // Deserialize
        let result = DetachedTimestampFile::from_bytes(&bytes).unwrap();

        assert_eq!(result, file);
    }

    #[test]
    fn test_detached_timestamp_file_has_magic() {
        use crate::core::ots::attestation::Attestation;
        use crate::core::ots::timestamp::{Step, StepData, Timestamp};

        let start_digest = vec![0xbb; 32];

        let attestation_step = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height: 100 }),
            output: start_digest.clone(),
            next: vec![],
        };

        let timestamp = Timestamp { start_digest, first_step: attestation_step };

        let file = DetachedTimestampFile { digest_type: DigestType::Sha256, timestamp };

        let bytes = file.to_bytes().unwrap();

        // Check magic bytes
        assert!(bytes.starts_with(MAGIC));
    }

    #[test]
    fn test_parse_real_ots_small() {
        let ots_data = include_bytes!("../../../test_data/ots/small-test.ots");
        let result = DetachedTimestampFile::from_bytes(ots_data);

        // Should successfully parse
        assert!(result.is_ok(), "Failed to parse small-test.ots: {:?}", result.err());

        let file = result.unwrap();
        assert_eq!(file.digest_type, DigestType::Sha256);
    }

    #[test]
    fn test_parse_real_ots_large() {
        let ots_data = include_bytes!("../../../test_data/ots/large-test.ots");
        let result = DetachedTimestampFile::from_bytes(ots_data);

        // Should successfully parse
        assert!(result.is_ok(), "Failed to parse large-test.ots: {:?}", result.err());

        let file = result.unwrap();
        assert_eq!(file.digest_type, DigestType::Sha256);
    }

    #[test]
    fn test_full_file_round_trip_small() {
        let ots_data = include_bytes!("../../../test_data/ots/small-test.ots");
        let file = DetachedTimestampFile::from_bytes(ots_data).unwrap();

        // Serialize back
        let serialized = file.to_bytes().unwrap();

        // Should produce identical bytes
        assert_eq!(serialized, ots_data, "Round-trip produced different bytes");
    }

    #[test]
    fn test_full_file_round_trip_large() {
        let ots_data = include_bytes!("../../../test_data/ots/large-test.ots");
        let file = DetachedTimestampFile::from_bytes(ots_data).unwrap();

        // Serialize back
        let serialized = file.to_bytes().unwrap();

        // Should produce identical bytes
        assert_eq!(serialized, ots_data, "Round-trip produced different bytes");
    }

    #[test]
    fn test_detached_timestamp_file_invalid_magic() {
        // Create data with wrong magic bytes (must be at least 31 bytes long)
        let mut bad_data = vec![0u8; 31];
        bad_data[0..13].copy_from_slice(b"BadMagicBytes");

        let result = DetachedTimestampFile::from_bytes(&bad_data);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::InvalidMagic(_)));
    }

    #[test]
    fn test_detached_timestamp_file_to_writer() {
        use crate::core::ots::attestation::Attestation;
        use crate::core::ots::timestamp::{Step, StepData, Timestamp};

        let start_digest = vec![0xcc; 32];

        let attestation_step = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height: 200 }),
            output: start_digest.clone(),
            next: vec![],
        };

        let timestamp = Timestamp { start_digest, first_step: attestation_step };

        let file = DetachedTimestampFile { digest_type: DigestType::Sha256, timestamp };

        let mut buf = Vec::new();
        file.to_writer(&mut buf).unwrap();

        // Parse back
        let result = DetachedTimestampFile::from_bytes(&buf).unwrap();
        assert_eq!(result, file);
    }

    #[test]
    fn test_detached_timestamp_file_clone_and_eq() {
        use crate::core::ots::attestation::Attestation;
        use crate::core::ots::timestamp::{Step, StepData, Timestamp};

        let start_digest = vec![0xdd; 32];

        let attestation_step = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height: 300 }),
            output: start_digest.clone(),
            next: vec![],
        };

        let timestamp = Timestamp { start_digest, first_step: attestation_step };

        let file1 = DetachedTimestampFile { digest_type: DigestType::Sha256, timestamp };

        let file2 = file1.clone();
        assert_eq!(file1, file2);
    }

    #[test]
    fn test_from_calendar_response_basic() {
        use crate::core::ots::attestation::Attestation;

        // Create a minimal calendar response: Prepend operation + PendingAttestation
        // This matches the format returned by calendar servers
        let mut response = Vec::new();
        let mut ser = Serializer::new(&mut response);

        // Prepend operation with data
        ser.write_byte(0xf0).unwrap(); // Prepend tag
        ser.write_bytes(&[0xca, 0xfe]).unwrap(); // Prepend data

        // SHA256 operation (transforms the prepended data)
        ser.write_byte(0x08).unwrap();

        // Pending attestation (serialize writes 0x00 marker internally)
        let att = Attestation::Pending { uri: "https://test.calendar.org".to_string() };
        att.serialize(&mut ser).unwrap();

        let hash = [0xaa; 32];
        let result = DetachedTimestampFile::from_calendar_response(hash, &response);
        assert!(result.is_ok(), "Failed to parse calendar response: {:?}", result.err());

        let file = result.unwrap();
        assert_eq!(file.digest_type, DigestType::Sha256);
        assert_eq!(file.timestamp.start_digest, hash.to_vec());
    }

    #[test]
    fn test_from_calendar_response_round_trip() {
        use crate::core::ots::attestation::Attestation;

        // Create a minimal calendar response: Prepend + SHA256 + PendingAttestation
        let mut response = Vec::new();
        let mut ser = Serializer::new(&mut response);

        ser.write_byte(0xf0).unwrap(); // Prepend tag
        ser.write_bytes(&[0xde, 0xad, 0xbe, 0xef]).unwrap(); // Prepend data
        ser.write_byte(0x08).unwrap(); // SHA256
        let att = Attestation::Pending { uri: "https://test.calendar.org".to_string() };
        att.serialize(&mut ser).unwrap();

        let hash = [0xbb; 32];

        // Create from calendar response
        let file1 = DetachedTimestampFile::from_calendar_response(hash, &response).unwrap();

        // Serialize to .ots format
        let ots_bytes = file1.to_bytes().unwrap();

        // Should have magic header
        assert!(ots_bytes.starts_with(MAGIC));

        // Parse back from .ots format
        let file2 = DetachedTimestampFile::from_bytes(&ots_bytes).unwrap();

        assert_eq!(file1, file2);
    }

    #[test]
    fn test_from_calendar_response_invalid_hash_length() {
        use crate::core::ots::attestation::Attestation;

        let mut response = Vec::new();
        let mut ser = Serializer::new(&mut response);
        ser.write_byte(0xf0).unwrap(); // Prepend tag
        ser.write_bytes(&[0xaa, 0xbb]).unwrap(); // Prepend data
        ser.write_byte(0x08).unwrap(); // SHA256
        let att = Attestation::Pending { uri: "https://test.calendar.org".to_string() };
        att.serialize(&mut ser).unwrap();

        let short_hash = vec![0xaa; 16]; // Wrong length for SHA256

        let result = DetachedTimestampFile::from_calendar_response_with_digest_type(
            short_hash,
            &response,
            DigestType::Sha256,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OtsError::InvalidDigestLength { expected: 32, actual: 16 }
        ));
    }

    #[test]
    fn test_from_calendar_response_sha1() {
        use crate::core::ots::attestation::Attestation;

        let mut response = Vec::new();
        let mut ser = Serializer::new(&mut response);
        ser.write_byte(0xf0).unwrap(); // Prepend tag
        ser.write_bytes(&[0xcc, 0xdd]).unwrap(); // Prepend data
        ser.write_byte(0x08).unwrap(); // SHA256
        let att = Attestation::Pending { uri: "https://test.calendar.org".to_string() };
        att.serialize(&mut ser).unwrap();

        let hash = vec![0xdd; 20]; // SHA1 length

        let result = DetachedTimestampFile::from_calendar_response_with_digest_type(
            hash.clone(),
            &response,
            DigestType::Sha1,
        );

        assert!(result.is_ok());
        let file = result.unwrap();
        assert_eq!(file.digest_type, DigestType::Sha1);
        assert_eq!(file.timestamp.start_digest, hash);
    }

    #[test]
    fn test_from_calendar_response_empty_response() {
        let hash = [0xee; 32];
        let result = DetachedTimestampFile::from_calendar_response(hash, &[]);
        assert!(result.is_err());
    }
}
