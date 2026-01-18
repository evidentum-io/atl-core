//! Attestation types for `OpenTimestamps` proofs
//!
//! Attestations are proof anchors that bind a timestamp to a verifiable
//! source of truth (e.g., Bitcoin blockchain or pending calendar server).

use std::io::{Read, Write};

use super::error::{OtsError, MAX_URI_LEN};
use super::ser::{Deserializer, Serializer};

/// Size of attestation type tag in bytes
pub const TAG_SIZE: usize = 8;

/// Bitcoin attestation tag (big-endian encoding of `0x05889_60d7_3d71901`)
pub const BITCOIN_TAG: &[u8; 8] = b"\x05\x88\x96\x0d\x73\xd7\x19\x01";

/// Pending attestation tag (big-endian encoding of `0x83dfe_30d2_ef90c8e`)
pub const PENDING_TAG: &[u8; 8] = b"\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e";

/// Proof attestation binding a timestamp to a verifiable source
///
/// Attestations are the leaves of the timestamp tree. They provide
/// cryptographic proof that a document existed at a specific time.
///
/// # Variants
///
/// * `Bitcoin` - Proof anchored in Bitcoin blockchain at a specific block height
/// * `Pending` - Proof submitted to a calendar server but not yet confirmed
/// * `Unknown` - Unrecognized attestation type (for forward compatibility)
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Attestation {
    /// Bitcoin blockchain attestation
    Bitcoin {
        /// Block height where the timestamp is anchored
        height: u64,
    },

    /// Pending calendar server attestation
    Pending {
        /// URI of the calendar server
        uri: String,
    },

    /// Unknown attestation type (forward compatibility)
    Unknown {
        /// Attestation type tag
        tag: [u8; 8],
        /// Attestation payload data
        data: Vec<u8>,
    },
}

impl Attestation {
    /// Deserializes an attestation from binary format
    ///
    /// # Arguments
    ///
    /// * `deser` - Deserializer to read from (assumes 0x00 marker already consumed)
    ///
    /// # Returns
    ///
    /// Deserialized attestation or error
    ///
    /// # Errors
    ///
    /// * [`OtsError::InvalidUriChar`] - Invalid character in pending URI
    /// * [`OtsError::InvalidLength`] - URI length exceeds maximum
    /// * [`OtsError::IoError`] - I/O error during deserialization
    pub fn deserialize<R: Read>(deser: &mut Deserializer<R>) -> Result<Self, OtsError> {
        // Read 8-byte attestation type tag
        let mut tag = [0u8; TAG_SIZE];
        for byte in &mut tag {
            *byte = deser.read_byte()?;
        }

        // Read payload length
        let payload_len = deser.read_uint()?;

        match &tag {
            BITCOIN_TAG => {
                // Bitcoin attestation: payload is LEB128-encoded block height
                let mut height_bytes = Vec::with_capacity(payload_len);
                for _ in 0..payload_len {
                    height_bytes.push(deser.read_byte()?);
                }

                // Decode block height from LEB128
                let mut height: u64 = 0;
                let mut shift = 0;
                for byte in height_bytes {
                    height |= u64::from(byte & 0x7f) << shift;
                    if byte & 0x80 == 0 {
                        break;
                    }
                    shift += 7;
                }

                Ok(Self::Bitcoin { height })
            }

            PENDING_TAG => {
                // Pending attestation: payload is UTF-8 URI
                if payload_len > MAX_URI_LEN {
                    return Err(OtsError::InvalidLength {
                        min: 1,
                        max: MAX_URI_LEN,
                        actual: payload_len,
                    });
                }

                let uri_bytes = deser.read_fixed_bytes(payload_len)?;
                let uri = String::from_utf8(uri_bytes)?;

                // Validate URI characters (only allow: a-z A-Z 0-9 . - _ / : + = & ?)
                for ch in uri.chars() {
                    if !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' | '/' | ':' | '+' | '=' | '&' | '?')
                    {
                        return Err(OtsError::InvalidUriChar(ch));
                    }
                }

                Ok(Self::Pending { uri })
            }

            _ => {
                // Unknown attestation type: store tag and raw payload
                let data = deser.read_fixed_bytes(payload_len)?;
                Ok(Self::Unknown { tag, data })
            }
        }
    }

    /// Serializes this attestation to binary format
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
        // Write 0x00 marker (attestation indicator)
        ser.write_byte(0x00)?;

        match self {
            Self::Bitcoin { height } => {
                // Write Bitcoin tag
                ser.write_fixed_bytes(BITCOIN_TAG)?;

                // Encode height as LEB128 to calculate inner length
                let mut height_encoded = Vec::new();
                let mut ser_height = Serializer::new(&mut height_encoded);
                #[allow(clippy::cast_possible_truncation)]
                ser_height.write_uint(*height as usize)?;

                // Write payload length (LEB128 of inner data)
                ser.write_uint(height_encoded.len())?;

                // Write encoded height
                ser.write_fixed_bytes(&height_encoded)?;
            }

            Self::Pending { uri } => {
                // Write Pending tag
                ser.write_fixed_bytes(PENDING_TAG)?;

                // Write payload length (URI bytes)
                ser.write_uint(uri.len())?;

                // Write URI
                ser.write_fixed_bytes(uri.as_bytes())?;
            }

            Self::Unknown { tag, data } => {
                // Write tag
                ser.write_fixed_bytes(tag)?;

                // Write payload length
                ser.write_uint(data.len())?;

                // Write payload
                ser.write_fixed_bytes(data)?;
            }
        }

        Ok(())
    }

    /// Returns `true` if this is a Bitcoin attestation
    #[must_use]
    pub const fn is_bitcoin(&self) -> bool {
        matches!(self, Self::Bitcoin { .. })
    }

    /// Returns `true` if this is a Pending attestation
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending { .. })
    }

    /// Returns the Bitcoin block height if this is a Bitcoin attestation
    #[must_use]
    pub const fn bitcoin_height(&self) -> Option<u64> {
        match self {
            Self::Bitcoin { height } => Some(*height),
            _ => None,
        }
    }

    /// Returns the pending URI if this is a Pending attestation
    #[must_use]
    pub fn pending_uri(&self) -> Option<&str> {
        match self {
            Self::Pending { uri } => Some(uri),
            _ => None,
        }
    }
}

impl std::fmt::Display for Attestation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bitcoin { height } => write!(f, "Bitcoin(height={height})"),
            Self::Pending { uri } => write!(f, "Pending(uri=\"{uri}\")"),
            Self::Unknown { tag, data } => {
                write!(f, "Unknown(tag={}, {} bytes)", hex::encode(tag), data.len())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_attestation_round_trip() {
        let att = Attestation::Bitcoin { height: 123_456 };

        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        att.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let marker = deser.read_byte().unwrap();
        assert_eq!(marker, 0x00);

        let result = Attestation::deserialize(&mut deser).unwrap();
        assert_eq!(result, att);
    }

    #[test]
    fn test_pending_attestation_round_trip() {
        let att = Attestation::Pending { uri: "https://calendar.example.com".to_string() };

        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        att.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let marker = deser.read_byte().unwrap();
        assert_eq!(marker, 0x00);

        let result = Attestation::deserialize(&mut deser).unwrap();
        assert_eq!(result, att);
    }

    #[test]
    fn test_unknown_attestation_round_trip() {
        let att = Attestation::Unknown {
            tag: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            data: vec![0xaa, 0xbb, 0xcc],
        };

        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        att.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let marker = deser.read_byte().unwrap();
        assert_eq!(marker, 0x00);

        let result = Attestation::deserialize(&mut deser).unwrap();
        assert_eq!(result, att);
    }

    #[test]
    fn test_invalid_uri_character_rejection() {
        // Create a buffer with pending attestation containing invalid character
        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);

        // Write tag
        ser.write_fixed_bytes(PENDING_TAG).unwrap();

        // Write invalid URI with null character
        let invalid_uri = "https://example.com\0";
        ser.write_uint(invalid_uri.len()).unwrap();
        ser.write_fixed_bytes(invalid_uri.as_bytes()).unwrap();

        // Try to deserialize
        let mut deser = Deserializer::new(&buf[..]);
        let result = Attestation::deserialize(&mut deser);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::InvalidUriChar('\0')));
    }

    #[test]
    fn test_invalid_uri_characters() {
        let invalid_chars = [
            '\0', '\n', '\t', ' ', '!', '@', '#', '$', '%', '^', '*', '(', ')', '[', ']', '{', '}',
            '|', '\\', '<', '>', ',', ';', '"', '\'',
        ];

        for &ch in &invalid_chars {
            let mut buf = Vec::new();
            let mut ser = Serializer::new(&mut buf);

            ser.write_fixed_bytes(PENDING_TAG).unwrap();
            let invalid_uri = format!("https://example.com{ch}");
            ser.write_uint(invalid_uri.len()).unwrap();
            ser.write_fixed_bytes(invalid_uri.as_bytes()).unwrap();

            let mut deser = Deserializer::new(&buf[..]);
            let result = Attestation::deserialize(&mut deser);

            assert!(result.is_err(), "Character {ch:?} should be rejected");
        }
    }

    #[test]
    fn test_valid_uri_characters() {
        let valid_uri = "https://calendar.example-server.com:8080/api/v1/timestamp";
        let att = Attestation::Pending { uri: valid_uri.to_string() };

        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        att.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        deser.read_byte().unwrap(); // consume marker
        let result = Attestation::deserialize(&mut deser).unwrap();

        assert_eq!(result, att);
    }

    #[test]
    fn test_is_bitcoin() {
        let att = Attestation::Bitcoin { height: 100 };
        assert!(att.is_bitcoin());
        assert!(!att.is_pending());

        let att = Attestation::Pending { uri: "https://example.com".into() };
        assert!(!att.is_bitcoin());
    }

    #[test]
    fn test_is_pending() {
        let att = Attestation::Pending { uri: "https://example.com".into() };
        assert!(att.is_pending());
        assert!(!att.is_bitcoin());

        let att = Attestation::Bitcoin { height: 100 };
        assert!(!att.is_pending());
    }

    #[test]
    fn test_bitcoin_height() {
        let att = Attestation::Bitcoin { height: 123_456 };
        assert_eq!(att.bitcoin_height(), Some(123_456));

        let att = Attestation::Pending { uri: "https://example.com".into() };
        assert_eq!(att.bitcoin_height(), None);

        let att = Attestation::Unknown { tag: [0; 8], data: vec![] };
        assert_eq!(att.bitcoin_height(), None);
    }

    #[test]
    fn test_pending_uri() {
        let att = Attestation::Pending { uri: "https://example.com".into() };
        assert_eq!(att.pending_uri(), Some("https://example.com"));

        let att = Attestation::Bitcoin { height: 100 };
        assert_eq!(att.pending_uri(), None);

        let att = Attestation::Unknown { tag: [0; 8], data: vec![] };
        assert_eq!(att.pending_uri(), None);
    }

    #[test]
    fn test_attestation_display() {
        let att = Attestation::Bitcoin { height: 123_456 };
        assert_eq!(att.to_string(), "Bitcoin(height=123_456)");

        let att = Attestation::Pending { uri: "https://example.com".into() };
        assert_eq!(att.to_string(), "Pending(uri=\"https://example.com\")");

        let att = Attestation::Unknown { tag: [0xaa; 8], data: vec![1, 2, 3] };
        let s = att.to_string();
        assert!(s.contains("Unknown"));
        assert!(s.contains("3 bytes"));
    }

    #[test]
    fn test_uri_length_limit() {
        let long_uri = "a".repeat(MAX_URI_LEN + 1);

        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);

        ser.write_fixed_bytes(PENDING_TAG).unwrap();
        ser.write_uint(long_uri.len()).unwrap();
        ser.write_fixed_bytes(long_uri.as_bytes()).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        let result = Attestation::deserialize(&mut deser);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OtsError::InvalidLength { .. }));
    }

    #[test]
    fn test_bitcoin_height_zero() {
        let att = Attestation::Bitcoin { height: 0 };

        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        att.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        deser.read_byte().unwrap();
        let result = Attestation::deserialize(&mut deser).unwrap();

        assert_eq!(result, att);
        assert_eq!(result.bitcoin_height(), Some(0));
    }

    #[test]
    fn test_bitcoin_height_large() {
        let att = Attestation::Bitcoin { height: 1_000_000 };

        let mut buf = Vec::new();
        let mut ser = Serializer::new(&mut buf);
        att.serialize(&mut ser).unwrap();

        let mut deser = Deserializer::new(&buf[..]);
        deser.read_byte().unwrap();
        let result = Attestation::deserialize(&mut deser).unwrap();

        assert_eq!(result, att);
        assert_eq!(result.bitcoin_height(), Some(1_000_000));
    }

    #[test]
    fn test_attestation_clone_and_eq() {
        let att1 = Attestation::Bitcoin { height: 100 };
        let att2 = att1.clone();
        assert_eq!(att1, att2);

        let att3 = Attestation::Bitcoin { height: 200 };
        assert_ne!(att1, att3);
    }

    #[test]
    fn test_attestation_debug() {
        let att = Attestation::Bitcoin { height: 123_456 };
        let debug_str = format!("{att:?}");
        assert!(debug_str.contains("Bitcoin"));
        assert!(debug_str.contains("123_456"));
    }
}
