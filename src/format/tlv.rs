//! TLV (Type-Length-Value) encoding and decoding for v2 format.
//!
//! TLV provides a flexible, extensible format where each field consists of:
//! - Type: 1 byte
//! - Length: 2 bytes (little-endian)
//! - Value: N bytes

use anyhow::{Result, bail};

/// A TLV (Type-Length-Value) entry.
#[derive(Debug)]
pub struct Tlv<'a> {
    ty: u8,
    value: &'a [u8],
}

const HEADER_LEN: usize = 3; // type(1) + len(2)

impl<'a> Tlv<'a> {
    /// Returns the type of this TLV entry.
    pub fn ty(&self) -> u8 {
        self.ty
    }

    /// Returns the value of this TLV entry.
    pub fn value(&self) -> &'a [u8] {
        self.value
    }
}

/// Encodes a TLV entry into the output buffer.
///
/// # Arguments
///
/// * `ty` - The type of the entry
/// * `value` - The value bytes
/// * `out` - The output buffer to append to
///
/// # Panics
///
/// Panics if value length exceeds u16::MAX.
pub fn encode(ty: u8, value: &[u8], out: &mut Vec<u8>) {
    assert!(value.len() <= u16::MAX as usize);

    out.push(ty);
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);
}

/// Decodes all TLV entries from data.
///
/// # Errors
///
/// Returns an error if the data is truncated or malformed.
pub fn decode_all(data: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let mut result = Vec::new();

    let mut remaining = data;

    while !remaining.is_empty() {
        if remaining.len() < HEADER_LEN {
            bail!("truncated tlv header");
        }

        let ty = remaining[0];
        let len = u16::from_le_bytes([remaining[1], remaining[2]]) as usize;

        remaining = &remaining[HEADER_LEN..];

        if remaining.len() < len {
            bail!("truncated tlv value");
        }

        let value = &remaining[..len];

        result.push(Tlv { ty, value });

        remaining = &remaining[len..];
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::v2::TlvType;

    #[test]
    fn encode_decode_single() {
        let mut buf = Vec::new();
        encode(TlvType::Salt.into(), b"hello", &mut buf);

        let decoded = decode_all(&buf).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].ty(), 2); // Salt
        assert_eq!(decoded[0].value(), b"hello");
    }

    #[test]
    fn encode_decode_multiple() {
        let mut buf = Vec::new();
        encode(TlvType::Kdf.into(), b"kdfdata", &mut buf);
        encode(TlvType::Salt.into(), b"saltdata", &mut buf);
        encode(TlvType::Nonce.into(), b"noncedata", &mut buf);

        let decoded = decode_all(&buf).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].ty(), 1); // Kdf
        assert_eq!(decoded[1].ty(), 2); // Salt
        assert_eq!(decoded[2].ty(), 3); // Nonce
    }

    #[test]
    fn encode_decode_roundtrip() {
        let original_data = b"test data for roundtrip";

        let mut buf = Vec::new();
        encode(TlvType::Ciphertext.into(), original_data, &mut buf);

        let decoded = decode_all(&buf).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].value(), original_data);
    }

    #[test]
    fn decode_truncated_header_fails() {
        let data = vec![1, 2]; // Only 2 bytes, need 3
        let result = decode_all(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("truncated"));
    }

    #[test]
    fn decode_truncated_value_fails() {
        // type(1) + len(2) = 3 bytes header, but value says 10 bytes
        let data = vec![1, 10, 0, 1, 2, 3]; // claims 10 bytes but only has 3
        let result = decode_all(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("truncated"));
    }

    #[test]
    fn decode_empty_data() {
        let data = vec![];
        let result = decode_all(&data).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn encode_large_value() {
        let mut buf = Vec::new();
        let large_data = vec![0u8; 1000];
        encode(TlvType::Ciphertext.into(), &large_data, &mut buf);

        let decoded = decode_all(&buf).unwrap();
        assert_eq!(decoded[0].value().len(), 1000);
    }
}
