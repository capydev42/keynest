//! TLV-based v2 file format for the keystore.
//!
//! V2 uses TLV (Type-Length-Value) encoding for extensibility.

use super::tlv;
use super::{KeystoreFile, MAGIC, MAGIC_LEN, VER_LEN};
use crate::{
    KdfParams,
    crypto::{NONCE_LEN, SALT_LEN},
};
use anyhow::{Result, bail};

/// V2 file format version.
pub const VERSION_V2: u8 = 2;

/// TLV type identifiers for v2 format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum TlvType {
    /// KDF parameters (memory, time, parallelism)
    Kdf,
    /// Salt for key derivation
    Salt,
    /// Nonce for encryption
    Nonce,
    /// Encrypted ciphertext
    Ciphertext,
    /// Unknown type (for forward compatibility)
    Unknown(u8),
}

impl From<u8> for TlvType {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Kdf,
            2 => Self::Salt,
            3 => Self::Nonce,
            4 => Self::Ciphertext,
            x => Self::Unknown(x),
        }
    }
}

impl From<TlvType> for u8 {
    fn from(t: TlvType) -> u8 {
        match t {
            TlvType::Kdf => 1,
            TlvType::Salt => 2,
            TlvType::Nonce => 3,
            TlvType::Ciphertext => 4,
            TlvType::Unknown(x) => x,
        }
    }
}

/// Parses a v2 keystore file.
///
/// # Errors
///
/// Returns an error if the file is malformed or required fields are missing.
pub fn parse(data: &[u8]) -> Result<KeystoreFile> {
    if data.len() < MAGIC_LEN + VER_LEN {
        bail!("file too short");
    }

    let tlv_data = &data[MAGIC_LEN + VER_LEN..];
    let tlvs = tlv::decode_all(tlv_data)?;

    let mut kdf: Option<KdfParams> = None;
    let mut salt: Option<Vec<u8>> = None;
    let mut nonce: Option<Vec<u8>> = None;
    let mut ciphertext: Option<Vec<u8>> = None;

    for t in tlvs {
        match TlvType::from(t.ty()) {
            TlvType::Kdf => {
                if t.value().len() != 12 {
                    bail!("invalid kdf tlv length");
                }

                let mem = u32::from_le_bytes(t.value()[0..4].try_into()?);
                let time = u32::from_le_bytes(t.value()[4..8].try_into()?);
                let par = u32::from_le_bytes(t.value()[8..12].try_into()?);

                kdf = Some(KdfParams::new(mem, time, par)?);
            }
            TlvType::Salt => {
                if t.value().len() != SALT_LEN {
                    bail!("invalid salt length");
                }
                salt = Some(t.value().to_vec());
            }
            TlvType::Nonce => {
                if t.value().len() != NONCE_LEN {
                    bail!("invalid nonce length");
                }
                nonce = Some(t.value().to_vec());
            }
            TlvType::Ciphertext => {
                ciphertext = Some(t.value().to_vec());
            }
            TlvType::Unknown(_) => {
                // forward compatibility:
                // ignore unknown TLVs
            }
        }
    }

    Ok(KeystoreFile::new(
        kdf.ok_or_else(|| anyhow::anyhow!("missing kdf"))?,
        salt.ok_or_else(|| anyhow::anyhow!("missing salt"))?,
        nonce.ok_or_else(|| anyhow::anyhow!("missing nonce"))?,
        ciphertext.ok_or_else(|| anyhow::anyhow!("missing ciphertext"))?,
    ))
}

/// Serializes a KeystoreFile to v2 format bytes using TLV encoding.
///
/// # Errors
///
/// Returns an error if the version is not v2.
pub fn serialize(file: &KeystoreFile) -> Result<Vec<u8>> {
    if file.version() != VERSION_V2 {
        bail!("wrong version for v2 serializer");
    }

    let mut buf = Vec::new();

    // header
    buf.extend_from_slice(MAGIC);
    buf.push(VERSION_V2);

    // TLVs
    let mut kdf_bytes = Vec::with_capacity(12);
    kdf_bytes.extend_from_slice(&file.kdf().mem_cost_kib().to_le_bytes());
    kdf_bytes.extend_from_slice(&file.kdf().time_cost().to_le_bytes());
    kdf_bytes.extend_from_slice(&file.kdf().parallelism().to_le_bytes());

    tlv::encode(TlvType::Kdf.into(), &kdf_bytes, &mut buf);
    tlv::encode(TlvType::Salt.into(), file.salt(), &mut buf);
    tlv::encode(TlvType::Nonce.into(), file.nonce(), &mut buf);
    tlv::encode(TlvType::Ciphertext.into(), file.ciphertext(), &mut buf);

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::format::{KeystoreFile, MAGIC, parse, serialize};

    #[test]
    fn v2_roundtrip() {
        let file = KeystoreFile::new(
            KdfParams::new(65536, 3, 2).unwrap(),
            vec![1u8; 16],
            vec![2u8; 24],
            vec![3u8; 32],
        );

        let bytes = serialize(&file).unwrap();

        // Verify magic and version
        assert_eq!(&bytes[..4], MAGIC);
        assert_eq!(bytes[4], VERSION_V2);

        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.version(), VERSION_V2);
        assert_eq!(parsed.kdf().mem_cost_kib(), 65536);
        assert_eq!(parsed.kdf().time_cost(), 3);
        assert_eq!(parsed.kdf().parallelism(), 2);
    }

    #[test]
    fn v2_ignores_unknown_tlv() {
        // Manually construct a v2 file with an unknown TLV (type 99)
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION_V2);

        // Add valid KDF TLV first
        let mut kdf_data = vec![0u8; 12];
        kdf_data[..4].copy_from_slice(&65536u32.to_le_bytes()); // mem
        kdf_data[4..8].copy_from_slice(&3u32.to_le_bytes()); // time
        kdf_data[8..12].copy_from_slice(&1u32.to_le_bytes()); // parallelism
        bytes.push(1); // type = Kdf
        bytes.extend_from_slice(&12u16.to_le_bytes());
        bytes.extend_from_slice(&kdf_data);

        // Add unknown TLV type 99 with length 3
        bytes.push(99); // type
        bytes.extend_from_slice(&3u16.to_le_bytes()); // length
        bytes.extend_from_slice(b"abc"); // value

        // Add required Salt TLV
        bytes.push(2); // type = Salt
        bytes.extend_from_slice(&16u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);

        // Add required Nonce TLV
        bytes.push(3); // type = Nonce
        bytes.extend_from_slice(&24u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 24]);

        // Add required Ciphertext TLV
        bytes.push(4); // type = Ciphertext
        bytes.extend_from_slice(&5u16.to_le_bytes());
        bytes.extend_from_slice(b"hello");

        // Should still parse successfully, ignoring unknown TLV
        let result = parse(&bytes);
        eprintln!("Error: {:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn v2_missing_kdf_fails() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION_V2);

        // Salt TLV
        bytes.push(2); // type = Salt
        bytes.extend_from_slice(&16u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);

        // Nonce TLV
        bytes.push(3); // type = Nonce
        bytes.extend_from_slice(&24u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 24]);

        // Ciphertext TLV
        bytes.push(4); // type = Ciphertext
        bytes.extend_from_slice(&10u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 10]);

        let result = parse(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing kdf"));
    }

    #[test]
    fn v2_empty_ciphertext() {
        let file = KeystoreFile::new(
            KdfParams::default(),
            vec![1u8; 16],
            vec![2u8; 24],
            vec![], // empty ciphertext
        );

        let bytes = serialize(&file).unwrap();
        let parsed = parse(&bytes).unwrap();

        assert!(parsed.ciphertext().is_empty());
    }
}
