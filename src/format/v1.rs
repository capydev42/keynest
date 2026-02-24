//! File format v1 for the keystore.
//!
//! V1 File Format:
//! ```text
//! MAGIC (4) | VERSION (1) | MEM_COST (4) | TIME_COST (4) | PARALLELISM (4) | SALT (16) | NONCE (24) | CIPHERTEXT
//! ```

use super::{KeystoreFile, MAGIC};
use crate::{
    KdfParams,
    crypto::{NONCE_LEN, SALT_LEN},
    format::{MAGIC_LEN, VER_LEN},
};
use anyhow::{Result, bail};

/// Current file format version.
pub const VERSION_V1: u8 = 1;

const MEM_LEN: usize = 4;
const TIME_LEN: usize = 4;
const PAR_LEN: usize = 4;

const HEADER_LEN: usize = MAGIC_LEN + VER_LEN + MEM_LEN + TIME_LEN + PAR_LEN + SALT_LEN + NONCE_LEN;

/// Parses a v1 keystore file.
///
/// # Errors
///
/// Returns an error if the file is too short or has invalid parameters.
pub fn parse(data: &[u8]) -> Result<KeystoreFile> {
    if data.len() < HEADER_LEN {
        bail!("file too short for v1");
    }

    let mut offset = MAGIC_LEN + VER_LEN;

    let mem_cost = u32::from_le_bytes(data[offset..offset + MEM_LEN].try_into()?);
    offset += MEM_LEN;

    let time_cost = u32::from_le_bytes(data[offset..offset + TIME_LEN].try_into()?);
    offset += TIME_LEN;

    let parallelism = u32::from_le_bytes(data[offset..offset + PAR_LEN].try_into()?);
    offset += PAR_LEN;

    let salt = data[offset..offset + SALT_LEN].to_vec();
    offset += SALT_LEN;

    let nonce = data[offset..offset + NONCE_LEN].to_vec();
    offset += NONCE_LEN;

    let ciphertext: Vec<u8> = data[offset..].to_vec();

    let kdf = KdfParams::new(mem_cost, time_cost, parallelism)?;

    Ok(KeystoreFile::new(kdf, salt, nonce, ciphertext))
}

/// Serializes a KeystoreFile to v1 format bytes.
///
/// # Errors
///
/// Returns an error if the version is not v1 or if salt/nonce have invalid lengths.
pub fn serialize(file: &KeystoreFile) -> Result<Vec<u8>> {
    if file.version() != VERSION_V1 {
        bail!("wrong version for v1 serializer");
    }

    if file.salt().len() != SALT_LEN {
        bail!("invalid salt length for v1");
    }

    if file.nonce().len() != NONCE_LEN {
        bail!("invalid nonce length for v1");
    }

    let mut buf = Vec::with_capacity(HEADER_LEN + file.ciphertext().len());

    buf.extend_from_slice(MAGIC);
    buf.push(VERSION_V1);

    buf.extend_from_slice(&file.kdf().mem_cost_kib().to_le_bytes());
    buf.extend_from_slice(&file.kdf().time_cost().to_le_bytes());
    buf.extend_from_slice(&file.kdf().parallelism().to_le_bytes());

    buf.extend_from_slice(file.salt());
    buf.extend_from_slice(file.nonce());
    buf.extend_from_slice(file.ciphertext());

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::KeystoreFile;
    use super::*;

    #[test]
    fn header_roundtrip() {
        use crate::crypto::KdfParams;

        let file = KeystoreFile::new(
            KdfParams::new(65536, 3, 2).unwrap(),
            vec![1u8; 16],
            vec![2u8; 24],
            vec![0u8; 10],
        );

        let bytes = serialize(&file).unwrap();
        let parsed = parse(&bytes).unwrap();

        assert_eq!(parsed.version(), VERSION_V1);
        assert_eq!(parsed.kdf().mem_cost_kib(), 65536);
        assert_eq!(parsed.kdf().time_cost(), 3);
        assert_eq!(parsed.kdf().parallelism(), 2);
        assert_eq!(parsed.salt(), file.salt());
        assert_eq!(parsed.nonce(), file.nonce());
    }

    #[test]
    fn header_invalid_magic_fails() {
        let mut data = vec![0u8; 61];
        data[..4].copy_from_slice(b"FAIL");

        assert!(super::parse(&data).is_err());
    }

    #[test]
    fn header_unsupported_version_fails() {
        let mut data = vec![0u8; 61];
        data[..4].copy_from_slice(b"KNST");
        data[4] = 99;

        assert!(super::parse(&data).is_err());
    }

    #[test]
    fn header_too_short_fails() {
        let data = vec![0u8; 10];
        assert!(super::parse(&data).is_err());
    }
}
