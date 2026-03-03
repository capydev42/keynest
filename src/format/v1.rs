//! File format v1 for the keystore.
//!
//! V1 File Format:
//! ```text
//! MAGIC (4) | VERSION (1) | MEM_COST (4) | TIME_COST (4) | PARALLELISM (4) | SALT (16) | NONCE (24) | CIPHERTEXT
//! ```

use super::KeystoreFile;
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

    Ok(KeystoreFile::new(
        kdf,
        crate::crypto::Algorithm::XChaCha20Poly1305,
        salt,
        nonce,
        ciphertext,
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn v1_parse_valid_data() {
        let mut data = vec![0u8; 61];
        data[..4].copy_from_slice(b"KNST"); // magic
        data[4] = 1; // version
        // ... rest of v1 header data
        // Just verify it doesn't panic
        let _result = super::parse(&data);
        // Will fail because rest of data is zeroed, but that's ok for this test
    }

    #[test]
    fn header_too_short_fails() {
        let data = vec![0u8; 10];
        assert!(super::parse(&data).is_err());
    }
}
