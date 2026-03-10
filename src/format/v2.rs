//! TLV-based v2 file format for the keystore.
//!
//! V2 uses TLV (Type-Length-Value) encoding for extensibility.

use super::tlv;
use super::{Header, KeystoreFile, MAGIC, MAGIC_LEN, VER_LEN};
use crate::{
    KdfParams,
    crypto::{SALT_LEN, algorithm::Algorithm},
};
use anyhow::{Result, bail};

/// V2 file format version.
pub const VERSION_V2: u8 = 2;
/// Size of the AEAD authentication tag (Poly1305).
const AEAD_TAG_LEN: usize = 16;
/// Maximum allowed ciphertext size to prevent memory exhaustion attacks.
const MAX_CIPHERTEXT: usize = 16 * 1024 * 1024; // 16 MiB max

/// TLV type identifiers for v2 format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum TlvType {
    /// KDF parameters (memory, time, parallelism)
    Kdf,
    /// Algorithm for encryption
    Algorithm,
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
            5 => Self::Algorithm,
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
            TlvType::Algorithm => 5,
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
    let mut algorithm: Option<Algorithm> = None;
    let mut salt: Option<Vec<u8>> = None;
    let mut nonce: Option<Vec<u8>> = None;
    let mut ciphertext: Option<Vec<u8>> = None;

    for t in tlvs {
        match TlvType::from(t.ty()) {
            TlvType::Kdf => {
                if kdf.is_some() {
                    bail!("duplicate KDF field");
                }
                if t.value().len() != 12 {
                    bail!("invalid kdf tlv length");
                }

                let mem = u32::from_le_bytes(t.value()[0..4].try_into()?);
                let time = u32::from_le_bytes(t.value()[4..8].try_into()?);
                let par = u32::from_le_bytes(t.value()[8..12].try_into()?);

                kdf = Some(KdfParams::new(mem, time, par)?);
            }
            TlvType::Algorithm => {
                if algorithm.is_some() {
                    bail!("duplicate algorithm field");
                }

                if t.value().len() != 1 {
                    bail!("invalid algorithm length");
                }

                let id = t.value()[0];
                algorithm = Some(Algorithm::try_from(id)?);
            }
            TlvType::Salt => {
                if salt.is_some() {
                    bail!("duplicate salt field");
                }
                salt = Some(t.value().to_vec());
            }
            TlvType::Nonce => {
                if nonce.is_some() {
                    bail!("duplicate nonce field");
                }
                nonce = Some(t.value().to_vec());
            }
            TlvType::Ciphertext => {
                if ciphertext.is_some() {
                    bail!("duplicate ciphertext field");
                }
                ciphertext = Some(t.value().to_vec());
            }
            TlvType::Unknown(_) => {
                // forward compatibility:
                // ignore unknown TLVs
            }
        }
    }

    let kdf = kdf.ok_or_else(|| anyhow::anyhow!("missing kdf"))?;
    let algorithm = algorithm.ok_or_else(|| anyhow::anyhow!("missing algorithm"))?;
    let salt = salt.ok_or_else(|| anyhow::anyhow!("missing salt"))?;
    let nonce = nonce.ok_or_else(|| anyhow::anyhow!("missing nonce"))?;
    let ciphertext = ciphertext.ok_or_else(|| anyhow::anyhow!("missing ciphertext"))?;

    if salt.len() != SALT_LEN {
        bail!("invalid salt length");
    }

    if nonce.len() != algorithm.nonce_len() {
        bail!("invalid nonce length for algorithm");
    }

    if ciphertext.len() < AEAD_TAG_LEN {
        bail!("ciphertext too short");
    }

    if ciphertext.len() > MAX_CIPHERTEXT {
        bail!("ciphertext too large");
    }

    let header = Header::new(kdf, algorithm, salt, nonce);
    Ok(KeystoreFile::new(header, ciphertext))
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

    let algo_id: u8 = file.algorithm().into();

    tlv::encode(TlvType::Kdf.into(), &kdf_bytes, &mut buf);
    tlv::encode(TlvType::Algorithm.into(), &[algo_id], &mut buf);
    tlv::encode(TlvType::Salt.into(), file.salt(), &mut buf);
    tlv::encode(TlvType::Nonce.into(), file.nonce(), &mut buf);
    tlv::encode(TlvType::Ciphertext.into(), file.ciphertext(), &mut buf);

    Ok(buf)
}

/// Builds AAD from header data for authenticated encryption.
///
/// Note: Nonce is NOT included in AAD because it's generated during encryption.
/// The AAD protects KDF params, algorithm, and salt from being modified.
pub(crate) fn build_header_aad(header: &Header) -> Vec<u8> {
    let mut aad = Vec::new();

    aad.extend_from_slice(MAGIC);
    aad.push(VERSION_V2);

    let mut kdf_bytes = Vec::with_capacity(12);
    kdf_bytes.extend_from_slice(&header.kdf().mem_cost_kib().to_le_bytes());
    kdf_bytes.extend_from_slice(&header.kdf().time_cost().to_le_bytes());
    kdf_bytes.extend_from_slice(&header.kdf().parallelism().to_le_bytes());

    let algo_id: u8 = header.algorithm().into();

    tlv::encode(TlvType::Kdf.into(), &kdf_bytes, &mut aad);
    tlv::encode(TlvType::Algorithm.into(), &[algo_id], &mut aad);
    tlv::encode(TlvType::Salt.into(), header.salt(), &mut aad);

    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::format::{Header, KeystoreFile, MAGIC, parse, serialize};

    #[test]
    fn v2_roundtrip() {
        let header = Header::new(
            KdfParams::new(65536, 3, 2).unwrap(),
            Algorithm::XChaCha20Poly1305,
            vec![1u8; 16],
            vec![2u8; 24],
        );
        let file = KeystoreFile::new(header, vec![3u8; 32]);

        let bytes = serialize(&file).unwrap();

        // Verify magic and version
        assert_eq!(&bytes[..4], MAGIC);
        assert_eq!(bytes[4], VERSION_V2);

        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed.version(), VERSION_V2);
        assert_eq!(parsed.kdf().mem_cost_kib(), 65536);
        assert_eq!(parsed.kdf().time_cost(), 3);
        assert_eq!(parsed.kdf().parallelism(), 2);
        assert_eq!(parsed.algorithm(), Algorithm::XChaCha20Poly1305);
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

        // Add Algorithm TLV (type 5)
        bytes.push(5); // type = Algorithm
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.push(1); // XChaCha20Poly1305

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

        // Add required Ciphertext TLV (minimum 16 bytes for AEAD tag)
        bytes.push(4); // type = Ciphertext
        bytes.extend_from_slice(&16u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);

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

        // Algorithm TLV (has algorithm, but missing kdf)
        bytes.push(5); // type = Algorithm
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.push(1); // XChaCha20Poly1305

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
        let header = Header::new(
            KdfParams::default(),
            Algorithm::XChaCha20Poly1305,
            vec![1u8; 16],
            vec![2u8; 24],
        );
        // Minimum ciphertext is 16 bytes (AEAD tag)
        let file = KeystoreFile::new(header, vec![0u8; 16]);

        let bytes = serialize(&file).unwrap();
        let parsed = parse(&bytes).unwrap();

        assert_eq!(parsed.ciphertext().len(), 16);
        assert_eq!(parsed.algorithm(), Algorithm::XChaCha20Poly1305);
    }

    #[test]
    fn v2_missing_algorithm_fails() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION_V2);

        // KDF TLV (valid params)
        let mut kdf_data = vec![0u8; 12];
        kdf_data[..4].copy_from_slice(&65536u32.to_le_bytes()); // mem = 64 MiB
        kdf_data[4..8].copy_from_slice(&3u32.to_le_bytes()); // time = 3
        kdf_data[8..12].copy_from_slice(&1u32.to_le_bytes()); // parallelism = 1
        bytes.push(1);
        bytes.extend_from_slice(&12u16.to_le_bytes());
        bytes.extend_from_slice(&kdf_data);

        // Salt TLV
        bytes.push(2);
        bytes.extend_from_slice(&16u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);

        // Nonce TLV
        bytes.push(3);
        bytes.extend_from_slice(&24u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 24]);

        // Ciphertext TLV
        bytes.push(4);
        bytes.extend_from_slice(&5u16.to_le_bytes());
        bytes.extend_from_slice(b"hello");

        let result = parse(&bytes);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        eprintln!("Error: {}", err);
        assert!(err.contains("algorithm"));
    }

    #[test]
    fn v2_invalid_algorithm_fails() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION_V2);

        // KDF TLV (valid params)
        let mut kdf_data = vec![0u8; 12];
        kdf_data[..4].copy_from_slice(&65536u32.to_le_bytes()); // mem = 64 MiB
        kdf_data[4..8].copy_from_slice(&3u32.to_le_bytes()); // time = 3
        kdf_data[8..12].copy_from_slice(&1u32.to_le_bytes()); // parallelism = 1
        bytes.push(1);
        bytes.extend_from_slice(&12u16.to_le_bytes());
        bytes.extend_from_slice(&kdf_data);

        // Algorithm TLV with invalid ID (99)
        bytes.push(5);
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.push(99); // invalid algorithm

        // Salt TLV
        bytes.push(2);
        bytes.extend_from_slice(&16u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);

        // Nonce TLV
        bytes.push(3);
        bytes.extend_from_slice(&24u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 24]);

        // Ciphertext TLV
        bytes.push(4);
        bytes.extend_from_slice(&5u16.to_le_bytes());
        bytes.extend_from_slice(b"hello");

        let result = parse(&bytes);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        eprintln!("Error: {}", err);
        assert!(err.contains("unsupported algorithm"));
    }

    #[test]
    fn aad_authentication_works() {
        use crate::crypto::derive_key;
        use crate::format::{Header, parse, serialize};

        // Create and encrypt with more data
        let kdf = KdfParams::new(65536, 3, 2).unwrap();
        let salt = vec![1u8; 16];
        let key = derive_key("password", &salt, kdf).unwrap();

        let plaintext = b"this is some secret data that is long enough";

        let (header, ciphertext) =
            Header::encrypt_store(kdf, Algorithm::XChaCha20Poly1305, salt, &key, plaintext)
                .unwrap();

        let file = KeystoreFile::new(header, ciphertext);
        let bytes = serialize(&file).unwrap();

        // Verify decryption works
        let parsed = parse(&bytes).unwrap();
        let key2 = derive_key("password", parsed.salt(), *parsed.kdf()).unwrap();
        let decrypted = parsed.decrypt(&key2).unwrap();
        assert_eq!(*decrypted, plaintext);

        // Tamper with ciphertext - should fail
        let mut tampered_bytes = bytes.clone();
        if tampered_bytes.len() > 50 {
            tampered_bytes[50] ^= 0xFF; // flip some bits in ciphertext
        }
        let parsed = parse(&tampered_bytes).unwrap();
        let key3 = derive_key("password", parsed.salt(), *parsed.kdf()).unwrap();
        let result = parsed.decrypt(&key3);
        assert!(
            result.is_err(),
            "decryption should fail with tampered ciphertext"
        );
    }
}
