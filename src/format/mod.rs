//! File format handling for the keystore.
//!
//! Provides version-aware parsing and serialization of the keystore file format.

use anyhow::{Result, bail};
use zeroize::Zeroizing;

use crate::KdfParams;
use crate::crypto::algorithm::Algorithm;

pub mod tlv;
pub mod v1;
pub mod v2;

/// Magic bytes identifying a keynest keystore file ("KNST").
pub const MAGIC: &[u8; 4] = b"KNST";
/// Length of magic bytes.
pub const MAGIC_LEN: usize = 4;
/// Length of version field.
pub const VER_LEN: usize = 1;
/// Latest format version
pub const CURRENT_VERSION: u8 = v2::VERSION_V2;

/// Authenticated header data used for AAD and file format.
///
/// Contains all metadata needed for key derivation and encryption.
#[derive(Debug, Clone)]
pub struct Header {
    pub(crate) version: u8,
    pub(crate) kdf: KdfParams,
    pub(crate) algorithm: Algorithm,
    pub(crate) salt: Vec<u8>,
    pub(crate) nonce: Vec<u8>,
}

impl Header {
    /// Creates a new Header.
    pub fn new(kdf: KdfParams, algorithm: Algorithm, salt: Vec<u8>, nonce: Vec<u8>) -> Self {
        Self {
            version: CURRENT_VERSION,
            kdf,
            algorithm,
            salt,
            nonce,
        }
    }

    /// Returns the file format version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns the KDF parameters used for key derivation.
    pub fn kdf(&self) -> &KdfParams {
        &self.kdf
    }

    /// Returns the algorithm used for encryption.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the salt used for key derivation.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Returns the nonce used for encryption.
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// Builds AAD from header data for authenticated encryption.
    pub fn build_aad(&self) -> Vec<u8> {
        build_header_aad(self)
    }

    /// Decrypts ciphertext using AAD from header.
    pub fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let aad = self.build_aad();
        self.algorithm.decrypt(key, self.nonce(), ciphertext, &aad)
    }

    /// Encrypts plaintext and creates a header in one step.
    ///
    /// This is the preferred way to create encrypted data - it handles
    /// nonce generation and AAD construction internally.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn encrypt_store(
        kdf: KdfParams,
        algorithm: Algorithm,
        salt: Vec<u8>,
        key: &[u8],
        plaintext: &[u8],
    ) -> Result<(Self, Vec<u8>)> {
        let tmp = Self::new(kdf, algorithm, salt.clone(), vec![]);

        let aad = tmp.build_aad();

        let (ciphertext, nonce) = algorithm.encrypt(key, plaintext, &aad)?;

        let header = Self::new(kdf, algorithm, salt, nonce);

        Ok((header, ciphertext))
    }
}

/// Represents a parsed keystore file with all components.
///
/// This struct holds the deserialized data from a keystore file,
/// including header metadata and encrypted ciphertext.
#[derive(Debug)]
pub struct KeystoreFile {
    pub(crate) header: Header,
    pub(crate) ciphertext: Vec<u8>,
}

impl KeystoreFile {
    /// Creates a new KeystoreFile from header and ciphertext.
    pub fn new(header: Header, ciphertext: Vec<u8>) -> Self {
        Self { header, ciphertext }
    }

    /// Returns the file format version.
    pub fn version(&self) -> u8 {
        self.header.version()
    }

    /// Returns the KDF parameters used for key derivation.
    pub fn kdf(&self) -> &KdfParams {
        self.header.kdf()
    }

    /// Returns the algorithm used for encryption.
    pub fn algorithm(&self) -> Algorithm {
        self.header.algorithm()
    }

    /// Returns the salt used for key derivation.
    pub fn salt(&self) -> &[u8] {
        self.header.salt()
    }

    /// Returns the nonce used for encryption.
    pub fn nonce(&self) -> &[u8] {
        self.header.nonce()
    }

    /// Returns the encrypted ciphertext.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Decrypts the ciphertext using AAD from header.
    pub fn decrypt(&self, key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.header.decrypt(key, self.ciphertext())
    }
}

/// Parses a keystore file and returns a KeystoreFile.
///
/// Automatically dispatches to the appropriate version parser.
///
/// # Errors
///
/// Returns an error if:
/// - The file is too short
/// - The magic bytes are invalid
/// - The version is unsupported
pub fn parse(data: &[u8]) -> Result<KeystoreFile> {
    if data.len() < MAGIC_LEN + VER_LEN {
        bail!("file too short");
    }

    if &data[..MAGIC_LEN] != MAGIC {
        bail!("invalid magic");
    }

    let version = data[MAGIC_LEN];

    match version {
        v1::VERSION_V1 => v1::parse(data),
        v2::VERSION_V2 => v2::parse(data),
        _ => bail!("unsupported version"),
    }
}

/// Serializes a KeystoreFile to bytes.
///
/// # Errors
///
/// Returns an error if the version is unsupported.
pub fn serialize(file: &KeystoreFile) -> Result<Vec<u8>> {
    v2::serialize(file)
}

/// Builds AAD from header data.
fn build_header_aad(header: &Header) -> Vec<u8> {
    match header.version() {
        v2::VERSION_V2 => v2::build_header_aad(header),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_invalid_magic_fails() {
        let mut data = vec![0u8; 10];
        data[..4].copy_from_slice(b"FAIL"); // invalid magic

        let result = parse(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid magic"));
    }

    #[test]
    fn parse_unsupported_version_fails() {
        let mut data = vec![0u8; 10];
        data[..4].copy_from_slice(b"KNST"); // valid magic
        data[4] = 99; // unsupported version

        let result = parse(&data);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unsupported version")
        );
    }
}
