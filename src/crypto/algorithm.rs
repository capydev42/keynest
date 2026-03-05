use anyhow::Result;
use zeroize::Zeroizing;

use crate::crypto::chacha20poly1305;

/// Encryption algorithm used for the keystore.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// XChaCha20-Poly1305 authenticated encryption.
    XChaCha20Poly1305 = 1,
}

impl TryFrom<u8> for Algorithm {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> anyhow::Result<Self> {
        match value {
            1 => Ok(Self::XChaCha20Poly1305),
            _ => anyhow::bail!("unsupported algorithm id {}", value),
        }
    }
}

impl From<Algorithm> for u8 {
    fn from(a: Algorithm) -> Self {
        a as u8
    }
}

impl Algorithm {
    /// Encrypts plaintext using the specified algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn encrypt(self, key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            Algorithm::XChaCha20Poly1305 => chacha20poly1305::encrypt(key, plaintext),
        }
    }

    /// Decrypts ciphertext using the specified algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption fails (wrong key, tampered data, or corruption).
    pub fn decrypt(
        self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            Algorithm::XChaCha20Poly1305 => chacha20poly1305::decrypt(key, nonce, ciphertext),
        }
    }

    /// Returns the nonce length required by this algorithm.
    pub fn nonce_len(self) -> usize {
        match self {
            Algorithm::XChaCha20Poly1305 => chacha20poly1305::NONCE_LEN,
        }
    }

    /// Returns the human-readable name of this algorithm.
    pub fn name(&self) -> &'static str {
        match self {
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
        }
    }
}
