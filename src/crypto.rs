use anyhow::{Result, anyhow};
use argon2::Argon2;
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use getrandom::fill;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

/// Fill buffer with cryptographically secure random bytes
fn secure_random(buf: &mut [u8]) -> Result<()> {
    fill(buf).map_err(|_| anyhow!("OS random generator unavailable"))
}

/// Generate salt
pub fn generate_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    secure_random(&mut salt)?;
    Ok(salt)
}

/// Derive encryption key from password
pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];

    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| anyhow!("key derivation failed"))?;

    Ok(key)
}

/// Encrypt plaintext
pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));

    let mut nonce = [0u8; NONCE_LEN];
    secure_random(&mut nonce)?;

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow!("encryption failed"))?;

    Ok((ciphertext, nonce))
}

/// Decrypt ciphertext
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));

    cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow!("Invalid password or corrupted data"))
}
