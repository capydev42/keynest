use super::{NONCE_LEN, SALT_LEN};
use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use getrandom::fill;
use zeroize::Zeroizing;

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
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));

    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow!("Invalid password or corrupted data"))?;
    Ok(Zeroizing::new(plaintext))
}
