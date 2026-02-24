//! Cryptographic primitives for the keystore.
//!
//! Provides encryption and key derivation functions.

pub mod aead;
pub mod kdf;

pub use aead::{decrypt, encrypt, generate_salt};
pub use kdf::{KdfParams, derive_key};

/// Length of the salt (16 bytes).
pub const SALT_LEN: usize = 16;
/// Length of the nonce (24 bytes for XChaCha20-Poly1305).
pub const NONCE_LEN: usize = 24;
/// Length of the encryption key (32 bytes / 256 bits).
pub const KEY_LEN: usize = 32;
