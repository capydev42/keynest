//! Cryptographic primitives for the keystore.
//!
//! Provides encryption and key derivation functions.
pub mod algorithm;
pub mod chacha20poly1305;
pub mod kdf;

pub use chacha20poly1305::generate_salt;
pub use kdf::{KdfParams, derive_key};

/// Length of the salt (16 bytes).
pub const SALT_LEN: usize = 16;
/// Length of the encryption key (32 bytes / 256 bits).
pub const KEY_LEN: usize = 32;
