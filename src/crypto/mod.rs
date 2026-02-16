//! Cryptographic primitives for the keystore.
//!
//! Provides encryption, key derivation, and file header handling.

pub mod aead;
pub mod header;
pub mod kdf;

pub use aead::{decrypt, encrypt, generate_salt};
pub use header::Header;
pub use kdf::{KdfParams, derive_key};

/// Length of the salt (16 bytes).
pub const SALT_LEN: usize = 16;
/// Length of the nonce (24 bytes for XChaCha20-Poly1305).
pub const NONCE_LEN: usize = 24;
/// Length of the encryption key (32 bytes / 256 bits).
pub const KEY_LEN: usize = 32;
/// Length of the magic bytes (4 bytes "KNST").
pub const MAGIC_LEN: usize = 4;
/// Length of the version field (1 byte).
pub const VER_LEN: usize = 1;
/// Length of the memory cost field (4 bytes).
pub const MEM_LEN: usize = 4;
/// Length of the time cost field (4 bytes).
pub const TIME_LEN: usize = 4;
/// Length of the parallelism field (4 bytes).
pub const PAR_LEN: usize = 4;
