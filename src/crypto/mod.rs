pub mod aead;
pub mod header;
pub mod kdf;

pub use aead::{decrypt, encrypt, generate_salt};
pub use header::Header;
pub use kdf::{KdfParams, derive_key};

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;
pub const MAGIC_LEN: usize = 4;
pub const VER_LEN: usize = 1;
pub const MEM_LEN: usize = 4;
pub const TIME_LEN: usize = 4;
pub const PAR_LEN: usize = 4;
