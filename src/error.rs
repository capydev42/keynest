//! Error types for the keystore.

use std::fmt;

/// Errors that can occur when operating on a store.
#[derive(Debug)]
pub enum StoreError {
    /// A secret with this key already exists.
    KeyAlreadyExists(String),
    /// No secret with this key was found.
    KeyNotFound(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::KeyAlreadyExists(k) => write!(f, "secret '{k}' already exists"),
            StoreError::KeyNotFound(k) => write!(f, "secret '{k}' not found"),
        }
    }
}

impl std::error::Error for StoreError {}
