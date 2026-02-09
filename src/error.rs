use std::fmt;

#[derive(Debug)]
pub enum StoreError {
    KeyAlreadyExists(String),
    KeyNotFound(String),
}

impl fmt::Display for StoreError{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::KeyAlreadyExists(k) => write!(f, "secret '{k}' already exists"),
            StoreError::KeyNotFound(k) => write!(f, "secret '{k}' not found"),
        }
    }
}

impl std::error::Error for StoreError {}
