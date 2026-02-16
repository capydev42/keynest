//! Storage backend for keystore files.

use anyhow::Result;
use std::fs;
use std::path::PathBuf;

/// A storage backend for persisting keystore data.
///
/// `Storage` handles reading and writing encrypted keystore files
/// to the filesystem.
#[derive(Clone)]
pub struct Storage {
    path: PathBuf,
}

impl Storage {
    /// Creates a new Storage instance with the given path.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Returns `true` if the storage file exists.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Loads the entire storage file into memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn load(&self) -> Result<Vec<u8>> {
        Ok(fs::read(&self.path)?)
    }

    /// Saves data to the storage file.
    ///
    /// Creates parent directories if they don't exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save(&self, data: &[u8]) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(fs::write(&self.path, data)?)
    }

    /// Returns the path to the storage file.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}
