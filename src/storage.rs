use anyhow::Result;
use std::fs;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Storage {
    path: PathBuf,
}

impl Storage {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn load(&self) -> Result<Vec<u8>> {
        Ok(fs::read(&self.path)?)
    }

    pub fn save(&self, data: &[u8]) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(fs::write(&self.path, data)?)
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}
