//! Storage backend for keystore files.

use anyhow::{Context, Result};
use getrandom::fill;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

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

    /// Saves data to the storage file using atomic write.
    ///
    /// This method ensures crash-safety by:
    /// 1. Writing data to a temporary file with random name
    /// 2. Syncing the temporary file to disk
    /// 3. Atomically replacing the old file with the new one
    /// 4. Syncing the parent directory to ensure the rename is persisted
    ///
    /// If a crash occurs during save, either the old or new file will be present,
    /// never a corrupted partial write.
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

        let tmp_path = self.random_tmp_path()?;

        // securely create temp file (fail if exists)
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .context("failed to create temporary file")?;

        // write data
        tmp_file.write_all(data)?;
        tmp_file.sync_all()?; //fsync file
        drop(tmp_file);

        //atomic replace
        if let Err(e) = self.atomic_replace(&tmp_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }

        // fsync directory
        if let Some(parent) = self.path.parent() {
            let dir = File::open(parent)?;
            dir.sync_all()?;
        }

        Ok(())
    }

    /// Returns the path to the storage file.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Generates a unique temporary file path in the same directory.
    ///
    /// Uses cryptographically secure random bytes to avoid name collisions.
    /// Format: `filename.tmp.<randomhex>`
    fn random_tmp_path(&self) -> Result<PathBuf> {
        let mut buf = [0u8; 8]; // 64 bit entropy
        fill(&mut buf)?;

        let rand_string = buf.iter().map(|b| format!("{:02x}", b)).collect::<String>();

        let file_name = self.path.file_name().unwrap().to_string_lossy();

        let tmp_name = format!("{}.tmp.{}", file_name, rand_string);

        Ok(self.path.with_file_name(tmp_name))
    }

    /// Atomically replaces the target file with the temporary file.
    ///
    /// Uses Windows `ReplaceFileW` API with `REPLACEFILE_WRITE_THROUGH` flag
    /// to ensure the operation is truly atomic and persisted to disk.
    #[cfg(target_os = "windows")]
    fn atomic_replace(&self, tmp_path: &Path) -> Result<()> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{REPLACEFILE_WRITE_THROUGH, ReplaceFileW};

        fn to_wide(s: &OsStr) -> Vec<u16> {
            s.encode_wide().chain(std::iter::once(0)).collect()
        }

        let target_w = to_wide(self.path.as_os_str());
        let tmp_w = to_wide(tmp_path.as_os_str());

        // SAFETY:
        // - Strings are valid UTF-16 and null-terminated
        // - Pointers remain valid during the call
        // - Windows does not retain the pointers after return
        let result = unsafe {
            ReplaceFileW(
                target_w.as_ptr(),
                tmp_w.as_ptr(),
                std::ptr::null(),
                REPLACEFILE_WRITE_THROUGH,
                std::ptr::null(),
                std::ptr::null(),
            )
        };

        if result == 0 {
            let err = std::io::Error::last_os_error();
            return Err(err).context("atomic replace failed");
        }

        Ok(())
    }

    /// Atomically replaces the target file with the temporary file.
    ///
    /// On Unix, `rename()` is atomic when both paths are on the same filesystem.
    #[cfg(not(target_os = "windows"))]
    fn atomic_replace(&self, tmp_path: &Path) -> Result<()> {
        fs::rename(tmp_path, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    // --------------------------------------------------
    // LOAD TESTS
    // --------------------------------------------------

    #[test]
    fn load_returns_written_data() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");

        let storage = Storage::new(path.clone());
        storage.save(b"hello world").unwrap();

        let data = storage.load().unwrap();
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn load_fails_if_file_does_not_exist() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.db");

        let storage = Storage::new(path);

        let result = storage.load();
        assert!(result.is_err());
    }

    // --------------------------------------------------
    // EXISTS TESTS
    // --------------------------------------------------

    #[test]
    fn exists_returns_false_if_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");

        let storage = Storage::new(path);
        assert!(!storage.exists());
    }

    #[test]
    fn exists_returns_true_after_save() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");

        let storage = Storage::new(path.clone());
        storage.save(b"data").unwrap();

        assert!(storage.exists());
    }

    // --------------------------------------------------
    // RANDOM TMP PATH TESTS
    // --------------------------------------------------

    #[test]
    fn random_tmp_path_has_same_parent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");

        let storage = Storage::new(path.clone());

        let tmp = storage.random_tmp_path().unwrap();

        assert_eq!(tmp.parent(), path.parent());
    }

    #[test]
    fn random_tmp_path_is_not_equal_to_final_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");

        let storage = Storage::new(path.clone());

        let tmp = storage.random_tmp_path().unwrap();

        assert_ne!(tmp, path);
    }

    #[test]
    fn tmp_names_are_unique() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");

        let storage = Storage::new(path);

        let a = storage.random_tmp_path().unwrap();
        let b = storage.random_tmp_path().unwrap();

        assert_ne!(a, b);
    }

    // --------------------------------------------------
    // SAVE EDGE CASES
    // --------------------------------------------------

    #[test]
    fn save_overwrites_large_data() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");

        let storage = Storage::new(path.clone());

        let large = vec![42u8; 10_000];
        storage.save(&large).unwrap();

        let loaded = storage.load().unwrap();
        assert_eq!(loaded.len(), 10_000);
        assert_eq!(loaded, large);
    }

    #[test]
    fn save_replaces_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");

        let storage = Storage::new(path.clone());

        storage.save(b"first").unwrap();
        storage.save(b"second").unwrap();

        let content = fs::read(path).unwrap();
        assert_eq!(content, b"second");
    }

    #[test]
    fn tmp_file_is_removed_after_success() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("store.db");

        let storage = Storage::new(path.clone());
        storage.save(b"data").unwrap();

        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], "store.db");
    }

    #[test]
    fn parent_directory_is_created() {
        let dir = tempdir().unwrap();

        let nested = dir.path().join("a").join("b").join("c").join("store.db");

        let storage = Storage::new(nested.clone());
        storage.save(b"data").unwrap();

        assert!(nested.exists());
    }
}
