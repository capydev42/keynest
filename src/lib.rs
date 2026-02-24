//! Keynest - Simple, offline, cross-platform secrets manager
//!
//! Keynest provides secure local secret storage using Argon2id for key derivation
//! and XChaCha20-Poly1305 for authenticated encryption.
//!
//! # Security
//!
//! For detailed cryptographic architecture, see [CRYPTO.md](https://github.com/capydev42/keynest/blob/main/CRYPTO.md).
//! For security policy and vulnerability reporting, see [SECURITY.md](https://github.com/capydev42/keynest/blob/main/SECURITY.md).
//!
//! # Quick Start
//!
//! ```ignore
//! use keynest::{Keynest, Storage};
//! use zeroize::Zeroizing;
//!
//! // Create a new keystore
//! let mut kn = Keynest::init(Zeroizing::new("password".to_string())).unwrap();
//!
//! // Store secrets
//! kn.set("api_key", "secret123").unwrap();
//! kn.save().unwrap();
//!
//! // Later: reopen the keystore
//! let kn = Keynest::open(Zeroizing::new("password".to_string())).unwrap();
//! assert_eq!(kn.get("api_key"), Some("secret123"));
//! ```

mod crypto;
mod error;
mod format;
mod storage;
mod store;

pub use crate::crypto::KdfParams;
use crate::format::{KeystoreFile, parse, serialize};
pub use crate::storage::Storage;
use crate::store::SecretEntry;
use anyhow::{Context, Result, bail};
use directories::ProjectDirs;
use std::path::PathBuf;
use store::Store;
use zeroize::{Zeroize, Zeroizing};

/// A secure keystore for storing secrets locally.
///
/// `Keynest` provides methods to initialize, open, and manage a local encrypted
/// keystore. All secrets are encrypted at rest using XChaCha20-Poly1305 with a
/// key derived from your password using Argon2id.
///
/// The struct holds sensitive data (encryption key) which is zeroized on drop
/// for secure memory handling.
///
/// # Example
///
/// ```ignore
/// use keynest::{Keynest, KdfParams, Storage};
/// use zeroize::Zeroizing;
///
/// let storage = Storage::new("/path/to/keystore.db");
/// let kdf = KdfParams::default();
/// let mut kn = Keynest::init_with_storage_and_kdf(Zeroizing::new("password"), storage, kdf).unwrap();
/// kn.set("key", "value").unwrap();
/// kn.save().unwrap();
/// ```
pub struct Keynest {
    store: Store,
    storage: Storage,
    key: [u8; 32],
    keystore_file: KeystoreFile,
}

impl Drop for Keynest {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Keynest {
    /// Creates a new keystore with the default KDF parameters.
    ///
    /// Uses default storage location (`~/.local/share/keynest/.keynest.db` on Linux).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A keystore already exists at the default location
    /// - Key derivation fails
    /// - Encryption fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// use keynest::Keynest;
    /// use zeroize::Zeroizing;
    ///
    /// let kn = Keynest::init(Zeroizing::new("password".to_string())).unwrap();
    /// ```
    pub fn init(password: Zeroizing<String>) -> Result<Self> {
        Self::init_with_kdf(password, KdfParams::default())
    }

    /// Creates a new keystore with custom KDF parameters.
    ///
    /// Uses default storage location. Useful for customizing Argon2 settings.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use keynest::{Keynest, KdfParams};
    /// use zeroize::Zeroizing;
    ///
    /// let kdf = KdfParams::new(131072, 4, 2).unwrap();
    /// let kn = Keynest::init_with_kdf(Zeroizing::new("password".to_string()), kdf).unwrap();
    /// ```
    pub fn init_with_kdf(password: Zeroizing<String>, kdf: KdfParams) -> Result<Self> {
        let storage = default_storage()?;
        Self::init_with_storage_and_kdf(password, storage, kdf)
    }

    /// Creates a new keystore with custom storage location and KDF parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A keystore already exists at the given storage path
    /// - Key derivation fails
    /// - Encryption fails
    pub fn init_with_storage_and_kdf(
        password: Zeroizing<String>,
        storage: Storage,
        kdf: KdfParams,
    ) -> Result<Self> {
        if storage.exists() {
            bail!("keynest store already exists");
        }

        let store = Store::new();
        let salt = crypto::generate_salt()?;
        let key =
            crypto::derive_key(&password, &salt, kdf).context("failed to derive encryption key")?;

        drop(password);

        let plaintext = Zeroizing::new(serde_json::to_vec(&store)?);
        let (ciphertext, nonce) = crypto::encrypt(&key, &plaintext)?;

        let keystore_file =
            KeystoreFile::new(kdf, salt.to_vec(), nonce.to_vec(), ciphertext.to_vec());
        let file = serialize(&keystore_file)?;
        storage.save(&file)?;

        Ok(Self {
            store,
            storage,
            key,
            keystore_file,
        })
    }

    /// Opens an existing keystore with the default storage location.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No keystore exists at the default location
    /// - The password is incorrect
    /// - The keystore is corrupted
    pub fn open(password: Zeroizing<String>) -> Result<Self> {
        let storage = default_storage()?;
        Self::open_with_storage(password, storage)
    }

    /// Opens an existing keystore from a custom storage location.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No keystore exists at the given storage path
    /// - The password is incorrect
    /// - The keystore is corrupted
    pub fn open_with_storage(password: Zeroizing<String>, storage: Storage) -> Result<Self> {
        if !storage.exists() {
            bail!("keynest store does not exist");
        }

        let data = storage.load()?;
        let keystore_file = parse(&data)?;

        let key = crypto::derive_key(&password, keystore_file.salt(), *keystore_file.kdf())
            .context("unable to derive encryption key")?;
        drop(password);

        let plaintext = crypto::decrypt(&key, keystore_file.nonce(), keystore_file.ciphertext())?;
        let store = serde_json::from_slice(&plaintext)
            .context("failed to deserialize keystore; possibly wrong password or corrupted data")?;

        Ok(Self {
            store,
            storage,
            key,
            keystore_file,
        })
    }

    /// Stores a secret in the keystore.
    ///
    /// # Errors
    ///
    /// Returns an error if a secret with the given key already exists.
    /// Use `update` to change an existing secret.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        self.store.set(key, value)?;
        Ok(())
    }

    /// Retrieves a secret by key.
    ///
    /// Returns `None` if the key does not exist.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.store.get(key)
    }

    /// Updates an existing secret's value.
    ///
    /// # Errors
    ///
    /// Returns an error if the key does not exist.
    /// Use `set` to create a new secret.
    pub fn update(&mut self, key: &str, value: &str) -> Result<()> {
        self.store.update(key, value)?;
        Ok(())
    }

    /// Removes a secret from the keystore.
    ///
    /// # Errors
    ///
    /// Returns an error if the key does not exist.
    pub fn remove(&mut self, key: &str) -> Result<()> {
        self.store.remove(key)?;
        Ok(())
    }

    /// Lists all secret keys.
    ///
    /// Returns a vector of references to the key strings.
    pub fn list(&self) -> Vec<&String> {
        self.store.keys().collect()
    }

    /// Lists all secrets with their metadata.
    ///
    /// Returns a vector of references to `SecretEntry` containing
    /// key, value, and update timestamp.
    pub fn list_all(&self) -> Vec<&SecretEntry> {
        self.store.entries().collect()
    }

    /// Persists the keystore to storage.
    ///
    /// Must be called after making changes (set, update, remove)
    /// to save them to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to storage fails.
    pub fn save(&mut self) -> Result<()> {
        let plaintext = Zeroizing::new(serde_json::to_vec(&self.store)?);
        let (ciphertext, nonce) = crypto::encrypt(&self.key, &plaintext)?;

        self.keystore_file = KeystoreFile::new(
            *self.keystore_file.kdf(),
            self.keystore_file.salt().to_vec(),
            nonce.to_vec(),
            ciphertext.to_vec(),
        );
        let file = serialize(&self.keystore_file)?;
        self.storage.save(&file)?;
        Ok(())
    }

    /// Returns information about the keystore.
    ///
    /// Includes file path, size, creation date, secret count,
    /// and KDF/encryption parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage metadata cannot be read.
    pub fn info(&self) -> Result<StoreInfo> {
        let metadata = std::fs::metadata(self.storage.path())?;
        Ok(StoreInfo {
            path: self.storage.path().to_path_buf(),
            file_size: metadata.len(),
            creation_date: self.store.creation_date().to_string(),
            secrets_count: self.store.len(),
            kdf: *self.keystore_file.kdf(),
            algorithm: "ChaCha20-Poly1305",
            nonce_len: self.keystore_file.nonce().len(),
            version: self.keystore_file.version(),
        })
    }

    /// Changes the password and/or KDF parameters.
    ///
    /// Re-encrypts the keystore with a new key derived from the new password
    /// and optional new KDF parameters. The existing secrets are preserved.
    ///
    /// # Arguments
    ///
    /// * `new_password` - The new password to derive the encryption key from
    /// * `new_kdf` - The new KDF parameters (can be different from current)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Key derivation fails
    /// - Encryption fails
    /// - Writing to storage fails
    pub fn rekey(&mut self, new_password: Zeroizing<String>, new_kdf: KdfParams) -> Result<()> {
        let new_salt = crypto::generate_salt()?;

        let new_key = crypto::derive_key(&new_password, &new_salt, new_kdf)
            .context("failed to derive new enryption key")?;

        drop(new_password);

        let plaintext = Zeroizing::new(serde_json::to_vec(&self.store)?);
        let (ciphertext, nonce) = crypto::encrypt(&new_key, &plaintext)?;

        self.keystore_file =
            KeystoreFile::new(new_kdf, new_salt.to_vec(), nonce.to_vec(), ciphertext);
        let file = serialize(&self.keystore_file)?;
        self.storage.save(&file)?;

        self.key.zeroize();
        self.key = new_key;

        Ok(())
    }
}

/// Returns the default storage location for the keystore.
///
/// The default location is platform-specific:
/// - Linux: `~/.local/share/keynest/.keynest.db`
/// - macOS: `~/Library/Application Support/keynest/.keynest.db`
/// - Windows: `%APPDATA%\keynest\.keynest.db`
///
/// # Errors
///
/// Returns an error if the platform-specific directories cannot be determined.
pub fn default_storage() -> Result<Storage> {
    let project_dirs =
        ProjectDirs::from("", "", "keynest").context("could not determine platform directories")?;

    let path = project_dirs.data_dir().join(".keynest.db");

    Ok(Storage::new(path))
}

/// Information about a keystore.
///
/// Returned by [`Keynest::info`].
pub struct StoreInfo {
    path: PathBuf,
    file_size: u64,
    creation_date: String,
    secrets_count: usize,
    kdf: KdfParams,
    algorithm: &'static str,
    nonce_len: usize,
    version: u8,
}

impl StoreInfo {
    /// Returns the keystore creation date.
    pub fn creation_date(&self) -> &str {
        &self.creation_date
    }

    /// Returns the number of secrets stored.
    pub fn secrets_count(&self) -> usize {
        self.secrets_count
    }

    /// Returns the KDF parameters used for key derivation.
    pub fn kdf(&self) -> &KdfParams {
        &self.kdf
    }
}

impl std::fmt::Display for StoreInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Keynest Store Information")?;
        writeln!(f, "────────────────────────────────────────")?;
        writeln!(f)?;

        writeln!(f, "Location")?;
        writeln!(f, "  Path:              {}", self.path.display())?;
        writeln!(f, "  Size:              {} bytes", self.file_size)?;
        writeln!(f, "  Format version:    {}", self.version)?;
        writeln!(f)?;

        writeln!(f, "Metadata")?;
        writeln!(f, "  Created:           {}", self.creation_date)?;
        writeln!(f, "  Secrets stored:    {}", self.secrets_count)?;
        writeln!(f)?;

        writeln!(f, "Encryption")?;
        writeln!(f, "  Algorithm:         {}", self.algorithm)?;
        writeln!(f, "  Nonce length:      {} bytes", self.nonce_len)?;
        writeln!(f)?;

        writeln!(f, "Key Derivation")?;
        writeln!(f, "  Memory:            {} KiB", self.kdf.mem_cost_kib())?;
        writeln!(f, "  Time cost:         {}", self.kdf.time_cost())?;
        writeln!(f, "  Parallelism:       {}", self.kdf.parallelism())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        use crate::crypto::*;
        use crate::format::{KeystoreFile, parse, serialize};

        let kdf = KdfParams::default();
        let salt = generate_salt().unwrap();
        let key = derive_key("pw", &salt, kdf).unwrap();

        let data = b"secret data".to_vec();
        let (ciphertext, nonce) = encrypt(&key, &data).unwrap();

        let keystore_file = KeystoreFile::new(kdf, salt.to_vec(), nonce.to_vec(), ciphertext);
        let file = serialize(&keystore_file).unwrap();

        let keystore_file2 = parse(&file).unwrap();
        let key2 = derive_key("pw", keystore_file2.salt(), *keystore_file2.kdf()).unwrap();
        let plaintext =
            decrypt(&key2, keystore_file2.nonce(), keystore_file2.ciphertext()).unwrap();

        assert_eq!(*plaintext, data);
    }

    #[test]
    fn init_and_open_with_zeroize_wrappers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keynest.db");
        let storage = Storage::new(path);
        let password = Zeroizing::new(String::from("pw"));
        let mut kn =
            Keynest::init_with_storage_and_kdf(password, storage.clone(), KdfParams::default())
                .unwrap();
        kn.set("A", "B").unwrap();
        kn.save().unwrap();

        let password = Zeroizing::new(String::from("pw"));
        let kn2 = Keynest::open_with_storage(password, storage).unwrap();
        assert_eq!(kn2.get("A"), Some("B"));
    }

    #[test]
    fn init_fails_if_store_exists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keynest.db");
        let storage = Storage::new(path);

        let password = Zeroizing::new(String::from("pw"));
        Keynest::init_with_storage_and_kdf(password, storage.clone(), KdfParams::default())
            .unwrap();
        let password = Zeroizing::new(String::from("pw"));
        assert!(
            Keynest::init_with_storage_and_kdf(password, storage, KdfParams::default()).is_err()
        );
    }

    #[test]
    fn wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        Keynest::init_with_storage_and_kdf(
            Zeroizing::new("correct".to_string()),
            storage.clone(),
            KdfParams::default(),
        )
        .unwrap();
        assert!(Keynest::open_with_storage(Zeroizing::new("wrong".to_string()), storage).is_err());
    }

    #[test]
    fn set_existing_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        let mut kn = Keynest::init_with_storage_and_kdf(
            Zeroizing::new("pw".to_string()),
            storage.clone(),
            KdfParams::default(),
        )
        .unwrap();
        kn.set("A", "B").unwrap();
        assert!(kn.set("A", "C").is_err());
    }

    #[test]
    fn update_key_works() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        let mut kn = Keynest::init_with_storage_and_kdf(
            Zeroizing::new("pw".to_string()),
            storage.clone(),
            KdfParams::default(),
        )
        .unwrap();
        kn.set("A", "B").unwrap();
        kn.update("A", "C").unwrap();
        assert_eq!(kn.get("A").unwrap(), "C");
    }

    #[test]
    fn update_not_existing_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        let mut kn = Keynest::init_with_storage_and_kdf(
            Zeroizing::new("pw".to_string()),
            storage.clone(),
            KdfParams::default(),
        )
        .unwrap();
        kn.set("A", "B").unwrap();
        assert!(kn.update("Z", "C").is_err());
    }

    #[test]
    fn removing_key_works() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        let mut kn = Keynest::init_with_storage_and_kdf(
            Zeroizing::new("pw".to_string()),
            storage.clone(),
            KdfParams::default(),
        )
        .unwrap();
        kn.set("A", "B").unwrap();

        assert_eq!(kn.get("A").unwrap(), "B");
        kn.remove("A").unwrap();
        assert_eq!(kn.get("A"), None);
    }

    #[test]
    fn removing_not_existing_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        let mut kn = Keynest::init_with_storage_and_kdf(
            Zeroizing::new("pw".to_string()),
            storage.clone(),
            KdfParams::default(),
        )
        .unwrap();
        assert!(kn.remove("A").is_err());
    }

    #[test]
    fn list_works() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        let mut kn = Keynest::init_with_storage_and_kdf(
            Zeroizing::new("pw".to_string()),
            storage.clone(),
            KdfParams::default(),
        )
        .unwrap();
        kn.set("A", "B").unwrap();

        assert!(kn.list().contains(&&"A".to_string()));
        assert!(!kn.list().contains(&&"B".to_string()));
    }

    #[test]
    fn list_all_works() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        let mut kn = Keynest::init_with_storage_and_kdf(
            Zeroizing::new("pw".to_string()),
            storage.clone(),
            KdfParams::default(),
        )
        .unwrap();
        kn.set("A", "B").unwrap();
        for sec_entry in kn.list_all() {
            assert_eq!(sec_entry.key(), "A");
            assert_eq!(sec_entry.value(), "B");
            assert_ne!(sec_entry.updated(), "");
        }
    }

    #[test]
    fn rekey_changes_password() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        let mut kn = Keynest::init_with_storage_and_kdf(
            Zeroizing::new("old".to_string()),
            storage.clone(),
            KdfParams::default(),
        )
        .unwrap();
        kn.set("A", "B").unwrap();
        kn.save().unwrap();

        //reopen
        let mut kn =
            Keynest::open_with_storage(Zeroizing::new("old".to_string()), storage.clone()).unwrap();

        //rekey
        kn.rekey(Zeroizing::new("new".to_string()), KdfParams::default())
            .unwrap();

        assert!(
            Keynest::open_with_storage(Zeroizing::new("old".to_string()), storage.clone()).is_err()
        );

        let kn2 = Keynest::open_with_storage(Zeroizing::new("new".to_string()), storage).unwrap();

        assert_eq!(kn2.get("A"), Some("B"));
    }

    #[test]
    fn rekey_changes_kdf_parameters() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        let original_kdf = KdfParams::default();

        // init
        let mut kn = Keynest::init_with_storage_and_kdf(
            Zeroizing::new("pw".to_string()),
            storage.clone(),
            original_kdf,
        )
        .unwrap();

        kn.save().unwrap();

        // reopen
        let mut kn =
            Keynest::open_with_storage(Zeroizing::new("pw".to_string()), storage.clone()).unwrap();

        // neue Parameter
        let new_kdf = KdfParams::new(
            original_kdf.mem_cost_kib() * 2,
            original_kdf.time_cost() + 1,
            original_kdf.parallelism(),
        )
        .unwrap();

        kn.rekey(Zeroizing::new("pw".to_string()), new_kdf).unwrap();

        // reopen mit neuem password
        let kn2 = Keynest::open_with_storage(Zeroizing::new("pw".to_string()), storage).unwrap();

        assert_eq!(
            kn2.keystore_file.kdf().mem_cost_kib(),
            new_kdf.mem_cost_kib()
        );
        assert_eq!(kn2.keystore_file.kdf().time_cost(), new_kdf.time_cost());
    }
}
