mod crypto;
mod error;
mod storage;
mod store;

pub use crate::crypto::KdfParams;
pub use crate::storage::Storage;
use crate::{crypto::Header, store::SecretEntry};
use anyhow::{bail, Context, Result};
use directories::ProjectDirs;
use store::Store;
use zeroize::{Zeroize, Zeroizing};

pub struct Keynest {
    store: Store,
    storage: Storage,
    key: [u8; 32],
    salt: [u8; 16],
    kdf: KdfParams,
}

impl Drop for Keynest {
    fn drop(&mut self) {
        self.key.zeroize();
        self.salt.zeroize();
    }
}

impl Keynest {
    pub fn init(password: Zeroizing<String>) -> Result<Self> {
        Self::init_with_kdf(password, KdfParams::default())
    }

    pub fn init_with_kdf(password: Zeroizing<String>, kdf: KdfParams) -> Result<Self> {
        let storage = default_storage()?;
        Self::init_with_storage_and_kdf(password, storage, kdf)
    }

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

        let header = Header::new(kdf, salt, nonce)?;

        let mut file = header.to_bytes();
        file.extend_from_slice(&ciphertext);
        storage.save(&file)?;

        Ok(Self {
            store,
            storage,
            key,
            salt,
            kdf,
        })
    }

    pub fn open(password: Zeroizing<String>) -> Result<Self> {
        let storage = default_storage()?;
        Self::open_with_storage(password, storage)
    }

    pub fn open_with_storage(password: Zeroizing<String>, storage: Storage) -> Result<Self> {
        if !storage.exists() {
            bail!("keynest store does not exist");
        }

        let data = storage.load()?;

        let (header, offset) = Header::from_bytes(&data)?;
        let key = crypto::derive_key(&password, header.salt(), *header.kdf())
            .context("unable to derive encryption key")?;
        drop(password);

        let plaintext = crypto::decrypt(&key, header.nonce(), &data[offset..])?;
        let store = serde_json::from_slice(&plaintext)
            .context("failed to deserialize keystore; possibly wrong password or corrupted data")?;

        Ok(Self {
            store,
            storage,
            key,
            salt: *header.salt(),
            kdf: *header.kdf(),
        })
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        self.store.set(key, value)?;
        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.store.get(key)
    }

    pub fn update(&mut self, key: &str, value: &str) -> Result<()> {
        self.store.update(key, value)?;
        Ok(())
    }

    pub fn remove(&mut self, key: &str) -> Result<()> {
        self.store.remove(key)?;
        Ok(())
    }

    pub fn list(&self) -> Vec<&String> {
        self.store.keys().collect()
    }

    pub fn list_all(&self) -> Vec<&SecretEntry> {
        self.store.entries().collect()
    }

    pub fn save(&self) -> Result<()> {
        let plaintext = Zeroizing::new(serde_json::to_vec(&self.store)?);
        let (ciphertext, nonce) = crypto::encrypt(&self.key, &plaintext)?;

        let header = Header::new(self.kdf, self.salt, nonce)?;

        let mut file = header.to_bytes();
        file.extend_from_slice(&ciphertext);
        self.storage.save(&file)?;
        Ok(())
    }
}

pub fn default_storage() -> Result<Storage> {
    let project_dirs =
        ProjectDirs::from("", "", "keynest").context("could not determine platform directories")?;

    let path = project_dirs.data_dir().join(".keynest.db");

    Ok(Storage::new(path))
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn encrypt_decrypt_with_header_roundtrip() {
        use crate::crypto::*;

        let kdf = KdfParams::default();
        let salt = generate_salt().unwrap();
        let key = derive_key("pw", &salt, kdf).unwrap();

        let data = b"secret data".to_vec();
        let (ciphertext, nonce) = encrypt(&key, &data).unwrap();

        let header = Header::new(kdf, salt, nonce).unwrap();

        let mut file = header.to_bytes();
        file.extend_from_slice(&ciphertext);

        let (parsed, offset) = Header::from_bytes(&file).unwrap();
        let key2 = derive_key("pw", parsed.salt(), *parsed.kdf()).unwrap();
        let plaintext = decrypt(&key2, parsed.nonce(), &file[offset..]).unwrap();

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
}
