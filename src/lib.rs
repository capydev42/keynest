mod crypto;
mod storage;
mod error;
mod store;

use crate::store::SecretEntry;
use anyhow::{Context, Result, bail};
use crypto::{MAGIC_LEN, NONCE_LEN, SALT_LEN, VER_LEN};
use storage::Storage;
use store::Store;
use zeroize::{Zeroize, Zeroizing};

pub struct Keynest {
    store: Store,
    storage: Storage,
    key: [u8; 32],
    salt: [u8; 16],
}

impl Drop for Keynest {
    fn drop(&mut self) {
        self.key.zeroize();
        self.salt.zeroize();
    }
}

impl Keynest {
    pub fn init(password: Zeroizing<String>) -> Result<Self> {
        let storage = default_storage()?;
        Self::init_with_storage(password, storage)
    }

    pub fn init_with_storage(password: Zeroizing<String>, storage: Storage) -> Result<Self> {
        if storage.exists() {
            bail!("Keynest store already exists");
        }

        let store = Store::new();
        let salt = crypto::generate_salt()?;
        let key = crypto::derive_key(&*password, &salt)?;

        drop(password);

        let plaintext = Zeroizing::new(serde_json::to_vec(&store)?);
        let (ciphertext, nonce) = crypto::encrypt(&key, &plaintext)?;

        let mut file = Vec::new();
        file.extend_from_slice(b"KNST");
        file.push(1);
        file.extend_from_slice(&salt);
        file.extend_from_slice(&nonce);
        file.extend_from_slice(&ciphertext);
        storage.save(&file)?;

        Ok(Self {
            store,
            storage,
            key,
            salt,
        })
    }

    pub fn open(password: Zeroizing<String>) -> Result<Self> {
        let storage = default_storage()?;
        Self::open_with_storage(password, storage)
    }

    pub fn open_with_storage(password: Zeroizing<String>, storage: Storage) -> Result<Self> {
        if !storage.exists() {
            bail!("Keynest store does not exist");
        }

        const MIN_LEN: usize = MAGIC_LEN + VER_LEN + SALT_LEN + NONCE_LEN;

        let data = storage.load()?;

        if data.len() < MIN_LEN {
            bail!("Keynest file too short or corrupted");
        }

        if &data[0..MAGIC_LEN] != b"KNST" {
            bail!("Invalid keynest file");
        }

        let salt = &data[MAGIC_LEN + VER_LEN..MAGIC_LEN + VER_LEN + SALT_LEN];
        let nonce = &data[MAGIC_LEN + VER_LEN + SALT_LEN..MIN_LEN];
        let ciphertext = &data[MIN_LEN..];

        let key = crypto::derive_key(&*password, salt)?;
        drop(password);

        let plaintext = crypto::decrypt(&key, nonce, ciphertext)?;
        let store = serde_json::from_slice(&plaintext)
            .context("failed to deserialize keystore; possibly wrong password or corrupted data")?;
        let salt_arr: [u8; 16] = salt
            .try_into()
            .context("invalid salt length in keynest file")?;

        Ok(Self {
            store,
            storage,
            key,
            salt: salt_arr,
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

        let mut file = Vec::new();
        file.extend_from_slice(b"KNST");
        file.push(1);
        file.extend_from_slice(&self.salt);
        file.extend_from_slice(&nonce);
        file.extend_from_slice(&ciphertext);
        self.storage.save(&file)?;
        Ok(())
    }
}

fn default_storage() -> Result<Storage> {
    let path = std::env::current_dir()
        .context("could not determine current directory")?
        .join(".keynest.db");
    Ok(Storage::new(path))
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn init_and_open_with_zeroize_wrappers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keynest.db");
        let storage = Storage::new(path);
        let password = Zeroizing::new(String::from("pw"));
        let mut kn = Keynest::init_with_storage(password, storage.clone()).unwrap();
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
        Keynest::init_with_storage(password, storage.clone()).unwrap();
        let password = Zeroizing::new(String::from("pw"));
        assert!(Keynest::init_with_storage(password, storage).is_err());
    }

    #[test]
    fn wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        Keynest::init_with_storage(Zeroizing::new("correct".to_string()), storage.clone()).unwrap();
        assert!(Keynest::open_with_storage(Zeroizing::new("wrong".to_string()), storage).is_err());
    }

    #[test]
    fn set_existing_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        let mut kn = Keynest::init_with_storage(Zeroizing::new("pw".to_string()), storage.clone()).unwrap();
        kn.set("A", "B").unwrap();
        assert!(kn.set("A", "C").is_err());
    }

    #[test]
    fn update_key_works(){
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        let mut kn = Keynest::init_with_storage(Zeroizing::new("pw".to_string()), storage.clone()).unwrap();
        kn.set("A", "B").unwrap();
        kn.update("A", "C").unwrap();
        assert_eq!(kn.get("A").unwrap(), "C");
    }

    #[test]
    fn update_not_existing_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        let mut kn = Keynest::init_with_storage(Zeroizing::new("pw".to_string()), storage.clone()).unwrap();
        kn.set("A", "B").unwrap();
        assert!(kn.update("Z", "C").is_err());
    }

    #[test]
    fn removing_key_works(){
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        let mut kn = Keynest::init_with_storage(Zeroizing::new("pw".to_string()), storage.clone()).unwrap();
        kn.set("A", "B").unwrap();

        assert_eq!(kn.get("A").unwrap(), "B");
        kn.remove("A").unwrap();
        assert_eq!(kn.get("A"), None);
    }

    #[test]
    fn removing_not_existing_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        let mut kn = Keynest::init_with_storage(Zeroizing::new("pw".to_string()), storage.clone()).unwrap();
        assert!(kn.remove("A").is_err());
    }

    #[test]
    fn list_works() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        let mut kn = Keynest::init_with_storage(Zeroizing::new("pw".to_string()), storage.clone()).unwrap();
        kn.set("A", "B").unwrap();

        assert!(kn.list().contains(&&"A".to_string()));
        assert!(!kn.list().contains(&&"B".to_string()));
    }

    #[test]
    fn list_all_works() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        let mut kn = Keynest::init_with_storage(Zeroizing::new("pw".to_string()), storage.clone()).unwrap();
        kn.set("A", "B").unwrap();
        for sec_entry in kn.list_all(){
            assert_eq!(sec_entry.key(), "A");
            assert_eq!(sec_entry.value(), "B");
            assert_ne!(sec_entry.updated(), "");
        }
    }
}
