mod crypto;
mod storage;
mod store;

use crate::store::SecretEntry;
use anyhow::{Result, bail};
use core::panic;
use storage::Storage;
use store::Store;

pub struct Keynest {
    store: Store,
    storage: Storage,
    key: [u8; 32],
    salt: [u8; 16],
}

impl Keynest {
    pub fn init(password: &str) -> Result<Self> {
        let storage = default_storage();
        Self::init_with_storage(password, storage)
    }

    pub fn init_with_storage(password: &str, storage: Storage) -> Result<Self> {
        if storage.exists() {
            bail!("Keynest store already exists");
        }

        let store = Store::new();
        let salt = crypto::generate_salt()?;
        let key = crypto::derive_key(password, &salt)?;

        let plaintext = serde_json::to_vec(&store)?;
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

    pub fn open(password: &str) -> Result<Self> {
        let storage = default_storage();
        Self::open_with_storage(password, storage)
    }

    pub fn open_with_storage(password: &str, storage: Storage) -> Result<Self> {
        if !storage.exists() {
            bail!("Keynest store does not exist");
        }

        let data = storage.load()?;

        if &data[0..4] != b"KNST" {
            bail!("Invalid keynest file");
        }

        let salt = &data[5..21];
        let nonce = &data[21..45];
        let ciphertext = &data[45..];

        let key = crypto::derive_key(password, salt)?;
        let plaintext = crypto::decrypt(&key, nonce, ciphertext)?;
        let store = serde_json::from_slice(&plaintext)?;

        Ok(Self {
            store,
            storage,
            key,
            salt: salt.try_into().unwrap(),
        })
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        if !self.store.set(key.to_string(), value.to_string()) {
            panic!("Could not set key {key}")
        } else {
            Ok(())
        }
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        self.store.get(key)
    }

    pub fn update(&mut self, key: &str, value: &str) -> Result<()> {
        if !self.store.update(key, value.to_string()) {
            panic!("Cound not update {key}")
        }

        Ok(())
    }

    pub fn remove(&mut self, key: &str) -> Result<()> {
        if !self.store.remove(key) {
            panic!("Key could not be removed")
        }
        Ok(())
    }

    pub fn list(&self) -> Vec<&String> {
        self.store.keys().collect()
    }

    pub fn list_all(&self) -> Vec<&SecretEntry> {
        self.store.entries().collect()
    }

    pub fn save(&self) -> Result<()> {
        let plaintext = serde_json::to_vec(&self.store)?;
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

fn default_storage() -> Storage {
    let path = std::env::current_dir().unwrap().join(".keynest.db");
    Storage::new(path)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn init_and_open_work() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keynest.db");
        let storage = Storage::new(path);
        let mut kn = Keynest::init_with_storage("pw", storage.clone()).unwrap();
        kn.set("A", "B").unwrap();
        kn.save().unwrap();

        let kn2 = Keynest::open_with_storage("pw", storage).unwrap();
        assert_eq!(kn2.get("A"), Some(&"B".to_string()));
    }

    #[test]
    fn init_fails_if_store_exists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keynest.db");
        let storage = Storage::new(path);

        Keynest::init_with_storage("pw", storage.clone()).unwrap();
        assert!(Keynest::init_with_storage("pw", storage).is_err());
    }

    #[test]
    fn wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path().join("keynest.db"));

        Keynest::init_with_storage("correct", storage.clone()).unwrap();
        assert!(Keynest::open_with_storage("wrong", storage).is_err());
    }
}
