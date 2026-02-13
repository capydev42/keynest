use crate::error::StoreError;
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Store {
    secrets: HashMap<String, SecretEntry>,
    creation_date: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecretEntry {
    key: String,
    value: String,
    updated: String,
}

impl SecretEntry {
    pub(crate) fn new(key: String, value: String) -> Self {
        Self {
            key,
            value,
            updated: Local::now().to_string(),
        }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn updated(&self) -> &str {
        &self.updated
    }

    pub(crate) fn update_value(&mut self, new_value: String) {
        self.value = new_value;
        self.updated = Local::now().to_string();
    }
}

impl Store {
    pub fn new() -> Self {
        Store {
            secrets: HashMap::new(),
            creation_date: Local::now().to_string(),
        }
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<(), StoreError> {
        if self.secrets.contains_key(key) {
            Err(StoreError::KeyAlreadyExists(key.to_string()))
        } else {
            self.secrets.insert(
                key.to_string(),
                SecretEntry::new(key.to_string(), value.to_string()),
            );
            Ok(())
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.secrets.get(key).map(|e| e.value())
    }

    pub fn remove(&mut self, key: &str) -> Result<(), StoreError> {
        if self.secrets.remove(key).is_some() {
            Ok(())
        } else {
            Err(StoreError::KeyNotFound(key.to_string()))
        }
    }

    pub fn update(&mut self, key: &str, value: &str) -> Result<(), StoreError> {
        match self.secrets.get_mut(key) {
            Some(secret) => {
                secret.update_value(value.to_string());
                Ok(())
            }
            None => Err(StoreError::KeyNotFound(key.to_string())),
        }
    }
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.secrets.keys()
    }

    pub fn entries(&self) -> impl Iterator<Item = &SecretEntry> {
        self.secrets.values()
    }

    pub fn creation_date(&self) -> &str {
        &self.creation_date
    }

    pub fn len(&self) -> usize {
        self.secrets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_new_store_works() {
        let store = Store::new();
        assert_eq!(store.secrets.keys().count(), 0);
        assert_ne!(store.creation_date, "");
    }

    #[test]
    fn set_key_works() {
        let mut store = Store::new();
        store.set("A", "B").unwrap();
        assert_eq!(store.get("A").unwrap(), "B");
    }

    #[test]
    fn set_existing_key_fails() {
        let mut store = Store::new();
        store.set("A", "B").unwrap();
        match store.set("A", "C") {
            Err(StoreError::KeyAlreadyExists(k)) => assert_eq!(k, "A"),
            other => panic!("expected KeyAlreadyExists, got: {other:?}"),
        }
    }

    #[test]
    fn update_key_works() {
        let mut store = Store::new();
        store.set("A", "B").unwrap();
        store.update("A", "C").unwrap();
        assert_eq!(store.get("A").unwrap(), "C");
    }

    #[test]
    fn update_not_existing_key_fails() {
        let mut store = Store::new();
        match store.update("A", "B") {
            Err(StoreError::KeyNotFound(k)) => assert_eq!(k, "A"),
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn remove_key_works() {
        let mut store = Store::new();
        store.set("A", "B").unwrap();
        store.remove("A").unwrap();
        assert_eq!(store.get("A"), None);
    }

    #[test]
    fn remove_not_existing_key_fails() {
        let mut store = Store::new();
        match store.remove("A") {
            Err(StoreError::KeyNotFound(k)) => assert_eq!(k, "A"),
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
    }

    #[test]
    fn get_key_works() {
        let mut store = Store::new();
        store.set("A", "B").unwrap();
        assert_eq!(store.get("A").unwrap(), "B");
    }

    #[test]
    fn get_not_existing_key_fails() {
        let store = Store::new();
        assert_eq!(store.get("A"), None);
    }
}
