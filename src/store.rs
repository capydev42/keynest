use chrono::Local;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Store {
    secrets: HashMap<String, SecretEntry>,
    encryption: String,
    creation_date: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SecretEntry {
    // i don not like that the field are 'pub' need to chenge this
    pub key: String,
    pub value: String,
    pub updated: String,
}

impl Store {
    pub fn new() -> Self {
        Store {
            secrets: HashMap::new(),
            encryption: "not encrypted".to_string(),
            creation_date: Local::now().to_string(),
        }
    }

    pub fn set(&mut self, key: String, value: String) -> bool {
        if self.secrets.contains_key(&key) {
            println!("Secret '{key}' alerady exists. Please use 'update' to replace it.");
            false
        } else {
            self.secrets.insert(
                key.clone(),
                SecretEntry {
                    key: key.clone(),
                    value,
                    updated: Local::now().to_string(),
                },
            );
            true
        }
    }

    pub fn get(&self, key: &str) -> Option<&String> {
        match self.secrets.get(key) {
            Some(secret) => Some(&secret.value),
            None => None,
        }
    }

    pub fn remove(&mut self, key: &str) -> bool {
        self.secrets.remove(key).is_some()
    }

    pub fn update(&mut self, key: &str, value: String) -> bool {
        match self.secrets.get_mut(key) {
            Some(secret) => {
                secret.value = value;
                secret.updated = Local::now().to_string();
                true
            }
            None => false,
        }
    }
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.secrets.keys()
    }

    pub fn entries(&self) -> impl Iterator<Item = &SecretEntry> {
        self.secrets.values()
    }
}
