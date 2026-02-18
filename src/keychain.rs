use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Mutex;

#[allow(dead_code)]
pub trait KeychainStore {
    fn get(&self, account: &str) -> Result<Option<String>>;
    fn set(&self, account: &str, value: &str) -> Result<()>;
    fn delete(&self, account: &str) -> Result<()>;
}

pub struct KeyringStore {
    service: String,
}

impl KeyringStore {
    pub fn new(service: &str) -> Self {
        Self {
            service: service.to_string(),
        }
    }

    fn entry(&self, account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, account).context("failed to open keychain entry")
    }
}

impl KeychainStore for KeyringStore {
    fn get(&self, account: &str) -> Result<Option<String>> {
        let entry = self.entry(account)?;
        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(err).context("failed to read keychain entry"),
        }
    }

    fn set(&self, account: &str, value: &str) -> Result<()> {
        let entry = self.entry(account)?;
        entry
            .set_password(value)
            .context("failed to store keychain entry")?;
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<()> {
        let entry = self.entry(account)?;
        match entry.delete_password() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(err).context("failed to delete keychain entry"),
        }
    }
}

#[allow(dead_code)]
#[derive(Default)]
pub struct InMemoryKeychain {
    values: Mutex<HashMap<String, String>>,
}

#[allow(dead_code)]
impl InMemoryKeychain {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeychainStore for InMemoryKeychain {
    fn get(&self, account: &str) -> Result<Option<String>> {
        Ok(self.values.lock().unwrap().get(account).cloned())
    }

    fn set(&self, account: &str, value: &str) -> Result<()> {
        self.values
            .lock()
            .unwrap()
            .insert(account.to_string(), value.to_string());
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<()> {
        self.values.lock().unwrap().remove(account);
        Ok(())
    }
}
