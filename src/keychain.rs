use anyhow::{Context, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::Mutex;

#[allow(dead_code)]
#[async_trait]
pub trait KeychainStore {
    async fn get(&self, account: &str) -> Result<Option<String>>;
    async fn set(&self, account: &str, value: &str) -> Result<()>;
    async fn delete(&self, account: &str) -> Result<()>;
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
}

#[async_trait]
impl KeychainStore for KeyringStore {
    async fn get(&self, account: &str) -> Result<Option<String>> {
        let service = self.service.clone();
        let account = account.to_string();
        tokio::task::spawn_blocking(move || {
            let entry =
                keyring::Entry::new(&service, &account).context("failed to open keychain entry")?;
            match entry.get_password() {
                Ok(value) => Ok(Some(value)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(err) => Err(err).context("failed to read keychain entry"),
            }
        })
        .await
        .context("keychain get task failed")?
    }

    async fn set(&self, account: &str, value: &str) -> Result<()> {
        let service = self.service.clone();
        let account = account.to_string();
        let value = value.to_string();
        tokio::task::spawn_blocking(move || {
            let entry =
                keyring::Entry::new(&service, &account).context("failed to open keychain entry")?;
            entry
                .set_password(&value)
                .context("failed to store keychain entry")?;
            Ok(())
        })
        .await
        .context("keychain set task failed")?
    }

    async fn delete(&self, account: &str) -> Result<()> {
        let service = self.service.clone();
        let account = account.to_string();
        tokio::task::spawn_blocking(move || {
            let entry =
                keyring::Entry::new(&service, &account).context("failed to open keychain entry")?;
            match entry.delete_password() {
                Ok(()) => Ok(()),
                Err(keyring::Error::NoEntry) => Ok(()),
                Err(err) => Err(err).context("failed to delete keychain entry"),
            }
        })
        .await
        .context("keychain delete task failed")?
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

#[async_trait]
impl KeychainStore for InMemoryKeychain {
    async fn get(&self, account: &str) -> Result<Option<String>> {
        Ok(self.values.lock().await.get(account).cloned())
    }

    async fn set(&self, account: &str, value: &str) -> Result<()> {
        self.values
            .lock()
            .await
            .insert(account.to_string(), value.to_string());
        Ok(())
    }

    async fn delete(&self, account: &str) -> Result<()> {
        self.values.lock().await.remove(account);
        Ok(())
    }
}
