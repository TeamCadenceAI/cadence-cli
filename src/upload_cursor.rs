//! Repo-scoped upload cursors for incremental post-commit scans.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadCursorRecord {
    pub repo_root: String,
    pub last_scanned_mtime_epoch: i64,
    #[serde(default)]
    pub last_scanned_source_label: Option<String>,
    pub updated_at: String,
}

pub async fn load_cursor(repo_root: &str) -> Result<Option<UploadCursorRecord>> {
    let dir = cursor_dir().await?;
    let path = record_path(&dir, repo_root);
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => {
            let record: UploadCursorRecord = serde_json::from_str(&content)
                .with_context(|| format!("failed to parse upload cursor {}", path.display()))?;
            Ok(Some(record))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => {
            Err(err).with_context(|| format!("failed to read upload cursor {}", path.display()))
        }
    }
}

pub async fn upsert_cursor(
    repo_root: &str,
    last_scanned_mtime_epoch: i64,
    last_scanned_source_label: Option<&str>,
) -> Result<()> {
    let dir = cursor_dir().await?;
    let path = record_path(&dir, repo_root);
    let tmp = path.with_extension("json.tmp");
    let record = UploadCursorRecord {
        repo_root: repo_root.to_string(),
        last_scanned_mtime_epoch,
        last_scanned_source_label: last_scanned_source_label.map(str::to_string),
        updated_at: crate::publication_state::now_rfc3339(),
    };
    let bytes = serde_json::to_vec_pretty(&record).context("failed to serialize upload cursor")?;
    tokio::fs::write(&tmp, bytes)
        .await
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    replace_path(&tmp, &path)
        .await
        .with_context(|| format!("failed to rename {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(not(windows))]
async fn replace_path(tmp: &Path, path: &Path) -> std::io::Result<()> {
    tokio::fs::rename(tmp, path).await
}

#[cfg(windows)]
async fn replace_path(tmp: &Path, path: &Path) -> std::io::Result<()> {
    match tokio::fs::rename(tmp, path).await {
        Ok(()) => Ok(()),
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::PermissionDenied
            ) && tokio::fs::try_exists(path).await.unwrap_or(false) =>
        {
            tokio::fs::remove_file(path).await?;
            tokio::fs::rename(tmp, path).await
        }
        Err(err) => Err(err),
    }
}

async fn cursor_dir() -> Result<PathBuf> {
    let home = crate::agents::home_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?;
    let dir = home.join(".cadence/cli").join("upload-cursors");
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("failed to create {}", dir.display()))?;
    Ok(dir)
}

fn record_path(dir: &Path, repo_root: &str) -> PathBuf {
    dir.join(format!("{}.json", short_hash(repo_root)))
}

fn short_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    format!("{:x}", digest)[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::TempDir;

    struct EnvGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvGuard {
        fn new(key: &'static str) -> Self {
            Self {
                key,
                original: std::env::var(key).ok(),
            }
        }

        fn set_path(&self, path: &Path) {
            unsafe { std::env::set_var(self.key, path) };
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    fn short_hash_is_stable() {
        assert_eq!(short_hash("/tmp/repo"), short_hash("/tmp/repo"));
    }

    #[tokio::test]
    #[serial]
    async fn upsert_cursor_round_trips_latest_position() {
        let dir = TempDir::new().expect("tempdir");
        let home = EnvGuard::new("HOME");
        home.set_path(dir.path());

        upsert_cursor("/tmp/repo", 123, Some("alpha"))
            .await
            .expect("write initial cursor");
        upsert_cursor("/tmp/repo", 456, Some("beta"))
            .await
            .expect("overwrite cursor");

        let record = load_cursor("/tmp/repo")
            .await
            .expect("load cursor")
            .expect("persisted cursor");
        assert_eq!(record.last_scanned_mtime_epoch, 456);
        assert_eq!(record.last_scanned_source_label.as_deref(), Some("beta"));
    }
}
