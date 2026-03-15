//! Repo-scoped upload cursors for incremental post-commit scans.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadCursorRecord {
    pub repo_root: String,
    pub last_scanned_mtime_epoch: i64,
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

pub async fn upsert_cursor(repo_root: &str, last_scanned_mtime_epoch: i64) -> Result<()> {
    let dir = cursor_dir().await?;
    let path = record_path(&dir, repo_root);
    let tmp = path.with_extension("json.tmp");
    let record = UploadCursorRecord {
        repo_root: repo_root.to_string(),
        last_scanned_mtime_epoch,
        updated_at: crate::note::now_rfc3339(),
    };
    let bytes = serde_json::to_vec_pretty(&record).context("failed to serialize upload cursor")?;
    tokio::fs::write(&tmp, bytes)
        .await
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    if tokio::fs::try_exists(&path).await.unwrap_or(false) {
        let _ = tokio::fs::remove_file(&path).await;
    }
    tokio::fs::rename(&tmp, &path)
        .await
        .with_context(|| format!("failed to rename {} to {}", tmp.display(), path.display()))?;
    Ok(())
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

    #[test]
    fn short_hash_is_stable() {
        assert_eq!(short_hash("/tmp/repo"), short_hash("/tmp/repo"));
    }
}
