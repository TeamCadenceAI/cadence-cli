//! Persistent index-ingest cursors.
//!
//! Records are scoped by `(repo_root, scope_type, scope_key_hash)` and stored under:
//! `~/.cadence/cli/sync-cursors/<repo-hash>--<scope>--<key-hash>.json`

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeType {
    Committer,
    Branch,
}

impl ScopeType {
    fn as_str(self) -> &'static str {
        match self {
            ScopeType::Committer => "committer",
            ScopeType::Branch => "branch",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncCursorRecord {
    pub repo_root: String,
    pub scope_type: ScopeType,
    pub scope_key_hash: String,
    pub last_scanned_mtime_epoch: i64,
    pub updated_at: String,
}

async fn cursor_dir_in(home: &Path) -> Result<PathBuf> {
    let dir = home.join(".cadence/cli").join("sync-cursors");
    tokio::fs::create_dir_all(&dir).await?;
    Ok(dir)
}

async fn cursor_dir() -> Result<PathBuf> {
    let home = crate::agents::home_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?;
    cursor_dir_in(&home).await
}

fn short_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    format!("{:x}", digest)[..16].to_string()
}

fn record_filename(repo_root: &str, scope_type: ScopeType, scope_key_hash: &str) -> String {
    let repo_hash = short_hash(repo_root);
    format!(
        "{}--{}--{}.json",
        repo_hash,
        scope_type.as_str(),
        scope_key_hash
    )
}

fn record_path(
    dir: &Path,
    repo_root: &str,
    scope_type: ScopeType,
    scope_key_hash: &str,
) -> PathBuf {
    dir.join(record_filename(repo_root, scope_type, scope_key_hash))
}

pub async fn load_cursor(
    repo_root: &str,
    scope_type: ScopeType,
    scope_key_hash: &str,
) -> Result<Option<SyncCursorRecord>> {
    let dir = cursor_dir().await?;
    let path = record_path(&dir, repo_root, scope_type, scope_key_hash);
    if tokio::fs::metadata(&path).await.is_err() {
        return Ok(None);
    }
    let content = tokio::fs::read_to_string(&path).await?;
    let record: SyncCursorRecord = serde_json::from_str(&content)?;
    Ok(Some(record))
}

pub async fn upsert_cursor(
    repo_root: &str,
    scope_type: ScopeType,
    scope_key_hash: &str,
    last_scanned_mtime_epoch: i64,
) -> Result<()> {
    let dir = cursor_dir().await?;
    let path = record_path(&dir, repo_root, scope_type, scope_key_hash);
    let tmp = path.with_extension("json.tmp");
    let record = SyncCursorRecord {
        repo_root: repo_root.to_string(),
        scope_type,
        scope_key_hash: scope_key_hash.to_string(),
        last_scanned_mtime_epoch,
        updated_at: crate::note::now_rfc3339(),
    };
    let json = serde_json::to_string_pretty(&record)?;
    tokio::fs::write(&tmp, json).await?;
    tokio::fs::rename(&tmp, &path).await?;
    Ok(())
}
