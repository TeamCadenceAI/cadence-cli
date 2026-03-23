//! Durable publication state and payload storage.

use crate::config::CliConfig;
use crate::publication::{LogicalSessionKey, PublicationObservations, sha256_hex};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Current durable status for a publication attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationStatus {
    AwaitingRemote,
    AwaitingOrg,
    ReadyToPublish,
    Publishing,
    AwaitingConfirm,
    RetryableFailure,
    Published,
}

/// On-disk state for one logical session within one target org context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicationStateRecord {
    /// Stable logical session identity.
    pub logical_session: LogicalSessionKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_org_id: Option<String>,
    pub status: PublicationStatus,
    pub current_content_sha256: String,
    pub current_metadata_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_published_content_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_published_metadata_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_id: Option<String>,
    pub upload_sha256: String,
    pub attempt_count: u32,
    pub next_attempt_at_epoch: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub observations: PublicationObservations,
    pub updated_at: String,
    pub created_at: String,
}

/// Publication record paired with its filesystem storage key.
#[derive(Debug, Clone)]
pub struct StoredPublication {
    pub storage_key: String,
    pub record: PublicationStateRecord,
}

/// Writes or updates a publication-state record and optional raw payload.
pub async fn upsert_record(record: &PublicationStateRecord, payload: Option<&str>) -> Result<()> {
    let dir = state_dir()?;
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("failed to create publication state dir {}", dir.display()))?;

    let storage_key = storage_key(&record.logical_session, record.target_org_id.as_deref());
    write_atomic(
        &record_path(&dir, &storage_key),
        serde_json::to_vec_pretty(record).context("failed to serialize publication state")?,
    )
    .await?;

    match payload {
        Some(payload) => {
            write_atomic(
                &payload_path(&dir, &storage_key),
                payload.as_bytes().to_vec(),
            )
            .await?
        }
        None => {
            let path = payload_path(&dir, &storage_key);
            let _ = tokio::fs::remove_file(path).await;
        }
    }

    Ok(())
}

/// Removes a publication-state record and any stored payload.
pub async fn remove_record(storage_key: &str) -> Result<()> {
    let dir = state_dir()?;
    let _ = tokio::fs::remove_file(record_path(&dir, storage_key)).await;
    let _ = tokio::fs::remove_file(payload_path(&dir, storage_key)).await;
    Ok(())
}

/// Loads every stored publication-state record from disk.
pub async fn load_all_records() -> Result<Vec<StoredPublication>> {
    let dir = state_dir()?;
    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!("failed to read publication state dir {}", dir.display())
            });
        }
    };

    let mut out = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let bytes = tokio::fs::read(&path)
            .await
            .with_context(|| format!("failed to read publication state {}", path.display()))?;
        let record: PublicationStateRecord = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse publication state {}", path.display()))?;
        let storage_key = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_default()
            .to_string();
        out.push(StoredPublication {
            storage_key,
            record,
        });
    }

    out.sort_by(|a, b| a.storage_key.cmp(&b.storage_key));
    Ok(out)
}

/// Loads the stored raw payload for a publication-state record.
pub async fn load_payload(storage_key: &str) -> Result<Option<String>> {
    let dir = state_dir()?;
    let path = payload_path(&dir, storage_key);
    match tokio::fs::read_to_string(&path).await {
        Ok(payload) => Ok(Some(payload)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("failed to read payload {}", path.display())),
    }
}

/// Builds the stable storage key for a logical session plus target org.
pub fn storage_key(logical_session: &LogicalSessionKey, target_org_id: Option<&str>) -> String {
    let key = format!(
        "{}|{}|{}",
        logical_session.agent,
        logical_session.agent_session_id,
        target_org_id.unwrap_or("unresolved")
    );
    sha256_hex(key.as_bytes())
}

/// Returns the current UTC timestamp formatted as RFC 3339.
pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use tempfile::TempDir;

    struct EnvGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvGuard {
        fn set_path(key: &'static str, path: &Path) -> Self {
            let previous = std::env::var_os(key);
            unsafe { std::env::set_var(key, path) };
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.take() {
                unsafe { std::env::set_var(self.key, previous) };
            } else {
                unsafe { std::env::remove_var(self.key) };
            }
        }
    }

    fn sample_record() -> PublicationStateRecord {
        PublicationStateRecord {
            logical_session: LogicalSessionKey {
                agent: "codex".to_string(),
                agent_session_id: "session-1".to_string(),
            },
            target_org_id: Some("org-1".to_string()),
            status: PublicationStatus::RetryableFailure,
            current_content_sha256: "a".repeat(64),
            current_metadata_sha256: "b".repeat(64),
            last_published_content_sha256: None,
            last_published_metadata_sha256: None,
            publish_uid: Some("pub_123".to_string()),
            publication_id: Some("publication-1".to_string()),
            upload_sha256: "c".repeat(64),
            attempt_count: 2,
            next_attempt_at_epoch: 42,
            last_error: Some("boom".to_string()),
            observations: PublicationObservations {
                canonical_remote_url: "git@github.com:test-org/repo.git".to_string(),
                remote_urls: vec!["git@github.com:test-org/repo.git".to_string()],
                canonical_repo_root: "/tmp/repo".to_string(),
                worktree_roots: vec!["/tmp/repo".to_string()],
                cwd: Some("/tmp/repo".to_string()),
                git_ref: Some("refs/heads/main".to_string()),
                head_commit_sha: Some("abc1234".to_string()),
                git_user_email: Some("dev@example.com".to_string()),
                git_user_name: Some("Dev".to_string()),
                cli_version: Some("1.0.0".to_string()),
            },
            updated_at: now_rfc3339(),
            created_at: now_rfc3339(),
        }
    }

    #[tokio::test]
    async fn state_round_trips_record_and_payload() {
        let temp = TempDir::new().unwrap();
        let _home = EnvGuard::set_path("HOME", temp.path());
        let record = sample_record();
        let key = storage_key(&record.logical_session, record.target_org_id.as_deref());

        upsert_record(&record, Some("payload")).await.unwrap();
        let records = load_all_records().await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].storage_key, key);
        assert_eq!(
            load_payload(&key).await.unwrap(),
            Some("payload".to_string())
        );
    }

    #[tokio::test]
    async fn remove_record_deletes_payload_and_metadata() {
        let temp = TempDir::new().unwrap();
        let _home = EnvGuard::set_path("HOME", temp.path());
        let record = sample_record();
        let key = storage_key(&record.logical_session, record.target_org_id.as_deref());

        upsert_record(&record, Some("payload")).await.unwrap();
        remove_record(&key).await.unwrap();

        assert!(load_all_records().await.unwrap().is_empty());
        assert_eq!(load_payload(&key).await.unwrap(), None);
    }

    #[test]
    fn storage_key_changes_with_target_org() {
        let logical_session = LogicalSessionKey {
            agent: "codex".to_string(),
            agent_session_id: "session-1".to_string(),
        };
        let first = storage_key(&logical_session, Some("org-a"));
        let second = storage_key(&logical_session, Some("org-b"));
        assert_ne!(first, second);
    }
}

fn state_dir() -> Result<PathBuf> {
    CliConfig::config_dir()
        .map(|dir| dir.join("publication-state"))
        .ok_or_else(|| anyhow::anyhow!("cannot determine Cadence config directory"))
}

fn record_path(dir: &Path, storage_key: &str) -> PathBuf {
    dir.join(format!("{storage_key}.json"))
}

fn payload_path(dir: &Path, storage_key: &str) -> PathBuf {
    dir.join(format!("{storage_key}.blob"))
}

async fn write_atomic(path: &Path, bytes: Vec<u8>) -> Result<()> {
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("tmp")
    ));
    tokio::fs::write(&tmp, bytes)
        .await
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!("failed to move {} into place", path.display()))?;
    Ok(())
}
