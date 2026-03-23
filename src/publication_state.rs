//! Durable v2 publication state and payload storage.

use crate::config::CliConfig;
use crate::publication_v2::{LogicalSessionKey, PublicationObservations, sha256_hex};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicationStateRecord {
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

#[derive(Debug, Clone)]
pub struct StoredPublication {
    pub storage_key: String,
    pub record: PublicationStateRecord,
}

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

pub async fn remove_record(storage_key: &str) -> Result<()> {
    let dir = state_dir()?;
    let _ = tokio::fs::remove_file(record_path(&dir, storage_key)).await;
    let _ = tokio::fs::remove_file(payload_path(&dir, storage_key)).await;
    Ok(())
}

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

pub async fn load_payload(storage_key: &str) -> Result<Option<String>> {
    let dir = state_dir()?;
    let path = payload_path(&dir, storage_key);
    match tokio::fs::read_to_string(&path).await {
        Ok(payload) => Ok(Some(payload)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("failed to read payload {}", path.display())),
    }
}

pub fn storage_key(logical_session: &LogicalSessionKey, target_org_id: Option<&str>) -> String {
    let key = format!(
        "{}|{}|{}",
        logical_session.agent,
        logical_session.agent_session_id,
        target_org_id.unwrap_or("unresolved")
    );
    sha256_hex(key.as_bytes())
}

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
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
