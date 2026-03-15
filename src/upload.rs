//! Direct session upload pipeline and pending retry queue.

use crate::api_client::{
    ApiClient, AuthenticatedRequestError, SessionUploadConfirmResponse, SessionUploadUrlRequest,
};
use crate::config;
use crate::keychain::{KeychainStore, KeyringStore};
use crate::note;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

const KEYCHAIN_SERVICE: &str = "cadence-cli";
const KEYCHAIN_AUTH_TOKEN_ACCOUNT: &str = "auth_token";
const API_TIMEOUT_SECS: u64 = 5;
const PRESIGNED_UPLOAD_TIMEOUT_SECS: u64 = 60;
const RETRY_DELAYS_SECS: &[i64] = &[0, 1, 2, 4, 8, 16, 32, 60, 120, 300, 600];
pub const DEFAULT_PENDING_UPLOADS_PER_RUN: usize = 8;

#[derive(Debug)]
pub struct UploadContext {
    client: ApiClient,
    token: Option<String>,
}

impl UploadContext {
    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct PreparedSessionUpload {
    pub session_uid: String,
    pub request: SessionUploadUrlRequest,
    pub compressed_payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveUploadOutcome {
    Uploaded,
    AlreadyExists,
    SkippedRepoNotAssociated,
    Queued,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PendingUploadSummary {
    pub attempted: usize,
    pub uploaded: usize,
    pub already_existed: usize,
    pub skipped_repo_not_associated: usize,
    pub auth_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingUploadRecord {
    pub session_uid: String,
    pub request: SessionUploadUrlRequest,
    pub enqueued_at: String,
    pub updated_at: String,
    pub attempt_count: u32,
    pub next_attempt_at_epoch: i64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadAttemptOutcome {
    Uploaded,
    AlreadyExists,
    SkippedRepoNotAssociated,
}

#[derive(Debug)]
enum UploadAttemptError {
    Unauthorized,
    Retryable(String),
}

pub async fn resolve_upload_context(api_url_override: Option<&str>) -> Result<UploadContext> {
    let cfg = config::CliConfig::load().await?;
    let resolved = cfg.resolve_api_url(api_url_override);
    let token = resolve_cli_auth_token(&cfg).await;
    Ok(UploadContext {
        client: ApiClient::new(&resolved.url),
        token,
    })
}

pub fn prepare_session_upload(
    record: note::SessionRecord,
    session_content: String,
) -> Result<PreparedSessionUpload> {
    let session_uid = record.session_uid.clone();
    let repo_remote_url = record
        .repo_remote_url
        .clone()
        .ok_or_else(|| anyhow::anyhow!("missing repo remote URL"))?;
    let envelope_bytes = note::serialize_session_object(record.clone(), session_content)?;
    let content_sha256 = sha256_hex(&envelope_bytes);
    let compressed_payload = note::compress_bytes(&envelope_bytes)?;
    let request = SessionUploadUrlRequest {
        session_uid: session_uid.clone(),
        agent: record.agent,
        agent_session_id: record.session_id,
        repo_remote_url,
        branch_key: record.branch_key,
        session_start: record.session_start,
        content_sha256,
        git_user_email: record.git_user_email,
        git_user_name: record.git_user_name,
        cli_version: record.cli_version,
        cwd: record.cwd,
        repo_root: record.repo_root,
    };
    Ok(PreparedSessionUpload {
        session_uid,
        request,
        compressed_payload,
    })
}

pub async fn upload_or_queue_prepared_session(
    context: &UploadContext,
    prepared: &PreparedSessionUpload,
) -> Result<LiveUploadOutcome> {
    let Some(token) = context.token.as_deref() else {
        enqueue_pending_upload(prepared, "missing Cadence CLI auth token").await?;
        return Ok(LiveUploadOutcome::Queued);
    };

    match attempt_upload(
        &context.client,
        token,
        &prepared.request,
        &prepared.compressed_payload,
    )
    .await
    {
        Ok(UploadAttemptOutcome::Uploaded) => Ok(LiveUploadOutcome::Uploaded),
        Ok(UploadAttemptOutcome::AlreadyExists) => Ok(LiveUploadOutcome::AlreadyExists),
        Ok(UploadAttemptOutcome::SkippedRepoNotAssociated) => {
            Ok(LiveUploadOutcome::SkippedRepoNotAssociated)
        }
        Err(UploadAttemptError::Unauthorized) => {
            enqueue_pending_upload(prepared, "Cadence CLI auth token was rejected").await?;
            Ok(LiveUploadOutcome::Queued)
        }
        Err(UploadAttemptError::Retryable(message)) => {
            enqueue_pending_upload(prepared, &message).await?;
            Ok(LiveUploadOutcome::Queued)
        }
    }
}

pub async fn process_pending_uploads(
    context: &UploadContext,
    max_items: usize,
) -> Result<PendingUploadSummary> {
    let Some(token) = context.token.as_deref() else {
        return Ok(PendingUploadSummary {
            auth_required: pending_upload_count().await? > 0,
            ..PendingUploadSummary::default()
        });
    };

    let records = list_due_pending_uploads(max_items).await?;
    let mut summary = PendingUploadSummary::default();
    for record in records {
        summary.attempted += 1;
        let payload = match load_pending_payload(&record.session_uid).await {
            Ok(payload) => payload,
            Err(err) => {
                record_pending_failure(
                    &record,
                    &format!("failed to read pending payload: {err:#}"),
                )
                .await?;
                continue;
            }
        };

        match attempt_upload(&context.client, token, &record.request, &payload).await {
            Ok(UploadAttemptOutcome::Uploaded) => {
                remove_pending_upload(&record.session_uid).await?;
                summary.uploaded += 1;
            }
            Ok(UploadAttemptOutcome::AlreadyExists) => {
                remove_pending_upload(&record.session_uid).await?;
                summary.already_existed += 1;
            }
            Ok(UploadAttemptOutcome::SkippedRepoNotAssociated) => {
                remove_pending_upload(&record.session_uid).await?;
                summary.skipped_repo_not_associated += 1;
            }
            Err(UploadAttemptError::Unauthorized) => {
                summary.auth_required = true;
                break;
            }
            Err(UploadAttemptError::Retryable(message)) => {
                record_pending_failure(&record, &message).await?;
            }
        }
    }

    Ok(summary)
}

pub async fn pending_upload_count() -> Result<usize> {
    let dir = pending_dir().await?;
    Ok(read_pending_records(&dir).await?.len())
}

async fn attempt_upload(
    client: &ApiClient,
    token: &str,
    request: &SessionUploadUrlRequest,
    compressed_payload: &[u8],
) -> std::result::Result<UploadAttemptOutcome, UploadAttemptError> {
    let upload = match client
        .request_session_upload_url(token, request, Duration::from_secs(API_TIMEOUT_SECS))
        .await
    {
        Ok(upload) => upload,
        Err(AuthenticatedRequestError::Conflict(_)) => {
            return Ok(UploadAttemptOutcome::AlreadyExists);
        }
        Err(AuthenticatedRequestError::Unprocessable(_)) => {
            return Ok(UploadAttemptOutcome::SkippedRepoNotAssociated);
        }
        Err(AuthenticatedRequestError::Unauthorized) => {
            return Err(UploadAttemptError::Unauthorized);
        }
        Err(err) => return Err(UploadAttemptError::Retryable(err.to_string())),
    };

    client
        .upload_presigned(
            &upload.upload_url,
            compressed_payload,
            Duration::from_secs(PRESIGNED_UPLOAD_TIMEOUT_SECS),
        )
        .await
        .map_err(|err| UploadAttemptError::Retryable(err.to_string()))?;

    match client
        .confirm_session_upload(
            token,
            &upload.session_uid,
            &upload.org_id,
            Duration::from_secs(API_TIMEOUT_SECS),
        )
        .await
    {
        Ok(SessionUploadConfirmResponse { .. }) => Ok(UploadAttemptOutcome::Uploaded),
        Err(AuthenticatedRequestError::Conflict(_)) => Ok(UploadAttemptOutcome::Uploaded),
        Err(AuthenticatedRequestError::Unauthorized) => Err(UploadAttemptError::Unauthorized),
        Err(err) => Err(UploadAttemptError::Retryable(err.to_string())),
    }
}

async fn enqueue_pending_upload(prepared: &PreparedSessionUpload, error: &str) -> Result<()> {
    let dir = pending_dir().await?;
    let now = now_epoch();
    let now_rfc3339 = note::now_rfc3339();
    let path = record_path(&dir, &prepared.session_uid);
    let existing = match tokio::fs::read_to_string(&path).await {
        Ok(content) => serde_json::from_str::<PendingUploadRecord>(&content).ok(),
        Err(_) => None,
    };

    let record = PendingUploadRecord {
        session_uid: prepared.session_uid.clone(),
        request: prepared.request.clone(),
        enqueued_at: existing
            .as_ref()
            .map(|record| record.enqueued_at.clone())
            .unwrap_or_else(|| now_rfc3339.clone()),
        updated_at: now_rfc3339,
        attempt_count: existing
            .as_ref()
            .map(|record| record.attempt_count)
            .unwrap_or(0),
        next_attempt_at_epoch: now,
        last_error: Some(error.to_string()),
    };

    write_pending_files(&dir, &record, &prepared.compressed_payload).await
}

async fn record_pending_failure(record: &PendingUploadRecord, error: &str) -> Result<()> {
    let dir = pending_dir().await?;
    let now = now_epoch();
    let attempts = record.attempt_count.saturating_add(1);
    let retry_delay = retry_delay_secs(attempts);
    let updated = PendingUploadRecord {
        session_uid: record.session_uid.clone(),
        request: record.request.clone(),
        enqueued_at: record.enqueued_at.clone(),
        updated_at: note::now_rfc3339(),
        attempt_count: attempts,
        next_attempt_at_epoch: now + retry_delay,
        last_error: Some(error.to_string()),
    };

    let payload = load_pending_payload(&record.session_uid).await?;
    write_pending_files(&dir, &updated, &payload).await
}

async fn remove_pending_upload(session_uid: &str) -> Result<()> {
    let dir = pending_dir().await?;
    let record_path = record_path(&dir, session_uid);
    let payload_path = payload_path(&dir, session_uid);
    if tokio::fs::try_exists(&record_path).await.unwrap_or(false) {
        let _ = tokio::fs::remove_file(&record_path).await;
    }
    if tokio::fs::try_exists(&payload_path).await.unwrap_or(false) {
        let _ = tokio::fs::remove_file(&payload_path).await;
    }
    Ok(())
}

async fn list_due_pending_uploads(max_items: usize) -> Result<Vec<PendingUploadRecord>> {
    let dir = pending_dir().await?;
    let mut records = read_pending_records(&dir).await?;
    let now = now_epoch();
    records.retain(|record| record.next_attempt_at_epoch <= now);
    records.sort_by(|a, b| {
        a.next_attempt_at_epoch
            .cmp(&b.next_attempt_at_epoch)
            .then(a.updated_at.cmp(&b.updated_at))
            .then(a.session_uid.cmp(&b.session_uid))
    });
    records.truncate(max_items);
    Ok(records)
}

async fn read_pending_records(dir: &Path) -> Result<Vec<PendingUploadRecord>> {
    let mut records = Vec::new();
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(records),
        Err(err) => {
            return Err(err).with_context(|| {
                format!("failed to read pending upload directory {}", dir.display())
            });
        }
    };

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let content = match tokio::fs::read_to_string(&path).await {
            Ok(content) => content,
            Err(_) => continue,
        };
        let Ok(record) = serde_json::from_str::<PendingUploadRecord>(&content) else {
            continue;
        };
        records.push(record);
    }

    Ok(records)
}

async fn load_pending_payload(session_uid: &str) -> Result<Vec<u8>> {
    let dir = pending_dir().await?;
    let path = payload_path(&dir, session_uid);
    tokio::fs::read(&path)
        .await
        .with_context(|| format!("failed to read pending upload payload {}", path.display()))
}

async fn write_pending_files(
    dir: &Path,
    record: &PendingUploadRecord,
    payload: &[u8],
) -> Result<()> {
    let record_path = record_path(dir, &record.session_uid);
    let payload_path = payload_path(dir, &record.session_uid);
    write_atomic(
        &record_path,
        serde_json::to_vec_pretty(record).context("failed to serialize pending upload")?,
    )
    .await?;
    write_atomic(&payload_path, payload.to_vec()).await
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
    if tokio::fs::try_exists(path).await.unwrap_or(false) {
        let _ = tokio::fs::remove_file(path).await;
    }
    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!("failed to rename {} to {}", tmp.display(), path.display()))
}

async fn pending_dir() -> Result<PathBuf> {
    let home = crate::agents::home_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?;
    let dir = home.join(".cadence/cli").join("pending-uploads");
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("failed to create {}", dir.display()))?;
    Ok(dir)
}

fn record_path(dir: &Path, session_uid: &str) -> PathBuf {
    dir.join(format!("{session_uid}.json"))
}

fn payload_path(dir: &Path, session_uid: &str) -> PathBuf {
    dir.join(format!("{session_uid}.zst"))
}

fn retry_delay_secs(attempt_count: u32) -> i64 {
    let idx = usize::min(attempt_count as usize, RETRY_DELAYS_SECS.len() - 1);
    RETRY_DELAYS_SECS[idx]
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

async fn resolve_cli_auth_token(cfg: &config::CliConfig) -> Option<String> {
    let keychain = KeyringStore::new(KEYCHAIN_SERVICE);
    match keychain.get(KEYCHAIN_AUTH_TOKEN_ACCOUNT).await {
        Ok(Some(token)) if !token.trim().is_empty() => Some(token),
        Ok(_) | Err(_) => cfg.token.clone().filter(|token| !token.trim().is_empty()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> note::SessionRecord {
        note::SessionRecord {
            session_uid: "uid-1".to_string(),
            agent: "codex".to_string(),
            session_id: "session-abc".to_string(),
            repo_root: "/tmp/repo".to_string(),
            repo_remote_url: Some("git@github.com:Org/Repo.git".to_string()),
            branch_key: "origin/main".to_string(),
            committer_key_hash: "committer-hash".to_string(),
            git_user_email: Some("dev@example.com".to_string()),
            git_user_name: Some("Dev Name".to_string()),
            session_start: Some(1_700_000_000),
            content_sha256: "content-sha".to_string(),
            cwd: Some("/tmp/repo".to_string()),
            ingested_at: "2026-03-02T00:00:00Z".to_string(),
            cli_version: "1.0.0".to_string(),
        }
    }

    #[test]
    fn prepare_session_upload_uses_envelope_sha() {
        let record = sample_record();
        let prepared = prepare_session_upload(record.clone(), "hello".to_string())
            .expect("prepare session upload");
        let envelope = note::serialize_session_object(record, "hello".to_string())
            .expect("serialize session object");
        assert_eq!(prepared.request.content_sha256, sha256_hex(&envelope));
    }
}
