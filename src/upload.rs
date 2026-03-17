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
const API_TIMEOUT_SECS: u64 = 15;
const PRESIGNED_UPLOAD_TIMEOUT_SECS: u64 = 60;
const RETRY_DELAYS_SECS: &[i64] = &[0, 1, 2, 4, 8, 16, 32, 60, 120, 300, 600];
pub const DEFAULT_PENDING_UPLOADS_PER_RUN: usize = 8;
const MAX_LOCAL_GIT_STATE_ATTEMPTS: u32 = 5;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveUploadOutcome {
    Uploaded,
    AlreadyExists,
    SkippedRepoNotAssociated,
    Queued { reason: String },
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PendingUploadSummary {
    pub attempted: usize,
    pub uploaded: usize,
    pub already_existed: usize,
    pub skipped_repo_not_associated: usize,
    pub dropped_permanent: usize,
    pub auth_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingUploadRecord {
    pub session_uid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<SessionUploadUrlRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope: Option<note::SessionEnvelope>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingFailureKind {
    Retryable,
    LocalGitState,
    PermanentData,
}

#[derive(Debug)]
struct PendingPreparationError {
    kind: PendingFailureKind,
    message: String,
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
    let compressed_payload = note::compress_bytes(&envelope_bytes)?;
    let upload_sha256 = sha256_hex(&compressed_payload);
    let request = SessionUploadUrlRequest {
        session_uid: session_uid.clone(),
        agent: record.agent,
        agent_session_id: record.session_id,
        repo_remote_url,
        git_ref: record.git_ref,
        head_sha: record.head_sha,
        session_start: record.session_start,
        upload_sha256,
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
        let reason = "missing Cadence CLI auth token";
        enqueue_prepared_upload(prepared, reason).await?;
        return Ok(LiveUploadOutcome::Queued {
            reason: reason.to_string(),
        });
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
            let reason = "Cadence CLI auth token was rejected";
            enqueue_prepared_upload(prepared, reason).await?;
            Ok(LiveUploadOutcome::Queued {
                reason: reason.to_string(),
            })
        }
        Err(UploadAttemptError::Retryable(message)) => {
            enqueue_prepared_upload(prepared, &message).await?;
            Ok(LiveUploadOutcome::Queued { reason: message })
        }
    }
}

pub async fn queue_session_for_remote_resolution(
    record: note::SessionRecord,
    session_content: String,
    error: &str,
) -> Result<()> {
    let envelope = note::SessionEnvelope {
        record,
        session_content,
    };
    enqueue_pending_envelope(&envelope, error).await
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
    crate::diagnostics_log::event(
        "pending_uploads_started",
        serde_json::json!({
            "max_items": max_items,
            "due_records": records.len(),
            "has_token": true,
        }),
    );
    for record in records {
        summary.attempted += 1;
        let prepared = match prepare_pending_upload(&record).await {
            Ok(prepared) => prepared,
            Err(err) => {
                let should_drop = err.kind == PendingFailureKind::PermanentData
                    || (err.kind == PendingFailureKind::LocalGitState
                        && record.attempt_count.saturating_add(1) >= MAX_LOCAL_GIT_STATE_ATTEMPTS);
                crate::diagnostics_log::event(
                    "pending_upload_prepare_failed",
                    serde_json::json!({
                        "session_uid": record.session_uid,
                        "attempt_count": record.attempt_count,
                        "kind": format!("{:?}", err.kind),
                        "message": err.message,
                        "dropped": should_drop,
                    }),
                );
                if should_drop {
                    remove_pending_upload(&record.session_uid).await?;
                    summary.dropped_permanent += 1;
                } else {
                    record_pending_failure(&record, &err.message).await?;
                }
                continue;
            }
        };

        match attempt_upload(
            &context.client,
            token,
            &prepared.request,
            &prepared.compressed_payload,
        )
        .await
        {
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

    crate::diagnostics_log::event(
        "pending_uploads_completed",
        serde_json::json!({
            "attempted": summary.attempted,
            "uploaded": summary.uploaded,
            "already_existed": summary.already_existed,
            "skipped_repo_not_associated": summary.skipped_repo_not_associated,
            "dropped_permanent": summary.dropped_permanent,
            "auth_required": summary.auth_required,
        }),
    );

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
    crate::diagnostics_log::event(
        "upload_attempt_started",
        serde_json::json!({
            "session_uid": request.session_uid,
            "repo_remote_url": request.repo_remote_url,
            "repo_root": request.repo_root,
            "git_ref": request.git_ref,
            "head_sha": request.head_sha,
            "payload_bytes": compressed_payload.len(),
        }),
    );
    let upload = match client
        .request_session_upload_url(token, request, Duration::from_secs(API_TIMEOUT_SECS))
        .await
    {
        Ok(upload) => {
            crate::diagnostics_log::event(
                "upload_request_url_succeeded",
                serde_json::json!({
                    "session_uid": request.session_uid,
                    "org_id": upload.org_id,
                }),
            );
            upload
        }
        Err(AuthenticatedRequestError::Conflict(_)) => {
            crate::diagnostics_log::event(
                "upload_request_url_conflict",
                serde_json::json!({
                    "session_uid": request.session_uid,
                }),
            );
            return Ok(UploadAttemptOutcome::AlreadyExists);
        }
        Err(AuthenticatedRequestError::Unprocessable(_)) => {
            crate::diagnostics_log::event(
                "upload_request_url_repo_not_associated",
                serde_json::json!({
                    "session_uid": request.session_uid,
                    "repo_remote_url": request.repo_remote_url,
                }),
            );
            return Ok(UploadAttemptOutcome::SkippedRepoNotAssociated);
        }
        Err(AuthenticatedRequestError::Unauthorized) => {
            crate::diagnostics_log::event(
                "upload_request_url_unauthorized",
                serde_json::json!({
                    "session_uid": request.session_uid,
                }),
            );
            return Err(UploadAttemptError::Unauthorized);
        }
        Err(err) => {
            crate::diagnostics_log::event(
                "upload_request_url_failed",
                serde_json::json!({
                    "session_uid": request.session_uid,
                    "error": err.to_string(),
                }),
            );
            return Err(UploadAttemptError::Retryable(err.to_string()));
        }
    };

    client
        .upload_presigned(
            &upload.upload_url,
            compressed_payload,
            Duration::from_secs(PRESIGNED_UPLOAD_TIMEOUT_SECS),
        )
        .await
        .map_err(|err| {
            crate::diagnostics_log::event(
                "upload_presigned_failed",
                serde_json::json!({
                    "session_uid": request.session_uid,
                    "error": err.to_string(),
                }),
            );
            UploadAttemptError::Retryable(err.to_string())
        })?;
    crate::diagnostics_log::event(
        "upload_presigned_succeeded",
        serde_json::json!({
            "session_uid": request.session_uid,
        }),
    );

    match client
        .confirm_session_upload(
            token,
            &upload.session_uid,
            &upload.org_id,
            Duration::from_secs(API_TIMEOUT_SECS),
        )
        .await
    {
        Ok(SessionUploadConfirmResponse { .. }) => {
            crate::diagnostics_log::event(
                "upload_confirm_succeeded",
                serde_json::json!({
                    "session_uid": request.session_uid,
                }),
            );
            Ok(UploadAttemptOutcome::Uploaded)
        }
        Err(AuthenticatedRequestError::Conflict(_)) => {
            crate::diagnostics_log::event(
                "upload_confirm_conflict",
                serde_json::json!({
                    "session_uid": request.session_uid,
                }),
            );
            Ok(UploadAttemptOutcome::Uploaded)
        }
        Err(AuthenticatedRequestError::Unauthorized) => {
            crate::diagnostics_log::event(
                "upload_confirm_unauthorized",
                serde_json::json!({
                    "session_uid": request.session_uid,
                }),
            );
            Err(UploadAttemptError::Unauthorized)
        }
        // Pending retries restart from request-url -> PUT -> confirm, so any
        // confirm mismatch is recovered with a fresh presigned upload cycle.
        Err(err) => {
            crate::diagnostics_log::event(
                "upload_confirm_failed",
                serde_json::json!({
                    "session_uid": request.session_uid,
                    "error": err.to_string(),
                }),
            );
            Err(UploadAttemptError::Retryable(err.to_string()))
        }
    }
}

async fn enqueue_prepared_upload(prepared: &PreparedSessionUpload, error: &str) -> Result<()> {
    let dir = pending_dir().await?;
    let now = now_epoch();
    let now_rfc3339 = note::now_rfc3339();
    let path = record_path(&dir, &prepared.session_uid);
    let existing = load_pending_record(&path).await;

    let record = PendingUploadRecord {
        session_uid: prepared.session_uid.clone(),
        request: Some(prepared.request.clone()),
        envelope: None,
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

    crate::diagnostics_log::event(
        "pending_upload_enqueued",
        serde_json::json!({
            "session_uid": record.session_uid,
            "mode": "prepared",
            "attempt_count": record.attempt_count,
            "next_attempt_at_epoch": record.next_attempt_at_epoch,
            "error": error,
        }),
    );
    write_pending_record(dir.as_path(), &record).await?;
    write_pending_payload(
        dir.as_path(),
        &record.session_uid,
        &prepared.compressed_payload,
    )
    .await
}

async fn enqueue_pending_envelope(envelope: &note::SessionEnvelope, error: &str) -> Result<()> {
    let dir = pending_dir().await?;
    let now = now_epoch();
    let now_rfc3339 = note::now_rfc3339();
    let path = record_path(&dir, &envelope.record.session_uid);
    let existing = load_pending_record(&path).await;

    let record = PendingUploadRecord {
        session_uid: envelope.record.session_uid.clone(),
        request: None,
        envelope: Some(envelope.clone()),
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

    crate::diagnostics_log::event(
        "pending_upload_enqueued",
        serde_json::json!({
            "session_uid": record.session_uid,
            "mode": "envelope",
            "attempt_count": record.attempt_count,
            "next_attempt_at_epoch": record.next_attempt_at_epoch,
            "error": error,
        }),
    );
    write_pending_record(dir.as_path(), &record).await?;
    remove_pending_payload(dir.as_path(), &record.session_uid).await
}

async fn record_pending_failure(record: &PendingUploadRecord, error: &str) -> Result<()> {
    let now = now_epoch();
    let attempts = record.attempt_count.saturating_add(1);
    let retry_delay = retry_delay_secs(attempts);
    let updated = PendingUploadRecord {
        session_uid: record.session_uid.clone(),
        request: record.request.clone(),
        envelope: record.envelope.clone(),
        enqueued_at: record.enqueued_at.clone(),
        updated_at: note::now_rfc3339(),
        attempt_count: attempts,
        next_attempt_at_epoch: now + retry_delay,
        last_error: Some(error.to_string()),
    };

    crate::diagnostics_log::event(
        "pending_upload_retry_scheduled",
        serde_json::json!({
            "session_uid": updated.session_uid,
            "attempt_count": updated.attempt_count,
            "next_attempt_at_epoch": updated.next_attempt_at_epoch,
            "error": error,
        }),
    );
    write_pending_record(pending_dir().await?.as_path(), &updated).await
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

async fn write_pending_record(dir: &Path, record: &PendingUploadRecord) -> Result<()> {
    let record_path = record_path(dir, &record.session_uid);
    write_atomic(
        &record_path,
        serde_json::to_vec_pretty(record).context("failed to serialize pending upload")?,
    )
    .await
}

async fn write_pending_payload(dir: &Path, session_uid: &str, payload: &[u8]) -> Result<()> {
    write_atomic(&payload_path(dir, session_uid), payload.to_vec()).await
}

async fn remove_pending_payload(dir: &Path, session_uid: &str) -> Result<()> {
    let payload_path = payload_path(dir, session_uid);
    if tokio::fs::try_exists(&payload_path).await.unwrap_or(false) {
        let _ = tokio::fs::remove_file(&payload_path).await;
    }
    Ok(())
}

async fn load_pending_record(path: &Path) -> Option<PendingUploadRecord> {
    match tokio::fs::read_to_string(path).await {
        Ok(content) => serde_json::from_str::<PendingUploadRecord>(&content).ok(),
        Err(_) => None,
    }
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
    replace_path(&tmp, path)
        .await
        .with_context(|| format!("failed to rename {} to {}", tmp.display(), path.display()))
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

async fn prepare_pending_upload(
    record: &PendingUploadRecord,
) -> std::result::Result<PreparedSessionUpload, PendingPreparationError> {
    if let Some(request) = record.request.clone() {
        let payload = load_pending_payload(&record.session_uid)
            .await
            .map_err(|err| PendingPreparationError {
                kind: PendingFailureKind::PermanentData,
                message: err.to_string(),
            })?;
        return Ok(PreparedSessionUpload {
            session_uid: record.session_uid.clone(),
            request,
            compressed_payload: payload,
        });
    }

    let envelope = record
        .envelope
        .clone()
        .ok_or_else(|| PendingPreparationError {
            kind: PendingFailureKind::PermanentData,
            message: format!(
                "pending upload {} is missing request data",
                record.session_uid
            ),
        })?;
    let repo_remote_url = resolve_repo_remote_url(Path::new(&envelope.record.repo_root))
        .await
        .map_err(|err| {
            let message = err.to_string();
            let kind = if message.contains("No such file or directory")
                || message.contains("not a git repository")
            {
                PendingFailureKind::LocalGitState
            } else {
                PendingFailureKind::Retryable
            };
            PendingPreparationError { kind, message }
        })?
        .ok_or_else(|| PendingPreparationError {
            kind: PendingFailureKind::LocalGitState,
            message: "repo has no push remote URL".to_string(),
        })?;
    rebuild_prepared_upload(&envelope, repo_remote_url).await
}

async fn rebuild_prepared_upload(
    envelope: &note::SessionEnvelope,
    repo_remote_url: String,
) -> std::result::Result<PreparedSessionUpload, PendingPreparationError> {
    let mut record = envelope.record.clone();
    let repo_root = PathBuf::from(record.repo_root.clone());
    record.repo_remote_url = Some(repo_remote_url);
    refresh_record_git_metadata(&repo_root, &mut record).await;
    if record.git_ref == "refs/heads/unknown" {
        return Err(PendingPreparationError {
            kind: PendingFailureKind::LocalGitState,
            message: "repo has no attached git branch".to_string(),
        });
    }
    if record.head_sha == "unknown" {
        return Err(PendingPreparationError {
            kind: PendingFailureKind::LocalGitState,
            message: "repo HEAD commit could not be resolved".to_string(),
        });
    }
    prepare_session_upload(record, envelope.session_content.clone()).map_err(|err| {
        let message = err.to_string();
        let kind = if message.contains("missing repo remote URL") {
            PendingFailureKind::LocalGitState
        } else {
            PendingFailureKind::PermanentData
        };
        PendingPreparationError { kind, message }
    })
}

async fn resolve_repo_remote_url(repo_root: &Path) -> Result<Option<String>> {
    crate::git::preferred_remote_url_at(repo_root).await
}

async fn refresh_record_git_metadata(repo_root: &Path, record: &mut note::SessionRecord) {
    if let Ok(Some(branch)) = crate::git::current_branch_at(repo_root).await
        && !branch.trim().is_empty()
    {
        record.git_ref = format!("refs/heads/{branch}");
    }

    if let Ok(Some(head_sha)) = crate::git::head_sha_at(repo_root).await
        && !head_sha.trim().is_empty()
    {
        record.head_sha = head_sha;
    }
}

async fn resolve_cli_auth_token(cfg: &config::CliConfig) -> Option<String> {
    let keychain = KeyringStore::new(KEYCHAIN_SERVICE);
    match keychain.get(KEYCHAIN_AUTH_TOKEN_ACCOUNT).await {
        Ok(Some(token)) if !token.trim().is_empty() => Some(token),
        Ok(_) | Err(_) => cfg.token.clone().filter(|token| !token.trim().is_empty()),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use crate::api_client::SessionUploadUrlRequest;
    use anyhow::{Context, Result};
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;

    #[derive(Debug, Clone, Default)]
    pub(crate) struct TestUploadServerConfig {
        pub upload_url_statuses: Vec<u16>,
        pub upload_statuses: Vec<u16>,
        pub confirm_statuses: Vec<u16>,
    }

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub(crate) struct TestUploadServerCounts {
        pub upload_url_requests: usize,
        pub uploads: usize,
        pub confirms: usize,
    }

    struct TestUploadServerState {
        counts: TestUploadServerCounts,
        upload_requests: Vec<SessionUploadUrlRequest>,
        upload_url_statuses: VecDeque<u16>,
        upload_statuses: VecDeque<u16>,
        confirm_statuses: VecDeque<u16>,
    }

    impl TestUploadServerState {
        fn new(config: TestUploadServerConfig) -> Self {
            Self {
                counts: TestUploadServerCounts::default(),
                upload_requests: Vec::new(),
                upload_url_statuses: config.upload_url_statuses.into(),
                upload_statuses: config.upload_statuses.into(),
                confirm_statuses: config.confirm_statuses.into(),
            }
        }

        fn next_upload_url_status(&mut self) -> u16 {
            self.counts.upload_url_requests += 1;
            self.upload_url_statuses.pop_front().unwrap_or(200)
        }

        fn next_upload_status(&mut self) -> u16 {
            self.counts.uploads += 1;
            self.upload_statuses.pop_front().unwrap_or(200)
        }

        fn next_confirm_status(&mut self) -> u16 {
            self.counts.confirms += 1;
            self.confirm_statuses.pop_front().unwrap_or(200)
        }
    }

    pub(crate) struct TestUploadServer {
        pub base_url: String,
        state: Arc<Mutex<TestUploadServerState>>,
        handle: JoinHandle<()>,
    }

    impl TestUploadServer {
        pub fn counts(&self) -> TestUploadServerCounts {
            self.state.lock().expect("server state").counts
        }

        pub fn upload_requests(&self) -> Vec<SessionUploadUrlRequest> {
            self.state
                .lock()
                .expect("server state")
                .upload_requests
                .clone()
        }
    }

    impl Drop for TestUploadServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    pub(crate) async fn spawn_test_upload_server(
        config: TestUploadServerConfig,
    ) -> Result<TestUploadServer> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind test upload server")?;
        let addr = listener
            .local_addr()
            .context("read test upload server addr")?;
        let base_url = format!("http://{addr}");
        let state = Arc::new(Mutex::new(TestUploadServerState::new(config)));
        let server_state = Arc::clone(&state);
        let server_base_url = base_url.clone();

        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let server_state = Arc::clone(&server_state);
                let server_base_url = server_base_url.clone();
                tokio::spawn(async move {
                    if let Ok(request) = read_http_request(&mut stream).await {
                        let response = build_response(&server_base_url, &server_state, request);
                        let _ = write_http_response(&mut stream, response).await;
                    }
                });
            }
        });

        Ok(TestUploadServer {
            base_url,
            state,
            handle,
        })
    }

    struct TestRequest {
        method: String,
        path: String,
        body: Vec<u8>,
    }

    struct TestResponse {
        status: u16,
        content_type: &'static str,
        body: Vec<u8>,
    }

    async fn read_http_request(stream: &mut TcpStream) -> Result<TestRequest> {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        let header_end = loop {
            let read = stream.read(&mut chunk).await.context("read test request")?;
            if read == 0 {
                anyhow::bail!("unexpected EOF while reading request");
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(pos) = find_bytes(&buffer, b"\r\n\r\n") {
                break pos + 4;
            }
        };

        let headers = String::from_utf8_lossy(&buffer[..header_end]);
        let mut lines = headers.lines();
        let request_line = lines.next().context("missing request line")?;
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts.next().unwrap_or_default().to_string();
        let path = request_parts.next().unwrap_or_default().to_string();
        let header_map = parse_headers(lines);
        let content_length = header_map
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);

        while buffer.len().saturating_sub(header_end) < content_length {
            let read = stream
                .read(&mut chunk)
                .await
                .context("read test request body")?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
        }

        Ok(TestRequest {
            method,
            path,
            body: buffer[header_end..header_end + content_length].to_vec(),
        })
    }

    fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((key, value)) = trimmed.split_once(':') {
                headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
            }
        }
        headers
    }

    fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    fn build_response(
        base_url: &str,
        state: &Arc<Mutex<TestUploadServerState>>,
        request: TestRequest,
    ) -> TestResponse {
        match (request.method.as_str(), request.path.as_str()) {
            ("POST", "/api/sessions/upload-url") => {
                let mut server_state = state.lock().expect("server state");
                let status = server_state.next_upload_url_status();
                if status == 200 {
                    let session_uid =
                        serde_json::from_slice::<SessionUploadUrlRequest>(&request.body)
                            .map(|request| {
                                let session_uid = request.session_uid.clone();
                                server_state.upload_requests.push(request);
                                session_uid
                            })
                            .unwrap_or_else(|_| "session-uid".to_string());
                    let body = format!(
                        r#"{{"upload_url":"{base_url}/uploads/{session_uid}","session_uid":"{session_uid}","org_id":"org-test"}}"#
                    )
                    .into_bytes();
                    TestResponse {
                        status,
                        content_type: "application/json",
                        body,
                    }
                } else {
                    TestResponse {
                        status,
                        content_type: "text/plain",
                        body: format!("upload-url failed with {status}").into_bytes(),
                    }
                }
            }
            ("PUT", path) if path.starts_with("/uploads/") => {
                let status = state.lock().expect("server state").next_upload_status();
                TestResponse {
                    status,
                    content_type: "text/plain",
                    body: if status == 200 {
                        Vec::new()
                    } else {
                        format!("upload failed with {status}").into_bytes()
                    },
                }
            }
            ("POST", path) if path.starts_with("/api/sessions/") && path.ends_with("/confirm") => {
                let status = state.lock().expect("server state").next_confirm_status();
                if status == 200 {
                    TestResponse {
                        status,
                        content_type: "application/json",
                        body: br#"{"status":"accepted"}"#.to_vec(),
                    }
                } else {
                    TestResponse {
                        status,
                        content_type: "text/plain",
                        body: format!("confirm failed with {status}").into_bytes(),
                    }
                }
            }
            _ => TestResponse {
                status: 404,
                content_type: "text/plain",
                body: b"not found".to_vec(),
            },
        }
    }

    async fn write_http_response(stream: &mut TcpStream, response: TestResponse) -> Result<()> {
        let status_text = match response.status {
            200 => "OK",
            401 => "Unauthorized",
            404 => "Not Found",
            409 => "Conflict",
            422 => "Unprocessable Entity",
            503 => "Service Unavailable",
            _ => "Test Error",
        };
        let headers = format!(
            "HTTP/1.1 {} {}\r\ncontent-length: {}\r\ncontent-type: {}\r\nconnection: close\r\n\r\n",
            response.status,
            status_text,
            response.body.len(),
            response.content_type
        );
        stream
            .write_all(headers.as_bytes())
            .await
            .context("write test response headers")?;
        if !response.body.is_empty() {
            stream
                .write_all(&response.body)
                .await
                .context("write test response body")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upload::test_support::{TestUploadServerConfig, spawn_test_upload_server};
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

    async fn run_git(repo: &Path, args: &[&str]) -> String {
        let out = crate::git::run_git_output_at(Some(repo), args, &[])
            .await
            .expect("run git");
        assert!(
            out.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout)
            .expect("utf8")
            .trim()
            .to_string()
    }

    async fn init_repo() -> TempDir {
        let dir = TempDir::new().expect("tempdir");
        run_git(dir.path(), &["init", "-q"]).await;
        run_git(dir.path(), &["config", "user.name", "Test User"]).await;
        run_git(dir.path(), &["config", "user.email", "test@example.com"]).await;
        tokio::fs::write(dir.path().join("README.md"), "hello")
            .await
            .expect("write");
        run_git(dir.path(), &["add", "README.md"]).await;
        run_git(dir.path(), &["commit", "-m", "init"]).await;
        dir
    }

    fn sample_record() -> note::SessionRecord {
        note::SessionRecord {
            session_uid: "uid-1".to_string(),
            agent: "codex".to_string(),
            session_id: "session-abc".to_string(),
            repo_root: "/tmp/repo".to_string(),
            repo_remote_url: Some("git@github.com:Org/Repo.git".to_string()),
            git_ref: "refs/heads/main".to_string(),
            head_sha: "abc123".to_string(),
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
    fn prepare_session_upload_uses_uploaded_blob_sha() {
        let record = sample_record();
        let prepared = prepare_session_upload(record.clone(), "hello".to_string())
            .expect("prepare session upload");
        let envelope = note::serialize_session_object(record, "hello".to_string())
            .expect("serialize session object");
        let compressed = note::compress_bytes(&envelope).expect("compress uploaded envelope");
        assert_eq!(prepared.request.upload_sha256, sha256_hex(&compressed));
    }

    #[test]
    fn prepare_session_upload_requires_repo_remote_url() {
        let mut record = sample_record();
        record.repo_remote_url = None;
        let err = prepare_session_upload(record, "hello".to_string()).expect_err("missing remote");
        assert!(err.to_string().contains("missing repo remote URL"));
    }

    #[tokio::test]
    async fn rebuild_prepared_upload_refreshes_remote_url_and_hash() {
        let mut record = sample_record();
        record.repo_remote_url = Some("cadence://missing-repo-remote-url".to_string());
        let envelope = note::SessionEnvelope {
            record,
            session_content: "hello".to_string(),
        };

        let prepared =
            rebuild_prepared_upload(&envelope, "git@github.com:team/example.git".to_string())
                .await
                .expect("rebuild prepared upload");

        assert_eq!(
            prepared.request.repo_remote_url,
            "git@github.com:team/example.git"
        );
        let envelope = note::serialize_session_object(
            note::SessionRecord {
                repo_remote_url: Some("git@github.com:team/example.git".to_string()),
                ..envelope.record
            },
            "hello".to_string(),
        )
        .expect("serialize rebuilt envelope");
        let compressed = note::compress_bytes(&envelope).expect("compress rebuilt envelope");
        assert_eq!(prepared.request.upload_sha256, sha256_hex(&compressed));
    }

    #[tokio::test]
    #[serial]
    async fn enqueue_pending_envelope_removes_stale_payload() {
        let dir = TempDir::new().expect("tempdir");
        let pending_dir = dir.path().join(".cadence/cli/pending-uploads");
        tokio::fs::create_dir_all(&pending_dir)
            .await
            .expect("create pending dir");

        let path = payload_path(&pending_dir, "uid-1");
        tokio::fs::write(&path, b"stale")
            .await
            .expect("write stale payload");

        let record = sample_record();
        let envelope = note::SessionEnvelope {
            record: note::SessionRecord {
                repo_remote_url: None,
                ..record
            },
            session_content: "hello".to_string(),
        };
        let home = EnvGuard::new("HOME");
        home.set_path(dir.path());

        enqueue_pending_envelope(&envelope, "missing remote")
            .await
            .expect("enqueue pending envelope");

        assert!(
            !tokio::fs::try_exists(&path)
                .await
                .expect("check stale payload removal")
        );
    }

    #[tokio::test]
    #[serial]
    async fn process_pending_uploads_retries_with_backoff_and_keeps_payload() {
        let dir = TempDir::new().expect("tempdir");
        let home = EnvGuard::new("HOME");
        home.set_path(dir.path());

        let prepared = prepare_session_upload(sample_record(), "hello".to_string())
            .expect("prepare session upload");
        enqueue_prepared_upload(&prepared, "initial failure")
            .await
            .expect("enqueue prepared upload");

        let server = spawn_test_upload_server(TestUploadServerConfig {
            upload_url_statuses: vec![503],
            ..TestUploadServerConfig::default()
        })
        .await
        .expect("spawn test server");
        let context = UploadContext {
            client: ApiClient::new(&server.base_url),
            token: Some("test-token".to_string()),
        };
        let before = now_epoch();

        let summary = process_pending_uploads(&context, 1)
            .await
            .expect("process pending uploads");

        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.uploaded, 0);
        assert_eq!(server.counts().upload_url_requests, 1);

        let pending_dir = pending_dir().await.expect("pending dir");
        let record = load_pending_record(&record_path(&pending_dir, &prepared.session_uid))
            .await
            .expect("pending record");
        assert_eq!(record.attempt_count, 1);
        assert!(record.next_attempt_at_epoch > before);
        assert!(
            record
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("server_error")
                || record
                    .last_error
                    .as_deref()
                    .unwrap_or_default()
                    .contains("503")
        );
        assert!(
            tokio::fs::try_exists(&payload_path(&pending_dir, &prepared.session_uid))
                .await
                .expect("check queued payload")
        );
    }

    #[tokio::test]
    #[serial]
    async fn upload_or_queue_prepared_session_queues_with_reason_when_auth_missing() {
        let dir = TempDir::new().expect("tempdir");
        let home = EnvGuard::new("HOME");
        home.set_path(dir.path());

        let prepared = prepare_session_upload(sample_record(), "hello".to_string())
            .expect("prepare session upload");
        let context = UploadContext {
            client: ApiClient::new("http://127.0.0.1:9"),
            token: None,
        };

        let outcome = upload_or_queue_prepared_session(&context, &prepared)
            .await
            .expect("queue upload");

        assert_eq!(
            outcome,
            LiveUploadOutcome::Queued {
                reason: "missing Cadence CLI auth token".to_string()
            }
        );
        assert_eq!(pending_upload_count().await.expect("pending count"), 1);
    }

    #[tokio::test]
    #[serial]
    async fn upload_or_queue_prepared_session_queues_with_reason_when_auth_rejected() {
        let dir = TempDir::new().expect("tempdir");
        let home = EnvGuard::new("HOME");
        home.set_path(dir.path());

        let prepared = prepare_session_upload(sample_record(), "hello".to_string())
            .expect("prepare session upload");
        let server = spawn_test_upload_server(TestUploadServerConfig {
            upload_url_statuses: vec![401],
            ..TestUploadServerConfig::default()
        })
        .await
        .expect("spawn test server");
        let context = UploadContext {
            client: ApiClient::new(&server.base_url),
            token: Some("test-token".to_string()),
        };

        let outcome = upload_or_queue_prepared_session(&context, &prepared)
            .await
            .expect("queue rejected upload");

        assert_eq!(
            outcome,
            LiveUploadOutcome::Queued {
                reason: "Cadence CLI auth token was rejected".to_string()
            }
        );
        assert_eq!(pending_upload_count().await.expect("pending count"), 1);
    }

    #[tokio::test]
    #[serial]
    async fn process_pending_uploads_rebuilds_remote_after_repo_remote_is_added() {
        let dir = TempDir::new().expect("tempdir");
        let home = EnvGuard::new("HOME");
        home.set_path(dir.path());

        let repo = init_repo().await;
        let repo_root = repo.path().to_string_lossy().to_string();
        let record = note::SessionRecord {
            session_uid: "queued-remote-resolution".to_string(),
            repo_root,
            repo_remote_url: None,
            ..sample_record()
        };
        let envelope = note::SessionEnvelope {
            record,
            session_content: "hello".to_string(),
        };
        enqueue_pending_envelope(&envelope, "repo has no push remote URL")
            .await
            .expect("enqueue pending envelope");

        run_git(
            repo.path(),
            &["remote", "add", "origin", "git@github.com:team/example.git"],
        )
        .await;

        let server = spawn_test_upload_server(TestUploadServerConfig::default())
            .await
            .expect("spawn test server");
        let context = UploadContext {
            client: ApiClient::new(&server.base_url),
            token: Some("test-token".to_string()),
        };

        let summary = process_pending_uploads(&context, 1)
            .await
            .expect("process pending uploads");

        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.uploaded, 1);
        assert_eq!(
            server.counts(),
            crate::upload::test_support::TestUploadServerCounts {
                upload_url_requests: 1,
                uploads: 1,
                confirms: 1,
            }
        );
        assert_eq!(
            pending_upload_count().await.expect("pending upload count"),
            0
        );
    }

    #[tokio::test]
    #[serial]
    async fn process_pending_uploads_refreshes_branch_and_head_metadata() {
        let dir = TempDir::new().expect("tempdir");
        let home = EnvGuard::new("HOME");
        home.set_path(dir.path());

        let repo = init_repo().await;
        run_git(
            repo.path(),
            &["remote", "add", "origin", "git@github.com:team/example.git"],
        )
        .await;
        let branch = run_git(repo.path(), &["symbolic-ref", "--short", "HEAD"]).await;
        let head_sha = run_git(repo.path(), &["rev-parse", "HEAD"]).await;

        let record = note::SessionRecord {
            session_uid: "queued-git-metadata-resolution".to_string(),
            repo_root: repo.path().to_string_lossy().to_string(),
            repo_remote_url: None,
            git_ref: "refs/heads/unknown".to_string(),
            head_sha: "unknown".to_string(),
            ..sample_record()
        };
        let envelope = note::SessionEnvelope {
            record,
            session_content: "hello".to_string(),
        };
        enqueue_pending_envelope(&envelope, "repo metadata unavailable")
            .await
            .expect("enqueue pending envelope");

        let server = spawn_test_upload_server(TestUploadServerConfig::default())
            .await
            .expect("spawn test server");
        let context = UploadContext {
            client: ApiClient::new(&server.base_url),
            token: Some("test-token".to_string()),
        };

        let summary = process_pending_uploads(&context, 1)
            .await
            .expect("process pending uploads");

        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.uploaded, 1);
        let requests = server.upload_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].git_ref, format!("refs/heads/{branch}"));
        assert_eq!(requests[0].head_sha, head_sha);
    }

    #[tokio::test]
    async fn attempt_upload_retries_confirm_failures_with_fresh_upload_cycles() {
        let server = spawn_test_upload_server(TestUploadServerConfig {
            confirm_statuses: vec![422, 200],
            ..TestUploadServerConfig::default()
        })
        .await
        .expect("spawn test server");
        let prepared = prepare_session_upload(sample_record(), "hello".to_string())
            .expect("prepare session upload");
        let client = ApiClient::new(&server.base_url);

        let first = attempt_upload(
            &client,
            "test-token",
            &prepared.request,
            &prepared.compressed_payload,
        )
        .await;
        assert!(matches!(first, Err(UploadAttemptError::Retryable(_))));

        let second = attempt_upload(
            &client,
            "test-token",
            &prepared.request,
            &prepared.compressed_payload,
        )
        .await
        .expect("retry fresh upload cycle");
        assert_eq!(second, UploadAttemptOutcome::Uploaded);
        assert_eq!(
            server.counts(),
            crate::upload::test_support::TestUploadServerCounts {
                upload_url_requests: 2,
                uploads: 2,
                confirms: 2,
            }
        );
    }

    #[tokio::test]
    #[serial]
    async fn process_pending_uploads_drops_repeated_local_git_state_failures() {
        let dir = TempDir::new().expect("tempdir");
        let home = EnvGuard::new("HOME");
        home.set_path(dir.path());

        let pending_root = dir.path().join(".cadence/cli/pending-uploads");
        tokio::fs::create_dir_all(&pending_root)
            .await
            .expect("create pending dir");

        let record = PendingUploadRecord {
            session_uid: "uid-local-state".to_string(),
            request: None,
            envelope: Some(note::SessionEnvelope {
                record: note::SessionRecord {
                    repo_root: dir
                        .path()
                        .join("missing-repo")
                        .to_string_lossy()
                        .to_string(),
                    repo_remote_url: None,
                    ..sample_record()
                },
                session_content: "content".to_string(),
            }),
            enqueued_at: note::now_rfc3339(),
            updated_at: note::now_rfc3339(),
            attempt_count: MAX_LOCAL_GIT_STATE_ATTEMPTS - 1,
            next_attempt_at_epoch: 0,
            last_error: Some("repo has no push remote URL".to_string()),
        };
        write_pending_record(&pending_root, &record)
            .await
            .expect("write pending record");

        let server = spawn_test_upload_server(TestUploadServerConfig::default())
            .await
            .expect("spawn test server");
        let context = UploadContext {
            client: ApiClient::new(&server.base_url),
            token: Some("test-token".to_string()),
        };

        let summary = process_pending_uploads(&context, 1)
            .await
            .expect("process pending uploads");

        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.dropped_permanent, 1);
        assert_eq!(pending_upload_count().await.expect("pending count"), 0);
        assert_eq!(server.counts().upload_url_requests, 0);
    }

    #[tokio::test]
    #[serial]
    async fn process_pending_uploads_drops_permanent_data_failures_immediately() {
        let dir = TempDir::new().expect("tempdir");
        let home = EnvGuard::new("HOME");
        home.set_path(dir.path());

        let pending_root = dir.path().join(".cadence/cli/pending-uploads");
        tokio::fs::create_dir_all(&pending_root)
            .await
            .expect("create pending dir");

        let prepared = prepare_session_upload(sample_record(), "hello".to_string())
            .expect("prepare session upload");
        let record = PendingUploadRecord {
            session_uid: prepared.session_uid.clone(),
            request: Some(prepared.request.clone()),
            envelope: None,
            enqueued_at: note::now_rfc3339(),
            updated_at: note::now_rfc3339(),
            attempt_count: 0,
            next_attempt_at_epoch: 0,
            last_error: Some("missing payload".to_string()),
        };
        write_pending_record(&pending_root, &record)
            .await
            .expect("write pending record");

        let server = spawn_test_upload_server(TestUploadServerConfig::default())
            .await
            .expect("spawn test server");
        let context = UploadContext {
            client: ApiClient::new(&server.base_url),
            token: Some("test-token".to_string()),
        };

        let summary = process_pending_uploads(&context, 1)
            .await
            .expect("process pending uploads");

        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.dropped_permanent, 1);
        assert_eq!(pending_upload_count().await.expect("pending count"), 0);
        assert_eq!(server.counts().upload_url_requests, 0);
    }

    #[tokio::test]
    #[serial]
    async fn process_pending_uploads_retries_local_git_state_failures_below_threshold() {
        let dir = TempDir::new().expect("tempdir");
        let home = EnvGuard::new("HOME");
        home.set_path(dir.path());

        let pending_root = dir.path().join(".cadence/cli/pending-uploads");
        tokio::fs::create_dir_all(&pending_root)
            .await
            .expect("create pending dir");

        let record = PendingUploadRecord {
            session_uid: "uid-local-state-retry".to_string(),
            request: None,
            envelope: Some(note::SessionEnvelope {
                record: note::SessionRecord {
                    repo_root: dir
                        .path()
                        .join("missing-repo")
                        .to_string_lossy()
                        .to_string(),
                    repo_remote_url: None,
                    ..sample_record()
                },
                session_content: "content".to_string(),
            }),
            enqueued_at: note::now_rfc3339(),
            updated_at: note::now_rfc3339(),
            attempt_count: MAX_LOCAL_GIT_STATE_ATTEMPTS - 2,
            next_attempt_at_epoch: 0,
            last_error: Some("repo has no push remote URL".to_string()),
        };
        write_pending_record(&pending_root, &record)
            .await
            .expect("write pending record");

        let server = spawn_test_upload_server(TestUploadServerConfig::default())
            .await
            .expect("spawn test server");
        let context = UploadContext {
            client: ApiClient::new(&server.base_url),
            token: Some("test-token".to_string()),
        };

        let summary = process_pending_uploads(&context, 1)
            .await
            .expect("process pending uploads");

        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.dropped_permanent, 0);
        assert_eq!(pending_upload_count().await.expect("pending count"), 1);

        let updated = load_pending_record(&record_path(&pending_root, "uid-local-state-retry"))
            .await
            .expect("pending record");
        assert_eq!(updated.attempt_count, MAX_LOCAL_GIT_STATE_ATTEMPTS - 1);
        assert!(updated.last_error.is_some());
        assert_eq!(server.counts().upload_url_requests, 0);
    }
}
