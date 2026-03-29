//! Session publication pipeline and durable retry state.

use crate::api_client::{
    ApiClient, AuthenticatedRequestError, CreateSessionPublicationRequest,
    SessionUploadConfirmResponse, UserOrgInfo,
};
use crate::config;
use crate::git;
use crate::publication::{
    LogicalSessionKey, PreparedPublication, PublicationObservations, new_publish_uid,
    prepare_publication,
};
use crate::publication_state::{
    PublicationStateRecord, PublicationStatus, StoredPublication, load_all_records, load_payload,
    now_rfc3339, remove_record, upsert_record,
};
use anyhow::Result;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::Mutex;

const API_TIMEOUT_SECS: u64 = 15;
const PRESIGNED_UPLOAD_TIMEOUT_SECS: u64 = 300;
const RETRY_DELAYS_SECS: &[i64] = &[0, 1, 2, 4, 8, 16, 32, 60, 120, 300, 600];

/// Shared upload context for one CLI invocation.
#[derive(Debug)]
pub struct UploadContext {
    client: ApiClient,
    token: Option<String>,
    user_orgs: Mutex<Option<Vec<UserOrgInfo>>>,
}

impl UploadContext {
    /// Returns whether the current context has an auth token available.
    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }
}

/// Raw session content plus publish-time observations ready for preparation.
#[derive(Debug, Clone)]
pub struct ObservedSessionUpload {
    pub logical_session: LogicalSessionKey,
    pub observations: PublicationObservations,
    pub raw_session_content: String,
}

/// Prepared publication data ready for immediate upload or durable queueing.
#[derive(Debug, Clone)]
pub struct PreparedSessionUpload {
    pub prepared: PreparedPublication,
}

/// Outcome for an attempted live publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveUploadOutcome {
    Uploaded,
    AlreadyExists,
    Queued { reason: String },
}

/// Aggregate result when draining pending publication state.
#[derive(Debug, Default, Clone, Copy)]
pub struct PendingUploadSummary {
    pub attempted: usize,
    pub uploaded: usize,
    pub already_existed: usize,
    pub skipped_repo_not_associated: usize,
    pub dropped_permanent: usize,
    pub auth_required: bool,
}

#[derive(Debug)]
enum PublishAttemptError {
    Unauthorized,
    Retryable(String),
}

/// Resolves the API client and auth state used for session publication.
pub async fn resolve_upload_context(api_url_override: Option<&str>) -> Result<UploadContext> {
    let cfg = config::CliConfig::load().await?;
    let resolved = cfg.resolve_api_url(api_url_override);
    let token = resolve_cli_auth_token(&cfg);
    Ok(UploadContext {
        client: ApiClient::new(&resolved.url).await?,
        token,
        user_orgs: Mutex::new(None),
    })
}

/// Converts observed session data into a prepared publication.
pub fn prepare_session_upload(observed: ObservedSessionUpload) -> Result<PreparedSessionUpload> {
    Ok(PreparedSessionUpload {
        prepared: prepare_publication(
            observed.logical_session,
            observed.observations,
            observed.raw_session_content,
        )?,
    })
}

/// Attempts to upload a prepared session immediately or queues it durably.
pub async fn upload_or_queue_prepared_session(
    context: &UploadContext,
    prepared: &PreparedSessionUpload,
) -> Result<LiveUploadOutcome> {
    prepare_state_and_attempt(context, prepared, None).await
}

/// Drains due pending publication records.
pub async fn process_pending_uploads(
    context: &UploadContext,
    max_items: usize,
) -> Result<PendingUploadSummary> {
    process_pending_uploads_matching(context, max_items, None).await
}

/// Drains due pending publication records scoped to one repository.
pub async fn process_pending_uploads_for_repo(
    context: &UploadContext,
    max_items: usize,
    repo_filter: &Path,
) -> Result<PendingUploadSummary> {
    process_pending_uploads_matching(context, max_items, Some(repo_filter)).await
}

/// Returns the number of pending publication records for one repository.
pub async fn pending_upload_count_for_repo(repo_filter: &Path) -> Result<usize> {
    pending_upload_count_matching(Some(repo_filter)).await
}

/// Returns the total number of pending publication records.
pub async fn pending_upload_count() -> Result<usize> {
    pending_upload_count_matching(None).await
}

async fn process_pending_uploads_matching(
    context: &UploadContext,
    max_items: usize,
    repo_filter: Option<&Path>,
) -> Result<PendingUploadSummary> {
    let records = pending_records(repo_filter).await?;
    if context.token.is_none() {
        return Ok(PendingUploadSummary {
            auth_required: !records.is_empty(),
            ..PendingUploadSummary::default()
        });
    }

    let mut summary = PendingUploadSummary::default();
    for stored in records.into_iter().take(max_items) {
        summary.attempted += 1;
        let Some(payload) = load_payload(&stored.storage_key).await? else {
            remove_record(&stored.storage_key).await?;
            summary.dropped_permanent += 1;
            continue;
        };
        let prepared = rebuild_prepared_upload(&stored.record, payload).await?;

        match prepare_state_and_attempt(context, &prepared, Some(stored)).await? {
            LiveUploadOutcome::Uploaded => summary.uploaded += 1,
            LiveUploadOutcome::AlreadyExists => summary.already_existed += 1,
            LiveUploadOutcome::Queued { .. } => {}
        }
    }

    Ok(summary)
}

async fn pending_upload_count_matching(repo_filter: Option<&Path>) -> Result<usize> {
    Ok(all_pending_records(repo_filter).await?.len())
}

async fn pending_records(repo_filter: Option<&Path>) -> Result<Vec<StoredPublication>> {
    let now_epoch = now_epoch();
    let mut records = all_pending_records(repo_filter).await?;
    records.retain(|stored| stored.record.next_attempt_at_epoch <= now_epoch);
    Ok(records)
}

async fn all_pending_records(repo_filter: Option<&Path>) -> Result<Vec<StoredPublication>> {
    let mut records = load_all_records().await?;
    records.retain(|stored| {
        stored.record.status != PublicationStatus::Published
            && repo_filter
                .map(|filter| record_matches_repo(&stored.record, filter))
                .unwrap_or(true)
    });
    Ok(records)
}

fn record_matches_repo(record: &PublicationStateRecord, repo_filter: &Path) -> bool {
    let filter = repo_filter.to_string_lossy();
    if record.observations.canonical_repo_root == filter {
        return true;
    }
    record
        .observations
        .worktree_roots
        .iter()
        .any(|root| root == &*filter)
}

async fn rebuild_prepared_upload(
    record: &PublicationStateRecord,
    raw_session_content: String,
) -> Result<PreparedSessionUpload> {
    let observations = refresh_observations(&record.observations).await?;
    prepare_session_upload(ObservedSessionUpload {
        logical_session: record.logical_session.clone(),
        observations,
        raw_session_content,
    })
}

async fn refresh_observations(
    observations: &PublicationObservations,
) -> Result<PublicationObservations> {
    let Some(repo_root) = resolve_refresh_repo_root(observations).await else {
        return Ok(observations.clone());
    };

    let remote_urls = git::remote_urls_at(&repo_root).await?;
    let canonical_remote_url = git::preferred_remote_url_at(&repo_root)
        .await?
        .or_else(|| remote_urls.first().cloned())
        .unwrap_or_default();

    Ok(PublicationObservations {
        canonical_remote_url,
        remote_urls,
        canonical_repo_root: repo_root.to_string_lossy().to_string(),
        worktree_roots: git::repo_and_worktree_roots_at(&repo_root).await,
        cwd: observations.cwd.clone(),
        git_ref: git::current_branch_at(&repo_root)
            .await
            .ok()
            .flatten()
            .map(|branch| format!("refs/heads/{branch}")),
        head_commit_sha: git::head_sha_at(&repo_root).await.ok().flatten(),
        git_user_email: git::config_get_at(&repo_root, "user.email")
            .await
            .ok()
            .flatten(),
        git_user_name: git::config_get_at(&repo_root, "user.name")
            .await
            .ok()
            .flatten(),
        cli_version: observations.cli_version.clone(),
    })
}

async fn resolve_refresh_repo_root(observations: &PublicationObservations) -> Option<PathBuf> {
    let mut candidates = BTreeSet::new();
    candidates.insert(observations.canonical_repo_root.clone());
    candidates.extend(observations.worktree_roots.iter().cloned());

    for candidate in candidates {
        if candidate.trim().is_empty() {
            continue;
        }
        if let Ok(resolution) = git::resolve_repo_root_with_fallbacks(Path::new(&candidate)).await {
            return Some(resolution.repo_root);
        }
    }

    None
}

async fn prepare_state_and_attempt(
    context: &UploadContext,
    prepared: &PreparedSessionUpload,
    existing: Option<StoredPublication>,
) -> Result<LiveUploadOutcome> {
    if prepared.prepared.observations.remote_urls.is_empty() {
        let reason = "repo has no remote URL observations".to_string();
        persist_state(
            existing,
            &prepared.prepared,
            None,
            PublicationStatus::AwaitingRemote,
            None,
            Some(reason.clone()),
        )
        .await?;
        return Ok(LiveUploadOutcome::Queued { reason });
    }

    let target_org_id =
        match resolve_target_org(context, &prepared.prepared.observations.remote_urls).await {
            Ok(org_id) => Some(org_id),
            Err(reason) => {
                persist_state(
                    existing,
                    &prepared.prepared,
                    None,
                    PublicationStatus::AwaitingOrg,
                    None,
                    Some(reason.clone()),
                )
                .await?;
                return Ok(LiveUploadOutcome::Queued { reason });
            }
        };

    let current =
        load_existing_for_org(&prepared.prepared.logical_session, target_org_id.as_deref())
            .await?
            .or(existing);

    if let Some(record) = current.as_ref().map(|stored| &stored.record)
        && record.last_published_content_sha256.as_deref()
            == Some(prepared.prepared.content_sha256.as_str())
        && record.last_published_metadata_sha256.as_deref()
            == Some(prepared.prepared.metadata_sha256.as_str())
        && record.status == PublicationStatus::Published
    {
        return Ok(LiveUploadOutcome::AlreadyExists);
    }

    let publish_uid = current
        .as_ref()
        .filter(|stored| {
            stored.record.current_content_sha256 == prepared.prepared.content_sha256
                && stored.record.current_metadata_sha256 == prepared.prepared.metadata_sha256
        })
        .and_then(|stored| stored.record.publish_uid.clone())
        .unwrap_or_else(new_publish_uid);

    persist_state(
        current.clone(),
        &prepared.prepared,
        target_org_id.clone(),
        PublicationStatus::Publishing,
        Some(publish_uid.clone()),
        None,
    )
    .await?;

    let Some(token) = context.token.as_deref() else {
        persist_state(
            current,
            &prepared.prepared,
            target_org_id,
            PublicationStatus::RetryableFailure,
            Some(publish_uid),
            Some("missing Cadence CLI auth token".to_string()),
        )
        .await?;
        return Ok(LiveUploadOutcome::Queued {
            reason: "missing Cadence CLI auth token".to_string(),
        });
    };

    match attempt_upload(
        &context.client,
        token,
        target_org_id.as_deref().expect("target org"),
        &prepared.prepared,
        &publish_uid,
    )
    .await
    {
        Ok(_outcome) => {
            persist_success(current, &prepared.prepared, target_org_id, publish_uid).await?;
            Ok(LiveUploadOutcome::Uploaded)
        }
        Err(PublishAttemptError::Unauthorized) => {
            let reason = "Cadence CLI auth token was rejected".to_string();
            persist_state(
                current,
                &prepared.prepared,
                target_org_id,
                PublicationStatus::RetryableFailure,
                Some(publish_uid),
                Some(reason.clone()),
            )
            .await?;
            Ok(LiveUploadOutcome::Queued { reason })
        }
        Err(PublishAttemptError::Retryable(message)) => {
            persist_state(
                current,
                &prepared.prepared,
                target_org_id,
                PublicationStatus::RetryableFailure,
                Some(publish_uid),
                Some(message),
            )
            .await?;
            Ok(LiveUploadOutcome::Queued {
                reason: "session publication will retry later".to_string(),
            })
        }
    }
}

async fn persist_success(
    existing: Option<StoredPublication>,
    prepared: &PreparedPublication,
    target_org_id: Option<String>,
    publish_uid: String,
) -> Result<()> {
    let now = now_rfc3339();
    let mut record = build_record(
        existing.as_ref().map(|stored| &stored.record),
        prepared,
        target_org_id.clone(),
        PublicationStatus::Published,
        Some(publish_uid),
        None,
    );
    record.last_published_content_sha256 = Some(prepared.content_sha256.clone());
    record.last_published_metadata_sha256 = Some(prepared.metadata_sha256.clone());
    record.updated_at = now;
    upsert_record(&record, None).await?;
    if let Some(existing) = existing
        && existing.record.target_org_id != target_org_id
    {
        remove_record(&existing.storage_key).await?;
    }
    Ok(())
}

async fn persist_state(
    existing: Option<StoredPublication>,
    prepared: &PreparedPublication,
    target_org_id: Option<String>,
    status: PublicationStatus,
    publish_uid: Option<String>,
    last_error: Option<String>,
) -> Result<()> {
    let record = build_record(
        existing.as_ref().map(|stored| &stored.record),
        prepared,
        target_org_id.clone(),
        status,
        publish_uid,
        last_error,
    );
    upsert_record(&record, Some(&prepared.raw_session_content)).await?;
    if let Some(existing) = existing
        && existing.record.target_org_id != target_org_id
    {
        remove_record(&existing.storage_key).await?;
    }
    Ok(())
}

fn build_record(
    existing: Option<&PublicationStateRecord>,
    prepared: &PreparedPublication,
    target_org_id: Option<String>,
    status: PublicationStatus,
    publish_uid: Option<String>,
    last_error: Option<String>,
) -> PublicationStateRecord {
    let now = now_rfc3339();
    let attempt_count = existing.map(|record| record.attempt_count).unwrap_or(0)
        + u32::from(matches!(status, PublicationStatus::RetryableFailure));
    PublicationStateRecord {
        logical_session: prepared.logical_session.clone(),
        target_org_id,
        status,
        current_content_sha256: prepared.content_sha256.clone(),
        current_metadata_sha256: prepared.metadata_sha256.clone(),
        last_published_content_sha256: existing
            .and_then(|record| record.last_published_content_sha256.clone()),
        last_published_metadata_sha256: existing
            .and_then(|record| record.last_published_metadata_sha256.clone()),
        publish_uid: publish_uid.or_else(|| existing.and_then(|record| record.publish_uid.clone())),
        publication_id: existing.and_then(|record| record.publication_id.clone()),
        upload_sha256: prepared.upload_sha256.clone(),
        attempt_count,
        next_attempt_at_epoch: next_attempt_epoch(attempt_count),
        last_error,
        observations: prepared.observations.clone(),
        updated_at: now.clone(),
        created_at: existing
            .map(|record| record.created_at.clone())
            .unwrap_or(now),
    }
}

fn next_attempt_epoch(attempt_count: u32) -> i64 {
    let idx = usize::try_from(attempt_count)
        .unwrap_or(usize::MAX)
        .min(RETRY_DELAYS_SECS.len().saturating_sub(1));
    now_epoch() + RETRY_DELAYS_SECS[idx]
}

async fn load_existing_for_org(
    logical_session: &LogicalSessionKey,
    target_org_id: Option<&str>,
) -> Result<Option<StoredPublication>> {
    let stored = load_all_records().await?.into_iter().find(|stored| {
        stored.record.logical_session == *logical_session
            && stored.record.target_org_id.as_deref() == target_org_id
    });
    normalize_stored_publication(stored).await
}

async fn normalize_stored_publication(
    stored: Option<StoredPublication>,
) -> Result<Option<StoredPublication>> {
    let Some(mut stored) = stored else {
        return Ok(None);
    };

    if stored.record.status != PublicationStatus::Published {
        return Ok(Some(stored));
    }

    let normalized_metadata_sha256 =
        crate::publication::metadata_sha256(&stored.record.observations)?;
    let current_changed = stored.record.current_metadata_sha256 != normalized_metadata_sha256;
    let last_published_changed = stored.record.last_published_metadata_sha256.as_deref()
        != Some(normalized_metadata_sha256.as_str());

    if !current_changed && !last_published_changed {
        return Ok(Some(stored));
    }

    stored.record.current_metadata_sha256 = normalized_metadata_sha256.clone();
    stored.record.last_published_metadata_sha256 = Some(normalized_metadata_sha256);
    stored.record.updated_at = now_rfc3339();
    upsert_record(&stored.record, None).await?;
    Ok(Some(stored))
}

async fn resolve_target_org(
    context: &UploadContext,
    remote_urls: &[String],
) -> Result<String, String> {
    let mut owners = remote_urls
        .iter()
        .filter_map(|remote| git::parse_org_from_url(remote))
        .collect::<Vec<_>>();
    owners.sort();
    owners.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    if owners.is_empty() {
        return Err("repo has no GitHub remote owner observations".to_string());
    }

    let configured_org = git::config_get_global("ai.cadence.org")
        .await
        .ok()
        .flatten();

    let user_orgs = fetch_user_orgs(context)
        .await
        .map_err(|err| err.to_string())?;
    let matches = user_orgs
        .into_iter()
        .filter(|org| org.org_id.is_some())
        .filter(|org| {
            owners
                .iter()
                .any(|owner| owner.eq_ignore_ascii_case(&org.github_org_login))
        })
        .filter(|org| {
            configured_org
                .as_ref()
                .map(|configured| configured.eq_ignore_ascii_case(&org.github_org_login))
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();

    if matches.is_empty() {
        if configured_org.is_some() {
            return Err(
                "configured Cadence org does not match any accessible remote owner".to_string(),
            );
        }
        return Err("no accessible Cadence org matched the repo remote owner".to_string());
    }
    if matches.len() > 1 {
        return Err("repo remotes matched multiple accessible Cadence orgs".to_string());
    }
    Ok(matches[0].org_id.clone().expect("org_id"))
}

async fn fetch_user_orgs(context: &UploadContext) -> Result<Vec<UserOrgInfo>> {
    let mut guard = context.user_orgs.lock().await;
    if let Some(cached) = guard.as_ref() {
        return Ok(cached.clone());
    }
    let token = context
        .token
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing Cadence CLI auth token"))?;
    let response = context
        .client
        .list_user_orgs(token, Duration::from_secs(API_TIMEOUT_SECS))
        .await
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    *guard = Some(response.orgs.clone());
    Ok(response.orgs)
}

async fn attempt_upload(
    client: &ApiClient,
    token: &str,
    org_id: &str,
    prepared: &PreparedPublication,
    publish_uid: &str,
) -> std::result::Result<(), PublishAttemptError> {
    let create = client
        .create_session_publication(
            token,
            org_id,
            &CreateSessionPublicationRequest {
                agent: prepared.logical_session.agent.clone(),
                agent_session_id: prepared.logical_session.agent_session_id.clone(),
                publish_uid: publish_uid.to_string(),
                upload_sha256: prepared.upload_sha256.clone(),
                metadata_sha256: prepared.metadata_sha256.clone(),
                canonical_remote_url: prepared.observations.canonical_remote_url.clone(),
                remote_urls: prepared.observations.remote_urls.clone(),
                canonical_repo_root: prepared.observations.canonical_repo_root.clone(),
                worktree_roots: prepared.observations.worktree_roots.clone(),
                cwd: prepared.observations.cwd.clone(),
                git_ref: prepared.observations.git_ref.clone(),
                head_commit_sha: prepared.observations.head_commit_sha.clone(),
                git_user_email: prepared.observations.git_user_email.clone(),
                git_user_name: prepared.observations.git_user_name.clone(),
                cli_version: prepared.observations.cli_version.clone(),
            },
            Duration::from_secs(API_TIMEOUT_SECS),
        )
        .await
        .map_err(map_request_error)?;

    client
        .upload_presigned(
            &create.upload_url,
            "application/jsonl",
            prepared.raw_session_content.as_bytes(),
            Duration::from_secs(PRESIGNED_UPLOAD_TIMEOUT_SECS),
        )
        .await
        .map_err(map_request_error)?;

    let _confirm: SessionUploadConfirmResponse = client
        .confirm_session_upload(
            token,
            &create.publication_id,
            org_id,
            Duration::from_secs(API_TIMEOUT_SECS),
        )
        .await
        .map_err(map_request_error)?;

    Ok(())
}

fn map_request_error(error: AuthenticatedRequestError) -> PublishAttemptError {
    match error {
        AuthenticatedRequestError::Unauthorized => PublishAttemptError::Unauthorized,
        other => PublishAttemptError::Retryable(other.to_string()),
    }
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn resolve_cli_auth_token(cfg: &config::CliConfig) -> Option<String> {
    cfg.auth_token()
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use anyhow::Context;
    use serde_json::Value;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[derive(Debug, Default, Clone)]
    pub struct TestUploadServerConfig {
        pub create_statuses: Vec<u16>,
        pub upload_statuses: Vec<u16>,
        pub confirm_statuses: Vec<u16>,
        pub user_orgs: Vec<Value>,
        pub upload_response_delay_ms: u64,
    }

    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    pub struct TestUploadServerCounts {
        pub create_requests: usize,
        pub uploads: usize,
        pub confirms: usize,
        pub user_org_requests: usize,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct UploadRequest {
        pub content_type: Option<String>,
        pub body: String,
    }

    #[derive(Debug, Clone)]
    pub struct TestUploadServer {
        pub base_url: String,
        state: Arc<Mutex<TestUploadServerState>>,
    }

    #[derive(Debug)]
    struct TestUploadServerState {
        counts: TestUploadServerCounts,
        create_requests: Vec<CreateSessionPublicationRequest>,
        upload_requests: Vec<UploadRequest>,
        create_statuses: VecDeque<u16>,
        upload_statuses: VecDeque<u16>,
        confirm_statuses: VecDeque<u16>,
        user_orgs: Vec<Value>,
        upload_response_delay_ms: u64,
    }

    impl TestUploadServer {
        pub fn counts(&self) -> TestUploadServerCounts {
            self.state.lock().expect("server state").counts.clone()
        }

        pub fn create_requests(&self) -> Vec<CreateSessionPublicationRequest> {
            self.state
                .lock()
                .expect("server state")
                .create_requests
                .clone()
        }

        pub fn upload_requests(&self) -> Vec<UploadRequest> {
            self.state
                .lock()
                .expect("server state")
                .upload_requests
                .clone()
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
        let state = Arc::new(Mutex::new(TestUploadServerState {
            counts: TestUploadServerCounts::default(),
            create_requests: Vec::new(),
            upload_requests: Vec::new(),
            create_statuses: config.create_statuses.into(),
            upload_statuses: config.upload_statuses.into(),
            confirm_statuses: config.confirm_statuses.into(),
            user_orgs: if config.user_orgs.is_empty() {
                vec![serde_json::json!({
                    "github_org_id": 1,
                    "github_org_login": "test-org",
                    "display_name": "Test Org",
                    "is_personal": false,
                    "is_onboarded": true,
                    "has_active_installation": true,
                    "org_id": "org-test"
                })]
            } else {
                config.user_orgs
            },
            upload_response_delay_ms: config.upload_response_delay_ms,
        }));

        let base_url = format!("http://{}", addr);
        let task_base_url = base_url.clone();
        let task_state = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let state = Arc::clone(&task_state);
                let base_url = task_base_url.clone();
                tokio::spawn(async move {
                    let Ok(request) = read_http_request(&mut stream).await else {
                        return;
                    };
                    let mut lines = request.lines();
                    let request_line = lines.next().unwrap_or_default();
                    let mut parts = request_line.split_whitespace();
                    let method = parts.next().unwrap_or_default();
                    let path = parts.next().unwrap_or_default();
                    let content_type = lines.clone().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-type")
                            .then(|| value.trim().to_string())
                    });
                    let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();

                    let (status, response_body) = match (method, path) {
                        ("GET", "/api/user/orgs") => {
                            let mut guard = state.lock().expect("server state");
                            guard.counts.user_org_requests += 1;
                            (
                                200,
                                serde_json::json!({ "data": { "orgs": guard.user_orgs } })
                                    .to_string(),
                            )
                        }
                        ("POST", "/api/v2/session-publications") => {
                            let mut guard = state.lock().expect("server state");
                            guard.counts.create_requests += 1;
                            let status = guard.create_statuses.pop_front().unwrap_or(200);
                            if status == 200 {
                                if let Ok(request) =
                                    serde_json::from_str::<CreateSessionPublicationRequest>(body)
                                {
                                    guard.create_requests.push(request);
                                }
                                (
                                    200,
                                    serde_json::json!({
                                        "publication_id": "publication-1",
                                        "upload_url": format!("{base_url}/uploads/publication-1"),
                                        "org_id": "org-test"
                                    })
                                    .to_string(),
                                )
                            } else {
                                (status, format!("create failed with {status}"))
                            }
                        }
                        ("PUT", path) if path.starts_with("/uploads/") => {
                            let (status, delay_ms) = {
                                let mut guard = state.lock().expect("server state");
                                guard.counts.uploads += 1;
                                guard.upload_requests.push(UploadRequest {
                                    content_type,
                                    body: body.to_string(),
                                });
                                (
                                    guard.upload_statuses.pop_front().unwrap_or(200),
                                    guard.upload_response_delay_ms,
                                )
                            };
                            if delay_ms > 0 {
                                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                            }
                            if status == 200 {
                                (200, String::new())
                            } else {
                                (status, format!("upload failed with {status}"))
                            }
                        }
                        ("POST", path)
                            if path.starts_with("/api/v2/session-publications/")
                                && path.ends_with("/confirm") =>
                        {
                            let mut guard = state.lock().expect("server state");
                            guard.counts.confirms += 1;
                            let status = guard.confirm_statuses.pop_front().unwrap_or(200);
                            if status == 200 {
                                (200, serde_json::json!({ "status": "enqueued" }).to_string())
                            } else {
                                (status, format!("confirm failed with {status}"))
                            }
                        }
                        _ => (404, "not found".to_string()),
                    };

                    let response = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                        response_body.len(),
                        response_body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        Ok(TestUploadServer { base_url, state })
    }

    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> Result<String> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        let mut content_length = None;

        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);

            if buf.len() >= 64 * 1024 {
                break;
            }

            let Some(headers_end) = buf.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let headers_len = headers_end + 4;
            if content_length.is_none() {
                let headers = String::from_utf8_lossy(&buf[..headers_len]);
                content_length = headers.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                });
            }

            match content_length {
                Some(expected_body_len) if buf.len() >= headers_len + expected_body_len => break,
                None if buf.len() >= headers_len => break,
                _ => {}
            }
        }

        if buf.is_empty() {
            anyhow::bail!("empty request");
        }

        Ok(String::from_utf8_lossy(&buf).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publication_state::{load_all_records, remove_record, storage_key};
    use serial_test::serial;
    use std::ffi::OsString;
    use tempfile::TempDir;
    use tokio::process::Command;

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

    async fn run_git(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .await
            .expect("run git");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    async fn init_repo() -> TempDir {
        let dir = TempDir::new().unwrap();
        run_git(dir.path(), &["init", "-q"]).await;
        run_git(dir.path(), &["config", "user.name", "Test User"]).await;
        run_git(dir.path(), &["config", "user.email", "test@example.com"]).await;
        tokio::fs::write(dir.path().join("README.md"), "hello")
            .await
            .unwrap();
        run_git(dir.path(), &["add", "README.md"]).await;
        run_git(dir.path(), &["commit", "-m", "init"]).await;
        dir
    }

    fn sample_observed(repo_root: &Path, remote_url: &str) -> ObservedSessionUpload {
        ObservedSessionUpload {
            logical_session: LogicalSessionKey {
                agent: "codex".to_string(),
                agent_session_id: "session-1".to_string(),
            },
            observations: PublicationObservations {
                canonical_remote_url: remote_url.to_string(),
                remote_urls: vec![remote_url.to_string()],
                canonical_repo_root: repo_root.to_string_lossy().to_string(),
                worktree_roots: vec![repo_root.to_string_lossy().to_string()],
                cwd: Some(repo_root.to_string_lossy().to_string()),
                git_ref: Some("refs/heads/main".to_string()),
                head_commit_sha: Some("abc1234".to_string()),
                git_user_email: Some("dev@example.com".to_string()),
                git_user_name: Some("Dev".to_string()),
                cli_version: Some("1.0.0".to_string()),
            },
            raw_session_content: "hello".to_string(),
        }
    }

    #[tokio::test]
    #[serial]
    async fn upload_or_queue_prepared_session_queues_without_remote_observations() {
        let home = TempDir::new().unwrap();
        let _home = EnvGuard::set_path("HOME", home.path());
        let context = UploadContext {
            client: ApiClient::new_for_test("http://127.0.0.1:9"),
            token: None,
            user_orgs: Mutex::new(None),
        };
        let prepared = prepare_session_upload(ObservedSessionUpload {
            observations: PublicationObservations {
                canonical_remote_url: String::new(),
                remote_urls: Vec::new(),
                canonical_repo_root: "/tmp/repo".to_string(),
                worktree_roots: vec!["/tmp/repo".to_string()],
                cwd: Some("/tmp/repo".to_string()),
                git_ref: None,
                head_commit_sha: None,
                git_user_email: None,
                git_user_name: None,
                cli_version: Some("1.0.0".to_string()),
            },
            ..sample_observed(Path::new("/tmp/repo"), "git@github.com:test-org/repo.git")
        })
        .unwrap();

        let outcome = upload_or_queue_prepared_session(&context, &prepared)
            .await
            .unwrap();
        assert_eq!(
            outcome,
            LiveUploadOutcome::Queued {
                reason: "repo has no remote URL observations".to_string(),
            }
        );
        assert_eq!(pending_upload_count().await.unwrap(), 1);
    }

    #[tokio::test]
    #[serial]
    async fn upload_or_queue_prepared_session_resolves_org_and_uploads() {
        let home = TempDir::new().unwrap();
        let _home = EnvGuard::set_path("HOME", home.path());
        let server =
            test_support::spawn_test_upload_server(test_support::TestUploadServerConfig::default())
                .await
                .unwrap();
        let context = UploadContext {
            client: ApiClient::new_for_test(&server.base_url),
            token: Some("token".to_string()),
            user_orgs: Mutex::new(None),
        };
        let prepared = prepare_session_upload(sample_observed(
            Path::new("/tmp/repo"),
            "git@github.com:test-org/repo.git",
        ))
        .unwrap();

        let outcome = upload_or_queue_prepared_session(&context, &prepared)
            .await
            .unwrap();
        assert_eq!(outcome, LiveUploadOutcome::Uploaded);
        assert_eq!(server.counts().create_requests, 1);
        let upload_requests = server.upload_requests();
        assert_eq!(upload_requests.len(), 1);
        assert_eq!(
            upload_requests[0].content_type.as_deref(),
            Some("application/jsonl")
        );
        assert_eq!(upload_requests[0].body, "hello");
        assert_eq!(pending_upload_count().await.unwrap(), 0);
    }

    #[tokio::test]
    #[serial]
    async fn upload_or_queue_prepared_session_skips_when_only_head_or_ref_changes() {
        let home = TempDir::new().unwrap();
        let _home = EnvGuard::set_path("HOME", home.path());
        let server =
            test_support::spawn_test_upload_server(test_support::TestUploadServerConfig::default())
                .await
                .unwrap();
        let context = UploadContext {
            client: ApiClient::new_for_test(&server.base_url),
            token: Some("token".to_string()),
            user_orgs: Mutex::new(None),
        };

        let initial = prepare_session_upload(sample_observed(
            Path::new("/tmp/repo"),
            "git@github.com:test-org/repo.git",
        ))
        .unwrap();
        let outcome = upload_or_queue_prepared_session(&context, &initial)
            .await
            .unwrap();
        assert_eq!(outcome, LiveUploadOutcome::Uploaded);

        let mut changed =
            sample_observed(Path::new("/tmp/repo"), "git@github.com:test-org/repo.git");
        changed.observations.git_ref = Some("refs/heads/feature/test".to_string());
        changed.observations.head_commit_sha = Some("deadbeef".repeat(8));
        let changed = prepare_session_upload(changed).unwrap();
        let outcome = upload_or_queue_prepared_session(&context, &changed)
            .await
            .unwrap();

        assert_eq!(outcome, LiveUploadOutcome::AlreadyExists);
        assert_eq!(server.counts().create_requests, 1);
        assert_eq!(server.upload_requests().len(), 1);
    }

    #[tokio::test]
    #[serial]
    async fn upload_or_queue_prepared_session_reuploads_content_with_latest_head_and_ref() {
        let home = TempDir::new().unwrap();
        let _home = EnvGuard::set_path("HOME", home.path());
        let server =
            test_support::spawn_test_upload_server(test_support::TestUploadServerConfig::default())
                .await
                .unwrap();
        let context = UploadContext {
            client: ApiClient::new_for_test(&server.base_url),
            token: Some("token".to_string()),
            user_orgs: Mutex::new(None),
        };

        let initial = prepare_session_upload(sample_observed(
            Path::new("/tmp/repo"),
            "git@github.com:test-org/repo.git",
        ))
        .unwrap();
        let outcome = upload_or_queue_prepared_session(&context, &initial)
            .await
            .unwrap();
        assert_eq!(outcome, LiveUploadOutcome::Uploaded);

        let mut changed =
            sample_observed(Path::new("/tmp/repo"), "git@github.com:test-org/repo.git");
        changed.raw_session_content = "hello again".to_string();
        changed.observations.git_ref = Some("refs/heads/feature/test".to_string());
        changed.observations.head_commit_sha = Some("deadbeef".repeat(8));
        let changed = prepare_session_upload(changed).unwrap();
        let outcome = upload_or_queue_prepared_session(&context, &changed)
            .await
            .unwrap();

        assert_eq!(outcome, LiveUploadOutcome::Uploaded);
        let requests = server.create_requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[1].git_ref.as_deref(),
            Some("refs/heads/feature/test")
        );
        assert_eq!(
            requests[1].head_commit_sha.as_deref(),
            Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        );
        let uploads = server.upload_requests();
        assert_eq!(uploads.len(), 2);
        assert_eq!(uploads[1].body, "hello again");
    }

    #[tokio::test]
    #[serial]
    async fn published_records_normalize_legacy_metadata_hashes_before_deduping() {
        let home = TempDir::new().unwrap();
        let _home = EnvGuard::set_path("HOME", home.path());
        let server =
            test_support::spawn_test_upload_server(test_support::TestUploadServerConfig::default())
                .await
                .unwrap();
        let context = UploadContext {
            client: ApiClient::new_for_test(&server.base_url),
            token: Some("token".to_string()),
            user_orgs: Mutex::new(None),
        };

        let prepared = prepare_session_upload(sample_observed(
            Path::new("/tmp/repo"),
            "git@github.com:test-org/repo.git",
        ))
        .unwrap();
        let legacy_metadata_sha = crate::publication::sha256_hex(
            format!(
                "{}:{}",
                prepared.prepared.metadata_sha256,
                prepared
                    .prepared
                    .observations
                    .head_commit_sha
                    .as_deref()
                    .unwrap_or_default()
            )
            .as_bytes(),
        );
        let record = PublicationStateRecord {
            logical_session: prepared.prepared.logical_session.clone(),
            target_org_id: Some("org-test".to_string()),
            status: PublicationStatus::Published,
            current_content_sha256: prepared.prepared.content_sha256.clone(),
            current_metadata_sha256: legacy_metadata_sha.clone(),
            last_published_content_sha256: Some(prepared.prepared.content_sha256.clone()),
            last_published_metadata_sha256: Some(legacy_metadata_sha),
            publish_uid: Some("pub_legacy".to_string()),
            publication_id: Some("publication-1".to_string()),
            upload_sha256: prepared.prepared.upload_sha256.clone(),
            attempt_count: 0,
            next_attempt_at_epoch: now_epoch(),
            last_error: None,
            observations: prepared.prepared.observations.clone(),
            updated_at: now_rfc3339(),
            created_at: now_rfc3339(),
        };
        upsert_record(&record, None).await.unwrap();

        let mut changed =
            sample_observed(Path::new("/tmp/repo"), "git@github.com:test-org/repo.git");
        changed.observations.git_ref = Some("refs/heads/feature/test".to_string());
        changed.observations.head_commit_sha = Some("deadbeef".repeat(8));
        let changed = prepare_session_upload(changed).unwrap();
        let outcome = upload_or_queue_prepared_session(&context, &changed)
            .await
            .unwrap();

        assert_eq!(outcome, LiveUploadOutcome::AlreadyExists);
        assert_eq!(server.counts().create_requests, 0);
        let key = storage_key(&prepared.prepared.logical_session, Some("org-test"));
        let normalized = load_all_records()
            .await
            .unwrap()
            .into_iter()
            .find(|stored| stored.storage_key == key)
            .unwrap();
        assert_eq!(
            normalized.record.current_metadata_sha256,
            prepared.prepared.metadata_sha256
        );
        assert_eq!(
            normalized.record.last_published_metadata_sha256.as_deref(),
            Some(prepared.prepared.metadata_sha256.as_str())
        );
    }

    #[tokio::test]
    #[serial]
    async fn upload_or_queue_prepared_session_queues_when_org_is_ambiguous() {
        let home = TempDir::new().unwrap();
        let _home = EnvGuard::set_path("HOME", home.path());
        let context = UploadContext {
            client: ApiClient::new_for_test("http://127.0.0.1:9"),
            token: Some("token".to_string()),
            user_orgs: Mutex::new(Some(vec![
                UserOrgInfo {
                    github_org_id: 1,
                    github_org_login: "test-org".to_string(),
                    display_name: Some("Test Org".to_string()),
                    is_personal: false,
                    is_onboarded: true,
                    has_active_installation: true,
                    org_id: Some("org-1".to_string()),
                },
                UserOrgInfo {
                    github_org_id: 2,
                    github_org_login: "TEST-ORG".to_string(),
                    display_name: Some("Duplicate Org".to_string()),
                    is_personal: false,
                    is_onboarded: true,
                    has_active_installation: true,
                    org_id: Some("org-2".to_string()),
                },
            ])),
        };
        let prepared = prepare_session_upload(sample_observed(
            Path::new("/tmp/repo"),
            "git@github.com:test-org/repo.git",
        ))
        .unwrap();

        let outcome = upload_or_queue_prepared_session(&context, &prepared)
            .await
            .unwrap();
        assert_eq!(
            outcome,
            LiveUploadOutcome::Queued {
                reason: "repo remotes matched multiple accessible Cadence orgs".to_string(),
            }
        );
    }

    #[tokio::test]
    #[serial]
    async fn process_pending_uploads_refreshes_repo_metadata_before_retry() {
        let home = TempDir::new().unwrap();
        let _home = EnvGuard::set_path("HOME", home.path());
        let repo = init_repo().await;

        let queued_context = UploadContext {
            client: ApiClient::new_for_test("http://127.0.0.1:9"),
            token: Some("token".to_string()),
            user_orgs: Mutex::new(None),
        };
        let prepared = prepare_session_upload(ObservedSessionUpload {
            observations: PublicationObservations {
                canonical_remote_url: String::new(),
                remote_urls: Vec::new(),
                canonical_repo_root: repo.path().to_string_lossy().to_string(),
                worktree_roots: vec![repo.path().to_string_lossy().to_string()],
                cwd: Some(repo.path().to_string_lossy().to_string()),
                git_ref: None,
                head_commit_sha: None,
                git_user_email: None,
                git_user_name: None,
                cli_version: Some("1.0.0".to_string()),
            },
            ..sample_observed(repo.path(), "git@github.com:test-org/repo.git")
        })
        .unwrap();

        let queued = upload_or_queue_prepared_session(&queued_context, &prepared)
            .await
            .unwrap();
        assert!(matches!(queued, LiveUploadOutcome::Queued { .. }));
        assert_eq!(pending_upload_count().await.unwrap(), 1);

        run_git(
            repo.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:test-org/repo.git",
            ],
        )
        .await;

        let server =
            test_support::spawn_test_upload_server(test_support::TestUploadServerConfig::default())
                .await
                .unwrap();
        let retry_context = UploadContext {
            client: ApiClient::new_for_test(&server.base_url),
            token: Some("token".to_string()),
            user_orgs: Mutex::new(None),
        };

        let summary = process_pending_uploads(&retry_context, 1).await.unwrap();
        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.uploaded, 1);
        assert_eq!(pending_upload_count().await.unwrap(), 0);

        let requests = server.create_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].canonical_remote_url,
            "git@github.com:test-org/repo.git"
        );
        assert_eq!(
            requests[0].remote_urls,
            vec!["git@github.com:test-org/repo.git".to_string()]
        );
        assert!(
            requests[0]
                .git_ref
                .as_deref()
                .is_some_and(|git_ref| git_ref.starts_with("refs/heads/"))
        );
        assert!(requests[0].head_commit_sha.is_some());
    }

    #[tokio::test]
    #[serial]
    async fn pending_upload_count_includes_future_retryable_records() {
        let home = TempDir::new().unwrap();
        let _home = EnvGuard::set_path("HOME", home.path());
        let server = test_support::spawn_test_upload_server(test_support::TestUploadServerConfig {
            create_statuses: vec![500],
            ..Default::default()
        })
        .await
        .unwrap();
        let context = UploadContext {
            client: ApiClient::new_for_test(&server.base_url),
            token: Some("token".to_string()),
            user_orgs: Mutex::new(None),
        };
        let prepared = prepare_session_upload(sample_observed(
            Path::new("/tmp/repo"),
            "git@github.com:test-org/repo.git",
        ))
        .unwrap();

        let outcome = upload_or_queue_prepared_session(&context, &prepared)
            .await
            .unwrap();
        assert!(matches!(outcome, LiveUploadOutcome::Queued { .. }));

        let records = load_all_records().await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].record.status,
            PublicationStatus::RetryableFailure
        );
        assert!(records[0].record.next_attempt_at_epoch > now_epoch());
        assert_eq!(pending_upload_count().await.unwrap(), 1);

        remove_record(&records[0].storage_key).await.unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn process_pending_uploads_drops_records_missing_payloads() {
        let home = TempDir::new().unwrap();
        let _home = EnvGuard::set_path("HOME", home.path());
        let queued_context = UploadContext {
            client: ApiClient::new_for_test("http://127.0.0.1:9"),
            token: None,
            user_orgs: Mutex::new(None),
        };
        let prepared = prepare_session_upload(ObservedSessionUpload {
            observations: PublicationObservations {
                canonical_remote_url: String::new(),
                remote_urls: Vec::new(),
                canonical_repo_root: "/tmp/repo".to_string(),
                worktree_roots: vec!["/tmp/repo".to_string()],
                cwd: Some("/tmp/repo".to_string()),
                git_ref: None,
                head_commit_sha: None,
                git_user_email: None,
                git_user_name: None,
                cli_version: Some("1.0.0".to_string()),
            },
            ..sample_observed(Path::new("/tmp/repo"), "git@github.com:test-org/repo.git")
        })
        .unwrap();

        upload_or_queue_prepared_session(&queued_context, &prepared)
            .await
            .unwrap();

        let key = storage_key(&prepared.prepared.logical_session, None);
        let payload_path = home
            .path()
            .join(".cadence")
            .join("cli")
            .join("publication-state")
            .join(format!("{key}.blob"));
        tokio::fs::remove_file(payload_path).await.unwrap();

        let retry_context = UploadContext {
            client: ApiClient::new_for_test("http://127.0.0.1:9"),
            token: Some("token".to_string()),
            user_orgs: Mutex::new(None),
        };
        let summary = process_pending_uploads(&retry_context, 1).await.unwrap();
        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.dropped_permanent, 1);
        assert_eq!(pending_upload_count().await.unwrap(), 0);
        assert!(load_all_records().await.unwrap().is_empty());
    }

    #[tokio::test]
    #[serial]
    async fn upload_server_reads_full_request_body_for_large_uploads() {
        let home = TempDir::new().unwrap();
        let _home = EnvGuard::set_path("HOME", home.path());
        let server =
            test_support::spawn_test_upload_server(test_support::TestUploadServerConfig::default())
                .await
                .unwrap();
        let context = UploadContext {
            client: ApiClient::new_for_test(&server.base_url),
            token: Some("token".to_string()),
            user_orgs: Mutex::new(None),
        };
        let large_body = "line\n".repeat(10_000);
        let prepared = prepare_session_upload(ObservedSessionUpload {
            raw_session_content: large_body.clone(),
            ..sample_observed(Path::new("/tmp/repo"), "git@github.com:test-org/repo.git")
        })
        .unwrap();

        let outcome = upload_or_queue_prepared_session(&context, &prepared)
            .await
            .unwrap();
        assert_eq!(outcome, LiveUploadOutcome::Uploaded);

        let upload_requests = server.upload_requests();
        assert_eq!(upload_requests.len(), 1);
        assert_eq!(upload_requests[0].body, large_body);
    }
}
