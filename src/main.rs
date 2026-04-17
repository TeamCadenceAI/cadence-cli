//! Cadence CLI binary entrypoint and subcommand orchestration.

mod agents;
mod api_client;
mod bootstrap;
mod git;
mod login;
mod monitor;
mod output;
mod publication;
mod publication_state;
mod scanner;
mod state_files;
mod tracing;
mod transport;
mod upload;

#[cfg(test)]
mod test_support;

use anyhow::Result;
use cadence_cli::{config, update};
use clap::{Parser, Subcommand};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::process;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OnceCell, Semaphore};
use tokio::task::JoinSet;

const LOGIN_TIMEOUT_SECS: u64 = 120;
const API_TIMEOUT_SECS: u64 = 5;
const MONITOR_LOG_RETENTION_DAYS: i64 = 14;
static API_URL_OVERRIDE: OnceCell<String> = OnceCell::const_new();

fn error_chain_messages(err: &anyhow::Error) -> Vec<String> {
    let mut messages = Vec::new();
    for cause in err.chain() {
        let msg = cause.to_string();
        if msg.trim().is_empty() {
            continue;
        }
        if messages.last().map(|last| last == &msg).unwrap_or(false) {
            continue;
        }
        messages.push(msg);
    }
    messages
}

fn report_error(err: &anyhow::Error) {
    if err.downcast_ref::<AlreadyReportedCliError>().is_some() {
        return;
    }
    let mut messages = error_chain_messages(err).into_iter();
    match messages.next() {
        Some(first) => {
            output::fail("Failed", &first);
            for cause in messages {
                output::detail(&format!("Caused by: {cause}"));
            }
            if let Some(help) = transport::tls_failure_help(err) {
                output::note(&help);
            }
        }
        None => output::fail("Failed", "unknown error"),
    }
}

#[derive(Debug)]
struct AlreadyReportedCliError;

impl std::fmt::Display for AlreadyReportedCliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("already reported")
    }
}

impl std::error::Error for AlreadyReportedCliError {}

/// Cadence CLI: upload AI coding agent sessions directly to Cadence.
///
/// Provides provenance and measurement of AI-assisted development
/// without polluting commit history.
#[derive(Parser, Debug)]
#[command(name = "cadence", version, about)]
struct Cli {
    /// Enable verbose logging (e.g., git commands and output).
    #[arg(long, global = true)]
    verbose: bool,

    /// API base URL override for this command invocation.
    #[arg(long, global = true)]
    api_url: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Install Cadence CLI and enable background monitoring.
    Install {
        /// Optional GitHub org filter for push scoping.
        #[arg(long)]
        org: Option<String>,
        /// Internal upgrade/bootstrap path that preserves an explicit disabled runtime.
        #[arg(long, hide = true)]
        preserve_disable_state: bool,
    },

    /// Git hook entry points.
    Hook {
        #[command(subcommand)]
        hook_command: HookCommand,
    },

    /// Backfill AI sessions for recent activity.
    Backfill {
        /// How far back to scan, e.g. "30d" for 30 days.
        #[arg(long, default_value = "30d")]
        since: String,
    },

    /// Sign in via browser OAuth and store a CLI token locally.
    Login,

    /// Revoke and clear local CLI authentication token.
    Logout,

    /// Show Cadence CLI status for the current repository.
    Status,

    /// Diagnose monitor and upload configuration issues.
    Doctor {
        /// Attempt to repair monitor scheduler artifacts based on configured runtime intent.
        #[arg(long)]
        repair: bool,
    },

    /// Manage Cadence background monitoring.
    Monitor {
        #[command(subcommand)]
        command: Option<MonitorCommand>,
    },

    /// Check for and install updates.
    Update {
        /// Only check if a newer version is available; do not download or install.
        #[arg(long)]
        check: bool,

        /// Skip confirmation prompt when installing an update.
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Manage unattended auto-update policy.
    AutoUpdate {
        #[command(subcommand)]
        command: Option<AutoUpdateCommand>,
    },

    /// View or modify CLI configuration.
    Config {
        #[command(subcommand)]
        config_command: Option<ConfigCommand>,
    },

    /// Remove Cadence CLI hooks, configuration, scheduler, and state.
    #[command(alias = "reset")]
    Uninstall {
        /// Skip the confirmation prompt.
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
    /// Set a configuration value.
    Set {
        /// Configuration key (e.g. update_check_interval, api_url).
        key: String,
        /// Value to set.
        value: String,
    },
    /// Get a configuration value.
    Get {
        /// Configuration key to read.
        key: String,
    },
    /// List all configuration keys and their current values.
    List,
}

#[derive(Subcommand, Debug)]
enum AutoUpdateCommand {
    /// Show auto-update status and runtime health.
    Status,
    /// Hidden compatibility command; background updates now follow monitor state.
    #[command(hide = true)]
    Enable,
    /// Hidden compatibility command; background updates now follow monitor state.
    #[command(hide = true)]
    Disable,
    /// Hidden compatibility command; scheduler lifecycle is monitor-owned.
    #[command(hide = true)]
    Uninstall,
}

#[derive(Subcommand, Debug)]
enum MonitorCommand {
    /// Show monitor status and scheduler health.
    Status,
    /// Enable background monitoring and reconcile scheduler artifacts.
    Enable,
    /// Disable background monitoring (scheduled ticks become no-op).
    Disable,
    /// Remove background monitor scheduler artifacts.
    Uninstall,
    /// Internal background monitor entrypoint (scheduler-only).
    #[command(hide = true)]
    Tick,
}

#[derive(Subcommand, Debug)]
enum HookCommand {
    /// Post-commit hook compatibility shim.
    PostCommit,
    /// Internal compatibility entrypoint routed to the monitor tick.
    #[command(hide = true)]
    AutoUpdate,
    /// Internal hook-refresh compatibility entrypoint.
    #[command(hide = true)]
    RefreshHooks,
}

fn api_url_override() -> Option<&'static str> {
    API_URL_OVERRIDE.get().map(String::as_str)
}

// ---------------------------------------------------------------------------
// Subcommand dispatch
// ---------------------------------------------------------------------------

/// The install subcommand: enable background monitoring.
async fn run_install(org: Option<String>, preserve_disable_state: bool) -> Result<()> {
    bootstrap::run_install(org, preserve_disable_state).await
}

async fn run_refresh_hooks() -> Result<()> {
    output::detail("Git hook refresh is no longer required.");
    output::detail(
        "Run `cadence install` to reconcile background monitoring and clean up legacy Cadence hook ownership.",
    );
    Ok(())
}

async fn run_login() -> Result<()> {
    let mut cfg = config::CliConfig::load().await?;
    let resolved = cfg.resolve_api_url(api_url_override());
    output::detail(&format!("Using API URL: {}", resolved.url));
    if resolved.is_non_https {
        output::note(&format!(
            "Using non-HTTPS API URL for login: {}",
            resolved.url
        ));
    }

    output::action("Login", "opening browser for authentication");
    let exchanged =
        login::login_via_browser(&resolved.url, Duration::from_secs(LOGIN_TIMEOUT_SECS)).await?;

    cfg.api_url = Some(resolved.url.clone());
    cfg.token = Some(exchanged.token.clone());
    cfg.github_login = Some(exchanged.login.clone());
    cfg.expires_at = Some(exchanged.expires_at.clone());
    cfg.save().await?;

    output::success("Login", &format!("authenticated as {}", exchanged.login));
    output::detail(&format!("Token expires at {}", exchanged.expires_at));
    Ok(())
}

async fn run_logout() -> Result<()> {
    let mut cfg = config::CliConfig::load().await?;
    let resolved = cfg.resolve_api_url(api_url_override());

    if let Some(token) = resolve_cli_auth_token(&cfg) {
        let client = api_client::ApiClient::new(&resolved.url).await?;
        match client
            .revoke_token(&token, Duration::from_secs(API_TIMEOUT_SECS))
            .await
        {
            Ok(()) => output::detail("Revoked token on server."),
            Err(api_client::AuthenticatedRequestError::Unauthorized) => {
                output::note("Token was already invalid or expired.");
            }
            Err(err) => {
                output::note(&format!("Could not revoke token on server ({err})"));
            }
        }
    } else {
        output::note("No local token found; clearing local auth state.");
    }

    cfg.clear_token().await?;
    output::success("Logout", "authentication cleared");
    Ok(())
}

#[derive(Debug, Clone)]
struct BackfillSyncStats {
    notes_attached: i64,
    notes_skipped: i64,
    issues: Vec<String>,
    repos_scanned: i32,
}

fn resolve_cli_auth_token(cfg: &config::CliConfig) -> Option<String> {
    cfg.auth_token()
}

async fn report_backfill_completion(window_days: i32, stats: BackfillSyncStats) {
    let cfg = match config::CliConfig::load().await {
        Ok(cfg) => cfg,
        Err(_) => return,
    };

    let token = match resolve_cli_auth_token(&cfg) {
        Some(token) => token,
        None => {
            output::note("Run `cadence login` to sync results");
            return;
        }
    };

    let resolved = cfg.resolve_api_url(api_url_override());
    let client = match api_client::ApiClient::new(&resolved.url).await {
        Ok(client) => client,
        Err(err) => {
            output::detail(&format!("Backfill sync skipped: {err}"));
            if let Some(help) = transport::tls_failure_help(&err) {
                output::note(&help);
            }
            return;
        }
    };
    let finished_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    let request = api_client::BackfillCompleteRequest {
        window_days,
        notes_attached: stats.notes_attached,
        notes_skipped: stats.notes_skipped,
        issues: stats.issues,
        repos_scanned: stats.repos_scanned,
        finished_at,
        cli_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    match client
        .report_backfill_complete(&token, &request, Duration::from_secs(API_TIMEOUT_SECS))
        .await
    {
        Ok(response) => {
            if response.recorded {
                output::detail(&format!(
                    "Backfill results synced to Cadence onboarding at {}.",
                    response.backfill_completed_at
                ));
            } else {
                output::detail("Backfill sync already recorded.");
            }
        }
        Err(api_client::AuthenticatedRequestError::Unauthorized) => {
            output::note("Run `cadence login` to re-authenticate");
        }
        Err(api_client::AuthenticatedRequestError::Network(_)) => {
            output::note("Notes are safely stored locally");
        }
        Err(api_client::AuthenticatedRequestError::NotFound) => {
            output::note("API does not support this yet");
        }
        Err(api_client::AuthenticatedRequestError::Server(_)) => {
            output::note("API returned an error");
        }
        Err(other) => {
            output::detail(&format!("Backfill sync skipped: {other}"));
        }
    }
}

/// Legacy post-commit compatibility hook.
///
/// Old installs may still invoke `cadence hook post-commit` briefly before the
/// new runtime bootstrap removes Cadence-owned hook artifacts. This must remain
/// a silent success no-op during that migration window.
async fn run_hook_post_commit() -> Result<()> {
    Ok(())
}

const MONITOR_DEFAULT_CURSOR_WINDOW_SECS: i64 = 30 * 86_400;
const MONITOR_DISCOVERY_LOOKBACK_SECS: i64 = 300;

async fn git_ref_for_repo(repo: &std::path::Path) -> Option<String> {
    let branch = git::current_branch_at(repo).await.ok().flatten()?;
    Some(format!("refs/heads/{branch}"))
}

async fn head_sha_for_repo(repo: &std::path::Path) -> Option<String> {
    git::head_sha_at(repo).await.ok().flatten()
}

fn monitor_discovery_concurrency() -> usize {
    std::env::var("CADENCE_HOOK_DISCOVERY_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get().clamp(2, 8))
                .unwrap_or(4)
        })
}

struct ParsedSessionLog {
    log: agents::SessionLog,
    metadata: scanner::SessionMetadata,
    session_log: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IncrementalCursor {
    last_scanned_mtime_epoch: i64,
    last_scanned_source_label: Option<String>,
}

impl IncrementalCursor {
    fn from_position(
        last_scanned_mtime_epoch: i64,
        last_scanned_source_label: Option<String>,
    ) -> Self {
        Self {
            last_scanned_mtime_epoch,
            last_scanned_source_label,
        }
    }
}

fn selection_cursor_with_lookback(cursor: &IncrementalCursor) -> IncrementalCursor {
    IncrementalCursor {
        last_scanned_mtime_epoch: cursor
            .last_scanned_mtime_epoch
            .saturating_sub(MONITOR_DISCOVERY_LOOKBACK_SECS),
        last_scanned_source_label: None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MonitorSessionDedupeKey {
    agent: String,
    session_identity: String,
    repo_root: String,
}

fn monitor_session_dedupe_key(
    parsed: &ParsedSessionLog,
    resolved_repo: &std::path::Path,
) -> MonitorSessionDedupeKey {
    let agent = parsed
        .metadata
        .agent_type
        .clone()
        .unwrap_or_else(|| parsed.log.agent_type.clone())
        .to_string();
    let session_identity = parsed
        .metadata
        .session_id
        .clone()
        .unwrap_or_else(|| parsed.log.source_label());
    MonitorSessionDedupeKey {
        agent,
        session_identity,
        repo_root: resolved_repo.to_string_lossy().to_string(),
    }
}

fn source_label_is_scanned(cursor: &IncrementalCursor, mtime: i64, source_label: &str) -> bool {
    if mtime < cursor.last_scanned_mtime_epoch {
        return true;
    }
    if mtime > cursor.last_scanned_mtime_epoch {
        return false;
    }
    match cursor.last_scanned_source_label.as_deref() {
        Some(scanned_label) => source_label <= scanned_label,
        None => true,
    }
}

fn advance_cursor_for_disposition(
    current_cursor: &IncrementalCursor,
    mtime: Option<i64>,
    source_label: &str,
) -> IncrementalCursor {
    let Some(mtime) = mtime else {
        return current_cursor.clone();
    };
    if mtime > current_cursor.last_scanned_mtime_epoch {
        return IncrementalCursor {
            last_scanned_mtime_epoch: mtime,
            last_scanned_source_label: Some(source_label.to_string()),
        };
    }
    if mtime == current_cursor.last_scanned_mtime_epoch {
        let next_label = match current_cursor.last_scanned_source_label.as_deref() {
            Some(existing) if existing >= source_label => existing.to_string(),
            _ => source_label.to_string(),
        };
        return IncrementalCursor {
            last_scanned_mtime_epoch: mtime,
            last_scanned_source_label: Some(next_label),
        };
    }
    current_cursor.clone()
}

fn apply_monitor_incremental_upload_outcome(
    stats: &mut MonitorTickSummary,
    cursor_advance: &mut IncrementalCursor,
    log_mtime: Option<i64>,
    log_source_label: &str,
    outcome: UploadFromLogOutcome,
) {
    let advance = |cursor_advance: &mut IncrementalCursor| {
        *cursor_advance =
            advance_cursor_for_disposition(cursor_advance, log_mtime, log_source_label);
    };
    match outcome {
        UploadFromLogOutcome::Uploaded => {
            stats.uploaded += 1;
            advance(cursor_advance);
        }
        UploadFromLogOutcome::AlreadyExists => {
            stats.skipped += 1;
            advance(cursor_advance);
        }
        UploadFromLogOutcome::Queued(_) => {
            stats.queued += 1;
            advance(cursor_advance);
        }
        UploadFromLogOutcome::Retryable(_) => {
            stats.issues += 1;
            advance(cursor_advance);
        }
    }
}

fn apply_monitor_org_filter_error(
    stats: &mut MonitorTickSummary,
    cursor_advance: &mut IncrementalCursor,
    log_mtime: Option<i64>,
    log_source_label: &str,
) {
    stats.issues += 1;
    *cursor_advance = advance_cursor_for_disposition(cursor_advance, log_mtime, log_source_label);
}

fn select_incremental_candidates(
    logs: Vec<agents::SessionLog>,
    cursor: &IncrementalCursor,
    max_items: usize,
) -> Vec<agents::SessionLog> {
    let mut candidates: Vec<_> = logs
        .into_iter()
        .filter(|log| {
            let Some(mtime) = log.updated_at else {
                return false;
            };
            !source_label_is_scanned(cursor, mtime, &log.source_label())
        })
        .collect();
    candidates.sort_by(|a, b| {
        a.updated_at
            .unwrap_or_default()
            .cmp(&b.updated_at.unwrap_or_default())
            .then_with(|| a.source_label().cmp(&b.source_label()))
    });
    candidates.truncate(max_items);
    candidates
}

async fn parse_session_log_once(log: agents::SessionLog) -> Option<ParsedSessionLog> {
    let session_log = match &log.source {
        agents::SessionSource::File(path) => tokio::fs::read_to_string(path).await.ok()?,
        agents::SessionSource::Inline { content, .. } => content.clone(),
    };
    let mut metadata = match &log.source {
        agents::SessionSource::File(path) => {
            scanner::parse_session_metadata_with_content(path, &session_log).await
        }
        agents::SessionSource::Inline { .. } => scanner::parse_session_metadata_str(&session_log),
    };
    metadata.agent_type = Some(log.agent_type.clone());
    Some(ParsedSessionLog {
        log,
        metadata,
        session_log,
    })
}

async fn parse_session_logs_bounded(logs: Vec<agents::SessionLog>) -> Vec<ParsedSessionLog> {
    if logs.is_empty() {
        return Vec::new();
    }
    let semaphore = Arc::new(Semaphore::new(monitor_discovery_concurrency()));
    let mut set = JoinSet::new();
    for (idx, log) in logs.into_iter().enumerate() {
        let semaphore = Arc::clone(&semaphore);
        set.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok()?;
            parse_session_log_once(log)
                .await
                .map(|parsed| (idx, parsed))
        });
    }

    let mut out = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Some(parsed)) = res {
            out.push(parsed);
        }
    }
    out.sort_by_key(|(idx, _)| *idx);
    out.into_iter().map(|(_, parsed)| parsed).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UploadFromLogOutcome {
    Uploaded,
    AlreadyExists,
    Queued(String),
    Retryable(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationMode {
    Live,
    Backfill,
}

async fn upload_session_from_log(
    context: &upload::UploadContext,
    parsed: &ParsedSessionLog,
    repo_root: &std::path::Path,
    repo_root_str: &str,
    mode: PublicationMode,
) -> UploadFromLogOutcome {
    let session_id = parsed
        .metadata
        .session_id
        .as_deref()
        .unwrap_or("unknown")
        .to_string();
    let agent = parsed
        .metadata
        .agent_type
        .clone()
        .unwrap_or(scanner::AgentType::Claude);
    let git_user_email = git::config_get_at(repo_root, "user.email")
        .await
        .ok()
        .flatten();
    let git_user_name = git::config_get_at(repo_root, "user.name")
        .await
        .ok()
        .flatten();
    let worktree_roots = git::repo_and_worktree_roots_at(repo_root).await;
    let (git_ref, head_commit_sha) = match mode {
        PublicationMode::Live => (
            git_ref_for_repo(repo_root).await,
            head_sha_for_repo(repo_root).await,
        ),
        PublicationMode::Backfill => (None, None),
    };
    let build_observed_upload =
        |canonical_remote_url: String, remote_urls: Vec<String>| upload::ObservedSessionUpload {
            logical_session: publication::LogicalSessionKey {
                agent: agent.to_string(),
                agent_session_id: session_id.clone(),
            },
            observations: publication::PublicationObservations {
                canonical_remote_url,
                remote_urls,
                canonical_repo_root: repo_root_str.to_string(),
                worktree_roots: worktree_roots.clone(),
                cwd: parsed
                    .metadata
                    .cwd
                    .clone()
                    .or_else(|| Some(repo_root_str.to_string())),
                git_ref: git_ref.clone(),
                head_commit_sha: head_commit_sha.clone(),
                git_user_email: git_user_email.clone(),
                git_user_name: git_user_name.clone(),
                cli_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            },
            raw_session_content: parsed.session_log.clone(),
        };

    let remote_urls = match git::remote_urls_at(repo_root).await {
        Ok(urls) => urls,
        Err(err) => {
            let prepared = match upload::prepare_session_upload(build_observed_upload(
                String::new(),
                Vec::new(),
            )) {
                Ok(prepared) => prepared,
                Err(prepare_err) => {
                    return UploadFromLogOutcome::Retryable(prepare_err.to_string());
                }
            };
            let reason = err.to_string();
            if let Err(persist_err) =
                upload::persist_retryable_prepared_session(&prepared, &reason).await
            {
                return UploadFromLogOutcome::Retryable(format!(
                    "{reason}; failed to persist retryable state: {persist_err}"
                ));
            }
            return UploadFromLogOutcome::Retryable(reason);
        }
    };
    let canonical_remote_url = git::preferred_remote_url_at(repo_root)
        .await
        .ok()
        .flatten()
        .or_else(|| remote_urls.first().cloned());

    let Some(canonical_remote_url) = canonical_remote_url else {
        let prepared =
            match upload::prepare_session_upload(build_observed_upload(String::new(), remote_urls))
            {
                Ok(prepared) => prepared,
                Err(err) => return UploadFromLogOutcome::Retryable(err.to_string()),
            };
        return match upload::upload_or_queue_prepared_session(context, &prepared).await {
            Ok(upload::LiveUploadOutcome::Queued { reason }) => {
                UploadFromLogOutcome::Queued(reason)
            }
            Ok(upload::LiveUploadOutcome::AlreadyExists) => {
                UploadFromLogOutcome::Queued("repo has no push remote URL".to_string())
            }
            Ok(upload::LiveUploadOutcome::Uploaded) => UploadFromLogOutcome::Uploaded,
            Err(err) => UploadFromLogOutcome::Retryable(err.to_string()),
        };
    };

    let prepared = match upload::prepare_session_upload(build_observed_upload(
        canonical_remote_url,
        remote_urls,
    )) {
        Ok(prepared) => prepared,
        Err(err) => return UploadFromLogOutcome::Retryable(err.to_string()),
    };

    match upload::upload_or_queue_prepared_session(context, &prepared).await {
        Ok(upload::LiveUploadOutcome::Uploaded) => UploadFromLogOutcome::Uploaded,
        Ok(upload::LiveUploadOutcome::AlreadyExists) => UploadFromLogOutcome::AlreadyExists,
        Ok(upload::LiveUploadOutcome::Queued { reason }) => UploadFromLogOutcome::Queued(reason),
        Err(err) => UploadFromLogOutcome::Retryable(err.to_string()),
    }
}

async fn session_log_metadata(log: &agents::SessionLog) -> scanner::SessionMetadata {
    let mut metadata = match &log.source {
        agents::SessionSource::File(path) => scanner::parse_session_metadata(path).await,
        agents::SessionSource::Inline { content, .. } => {
            scanner::parse_session_metadata_str(content)
        }
    };
    metadata.agent_type = Some(log.agent_type.clone());
    metadata
}

fn discovery_skip_reason_for_missing_metadata(log: &agents::SessionLog) -> &'static str {
    match log.agent_type {
        scanner::AgentType::Cursor => {
            let label = log.source_label();
            if label.contains("agent-tools")
                || label.contains("terminals")
                || label.contains("mcps")
            {
                "cursor_non_session_artifact"
            } else {
                "cursor_unsupported_storage_shape"
            }
        }
        scanner::AgentType::Warp => "warp_missing_session_id",
        _ => "missing_session_metadata",
    }
}

fn discovery_skip_reason_for_missing_cwd(log: &agents::SessionLog) -> &'static str {
    match log.agent_type {
        scanner::AgentType::Cursor => "cursor_workspace_unresolved",
        scanner::AgentType::Warp => "warp_cwd_unrecoverable_after_fallbacks",
        _ => "missing_cwd",
    }
}

async fn session_log_content_async(log: &agents::SessionLog) -> Option<String> {
    match &log.source {
        agents::SessionSource::File(path) => tokio::fs::read_to_string(path).await.ok(),
        agents::SessionSource::Inline { content, .. } => Some(content.clone()),
    }
}

/// Maximum number of candidate directories to try when resolving a repo
/// from transcript content. Prevents excessive `git rev-parse` calls when
/// a transcript references many unique directories.
const TRANSCRIPT_CWD_MAX_CANDIDATES: usize = 20;

/// Attempt to resolve a session's repo root by scanning transcript content
/// for file paths when the recorded `cwd` doesn't resolve to a git repo.
///
/// This is a fallback for sessions (typically Claude desktop app) where the
/// manifest's `cwd` points to a parent directory rather than a specific repo.
/// Reads the transcript, extracts absolute file paths from tool-call inputs,
/// and tries to resolve each to a git repo root.
///
/// Caps the number of candidates tried at [`TRANSCRIPT_CWD_MAX_CANDIDATES`]
/// to bound the cost of git subprocess calls.
async fn resolve_repo_from_transcript(
    log: &agents::SessionLog,
    repo_root_cache: &std::collections::HashMap<String, git::RepoRootResolution>,
) -> Option<git::RepoRootResolution> {
    let content = session_log_content_async(log).await?;
    let candidate_cwds = scanner::extract_candidate_cwds_from_transcript(&content);

    for candidate_cwd in candidate_cwds.iter().take(TRANSCRIPT_CWD_MAX_CANDIDATES) {
        // Check cache first.
        if let Some(cached) = repo_root_cache.get(candidate_cwd.as_str()) {
            return Some(cached.clone());
        }

        let cwd_path = std::path::Path::new(&candidate_cwd);
        if let Ok(resolution) = git::resolve_repo_root_with_fallbacks(cwd_path).await {
            return Some(resolution);
        }
    }

    None
}

/// Parse a duration string like "7d", "30d", "1d" into seconds.
///
/// Currently only supports the `<N>d` format (number of days).
/// Returns an error for unrecognized formats.
fn parse_since_duration(since: &str) -> Result<i64> {
    let since = since.trim();
    if let Some(days_str) = since.strip_suffix('d') {
        let days: i64 = days_str
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid --since value: {:?}", since))?;
        if days <= 0 {
            anyhow::bail!("--since value must be positive: {:?}", since);
        }
        Ok(days * 86_400)
    } else {
        anyhow::bail!(
            "unsupported --since format {:?}: expected e.g. \"7d\", \"30d\"",
            since
        );
    }
}

/// The backfill subcommand: upload recent AI session logs to Cadence.
///
/// This scans ALL supported agent log directories (not scoped to any
/// single repo), resolves repos from session metadata, and stores
/// session records where missing.
///
/// Properties:
/// - Can take minutes for large log directories
/// - Prints verbose progress throughout
/// - All errors are non-fatal (logged and continued)
/// - Uploads session blobs directly to the Cadence API
async fn run_backfill(since: &str) -> Result<()> {
    run_backfill_inner(since, None).await
}

/// Inner implementation of backfill that accepts an optional repo filter.
///
/// When `repo_filter` is `Some`, only sessions whose resolved repo root
/// matches the given path are processed. Used by `cadence gc` to scope
/// re-backfill to the current repository.
#[derive(Clone)]
struct SessionInfo {
    log: agents::SessionLog,
    session_id: String,
    repo_root: std::path::PathBuf,
    metadata: scanner::SessionMetadata,
}

#[derive(Default)]
struct RepoBackfillStats {
    sessions_seen: usize,
    uploaded: usize,
    queued: usize,
    skipped: usize,
    errors: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackfillInvocation {
    Manual,
    RecoveryBootstrap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackfillOutcome {
    Completed,
    SkippedAuth,
}

fn repo_label_from_display(display: &str) -> String {
    let trimmed = display.trim();
    if trimmed.is_empty() {
        return "unknown".to_string();
    }

    // HTTPS / HTTP remotes: https://github.com/org/repo(.git)
    if let Ok(url) = reqwest::Url::parse(trimmed) {
        let mut segments = url
            .path_segments()
            .map(|s| s.filter(|p| !p.is_empty()).collect::<Vec<_>>())
            .unwrap_or_default();
        if segments.len() >= 2 {
            let org = segments.remove(segments.len() - 2);
            let mut repo = segments.remove(segments.len() - 1).to_string();
            if let Some(stripped) = repo.strip_suffix(".git") {
                repo = stripped.to_string();
            }
            return format!("{org}/{repo}");
        }
    }

    // SSH remote: git@github.com:org/repo.git
    if let Some((_, path)) = trimmed.split_once(':') {
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        if parts.len() >= 2 {
            let org = parts[parts.len() - 2];
            let mut repo = parts[parts.len() - 1].to_string();
            if let Some(stripped) = repo.strip_suffix(".git") {
                repo = stripped.to_string();
            }
            return format!("{org}/{repo}");
        }
    }

    trimmed.to_string()
}

fn backfill_repo_concurrency() -> usize {
    let adaptive = std::thread::available_parallelism()
        .map(|n| n.get().saturating_mul(2))
        .unwrap_or(4)
        .clamp(1, 32);
    std::env::var("CADENCE_BACKFILL_REPO_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(adaptive)
}

fn backfill_auth_message(
    state: &upload::PublicationAuthState,
    invocation: BackfillInvocation,
) -> Option<String> {
    match invocation {
        BackfillInvocation::Manual => match state {
            upload::PublicationAuthState::Ready => None,
            upload::PublicationAuthState::MissingToken => Some(
                "Cadence login is missing; run `cadence login` before running `cadence backfill`."
                    .to_string(),
            ),
            upload::PublicationAuthState::Rejected => Some(
                "Cadence login was rejected by the server; run `cadence login` before running `cadence backfill`."
                    .to_string(),
            ),
            upload::PublicationAuthState::CheckFailed(message) => Some(format!(
                "Cadence publication auth check failed ({message}); backfill did not start."
            )),
        },
        BackfillInvocation::RecoveryBootstrap => match state {
            upload::PublicationAuthState::Ready => None,
            upload::PublicationAuthState::MissingToken => Some(
                "Automatic recovery backfill skipped because Cadence login is missing."
                    .to_string(),
            ),
            upload::PublicationAuthState::Rejected => Some(
                "Automatic recovery backfill skipped because Cadence login was rejected by the server."
                    .to_string(),
            ),
            upload::PublicationAuthState::CheckFailed(message) => Some(format!(
                "Automatic recovery backfill skipped because the publication auth check failed ({message})."
            )),
        },
    }
}

fn render_boxed_message(lines: &[String]) -> String {
    let width = lines.iter().map(|line| line.len()).max().unwrap_or(0);
    let border = "*".repeat(width + 4);
    let mut rendered = String::new();
    rendered.push_str(&border);
    rendered.push('\n');
    for line in lines {
        rendered.push_str(&format!("* {:width$} *\n", line, width = width));
    }
    rendered.push_str(&border);
    rendered
}

fn backfill_auth_required_box(state: &upload::PublicationAuthState) -> Option<String> {
    let auth_line = match state {
        upload::PublicationAuthState::MissingToken => "Cadence login is missing.",
        upload::PublicationAuthState::Rejected => "Cadence login was rejected by the server.",
        _ => return None,
    };

    Some(render_boxed_message(&[
        "MANUAL ACTION REQUIRED".to_string(),
        String::new(),
        auth_line.to_string(),
        String::new(),
        "Cadence cannot publish sessions or finish recovery until".to_string(),
        "you log in again.".to_string(),
        String::new(),
        "Run now:".to_string(),
        "  cadence login".to_string(),
        String::new(),
        "After logging in, recover recent sessions with:".to_string(),
        "  cadence backfill --since 30d".to_string(),
    ]))
}

async fn process_repo_backfill(
    repo_display: String,
    sessions: Vec<SessionInfo>,
    upload_context: Arc<upload::UploadContext>,
    repo_progress: Option<ProgressBar>,
) -> RepoBackfillStats {
    let mut stats = RepoBackfillStats::default();
    let planned_units: u64 = (sessions.len() as u64).max(1);
    if let Some(pb) = &repo_progress {
        pb.set_length(planned_units);
        pb.set_message("starting");
    }

    let repo_root = match sessions.first() {
        Some(session) => session.repo_root.clone(),
        None => {
            ::tracing::info!(
                event = "repo_skipped",
                repo_display = repo_display.as_str(),
                reason = "no_sessions"
            );
            if let Some(pb) = &repo_progress {
                pb.finish_with_message("no sessions");
            }
            return stats;
        }
    };
    let repo_root_str = repo_root.to_string_lossy().to_string();
    let unique_repo_roots = sessions
        .iter()
        .map(|session| session.repo_root.to_string_lossy().to_string())
        .collect::<std::collections::BTreeSet<_>>();

    ::tracing::info!(
        event = "repo_started",
        repo_display = repo_display.as_str(),
        repo_root = repo_root_str.as_str(),
        alternative_repo_roots = ?unique_repo_roots
            .iter()
            .filter(|root| root.as_str() != repo_root_str.as_str())
            .cloned()
            .collect::<Vec<_>>(),
        sessions = sessions.len(),
        planned_units,
        upload_mode = "direct"
    );

    match git::repo_matches_org_filter(&repo_root).await {
        Ok(true) => {}
        Ok(false) => {
            ::tracing::info!(
                event = "repo_skipped",
                repo_display = repo_display.as_str(),
                repo_root = repo_root_str.as_str(),
                reason = "org_filter"
            );
            if let Some(pb) = &repo_progress {
                pb.finish_with_message("skipped (org filter)");
            }
            return stats;
        }
        Err(e) => {
            output::detail(&format!("{}: org filter check failed: {}", repo_display, e));
            stats.errors += 1;
            ::tracing::warn!(
                event = "repo_error",
                repo_display = repo_display.as_str(),
                repo_root = repo_root_str.as_str(),
                stage = "org_filter_check",
                error = e.to_string()
            );
            if let Some(pb) = &repo_progress {
                pb.finish_with_message("error (org filter)");
            }
            return stats;
        }
    }

    let repo_enabled = git::check_enabled_at(&repo_root).await;
    if !repo_enabled {
        ::tracing::info!(
            event = "repo_skipped",
            repo_display = repo_display.as_str(),
            repo_root = repo_root_str.as_str(),
            reason = "disabled"
        );
        if let Some(pb) = &repo_progress {
            pb.finish_with_message("skipped (disabled)");
        }
        return stats;
    }

    for session in sessions {
        stats.sessions_seen += 1;
        let session_file = session.log.source_label();
        let agent_type = session
            .metadata
            .agent_type
            .clone()
            .unwrap_or(scanner::AgentType::Claude);
        ::tracing::info!(
            event = "repo_session_started",
            repo_display = repo_display.as_str(),
            repo_root = repo_root_str.as_str(),
            session_id = session.session_id.as_str(),
            file = session_file.as_str(),
            agent = agent_type.to_string()
        );

        let session_log = match session_log_content_async(&session.log).await {
            Some(content) => content,
            None => {
                stats.errors += 1;
                ::tracing::warn!(
                    event = "session_error",
                    repo_display = repo_display.as_str(),
                    repo_root = repo_root_str.as_str(),
                    session_id = session.session_id.as_str(),
                    file = session.log.source_label(),
                    stage = "read_session_log",
                    error = "failed to read session log"
                );
                if let Some(pb) = &repo_progress {
                    pb.inc(1);
                }
                continue;
            }
        };
        let repo_str = session.repo_root.to_string_lossy().to_string();
        let parsed = ParsedSessionLog {
            log: session.log.clone(),
            metadata: session.metadata.clone(),
            session_log,
        };

        match upload_session_from_log(
            &upload_context,
            &parsed,
            &session.repo_root,
            &repo_str,
            PublicationMode::Backfill,
        )
        .await
        {
            UploadFromLogOutcome::Uploaded => {
                stats.uploaded += 1;
                ::tracing::info!(
                    event = "session_uploaded",
                    repo_display = repo_display.as_str(),
                    repo_root = repo_root_str.as_str(),
                    session_id = session.session_id.as_str(),
                    file = session.log.source_label()
                );
            }
            UploadFromLogOutcome::Queued(reason) => {
                stats.queued += 1;
                ::tracing::info!(
                    event = "session_queued",
                    repo_display = repo_display.as_str(),
                    repo_root = repo_root_str.as_str(),
                    session_id = session.session_id.as_str(),
                    file = session.log.source_label(),
                    reason
                );
            }
            UploadFromLogOutcome::AlreadyExists => {
                stats.skipped += 1;
                ::tracing::info!(
                    event = "session_skipped_already_exists",
                    repo_display = repo_display.as_str(),
                    repo_root = repo_root_str.as_str(),
                    session_id = session.session_id.as_str(),
                    file = session.log.source_label()
                );
            }
            UploadFromLogOutcome::Retryable(error) => {
                stats.errors += 1;
                ::tracing::warn!(
                    event = "session_upload_error",
                    repo_display = repo_display.as_str(),
                    repo_root = repo_root_str.as_str(),
                    session_id = session.session_id.as_str(),
                    file = session.log.source_label(),
                    error
                );
            }
        }
        if let Some(pb) = &repo_progress {
            pb.inc(1);
            pb.set_message(format!(
                "sessions={}, uploaded={}, queued={}, issues={}",
                stats.sessions_seen, stats.uploaded, stats.queued, stats.errors
            ));
        }
    }

    if let Some(pb) = &repo_progress {
        pb.finish_with_message(format!(
            "done: sessions={}, uploaded={}, queued={}, skipped={}, issues={}",
            stats.sessions_seen, stats.uploaded, stats.queued, stats.skipped, stats.errors
        ));
    }

    ::tracing::info!(
        event = "repo_completed",
        repo_display = repo_display.as_str(),
        repo_root = repo_root_str.as_str(),
        sessions_seen = stats.sessions_seen,
        uploaded = stats.uploaded,
        queued = stats.queued,
        skipped = stats.skipped,
        errors = stats.errors
    );

    stats
}

async fn run_backfill_inner(since: &str, repo_filter: Option<&std::path::Path>) -> Result<()> {
    match run_backfill_inner_with_invocation(since, repo_filter, BackfillInvocation::Manual).await?
    {
        BackfillOutcome::Completed | BackfillOutcome::SkippedAuth => Ok(()),
    }
}

async fn run_backfill_inner_with_invocation(
    since: &str,
    repo_filter: Option<&std::path::Path>,
    invocation: BackfillInvocation,
) -> Result<BackfillOutcome> {
    let since_secs = parse_since_duration(since)?;
    let since_days = since_secs / 86_400;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let _diagnostics_session = match tracing::DiagnosticsLogger::new("backfill").await {
        Ok(logger) => {
            if let Some(path) = logger.path() {
                output::detail(&format!("Backfill trace: {}", path.display()));
            }
            Some(tracing::install_global(logger))
        }
        Err(e) => {
            output::detail(&format!("Backfill trace unavailable: {e}"));
            None
        }
    };

    let upload_context = Arc::new(upload::resolve_upload_context(api_url_override()).await?);
    let publication_auth = upload::publication_auth_state(&upload_context).await;
    if publication_auth.blocks_background_publication()
        && let Some(message) = backfill_auth_message(&publication_auth, invocation)
    {
        ::tracing::warn!(
            event = "backfill_skipped_auth",
            invocation = ?invocation,
            state = publication_auth.detail(),
            message
        );
        if let Some(boxed) = backfill_auth_required_box(&publication_auth) {
            eprintln!("{boxed}");
            return match invocation {
                BackfillInvocation::Manual => Err(anyhow::Error::new(AlreadyReportedCliError)),
                BackfillInvocation::RecoveryBootstrap => Ok(BackfillOutcome::SkippedAuth),
            };
        }
        match invocation {
            BackfillInvocation::Manual => {
                output::fail("Backfill", &message);
                if let Some(remediation) = publication_auth.remediation() {
                    output::detail(remediation);
                }
                anyhow::bail!(message);
            }
            BackfillInvocation::RecoveryBootstrap => {
                output::detail(&message);
                if let Some(remediation) = publication_auth.remediation() {
                    output::detail(remediation);
                }
                return Ok(BackfillOutcome::SkippedAuth);
            }
        }
    }

    let pending_to_drain = match repo_filter {
        Some(filter) => upload::pending_upload_count_for_repo(filter)
            .await
            .unwrap_or(0),
        None => upload::pending_upload_count().await.unwrap_or(0),
    };
    ::tracing::info!(
        event = "pending_upload_drain_started",
        pending_records = pending_to_drain
    );
    let pending_summary = match repo_filter {
        Some(filter) => {
            match upload::process_pending_uploads_for_repo(
                &upload_context,
                pending_to_drain,
                filter,
            )
            .await
            {
                Ok(summary) => summary,
                Err(err) => {
                    ::tracing::warn!(
                        event = "pending_upload_drain_error",
                        error = err.to_string()
                    );
                    upload::PendingUploadSummary::default()
                }
            }
        }
        None => match upload::process_pending_uploads(&upload_context, pending_to_drain).await {
            Ok(summary) => summary,
            Err(err) => {
                ::tracing::warn!(
                    event = "pending_upload_drain_error",
                    error = err.to_string()
                );
                upload::PendingUploadSummary::default()
            }
        },
    };
    ::tracing::info!(
        event = "pending_upload_drain_completed",
        attempted = pending_summary.attempted,
        uploaded = pending_summary.uploaded,
        already_existed = pending_summary.already_existed,
        skipped_repo_not_associated = pending_summary.skipped_repo_not_associated,
        dropped_permanent = pending_summary.dropped_permanent,
        auth_required = pending_summary.auth_required
    );

    let use_progress = output::is_stderr_tty();
    let spinner = if use_progress {
        let pb = ProgressBar::new_spinner();
        pb.set_draw_target(ProgressDrawTarget::stderr());
        pb.set_style(
            ProgressStyle::with_template("{spinner} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(120));
        pb.set_message(format!("Scanning agent logs (last {} days)", since_days));
        Some(pb)
    } else {
        None
    };

    ::tracing::info!(
        event = "backfill_started",
        cli_version = env!("CARGO_PKG_VERSION"),
        since,
        since_secs,
        since_days,
        upload_mode = "direct",
        repo_filter = ?repo_filter.map(|p| p.to_string_lossy().to_string()),
        use_progress,
        pending_drain_attempted = pending_summary.attempted
    );

    // Step 2: Find all session files modified within the --since window
    ::tracing::info!(
        event = "scan_recent_files_started",
        now_epoch = now,
        since_secs
    );
    let files = agents::discover_recent_sessions_for_backfill(now, since_secs).await;
    if let Some(pb) = spinner {
        pb.finish_and_clear();
    }
    output::action("Scanned", &format!("agent logs (last {} days)", since_days));
    output::detail(&format!("Found {} session logs", files.len()));
    let mut agent_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for file in &files {
        let agent = file.agent_type.to_string();
        *agent_counts.entry(agent).or_insert(0) += 1;
    }
    ::tracing::info!(
        event = "scan_recent_files_completed",
        files_found = files.len(),
        agent_counts = ?agent_counts
    );
    if !files.is_empty() {
        let summary = agent_counts
            .iter()
            .map(|(agent, count)| format!("{agent}={count}"))
            .collect::<Vec<_>>()
            .join(", ");
        output::detail(&format!("Agents: {}", summary));
    }

    // Counters for final summary
    let mut uploaded = 0usize;
    let mut queued = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;
    let mut sessions_by_repo: std::collections::BTreeMap<String, Vec<SessionInfo>> =
        std::collections::BTreeMap::new();
    let mut repo_root_cache: std::collections::HashMap<String, git::RepoRootResolution> =
        std::collections::HashMap::new();
    let mut repo_display_cache: std::collections::HashMap<std::path::PathBuf, String> =
        std::collections::HashMap::new();

    let progress = if use_progress {
        let pb = ProgressBar::new(files.len() as u64);
        pb.set_draw_target(ProgressDrawTarget::stderr());
        pb.set_style(
            ProgressStyle::with_template("{bar:40.cyan/blue} {pos}/{len} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_bar()),
        );
        pb.set_message("Processing sessions");
        Some(pb)
    } else {
        None
    };

    for log in &files {
        let file_path = log.source_label();
        let metadata = session_log_metadata(log).await;

        // Skip files with no session metadata (e.g., file-history-snapshot files)
        if metadata.session_id.is_none() && metadata.cwd.is_none() {
            let reason = discovery_skip_reason_for_missing_metadata(log);
            ::tracing::info!(
                event = "session_discovery_skipped",
                file = file_path.as_str(),
                agent = log.agent_type.to_string(),
                reason
            );
            if let Some(ref pb) = progress {
                pb.inc(1);
            }
            continue;
        }

        // Skip sessions with no cwd silently — we can't determine the repo
        let cwd = match &metadata.cwd {
            Some(c) => c.clone(),
            None => {
                let reason = discovery_skip_reason_for_missing_cwd(log);
                ::tracing::info!(
                    event = "session_discovery_skipped",
                    file = file_path.as_str(),
                    agent = log.agent_type.to_string(),
                    session_id = ?metadata.session_id,
                    reason
                );
                if let Some(ref pb) = progress {
                    pb.inc(1);
                }
                continue;
            }
        };

        let repo_resolution = if let Some(cached) = repo_root_cache.get(&cwd) {
            cached.clone()
        } else {
            let cwd_path = std::path::Path::new(&cwd);
            let resolved = match git::resolve_repo_root_with_fallbacks(cwd_path).await {
                Ok(resolution) => resolution,
                Err(diagnostics) => {
                    // Fallback: scan transcript content for file paths that
                    // reveal the actual working directory. This handles cases
                    // like Claude desktop sessions where the manifest's `cwd`
                    // points to a parent directory (e.g. ~/Documents/GitHub)
                    // rather than the specific repo.
                    let transcript_resolution =
                        resolve_repo_from_transcript(log, &repo_root_cache).await;

                    if let Some(resolution) = transcript_resolution {
                        ::tracing::info!(
                            event = "session_cwd_resolved_from_transcript",
                            file = file_path.as_str(),
                            session_id = ?metadata.session_id,
                            original_cwd = cwd.as_str(),
                            resolved_repo = resolution.repo_root.to_string_lossy().to_string(),
                        );
                        resolution
                    } else {
                        ::tracing::warn!(
                            event = "session_discovery_skipped",
                            file = file_path.as_str(),
                            session_id = ?metadata.session_id,
                            cwd = cwd.as_str(),
                            requested_cwd = diagnostics.requested_cwd.to_string_lossy().to_string(),
                            reason = "repo_root_lookup_failed",
                            error = ?diagnostics.direct_error,
                            cwd_exists = diagnostics.cwd_exists,
                            nearest_existing_ancestor = ?diagnostics
                                .nearest_existing_ancestor
                                .map(|path| path.to_string_lossy().to_string()),
                            ancestor_error = ?diagnostics.ancestor_error,
                            candidate_repo_names = ?diagnostics.candidate_repo_names,
                            candidate_owner_repo_roots = ?diagnostics
                                .candidate_owner_repo_roots
                                .into_iter()
                                .map(|path| path.to_string_lossy().to_string())
                                .collect::<Vec<_>>(),
                            matched_worktree_owner_repo_root = ?diagnostics
                                .matched_worktree_owner_repo_root
                                .map(|path| path.to_string_lossy().to_string()),
                            matched_worktree_path = ?diagnostics
                                .matched_worktree_path
                                .map(|path| path.to_string_lossy().to_string()),
                        );
                        if let Some(ref pb) = progress {
                            pb.inc(1);
                        }
                        continue;
                    }
                }
            };
            repo_root_cache.insert(cwd.clone(), resolved.clone());
            resolved
        };
        let repo_root = repo_resolution.repo_root.clone();

        // If a repo filter is set, skip sessions that don't match.
        if let Some(filter) = repo_filter
            && repo_root != filter
        {
            ::tracing::info!(
                event = "session_discovery_skipped",
                file = file_path.as_str(),
                session_id = ?metadata.session_id,
                cwd = cwd.as_str(),
                repo_root = repo_root.to_string_lossy().to_string(),
                resolved_via = ?repo_resolution.diagnostics.resolved_via,
                alternative_repo_roots = ?repo_resolution
                    .diagnostics
                    .alternative_repo_roots
                    .iter()
                    .map(|path| path.to_string_lossy().to_string())
                    .collect::<Vec<_>>(),
                reason = "repo_filter_mismatch",
                repo_filter = filter.to_string_lossy().to_string()
            );
            if let Some(ref pb) = progress {
                pb.inc(1);
            }
            continue;
        }

        let session_id = metadata
            .session_id
            .as_deref()
            .unwrap_or("unknown")
            .to_string();

        // Determine repo display: prefer remote URL, fall back to directory name
        let repo_display = if let Some(cached) = repo_display_cache.get(&repo_root) {
            cached.clone()
        } else {
            let resolved = match git::first_remote_url_at(&repo_root).await {
                Ok(Some(url)) => url,
                Err(e) => {
                    ::tracing::warn!(
                        event = "repo_display_fallback",
                        file = file_path.as_str(),
                        session_id = session_id.as_str(),
                        repo_root = repo_root.to_string_lossy().to_string(),
                        error = e.to_string()
                    );
                    repo_root
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                }
                _ => repo_root
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
            };
            repo_display_cache.insert(repo_root.clone(), resolved.clone());
            resolved
        };

        let agent_label = metadata
            .agent_type
            .clone()
            .unwrap_or(scanner::AgentType::Claude)
            .to_string();
        ::tracing::info!(
            event = "session_enqueued",
            file = file_path.as_str(),
            session_id = session_id.as_str(),
            cwd = cwd.as_str(),
            repo_root = repo_root.to_string_lossy().to_string(),
            repo_display = repo_display.as_str(),
            agent = agent_label,
            resolved_via = ?repo_resolution.diagnostics.resolved_via,
            alternative_repo_roots = ?repo_resolution
                .diagnostics
                .alternative_repo_roots
                .iter()
                .map(|path| path.to_string_lossy().to_string())
                .collect::<Vec<_>>(),
        );

        sessions_by_repo
            .entry(repo_display.clone())
            .or_default()
            .push(SessionInfo {
                log: log.clone(),
                session_id,
                repo_root,
                metadata,
            });

        if let Some(ref pb) = progress {
            pb.inc(1);
        }
    }

    if let Some(pb) = progress {
        pb.finish_and_clear();
    }

    // Step 4: Process sessions grouped by repo (bounded parallelism)
    let total_repos = sessions_by_repo.len();
    let concurrency = backfill_repo_concurrency();
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut join_set = tokio::task::JoinSet::new();
    let multi = use_progress.then(MultiProgress::new);
    ::tracing::info!(event = "repo_workers_started", total_repos, concurrency);
    if let Some(mp) = &multi {
        mp.set_draw_target(ProgressDrawTarget::stderr());
        mp.set_move_cursor(true);
    }

    for (repo_display, sessions) in sessions_by_repo {
        let permit = semaphore.clone().acquire_owned().await?;
        let upload_context = Arc::clone(&upload_context);
        ::tracing::info!(
            event = "repo_worker_queued",
            repo_display = repo_display.as_str(),
            sessions = sessions.len()
        );
        let per_repo_bar = if let Some(mp) = &multi {
            let total_units: u64 = (sessions.len() as u64).max(1);
            let pb = mp.add(ProgressBar::new(total_units));
            pb.set_style(
                ProgressStyle::with_template(
                    "  {prefix:36.cyan.bold} {bar:20.green/black} {pos:>3}/{len:<3} {msg:.yellow}",
                )
                .unwrap_or_else(|_| ProgressStyle::default_bar()),
            );
            let repo_label = repo_label_from_display(&repo_display);
            let short_name = if repo_label.len() > 36 {
                format!("{}…", &repo_label[..35])
            } else {
                repo_label
            };
            pb.set_prefix(short_name);
            pb.set_message("queued");
            Some(pb)
        } else {
            None
        };
        join_set.spawn(async move {
            let _permit = permit;
            Ok::<RepoBackfillStats, tokio::task::JoinError>(
                process_repo_backfill(repo_display, sessions, upload_context, per_repo_bar).await,
            )
        });
    }

    while let Some(joined) = join_set.join_next().await {
        match joined {
            Ok(Ok(repo_stats)) => {
                uploaded += repo_stats.uploaded;
                queued += repo_stats.queued;
                skipped += repo_stats.skipped;
                errors += repo_stats.errors;
                ::tracing::info!(
                    event = "repo_worker_result",
                    uploaded = repo_stats.uploaded,
                    queued = repo_stats.queued,
                    sessions_seen = repo_stats.sessions_seen,
                    skipped = repo_stats.skipped,
                    errors = repo_stats.errors
                );
            }
            Ok(Err(e)) => {
                errors += 1;
                output::detail(&format!("repo worker failed: {}", e));
                ::tracing::warn!(event = "repo_worker_error", error = e.to_string());
            }
            Err(e) => {
                errors += 1;
                output::detail(&format!("repo task join failed: {}", e));
                ::tracing::warn!(event = "repo_worker_join_error", error = e.to_string());
            }
        }
    }

    // Final summary
    output::success(
        "Backfill",
        &format!("{uploaded} uploaded, {queued} queued, {skipped} skipped, {errors} issues"),
    );
    let issues = if errors > 0 {
        vec![format!("{errors} issue(s) encountered during backfill")]
    } else if queued > 0 {
        vec![format!("{queued} session(s) queued for retry")]
    } else {
        Vec::new()
    };
    report_backfill_completion(
        since_days as i32,
        BackfillSyncStats {
            notes_attached: uploaded as i64,
            notes_skipped: skipped as i64,
            issues,
            repos_scanned: total_repos as i32,
        },
    )
    .await;
    ::tracing::info!(
        event = "backfill_completed",
        uploaded,
        queued,
        skipped,
        errors,
        repos_scanned = total_repos,
        since_days,
        pending_attempted = pending_summary.attempted,
        pending_uploaded = pending_summary.uploaded,
        pending_already_existed = pending_summary.already_existed,
        pending_skipped_repo_not_associated = pending_summary.skipped_repo_not_associated,
        pending_dropped_permanent = pending_summary.dropped_permanent,
        pending_auth_required = pending_summary.auth_required
    );
    if !upload_context.has_token() && queued > 0 {
        output::note("Run `cadence login` to upload queued AI sessions.");
    }
    Ok(BackfillOutcome::Completed)
}

#[derive(Debug, Default, Clone, Copy)]
struct MonitorTickSummary {
    discovered: usize,
    uploaded: usize,
    queued: usize,
    skipped: usize,
    issues: usize,
    pending_attempted: usize,
    pending_uploaded: usize,
}

#[derive(Debug)]
struct MonitorTickOutcome {
    summary: MonitorTickSummary,
    state_error: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct MonitorTickOptions {
    force: bool,
    drain_pending: bool,
    run_auto_update: bool,
}

fn publication_auth_skip_message(state: &upload::PublicationAuthState) -> Option<String> {
    match state {
        upload::PublicationAuthState::Ready => None,
        upload::PublicationAuthState::MissingToken => Some(
            "Cadence login is missing; background publishing is paused until you run `cadence login`."
                .to_string(),
        ),
        upload::PublicationAuthState::Rejected => Some(
            "Cadence login was rejected by the server; background publishing is paused until you run `cadence login`."
                .to_string(),
        ),
        upload::PublicationAuthState::CheckFailed(message) => Some(format!(
            "Cadence publication auth check failed; background publishing is paused ({message})."
        )),
    }
}

async fn current_publication_auth_state() -> upload::PublicationAuthState {
    match upload::resolve_upload_context(api_url_override()).await {
        Ok(context) => upload::publication_auth_state(&context).await,
        Err(err) => upload::PublicationAuthState::CheckFailed(format!(
            "failed to initialize upload context ({err:#})"
        )),
    }
}

async fn write_publication_auth_status_line(w: &mut dyn std::io::Write) {
    let state = current_publication_auth_state().await;
    output::detail_to_with_tty(w, &format!("Publication auth: {}", state.detail()), false);
    if let Some(remediation) = state.remediation() {
        output::detail_to_with_tty(
            w,
            &format!("Publication auth remediation: {remediation}"),
            false,
        );
    }
}

async fn upload_incremental_sessions_globally(
    context: &upload::UploadContext,
) -> Result<MonitorTickSummary> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let persisted_cursor = monitor::load_discovery_cursor().await?;
    let initial_cursor = match persisted_cursor {
        Some(record) => IncrementalCursor::from_position(
            record.last_scanned_mtime_epoch,
            record.last_scanned_source_label,
        ),
        None => IncrementalCursor::from_position(now - MONITOR_DEFAULT_CURSOR_WINDOW_SECS, None),
    };
    let selection_cursor = selection_cursor_with_lookback(&initial_cursor);
    let since_secs = (now - selection_cursor.last_scanned_mtime_epoch).max(0);
    let files = agents::discover_recent_sessions_for_monitor(now, since_secs).await;
    let candidates = select_incremental_candidates(files, &selection_cursor, usize::MAX);
    let parsed_logs = parse_session_logs_bounded(candidates).await;

    let mut repo_root_cache: std::collections::HashMap<String, Option<std::path::PathBuf>> =
        std::collections::HashMap::new();
    let mut repo_enabled_cache: std::collections::HashMap<std::path::PathBuf, bool> =
        std::collections::HashMap::new();
    let mut repo_org_cache: std::collections::HashMap<std::path::PathBuf, bool> =
        std::collections::HashMap::new();
    let mut seen_sessions: std::collections::HashSet<MonitorSessionDedupeKey> =
        std::collections::HashSet::new();
    let mut stats = MonitorTickSummary {
        discovered: parsed_logs.len(),
        ..MonitorTickSummary::default()
    };
    let mut cursor_advance = initial_cursor.clone();

    for parsed in parsed_logs {
        let log_mtime = parsed.log.updated_at;
        let log_source_label = parsed.log.source_label();
        let Some(cwd) = parsed.metadata.cwd.clone() else {
            cursor_advance =
                advance_cursor_for_disposition(&cursor_advance, log_mtime, &log_source_label);
            continue;
        };
        let resolved_repo = if let Some(cached) = repo_root_cache.get(&cwd) {
            cached.clone()
        } else {
            let mut resolved = git::resolve_repo_root_with_fallbacks(std::path::Path::new(&cwd))
                .await
                .ok()
                .map(|resolution| resolution.repo_root);

            // Fallback: scan transcript for file paths when CWD doesn't
            // resolve to a repo (e.g. Claude desktop app parent-dir CWD).
            if resolved.is_none()
                && let Some(content) = session_log_content_async(&parsed.log).await
            {
                let candidates = scanner::extract_candidate_cwds_from_transcript(&content);
                for candidate_cwd in candidates.iter().take(TRANSCRIPT_CWD_MAX_CANDIDATES) {
                    let cwd_path = std::path::Path::new(&candidate_cwd);
                    if let Ok(resolution) = git::resolve_repo_root_with_fallbacks(cwd_path).await {
                        resolved = Some(resolution.repo_root);
                        break;
                    }
                }
            }

            repo_root_cache.insert(cwd.clone(), resolved.clone());
            resolved
        };
        let Some(resolved_repo) = resolved_repo else {
            cursor_advance =
                advance_cursor_for_disposition(&cursor_advance, log_mtime, &log_source_label);
            continue;
        };

        let repo_enabled = if let Some(cached) = repo_enabled_cache.get(&resolved_repo) {
            *cached
        } else {
            let enabled = git::check_enabled_at(&resolved_repo).await;
            repo_enabled_cache.insert(resolved_repo.clone(), enabled);
            enabled
        };
        if !repo_enabled {
            cursor_advance =
                advance_cursor_for_disposition(&cursor_advance, log_mtime, &log_source_label);
            continue;
        }

        let repo_matches_org = if let Some(cached) = repo_org_cache.get(&resolved_repo) {
            *cached
        } else {
            let matches = match git::repo_matches_org_filter(&resolved_repo).await {
                Ok(matches) => matches,
                Err(err) => {
                    output::detail(&format!(
                        "{}: org filter check failed: {}",
                        resolved_repo.display(),
                        err
                    ));
                    ::tracing::warn!(
                        event = "monitor_discovery_skipped",
                        repo_root = resolved_repo.to_string_lossy().as_ref(),
                        source_label = log_source_label.as_str(),
                        stage = "org_filter_check",
                        error = err.to_string()
                    );
                    apply_monitor_org_filter_error(
                        &mut stats,
                        &mut cursor_advance,
                        log_mtime,
                        &log_source_label,
                    );
                    continue;
                }
            };
            repo_org_cache.insert(resolved_repo.clone(), matches);
            matches
        };
        if !repo_matches_org {
            cursor_advance =
                advance_cursor_for_disposition(&cursor_advance, log_mtime, &log_source_label);
            continue;
        }

        let dedupe_key = monitor_session_dedupe_key(&parsed, &resolved_repo);
        if !seen_sessions.insert(dedupe_key) {
            stats.skipped += 1;
            cursor_advance =
                advance_cursor_for_disposition(&cursor_advance, log_mtime, &log_source_label);
            continue;
        }

        let repo_root_str = resolved_repo.to_string_lossy().to_string();
        let outcome = upload_session_from_log(
            context,
            &parsed,
            &resolved_repo,
            &repo_root_str,
            PublicationMode::Live,
        )
        .await;
        apply_monitor_incremental_upload_outcome(
            &mut stats,
            &mut cursor_advance,
            log_mtime,
            &log_source_label,
            outcome,
        );
    }

    if cursor_advance != initial_cursor {
        monitor::upsert_discovery_cursor(
            cursor_advance.last_scanned_mtime_epoch,
            cursor_advance.last_scanned_source_label.as_deref(),
        )
        .await?;
    }

    Ok(stats)
}

async fn run_monitor_tick_internal(options: MonitorTickOptions) -> Result<MonitorTickSummary> {
    let mut state = monitor::load_state().await.unwrap_or_default();
    if !options.force && !state.enabled {
        return Ok(MonitorTickSummary::default());
    }

    let Some(_activity_lock) =
        update::try_acquire_activity_lock_nonblocking("monitor-tick").await?
    else {
        return Ok(MonitorTickSummary::default());
    };

    if let Err(err) = update::cleanup_legacy_auto_update_scheduler_for_monitor_runtime().await {
        ::tracing::warn!(
            event = "legacy_auto_update_scheduler_cleanup_failed",
            error = %format!("{err:#}")
        );
    }

    let now = publication_state::now_rfc3339();
    state.last_run_at = Some(now.clone());
    monitor::save_state(&state).await?;

    let run_result: Result<MonitorTickOutcome> = async {
        let upload_context = upload::resolve_upload_context(api_url_override()).await?;
        let publication_auth = upload::publication_auth_state(&upload_context).await;
        if publication_auth.blocks_background_publication()
            && let Some(skip_message) = publication_auth_skip_message(&publication_auth)
        {
            ::tracing::warn!(
                event = "monitor_tick_publication_paused",
                reason = skip_message
            );
            if options.run_auto_update {
                update::run_background_auto_update_for_monitor_tick().await?;
            }
            return Ok(MonitorTickOutcome {
                summary: MonitorTickSummary::default(),
                state_error: Some(skip_message),
            });
        }
        let pending_summary = if options.drain_pending {
            let pending_to_drain = upload::pending_upload_count().await.unwrap_or(0);
            upload::process_pending_uploads(&upload_context, pending_to_drain).await?
        } else {
            upload::PendingUploadSummary::default()
        };
        let mut summary = upload_incremental_sessions_globally(&upload_context).await?;
        summary.pending_attempted = pending_summary.attempted;
        summary.pending_uploaded = pending_summary.uploaded + pending_summary.already_existed;
        if options.run_auto_update {
            update::run_background_auto_update_for_monitor_tick().await?;
        }
        Ok(MonitorTickOutcome {
            summary,
            state_error: None,
        })
    }
    .await;

    match run_result {
        Ok(outcome) => {
            state.last_success_at = Some(publication_state::now_rfc3339());
            state.last_error = outcome.state_error;
            let summary = outcome.summary;
            state.last_discovered = summary.discovered;
            state.last_uploaded = summary.uploaded;
            state.last_queued = summary.queued;
            state.last_skipped = summary.skipped;
            state.last_issues = summary.issues;
            state.last_pending_attempted = summary.pending_attempted;
            state.last_pending_uploaded = summary.pending_uploaded;
            monitor::save_state(&state).await?;
            Ok(summary)
        }
        Err(err) => {
            state.last_error = Some(format!("{err:#}"));
            monitor::save_state(&state).await?;
            Err(err)
        }
    }
}

async fn run_monitor_tick(force: bool) -> Result<()> {
    let _ = run_monitor_tick_internal(MonitorTickOptions {
        force,
        drain_pending: true,
        run_auto_update: true,
    })
    .await?;
    Ok(())
}

/// The status subcommand: show Cadence CLI configuration and state.
///
/// Displays:
/// - Current repo root (or a message if not in a git repo)
/// - Monitor enabled state, scheduler health, and last-run metadata
/// - Pending upload count and updater health
/// - Org filter config (if any)
/// - Per-repo enabled/disabled status
///
/// All output is user-facing and written to stderr.
/// Handles being called outside a git repo gracefully.
async fn run_status() -> Result<()> {
    run_status_inner(&mut std::io::stderr()).await
}

async fn run_status_inner(w: &mut dyn std::io::Write) -> Result<()> {
    output::action_to_with_tty(w, "Status", "", false);

    let repo_root = match git::repo_root().await {
        Ok(root) => {
            output::detail_to_with_tty(w, &format!("Repo: {}", root.to_string_lossy()), false);
            Some(root)
        }
        Err(_) => {
            output::detail_to_with_tty(w, "Repo: (not in a git repository)", false);
            None
        }
    };

    write_monitor_status_block(w, true).await?;

    match git::config_get_global("ai.cadence.org").await {
        Ok(Some(org)) => {
            output::detail_to_with_tty(w, &format!("Org filter: {}", org), false);
        }
        _ => {
            output::detail_to_with_tty(w, "Org filter: (none)", false);
        }
    }

    if repo_root.is_some() {
        let enabled = git::check_enabled().await;
        if enabled {
            output::detail_to_with_tty(w, "Repo enabled: yes", false);
        } else {
            output::detail_to_with_tty(w, "Repo enabled: no", false);
        }
    } else {
        output::detail_to_with_tty(w, "Repo enabled: (n/a - not in a repo)", false);
    }

    let updater_health = update::updater_health().await;
    let updater_state = match updater_health.state {
        update::UpdaterHealthState::Disabled => "disabled",
        update::UpdaterHealthState::NeverRun => "never-run",
        update::UpdaterHealthState::Healthy => "healthy",
        update::UpdaterHealthState::Retrying => "retrying",
        update::UpdaterHealthState::Failing => "failing",
    };
    output::detail_to_with_tty(
        w,
        &format!(
            "Auto-update: {} (enabled: {}, last result: {})",
            updater_state,
            if updater_health.enabled { "yes" } else { "no" },
            updater_health.last_result
        ),
        false,
    );
    if let Some(last_attempt) = updater_health.last_attempt_at {
        output::detail_to_with_tty(
            w,
            &format!("Auto-update last attempt: {last_attempt}"),
            false,
        );
    }
    if let Some(next_retry) = updater_health.next_retry_after {
        output::detail_to_with_tty(w, &format!("Auto-update next retry: {next_retry}"), false);
    }
    if let Some(last_error) = updater_health.last_error {
        output::detail_to_with_tty(w, &format!("Auto-update last error: {last_error}"), false);
    }
    output::detail_to_with_tty(
        w,
        &format!(
            "Auto-update policy: {}",
            update::auto_update_policy_summary()
        ),
        false,
    );
    output::detail_to_with_tty(w, "Controls: `cadence auto-update status`", false);

    Ok(())
}

async fn run_doctor(repair: bool) -> Result<()> {
    run_doctor_inner(&mut std::io::stderr(), repair).await
}

fn desired_monitor_enabled_for_repair(
    configured_enabled_state: Result<Option<bool>>,
) -> (bool, bool) {
    match configured_enabled_state {
        Ok(Some(enabled)) => (enabled, false),
        Ok(None) => (true, false),
        Err(_) => (true, true),
    }
}

fn repaired_monitor_state_for_enabled(
    enabled: bool,
    loaded_state: Result<monitor::MonitorState>,
) -> monitor::MonitorState {
    let mut state = loaded_state.unwrap_or_default();
    state.enabled = enabled;
    state
}

async fn run_doctor_inner(w: &mut dyn std::io::Write, repair: bool) -> Result<()> {
    output::action_to_with_tty(w, "Doctor", "", false);

    let mut issues = 0usize;

    match git::repo_root().await {
        Ok(root) => {
            output::detail_to_with_tty(w, &format!("Repo: {}", root.to_string_lossy()), false);
        }
        Err(_) => {
            output::detail_to_with_tty(w, "Repo: (not in a git repository)", false);
        }
    };

    match monitor::load_state().await {
        Ok(state) => {
            output::detail_to_with_tty(
                w,
                &format!(
                    "Monitor enabled: {}",
                    if state.enabled { "yes" } else { "no" }
                ),
                false,
            );
        }
        Err(err) => {
            output::fail_to_with_tty(
                w,
                "Fail",
                &format!("could not read monitor state ({err})"),
                false,
            );
            issues += 1;
        }
    }

    if let Err(err) = monitor::load_discovery_cursor().await {
        output::fail_to_with_tty(
            w,
            "Fail",
            &format!("could not read monitor discovery cursor ({err})"),
            false,
        );
        issues += 1;
    } else {
        output::detail_to_with_tty(w, "Monitor discovery cursor: readable", false);
    }

    match upload::pending_upload_count().await {
        Ok(count) => {
            output::detail_to_with_tty(w, &format!("Pending uploads: {}", count), false);
        }
        Err(err) => {
            output::fail_to_with_tty(
                w,
                "Fail",
                &format!("pending upload state is unreadable ({err})"),
                false,
            );
            issues += 1;
        }
    }

    let publication_auth = current_publication_auth_state().await;
    match &publication_auth {
        upload::PublicationAuthState::Ready => {
            output::detail_to_with_tty(w, "Publication auth: ready", false);
        }
        upload::PublicationAuthState::MissingToken
        | upload::PublicationAuthState::Rejected
        | upload::PublicationAuthState::CheckFailed(_) => {
            output::fail_to_with_tty(
                w,
                "Fail",
                &format!("Publication auth: {}", publication_auth.detail()),
                false,
            );
            if let Some(remediation) = publication_auth.remediation() {
                output::detail_to_with_tty(
                    w,
                    &format!("Publication auth remediation: {remediation}"),
                    false,
                );
            }
            issues += 1;
        }
    }

    let updater_health = update::updater_health().await;
    match updater_health.state {
        update::UpdaterHealthState::Disabled => {
            output::detail_to_with_tty(
                w,
                "Auto-update: disabled because background monitoring is disabled",
                false,
            );
        }
        update::UpdaterHealthState::NeverRun => {
            output::detail_to_with_tty(w, "Auto-update: enabled, never run yet", false);
        }
        update::UpdaterHealthState::Healthy => {
            output::detail_to_with_tty(w, "Auto-update: healthy", false);
        }
        update::UpdaterHealthState::Retrying => {
            output::fail_to_with_tty(w, "Fail", "Auto-update is retrying after failures", false);
            issues += 1;
        }
        update::UpdaterHealthState::Failing => {
            output::fail_to_with_tty(w, "Fail", "Auto-update is failing repeatedly", false);
            issues += 1;
        }
    }
    if let Some(next_retry) = updater_health.next_retry_after {
        output::detail_to_with_tty(w, &format!("Auto-update next retry: {next_retry}"), false);
    }
    if let Some(last_error) = updater_health.last_error {
        output::detail_to_with_tty(w, &format!("Auto-update last error: {last_error}"), false);
    }
    if let Some(last_attempt) = updater_health.last_attempt_at {
        output::detail_to_with_tty(
            w,
            &format!("Auto-update last attempt: {last_attempt}"),
            false,
        );
    }
    output::detail_to_with_tty(
        w,
        &format!(
            "Auto-update policy: {}",
            update::auto_update_policy_summary()
        ),
        false,
    );

    if repair {
        let configured_enabled_state = monitor::configured_enabled_state().await;
        let (enabled, defaulted_to_enabled) =
            desired_monitor_enabled_for_repair(configured_enabled_state);
        let repaired_state =
            repaired_monitor_state_for_enabled(enabled, monitor::load_state().await);
        monitor::save_state(&repaired_state).await?;
        let reconcile = monitor::reconcile_scheduler_for_enabled(enabled).await?;
        if defaulted_to_enabled {
            output::note_to_with_tty(
                w,
                "Monitor state was unreadable; repair recreated it with monitoring enabled.",
                false,
            );
        }
        output::detail_to_with_tty(
            w,
            &format!("Repair applied: {}", reconcile.description),
            false,
        );
    }

    let scheduler_health = monitor::scheduler_health().await;
    match scheduler_health.state {
        monitor::SchedulerHealthState::Installed | monitor::SchedulerHealthState::Unsupported => {
            output::detail_to_with_tty(
                w,
                &format!("Monitor scheduler: {}", scheduler_health.details),
                false,
            );
        }
        monitor::SchedulerHealthState::Missing | monitor::SchedulerHealthState::Broken => {
            output::fail_to_with_tty(
                w,
                "Fail",
                &format!("Monitor scheduler: {}", scheduler_health.details),
                false,
            );
            issues += 1;
        }
    }
    output::detail_to_with_tty(
        w,
        &format!("Monitor remediation: {}", scheduler_health.remediation),
        false,
    );
    output::detail_to_with_tty(
        w,
        "Remediation commands: `cadence monitor enable`, `cadence monitor disable`, `cadence monitor uninstall`, `cadence install`, `cadence doctor --repair`",
        false,
    );

    if issues == 0 {
        output::success_to_with_tty(w, "Doctor", "all checks passed", false);
        Ok(())
    } else {
        output::fail_to_with_tty(w, "Doctor", &format!("{} issue(s) found", issues), false);
        anyhow::bail!("doctor found {} issue(s)", issues);
    }
}

// ---------------------------------------------------------------------------
// Config subcommand handlers
// ---------------------------------------------------------------------------

/// Set a configuration value and persist to disk.
async fn run_config_set(key_str: &str, value: &str) -> Result<()> {
    let key: config::ConfigKey = key_str.parse()?;
    let mut cfg = config::CliConfig::load().await?;
    cfg.set_key(key, value)?;
    cfg.save().await?;
    output::success("Set", &format!("{} = {}", key.name(), cfg.get_key(key)));
    Ok(())
}

/// Print a single configuration value to stdout (machine-readable).
async fn run_config_get(key_str: &str) -> Result<()> {
    let key: config::ConfigKey = key_str.parse()?;
    let cfg = config::CliConfig::load().await?;
    println!("{}", cfg.get_key(key));
    Ok(())
}

/// List all user-settable configuration keys with their current values.
async fn run_config_list() -> Result<()> {
    let cfg = config::CliConfig::load().await?;
    for key in config::ALL_CONFIG_KEYS {
        let value = cfg.get_key(*key);
        println!("{} = {}", key.name(), value);
    }
    Ok(())
}

async fn write_monitor_status_block(
    w: &mut dyn std::io::Write,
    include_controls: bool,
) -> Result<()> {
    let state = monitor::load_state().await.unwrap_or_default();
    let scheduler = monitor::scheduler_health().await;
    let scheduler_state = match scheduler.state {
        monitor::SchedulerHealthState::Installed => "installed",
        monitor::SchedulerHealthState::Missing => "missing",
        monitor::SchedulerHealthState::Broken => "broken",
        monitor::SchedulerHealthState::Unsupported => "unsupported",
    };
    output::detail_to_with_tty(
        w,
        &format!(
            "Monitor enabled: {}",
            if state.enabled { "yes" } else { "no" }
        ),
        false,
    );
    output::detail_to_with_tty(
        w,
        &format!("Monitor cadence: {}", monitor::cadence_label()),
        false,
    );
    output::detail_to_with_tty(
        w,
        &format!(
            "Monitor scheduler: {scheduler_state} ({})",
            scheduler.details
        ),
        false,
    );
    output::detail_to_with_tty(
        w,
        &format!("Monitor remediation: {}", scheduler.remediation),
        false,
    );
    if let Some(last_run) = state.last_run_at {
        output::detail_to_with_tty(w, &format!("Monitor last run: {last_run}"), false);
    }
    if let Some(last_success) = state.last_success_at {
        output::detail_to_with_tty(w, &format!("Monitor last success: {last_success}"), false);
    }
    if let Some(last_error) = state.last_error {
        output::detail_to_with_tty(w, &format!("Monitor last error: {last_error}"), false);
    }
    output::detail_to_with_tty(
        w,
        &format!(
            "Monitor last summary: discovered={}, uploaded={}, queued={}, skipped={}, issues={}, pending_retried={}",
            state.last_discovered,
            state.last_uploaded,
            state.last_queued,
            state.last_skipped,
            state.last_issues,
            state.last_pending_uploaded,
        ),
        false,
    );
    let pending_uploads = upload::pending_upload_count().await.unwrap_or(0);
    output::detail_to_with_tty(w, &format!("Pending uploads: {}", pending_uploads), false);
    write_publication_auth_status_line(w).await;
    if include_controls {
        output::detail_to_with_tty(
            w,
            "Controls: `cadence monitor status|enable|disable|uninstall`",
            false,
        );
    }
    Ok(())
}

async fn run_monitor_status() -> Result<()> {
    let mut stderr = std::io::stderr();
    output::action_to_with_tty(&mut stderr, "Monitor", "status", false);
    write_monitor_status_block(&mut stderr, true).await
}

async fn run_monitor_enable() -> Result<()> {
    let reconcile = monitor::ensure_enabled_and_reconciled().await?;
    output::success("Monitor", "enabled. Background monitoring is now active.");
    output::detail(&format!("Cadence: {}", monitor::cadence_label()));
    output::detail(&format!("Scheduler reconciled: {}", reconcile.description));
    output::detail("Disable with `cadence monitor disable`.");
    output::detail("Remove scheduler artifacts with `cadence monitor uninstall`.");
    Ok(())
}

async fn run_monitor_disable() -> Result<()> {
    let _ = monitor::set_enabled(false).await?;
    output::success(
        "Monitor",
        "disabled. Scheduled monitor runs will no-op immediately.",
    );
    output::detail("Re-enable with `cadence monitor enable`.");
    output::detail("Remove scheduler artifacts with `cadence monitor uninstall`.");
    Ok(())
}

async fn run_monitor_uninstall() -> Result<()> {
    let removed = monitor::uninstall_monitor().await?;
    if removed.removed {
        output::success("Monitor", "scheduler artifacts removed.");
    } else {
        output::detail("Monitor scheduler artifacts were already absent.");
    }
    output::detail(&format!("Cleanup target: {}", removed.description));
    output::detail(
        "Background monitoring remains disabled until you run `cadence monitor enable`.",
    );
    Ok(())
}

async fn run_monitor(command: Option<MonitorCommand>) -> Result<()> {
    match command.unwrap_or(MonitorCommand::Status) {
        MonitorCommand::Status => run_monitor_status().await,
        MonitorCommand::Enable => run_monitor_enable().await,
        MonitorCommand::Disable => run_monitor_disable().await,
        MonitorCommand::Uninstall => run_monitor_uninstall().await,
        MonitorCommand::Tick => run_monitor_tick(false).await,
    }
}

async fn run_auto_update_status() -> Result<()> {
    let mut stderr = std::io::stderr();
    let updater = update::updater_health().await;
    output::action_to_with_tty(&mut stderr, "Auto-update", "status", false);
    output::detail_to_with_tty(
        &mut stderr,
        &format!("Enabled: {}", if updater.enabled { "yes" } else { "no" }),
        false,
    );
    output::detail_to_with_tty(
        &mut stderr,
        &format!("Policy: {}", update::auto_update_policy_summary()),
        false,
    );
    let updater_state = match updater.state {
        update::UpdaterHealthState::Disabled => "disabled",
        update::UpdaterHealthState::NeverRun => "never-run",
        update::UpdaterHealthState::Healthy => "healthy",
        update::UpdaterHealthState::Retrying => "retrying",
        update::UpdaterHealthState::Failing => "failing",
    };
    output::detail_to_with_tty(
        &mut stderr,
        &format!("Updater state: {updater_state}"),
        false,
    );
    if let Some(last_attempt) = updater.last_attempt_at {
        output::detail_to_with_tty(
            &mut stderr,
            &format!("Last updater attempt: {last_attempt}"),
            false,
        );
    }
    output::detail_to_with_tty(
        &mut stderr,
        "Runtime: monitor-driven; monitor enablement controls unattended updates.",
        false,
    );
    output::detail_to_with_tty(
        &mut stderr,
        "Use `cadence monitor status` for scheduler visibility.",
        false,
    );
    Ok(())
}

async fn run_auto_update_enable() -> Result<()> {
    output::note(
        "`cadence auto-update enable` is now a compatibility command. Unattended updates run automatically whenever background monitoring is enabled.",
    );
    if monitor::monitor_enabled().await {
        output::detail("Background monitoring is already enabled.");
    } else {
        output::detail(
            "Run `cadence monitor enable` or `cadence install` to turn the runtime back on.",
        );
    }
    Ok(())
}

async fn run_auto_update_disable() -> Result<()> {
    output::note(
        "`cadence auto-update disable` is no longer supported because Cadence updates now follow monitor state.",
    );
    output::detail(
        "Run `cadence monitor disable` if you need to stop all background Cadence work.",
    );
    Ok(())
}

async fn run_auto_update_uninstall() -> Result<()> {
    output::note(
        "`cadence auto-update uninstall` now maps to `cadence monitor uninstall` because the scheduler is shared with background monitoring.",
    );
    run_monitor_uninstall().await?;
    Ok(())
}

async fn run_auto_update(command: Option<AutoUpdateCommand>) -> Result<()> {
    match command.unwrap_or(AutoUpdateCommand::Status) {
        AutoUpdateCommand::Status => run_auto_update_status().await,
        AutoUpdateCommand::Enable => run_auto_update_enable().await,
        AutoUpdateCommand::Disable => run_auto_update_disable().await,
        AutoUpdateCommand::Uninstall => run_auto_update_uninstall().await,
    }
}

// ---------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------

/// Completely remove Cadence CLI monitor configuration, legacy hook ownership,
/// scheduler artifacts, and local state.
///
/// Execution order (dependencies noted):
/// 1. Revoke API token (needs config.toml + network)
/// 2. Disable background monitoring + remove scheduler artifacts
/// 3. Remove Cadence-managed global git config
/// 4. Clean up legacy Cadence hook ownership where safe
/// 5. Clean ai.cadence.enabled from current + sibling repos
/// 6. Remove ~/.cadence/ directory tree
/// 7. Remove monitor/update compatibility logs
/// 8. Print summary
/// 9. Self-delete binary
async fn run_uninstall(yes: bool) -> Result<()> {
    println!();

    if !yes {
        let home = agents::home_dir().unwrap_or_default();
        let hooks_dir = home.join(".git-hooks");
        let state_dir = home.join(".cadence");
        let exe_path = std::env::current_exe().unwrap_or_default();

        output::fail(
            "Warning",
            "this will permanently remove all Cadence CLI artifacts:",
        );
        output::detail("Git config:  ai.cadence.org");
        output::detail(&format!("Hooks dir:   {}", hooks_dir.display()));
        output::detail(&format!("State dir:   {}", state_dir.display()));
        output::detail("Scheduler:   LaunchAgent / systemd / schtasks");
        output::detail(&format!("Binary:      {}", exe_path.display()));
        output::detail("API token:   will be revoked on server");
        println!();

        eprint!("  Type \"uninstall\" to confirm: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim() != "uninstall" {
            output::note("Uninstall cancelled.");
            return Ok(());
        }
        println!();
    }

    let start = std::time::Instant::now();
    let mut had_errors = false;

    // Step 1: Revoke API token (needs config.toml + network)
    match revoke_token_for_uninstall().await {
        Ok(()) => {}
        Err(e) => {
            output::note(&format!("Could not revoke token ({e})"));
            had_errors = true;
        }
    }

    // Step 2: Disable monitoring + remove scheduler artifacts
    match uninstall_scheduler().await {
        Ok(()) => {}
        Err(e) => {
            output::note(&format!("Could not remove scheduler ({e})"));
            had_errors = true;
        }
    }

    // Step 3: Remove Cadence-managed global git config
    match git::config_unset_global("ai.cadence.org").await {
        Ok(()) => output::success("Removed", "git config --global ai.cadence.org"),
        Err(e) => {
            output::note(&format!("Could not unset ai.cadence.org ({e})"));
            had_errors = true;
        }
    }

    // Step 4: Clean up legacy Cadence hook ownership where safe
    match bootstrap::cleanup_cadence_hook_ownership(None, true).await {
        Ok(had_cleanup_errors) => {
            had_errors |= had_cleanup_errors;
        }
        Err(e) => {
            output::note(&format!("Could not clean legacy hook ownership ({e})"));
            had_errors = true;
        }
    }

    // Step 5: Clean ai.cadence.enabled from current + sibling repos
    if let Err(e) = clean_repo_cadence_config().await {
        output::note(&format!("Could not clean per-repo config ({e})"));
        had_errors = true;
    }

    // Step 6: Remove ~/.cadence/ directory tree
    match uninstall_state_dir().await {
        Ok(()) => {}
        Err(e) => {
            output::note(&format!("Could not remove state directory ({e})"));
            had_errors = true;
        }
    }

    // Step 7: Remove compatibility logs
    for log_path in [
        std::path::Path::new("/tmp/cadence-autoupdate.log"),
        std::path::Path::new("/tmp/cadence-monitor.log"),
    ] {
        if log_path.exists() {
            match tokio::fs::remove_file(log_path).await {
                Ok(()) => output::success("Removed", &format!("{}", log_path.display())),
                Err(e) => {
                    output::note(&format!("Could not remove log file ({e})"));
                    had_errors = true;
                }
            }
        }
    }

    // Step 8: Summary
    println!();
    if had_errors {
        output::fail("Uninstall", "completed with issues");
    } else {
        output::success("Uninstall", "complete");
    }
    output::detail(&format!("Total time: {} ms", start.elapsed().as_millis()));

    // Step 9: Self-delete binary
    match std::env::current_exe() {
        Ok(exe) => {
            if cfg!(windows) {
                output::note(&format!(
                    "On Windows, delete the binary manually:\n  del \"{}\"",
                    exe.display()
                ));
            } else {
                match tokio::fs::remove_file(&exe).await {
                    Ok(()) => output::success("Removed", &format!("binary {}", exe.display())),
                    Err(e) => {
                        output::note(&format!(
                            "Could not remove binary ({e}).\n  Remove manually: rm \"{}\"",
                            exe.display()
                        ));
                    }
                }
            }
        }
        Err(e) => {
            output::note(&format!("Could not determine binary path ({e})"));
        }
    }

    Ok(())
}

/// Revoke the API token on the server, if one exists locally.
async fn revoke_token_for_uninstall() -> Result<()> {
    let cfg = config::CliConfig::load().await?;
    let token = match resolve_cli_auth_token(&cfg) {
        Some(t) => t,
        None => return Ok(()), // No token, nothing to revoke
    };

    let resolved = cfg.resolve_api_url(api_url_override());
    let client = api_client::ApiClient::new(&resolved.url).await?;
    match client
        .revoke_token(&token, Duration::from_secs(API_TIMEOUT_SECS))
        .await
    {
        Ok(()) => {
            output::success("Revoked", "API token on server");
        }
        Err(api_client::AuthenticatedRequestError::Unauthorized) => {
            output::detail("Token was already invalid or expired.");
        }
        Err(err) => {
            output::note(&format!("Could not revoke token on server ({err})"));
        }
    }
    Ok(())
}

/// Disable background monitoring and remove scheduler artifacts.
async fn uninstall_scheduler() -> Result<()> {
    let removed = monitor::uninstall_monitor().await?;
    if removed.removed {
        output::success("Removed", &format!("scheduler ({})", removed.description));
    } else {
        output::detail("Scheduler artifacts were already absent.");
    }
    Ok(())
}

/// Clean ai.cadence.enabled from the current repo and sibling repos.
async fn clean_repo_cadence_config() -> Result<()> {
    let cwd = std::env::current_dir()?;

    // Check if cwd is inside a git repo
    let in_repo = git::repo_root_at(&cwd).await.is_ok();

    if !in_repo {
        output::detail(
            "Not inside a git repo. To clean per-repo config manually:\n  \
             git config --unset ai.cadence.enabled",
        );
        return Ok(());
    }

    let repo_root = git::repo_root_at(&cwd).await?;
    let mut cleaned = 0u32;

    // Clean current repo
    if let Ok(Some(_)) = git::config_get_local_at(&repo_root, "ai.cadence.enabled").await {
        git::config_unset_local_at(&repo_root, "ai.cadence.enabled").await?;
        cleaned += 1;
    }

    // Clean sibling repos under the same parent directory
    if let Some(parent) = repo_root.parent() {
        let mut entries = tokio::fs::read_dir(parent).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path == repo_root || !path.is_dir() {
                continue;
            }
            // Check if it's a git repo with ai.cadence.enabled set
            if let Ok(Some(_)) = git::config_get_local_at(&path, "ai.cadence.enabled").await
                && git::config_unset_local_at(&path, "ai.cadence.enabled")
                    .await
                    .is_ok()
            {
                cleaned += 1;
            }
        }

        if cleaned > 0 {
            output::success(
                "Cleaned",
                &format!(
                    "ai.cadence.enabled from {} repo(s) in {}",
                    cleaned,
                    parent.display()
                ),
            );
        } else {
            output::detail("No repos with ai.cadence.enabled found in sibling directories.");
        }
    }

    Ok(())
}

/// Remove the ~/.cadence/ state directory.
async fn uninstall_state_dir() -> Result<()> {
    let home =
        agents::home_dir().ok_or_else(|| anyhow::anyhow!("could not determine home directory"))?;
    let state_dir = home.join(".cadence");

    if !tokio::fs::try_exists(&state_dir).await.unwrap_or(false) {
        output::detail("State directory already absent.");
        return Ok(());
    }

    tokio::fs::remove_dir_all(&state_dir).await?;
    output::success("Removed", &format!("{}", state_dir.display()));
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn should_run_automatic_current_version_bootstrap(command: &Command) -> bool {
    !matches!(
        command,
        Command::Hook { .. }
            | Command::Install { .. }
            | Command::Uninstall { .. }
            | Command::Monitor {
                command: Some(MonitorCommand::Disable | MonitorCommand::Uninstall)
            }
    )
}

fn automatic_bootstrap_includes_recovery_backfill(command: &Command) -> bool {
    !matches!(command, Command::Backfill { .. })
}

fn uses_monitor_diagnostics_session(command: &Command) -> bool {
    matches!(
        command,
        Command::Monitor {
            command: Some(MonitorCommand::Tick)
        } | Command::Hook {
            hook_command: HookCommand::AutoUpdate
        }
    )
}

async fn install_monitor_diagnostics_session(
    command: &Command,
) -> Option<tracing::DiagnosticsSessionGuard> {
    if !uses_monitor_diagnostics_session(command) {
        return None;
    }

    match tracing::DiagnosticsLogger::new_daily("monitor", MONITOR_LOG_RETENTION_DAYS).await {
        Ok(logger) => Some(tracing::install_global(logger)),
        Err(err) => {
            eprintln!("Warning: monitor diagnostics unavailable: {err:#}");
            None
        }
    }
}

fn activity_lock_purpose_for_command(command: &Command) -> &'static str {
    match command {
        Command::Install { .. } => "install",
        Command::Hook { hook_command } => match hook_command {
            HookCommand::PostCommit => "hook-post-commit",
            HookCommand::AutoUpdate => "hook-auto-update",
            HookCommand::RefreshHooks => "hook-refresh-hooks",
        },
        Command::Backfill { .. } => "backfill",
        Command::Login => "login",
        Command::Logout => "logout",
        Command::Status => "status",
        Command::Monitor { .. } => "monitor",
        Command::Config { .. } => "config",
        Command::Doctor { .. } => "doctor",
        Command::Update { check, .. } => {
            if *check {
                "update-check"
            } else {
                "update"
            }
        }
        Command::AutoUpdate { .. } => "auto-update",
        Command::Uninstall { .. } => "uninstall",
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cli = Cli::parse();
    output::set_verbose(cli.verbose);
    if let Some(url) = cli.api_url.clone() {
        let _ = API_URL_OVERRIDE.set(url);
    }
    let _activity_lock = match update::acquire_command_activity_lock(
        activity_lock_purpose_for_command(&cli.command),
    )
    .await
    {
        Ok(lock) => lock,
        Err(err) => {
            report_error(&err);
            process::exit(1);
        }
    };
    let use_monitor_diagnostics = uses_monitor_diagnostics_session(&cli.command);
    let monitor_diagnostics_command = if use_monitor_diagnostics {
        Some(format!("{:?}", &cli.command))
    } else {
        None
    };
    let _monitor_diagnostics = install_monitor_diagnostics_session(&cli.command).await;

    let is_update_command = matches!(&cli.command, Command::Update { .. });
    let is_hook_command = matches!(&cli.command, Command::Hook { .. });
    let is_monitor_tick_command = matches!(
        &cli.command,
        Command::Monitor {
            command: Some(MonitorCommand::Tick)
        }
    );
    if should_run_automatic_current_version_bootstrap(&cli.command)
        && let Err(err) = bootstrap::maybe_run_current_version_bootstrap(
            automatic_bootstrap_includes_recovery_backfill(&cli.command),
        )
        .await
    {
        if use_monitor_diagnostics {
            ::tracing::warn!(
                event = "automatic_runtime_bootstrap_failed",
                error = %format!("{err:#}")
            );
        }
        eprintln!("Warning: automatic runtime bootstrap did not complete: {err:#}");
        eprintln!(
            "Run `cadence install` to reconcile background monitoring and clean up legacy Cadence hook ownership."
        );
    }

    let result = match cli.command {
        Command::Install {
            org,
            preserve_disable_state,
        } => run_install(org, preserve_disable_state).await,
        Command::Hook { hook_command } => match hook_command {
            HookCommand::PostCommit => run_hook_post_commit().await,
            HookCommand::AutoUpdate => run_monitor_tick(false).await,
            HookCommand::RefreshHooks => run_refresh_hooks().await,
        },
        Command::Backfill { since } => run_backfill(&since).await,
        Command::Login => run_login().await,
        Command::Logout => run_logout().await,
        Command::Status => run_status().await,
        Command::Monitor { command } => run_monitor(command).await,
        Command::Config { config_command } => match config_command.unwrap_or(ConfigCommand::List) {
            ConfigCommand::Set { key, value } => run_config_set(&key, &value).await,
            ConfigCommand::Get { key } => run_config_get(&key).await,
            ConfigCommand::List => run_config_list().await,
        },
        Command::Doctor { repair } => run_doctor(repair).await,
        Command::Update { check, yes } => match update::run_update(check, yes).await {
            Ok(update::UpdateCommandStatus::Completed) => Ok(()),
            Ok(update::UpdateCommandStatus::HandoffPending) => {
                process::exit(update::UPDATE_HELPER_PENDING_EXIT_CODE);
            }
            Err(err) => Err(err),
        },
        Command::AutoUpdate { command } => run_auto_update(command).await,
        Command::Uninstall { yes } => run_uninstall(yes).await,
    };

    // Passive background version check: run after successful command execution
    // on all non-Update commands. Failures are silently ignored.
    if result.is_ok() && !is_update_command && !is_hook_command && !is_monitor_tick_command {
        update::passive_version_check().await;
    }

    if let Err(e) = result {
        if use_monitor_diagnostics {
            ::tracing::error!(
                event = "background_command_failed",
                command = monitor_diagnostics_command.as_deref().unwrap_or("unknown"),
                error = %format!("{e:#}")
            );
        }
        report_error(&e);
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::EnvGuard;
    use anyhow::anyhow;
    use serde_json::Value;
    use serial_test::serial;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};

    async fn run_git(repo: &std::path::Path, args: &[&str]) -> String {
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

    struct DiscoveryTestEnv {
        _home: EnvGuard,
        _userprofile: EnvGuard,
        _homedrive: EnvGuard,
        _homepath: EnvGuard,
        _appdata: EnvGuard,
        _localappdata: EnvGuard,
        codex_home: EnvGuard,
        _xdg_config_home: EnvGuard,
        _xdg_data_home: EnvGuard,
    }

    impl DiscoveryTestEnv {
        fn install(home: &Path) -> Self {
            let home_guard = EnvGuard::new("HOME");
            home_guard.set_path(home);

            let userprofile_guard = EnvGuard::new("USERPROFILE");
            userprofile_guard.set_path(home);

            let homedrive_guard = EnvGuard::new("HOMEDRIVE");
            homedrive_guard.clear();

            let homepath_guard = EnvGuard::new("HOMEPATH");
            homepath_guard.clear();

            let appdata_guard = EnvGuard::new("APPDATA");
            appdata_guard.set_path(&home.join("AppData").join("Roaming"));

            let localappdata_guard = EnvGuard::new("LOCALAPPDATA");
            localappdata_guard.set_path(&home.join("AppData").join("Local"));

            let codex_home_guard = EnvGuard::new("CODEX_HOME");
            codex_home_guard.clear();

            let xdg_config_home_guard = EnvGuard::new("XDG_CONFIG_HOME");
            xdg_config_home_guard.set_path(&home.join(".config"));

            let xdg_data_home_guard = EnvGuard::new("XDG_DATA_HOME");
            xdg_data_home_guard.set_path(&home.join(".local").join("share"));

            Self {
                _home: home_guard,
                _userprofile: userprofile_guard,
                _homedrive: homedrive_guard,
                _homepath: homepath_guard,
                _appdata: appdata_guard,
                _localappdata: localappdata_guard,
                codex_home: codex_home_guard,
                _xdg_config_home: xdg_config_home_guard,
                _xdg_data_home: xdg_data_home_guard,
            }
        }
    }

    async fn read_jsonl(path: &std::path::Path) -> Vec<Value> {
        let content = tokio::fs::read_to_string(path).await.expect("read jsonl");
        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("json row"))
            .collect()
    }

    fn output_string(buf: Vec<u8>) -> String {
        String::from_utf8(buf).expect("utf8 output")
    }

    fn current_unix_epoch() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("current unix epoch")
            .as_secs() as i64
    }

    fn encode_cursor_workspace_key_for_tests(path: &Path) -> String {
        use std::path::Component;

        let mut encoded = String::new();
        for component in path.components() {
            match component {
                Component::Prefix(prefix) => {
                    let raw = prefix.as_os_str().to_string_lossy();
                    if let Some(drive) = raw.strip_suffix(':') {
                        encoded.push_str(drive);
                        encoded.push_str("--");
                    } else if !raw.is_empty() {
                        if !encoded.is_empty() && !encoded.ends_with('-') {
                            encoded.push('-');
                        }
                        encoded.push_str(&raw.replace(['/', '\\', ':'], "-"));
                    }
                }
                Component::RootDir => {}
                Component::Normal(segment) => {
                    let segment = segment.to_string_lossy();
                    if segment.is_empty() {
                        continue;
                    }
                    if !encoded.is_empty() && !encoded.ends_with('-') {
                        encoded.push('-');
                    }
                    encoded.push_str(&segment);
                }
                Component::CurDir | Component::ParentDir => {}
            }
        }
        encoded
    }

    fn occurrence_count(haystack: &str, needle: &str) -> usize {
        haystack.matches(needle).count()
    }

    fn event_names(rows: &[Value]) -> Vec<String> {
        rows.iter()
            .filter_map(|row| {
                row.pointer("/fields/event")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
            .collect()
    }

    fn sample_inline_session(
        repo_root: &std::path::Path,
        label: &str,
        session_id: &str,
    ) -> SessionInfo {
        let content = serde_json::json!({
            "sessionId": session_id,
            "cwd": repo_root.to_string_lossy().to_string(),
            "message": "hello",
        })
        .to_string()
            + "\n";
        let mut metadata = scanner::parse_session_metadata_str(&content);
        metadata.cwd = Some(repo_root.to_string_lossy().to_string());
        metadata.session_id = Some(session_id.to_string());
        metadata.agent_type = Some(scanner::AgentType::Claude);

        SessionInfo {
            log: agents::SessionLog {
                agent_type: scanner::AgentType::Claude,
                source: agents::SessionSource::Inline {
                    label: label.to_string(),
                    content,
                },
                updated_at: Some(1_707_526_800),
            },
            session_id: session_id.to_string(),
            repo_root: repo_root.to_path_buf(),
            metadata,
        }
    }

    fn sample_observed_upload(
        repo_root: &std::path::Path,
        session_id: &str,
        content: &str,
    ) -> upload::ObservedSessionUpload {
        upload::ObservedSessionUpload {
            logical_session: publication::LogicalSessionKey {
                agent: "claude".to_string(),
                agent_session_id: session_id.to_string(),
            },
            observations: publication::PublicationObservations {
                canonical_remote_url: "git@github.com:test-org/example.git".to_string(),
                remote_urls: vec!["git@github.com:test-org/example.git".to_string()],
                canonical_repo_root: repo_root.to_string_lossy().to_string(),
                worktree_roots: vec![repo_root.to_string_lossy().to_string()],
                cwd: Some(repo_root.to_string_lossy().to_string()),
                git_ref: Some("refs/heads/main".to_string()),
                head_commit_sha: Some("abc1234".to_string()),
                git_user_email: Some("dev@example.com".to_string()),
                git_user_name: Some("Dev".to_string()),
                cli_version: Some("1.0.0".to_string()),
            },
            raw_session_content: content.to_string(),
        }
    }

    async fn write_codex_session_log(
        home: &std::path::Path,
        session_id: &str,
        cwd: &std::path::Path,
        updated_at: i64,
    ) -> PathBuf {
        let dir = home
            .join(".codex")
            .join("sessions")
            .join("2026")
            .join("03")
            .join("24");
        tokio::fs::create_dir_all(&dir)
            .await
            .expect("create codex session dir");
        let path = dir.join(format!("{session_id}.jsonl"));
        let content = serde_json::json!({
            "type": "session_meta",
            "payload": {
                "id": session_id,
                "cwd": cwd.to_string_lossy().to_string(),
            }
        })
        .to_string()
            + "\n";
        tokio::fs::write(&path, content)
            .await
            .expect("write codex session log");
        filetime::set_file_mtime(&path, filetime::FileTime::from_unix_time(updated_at, 0))
            .expect("set codex session mtime");
        path
    }

    async fn write_cursor_agent_transcript(
        home: &Path,
        workspace_key: &str,
        session_id: &str,
        body: &str,
        updated_at: i64,
    ) -> PathBuf {
        let path = home
            .join(".cursor")
            .join("projects")
            .join(workspace_key)
            .join("agent-transcripts")
            .join(session_id)
            .join(format!("{session_id}.jsonl"));
        tokio::fs::create_dir_all(path.parent().expect("parent"))
            .await
            .expect("create cursor transcript dir");
        tokio::fs::write(&path, body)
            .await
            .expect("write cursor transcript");
        filetime::set_file_mtime(&path, filetime::FileTime::from_unix_time(updated_at, 0))
            .expect("set cursor transcript mtime");
        path
    }

    async fn write_cursor_project_noise(home: &Path, workspace_key: &str) {
        for relative in [
            PathBuf::from("agent-tools/tool-output.txt"),
            PathBuf::from("terminals/1.txt"),
            PathBuf::from("mcps/example/tools/tool.json"),
        ] {
            let path = home
                .join(".cursor")
                .join("projects")
                .join(workspace_key)
                .join(relative);
            tokio::fs::create_dir_all(path.parent().expect("noise parent"))
                .await
                .expect("create cursor noise dir");
            tokio::fs::write(&path, "noise")
                .await
                .expect("write cursor noise file");
        }
    }

    fn create_cursor_state_db(path: &Path) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(path).expect("open cursor state db");
        conn.execute_batch(
            "CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB);
             CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB);",
        )
        .expect("create cursor state schema");
        conn
    }

    async fn write_cursor_desktop_session(
        home: &Path,
        workspace_id: &str,
        composer_id: &str,
        repo_root: &Path,
        updated_at_ms: i64,
        user_text: &str,
        assistant_text: &str,
    ) {
        let global_dir = agents::app_config_dir_in("Cursor", home)
            .join("User")
            .join("globalStorage");
        tokio::fs::create_dir_all(&global_dir)
            .await
            .expect("create cursor global storage dir");
        let global_db_path = global_dir.join("state.vscdb");
        let global = create_cursor_state_db(&global_db_path);
        global
            .execute(
                "INSERT INTO cursorDiskKV (key, value) VALUES (?1, ?2)",
                rusqlite::params![
                    format!("composerData:{composer_id}"),
                    serde_json::json!({
                        "composerId": composer_id,
                        "createdAt": updated_at_ms - 5_000,
                        "lastUpdatedAt": updated_at_ms,
                        "modelConfig": { "modelName": "claude-opus-4.1" },
                        "fullConversationHeadersOnly": [
                            { "bubbleId": "bubble-user", "type": 1 },
                            { "bubbleId": "bubble-assistant", "type": 2 }
                        ]
                    })
                    .to_string()
                ],
            )
            .expect("insert cursor composer");
        global
            .execute(
                "INSERT INTO cursorDiskKV (key, value) VALUES (?1, ?2)",
                rusqlite::params![
                    format!("bubbleId:{composer_id}:bubble-user"),
                    serde_json::json!({
                        "type": 1,
                        "text": user_text,
                        "createdAt": "2026-04-01T22:42:55.658Z",
                        "modelInfo": { "modelName": "claude-opus-4.1" }
                    })
                    .to_string()
                ],
            )
            .expect("insert cursor user bubble");
        global
            .execute(
                "INSERT INTO cursorDiskKV (key, value) VALUES (?1, ?2)",
                rusqlite::params![
                    format!("bubbleId:{composer_id}:bubble-assistant"),
                    serde_json::json!({
                        "type": 2,
                        "markdown": assistant_text,
                        "createdAt": "2026-04-01T22:42:57.468Z"
                    })
                    .to_string()
                ],
            )
            .expect("insert cursor assistant bubble");

        let workspace_dir = agents::app_config_dir_in("Cursor", home)
            .join("User")
            .join("workspaceStorage")
            .join(workspace_id);
        tokio::fs::create_dir_all(&workspace_dir)
            .await
            .expect("create cursor workspace dir");
        tokio::fs::write(
            workspace_dir.join("workspace.json"),
            serde_json::json!({
                "folder": format!("file://{}", repo_root.to_string_lossy())
            })
            .to_string(),
        )
        .await
        .expect("write cursor workspace json");
        let workspace = create_cursor_state_db(&workspace_dir.join("state.vscdb"));
        workspace
            .execute(
                "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)",
                rusqlite::params![
                    "composer.composerData",
                    serde_json::json!({
                        "allComposers": [{
                            "composerId": composer_id,
                            "lastUpdatedAt": updated_at_ms,
                            "createdAt": updated_at_ms - 5_000,
                        }]
                    })
                    .to_string()
                ],
            )
            .expect("insert cursor workspace composer");
    }

    fn create_warp_fixture_db(path: &Path) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(path).expect("open warp fixture db");
        conn.execute_batch(
            "CREATE TABLE ai_queries (
                exchange_id TEXT,
                conversation_id TEXT,
                start_ts INTEGER,
                input TEXT,
                working_directory TEXT,
                output_status TEXT,
                model_id TEXT,
                planning_model_id TEXT,
                coding_model_id TEXT
            );
            CREATE TABLE agent_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                task BLOB NOT NULL,
                last_modified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE blocks (
                ai_metadata TEXT,
                pwd TEXT
            );
            CREATE TABLE agent_conversations (
                conversation_id TEXT,
                conversation_data TEXT
            );",
        )
        .expect("create warp fixture schema");
        conn
    }

    #[test]
    fn cli_parses_login_command() {
        let cli = Cli::parse_from(["cadence", "login"]);
        assert!(matches!(cli.command, Command::Login));
    }

    #[test]
    fn cli_parses_logout_command() {
        let cli = Cli::parse_from(["cadence", "logout"]);
        assert!(matches!(cli.command, Command::Logout));
    }

    #[test]
    fn cli_parses_backfill_command() {
        let cli = Cli::parse_from(["cadence", "backfill", "--since", "30d"]);
        match cli.command {
            Command::Backfill { since } => {
                assert_eq!(since, "30d");
            }
            _ => panic!("expected Backfill command"),
        }
    }

    // -----------------------------------------------------------------------
    // Update command parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn cli_parses_update_defaults() {
        let cli = Cli::parse_from(["cadence", "update"]);
        match cli.command {
            Command::Update { check, yes } => {
                assert!(!check);
                assert!(!yes);
            }
            _ => panic!("expected Update command"),
        }
    }

    #[test]
    fn cli_parses_update_check() {
        let cli = Cli::parse_from(["cadence", "update", "--check"]);
        match cli.command {
            Command::Update { check, yes } => {
                assert!(check);
                assert!(!yes);
            }
            _ => panic!("expected Update command"),
        }
    }

    #[test]
    fn cli_parses_update_yes_long() {
        let cli = Cli::parse_from(["cadence", "update", "--yes"]);
        match cli.command {
            Command::Update { check, yes } => {
                assert!(!check);
                assert!(yes);
            }
            _ => panic!("expected Update command"),
        }
    }

    #[test]
    fn cli_parses_update_yes_short() {
        let cli = Cli::parse_from(["cadence", "update", "-y"]);
        match cli.command {
            Command::Update { check, yes } => {
                assert!(!check);
                assert!(yes);
            }
            _ => panic!("expected Update command"),
        }
    }

    #[test]
    fn cli_parses_update_check_and_yes() {
        let cli = Cli::parse_from(["cadence", "update", "--check", "--yes"]);
        match cli.command {
            Command::Update { check, yes } => {
                assert!(check);
                assert!(yes);
            }
            _ => panic!("expected Update command"),
        }
    }

    #[test]
    fn cli_parses_update_check_and_short_yes() {
        let cli = Cli::parse_from(["cadence", "update", "--check", "-y"]);
        match cli.command {
            Command::Update { check, yes } => {
                assert!(check);
                assert!(yes);
            }
            _ => panic!("expected Update command"),
        }
    }

    // -----------------------------------------------------------------------
    // Config command parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn cli_parses_config_set() {
        let cli = Cli::parse_from(["cadence", "config", "set", "update_check_interval", "24h"]);
        match cli.command {
            Command::Config { config_command } => match config_command {
                Some(ConfigCommand::Set { key, value }) => {
                    assert_eq!(key, "update_check_interval");
                    assert_eq!(value, "24h");
                }
                other => panic!("expected Config Set, got {:?}", other),
            },
            other => panic!("expected Config command, got {:?}", other),
        }
    }

    #[test]
    fn cli_parses_doctor() {
        let cli = Cli::parse_from(["cadence", "doctor"]);
        match cli.command {
            Command::Doctor { repair } => {
                assert!(!repair);
            }
            _ => panic!("expected Doctor command"),
        }
    }

    #[test]
    fn cli_parses_doctor_repair() {
        let cli = Cli::parse_from(["cadence", "doctor", "--repair"]);
        match cli.command {
            Command::Doctor { repair } => {
                assert!(repair);
            }
            _ => panic!("expected Doctor command"),
        }
    }

    #[test]
    fn cli_parses_auto_update_default_status() {
        let cli = Cli::parse_from(["cadence", "auto-update"]);
        match cli.command {
            Command::AutoUpdate { command } => {
                assert!(command.is_none());
            }
            _ => panic!("expected AutoUpdate command"),
        }
    }

    #[test]
    fn cli_parses_auto_update_disable() {
        let cli = Cli::parse_from(["cadence", "auto-update", "disable"]);
        match cli.command {
            Command::AutoUpdate { command } => {
                assert!(matches!(command, Some(AutoUpdateCommand::Disable)));
            }
            _ => panic!("expected AutoUpdate command"),
        }
    }

    #[test]
    fn cli_parses_auto_update_uninstall() {
        let cli = Cli::parse_from(["cadence", "auto-update", "uninstall"]);
        match cli.command {
            Command::AutoUpdate { command } => {
                assert!(matches!(command, Some(AutoUpdateCommand::Uninstall)));
            }
            _ => panic!("expected AutoUpdate command"),
        }
    }

    #[test]
    fn cli_parses_monitor_default_status() {
        let cli = Cli::parse_from(["cadence", "monitor"]);
        match cli.command {
            Command::Monitor { command } => {
                assert!(command.is_none());
            }
            _ => panic!("expected Monitor command"),
        }
    }

    #[test]
    fn cli_parses_monitor_enable() {
        let cli = Cli::parse_from(["cadence", "monitor", "enable"]);
        match cli.command {
            Command::Monitor { command } => {
                assert!(matches!(command, Some(MonitorCommand::Enable)));
            }
            _ => panic!("expected Monitor command"),
        }
    }

    #[test]
    fn cli_parses_monitor_uninstall() {
        let cli = Cli::parse_from(["cadence", "monitor", "uninstall"]);
        match cli.command {
            Command::Monitor { command } => {
                assert!(matches!(command, Some(MonitorCommand::Uninstall)));
            }
            _ => panic!("expected Monitor command"),
        }
    }

    #[test]
    fn automatic_bootstrap_runs_for_monitor_tick_and_status_commands() {
        let tick = Command::Monitor {
            command: Some(MonitorCommand::Tick),
        };
        let status = Command::Monitor {
            command: Some(MonitorCommand::Status),
        };

        assert!(should_run_automatic_current_version_bootstrap(&tick));
        assert!(should_run_automatic_current_version_bootstrap(&status));
        assert!(automatic_bootstrap_includes_recovery_backfill(&tick));
    }

    #[test]
    fn automatic_bootstrap_skips_disable_uninstall_and_backfill_recovery() {
        let disable = Command::Monitor {
            command: Some(MonitorCommand::Disable),
        };
        let uninstall = Command::Monitor {
            command: Some(MonitorCommand::Uninstall),
        };
        let backfill = Command::Backfill {
            since: "7d".to_string(),
        };

        assert!(!should_run_automatic_current_version_bootstrap(&disable));
        assert!(!should_run_automatic_current_version_bootstrap(&uninstall));
        assert!(!automatic_bootstrap_includes_recovery_backfill(&backfill));
    }

    #[test]
    fn doctor_repair_defaults_to_enabled_when_monitor_state_is_unreadable() {
        let (enabled, defaulted) =
            desired_monitor_enabled_for_repair(Err(anyhow::anyhow!("corrupt state")));
        assert!(enabled);
        assert!(defaulted);
    }

    #[test]
    fn doctor_repair_rewrites_unreadable_state_with_enabled_default() {
        let repaired =
            repaired_monitor_state_for_enabled(true, Err(anyhow::anyhow!("corrupt state")));
        assert!(repaired.enabled);
        assert_eq!(repaired.last_run_at, None);
    }

    #[test]
    fn monitor_diagnostics_sessions_only_wrap_hidden_runtime_commands() {
        let tick = Command::Monitor {
            command: Some(MonitorCommand::Tick),
        };
        let compatibility = Command::Hook {
            hook_command: HookCommand::AutoUpdate,
        };
        let status = Command::Monitor {
            command: Some(MonitorCommand::Status),
        };

        assert!(uses_monitor_diagnostics_session(&tick));
        assert!(uses_monitor_diagnostics_session(&compatibility));
        assert!(!uses_monitor_diagnostics_session(&status));
    }

    #[test]
    fn cli_parses_hidden_hook_auto_update() {
        let cli = Cli::parse_from(["cadence", "hook", "auto-update"]);
        match cli.command {
            Command::Hook { hook_command } => {
                assert!(matches!(hook_command, HookCommand::AutoUpdate));
            }
            _ => panic!("expected Hook command"),
        }
    }

    #[test]
    fn cli_parses_hidden_hook_refresh_hooks() {
        let cli = Cli::parse_from(["cadence", "hook", "refresh-hooks"]);
        match cli.command {
            Command::Hook { hook_command } => {
                assert!(matches!(hook_command, HookCommand::RefreshHooks));
            }
            _ => panic!("expected Hook command"),
        }
    }

    #[tokio::test]
    async fn hook_post_commit_is_a_success_no_op() {
        run_hook_post_commit()
            .await
            .expect("post-commit compatibility hook should no-op successfully");
    }

    #[test]
    fn error_chain_messages_include_context_and_root_cause() {
        let err = anyhow!("root cause")
            .context("mid context")
            .context("top context");

        assert_eq!(
            error_chain_messages(&err),
            vec![
                "top context".to_string(),
                "mid context".to_string(),
                "root cause".to_string()
            ]
        );
    }

    #[test]
    fn error_chain_messages_skip_adjacent_duplicates() {
        let err = anyhow!("same").context("same");

        assert_eq!(error_chain_messages(&err), vec!["same".to_string()]);
    }

    #[test]
    fn cli_rejects_removed_keys_command() {
        let err = Cli::try_parse_from(["cadence", "keys"]).expect_err("keys should be removed");
        assert!(err.to_string().contains("unrecognized subcommand"));
    }

    #[test]
    fn cli_rejects_removed_sessions_command() {
        let err =
            Cli::try_parse_from(["cadence", "sessions"]).expect_err("sessions should be removed");
        assert!(err.to_string().contains("unrecognized subcommand"));
    }

    #[test]
    fn cli_rejects_removed_gc_command() {
        let err = Cli::try_parse_from(["cadence", "gc"]).expect_err("gc should be removed");
        assert!(err.to_string().contains("unrecognized subcommand"));
    }

    #[test]
    fn cli_rejects_removed_pre_push_hook_command() {
        let err = Cli::try_parse_from(["cadence", "hook", "pre-push", "origin", "git@example"])
            .expect_err("pre-push hook should be removed");
        assert!(err.to_string().contains("unrecognized subcommand"));
    }

    #[test]
    fn cli_parses_config_get() {
        let cli = Cli::parse_from(["cadence", "config", "get", "update_check_interval"]);
        match cli.command {
            Command::Config { config_command } => match config_command {
                Some(ConfigCommand::Get { key }) => {
                    assert_eq!(key, "update_check_interval");
                }
                other => panic!("expected Config Get, got {:?}", other),
            },
            other => panic!("expected Config command, got {:?}", other),
        }
    }

    #[test]
    fn cli_parses_config_list() {
        let cli = Cli::parse_from(["cadence", "config", "list"]);
        match cli.command {
            Command::Config { config_command } => {
                assert!(matches!(config_command, Some(ConfigCommand::List)));
            }
            other => panic!("expected Config command, got {:?}", other),
        }
    }

    #[test]
    fn cli_parses_bare_config_defaults_to_none() {
        let cli = Cli::parse_from(["cadence", "config"]);
        match cli.command {
            Command::Config { config_command } => {
                assert!(config_command.is_none());
            }
            other => panic!("expected Config command, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn resolve_hooks_path_uses_repo_root_for_relative_paths() {
        let repo = TempDir::new().expect("tempdir");
        let resolved = bootstrap::resolve_hooks_path(Some(repo.path()), ".git/hooks");
        assert_eq!(resolved, repo.path().join(".git/hooks"));
    }

    #[tokio::test]
    async fn paths_equivalent_matches_relative_and_absolute_same_target() {
        let repo = TempDir::new().expect("tempdir");
        let hooks_dir = repo.path().join(".git/hooks");
        tokio::fs::create_dir_all(&hooks_dir)
            .await
            .expect("create hooks dir");

        let absolute = hooks_dir.clone();
        let relative = repo.path().join(".git/./hooks");
        assert!(bootstrap::paths_equivalent(&absolute, &relative));
    }

    #[tokio::test]
    #[serial]
    async fn cleanup_cadence_hook_ownership_removes_managed_hooks() {
        let home = TempDir::new().expect("home tempdir");
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(home.path());

        let global_config = home.path().join("global.gitconfig");
        tokio::fs::write(&global_config, "")
            .await
            .expect("write empty global gitconfig");
        let global_guard = EnvGuard::new("GIT_CONFIG_GLOBAL");
        global_guard.set_path(&global_config);
        crate::git::config_set_global("ai.cadence.org", "test-org")
            .await
            .expect("set org filter");

        let hooks_dir = home.path().join(".git-hooks");
        tokio::fs::create_dir_all(&hooks_dir)
            .await
            .expect("create hooks dir");
        crate::git::config_set_global("core.hooksPath", &hooks_dir.to_string_lossy())
            .await
            .expect("set core.hooksPath");
        tokio::fs::write(
            hooks_dir.join("post-commit"),
            "#!/bin/sh\nexec cadence hook post-commit\n",
        )
        .await
        .expect("seed cadence post-commit hook");
        tokio::fs::write(
            hooks_dir.join("pre-push"),
            "#!/bin/sh\nexec cadence hook pre-push\n",
        )
        .await
        .expect("seed legacy pre-push hook");

        let had_errors = bootstrap::cleanup_cadence_hook_ownership(Some(home.path()), false)
            .await
            .expect("cleanup hook ownership");
        assert!(!had_errors);

        assert!(
            !hooks_dir.exists(),
            "expected managed hooks directory to be removed"
        );

        let configured_hooks_path = crate::git::config_get_global("core.hooksPath")
            .await
            .expect("read core.hooksPath");
        assert!(configured_hooks_path.is_none());
    }

    #[test]
    fn monitor_default_cursor_window_defaults_are_stable() {
        assert_eq!(MONITOR_DEFAULT_CURSOR_WINDOW_SECS, 30 * 86_400);
        assert_eq!(MONITOR_DISCOVERY_LOOKBACK_SECS, 300);
    }

    #[test]
    fn selection_cursor_with_lookback_rewinds_mtime_and_clears_label() {
        let rewound = selection_cursor_with_lookback(&IncrementalCursor {
            last_scanned_mtime_epoch: 500,
            last_scanned_source_label: Some("session-z".to_string()),
        });

        assert_eq!(rewound.last_scanned_mtime_epoch, 200);
        assert_eq!(rewound.last_scanned_source_label, None);
    }

    #[test]
    fn anonymized_backfill_fixture_contains_expected_failure_modes() {
        let csv = include_str!("../tests/fixtures/backfill/anonymized_report.csv");
        let mut missing_meta = 0usize;
        for line in csv.lines().skip(1) {
            if line.contains("missing_session_metadata") {
                missing_meta += 1;
            }
        }
        assert_eq!(missing_meta, 1);
    }

    #[test]
    fn cursor_advances_for_indexed_logs() {
        let updated = advance_cursor_for_disposition(
            &IncrementalCursor {
                last_scanned_mtime_epoch: 100,
                last_scanned_source_label: Some("a".to_string()),
            },
            Some(150),
            "b",
        );
        assert_eq!(updated.last_scanned_mtime_epoch, 150);
        assert_eq!(updated.last_scanned_source_label.as_deref(), Some("b"));
    }

    #[test]
    fn cursor_advances_for_permanent_skips() {
        let updated = advance_cursor_for_disposition(
            &IncrementalCursor {
                last_scanned_mtime_epoch: 100,
                last_scanned_source_label: Some("a".to_string()),
            },
            Some(140),
            "c",
        );
        assert_eq!(updated.last_scanned_mtime_epoch, 140);
        assert_eq!(updated.last_scanned_source_label.as_deref(), Some("c"));
    }

    #[test]
    fn cursor_uses_source_label_to_track_same_mtime_progress() {
        let updated = advance_cursor_for_disposition(
            &IncrementalCursor {
                last_scanned_mtime_epoch: 100,
                last_scanned_source_label: Some("a".to_string()),
            },
            Some(100),
            "c",
        );
        assert_eq!(updated.last_scanned_mtime_epoch, 100);
        assert_eq!(updated.last_scanned_source_label.as_deref(), Some("c"));
    }

    #[test]
    fn select_incremental_candidates_orders_and_caps() {
        let cursor = IncrementalCursor {
            last_scanned_mtime_epoch: 100,
            last_scanned_source_label: Some("a".to_string()),
        };
        let candidates = select_incremental_candidates(
            vec![
                agents::SessionLog {
                    agent_type: scanner::AgentType::Codex,
                    source: agents::SessionSource::Inline {
                        label: "c".to_string(),
                        content: "{}".to_string(),
                    },
                    updated_at: Some(110),
                },
                agents::SessionLog {
                    agent_type: scanner::AgentType::Codex,
                    source: agents::SessionSource::Inline {
                        label: "b".to_string(),
                        content: "{}".to_string(),
                    },
                    updated_at: Some(100),
                },
                agents::SessionLog {
                    agent_type: scanner::AgentType::Codex,
                    source: agents::SessionSource::Inline {
                        label: "d".to_string(),
                        content: "{}".to_string(),
                    },
                    updated_at: Some(110),
                },
            ],
            &cursor,
            2,
        );
        let labels: Vec<_> = candidates
            .into_iter()
            .map(|log| log.source_label())
            .collect();
        assert_eq!(labels, vec!["b".to_string(), "c".to_string()]);
    }

    #[tokio::test]
    #[serial]
    async fn upload_incremental_sessions_globally_advances_discovery_cursor_after_success() {
        let home = TempDir::new().expect("home tempdir");
        let env = DiscoveryTestEnv::install(home.path());
        env.codex_home.set_path(&home.path().join(".codex"));

        let global_config = home.path().join("global.gitconfig");
        tokio::fs::write(&global_config, "")
            .await
            .expect("write empty global gitconfig");
        let global_guard = EnvGuard::new("GIT_CONFIG_GLOBAL");
        global_guard.set_path(&global_config);

        let repo = init_repo().await;
        run_git(
            repo.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:test-org/example.git",
            ],
        )
        .await;

        let session_updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("current epoch")
            .as_secs() as i64;
        let session_path = write_codex_session_log(
            home.path(),
            "session-global-success",
            repo.path(),
            session_updated_at,
        )
        .await;

        let server = crate::upload::test_support::spawn_test_upload_server(
            crate::upload::test_support::TestUploadServerConfig::default(),
        )
        .await
        .expect("spawn upload test server");
        let cfg = config::CliConfig {
            token: Some("test-token".to_string()),
            ..config::CliConfig::default()
        };
        cfg.save().await.expect("save config");

        let upload_context = upload::resolve_upload_context(Some(server.base_url.as_str()))
            .await
            .expect("resolve upload context");
        let summary = upload_incremental_sessions_globally(&upload_context)
            .await
            .expect("upload incremental sessions globally");

        assert_eq!(summary.discovered, 1);
        assert_eq!(summary.uploaded, 1);
        assert_eq!(summary.queued, 0);
        assert_eq!(summary.skipped, 0);
        assert_eq!(summary.issues, 0);

        let cursor = monitor::load_discovery_cursor()
            .await
            .expect("load discovery cursor")
            .expect("cursor record");
        assert_eq!(cursor.last_scanned_mtime_epoch, session_updated_at);
        assert_eq!(
            cursor.last_scanned_source_label.as_deref(),
            Some(session_path.to_string_lossy().as_ref())
        );
        assert_eq!(
            server.counts(),
            crate::upload::test_support::TestUploadServerCounts {
                create_requests: 1,
                uploads: 1,
                confirms: 1,
                user_org_requests: 1,
            }
        );
    }

    #[tokio::test]
    #[serial]
    async fn upload_incremental_sessions_globally_uses_lookback_to_recover_older_sessions() {
        let home = TempDir::new().expect("home tempdir");
        let env = DiscoveryTestEnv::install(home.path());
        env.codex_home.set_path(&home.path().join(".codex"));

        let global_config = home.path().join("global.gitconfig");
        tokio::fs::write(&global_config, "")
            .await
            .expect("write empty global gitconfig");
        let global_guard = EnvGuard::new("GIT_CONFIG_GLOBAL");
        global_guard.set_path(&global_config);

        let repo_a = init_repo().await;
        run_git(
            repo_a.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:test-org/repo-a.git",
            ],
        )
        .await;

        let repo_b = init_repo().await;
        run_git(
            repo_b.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:test-org/repo-b.git",
            ],
        )
        .await;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("current epoch")
            .as_secs() as i64;
        let newer_session_updated_at = now - 60;
        let newer_session_path = write_codex_session_log(
            home.path(),
            "session-repo-b-newer",
            repo_b.path(),
            newer_session_updated_at,
        )
        .await;

        let server = crate::upload::test_support::spawn_test_upload_server(
            crate::upload::test_support::TestUploadServerConfig::default(),
        )
        .await
        .expect("spawn upload test server");
        let cfg = config::CliConfig {
            token: Some("test-token".to_string()),
            ..config::CliConfig::default()
        };
        cfg.save().await.expect("save config");

        let upload_context = upload::resolve_upload_context(Some(server.base_url.as_str()))
            .await
            .expect("resolve upload context");
        let first_summary = upload_incremental_sessions_globally(&upload_context)
            .await
            .expect("first incremental upload");
        assert_eq!(first_summary.uploaded, 1);

        let older_session_updated_at = newer_session_updated_at - 120;
        let older_session_path = write_codex_session_log(
            home.path(),
            "session-repo-a-older",
            repo_a.path(),
            older_session_updated_at,
        )
        .await;

        let second_summary = upload_incremental_sessions_globally(&upload_context)
            .await
            .expect("second incremental upload");

        assert_eq!(second_summary.discovered, 2);
        assert_eq!(second_summary.uploaded, 1);
        assert_eq!(second_summary.skipped, 1);
        assert_eq!(second_summary.queued, 0);
        assert_eq!(second_summary.issues, 0);

        let cursor = monitor::load_discovery_cursor()
            .await
            .expect("load discovery cursor")
            .expect("cursor record");
        assert_eq!(cursor.last_scanned_mtime_epoch, newer_session_updated_at);
        assert_eq!(
            cursor.last_scanned_source_label.as_deref(),
            Some(newer_session_path.to_string_lossy().as_ref())
        );

        let requests = server.create_requests();
        assert_eq!(requests.len(), 2);
        let upload_bodies = server
            .upload_requests()
            .into_iter()
            .map(|request| request.body)
            .collect::<Vec<_>>();
        assert_eq!(upload_bodies.len(), 2);
        assert!(
            upload_bodies
                .iter()
                .any(|body| body.contains("session-repo-a-older"))
        );
        assert!(
            upload_bodies
                .iter()
                .any(|body| body.contains("session-repo-b-newer"))
        );

        let older_label = older_session_path.to_string_lossy().to_string();
        assert_ne!(older_label, newer_session_path.to_string_lossy());
    }

    #[test]
    fn monitor_retryable_incremental_outcome_advances_cursor_without_blocking_followups() {
        let mut stats = MonitorTickSummary::default();
        let mut cursor = IncrementalCursor {
            last_scanned_mtime_epoch: 100,
            last_scanned_source_label: Some("a".to_string()),
        };

        apply_monitor_incremental_upload_outcome(
            &mut stats,
            &mut cursor,
            Some(150),
            "b",
            UploadFromLogOutcome::Retryable("git remote failed".to_string()),
        );

        assert_eq!(stats.issues, 1);
        assert_eq!(cursor.last_scanned_mtime_epoch, 150);
        assert_eq!(cursor.last_scanned_source_label.as_deref(), Some("b"));

        apply_monitor_incremental_upload_outcome(
            &mut stats,
            &mut cursor,
            Some(200),
            "c",
            UploadFromLogOutcome::Uploaded,
        );

        assert_eq!(stats.uploaded, 1);
        assert_eq!(cursor.last_scanned_mtime_epoch, 200);
        assert_eq!(cursor.last_scanned_source_label.as_deref(), Some("c"));
    }

    #[test]
    fn monitor_org_filter_error_advances_cursor() {
        let mut stats = MonitorTickSummary::default();
        let mut cursor = IncrementalCursor {
            last_scanned_mtime_epoch: 100,
            last_scanned_source_label: Some("a".to_string()),
        };

        apply_monitor_org_filter_error(&mut stats, &mut cursor, Some(200), "b");

        assert_eq!(stats.issues, 1);
        assert_eq!(cursor.last_scanned_mtime_epoch, 200);
        assert_eq!(cursor.last_scanned_source_label.as_deref(), Some("b"));
    }

    #[tokio::test]
    #[serial]
    async fn monitor_tick_skips_disabled_runtime_without_writing_state() {
        let home = TempDir::new().expect("home tempdir");
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(home.path());

        let summary = run_monitor_tick_internal(MonitorTickOptions {
            force: false,
            drain_pending: true,
            run_auto_update: false,
        })
        .await
        .expect("monitor tick");

        assert_eq!(summary.discovered, 0);
        assert_eq!(summary.uploaded, 0);
        assert_eq!(summary.queued, 0);
        assert_eq!(summary.skipped, 0);
        assert_eq!(summary.issues, 0);
        assert_eq!(summary.pending_attempted, 0);
        assert_eq!(summary.pending_uploaded, 0);

        let monitor_state_path = config::CliConfig::config_dir_with_home(home.path())
            .expect("config dir")
            .join("monitor-state.json");
        assert!(
            tokio::fs::metadata(&monitor_state_path).await.is_err(),
            "disabled early exit should not create monitor state"
        );
    }

    #[tokio::test]
    #[serial]
    async fn monitor_tick_attempts_legacy_auto_update_cleanup() {
        let home = TempDir::new().expect("home tempdir");
        let _env = DiscoveryTestEnv::install(home.path());
        let _cleanup_hook = update::install_legacy_cleanup_test_hook(Ok(
            update::LegacyAutoUpdateCleanupDisposition::Deferred,
        ));

        let summary = run_monitor_tick_internal(MonitorTickOptions {
            force: true,
            drain_pending: false,
            run_auto_update: false,
        })
        .await
        .expect("monitor tick");

        assert_eq!(summary.discovered, 0);
        assert_eq!(summary.uploaded, 0);
        assert_eq!(summary.queued, 0);
        assert_eq!(summary.skipped, 0);
        assert_eq!(summary.issues, 0);
        assert_eq!(summary.pending_attempted, 0);
        assert_eq!(summary.pending_uploaded, 0);
        assert_eq!(update::legacy_cleanup_test_hook_calls(), 1);
    }

    #[tokio::test]
    #[serial]
    async fn monitor_tick_drains_pending_uploads_and_records_runtime_state() {
        let home = TempDir::new().expect("home tempdir");
        let _env = DiscoveryTestEnv::install(home.path());

        let global_config = home.path().join("global.gitconfig");
        tokio::fs::write(&global_config, "")
            .await
            .expect("write empty global gitconfig");
        let global_guard = EnvGuard::new("GIT_CONFIG_GLOBAL");
        global_guard.set_path(&global_config);

        let api_url_guard = EnvGuard::new("CADENCE_API_URL");

        let prepared = upload::prepare_session_upload(sample_observed_upload(
            Path::new("/tmp/repo"),
            "session-monitor-pending",
            "hello",
        ))
        .expect("prepare session upload");
        let no_token_context = upload::resolve_upload_context(Some("http://127.0.0.1:9"))
            .await
            .expect("context without token");
        let queued = upload::upload_or_queue_prepared_session(&no_token_context, &prepared)
            .await
            .expect("queue upload");
        assert!(matches!(queued, upload::LiveUploadOutcome::Queued { .. }));

        let server = crate::upload::test_support::spawn_test_upload_server(
            crate::upload::test_support::TestUploadServerConfig::default(),
        )
        .await
        .expect("spawn upload test server");
        api_url_guard.set_str(server.base_url.as_str());

        let cfg = config::CliConfig {
            token: Some("test-token".to_string()),
            ..config::CliConfig::default()
        };
        cfg.save().await.expect("save config");

        let summary = run_monitor_tick_internal(MonitorTickOptions {
            force: true,
            drain_pending: true,
            run_auto_update: false,
        })
        .await
        .expect("monitor tick");

        assert_eq!(summary.discovered, 0);
        assert_eq!(summary.pending_attempted, 1);
        assert_eq!(summary.pending_uploaded, 1);
        assert_eq!(
            upload::pending_upload_count().await.expect("pending count"),
            0
        );

        let state = monitor::load_state().await.expect("load monitor state");
        assert_eq!(state.last_pending_attempted, 1);
        assert_eq!(state.last_pending_uploaded, 1);
        assert!(state.last_run_at.is_some());
        assert!(state.last_success_at.is_some());
        assert_eq!(state.last_error, None);
        assert_eq!(
            server.counts(),
            crate::upload::test_support::TestUploadServerCounts {
                create_requests: 1,
                uploads: 1,
                confirms: 1,
                user_org_requests: 1,
            }
        );
    }

    #[tokio::test]
    #[serial]
    async fn monitor_tick_pauses_publication_when_auth_is_rejected() {
        let home = TempDir::new().expect("home tempdir");
        let _env = DiscoveryTestEnv::install(home.path());

        let global_config = home.path().join("global.gitconfig");
        tokio::fs::write(&global_config, "")
            .await
            .expect("write empty global gitconfig");
        let global_guard = EnvGuard::new("GIT_CONFIG_GLOBAL");
        global_guard.set_path(&global_config);

        let api_url_guard = EnvGuard::new("CADENCE_API_URL");

        let prepared = upload::prepare_session_upload(sample_observed_upload(
            Path::new("/tmp/repo"),
            "session-monitor-auth-paused",
            "hello",
        ))
        .expect("prepare session upload");
        let no_token_context = upload::resolve_upload_context(Some("http://127.0.0.1:9"))
            .await
            .expect("context without token");
        let queued = upload::upload_or_queue_prepared_session(&no_token_context, &prepared)
            .await
            .expect("queue upload");
        assert!(matches!(queued, upload::LiveUploadOutcome::Queued { .. }));

        let server = crate::upload::test_support::spawn_test_upload_server(
            crate::upload::test_support::TestUploadServerConfig {
                user_org_statuses: vec![401],
                ..crate::upload::test_support::TestUploadServerConfig::default()
            },
        )
        .await
        .expect("spawn upload test server");
        api_url_guard.set_str(server.base_url.as_str());

        let cfg = config::CliConfig {
            token: Some("test-token".to_string()),
            ..config::CliConfig::default()
        };
        cfg.save().await.expect("save config");

        let summary = run_monitor_tick_internal(MonitorTickOptions {
            force: true,
            drain_pending: true,
            run_auto_update: false,
        })
        .await
        .expect("monitor tick");

        assert_eq!(summary.discovered, 0);
        assert_eq!(summary.uploaded, 0);
        assert_eq!(summary.queued, 0);
        assert_eq!(summary.skipped, 0);
        assert_eq!(summary.issues, 0);
        assert_eq!(summary.pending_attempted, 0);
        assert_eq!(summary.pending_uploaded, 0);
        assert_eq!(
            upload::pending_upload_count().await.expect("pending count"),
            1
        );

        let state = monitor::load_state().await.expect("load monitor state");
        assert!(state.last_run_at.is_some());
        assert!(state.last_success_at.is_some());
        assert_eq!(
            state.last_error.as_deref(),
            Some(
                "Cadence login was rejected by the server; background publishing is paused until you run `cadence login`."
            )
        );
        assert_eq!(
            server.counts(),
            crate::upload::test_support::TestUploadServerCounts {
                create_requests: 0,
                uploads: 0,
                confirms: 0,
                user_org_requests: 1,
            }
        );
    }

    #[tokio::test]
    #[serial]
    async fn monitor_tick_records_completion_timestamp_after_background_update() {
        let home = TempDir::new().expect("home tempdir");
        let _env = DiscoveryTestEnv::install(home.path());
        let api_url_guard = EnvGuard::new("CADENCE_API_URL");
        let _update_hook = update::install_background_auto_update_test_hook(Ok(()), 75);

        let server = crate::upload::test_support::spawn_test_upload_server(
            crate::upload::test_support::TestUploadServerConfig {
                user_org_statuses: vec![401],
                ..crate::upload::test_support::TestUploadServerConfig::default()
            },
        )
        .await
        .expect("spawn upload test server");
        api_url_guard.set_str(server.base_url.as_str());

        let cfg = config::CliConfig {
            token: Some("test-token".to_string()),
            ..config::CliConfig::default()
        };
        cfg.save().await.expect("save config");

        run_monitor_tick_internal(MonitorTickOptions {
            force: true,
            drain_pending: true,
            run_auto_update: true,
        })
        .await
        .expect("monitor tick");

        assert_eq!(update::background_auto_update_test_hook_calls(), 1);

        let state = monitor::load_state().await.expect("load monitor state");
        let last_run =
            OffsetDateTime::parse(state.last_run_at.as_deref().expect("last_run_at"), &Rfc3339)
                .expect("parse last_run_at");
        let last_success = OffsetDateTime::parse(
            state.last_success_at.as_deref().expect("last_success_at"),
            &Rfc3339,
        )
        .expect("parse last_success_at");

        assert!(
            last_success > last_run,
            "expected completion timestamp after run start: run={last_run}, success={last_success}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn status_reports_publication_auth_rejection_once() {
        let home = TempDir::new().expect("home tempdir");
        let _env = DiscoveryTestEnv::install(home.path());
        let api_url_guard = EnvGuard::new("CADENCE_API_URL");

        let server = crate::upload::test_support::spawn_test_upload_server(
            crate::upload::test_support::TestUploadServerConfig {
                user_org_statuses: vec![401],
                ..crate::upload::test_support::TestUploadServerConfig::default()
            },
        )
        .await
        .expect("spawn upload test server");
        api_url_guard.set_str(server.base_url.as_str());

        let cfg = config::CliConfig {
            token: Some("test-token".to_string()),
            ..config::CliConfig::default()
        };
        cfg.save().await.expect("save config");

        let mut output = Vec::new();
        run_status_inner(&mut output).await.expect("run status");
        let rendered = output_string(output);

        assert_eq!(
            occurrence_count(
                &rendered,
                "Publication auth: CLI auth token was rejected by the server"
            ),
            1
        );
        assert!(rendered.contains(
            "Publication auth remediation: Run `cadence login` to restore background publishing."
        ));
        assert_eq!(server.counts().user_org_requests, 1);
    }

    #[tokio::test]
    #[serial]
    async fn monitor_status_reports_publication_auth_rejection() {
        let home = TempDir::new().expect("home tempdir");
        let _env = DiscoveryTestEnv::install(home.path());
        let api_url_guard = EnvGuard::new("CADENCE_API_URL");

        let server = crate::upload::test_support::spawn_test_upload_server(
            crate::upload::test_support::TestUploadServerConfig {
                user_org_statuses: vec![401],
                ..crate::upload::test_support::TestUploadServerConfig::default()
            },
        )
        .await
        .expect("spawn upload test server");
        api_url_guard.set_str(server.base_url.as_str());

        let cfg = config::CliConfig {
            token: Some("test-token".to_string()),
            ..config::CliConfig::default()
        };
        cfg.save().await.expect("save config");

        let mut output = Vec::new();
        write_monitor_status_block(&mut output, true)
            .await
            .expect("write monitor status");
        let rendered = output_string(output);

        assert!(rendered.contains("Publication auth: CLI auth token was rejected by the server"));
        assert!(rendered.contains(
            "Publication auth remediation: Run `cadence login` to restore background publishing."
        ));
        assert_eq!(server.counts().user_org_requests, 1);
    }

    #[tokio::test]
    #[serial]
    async fn doctor_fails_when_publication_auth_is_rejected() {
        let home = TempDir::new().expect("home tempdir");
        let _env = DiscoveryTestEnv::install(home.path());
        let api_url_guard = EnvGuard::new("CADENCE_API_URL");

        let server = crate::upload::test_support::spawn_test_upload_server(
            crate::upload::test_support::TestUploadServerConfig {
                user_org_statuses: vec![401],
                ..crate::upload::test_support::TestUploadServerConfig::default()
            },
        )
        .await
        .expect("spawn upload test server");
        api_url_guard.set_str(server.base_url.as_str());

        let cfg = config::CliConfig {
            token: Some("test-token".to_string()),
            ..config::CliConfig::default()
        };
        cfg.save().await.expect("save config");

        let mut output = Vec::new();
        let err = run_doctor_inner(&mut output, false)
            .await
            .expect_err("doctor should fail");
        let rendered = output_string(output);

        assert!(err.to_string().contains("doctor found"));
        assert!(
            rendered.contains("Fail Publication auth: CLI auth token was rejected by the server")
        );
        assert!(rendered.contains(
            "Publication auth remediation: Run `cadence login` to restore background publishing."
        ));
        assert_eq!(server.counts().user_org_requests, 1);
    }

    #[tokio::test]
    #[serial]
    async fn monitor_enable_disable_round_trip_updates_runtime_intent() {
        let home = TempDir::new().expect("home tempdir");
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(home.path());
        let _hook =
            monitor::install_reconcile_scheduler_test_hook(monitor::SchedulerProvisionResult {
                configured: true,
                description: "test scheduler".to_string(),
            });

        run_monitor_enable().await.expect("enable monitor");
        assert!(
            monitor::load_state()
                .await
                .expect("load enabled state")
                .enabled
        );

        run_monitor_disable().await.expect("disable monitor");
        assert!(
            !monitor::load_state()
                .await
                .expect("load disabled state")
                .enabled
        );

        run_monitor_enable().await.expect("re-enable monitor");
        assert!(
            monitor::load_state()
                .await
                .expect("load re-enabled state")
                .enabled
        );
        assert_eq!(
            monitor::reconcile_scheduler_test_hook_calls(),
            vec![true, true]
        );
    }

    #[tokio::test]
    #[serial]
    async fn process_repo_backfill_uses_direct_upload_pipeline() {
        let home = TempDir::new().expect("home tempdir");
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(home.path());

        let global_config = home.path().join("global.gitconfig");
        tokio::fs::write(&global_config, "")
            .await
            .expect("write empty global gitconfig");
        let global_guard = EnvGuard::new("GIT_CONFIG_GLOBAL");
        global_guard.set_path(&global_config);

        let repo = init_repo().await;
        run_git(
            repo.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:test-org/example.git",
            ],
        )
        .await;

        let server = crate::upload::test_support::spawn_test_upload_server(
            crate::upload::test_support::TestUploadServerConfig::default(),
        )
        .await
        .expect("spawn upload test server");

        let cfg = config::CliConfig {
            token: Some("test-token".to_string()),
            ..config::CliConfig::default()
        };
        cfg.save().await.expect("save config");

        let upload_context = Arc::new(
            upload::resolve_upload_context(Some(server.base_url.as_str()))
                .await
                .expect("resolve upload context"),
        );

        let content =
            include_str!("../tests/fixtures/backfill/session_no_ranked.jsonl").to_string();
        let mut metadata = scanner::parse_session_metadata_str(&content);
        metadata.cwd = Some(repo.path().to_string_lossy().to_string());
        metadata.agent_type = Some(scanner::AgentType::Claude);
        let session_id = metadata
            .session_id
            .clone()
            .unwrap_or_else(|| "backfill-session".to_string());

        let stats = process_repo_backfill(
            "git@github.com:test-org/example.git".to_string(),
            vec![SessionInfo {
                log: agents::SessionLog {
                    agent_type: scanner::AgentType::Claude,
                    source: agents::SessionSource::Inline {
                        label: "fixture.jsonl".to_string(),
                        content,
                    },
                    updated_at: Some(1_707_526_800),
                },
                session_id,
                repo_root: repo.path().to_path_buf(),
                metadata,
            }],
            upload_context,
            None,
        )
        .await;

        assert_eq!(stats.sessions_seen, 1);
        assert_eq!(stats.uploaded, 1);
        assert_eq!(stats.queued, 0);
        assert_eq!(stats.skipped, 0);
        assert_eq!(stats.errors, 0);
        assert_eq!(
            server.counts(),
            crate::upload::test_support::TestUploadServerCounts {
                create_requests: 1,
                uploads: 1,
                confirms: 1,
                user_org_requests: 1,
            }
        );
    }

    #[tokio::test]
    #[serial]
    async fn process_repo_backfill_logs_distinct_skip_reasons() {
        let home = TempDir::new().expect("home tempdir");
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(home.path());

        let global_config = home.path().join("global.gitconfig");
        tokio::fs::write(&global_config, "")
            .await
            .expect("write empty global gitconfig");
        let global_guard = EnvGuard::new("GIT_CONFIG_GLOBAL");
        global_guard.set_path(&global_config);

        let repo = init_repo().await;
        run_git(
            repo.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:test-org/example.git",
            ],
        )
        .await;

        let server = crate::upload::test_support::spawn_test_upload_server(
            crate::upload::test_support::TestUploadServerConfig {
                create_statuses: vec![409, 422],
                ..crate::upload::test_support::TestUploadServerConfig::default()
            },
        )
        .await
        .expect("spawn upload test server");
        let cfg = config::CliConfig {
            token: Some("test-token".to_string()),
            ..config::CliConfig::default()
        };
        cfg.save().await.expect("save config");
        let upload_context = Arc::new(
            upload::resolve_upload_context(Some(server.base_url.as_str()))
                .await
                .expect("resolve upload context"),
        );
        let logger = tracing::DiagnosticsLogger::new_in_dir(
            config::CliConfig::config_dir_with_home(home.path())
                .expect("config dir")
                .as_path(),
            "backfill",
            time::OffsetDateTime::from_unix_timestamp(1_700_000_010).expect("ts"),
        )
        .await
        .expect("create backfill logger");
        let _session = tracing::install_global(logger.clone());

        let stats = process_repo_backfill(
            "git@github.com:test-org/example.git".to_string(),
            vec![
                sample_inline_session(repo.path(), "session-1.jsonl", "session-1"),
                sample_inline_session(repo.path(), "session-2.jsonl", "session-2"),
            ],
            upload_context,
            None,
        )
        .await;
        logger.flush().await;

        assert_eq!(stats.sessions_seen, 2);
        assert_eq!(stats.queued, 2);
        assert_eq!(stats.uploaded, 0);

        let rows = read_jsonl(&logger.path().expect("logger path")).await;
        let names = event_names(&rows);
        assert!(names.contains(&"session_queued".to_string()));
    }

    #[tokio::test]
    #[serial]
    async fn run_backfill_inner_drains_pending_uploads_before_scan() {
        let home = TempDir::new().expect("home tempdir");
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(home.path());

        let global_config = home.path().join("global.gitconfig");
        tokio::fs::write(&global_config, "")
            .await
            .expect("write empty global gitconfig");
        let global_guard = EnvGuard::new("GIT_CONFIG_GLOBAL");
        global_guard.set_path(&global_config);

        let api_url_guard = EnvGuard::new("CADENCE_API_URL");

        let prepared = upload::prepare_session_upload(sample_observed_upload(
            Path::new("/tmp/repo"),
            "session-pending",
            "hello",
        ))
        .expect("prepare session upload");
        let no_token_context = upload::resolve_upload_context(Some("http://127.0.0.1:9"))
            .await
            .expect("context without token");
        let queued = upload::upload_or_queue_prepared_session(&no_token_context, &prepared)
            .await
            .expect("queue upload");
        assert!(matches!(queued, upload::LiveUploadOutcome::Queued { .. }));

        let server = crate::upload::test_support::spawn_test_upload_server(
            crate::upload::test_support::TestUploadServerConfig::default(),
        )
        .await
        .expect("spawn upload test server");
        api_url_guard.set_str(server.base_url.as_str());

        let cfg = config::CliConfig {
            token: Some("test-token".to_string()),
            ..config::CliConfig::default()
        };
        cfg.save().await.expect("save config");

        run_backfill_inner("1d", None).await.expect("run backfill");

        assert_eq!(
            upload::pending_upload_count().await.expect("pending count"),
            0
        );
        assert_eq!(
            server.counts(),
            crate::upload::test_support::TestUploadServerCounts {
                create_requests: 1,
                uploads: 1,
                confirms: 1,
                user_org_requests: 1,
            }
        );

        let config_dir = config::CliConfig::config_dir_with_home(home.path()).expect("config dir");
        let mut entries = tokio::fs::read_dir(&config_dir)
            .await
            .expect("read config dir");
        let mut backfill_log_path = None;
        while let Some(entry) = entries.next_entry().await.expect("dir entry") {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name.starts_with("backfill.") && file_name.ends_with(".log") {
                backfill_log_path = Some(entry.path());
                break;
            }
        }
        let rows = read_jsonl(&backfill_log_path.expect("backfill log path")).await;
        let names = event_names(&rows);
        assert!(names.contains(&"pending_upload_drain_started".to_string()));
        assert!(names.contains(&"pending_upload_drain_completed".to_string()));
    }

    #[tokio::test]
    #[serial]
    async fn run_backfill_inner_fails_fast_when_publication_auth_is_rejected() {
        let home = TempDir::new().expect("home tempdir");
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(home.path());

        let global_config = home.path().join("global.gitconfig");
        tokio::fs::write(&global_config, "")
            .await
            .expect("write empty global gitconfig");
        let global_guard = EnvGuard::new("GIT_CONFIG_GLOBAL");
        global_guard.set_path(&global_config);

        let api_url_guard = EnvGuard::new("CADENCE_API_URL");

        let prepared = upload::prepare_session_upload(sample_observed_upload(
            Path::new("/tmp/repo"),
            "session-pending-auth-rejected",
            "hello",
        ))
        .expect("prepare session upload");
        let no_token_context = upload::resolve_upload_context(Some("http://127.0.0.1:9"))
            .await
            .expect("context without token");
        let queued = upload::upload_or_queue_prepared_session(&no_token_context, &prepared)
            .await
            .expect("queue upload");
        assert!(matches!(queued, upload::LiveUploadOutcome::Queued { .. }));

        let server = crate::upload::test_support::spawn_test_upload_server(
            crate::upload::test_support::TestUploadServerConfig {
                user_org_statuses: vec![401],
                ..crate::upload::test_support::TestUploadServerConfig::default()
            },
        )
        .await
        .expect("spawn upload test server");
        api_url_guard.set_str(server.base_url.as_str());

        let cfg = config::CliConfig {
            token: Some("test-token".to_string()),
            ..config::CliConfig::default()
        };
        cfg.save().await.expect("save config");

        let err = run_backfill_inner("1d", None)
            .await
            .expect_err("manual backfill should fail");

        assert!(err.downcast_ref::<AlreadyReportedCliError>().is_some());
        assert_eq!(
            upload::pending_upload_count().await.expect("pending count"),
            1
        );
        assert_eq!(
            server.counts(),
            crate::upload::test_support::TestUploadServerCounts {
                create_requests: 0,
                uploads: 0,
                confirms: 0,
                user_org_requests: 1,
            }
        );
    }

    #[test]
    fn backfill_auth_required_box_includes_login_and_30d_recovery_inside_border() {
        let rendered = backfill_auth_required_box(&upload::PublicationAuthState::Rejected)
            .expect("rejected auth should render action box");

        assert!(rendered.contains("MANUAL ACTION REQUIRED"));
        assert!(rendered.contains("Cadence login was rejected by the server."));
        assert!(rendered.contains("  cadence login"));
        assert!(rendered.contains("  cadence backfill --since 30d"));

        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines.len() > 3, "expected multi-line boxed message");
        let border = lines.first().expect("first border line");
        assert!(border.chars().all(|ch| ch == '*'));
        assert_eq!(lines.last().expect("last border line"), border);
    }

    #[tokio::test]
    #[serial]
    async fn recovery_backfill_skips_fast_when_publication_auth_is_rejected() {
        let home = TempDir::new().expect("home tempdir");
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(home.path());

        let global_config = home.path().join("global.gitconfig");
        tokio::fs::write(&global_config, "")
            .await
            .expect("write empty global gitconfig");
        let global_guard = EnvGuard::new("GIT_CONFIG_GLOBAL");
        global_guard.set_path(&global_config);

        let api_url_guard = EnvGuard::new("CADENCE_API_URL");

        let prepared = upload::prepare_session_upload(sample_observed_upload(
            Path::new("/tmp/repo"),
            "session-pending-recovery-auth-rejected",
            "hello",
        ))
        .expect("prepare session upload");
        let no_token_context = upload::resolve_upload_context(Some("http://127.0.0.1:9"))
            .await
            .expect("context without token");
        let queued = upload::upload_or_queue_prepared_session(&no_token_context, &prepared)
            .await
            .expect("queue upload");
        assert!(matches!(queued, upload::LiveUploadOutcome::Queued { .. }));

        let server = crate::upload::test_support::spawn_test_upload_server(
            crate::upload::test_support::TestUploadServerConfig {
                user_org_statuses: vec![401],
                ..crate::upload::test_support::TestUploadServerConfig::default()
            },
        )
        .await
        .expect("spawn upload test server");
        api_url_guard.set_str(server.base_url.as_str());

        let cfg = config::CliConfig {
            token: Some("test-token".to_string()),
            ..config::CliConfig::default()
        };
        cfg.save().await.expect("save config");

        let outcome =
            run_backfill_inner_with_invocation("1d", None, BackfillInvocation::RecoveryBootstrap)
                .await
                .expect("recovery backfill should skip cleanly");

        assert_eq!(outcome, BackfillOutcome::SkippedAuth);
        assert_eq!(
            upload::pending_upload_count().await.expect("pending count"),
            1
        );
        assert_eq!(
            server.counts(),
            crate::upload::test_support::TestUploadServerCounts {
                create_requests: 0,
                uploads: 0,
                confirms: 0,
                user_org_requests: 1,
            }
        );
    }

    #[tokio::test]
    #[serial]
    async fn run_backfill_inner_repo_filter_only_drains_matching_pending_uploads() {
        let home = TempDir::new().expect("home tempdir");
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(home.path());

        let global_config = home.path().join("global.gitconfig");
        tokio::fs::write(&global_config, "")
            .await
            .expect("write empty global gitconfig");
        let global_guard = EnvGuard::new("GIT_CONFIG_GLOBAL");
        global_guard.set_path(&global_config);

        let api_url_guard = EnvGuard::new("CADENCE_API_URL");

        let repo_a = home.path().join("repo-a");
        let repo_b = home.path().join("repo-b");
        tokio::fs::create_dir_all(&repo_a)
            .await
            .expect("create repo a");
        tokio::fs::create_dir_all(&repo_b)
            .await
            .expect("create repo b");

        for (uid, repo_root) in [
            ("queued-repo-a", repo_a.as_path()),
            ("queued-repo-b", repo_b.as_path()),
        ] {
            let prepared = upload::prepare_session_upload(sample_observed_upload(
                repo_root,
                &format!("session-{uid}"),
                "hello",
            ))
            .expect("prepare session upload");
            let no_token_context = upload::resolve_upload_context(Some("http://127.0.0.1:9"))
                .await
                .expect("context without token");
            let queued = upload::upload_or_queue_prepared_session(&no_token_context, &prepared)
                .await
                .expect("queue upload");
            assert!(matches!(queued, upload::LiveUploadOutcome::Queued { .. }));
        }

        let server = crate::upload::test_support::spawn_test_upload_server(
            crate::upload::test_support::TestUploadServerConfig::default(),
        )
        .await
        .expect("spawn upload test server");
        api_url_guard.set_str(server.base_url.as_str());

        let cfg = config::CliConfig {
            token: Some("test-token".to_string()),
            ..config::CliConfig::default()
        };
        cfg.save().await.expect("save config");

        run_backfill_inner("1d", Some(repo_a.as_path()))
            .await
            .expect("run backfill");

        assert_eq!(
            upload::pending_upload_count().await.expect("pending count"),
            1
        );
        assert_eq!(
            upload::pending_upload_count_for_repo(repo_a.as_path())
                .await
                .expect("pending count repo a"),
            0
        );
        assert_eq!(
            upload::pending_upload_count_for_repo(repo_b.as_path())
                .await
                .expect("pending count repo b"),
            1
        );
        assert_eq!(
            server.counts(),
            crate::upload::test_support::TestUploadServerCounts {
                create_requests: 1,
                uploads: 1,
                confirms: 1,
                user_org_requests: 1,
            }
        );
        let requests = server.create_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].canonical_repo_root, repo_a.to_string_lossy());
    }

    #[tokio::test]
    #[serial]
    async fn run_backfill_inner_discovers_real_world_cursor_sessions_and_ignores_noise() {
        let home = TempDir::new().expect("home tempdir");
        let _env = DiscoveryTestEnv::install(home.path());

        let global_config = home.path().join("global.gitconfig");
        tokio::fs::write(&global_config, "")
            .await
            .expect("write empty global gitconfig");
        let global_guard = EnvGuard::new("GIT_CONFIG_GLOBAL");
        global_guard.set_path(&global_config);

        let api_url_guard = EnvGuard::new("CADENCE_API_URL");

        let repo = init_repo().await;
        run_git(
            repo.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:test-org/example.git",
            ],
        )
        .await;

        let workspace_key = encode_cursor_workspace_key_for_tests(repo.path());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        write_cursor_agent_transcript(
            home.path(),
            &workspace_key,
            "cursor-transcript-session",
            concat!(
                "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"Explain the architecture of the project\"}]}}\n",
                "{\"role\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"Here is the project architecture.\"}]}}\n"
            ),
            now,
        )
        .await;
        write_cursor_project_noise(home.path(), &workspace_key).await;
        write_cursor_desktop_session(
            home.path(),
            "workspace-abc",
            "cursor-desktop-session",
            repo.path(),
            now * 1000,
            "Review the deployment flow",
            "Deployment flow summary",
        )
        .await;

        let server = crate::upload::test_support::spawn_test_upload_server(
            crate::upload::test_support::TestUploadServerConfig::default(),
        )
        .await
        .expect("spawn upload test server");
        api_url_guard.set_str(server.base_url.as_str());

        let cfg = config::CliConfig {
            token: Some("test-token".to_string()),
            ..config::CliConfig::default()
        };
        cfg.save().await.expect("save config");

        let files =
            agents::discover_recent_sessions_for_backfill(current_unix_epoch(), 86_400).await;
        let cursor_files = files
            .into_iter()
            .filter(|log| log.agent_type == scanner::AgentType::Cursor)
            .collect::<Vec<_>>();
        assert_eq!(cursor_files.len(), 2);

        let parsed_logs = parse_session_logs_bounded(cursor_files).await;
        assert_eq!(parsed_logs.len(), 2);
        for parsed in &parsed_logs {
            assert_eq!(parsed.metadata.agent_type, Some(scanner::AgentType::Cursor));
        }

        let upload_context = upload::resolve_upload_context(Some(server.base_url.as_str()))
            .await
            .expect("resolve upload context");
        for parsed in &parsed_logs {
            let outcome = upload_session_from_log(
                &upload_context,
                parsed,
                repo.path(),
                &repo.path().to_string_lossy(),
                PublicationMode::Backfill,
            )
            .await;
            assert!(matches!(outcome, UploadFromLogOutcome::Uploaded));
        }

        let upload_bodies = server
            .upload_requests()
            .into_iter()
            .map(|request| request.body)
            .collect::<Vec<_>>();
        assert_eq!(upload_bodies.len(), 2);
        assert!(
            upload_bodies
                .iter()
                .any(|body| body.contains("Explain the architecture of the project"))
        );
        assert!(
            upload_bodies
                .iter()
                .any(|body| body.contains("Deployment flow summary"))
        );
    }

    #[tokio::test]
    #[serial]
    async fn run_backfill_inner_uploads_warp_session_with_cwd_from_query_context() {
        let home = TempDir::new().expect("home tempdir");
        let _env = DiscoveryTestEnv::install(home.path());

        let global_config = home.path().join("global.gitconfig");
        tokio::fs::write(&global_config, "")
            .await
            .expect("write empty global gitconfig");
        let global_guard = EnvGuard::new("GIT_CONFIG_GLOBAL");
        global_guard.set_path(&global_config);
        let api_url_guard = EnvGuard::new("CADENCE_API_URL");
        let warp_db_guard = EnvGuard::new("WARP_DB_PATH");

        let repo = init_repo().await;
        run_git(
            repo.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:test-org/example.git",
            ],
        )
        .await;

        let warp_db_path = home.path().join("warp.sqlite");
        let conn = create_warp_fixture_db(&warp_db_path);
        conn.execute(
            "INSERT INTO ai_queries (exchange_id, conversation_id, start_ts, input, output_status, model_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                "ex1",
                "warp-query-context",
                current_unix_epoch(),
                serde_json::json!([
                    {"Query": {
                        "text": "Explain the service boundaries",
                        "context": {"Directory": {"pwd": repo.path().to_string_lossy().to_string()}}
                    }}
                ])
                .to_string(),
                "Succeeded",
                "claude-opus-4.1"
            ],
        )
        .expect("insert warp query row");
        warp_db_guard.set_path(&warp_db_path);

        let server = crate::upload::test_support::spawn_test_upload_server(
            crate::upload::test_support::TestUploadServerConfig::default(),
        )
        .await
        .expect("spawn upload test server");
        api_url_guard.set_str(server.base_url.as_str());

        let cfg = config::CliConfig {
            token: Some("test-token".to_string()),
            ..config::CliConfig::default()
        };
        cfg.save().await.expect("save config");

        let files =
            agents::discover_recent_sessions_for_backfill(current_unix_epoch(), 86_400).await;
        let warp_files = files
            .into_iter()
            .filter(|log| log.agent_type == scanner::AgentType::Warp)
            .collect::<Vec<_>>();
        assert_eq!(warp_files.len(), 1);
        let parsed_logs = parse_session_logs_bounded(warp_files).await;
        assert_eq!(parsed_logs.len(), 1);
        assert_eq!(
            parsed_logs[0].metadata.session_id.as_deref(),
            Some("warp-query-context")
        );

        let upload_context = upload::resolve_upload_context(Some(server.base_url.as_str()))
            .await
            .expect("resolve upload context");
        let outcome = upload_session_from_log(
            &upload_context,
            &parsed_logs[0],
            repo.path(),
            &repo.path().to_string_lossy(),
            PublicationMode::Backfill,
        )
        .await;
        assert!(matches!(outcome, UploadFromLogOutcome::Uploaded));

        let uploads = server.upload_requests();
        assert_eq!(uploads.len(), 1);
        assert!(uploads[0].body.contains("Explain the service boundaries"));
        let create_requests = server.create_requests();
        assert_eq!(create_requests.len(), 1);
        assert_eq!(
            create_requests[0].canonical_repo_root,
            repo.path().to_string_lossy()
        );
    }

    #[tokio::test]
    #[serial]
    async fn run_backfill_inner_skips_only_truly_unrecoverable_warp_sessions() {
        let home = TempDir::new().expect("home tempdir");
        let _env = DiscoveryTestEnv::install(home.path());

        let global_config = home.path().join("global.gitconfig");
        tokio::fs::write(&global_config, "")
            .await
            .expect("write empty global gitconfig");
        let global_guard = EnvGuard::new("GIT_CONFIG_GLOBAL");
        global_guard.set_path(&global_config);
        let api_url_guard = EnvGuard::new("CADENCE_API_URL");
        let warp_db_guard = EnvGuard::new("WARP_DB_PATH");

        let repo = init_repo().await;
        run_git(
            repo.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:test-org/example.git",
            ],
        )
        .await;

        let warp_db_path = home.path().join("warp.sqlite");
        let conn = create_warp_fixture_db(&warp_db_path);
        conn.execute(
            "INSERT INTO ai_queries (exchange_id, conversation_id, start_ts, input, output_status)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                "ex-recoverable",
                "warp-block-recovery",
                current_unix_epoch(),
                serde_json::json!({"prompt": "Recover from blocks"}).to_string(),
                "Succeeded"
            ],
        )
        .expect("insert recoverable warp row");
        conn.execute(
            "INSERT INTO blocks (ai_metadata, pwd) VALUES (?1, ?2)",
            rusqlite::params![
                serde_json::json!({"conversation_id": "warp-block-recovery"}).to_string(),
                repo.path().to_string_lossy().to_string()
            ],
        )
        .expect("insert recoverable warp block");
        conn.execute(
            "INSERT INTO ai_queries (exchange_id, conversation_id, start_ts, input, output_status)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                "ex-missing",
                "warp-unrecoverable",
                current_unix_epoch(),
                serde_json::json!({"prompt": "No cwd anywhere"}).to_string(),
                "Succeeded"
            ],
        )
        .expect("insert missing warp row");
        warp_db_guard.set_path(&warp_db_path);

        let server = crate::upload::test_support::spawn_test_upload_server(
            crate::upload::test_support::TestUploadServerConfig::default(),
        )
        .await
        .expect("spawn upload test server");
        api_url_guard.set_str(server.base_url.as_str());

        let cfg = config::CliConfig {
            token: Some("test-token".to_string()),
            ..config::CliConfig::default()
        };
        cfg.save().await.expect("save config");

        let files =
            agents::discover_recent_sessions_for_backfill(current_unix_epoch(), 86_400).await;
        let warp_files = files
            .into_iter()
            .filter(|log| log.agent_type == scanner::AgentType::Warp)
            .collect::<Vec<_>>();
        assert_eq!(warp_files.len(), 2);
        let parsed_logs = parse_session_logs_bounded(warp_files).await;
        assert_eq!(parsed_logs.len(), 2);
        let mut recoverable = None;
        let mut missing = None;
        for parsed in parsed_logs {
            match parsed.metadata.session_id.as_deref() {
                Some("warp-block-recovery") => recoverable = Some(parsed),
                Some("warp-unrecoverable") => missing = Some(parsed),
                _ => {}
            }
        }
        let recoverable = recoverable.expect("recoverable warp session");
        let missing = missing.expect("missing warp session");
        assert!(missing.metadata.cwd.is_none());

        let upload_context = upload::resolve_upload_context(Some(server.base_url.as_str()))
            .await
            .expect("resolve upload context");
        let outcome = upload_session_from_log(
            &upload_context,
            &recoverable,
            repo.path(),
            &repo.path().to_string_lossy(),
            PublicationMode::Backfill,
        )
        .await;
        assert!(matches!(outcome, UploadFromLogOutcome::Uploaded));

        let uploads = server.upload_requests();
        assert_eq!(uploads.len(), 1);
        assert!(uploads[0].body.contains("Recover from blocks"));
        assert!(!uploads[0].body.contains("No cwd anywhere"));
    }

    // -----------------------------------------------------------------------
    // Uninstall command parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn cli_parses_uninstall_command() {
        let cli = Cli::parse_from(["cadence", "uninstall"]);
        match cli.command {
            Command::Uninstall { yes } => {
                assert!(!yes);
            }
            _ => panic!("expected Uninstall command"),
        }
    }

    #[test]
    fn cli_parses_uninstall_yes_flag() {
        let cli = Cli::parse_from(["cadence", "uninstall", "--yes"]);
        match cli.command {
            Command::Uninstall { yes } => {
                assert!(yes);
            }
            _ => panic!("expected Uninstall command"),
        }
    }

    #[test]
    fn cli_parses_uninstall_short_yes_flag() {
        let cli = Cli::parse_from(["cadence", "uninstall", "-y"]);
        match cli.command {
            Command::Uninstall { yes } => {
                assert!(yes);
            }
            _ => panic!("expected Uninstall command"),
        }
    }

    #[test]
    fn cli_parses_reset_alias() {
        let cli = Cli::parse_from(["cadence", "reset"]);
        match cli.command {
            Command::Uninstall { yes } => {
                assert!(!yes);
            }
            _ => panic!("expected Uninstall command via reset alias"),
        }
    }

    #[test]
    fn cli_parses_reset_alias_with_yes() {
        let cli = Cli::parse_from(["cadence", "reset", "--yes"]);
        match cli.command {
            Command::Uninstall { yes } => {
                assert!(yes);
            }
            _ => panic!("expected Uninstall command via reset alias"),
        }
    }
}
