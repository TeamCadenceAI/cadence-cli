//! Cadence CLI binary entrypoint and subcommand orchestration.

mod agents;
mod api_client;
mod config;
mod git;
mod login;
mod output;
mod publication;
mod publication_state;
mod scanner;
mod tracing;
mod update;
mod upload;
mod upload_cursor;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use console::Term;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OnceCell, Semaphore};
use tokio::task::JoinSet;

const LOGIN_TIMEOUT_SECS: u64 = 120;
const API_TIMEOUT_SECS: u64 = 5;
const POST_COMMIT_MAX_UPLOADS_PER_RUN: usize = 20;
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
    let mut messages = error_chain_messages(err).into_iter();
    match messages.next() {
        Some(first) => {
            output::fail("Failed", &first);
            for cause in messages {
                output::detail(&format!("Caused by: {cause}"));
            }
        }
        None => output::fail("Failed", "unknown error"),
    }
}

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
    /// Install Cadence CLI: set up git hooks.
    Install {
        /// Optional GitHub org filter for push scoping.
        #[arg(long)]
        org: Option<String>,
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

    /// Diagnose hook and upload configuration issues.
    Doctor {
        /// Attempt to repair auto-update scheduler artifacts based on config intent.
        #[arg(long)]
        repair: bool,
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

    /// Manage unattended auto-update controls and scheduler artifacts.
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
        /// Configuration key (e.g. auto_update, update_check_interval, api_url).
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
    /// Show auto-update status and scheduler health.
    Status,
    /// Enable unattended background auto-update and reconcile scheduler artifacts.
    Enable,
    /// Disable unattended background auto-update (scheduler runs become no-op).
    Disable,
    /// Remove scheduler artifacts (idempotent and safe to rerun).
    Uninstall,
}

#[derive(Subcommand, Debug)]
enum HookCommand {
    /// Post-commit hook: upload recent AI sessions for the current repository.
    PostCommit,
    /// Internal unattended background updater entrypoint (scheduler-only).
    #[command(hide = true)]
    AutoUpdate,
    /// Internal Git hook refresh entrypoint used after self-update.
    #[command(hide = true)]
    RefreshHooks,
}

// ---------------------------------------------------------------------------
// Hook error taxonomy
// ---------------------------------------------------------------------------

/// Error classification for the post-commit hook.
///
/// Direct uploads must never block a commit, so all hook failures are soft.
enum HookError {
    /// Any hook failure is logged as a note and the commit proceeds.
    Soft(anyhow::Error),
}

impl From<anyhow::Error> for HookError {
    fn from(e: anyhow::Error) -> Self {
        HookError::Soft(e)
    }
}

fn api_url_override() -> Option<&'static str> {
    API_URL_OVERRIDE.get().map(String::as_str)
}

// ---------------------------------------------------------------------------
// Subcommand dispatch
// ---------------------------------------------------------------------------

/// The install subcommand: set up global git hooks.
///
/// Steps:
/// 1. Set `git config --global core.hooksPath ~/.git-hooks`
/// 2. Create `~/.git-hooks/` directory if missing
/// 3. Write `~/.git-hooks/post-commit` shim script
/// 4. Make shim executable (chmod +x)
/// 5. If `--org` provided, persist org filter to global git config
///
/// Errors at each step are reported but do not prevent subsequent steps
/// from being attempted.
async fn run_install(org: Option<String>) -> Result<()> {
    run_install_inner(org, None).await
}

fn is_cadence_hook(content: &str) -> bool {
    content.contains("cadence hook") || content.contains("cadence")
}

fn hook_command_exe() -> String {
    if cfg!(debug_assertions)
        && let Some(path) = debug_hook_exe_path()
    {
        return path;
    }
    "cadence".to_string()
}

fn debug_hook_exe_path() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    if let Some(name) = exe.file_name().and_then(|s| s.to_str())
        && name.starts_with("cadence")
    {
        return Some(exe.display().to_string());
    }

    let dir = exe.parent()?;
    if dir.file_name().and_then(|s| s.to_str()) == Some("deps") {
        let candidate = dir.parent()?.join("cadence");
        if candidate.exists() {
            return Some(candidate.display().to_string());
        }
    }

    None
}

fn post_commit_hook_content() -> String {
    format!("#!/bin/sh\nexec {} hook post-commit\n", hook_command_exe())
}

fn resolve_hooks_path(repo_root: Option<&Path>, configured_path: &str) -> PathBuf {
    let path = Path::new(configured_path);
    if path.is_absolute() {
        return path.to_path_buf();
    }
    match repo_root {
        Some(root) => root.join(path),
        None => path.to_path_buf(),
    }
}

fn paths_equivalent(left: &Path, right: &Path) -> bool {
    let left_norm = left.canonicalize().unwrap_or_else(|_| left.to_path_buf());
    let right_norm = right.canonicalize().unwrap_or_else(|_| right.to_path_buf());
    left_norm == right_norm
}

async fn cadence_hooks_installed(hooks_dir: &Path) -> bool {
    let post_path = hooks_dir.join("post-commit");
    match tokio::fs::read_to_string(&post_path).await {
        Ok(content) => is_cadence_hook(&content),
        Err(_) => false,
    }
}

/// Inner implementation of install, accepting an optional home directory override
/// for testability. If `home_override` is `None`, uses the real home directory.
async fn run_install_inner(
    org: Option<String>,
    home_override: Option<&std::path::Path>,
) -> Result<()> {
    println!();
    output::action("Installing", "hooks");
    let install_start = std::time::Instant::now();
    let mut had_errors = refresh_cadence_git_hooks(home_override, true).await?;

    // Step 4: Scheduler reconciliation is performed after auto-update consent is resolved.

    // Step 5: Persist org filter if provided
    if let Some(ref org_value) = org {
        match git::config_set_global("ai.cadence.org", org_value).await {
            Ok(()) => {
                output::success("Updated", &format!("org filter = {}", org_value));
            }
            Err(e) => {
                output::fail("Failed", &format!("to set org filter ({})", e));
                had_errors = true;
            }
        }
    }

    // Step 5.5: Optional auto-update preference prompt
    run_install_auto_update_prompt().await;

    // Step 5.6: Reconcile scheduler with persisted user intent.
    let auto_update_enabled = config::CliConfig::load()
        .await
        .unwrap_or_default()
        .auto_update_enabled();
    match update::reconcile_scheduler_for_auto_update_enabled(auto_update_enabled).await {
        Ok(result) if result.configured => {
            output::success(
                "Updated",
                &format!("auto-update scheduler ({})", result.description),
            );
        }
        Ok(result) => {
            output::detail(&format!("Auto-update scheduler: {}", result.description));
        }
        Err(e) => {
            output::note(&format!("Could not reconcile auto-update scheduler ({e})"));
        }
    }

    println!();
    if had_errors {
        output::fail("Install", "completed with issues");
    } else {
        output::success("Install", "complete");
    }
    output::detail(&format!(
        "Total time: {} ms",
        install_start.elapsed().as_millis()
    ));

    Ok(())
}

async fn refresh_cadence_git_hooks(
    home_override: Option<&std::path::Path>,
    log_progress: bool,
) -> Result<bool> {
    let home = match home_override {
        Some(h) => h.to_path_buf(),
        None => agents::home_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine home directory"))?,
    };

    let hooks_dir = home.join(".git-hooks");
    let hooks_dir_str = hooks_dir.to_string_lossy().to_string();
    let mut had_errors = false;

    match git::config_set_global("core.hooksPath", &hooks_dir_str).await {
        Ok(()) => {
            if log_progress {
                output::success("Updated", &format!("core.hooksPath = {}", hooks_dir_str));
            }
        }
        Err(e) => {
            if log_progress {
                output::fail("Failed", &format!("to set core.hooksPath ({})", e));
            }
            had_errors = true;
        }
    }

    if !tokio::fs::try_exists(&hooks_dir).await.unwrap_or(false) {
        match tokio::fs::create_dir_all(&hooks_dir).await {
            Ok(()) => {
                if log_progress {
                    output::success("Created", &hooks_dir_str);
                }
            }
            Err(e) => {
                if log_progress {
                    output::fail("Failed", &format!("to create {} ({})", hooks_dir_str, e));
                }
                had_errors = true;
            }
        }
    } else if log_progress {
        output::detail(&format!(
            "Hooks directory already exists: {}",
            hooks_dir_str
        ));
    }

    let shim_path = hooks_dir.join("post-commit");
    let shim_content = post_commit_hook_content();

    let should_write = if tokio::fs::try_exists(&shim_path).await.unwrap_or(false) {
        match tokio::fs::read_to_string(&shim_path).await {
            Ok(existing) => {
                if is_cadence_hook(&existing) {
                    if log_progress {
                        output::detail("Post-commit hook already installed; updating");
                    }
                    true
                } else {
                    let backup_path = hooks_dir.join("post-commit.pre-cadence");
                    match tokio::fs::copy(&shim_path, &backup_path).await {
                        Ok(_) => {
                            if log_progress {
                                output::note(&format!(
                                    "Existing post-commit hook saved to {}",
                                    backup_path.display()
                                ));
                            }
                        }
                        Err(e) => {
                            if log_progress {
                                output::note(&format!(
                                    "Could not back up existing post-commit hook ({})",
                                    e
                                ));
                            }
                        }
                    }
                    true
                }
            }
            Err(_) => {
                if log_progress {
                    output::note(&format!(
                        "Could not read existing {}; overwriting",
                        shim_path.display()
                    ));
                }
                true
            }
        }
    } else {
        true
    };

    if should_write {
        match tokio::fs::write(&shim_path, shim_content).await {
            Ok(()) => {
                if log_progress {
                    output::success(
                        "Wrote",
                        &format!("post-commit hook ({})", shim_path.display()),
                    );
                }

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o755);
                    match tokio::fs::set_permissions(&shim_path, perms).await {
                        Ok(()) => {
                            if log_progress {
                                output::detail(&format!("Made {} executable", shim_path.display()));
                            }
                        }
                        Err(e) => {
                            if log_progress {
                                output::fail(
                                    "Failed",
                                    &format!("to make {} executable ({})", shim_path.display(), e),
                                );
                            }
                            had_errors = true;
                        }
                    }
                }
            }
            Err(e) => {
                if log_progress {
                    output::fail(
                        "Failed",
                        &format!("to write {} ({})", shim_path.display(), e),
                    );
                }
                had_errors = true;
            }
        }
    }

    let pre_push_path = hooks_dir.join("pre-push");
    if tokio::fs::try_exists(&pre_push_path).await.unwrap_or(false) {
        match tokio::fs::read_to_string(&pre_push_path).await {
            Ok(existing) if is_cadence_hook(&existing) => {
                match tokio::fs::remove_file(&pre_push_path).await {
                    Ok(()) => {
                        if log_progress {
                            output::success(
                                "Removed",
                                &format!("legacy pre-push hook ({})", pre_push_path.display()),
                            );
                        }
                    }
                    Err(e) => {
                        if log_progress {
                            output::fail(
                                "Failed",
                                &format!("to remove {} ({})", pre_push_path.display(), e),
                            );
                        }
                        had_errors = true;
                    }
                }
            }
            Ok(_) => {
                if log_progress {
                    output::detail(&format!(
                        "Leaving non-Cadence pre-push hook untouched: {}",
                        pre_push_path.display()
                    ));
                }
            }
            Err(e) => {
                if log_progress {
                    output::note(&format!(
                        "Could not inspect legacy pre-push hook {} ({})",
                        pre_push_path.display(),
                        e
                    ));
                }
            }
        }
    }

    Ok(had_errors)
}

async fn run_refresh_hooks() -> Result<()> {
    if refresh_cadence_git_hooks(None, false).await? {
        bail!("Git hook refresh completed with issues. Run `cadence install` to repair hooks.");
    }
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
        let client = api_client::ApiClient::new(&resolved.url);
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
    let client = api_client::ApiClient::new(&resolved.url);
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

/// The post-commit hook handler. This is the critical hot path.
///
/// Direct uploads must never block a commit, so all failures are swallowed
/// after being surfaced as a note.
async fn run_hook_post_commit() -> Result<()> {
    // Catch-all: catch panics
    let result = tokio::spawn(async { hook_post_commit_inner().await }).await;

    let final_result = match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(HookError::Soft(e))) => {
            output::note(&format!("Hook issue: {}", e));
            Ok(())
        }
        Err(e) => {
            if e.is_panic() {
                output::note("Hook panicked (please report this issue)");
            } else {
                output::note(&format!("Hook task failed: {}", e));
            }
            Ok(())
        }
    };

    eprintln!();
    final_result
}

/// Inner implementation of the post-commit hook.
async fn hook_post_commit_inner() -> std::result::Result<(), HookError> {
    // Step 0: Per-repo enabled check — if disabled, skip EVERYTHING
    if !git::check_enabled().await {
        return Ok(());
    }
    let _activity_lock = update::acquire_activity_lock_blocking("hook-post-commit")
        .await
        .map_err(HookError::Soft)?;
    let _diagnostics_session = match tracing::DiagnosticsLogger::new("hook").await {
        Ok(logger) => {
            if let Some(path) = logger.path() {
                output::detail(&format!("Hook trace: {}", path.display()));
            }
            Some(tracing::install_global(logger))
        }
        Err(err) => {
            output::detail(&format!("Hook trace unavailable: {err}"));
            None
        }
    };

    // Step 1: Get repo root
    let repo_root = git::repo_root().await?;
    let repo_root_str = repo_root.to_string_lossy().to_string();

    // Step 1.25: Org filter gating — skip session storage if mismatched
    match git::repo_matches_org_filter(&repo_root).await {
        Ok(true) => {}
        Ok(false) => return Ok(()),
        Err(e) => return Err(HookError::Soft(e)),
    }

    let upload_context = upload::resolve_upload_context(api_url_override())
        .await
        .map_err(HookError::Soft)?;
    ::tracing::info!(
        event = "hook_post_commit_started",
        repo_root = repo_root_str.as_str(),
        has_token = upload_context.has_token()
    );
    let pending_summary =
        upload::process_pending_uploads(&upload_context, upload::DEFAULT_PENDING_UPLOADS_PER_RUN)
            .await
            .map_err(HookError::Soft)?;

    let uploading_progress = hook_status_spinner_start("Uploading AI sessions");
    let stats =
        match upload_incremental_sessions_for_repo(&upload_context, &repo_root, &repo_root_str)
            .await
        {
            Ok(stats) => {
                hook_status_spinner_finish_ok(uploading_progress, "Uploading AI sessions");
                stats
            }
            Err(e) => {
                hook_status_spinner_finish_err(uploading_progress, "Uploading AI sessions");
                return Err(HookError::Soft(e));
            }
        };

    if (!upload_context.has_token() && stats.queued > 0) || pending_summary.auth_required {
        output::note("Run `cadence login` to upload queued AI sessions.");
    }
    if output::is_verbose() {
        output::detail(&format!(
            "uploaded={} queued={} skipped={} issues={} retried_pending={} dropped_pending={}",
            stats.uploaded,
            stats.queued,
            stats.skipped,
            stats.issues,
            pending_summary.uploaded + pending_summary.already_existed,
            pending_summary.dropped_permanent,
        ));
    }
    ::tracing::info!(
        event = "hook_post_commit_completed",
        repo_root = repo_root_str.as_str(),
        uploaded = stats.uploaded,
        queued = stats.queued,
        skipped = stats.skipped,
        issues = stats.issues,
        pending_attempted = pending_summary.attempted,
        pending_uploaded = pending_summary.uploaded,
        pending_already_existed = pending_summary.already_existed,
        pending_skipped_repo_not_associated = pending_summary.skipped_repo_not_associated,
        pending_dropped_permanent = pending_summary.dropped_permanent,
        pending_auth_required = pending_summary.auth_required
    );

    Ok(())
}

const POST_COMMIT_FALLBACK_WINDOW_SECS: i64 = 30 * 86_400;

fn cadence_hook_label(is_tty: bool) -> String {
    if is_tty {
        console::style("[Cadence]")
            .bold()
            .fg(console::Color::Cyan)
            .to_string()
    } else {
        "[Cadence]".to_string()
    }
}

fn hook_status_spinner_start(task: &str) -> Option<ProgressBar> {
    if !output::is_stderr_tty() {
        eprintln!("{} {}", cadence_hook_label(false), task);
        eprintln!();
        return None;
    }
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner()),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb.set_message(format!("{} {}", cadence_hook_label(true), task));
    Some(pb)
}

fn hook_status_spinner_finish_ok(pb: Option<ProgressBar>, task: &str) {
    if let Some(pb) = pb {
        let check = console::style("✓").fg(console::Color::Green).to_string();
        pb.finish_with_message(format!("{} {} {}", check, cadence_hook_label(true), task));
    } else {
        eprintln!("✓ {} {}", cadence_hook_label(false), task);
    }
}

fn hook_status_spinner_finish_err(pb: Option<ProgressBar>, task: &str) {
    if let Some(pb) = pb {
        let cross = console::style("✗").fg(console::Color::Red).to_string();
        pb.finish_with_message(format!("{} {} {}", cross, cadence_hook_label(true), task));
    }
}

async fn git_ref_for_repo(repo: &std::path::Path) -> Option<String> {
    let branch = git::current_branch_at(repo).await.ok().flatten()?;
    Some(format!("refs/heads/{branch}"))
}

async fn head_sha_for_repo(repo: &std::path::Path) -> Option<String> {
    git::head_sha_at(repo).await.ok().flatten()
}

fn apply_incremental_upload_outcome(
    stats: &mut UploadRunStats,
    cursor_advance: &mut IncrementalCursor,
    log_mtime: Option<i64>,
    log_source_label: &str,
    outcome: UploadFromLogOutcome,
) -> bool {
    match outcome {
        UploadFromLogOutcome::Uploaded => {
            stats.uploaded += 1;
            *cursor_advance =
                advance_cursor_for_disposition(cursor_advance, log_mtime, log_source_label);
            true
        }
        UploadFromLogOutcome::AlreadyExists => {
            stats.skipped += 1;
            *cursor_advance =
                advance_cursor_for_disposition(cursor_advance, log_mtime, log_source_label);
            true
        }
        UploadFromLogOutcome::Queued(_) => {
            stats.queued += 1;
            *cursor_advance =
                advance_cursor_for_disposition(cursor_advance, log_mtime, log_source_label);
            true
        }
        UploadFromLogOutcome::Retryable(message) => {
            stats.issues += 1;
            if output::is_verbose() {
                output::detail(&format!("post-commit upload retryable error: {message}"));
            }
            // Stop here so we do not persist a cursor past a failed candidate.
            false
        }
    }
}

fn hook_discovery_concurrency() -> usize {
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
    fn from_persisted(
        record: Option<upload_cursor::UploadCursorRecord>,
        default_mtime_epoch: i64,
    ) -> Self {
        match record {
            Some(record) => Self {
                last_scanned_mtime_epoch: record.last_scanned_mtime_epoch,
                last_scanned_source_label: record.last_scanned_source_label,
            },
            None => Self {
                last_scanned_mtime_epoch: default_mtime_epoch,
                last_scanned_source_label: None,
            },
        }
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
    let semaphore = Arc::new(Semaphore::new(hook_discovery_concurrency()));
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

#[derive(Debug, Default, Clone, Copy)]
struct UploadRunStats {
    uploaded: usize,
    queued: usize,
    skipped: usize,
    issues: usize,
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
    let remote_urls = match git::remote_urls_at(repo_root).await {
        Ok(urls) => urls,
        Err(err) => return UploadFromLogOutcome::Retryable(err.to_string()),
    };
    let canonical_remote_url = git::preferred_remote_url_at(repo_root)
        .await
        .ok()
        .flatten()
        .or_else(|| remote_urls.first().cloned());
    let worktree_roots = git::repo_and_worktree_roots_at(repo_root).await;
    let (git_ref, head_commit_sha) = match mode {
        PublicationMode::Live => (
            git_ref_for_repo(repo_root).await,
            head_sha_for_repo(repo_root).await,
        ),
        PublicationMode::Backfill => (None, None),
    };

    let Some(canonical_remote_url) = canonical_remote_url else {
        let prepared = match upload::prepare_session_upload(upload::ObservedSessionUpload {
            logical_session: publication::LogicalSessionKey {
                agent: agent.to_string(),
                agent_session_id: session_id,
            },
            observations: publication::PublicationObservations {
                canonical_remote_url: String::new(),
                remote_urls,
                canonical_repo_root: repo_root_str.to_string(),
                worktree_roots,
                cwd: parsed
                    .metadata
                    .cwd
                    .clone()
                    .or_else(|| Some(repo_root_str.to_string())),
                git_ref,
                head_commit_sha,
                git_user_email,
                git_user_name,
                cli_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            },
            raw_session_content: parsed.session_log.clone(),
        }) {
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

    let prepared = match upload::prepare_session_upload(upload::ObservedSessionUpload {
        logical_session: publication::LogicalSessionKey {
            agent: agent.to_string(),
            agent_session_id: session_id,
        },
        observations: publication::PublicationObservations {
            canonical_remote_url,
            remote_urls,
            canonical_repo_root: repo_root_str.to_string(),
            worktree_roots,
            cwd: parsed
                .metadata
                .cwd
                .clone()
                .or_else(|| Some(repo_root_str.to_string())),
            git_ref,
            head_commit_sha,
            git_user_email,
            git_user_name,
            cli_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        },
        raw_session_content: parsed.session_log.clone(),
    }) {
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

async fn upload_incremental_sessions_for_repo(
    context: &upload::UploadContext,
    repo_root: &std::path::Path,
    repo_root_str: &str,
) -> Result<UploadRunStats> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let persisted_cursor = upload_cursor::load_cursor(repo_root_str).await?;
    let initial_cursor =
        IncrementalCursor::from_persisted(persisted_cursor, now - POST_COMMIT_FALLBACK_WINDOW_SECS);
    let since_secs = (now - initial_cursor.last_scanned_mtime_epoch).max(0);
    let files = agents::discover_recent_sessions(now, since_secs).await;
    let candidates =
        select_incremental_candidates(files, &initial_cursor, POST_COMMIT_MAX_UPLOADS_PER_RUN);

    let parsed_logs = parse_session_logs_bounded(candidates).await;
    let mut repo_root_cache: std::collections::HashMap<String, Option<std::path::PathBuf>> =
        std::collections::HashMap::new();
    let mut stats = UploadRunStats::default();
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
            let resolved = git::resolve_repo_root_with_fallbacks(std::path::Path::new(&cwd))
                .await
                .ok()
                .map(|resolution| resolution.repo_root);
            repo_root_cache.insert(cwd.clone(), resolved.clone());
            resolved
        };
        let Some(resolved_repo) = resolved_repo else {
            cursor_advance =
                advance_cursor_for_disposition(&cursor_advance, log_mtime, &log_source_label);
            continue;
        };
        if resolved_repo != repo_root {
            cursor_advance =
                advance_cursor_for_disposition(&cursor_advance, log_mtime, &log_source_label);
            continue;
        }

        if !apply_incremental_upload_outcome(
            &mut stats,
            &mut cursor_advance,
            log_mtime,
            &log_source_label,
            upload_session_from_log(
                context,
                &parsed,
                repo_root,
                repo_root_str,
                PublicationMode::Live,
            )
            .await,
        ) {
            break;
        }
    }

    if cursor_advance != initial_cursor {
        upload_cursor::upsert_cursor(
            repo_root_str,
            cursor_advance.last_scanned_mtime_epoch,
            cursor_advance.last_scanned_source_label.as_deref(),
        )
        .await?;
    }

    Ok(stats)
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

async fn session_log_content_async(log: &agents::SessionLog) -> Option<String> {
    match &log.source {
        agents::SessionSource::File(path) => tokio::fs::read_to_string(path).await.ok(),
        agents::SessionSource::Inline { content, .. } => Some(content.clone()),
    }
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
    let files = agents::discover_recent_sessions(now, since_secs).await;
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
            ::tracing::info!(
                event = "session_discovery_skipped",
                file = file_path.as_str(),
                reason = "missing_session_metadata"
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
                ::tracing::info!(
                    event = "session_discovery_skipped",
                    file = file_path.as_str(),
                    session_id = ?metadata.session_id,
                    reason = "missing_cwd"
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
    Ok(())
}

/// The status subcommand: show Cadence CLI configuration and state.
///
/// Displays:
/// - Current repo root (or a message if not in a git repo)
/// - Effective hooks path and whether the post-commit shim is installed
/// - Warning when a repo-local hooksPath overrides global Cadence hooks
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

    // --- Repo root ---
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

    // --- Hooks path and shim status ---
    let global_hooks_path = git::config_get_global("core.hooksPath")
        .await
        .ok()
        .flatten();
    if let Some(ref root) = repo_root {
        match git::config_get_at(root, "core.hooksPath")
            .await
            .ok()
            .flatten()
        {
            Some(path) => {
                let hooks_dir = resolve_hooks_path(Some(root), &path);
                let post_installed = cadence_hooks_installed(&hooks_dir).await;
                let post_str = if post_installed { "yes" } else { "no" };
                output::detail_to_with_tty(
                    w,
                    &format!("Hooks path: {} (post-commit: {})", path, post_str),
                    false,
                );

                if !post_installed {
                    output::note_to_with_tty(
                        w,
                        "Cadence post-commit hook is not installed in the active hooksPath.",
                        false,
                    );
                }
            }
            None => {
                output::detail_to_with_tty(w, "Hooks path: (not configured)", false);
            }
        }

        if let Ok(Some(local_hooks_path)) = git::config_get_local_at(root, "core.hooksPath").await
            && let Some(global_path) = &global_hooks_path
        {
            let local_resolved = resolve_hooks_path(Some(root), &local_hooks_path);
            let global_resolved = resolve_hooks_path(Some(root), global_path);
            if !paths_equivalent(&local_resolved, &global_resolved) {
                output::note_to_with_tty(
                    w,
                    &format!(
                        "Repo-local core.hooksPath overrides global Cadence hooks: {}",
                        local_hooks_path
                    ),
                    false,
                );
                output::detail_to_with_tty(
                    w,
                    "Run `git config --unset core.hooksPath` in this repo to use global hooks.",
                    false,
                );
            }
        }
    } else if let Some(path) = global_hooks_path {
        let hooks_dir = resolve_hooks_path(None, &path);
        let post_installed = cadence_hooks_installed(&hooks_dir).await;
        let post_str = if post_installed { "yes" } else { "no" };
        output::detail_to_with_tty(
            w,
            &format!("Hooks path: {} (post-commit: {})", path, post_str),
            false,
        );
    } else {
        output::detail_to_with_tty(w, "Hooks path: (not configured)", false);
    }

    let pending_uploads = upload::pending_upload_count().await.unwrap_or(0);
    output::detail_to_with_tty(w, &format!("Pending uploads: {}", pending_uploads), false);

    // --- Org filter ---
    match git::config_get_global("ai.cadence.org").await {
        Ok(Some(org)) => {
            output::detail_to_with_tty(w, &format!("Org filter: {}", org), false);
        }
        _ => {
            output::detail_to_with_tty(w, "Org filter: (none)", false);
        }
    }

    // --- Per-repo enabled/disabled ---
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
    let scheduler_health = update::scheduler_health().await;
    let scheduler_state = match scheduler_health.state {
        update::SchedulerHealthState::Installed => "installed",
        update::SchedulerHealthState::Missing => "missing",
        update::SchedulerHealthState::Broken => "broken",
        update::SchedulerHealthState::Unsupported => "unsupported",
    };
    output::detail_to_with_tty(
        w,
        &format!(
            "Auto-update scheduler: {scheduler_state} ({})",
            scheduler_health.details
        ),
        false,
    );
    output::detail_to_with_tty(
        w,
        &format!("Auto-update remediation: {}", scheduler_health.remediation),
        false,
    );
    output::detail_to_with_tty(
        w,
        "Controls: `cadence auto-update status|enable|disable|uninstall`",
        false,
    );

    Ok(())
}

async fn run_doctor(repair: bool) -> Result<()> {
    run_doctor_inner(&mut std::io::stderr(), repair).await
}

async fn run_doctor_inner(w: &mut dyn std::io::Write, repair: bool) -> Result<()> {
    output::action_to_with_tty(w, "Doctor", "", false);

    let mut issues = 0usize;

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

    let global_hooks_path = match git::config_get_global("core.hooksPath").await {
        Ok(path) => path,
        Err(e) => {
            output::fail_to_with_tty(
                w,
                "Failed",
                &format!("could not read global core.hooksPath ({e})"),
                false,
            );
            issues += 1;
            None
        }
    };

    match &global_hooks_path {
        Some(path) => {
            let hooks_dir = resolve_hooks_path(repo_root.as_deref(), path);
            let post_installed = cadence_hooks_installed(&hooks_dir).await;
            output::detail_to_with_tty(
                w,
                &format!(
                    "Global hooks: {} (post-commit: {})",
                    path,
                    if post_installed { "yes" } else { "no" }
                ),
                false,
            );
            if !post_installed {
                output::fail_to_with_tty(
                    w,
                    "Fail",
                    "Cadence global post-commit hook is not installed",
                    false,
                );
                output::detail_to_with_tty(w, "Run `cadence install` to repair hooks.", false);
                issues += 1;
            }
        }
        None => {
            output::fail_to_with_tty(w, "Fail", "Global core.hooksPath is not configured", false);
            output::detail_to_with_tty(w, "Run `cadence install` to configure hooks.", false);
            issues += 1;
        }
    }

    if let Some(ref root) = repo_root {
        match git::config_get_at(root, "core.hooksPath").await {
            Ok(Some(active_path)) => {
                let hooks_dir = resolve_hooks_path(Some(root), &active_path);
                let post_installed = cadence_hooks_installed(&hooks_dir).await;
                output::detail_to_with_tty(
                    w,
                    &format!(
                        "Active hooks: {} (post-commit: {})",
                        active_path,
                        if post_installed { "yes" } else { "no" }
                    ),
                    false,
                );
                if !post_installed {
                    output::fail_to_with_tty(
                        w,
                        "Fail",
                        "Active hooksPath does not contain the Cadence post-commit hook",
                        false,
                    );
                    output::detail_to_with_tty(w, "Run `cadence install` or fix hooksPath.", false);
                    issues += 1;
                }
            }
            Ok(None) => {
                output::fail_to_with_tty(
                    w,
                    "Fail",
                    "No effective hooksPath found for this repository",
                    false,
                );
                issues += 1;
            }
            Err(e) => {
                output::fail_to_with_tty(
                    w,
                    "Fail",
                    &format!("could not read repo hooksPath ({e})"),
                    false,
                );
                issues += 1;
            }
        }

        if let (Ok(Some(local_hooks_path)), Some(global_path)) = (
            git::config_get_local_at(root, "core.hooksPath").await,
            global_hooks_path.as_ref(),
        ) {
            let local_resolved = resolve_hooks_path(Some(root), &local_hooks_path);
            let global_resolved = resolve_hooks_path(Some(root), global_path);
            if !paths_equivalent(&local_resolved, &global_resolved) {
                output::fail_to_with_tty(
                    w,
                    "Fail",
                    &format!(
                        "Repo-local core.hooksPath overrides global Cadence hooks: {}",
                        local_hooks_path
                    ),
                    false,
                );
                output::detail_to_with_tty(
                    w,
                    "Run `git config --unset core.hooksPath` in this repo to use global hooks.",
                    false,
                );
                issues += 1;
            }
        }
    } else {
        output::note_to_with_tty(
            w,
            "Skipped repo-local hook checks because current directory is not a git repository.",
            false,
        );
    }

    let pending_uploads = upload::pending_upload_count().await.unwrap_or(0);
    output::detail_to_with_tty(w, &format!("Pending uploads: {}", pending_uploads), false);

    let updater_health = update::updater_health().await;
    match updater_health.state {
        update::UpdaterHealthState::Disabled => {
            output::detail_to_with_tty(w, "Auto-update: disabled", false);
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
        let cfg = config::CliConfig::load().await.unwrap_or_default();
        let reconcile =
            update::reconcile_scheduler_for_auto_update_enabled(cfg.auto_update_enabled()).await?;
        output::detail_to_with_tty(
            w,
            &format!("Repair applied: {}", reconcile.description),
            false,
        );
    }

    let scheduler_health = update::scheduler_health().await;
    match scheduler_health.state {
        update::SchedulerHealthState::Installed | update::SchedulerHealthState::Unsupported => {
            output::detail_to_with_tty(
                w,
                &format!("Auto-update scheduler: {}", scheduler_health.details),
                false,
            );
        }
        update::SchedulerHealthState::Missing | update::SchedulerHealthState::Broken => {
            output::fail_to_with_tty(
                w,
                "Fail",
                &format!("Auto-update scheduler: {}", scheduler_health.details),
                false,
            );
            issues += 1;
        }
    }
    output::detail_to_with_tty(
        w,
        &format!("Auto-update remediation: {}", scheduler_health.remediation),
        false,
    );
    output::detail_to_with_tty(
        w,
        "Remediation commands: `cadence auto-update disable`, `cadence auto-update enable`, `cadence auto-update uninstall`, `cadence install`, `cadence doctor --repair`",
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
// Install: auto-update preference prompt
// ---------------------------------------------------------------------------

/// Configure automatic updates during install.
///
/// This is non-critical: failures are logged but never abort install.
/// Skipped silently if output is not interactive.
async fn run_install_auto_update_prompt() {
    let cfg = match config::CliConfig::load().await {
        Ok(c) => c,
        Err(_) => return,
    };
    let config_path = match config::CliConfig::config_path() {
        Some(p) => p,
        None => return,
    };
    run_install_auto_update_prompt_inner(
        &cfg,
        &config_path,
        output::is_stderr_tty() && Term::stdout().is_term(),
    )
    .await;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallAutoUpdateFtueState {
    Skip,
    Disclosure,
    EnableByDefault,
}

fn install_auto_update_ftue_state(cfg: &config::CliConfig) -> InstallAutoUpdateFtueState {
    match cfg.auto_update {
        Some(true) => InstallAutoUpdateFtueState::Disclosure,
        Some(false) => InstallAutoUpdateFtueState::Skip,
        None => InstallAutoUpdateFtueState::EnableByDefault,
    }
}

/// Testable inner implementation of the install-time auto-update behavior.
async fn run_install_auto_update_prompt_inner(
    cfg: &config::CliConfig,
    config_path: &std::path::Path,
    is_tty: bool,
) {
    if !is_tty {
        return;
    }

    let mut stdout = std::io::stdout();
    match install_auto_update_ftue_state(cfg) {
        InstallAutoUpdateFtueState::Skip => return,
        InstallAutoUpdateFtueState::Disclosure => {
            println!();
            output::action_to_with_tty(&mut stdout, "Auto-update", "disclosure", is_tty);
            output::detail_to_with_tty(
                &mut stdout,
                "Cadence background updater runs unattended and installs stable releases only.",
                is_tty,
            );
            output::detail_to_with_tty(
                &mut stdout,
                "Controls: `cadence auto-update disable` or `cadence auto-update uninstall`.",
                is_tty,
            );
            output::detail_to_with_tty(&mut stdout, "Current setting: enabled", is_tty);
            return;
        }
        InstallAutoUpdateFtueState::EnableByDefault => {}
    }

    println!();
    output::action_to_with_tty(&mut stdout, "Auto-update", "enabled", is_tty);
    output::detail_to_with_tty(
        &mut stdout,
        "Cadence enables unattended background updates by default (stable channel only, no prompts).",
        is_tty,
    );
    output::detail_to_with_tty(
        &mut stdout,
        "Disable anytime: `cadence auto-update disable`",
        is_tty,
    );
    output::detail_to_with_tty(
        &mut stdout,
        "Remove scheduler artifacts: `cadence auto-update uninstall`",
        is_tty,
    );

    let mut updated_cfg = cfg.clone();
    if let Err(e) = updated_cfg.set_key(config::ConfigKey::AutoUpdate, "true") {
        output::note_to_with_tty(
            &mut stdout,
            &format!("Could not save auto-update preference: {e}"),
            is_tty,
        );
        return;
    }
    if let Err(e) = updated_cfg.save_to(config_path).await {
        output::note_to_with_tty(
            &mut stdout,
            &format!("Could not save auto-update preference: {e}"),
            is_tty,
        );
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

async fn set_auto_update_enabled(enabled: bool) -> Result<()> {
    let mut cfg = config::CliConfig::load().await?;
    cfg.auto_update = Some(enabled);
    cfg.save().await?;
    Ok(())
}

async fn run_auto_update_status() -> Result<()> {
    let mut stderr = std::io::stderr();
    let updater = update::updater_health().await;
    let scheduler = update::scheduler_health().await;
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
    let scheduler_state = match scheduler.state {
        update::SchedulerHealthState::Installed => "installed",
        update::SchedulerHealthState::Missing => "missing",
        update::SchedulerHealthState::Broken => "broken",
        update::SchedulerHealthState::Unsupported => "unsupported",
    };
    output::detail_to_with_tty(
        &mut stderr,
        &format!("Scheduler: {scheduler_state} ({})", scheduler.details),
        false,
    );
    output::detail_to_with_tty(
        &mut stderr,
        &format!("Remediation: {}", scheduler.remediation),
        false,
    );
    Ok(())
}

async fn run_auto_update_enable() -> Result<()> {
    set_auto_update_enabled(true).await?;
    let reconcile = update::reconcile_scheduler_for_auto_update_enabled(true).await?;
    output::success(
        "Auto-update",
        "enabled. Background stable-channel updates are now active.",
    );
    output::detail(&format!("Scheduler reconciled: {}", reconcile.description));
    output::detail("Disable with `cadence auto-update disable`.");
    output::detail("Remove scheduler artifacts with `cadence auto-update uninstall`.");
    Ok(())
}

async fn run_auto_update_disable() -> Result<()> {
    set_auto_update_enabled(false).await?;
    output::success(
        "Auto-update",
        "disabled. Scheduled updater runs will no-op immediately.",
    );
    output::detail("Re-enable with `cadence auto-update enable`.");
    Ok(())
}

async fn run_auto_update_uninstall() -> Result<()> {
    set_auto_update_enabled(false).await?;
    let removed = update::uninstall_auto_update_scheduler().await?;
    if removed.removed {
        output::success("Auto-update", "scheduler artifacts removed.");
    } else {
        output::detail("Auto-update scheduler artifacts were already absent.");
    }
    output::detail(&format!("Cleanup target: {}", removed.description));
    output::detail(
        "Background updates remain disabled until you run `cadence auto-update enable`.",
    );
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

/// Check for or install updates.
///
/// With `--check`: queries GitHub for the latest release and reports whether
/// an update is available. Never downloads or writes files.
///
/// Without `--check`: downloads, verifies, and replaces the running binary.
/// Use `--yes` / `-y` to skip the confirmation prompt.
async fn run_update(check: bool, yes: bool) -> Result<()> {
    update::run_update(check, yes).await
}

// ---------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------

/// Completely remove Cadence CLI hooks, configuration, scheduler, and state.
///
/// Execution order (dependencies noted):
/// 1. Revoke API token (needs config.toml + network)
/// 2. Disable auto-update + remove scheduler artifacts
/// 3. Unset global git config keys
/// 4. Restore pre-cadence hook backup + remove ~/.git-hooks/ if empty
/// 5. Clean ai.cadence.enabled from current + sibling repos
/// 6. Remove ~/.cadence/ directory tree
/// 7. Remove /tmp/cadence-autoupdate.log
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
        output::detail("Git config:  core.hooksPath, ai.cadence.org");
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

    // Step 2: Disable auto-update + remove scheduler artifacts
    match uninstall_scheduler().await {
        Ok(()) => {}
        Err(e) => {
            output::note(&format!("Could not remove scheduler ({e})"));
            had_errors = true;
        }
    }

    // Step 3: Unset global git config keys
    for key in &["core.hooksPath", "ai.cadence.org"] {
        match git::config_unset_global(key).await {
            Ok(()) => output::success("Removed", &format!("git config --global {key}")),
            Err(e) => {
                output::note(&format!("Could not unset {key} ({e})"));
                had_errors = true;
            }
        }
    }

    // Step 4: Restore pre-cadence hook backup + remove ~/.git-hooks/ if empty
    match uninstall_hooks_dir().await {
        Ok(()) => {}
        Err(e) => {
            output::note(&format!("Could not clean hooks directory ({e})"));
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

    // Step 7: Remove /tmp/cadence-autoupdate.log
    let log_path = std::path::Path::new("/tmp/cadence-autoupdate.log");
    if log_path.exists() {
        match tokio::fs::remove_file(log_path).await {
            Ok(()) => output::success("Removed", "/tmp/cadence-autoupdate.log"),
            Err(e) => {
                output::note(&format!("Could not remove log file ({e})"));
                had_errors = true;
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
    let client = api_client::ApiClient::new(&resolved.url);
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

/// Disable auto-update and remove scheduler artifacts.
async fn uninstall_scheduler() -> Result<()> {
    // Best-effort disable in config — config may not exist
    let _ = set_auto_update_enabled(false).await;

    let removed = update::uninstall_auto_update_scheduler().await?;
    if removed.removed {
        output::success("Removed", &format!("scheduler ({})", removed.description));
    } else {
        output::detail("Scheduler artifacts were already absent.");
    }
    Ok(())
}

/// Remove the ~/.git-hooks/ directory, restoring any pre-cadence backup first.
async fn uninstall_hooks_dir() -> Result<()> {
    let home =
        agents::home_dir().ok_or_else(|| anyhow::anyhow!("could not determine home directory"))?;
    let hooks_dir = home.join(".git-hooks");

    if !tokio::fs::try_exists(&hooks_dir).await.unwrap_or(false) {
        output::detail("Hooks directory already absent.");
        return Ok(());
    }

    let post_commit = hooks_dir.join("post-commit");
    let backup = hooks_dir.join("post-commit.pre-cadence");

    // If there's a pre-cadence backup, restore it
    if tokio::fs::try_exists(&backup).await.unwrap_or(false) {
        tokio::fs::rename(&backup, &post_commit).await?;
        output::success("Restored", "pre-cadence post-commit hook");
    } else if tokio::fs::try_exists(&post_commit).await.unwrap_or(false) {
        // Only remove post-commit if it's a cadence hook
        if let Ok(content) = tokio::fs::read_to_string(&post_commit).await
            && is_cadence_hook(&content)
        {
            tokio::fs::remove_file(&post_commit).await?;
        }
    }

    // Check if directory is now empty (or only has cadence files)
    let mut entries = tokio::fs::read_dir(&hooks_dir).await?;
    let mut remaining = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        remaining.push(entry.file_name().to_string_lossy().to_string());
    }

    if remaining.is_empty() {
        tokio::fs::remove_dir(&hooks_dir).await?;
        output::success("Removed", &format!("{}", hooks_dir.display()));
    } else {
        output::note(&format!(
            "{} contains non-cadence files ({}), left in place",
            hooks_dir.display(),
            remaining.join(", ")
        ));
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

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let cli = Cli::parse();
    output::set_verbose(cli.verbose);
    if let Some(url) = cli.api_url.clone() {
        let _ = API_URL_OVERRIDE.set(url);
    }

    let is_update_command = matches!(&cli.command, Command::Update { .. });
    let is_hook_command = matches!(&cli.command, Command::Hook { .. });

    let result = match cli.command {
        Command::Install { org } => run_install(org).await,
        Command::Hook { hook_command } => match hook_command {
            HookCommand::PostCommit => run_hook_post_commit().await,
            HookCommand::AutoUpdate => update::run_background_auto_update().await,
            HookCommand::RefreshHooks => run_refresh_hooks().await,
        },
        Command::Backfill { since } => run_backfill(&since).await,
        Command::Login => run_login().await,
        Command::Logout => run_logout().await,
        Command::Status => run_status().await,
        Command::Config { config_command } => match config_command.unwrap_or(ConfigCommand::List) {
            ConfigCommand::Set { key, value } => run_config_set(&key, &value).await,
            ConfigCommand::Get { key } => run_config_get(&key).await,
            ConfigCommand::List => run_config_list().await,
        },
        Command::Doctor { repair } => run_doctor(repair).await,
        Command::Update { check, yes } => run_update(check, yes).await,
        Command::AutoUpdate { command } => run_auto_update(command).await,
        Command::Uninstall { yes } => run_uninstall(yes).await,
    };

    // Passive background version check: run after successful command execution
    // on all non-Update commands. Failures are silently ignored.
    if result.is_ok() && !is_update_command && !is_hook_command {
        update::passive_version_check().await;
    }

    if let Err(e) = result {
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
    use anyhow::anyhow;
    use serde_json::Value;
    use serial_test::serial;
    use tempfile::TempDir;

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

        fn set_str(&self, value: &str) {
            unsafe { std::env::set_var(self.key, value) };
        }

        fn set_path(&self, value: &std::path::Path) {
            self.set_str(&value.to_string_lossy());
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

    async fn read_jsonl(path: &std::path::Path) -> Vec<Value> {
        let content = tokio::fs::read_to_string(path).await.expect("read jsonl");
        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("json row"))
            .collect()
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
        let content = format!(
            "{{\"sessionId\":\"{session_id}\",\"cwd\":\"{}\",\"message\":\"hello\"}}\n",
            repo_root.to_string_lossy()
        );
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
        let cli = Cli::parse_from(["cadence", "config", "set", "auto_update", "true"]);
        match cli.command {
            Command::Config { config_command } => match config_command {
                Some(ConfigCommand::Set { key, value }) => {
                    assert_eq!(key, "auto_update");
                    assert_eq!(value, "true");
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

    #[test]
    fn install_auto_update_ftue_state_matches_config() {
        let enabled = config::CliConfig {
            auto_update: Some(true),
            ..config::CliConfig::default()
        };
        assert_eq!(
            install_auto_update_ftue_state(&enabled),
            InstallAutoUpdateFtueState::Disclosure
        );

        let disabled = config::CliConfig {
            auto_update: Some(false),
            ..config::CliConfig::default()
        };
        assert_eq!(
            install_auto_update_ftue_state(&disabled),
            InstallAutoUpdateFtueState::Skip
        );

        assert_eq!(
            install_auto_update_ftue_state(&config::CliConfig::default()),
            InstallAutoUpdateFtueState::EnableByDefault
        );
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

    #[tokio::test]
    async fn install_auto_update_defaults_to_enabled_when_unset() {
        let dir = TempDir::new().expect("tempdir");
        let config_path = dir.path().join("config.toml");
        let cfg = config::CliConfig::default();

        run_install_auto_update_prompt_inner(&cfg, &config_path, true).await;
        let saved = config::CliConfig::load_from(&config_path)
            .await
            .expect("load config");
        assert_eq!(saved.auto_update, Some(true));
    }

    #[tokio::test]
    async fn install_auto_update_disclosure_skips_prompt_when_enabled() {
        let dir = TempDir::new().expect("tempdir");
        let config_path = dir.path().join("config.toml");
        let cfg = config::CliConfig {
            auto_update: Some(true),
            ..config::CliConfig::default()
        };

        run_install_auto_update_prompt_inner(&cfg, &config_path, true).await;

        assert!(!config_path.exists());
    }

    #[tokio::test]
    async fn install_auto_update_respects_explicit_disable() {
        let dir = TempDir::new().expect("tempdir");
        let config_path = dir.path().join("config.toml");
        let cfg = config::CliConfig {
            auto_update: Some(false),
            ..config::CliConfig::default()
        };

        run_install_auto_update_prompt_inner(&cfg, &config_path, true).await;

        assert!(!config_path.exists());
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
        let cli = Cli::parse_from(["cadence", "config", "get", "auto_update"]);
        match cli.command {
            Command::Config { config_command } => match config_command {
                Some(ConfigCommand::Get { key }) => {
                    assert_eq!(key, "auto_update");
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
        let resolved = resolve_hooks_path(Some(repo.path()), ".git/hooks");
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
        assert!(paths_equivalent(&absolute, &relative));
    }

    #[tokio::test]
    #[serial]
    async fn refresh_cadence_git_hooks_updates_existing_managed_hooks() {
        let home = TempDir::new().expect("home tempdir");
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(home.path());

        let global_config = home.path().join("global.gitconfig");
        tokio::fs::write(&global_config, "")
            .await
            .expect("write empty global gitconfig");
        let global_guard = EnvGuard::new("GIT_CONFIG_GLOBAL");
        global_guard.set_path(&global_config);

        let hooks_dir = home.path().join(".git-hooks");
        tokio::fs::create_dir_all(&hooks_dir)
            .await
            .expect("create hooks dir");
        tokio::fs::write(
            hooks_dir.join("post-commit"),
            "#!/bin/sh\nexec cadence hook pre-push\n",
        )
        .await
        .expect("seed stale post-commit hook");
        tokio::fs::write(
            hooks_dir.join("pre-push"),
            "#!/bin/sh\nexec cadence hook pre-push\n",
        )
        .await
        .expect("seed legacy pre-push hook");

        let had_errors = refresh_cadence_git_hooks(Some(home.path()), false)
            .await
            .expect("refresh hooks");
        assert!(!had_errors);

        let post_commit = tokio::fs::read_to_string(hooks_dir.join("post-commit"))
            .await
            .expect("read post-commit");
        assert_eq!(post_commit, post_commit_hook_content());
        assert!(
            !hooks_dir.join("pre-push").exists(),
            "expected legacy pre-push hook to be removed"
        );

        let configured_hooks_path = crate::git::config_get_global("core.hooksPath")
            .await
            .expect("read core.hooksPath");
        assert_eq!(
            configured_hooks_path.as_deref(),
            Some(hooks_dir.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn post_commit_fallback_window_defaults_are_stable() {
        assert_eq!(POST_COMMIT_FALLBACK_WINDOW_SECS, 30 * 86_400);
    }

    #[test]
    fn post_commit_max_uploads_per_run_defaults_are_stable() {
        assert_eq!(POST_COMMIT_MAX_UPLOADS_PER_RUN, 20);
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

    #[test]
    fn retryable_incremental_outcome_stops_before_cursor_advances() {
        let mut stats = UploadRunStats::default();
        let mut cursor = IncrementalCursor {
            last_scanned_mtime_epoch: 100,
            last_scanned_source_label: Some("a".to_string()),
        };

        let should_continue = apply_incremental_upload_outcome(
            &mut stats,
            &mut cursor,
            Some(200),
            "z",
            UploadFromLogOutcome::Retryable("queue write failed".to_string()),
        );

        assert!(!should_continue);
        assert_eq!(stats.issues, 1);
        assert_eq!(
            cursor,
            IncrementalCursor {
                last_scanned_mtime_epoch: 100,
                last_scanned_source_label: Some("a".to_string()),
            }
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
