//! Cadence runtime bootstrap, migration, and legacy hook cleanup helpers.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::{agents, git, monitor, output, state_files, update};

pub(crate) const VERSION_BOOTSTRAP_BACKFILL_SINCE: &str = "7d";
const VERSION_BOOTSTRAP_MARKER_FILE: &str = "last-version-bootstrap";
const VERSION_BOOTSTRAP_BACKFILL_MARKER_FILE: &str = "last-version-recovery-backfill";
const VERSION_BOOTSTRAP_LOCK_FILE: &str = "current-version-bootstrap.lock";
const VERSION_BOOTSTRAP_LOCK_STALE_SECS: i64 = 15 * 60;
const VERSION_BOOTSTRAP_LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const VERSION_BOOTSTRAP_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(100);
const TEST_INSTALL_SENTINEL_ENV: &str = "CADENCE_TEST_INSTALL_SENTINEL_PATH";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapTrigger {
    InstallCommand,
    AutomaticFirstRun,
}

#[derive(Debug, Clone, Copy)]
struct BootstrapOptions<'a> {
    trigger: BootstrapTrigger,
    org: Option<&'a str>,
    preserve_disable_state: bool,
    include_recovery_backfill: bool,
}

#[derive(Debug, Clone, Copy)]
struct BootstrapOutcome {
    had_runtime_errors: bool,
    performed_recovery_backfill: bool,
}

#[derive(Debug, Serialize)]
struct TestInstallSentinel {
    org: Option<String>,
    preserve_disable_state: bool,
    passive_version_check_disabled: bool,
    pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BootstrapLockRecord {
    pid: u32,
    created_at_epoch: i64,
}

struct BootstrapExecutionLockGuard {
    path: PathBuf,
}

impl Drop for BootstrapExecutionLockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn is_cadence_hook(content: &str) -> bool {
    content.lines().map(str::trim).any(|line| {
        if line.is_empty() || line.starts_with('#') {
            return false;
        }

        let normalized = line.replace(['"', '\''], " ");
        let targets_cadence_hook =
            normalized.contains(" hook post-commit") || normalized.contains(" hook pre-push");
        let invokes_cadence = normalized.contains(" cadence ")
            || normalized.contains("/cadence ")
            || normalized.contains("\\cadence ")
            || normalized.contains(" cadence.exe ")
            || normalized.contains("/cadence.exe ")
            || normalized.contains("\\cadence.exe ");

        targets_cadence_hook && invokes_cadence
    })
}

pub(crate) fn resolve_hooks_path(repo_root: Option<&Path>, configured_path: &str) -> PathBuf {
    let path = Path::new(configured_path);
    if path.is_absolute() {
        return path.to_path_buf();
    }
    match repo_root {
        Some(root) => root.join(path),
        None => path.to_path_buf(),
    }
}

pub(crate) fn paths_equivalent(left: &Path, right: &Path) -> bool {
    let left_norm = left.canonicalize().unwrap_or_else(|_| left.to_path_buf());
    let right_norm = right.canonicalize().unwrap_or_else(|_| right.to_path_buf());
    left_norm == right_norm
}

fn version_marker_path(file_name: &str) -> Option<PathBuf> {
    Some(crate::config::CliConfig::config_dir()?.join(file_name))
}

fn version_bootstrap_marker_path() -> Option<PathBuf> {
    version_marker_path(VERSION_BOOTSTRAP_MARKER_FILE)
}

fn version_bootstrap_backfill_marker_path() -> Option<PathBuf> {
    version_marker_path(VERSION_BOOTSTRAP_BACKFILL_MARKER_FILE)
}

fn version_bootstrap_lock_path() -> Option<PathBuf> {
    Some(
        crate::config::CliConfig::config_dir()?
            .join("locks")
            .join(VERSION_BOOTSTRAP_LOCK_FILE),
    )
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

async fn try_create_bootstrap_lock(path: &Path) -> Result<bool> {
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    let file = opts.open(path).await;
    let mut file = match file {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(err) => return Err(err).with_context(|| format!("create lock {}", path.display())),
    };
    let payload = serde_json::to_vec_pretty(&BootstrapLockRecord {
        pid: std::process::id(),
        created_at_epoch: now_epoch(),
    })
    .context("serialize bootstrap lock record")?;
    tokio::io::AsyncWriteExt::write_all(&mut file, &payload).await?;
    Ok(true)
}

async fn clear_stale_bootstrap_lock(path: &Path) -> Result<()> {
    let content = match tokio::fs::read_to_string(path).await {
        Ok(content) => content,
        Err(_) => {
            let _ = tokio::fs::remove_file(path).await;
            return Ok(());
        }
    };
    let parsed = match serde_json::from_str::<BootstrapLockRecord>(&content) {
        Ok(parsed) => parsed,
        Err(_) => {
            let _ = tokio::fs::remove_file(path).await;
            return Ok(());
        }
    };
    let age = now_epoch().saturating_sub(parsed.created_at_epoch);
    if age > VERSION_BOOTSTRAP_LOCK_STALE_SECS || !update::is_pid_alive(parsed.pid) {
        let _ = tokio::fs::remove_file(path).await;
    }
    Ok(())
}

async fn try_acquire_bootstrap_execution_lock() -> Result<Option<BootstrapExecutionLockGuard>> {
    let Some(lock_path) = version_bootstrap_lock_path() else {
        return Ok(None);
    };
    if let Some(parent) = lock_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    clear_stale_bootstrap_lock(&lock_path).await?;
    if try_create_bootstrap_lock(&lock_path).await? {
        return Ok(Some(BootstrapExecutionLockGuard { path: lock_path }));
    }
    Ok(None)
}

async fn acquire_bootstrap_execution_lock_blocking(
    timeout: Duration,
) -> Result<Option<BootstrapExecutionLockGuard>> {
    let Some(lock_path) = version_bootstrap_lock_path() else {
        return Ok(None);
    };
    if let Some(parent) = lock_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    let start = Instant::now();
    loop {
        clear_stale_bootstrap_lock(&lock_path).await?;
        if try_create_bootstrap_lock(&lock_path).await? {
            return Ok(Some(BootstrapExecutionLockGuard { path: lock_path }));
        }
        if start.elapsed() >= timeout {
            bail!(
                "timed out waiting for current-version bootstrap lock after {:?}",
                timeout
            );
        }
        tokio::time::sleep(VERSION_BOOTSTRAP_LOCK_POLL_INTERVAL).await;
    }
}

async fn read_version_bootstrap_marker(path: &Path) -> Result<Option<String>> {
    match tokio::fs::read_to_string(path).await {
        Ok(content) => Ok(match content.trim() {
            "" => None,
            value => Some(value.to_string()),
        }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err)
            .with_context(|| format!("failed to read version bootstrap marker {}", path.display())),
    }
}

async fn write_version_bootstrap_marker(path: &Path, version: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    tokio::fs::write(path, format!("{version}\n"))
        .await
        .with_context(|| {
            format!(
                "failed to write version bootstrap marker {}",
                path.display()
            )
        })
}

pub(crate) async fn mark_current_version_bootstrap_complete() -> Result<()> {
    let Some(path) = version_bootstrap_marker_path() else {
        return Ok(());
    };
    write_version_bootstrap_marker(&path, update::current_version()).await
}

async fn mark_current_version_recovery_backfill_complete() -> Result<()> {
    let Some(path) = version_bootstrap_backfill_marker_path() else {
        return Ok(());
    };
    write_version_bootstrap_marker(&path, update::current_version()).await
}

async fn should_run_current_version_recovery_backfill(requested: bool) -> Result<bool> {
    if !requested {
        return Ok(false);
    }

    let Some(path) = version_bootstrap_backfill_marker_path() else {
        return Ok(true);
    };
    let current_version = update::current_version();
    let last_completed = read_version_bootstrap_marker(&path).await?;
    Ok(last_completed.as_deref() != Some(current_version))
}

pub(crate) async fn maybe_run_current_version_bootstrap(
    include_recovery_backfill: bool,
) -> Result<bool> {
    let Some(marker_path) = version_bootstrap_marker_path() else {
        return Ok(false);
    };

    let current_version = update::current_version();
    let last_completed = read_version_bootstrap_marker(&marker_path).await?;
    if last_completed.as_deref() == Some(current_version) {
        return Ok(false);
    }

    let Some(_bootstrap_lock) = try_acquire_bootstrap_execution_lock().await? else {
        log_bootstrap_stage(
            "another runtime bootstrap is already active; skipping duplicate invocation",
        );
        return Ok(false);
    };

    let last_completed = read_version_bootstrap_marker(&marker_path).await?;
    if last_completed.as_deref() == Some(current_version) {
        return Ok(false);
    }

    output::detail(&format!(
        "Reconciling Cadence runtime for v{}.",
        current_version
    ));
    let include_recovery_backfill =
        should_run_current_version_recovery_backfill(include_recovery_backfill).await?;
    log_bootstrap_stage(format!(
        "automatic runtime bootstrap start (recovery_backfill={include_recovery_backfill})"
    ));
    let outcome = execute_bootstrap(BootstrapOptions {
        trigger: BootstrapTrigger::AutomaticFirstRun,
        org: None,
        preserve_disable_state: true,
        include_recovery_backfill,
    })
    .await?;

    if outcome.performed_recovery_backfill {
        mark_current_version_recovery_backfill_complete().await?;
    }
    if outcome.had_runtime_errors {
        bail!("bootstrap completed with issues");
    }

    write_version_bootstrap_marker(&marker_path, current_version).await?;
    let _ = update::reconcile_updater_state_with_bootstrapped_version(current_version).await?;

    if outcome.performed_recovery_backfill {
        output::detail(&format!(
            "Current-version bootstrap completed for v{}.",
            current_version
        ));
    } else {
        output::detail(&format!(
            "Current-version bootstrap recorded for v{}.",
            current_version
        ));
    }

    Ok(true)
}

async fn desired_monitor_enabled(preserve_disable_state: bool) -> Result<bool> {
    if !preserve_disable_state {
        return Ok(true);
    }

    Ok(monitor::configured_enabled_state().await?.unwrap_or(true))
}

fn log_bootstrap_stage(stage: impl std::fmt::Display) {
    let stage = stage.to_string();
    output::detail(&format!("Bootstrap stage: {stage}"));
    ::tracing::info!(event = "runtime_bootstrap_stage", stage = %stage);
}

async fn maybe_write_test_install_sentinel(
    org: Option<&str>,
    preserve_disable_state: bool,
) -> Result<bool> {
    let Ok(path) = std::env::var(TEST_INSTALL_SENTINEL_ENV) else {
        return Ok(false);
    };
    let path = PathBuf::from(path);
    state_files::write_json_atomic(
        &path,
        &TestInstallSentinel {
            org: org.map(str::to_string),
            preserve_disable_state,
            passive_version_check_disabled: std::env::var("CADENCE_NO_UPDATE_CHECK")
                .ok()
                .as_deref()
                == Some("1"),
            pid: std::process::id(),
        },
    )
    .await?;
    Ok(true)
}

async fn run_bootstrap(options: BootstrapOptions<'_>) -> Result<BootstrapOutcome> {
    log_bootstrap_stage("cleaning up legacy Cadence hook ownership");
    let mut had_runtime_errors = cleanup_cadence_hook_ownership(None, true).await?;
    log_bootstrap_stage(format!(
        "legacy hook cleanup complete (had_errors={had_runtime_errors})"
    ));
    let mut performed_recovery_backfill = false;

    if let Some(org) = options.org {
        log_bootstrap_stage(format!("writing org filter ({org})"));
        match git::config_set_global("ai.cadence.org", org).await {
            Ok(()) => output::success("Updated", &format!("org filter = {org}")),
            Err(err) => {
                output::fail("Failed", &format!("to set org filter ({err})"));
                had_runtime_errors = true;
            }
        }
    }

    log_bootstrap_stage(format!(
        "resolving monitor enabled state (preserve_disable_state={})",
        options.preserve_disable_state
    ));
    let monitor_enabled = desired_monitor_enabled(options.preserve_disable_state).await?;
    log_bootstrap_stage(format!(
        "persisting monitor enabled state (enabled={monitor_enabled})"
    ));
    match monitor::set_enabled(monitor_enabled).await {
        Ok(_) => {
            if matches!(options.trigger, BootstrapTrigger::InstallCommand) {
                output::action(
                    "Monitor",
                    if monitor_enabled {
                        "enabled"
                    } else {
                        "left disabled"
                    },
                );
            }
        }
        Err(err) => {
            output::note(&format!("Could not persist monitor state ({err})"));
            had_runtime_errors = true;
        }
    }

    log_bootstrap_stage(format!(
        "reconciling monitor scheduler (enabled={monitor_enabled})"
    ));
    match monitor::reconcile_scheduler_for_enabled(monitor_enabled).await {
        Ok(result) if result.configured => {
            output::success(
                "Updated",
                &format!("monitor scheduler ({})", result.description),
            );
        }
        Ok(result) => {
            output::detail(&format!("Monitor scheduler: {}", result.description));
        }
        Err(err) => {
            output::note(&format!("Could not reconcile monitor scheduler ({err})"));
            had_runtime_errors = true;
        }
    }

    if monitor_enabled {
        match options.trigger {
            BootstrapTrigger::InstallCommand => {
                if output::is_stderr_tty() && console::Term::stdout().is_term() {
                    println!();
                    output::detail(&format!(
                        "Cadence scans supported agent session sources every {} without taking ownership of Git hooks.",
                        monitor::cadence_label()
                    ));
                    output::detail(
                        "Unattended stable-channel updates run inside the monitor runtime while monitoring is enabled.",
                    );
                    output::detail("Disable anytime: `cadence monitor disable`");
                    output::detail("Remove scheduler artifacts: `cadence monitor uninstall`");
                }
            }
            BootstrapTrigger::AutomaticFirstRun => {
                output::detail(&format!(
                    "Cadence background monitoring is active with a {} cadence.",
                    monitor::cadence_label()
                ));
            }
        }
    } else {
        output::detail(
            "Preserved disabled monitor state; Cadence will stay inactive until re-enabled.",
        );
    }

    if monitor_enabled && options.include_recovery_backfill {
        log_bootstrap_stage(format!(
            "starting automatic recovery backfill (since {})",
            VERSION_BOOTSTRAP_BACKFILL_SINCE
        ));
        output::action(
            "Recovery",
            &format!("backfill --since {}", VERSION_BOOTSTRAP_BACKFILL_SINCE),
        );
        match crate::run_backfill_inner_with_invocation(
            VERSION_BOOTSTRAP_BACKFILL_SINCE,
            None,
            crate::BackfillInvocation::RecoveryBootstrap,
        )
        .await
        {
            Ok(crate::BackfillOutcome::Completed) => {
                log_bootstrap_stage("automatic recovery backfill finished (success=true)")
            }
            Ok(crate::BackfillOutcome::SkippedAuth) => {
                log_bootstrap_stage("automatic recovery backfill finished (success=skipped_auth)")
            }
            Err(err) => {
                output::note(&format!(
                    "Automatic recovery backfill did not complete ({err:#})"
                ));
                output::detail(&format!(
                    "Run `cadence backfill --since {}` if you need to recover recent local sessions manually.",
                    VERSION_BOOTSTRAP_BACKFILL_SINCE
                ));
                log_bootstrap_stage("automatic recovery backfill finished (success=false)");
            }
        }
        performed_recovery_backfill = true;
    }

    log_bootstrap_stage(format!(
        "runtime bootstrap finished (runtime_errors={had_runtime_errors}, recovery_backfill={performed_recovery_backfill})"
    ));
    Ok(BootstrapOutcome {
        had_runtime_errors,
        performed_recovery_backfill,
    })
}

pub(crate) async fn run_install(org: Option<String>, preserve_disable_state: bool) -> Result<()> {
    if maybe_write_test_install_sentinel(org.as_deref(), preserve_disable_state).await? {
        return Ok(());
    }

    println!();
    output::action("Installing", "background monitor");
    let install_start = std::time::Instant::now();
    let _bootstrap_lock =
        acquire_bootstrap_execution_lock_blocking(VERSION_BOOTSTRAP_LOCK_WAIT_TIMEOUT).await?;

    let include_recovery_backfill = should_run_current_version_recovery_backfill(true).await?;
    let outcome = execute_bootstrap(BootstrapOptions {
        trigger: BootstrapTrigger::InstallCommand,
        org: org.as_deref(),
        preserve_disable_state,
        include_recovery_backfill,
    })
    .await?;

    if outcome.performed_recovery_backfill {
        mark_current_version_recovery_backfill_complete().await?;
    }
    if outcome.had_runtime_errors {
        bail!("bootstrap completed with issues");
    }

    mark_current_version_bootstrap_complete().await?;
    let _ = update::reconcile_updater_state_with_bootstrapped_version(update::current_version())
        .await?;

    println!();
    output::success("Install", "complete");
    output::detail(&format!(
        "Total time: {} ms",
        install_start.elapsed().as_millis()
    ));

    Ok(())
}

async fn execute_bootstrap(options: BootstrapOptions<'_>) -> Result<BootstrapOutcome> {
    #[cfg(test)]
    if let Some(result) = take_bootstrap_test_result(options) {
        return result;
    }

    run_bootstrap(options).await
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BootstrapTestInvocation {
    trigger: BootstrapTrigger,
    preserve_disable_state: bool,
    include_recovery_backfill: bool,
}

#[cfg(test)]
#[derive(Default)]
struct BootstrapTestHooks {
    outcomes: std::collections::VecDeque<std::result::Result<BootstrapOutcome, String>>,
    invocations: Vec<BootstrapTestInvocation>,
}

#[cfg(test)]
fn bootstrap_test_hooks() -> &'static std::sync::Mutex<Option<BootstrapTestHooks>> {
    static HOOKS: std::sync::OnceLock<std::sync::Mutex<Option<BootstrapTestHooks>>> =
        std::sync::OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(None))
}

#[cfg(test)]
fn take_bootstrap_test_result(options: BootstrapOptions<'_>) -> Option<Result<BootstrapOutcome>> {
    let mut hooks = bootstrap_test_hooks().lock().ok()?;
    let state = hooks.as_mut()?;
    state.invocations.push(BootstrapTestInvocation {
        trigger: options.trigger,
        preserve_disable_state: options.preserve_disable_state,
        include_recovery_backfill: options.include_recovery_backfill,
    });
    let next = state
        .outcomes
        .pop_front()
        .unwrap_or_else(|| panic!("missing bootstrap test outcome"));
    Some(match next {
        Ok(outcome) => Ok(outcome),
        Err(message) => Err(anyhow::anyhow!(message)),
    })
}

#[cfg(test)]
struct BootstrapTestHooksGuard;

#[cfg(test)]
impl Drop for BootstrapTestHooksGuard {
    fn drop(&mut self) {
        if let Ok(mut hooks) = bootstrap_test_hooks().lock() {
            *hooks = None;
        }
    }
}

#[cfg(test)]
fn install_bootstrap_test_hooks(
    outcomes: impl IntoIterator<Item = std::result::Result<BootstrapOutcome, &'static str>>,
) -> BootstrapTestHooksGuard {
    let mut hooks = bootstrap_test_hooks()
        .lock()
        .expect("bootstrap test hooks lock");
    *hooks = Some(BootstrapTestHooks {
        outcomes: outcomes
            .into_iter()
            .map(|outcome| outcome.map_err(|message| message.to_string()))
            .collect(),
        invocations: Vec::new(),
    });
    BootstrapTestHooksGuard
}

#[cfg(test)]
fn bootstrap_test_invocations() -> Vec<BootstrapTestInvocation> {
    bootstrap_test_hooks()
        .lock()
        .expect("bootstrap test hooks lock")
        .as_ref()
        .map(|hooks| hooks.invocations.clone())
        .unwrap_or_default()
}

pub(crate) async fn cleanup_cadence_hook_ownership(
    home_override: Option<&Path>,
    log_progress: bool,
) -> Result<bool> {
    let home = match home_override {
        Some(home) => home.to_path_buf(),
        None => agents::home_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine home directory"))?,
    };

    let hooks_dir = home.join(".git-hooks");
    let mut had_errors = false;

    let global_hooks_path = match git::config_get_global("core.hooksPath").await {
        Ok(path) => path,
        Err(err) => {
            if log_progress {
                output::note(&format!("Could not inspect global core.hooksPath ({err})"));
            }
            had_errors = true;
            None
        }
    };
    let global_points_to_cadence_hooks = global_hooks_path
        .as_ref()
        .map(|path| paths_equivalent(&resolve_hooks_path(None, path), &hooks_dir))
        .unwrap_or(false);

    if !tokio::fs::try_exists(&hooks_dir).await.unwrap_or(false) {
        if global_points_to_cadence_hooks {
            match git::config_unset_global("core.hooksPath").await {
                Ok(()) => {
                    if log_progress {
                        output::success("Removed", "Cadence-owned global core.hooksPath");
                    }
                }
                Err(err) => {
                    if log_progress {
                        output::note(&format!("Could not unset global core.hooksPath ({err})"));
                    }
                    had_errors = true;
                }
            }
        }
        return Ok(had_errors);
    }

    let post_commit = hooks_dir.join("post-commit");
    let backup = hooks_dir.join("post-commit.pre-cadence");
    let pre_push = hooks_dir.join("pre-push");
    let mut restored_backup = false;

    if tokio::fs::try_exists(&backup).await.unwrap_or(false) {
        let should_restore = match tokio::fs::read_to_string(&post_commit).await {
            Ok(content) => is_cadence_hook(&content),
            Err(_) => true,
        };
        if should_restore {
            let _ = tokio::fs::remove_file(&post_commit).await;
            match tokio::fs::rename(&backup, &post_commit).await {
                Ok(()) => {
                    restored_backup = true;
                    if log_progress {
                        output::success("Restored", "pre-Cadence post-commit hook");
                    }
                }
                Err(err) => {
                    if log_progress {
                        output::note(&format!("Could not restore pre-Cadence hook ({err})"));
                    }
                    had_errors = true;
                }
            }
        }
    } else if tokio::fs::try_exists(&post_commit).await.unwrap_or(false) {
        match tokio::fs::read_to_string(&post_commit).await {
            Ok(content) if is_cadence_hook(&content) => {
                match tokio::fs::remove_file(&post_commit).await {
                    Ok(()) => {
                        if log_progress {
                            output::success(
                                "Removed",
                                &format!("Cadence post-commit hook ({})", post_commit.display()),
                            );
                        }
                    }
                    Err(err) => {
                        if log_progress {
                            output::note(&format!(
                                "Could not remove Cadence post-commit hook ({err})"
                            ));
                        }
                        had_errors = true;
                    }
                }
            }
            Ok(_) => {
                if log_progress {
                    output::detail(&format!(
                        "Leaving non-Cadence post-commit hook untouched: {}",
                        post_commit.display()
                    ));
                }
            }
            Err(err) => {
                if log_progress {
                    output::note(&format!(
                        "Could not inspect post-commit hook {} ({err})",
                        post_commit.display()
                    ));
                }
                had_errors = true;
            }
        }
    }

    if tokio::fs::try_exists(&pre_push).await.unwrap_or(false) {
        match tokio::fs::read_to_string(&pre_push).await {
            Ok(content) if is_cadence_hook(&content) => {
                match tokio::fs::remove_file(&pre_push).await {
                    Ok(()) => {
                        if log_progress {
                            output::success(
                                "Removed",
                                &format!("legacy Cadence pre-push hook ({})", pre_push.display()),
                            );
                        }
                    }
                    Err(err) => {
                        if log_progress {
                            output::note(&format!("Could not remove legacy pre-push hook ({err})"));
                        }
                        had_errors = true;
                    }
                }
            }
            Ok(_) => {
                if log_progress {
                    output::detail(&format!(
                        "Leaving non-Cadence pre-push hook untouched: {}",
                        pre_push.display()
                    ));
                }
            }
            Err(err) => {
                if log_progress {
                    output::note(&format!(
                        "Could not inspect legacy pre-push hook {} ({err})",
                        pre_push.display()
                    ));
                }
                had_errors = true;
            }
        }
    }

    let mut entries = tokio::fs::read_dir(&hooks_dir).await?;
    let mut remaining = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        remaining.push(entry.file_name().to_string_lossy().to_string());
    }

    if remaining.is_empty() {
        if let Err(err) = tokio::fs::remove_dir(&hooks_dir).await {
            if log_progress {
                output::note(&format!(
                    "Could not remove empty hooks directory {} ({err})",
                    hooks_dir.display()
                ));
            }
            had_errors = true;
        } else if log_progress {
            output::success("Removed", &format!("{}", hooks_dir.display()));
        }
    } else if log_progress {
        output::detail(&format!(
            "Hooks directory still contains preserved files: {}",
            remaining.join(", ")
        ));
    }

    if global_points_to_cadence_hooks && !restored_backup && remaining.is_empty() {
        match git::config_unset_global("core.hooksPath").await {
            Ok(()) => {
                if log_progress {
                    output::success("Removed", "Cadence-owned global core.hooksPath");
                }
            }
            Err(err) => {
                if log_progress {
                    output::note(&format!("Could not unset global core.hooksPath ({err})"));
                }
                had_errors = true;
            }
        }
    } else if global_points_to_cadence_hooks && log_progress {
        output::detail(
            "Preserved global core.hooksPath because the hooks directory still contains user-owned hooks.",
        );
    }

    Ok(had_errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::EnvGuard;
    use serial_test::serial;
    use tempfile::TempDir;

    #[tokio::test]
    #[serial]
    async fn maybe_run_current_version_bootstrap_skips_when_version_marker_is_current() {
        let home = TempDir::new().expect("home tempdir");
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(home.path());

        mark_current_version_bootstrap_complete()
            .await
            .expect("mark version bootstrap");

        let ran = maybe_run_current_version_bootstrap(true)
            .await
            .expect("skip bootstrap");
        assert!(!ran);
    }

    #[tokio::test]
    #[serial]
    async fn maybe_run_current_version_bootstrap_records_backfill_once_even_after_partial_failure()
    {
        let home = TempDir::new().expect("home tempdir");
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(home.path());

        let _hooks = install_bootstrap_test_hooks([
            Ok(BootstrapOutcome {
                had_runtime_errors: true,
                performed_recovery_backfill: true,
            }),
            Ok(BootstrapOutcome {
                had_runtime_errors: false,
                performed_recovery_backfill: false,
            }),
        ]);

        let err = maybe_run_current_version_bootstrap(true)
            .await
            .expect_err("expected partial bootstrap failure");
        assert!(
            err.to_string().contains("bootstrap completed with issues"),
            "unexpected error: {err:#}"
        );

        let ran = maybe_run_current_version_bootstrap(true)
            .await
            .expect("retry bootstrap after partial failure");
        assert!(ran);

        let skipped = maybe_run_current_version_bootstrap(true)
            .await
            .expect("skip once version marker recorded");
        assert!(!skipped);

        let invocations = bootstrap_test_invocations();
        assert_eq!(invocations.len(), 2);
        assert!(invocations[0].include_recovery_backfill);
        assert!(!invocations[1].include_recovery_backfill);
    }

    #[tokio::test]
    #[serial]
    async fn maybe_run_current_version_bootstrap_skips_when_another_bootstrap_is_active() {
        let home = TempDir::new().expect("home tempdir");
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(home.path());

        let _lock = try_acquire_bootstrap_execution_lock()
            .await
            .expect("acquire bootstrap execution lock")
            .expect("bootstrap lock should be available");
        let _hooks = install_bootstrap_test_hooks([Ok(BootstrapOutcome {
            had_runtime_errors: false,
            performed_recovery_backfill: true,
        })]);

        let ran = maybe_run_current_version_bootstrap(true)
            .await
            .expect("skip duplicate bootstrap");

        assert!(!ran);
        assert!(bootstrap_test_invocations().is_empty());
    }

    #[tokio::test]
    #[serial]
    async fn run_install_waits_for_bootstrap_lock_before_running_bootstrap() {
        let home = TempDir::new().expect("home tempdir");
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(home.path());

        let lock = try_acquire_bootstrap_execution_lock()
            .await
            .expect("acquire bootstrap execution lock")
            .expect("bootstrap lock should be available");
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(75)).await;
            drop(lock);
        });
        let _hooks = install_bootstrap_test_hooks([Ok(BootstrapOutcome {
            had_runtime_errors: false,
            performed_recovery_backfill: false,
        })]);

        run_install(None, true)
            .await
            .expect("install waits for lock");
        release.await.expect("release bootstrap lock");

        let invocations = bootstrap_test_invocations();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].trigger, BootstrapTrigger::InstallCommand);
        assert!(
            read_version_bootstrap_marker(&version_bootstrap_marker_path().unwrap())
                .await
                .expect("read version bootstrap marker")
                .as_deref()
                == Some(update::current_version())
        );
    }

    #[test]
    fn cadence_hook_detection_requires_real_cadence_hook_invocation() {
        assert!(is_cadence_hook(
            "#!/bin/sh\nexec cadence hook post-commit \"$@\"\n"
        ));
        assert!(is_cadence_hook(
            "#!/bin/sh\n\"/usr/local/bin/cadence\" hook pre-push \"$@\"\n"
        ));
        assert!(!is_cadence_hook(
            "#!/bin/sh\n# cadence sprint helper\nexec cadence-linter hook post-commit\n"
        ));
    }

    #[tokio::test]
    #[serial]
    async fn cleanup_cadence_hook_ownership_preserves_non_cadence_hooks() {
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
        crate::git::config_set_global("core.hooksPath", &hooks_dir.to_string_lossy())
            .await
            .expect("set core.hooksPath");
        let hook_path = hooks_dir.join("post-commit");
        let original_hook =
            "#!/bin/sh\n# cadence sprint helper\nexec cadence-linter hook post-commit\n";
        tokio::fs::write(&hook_path, original_hook)
            .await
            .expect("write non-cadence hook");

        let had_errors = cleanup_cadence_hook_ownership(Some(home.path()), false)
            .await
            .expect("cleanup hook ownership");
        assert!(!had_errors);
        assert!(hook_path.exists(), "expected non-cadence hook to remain");

        let preserved = tokio::fs::read_to_string(&hook_path)
            .await
            .expect("read preserved hook");
        assert_eq!(preserved, original_hook);
    }
}
