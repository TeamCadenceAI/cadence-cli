//! Cadence runtime bootstrap, migration, and legacy hook cleanup helpers.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

use crate::{agents, git, monitor, output, update};

pub(crate) const VERSION_BOOTSTRAP_BACKFILL_SINCE: &str = "7d";
const VERSION_BOOTSTRAP_MARKER_FILE: &str = "last-version-bootstrap";
const VERSION_BOOTSTRAP_BACKFILL_MARKER_FILE: &str = "last-version-recovery-backfill";

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

    output::detail(&format!(
        "Reconciling Cadence runtime for v{}.",
        current_version
    ));
    let include_recovery_backfill =
        should_run_current_version_recovery_backfill(include_recovery_backfill).await?;
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

async fn run_bootstrap(options: BootstrapOptions<'_>) -> Result<BootstrapOutcome> {
    let mut had_runtime_errors = cleanup_cadence_hook_ownership(None, true).await?;
    let mut performed_recovery_backfill = false;

    if let Some(org) = options.org {
        match git::config_set_global("ai.cadence.org", org).await {
            Ok(()) => output::success("Updated", &format!("org filter = {org}")),
            Err(err) => {
                output::fail("Failed", &format!("to set org filter ({err})"));
                had_runtime_errors = true;
            }
        }
    }

    let monitor_enabled = desired_monitor_enabled(options.preserve_disable_state).await?;
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
        println!();
        output::action(
            "Recovery",
            &format!("backfill --since {}", VERSION_BOOTSTRAP_BACKFILL_SINCE),
        );
        if let Err(err) = crate::run_backfill_inner(VERSION_BOOTSTRAP_BACKFILL_SINCE, None).await {
            output::note(&format!(
                "Automatic recovery backfill did not complete ({err:#})"
            ));
            output::detail(&format!(
                "Run `cadence backfill --since {}` if you need to recover recent local sessions manually.",
                VERSION_BOOTSTRAP_BACKFILL_SINCE
            ));
        }
        performed_recovery_backfill = true;
    }

    Ok(BootstrapOutcome {
        had_runtime_errors,
        performed_recovery_backfill,
    })
}

pub(crate) async fn run_install(org: Option<String>, preserve_disable_state: bool) -> Result<()> {
    println!();
    output::action("Installing", "background monitor");
    let install_start = std::time::Instant::now();

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
    use serial_test::serial;
    use tempfile::TempDir;

    struct EnvGuard {
        key: &'static str,
        original: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn new(key: &'static str) -> Self {
            Self {
                key,
                original: std::env::var_os(key),
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
