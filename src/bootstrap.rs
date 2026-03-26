//! Cadence runtime bootstrap, migration, and legacy hook cleanup helpers.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

use crate::{agents, git, monitor, output, update};

pub(crate) const VERSION_BOOTSTRAP_BACKFILL_SINCE: &str = "7d";
const VERSION_BOOTSTRAP_MARKER_FILE: &str = "last-version-bootstrap";

#[derive(Debug, Clone, Copy)]
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
    monitor_enabled: bool,
}

fn is_cadence_hook(content: &str) -> bool {
    content.contains("cadence hook") || content.contains("cadence")
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

fn version_bootstrap_marker_path() -> Option<PathBuf> {
    Some(crate::config::CliConfig::config_dir()?.join(VERSION_BOOTSTRAP_MARKER_FILE))
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
    let outcome = run_bootstrap(BootstrapOptions {
        trigger: BootstrapTrigger::AutomaticFirstRun,
        org: None,
        preserve_disable_state: true,
        include_recovery_backfill,
    })
    .await?;

    write_version_bootstrap_marker(&marker_path, current_version).await?;

    if outcome.monitor_enabled && include_recovery_backfill {
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
    }

    if had_runtime_errors {
        bail!("bootstrap completed with issues")
    }

    Ok(BootstrapOutcome { monitor_enabled })
}

pub(crate) async fn run_install(org: Option<String>, preserve_disable_state: bool) -> Result<()> {
    println!();
    output::action("Installing", "background monitor");
    let install_start = std::time::Instant::now();

    run_bootstrap(BootstrapOptions {
        trigger: BootstrapTrigger::InstallCommand,
        org: org.as_deref(),
        preserve_disable_state,
        include_recovery_backfill: true,
    })
    .await?;

    mark_current_version_bootstrap_complete().await?;

    println!();
    output::success("Install", "complete");
    output::detail(&format!(
        "Total time: {} ms",
        install_start.elapsed().as_millis()
    ));

    Ok(())
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
