//! Background monitor state and scheduler management.

use crate::state_files;
#[cfg(target_os = "macos")]
use anyhow::bail;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::process::Output;
use tokio::process::Command;

const MONITOR_STATE_FILE: &str = "monitor-state.json";
const MONITOR_DISCOVERY_CURSOR_FILE: &str = "monitor-discovery-cursor.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MonitorState {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_discovered: usize,
    #[serde(default)]
    pub last_uploaded: usize,
    #[serde(default)]
    pub last_queued: usize,
    #[serde(default)]
    pub last_skipped: usize,
    #[serde(default)]
    pub last_issues: usize,
    #[serde(default)]
    pub last_pending_attempted: usize,
    #[serde(default)]
    pub last_pending_uploaded: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub filtered_session_throttle: BTreeMap<String, FilteredSessionThrottleEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilteredSessionReason {
    UnresolvedRepo,
    RepoDisabled,
    OrgMismatch,
    OrgFilterError,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilteredSessionThrottleEntry {
    pub updated_at_epoch: i64,
    pub reason: FilteredSessionReason,
    pub next_recheck_at_epoch: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryCursorRecord {
    pub last_scanned_mtime_epoch: i64,
    #[serde(default)]
    pub last_scanned_source_label: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct SchedulerProvisionResult {
    pub configured: bool,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct SchedulerUninstallResult {
    pub removed: bool,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchedulerHealthState {
    Installed,
    Missing,
    Broken,
    Unsupported,
}

#[derive(Debug, Clone)]
pub struct SchedulerHealth {
    pub state: SchedulerHealthState,
    pub details: String,
    pub remediation: String,
}

fn monitor_state_path() -> Result<PathBuf> {
    Ok(state_files::cadence_dir()?.join(MONITOR_STATE_FILE))
}

fn discovery_cursor_path() -> Result<PathBuf> {
    Ok(state_files::cadence_dir()?.join(MONITOR_DISCOVERY_CURSOR_FILE))
}

pub async fn load_state() -> Result<MonitorState> {
    let path = monitor_state_path()?;
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => serde_json::from_str::<MonitorState>(&content)
            .with_context(|| format!("failed to parse monitor state {}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(MonitorState::default()),
        Err(err) => {
            Err(err).with_context(|| format!("failed to read monitor state {}", path.display()))
        }
    }
}

pub async fn save_state(state: &MonitorState) -> Result<()> {
    let path = monitor_state_path()?;
    state_files::write_json_atomic(&path, state).await
}

pub async fn set_enabled(enabled: bool) -> Result<MonitorState> {
    let mut state = load_state().await?;
    state.enabled = enabled;
    save_state(&state).await?;
    Ok(state)
}

pub async fn monitor_enabled() -> bool {
    load_state()
        .await
        .map(|state| state.enabled)
        .unwrap_or(false)
}

pub async fn configured_enabled_state() -> Result<Option<bool>> {
    let path = monitor_state_path()?;
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => {
            let state = serde_json::from_str::<MonitorState>(&content)
                .with_context(|| format!("failed to parse monitor state {}", path.display()))?;
            Ok(Some(state.enabled))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => {
            Err(err).with_context(|| format!("failed to read monitor state {}", path.display()))
        }
    }
}

pub async fn load_discovery_cursor() -> Result<Option<DiscoveryCursorRecord>> {
    let path = discovery_cursor_path()?;
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => {
            let record =
                serde_json::from_str::<DiscoveryCursorRecord>(&content).with_context(|| {
                    format!(
                        "failed to parse monitor discovery cursor {}",
                        path.display()
                    )
                })?;
            Ok(Some(record))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err)
            .with_context(|| format!("failed to read monitor discovery cursor {}", path.display())),
    }
}

pub async fn upsert_discovery_cursor(
    last_scanned_mtime_epoch: i64,
    last_scanned_source_label: Option<&str>,
) -> Result<()> {
    let path = discovery_cursor_path()?;
    let record = DiscoveryCursorRecord {
        last_scanned_mtime_epoch,
        last_scanned_source_label: last_scanned_source_label.map(str::to_string),
        updated_at: state_files::now_rfc3339(),
    };
    state_files::write_json_atomic(&path, &record).await
}

pub fn cadence_secs() -> u64 {
    if cfg!(windows) { 60 } else { 30 }
}

pub fn cadence_label() -> String {
    format!("{}s", cadence_secs())
}

#[cfg(target_os = "macos")]
const MACOS_LAUNCH_AGENT_LABEL: &str = "ai.teamcadence.cadence.monitor";
#[cfg(target_os = "windows")]
const WINDOWS_TASK_NAME: &str = "Cadence CLI Monitor";

#[cfg(target_os = "windows")]
fn scheduler_command_line(exe_path: &Path) -> String {
    format!("\"{}\" monitor tick", exe_path.display())
}

#[cfg(target_os = "macos")]
fn parent_pid_for_logs() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::getppid() as u32 }
    }

    #[cfg(not(unix))]
    {
        0
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn command_failure_detail(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    [stderr, stdout]
        .into_iter()
        .find(|value| !value.is_empty())
        .unwrap_or_else(|| format!("exit status {}", output.status))
}

#[cfg(any(target_os = "windows", test))]
fn windows_task_query_reports_missing(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("cannot find the file specified")
        || detail.contains("cannot find the task")
        || detail.contains("system cannot find")
        || detail.contains("task does not exist")
}

#[cfg(target_os = "macos")]
fn macos_launchctl_domain() -> String {
    format!("gui/{}", unsafe { libc::geteuid() })
}

#[cfg(target_os = "macos")]
async fn launchctl_output(args: &[&str]) -> Result<Output> {
    Command::new("launchctl")
        .args(args)
        .output()
        .await
        .with_context(|| format!("failed to execute launchctl {}", args.join(" ")))
}

#[cfg(target_os = "macos")]
async fn launchctl_file_operation(operation: &str, plist_path: &Path) -> Result<Output> {
    Command::new("launchctl")
        .args([operation, "-w"])
        .arg(plist_path)
        .output()
        .await
        .with_context(|| {
            format!(
                "failed to execute launchctl {operation} -w {}",
                plist_path.display()
            )
        })
}

#[cfg(target_os = "macos")]
fn launchctl_reports_missing_service(detail: &str) -> bool {
    detail.contains("Could not find service")
        || detail.contains("Could not find specified service")
        || detail.contains("service already bootstrapped")
        || detail.contains("No such process")
        || detail.contains("not found")
}

#[cfg(target_os = "macos")]
async fn macos_launch_agent_loaded(label: &str) -> Result<bool> {
    let service_target = format!("{}/{}", macos_launchctl_domain(), label);
    let output = launchctl_output(&["print", &service_target]).await?;
    if output.status.success() {
        return Ok(true);
    }

    let detail = command_failure_detail(&output);
    if launchctl_reports_missing_service(&detail) {
        return Ok(false);
    }

    bail!("launchctl print {service_target} failed: {detail}");
}

#[cfg(target_os = "macos")]
fn macos_launch_agent_disabled_from_output(output: &str, label: &str) -> Option<bool> {
    let needle = format!("\"{label}\" =>");
    output.lines().find_map(|line| {
        let (_, value) = line.split_once(&needle)?;
        let value = value.trim();
        if value.starts_with("disabled") || value.starts_with("true") {
            return Some(true);
        }
        if value.starts_with("enabled") || value.starts_with("false") {
            return Some(false);
        }
        None
    })
}

#[cfg(target_os = "macos")]
async fn macos_launch_agent_disabled(label: &str) -> Result<Option<bool>> {
    let domain = macos_launchctl_domain();
    let output = launchctl_output(&["print-disabled", &domain]).await?;
    if !output.status.success() {
        bail!(
            "launchctl print-disabled {domain} failed: {}",
            command_failure_detail(&output)
        );
    }
    Ok(macos_launch_agent_disabled_from_output(
        &String::from_utf8_lossy(&output.stdout),
        label,
    ))
}

#[cfg(target_os = "macos")]
fn running_under_monitor_launch_agent() -> bool {
    std::env::var("XPC_SERVICE_NAME").ok().as_deref() == Some(MACOS_LAUNCH_AGENT_LABEL)
}

#[cfg(target_os = "macos")]
fn launch_agent_plist(label: &str, exe_path: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>monitor</string>
    <string>tick</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>{interval}</integer>
</dict>
</plist>
"#,
        exe = exe_path.display(),
        interval = cadence_secs()
    )
}

#[cfg(target_os = "macos")]
fn macos_launch_agent_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME is required for LaunchAgent provisioning")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{MACOS_LAUNCH_AGENT_LABEL}.plist")))
}

#[cfg(target_os = "linux")]
fn systemd_service_contents(exe_path: &Path) -> String {
    format!(
        "[Unit]\nDescription=Cadence CLI background monitor\n\n[Service]\nType=oneshot\nExecStart={} monitor tick\n",
        exe_path.display()
    )
}

#[cfg(target_os = "linux")]
fn systemd_timer_contents() -> String {
    format!(
        "[Unit]\nDescription=Cadence CLI background monitor timer\n\n[Timer]\nOnBootSec=15s\nOnUnitActiveSec={}s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
        cadence_secs()
    )
}

#[cfg(target_os = "linux")]
fn linux_systemd_paths() -> Result<(PathBuf, PathBuf)> {
    let home = std::env::var("HOME").context("HOME is required for systemd user provisioning")?;
    let user_dir = PathBuf::from(home)
        .join(".config")
        .join("systemd")
        .join("user");
    Ok((
        user_dir.join("cadence-monitor.service"),
        user_dir.join("cadence-monitor.timer"),
    ))
}

pub async fn provision_scheduler() -> Result<SchedulerProvisionResult> {
    let exe =
        std::env::current_exe().context("failed to resolve current cadence executable path")?;
    provision_scheduler_for_exe(&exe).await
}

pub async fn provision_scheduler_for_exe(exe: &Path) -> Result<SchedulerProvisionResult> {
    #[cfg(target_os = "macos")]
    {
        let plist_path = macos_launch_agent_path()?;
        let agents_dir = plist_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("invalid launch agent path"))?;
        tokio::fs::create_dir_all(&agents_dir).await?;
        let plist = launch_agent_plist(MACOS_LAUNCH_AGENT_LABEL, exe);
        tokio::fs::write(&plist_path, plist).await?;
        let xpc_service_name = std::env::var("XPC_SERVICE_NAME").ok();
        let loaded_before = macos_launch_agent_loaded(MACOS_LAUNCH_AGENT_LABEL)
            .await
            .ok();
        let disabled_before = macos_launch_agent_disabled(MACOS_LAUNCH_AGENT_LABEL)
            .await
            .ok()
            .flatten();
        ::tracing::info!(
            event = "monitor_scheduler_reconcile_start",
            pid = std::process::id(),
            ppid = parent_pid_for_logs(),
            exe = exe.display().to_string(),
            plist = plist_path.display().to_string(),
            xpc_service_name = xpc_service_name.as_deref().unwrap_or(""),
            loaded_before = ?loaded_before,
            disabled_before = ?disabled_before
        );

        if running_under_monitor_launch_agent() {
            ::tracing::warn!(
                event = "monitor_scheduler_reconcile_deferred_for_active_job",
                pid = std::process::id(),
                ppid = parent_pid_for_logs(),
                plist = plist_path.display().to_string(),
                xpc_service_name = xpc_service_name.as_deref().unwrap_or(""),
                loaded_before = ?loaded_before,
                disabled_before = ?disabled_before,
                reason = "running under active monitor LaunchAgent; skipping launchctl unload/load"
            );
            return Ok(SchedulerProvisionResult {
                configured: true,
                description: format!(
                    "LaunchAgent {} updated on disk; reload deferred for active monitor job",
                    plist_path.display()
                ),
            });
        }

        if let Ok(output) = launchctl_file_operation("unload", &plist_path).await
            && !output.status.success()
        {
            let detail = command_failure_detail(&output);
            if !launchctl_reports_missing_service(&detail) {
                ::tracing::warn!(
                    event = "launchctl_unload_failed",
                    plist = plist_path.display().to_string(),
                    error = detail
                );
            }
        }
        let disabled_after_unload = macos_launch_agent_disabled(MACOS_LAUNCH_AGENT_LABEL)
            .await
            .ok()
            .flatten();
        ::tracing::info!(
            event = "monitor_scheduler_reconcile_after_unload",
            pid = std::process::id(),
            ppid = parent_pid_for_logs(),
            plist = plist_path.display().to_string(),
            disabled_after_unload = ?disabled_after_unload
        );

        let load = launchctl_file_operation("load", &plist_path).await?;
        ::tracing::info!(
            event = "monitor_scheduler_reconcile_after_load",
            pid = std::process::id(),
            ppid = parent_pid_for_logs(),
            plist = plist_path.display().to_string(),
            load_status = %load.status,
            load_detail = command_failure_detail(&load)
        );
        if !load.status.success() {
            bail!(
                "launchctl load failed for {}: {}",
                plist_path.display(),
                command_failure_detail(&load)
            );
        }

        if !macos_launch_agent_loaded(MACOS_LAUNCH_AGENT_LABEL).await? {
            bail!(
                "LaunchAgent {} was written but is not loaded in launchd",
                plist_path.display()
            );
        }
        let disabled_after_load = macos_launch_agent_disabled(MACOS_LAUNCH_AGENT_LABEL)
            .await
            .ok()
            .flatten();
        ::tracing::info!(
            event = "monitor_scheduler_reconcile_verified",
            pid = std::process::id(),
            ppid = parent_pid_for_logs(),
            plist = plist_path.display().to_string(),
            disabled_after_load = ?disabled_after_load
        );

        return Ok(SchedulerProvisionResult {
            configured: true,
            description: format!("LaunchAgent {}", plist_path.display()),
        });
    }

    #[cfg(target_os = "linux")]
    {
        let (service_path, timer_path) = linux_systemd_paths()?;
        let user_dir = service_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("invalid systemd user service path"))?;
        tokio::fs::create_dir_all(&user_dir).await?;
        tokio::fs::write(&service_path, systemd_service_contents(exe)).await?;
        tokio::fs::write(&timer_path, systemd_timer_contents()).await?;

        let daemon_reload = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status()
            .await;
        if daemon_reload.as_ref().is_ok_and(|status| status.success()) {
            let _ = Command::new("systemctl")
                .args(["--user", "enable", "--now", "cadence-monitor.timer"])
                .status()
                .await;
        }

        return Ok(SchedulerProvisionResult {
            configured: true,
            description: format!("systemd user timer {}", timer_path.display()),
        });
    }

    #[cfg(target_os = "windows")]
    {
        let command = scheduler_command_line(exe);
        let _ = Command::new("schtasks")
            .args([
                "/Create",
                "/F",
                "/SC",
                "MINUTE",
                "/MO",
                "1",
                "/TN",
                WINDOWS_TASK_NAME,
                "/TR",
                &command,
            ])
            .status()
            .await;
        return Ok(SchedulerProvisionResult {
            configured: true,
            description: WINDOWS_TASK_NAME.to_string(),
        });
    }

    #[allow(unreachable_code)]
    Ok(SchedulerProvisionResult {
        configured: false,
        description: "scheduler unsupported on this platform".to_string(),
    })
}

pub async fn uninstall_scheduler() -> Result<SchedulerUninstallResult> {
    #[cfg(target_os = "macos")]
    {
        let plist_path = macos_launch_agent_path()?;
        let existed = tokio::fs::try_exists(&plist_path).await.unwrap_or(false);
        if existed
            && let Ok(output) = launchctl_file_operation("unload", &plist_path).await
            && !output.status.success()
        {
            let detail = command_failure_detail(&output);
            if !launchctl_reports_missing_service(&detail) {
                ::tracing::warn!(
                    event = "launchctl_unload_failed",
                    plist = plist_path.display().to_string(),
                    error = detail
                );
            }
        }
        if existed {
            let _ = tokio::fs::remove_file(&plist_path).await;
        }
        return Ok(SchedulerUninstallResult {
            removed: existed,
            description: format!("LaunchAgent {}", plist_path.display()),
        });
    }

    #[cfg(target_os = "linux")]
    {
        let (service_path, timer_path) = linux_systemd_paths()?;
        let _ = Command::new("systemctl")
            .args(["--user", "disable", "--now", "cadence-monitor.timer"])
            .status()
            .await;
        let _ = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status()
            .await;

        let service_exists = tokio::fs::try_exists(&service_path).await.unwrap_or(false);
        let timer_exists = tokio::fs::try_exists(&timer_path).await.unwrap_or(false);
        if service_exists {
            let _ = tokio::fs::remove_file(&service_path).await;
        }
        if timer_exists {
            let _ = tokio::fs::remove_file(&timer_path).await;
        }
        return Ok(SchedulerUninstallResult {
            removed: service_exists || timer_exists,
            description: format!(
                "systemd user files ({}, {})",
                service_path.display(),
                timer_path.display()
            ),
        });
    }

    #[cfg(target_os = "windows")]
    {
        let out = Command::new("schtasks")
            .args(["/Delete", "/F", "/TN", WINDOWS_TASK_NAME])
            .status()
            .await;
        return Ok(SchedulerUninstallResult {
            removed: out.as_ref().is_ok_and(|status| status.success()),
            description: WINDOWS_TASK_NAME.to_string(),
        });
    }

    #[allow(unreachable_code)]
    Ok(SchedulerUninstallResult {
        removed: false,
        description: "scheduler unsupported on this platform".to_string(),
    })
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct ReconcileSchedulerTestHook {
    result: SchedulerProvisionResult,
    calls: Vec<bool>,
}

#[cfg(test)]
fn reconcile_scheduler_test_hook() -> &'static std::sync::Mutex<Option<ReconcileSchedulerTestHook>>
{
    static HOOK: std::sync::OnceLock<std::sync::Mutex<Option<ReconcileSchedulerTestHook>>> =
        std::sync::OnceLock::new();
    HOOK.get_or_init(|| std::sync::Mutex::new(None))
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) struct InstalledReconcileSchedulerTestHook;

#[cfg(test)]
impl Drop for InstalledReconcileSchedulerTestHook {
    fn drop(&mut self) {
        if let Ok(mut hook) = reconcile_scheduler_test_hook().lock() {
            *hook = None;
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn install_reconcile_scheduler_test_hook(
    result: SchedulerProvisionResult,
) -> InstalledReconcileSchedulerTestHook {
    let mut hook = reconcile_scheduler_test_hook()
        .lock()
        .expect("reconcile scheduler test hook lock");
    *hook = Some(ReconcileSchedulerTestHook {
        result,
        calls: Vec::new(),
    });
    InstalledReconcileSchedulerTestHook
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn reconcile_scheduler_test_hook_calls() -> Vec<bool> {
    reconcile_scheduler_test_hook()
        .lock()
        .expect("reconcile scheduler test hook lock")
        .as_ref()
        .map(|hook| hook.calls.clone())
        .unwrap_or_default()
}

pub async fn reconcile_scheduler_for_enabled(enabled: bool) -> Result<SchedulerProvisionResult> {
    #[cfg(test)]
    {
        let mut hook = reconcile_scheduler_test_hook()
            .lock()
            .expect("reconcile scheduler test hook lock");
        if let Some(hook) = hook.as_mut() {
            hook.calls.push(enabled);
            return Ok(hook.result.clone());
        }
    }

    if let Err(err) =
        crate::update::cleanup_legacy_auto_update_scheduler_for_monitor_runtime().await
    {
        ::tracing::warn!(
            event = "legacy_auto_update_scheduler_cleanup_failed",
            error = %format!("{err:#}")
        );
    }
    if enabled {
        return provision_scheduler().await;
    }
    let removed = uninstall_scheduler().await?;
    Ok(SchedulerProvisionResult {
        configured: false,
        description: format!(
            "disabled; cleaned scheduler artifacts ({})",
            removed.description
        ),
    })
}

pub async fn ensure_enabled_and_reconciled() -> Result<SchedulerProvisionResult> {
    let _ = set_enabled(true).await?;
    reconcile_scheduler_for_enabled(true).await
}

pub async fn uninstall_monitor() -> Result<SchedulerUninstallResult> {
    let _ = set_enabled(false).await?;
    uninstall_scheduler().await
}

pub async fn scheduler_health() -> SchedulerHealth {
    #[cfg(target_os = "macos")]
    {
        return scheduler_health_macos().await;
    }

    #[cfg(target_os = "linux")]
    {
        let (service_path, timer_path) = match linux_systemd_paths() {
            Ok(value) => value,
            Err(err) => {
                return SchedulerHealth {
                    state: SchedulerHealthState::Broken,
                    details: format!("systemd user path unavailable: {err}"),
                    remediation: "Run `cadence install` to repair monitor setup.".to_string(),
                };
            }
        };
        let service_exists = tokio::fs::try_exists(&service_path).await.unwrap_or(false);
        let timer_exists = tokio::fs::try_exists(&timer_path).await.unwrap_or(false);
        if !service_exists && !timer_exists {
            return SchedulerHealth {
                state: SchedulerHealthState::Missing,
                details: format!(
                    "missing systemd user timer/service ({}, {})",
                    service_path.display(),
                    timer_path.display()
                ),
                remediation: "Run `cadence monitor enable` or `cadence install` to create them."
                    .to_string(),
            };
        }
        if !service_exists || !timer_exists {
            return SchedulerHealth {
                state: SchedulerHealthState::Broken,
                details: format!(
                    "partial systemd artifacts present ({}, {})",
                    service_path.display(),
                    timer_path.display()
                ),
                remediation: "Run `cadence install` to reconcile monitor artifacts.".to_string(),
            };
        }
        let service_contents = tokio::fs::read_to_string(&service_path)
            .await
            .unwrap_or_default();
        if !service_contents.contains("monitor tick") {
            return SchedulerHealth {
                state: SchedulerHealthState::Broken,
                details: format!(
                    "systemd service exists but command is invalid: {}",
                    service_path.display()
                ),
                remediation: "Run `cadence install` to rewrite monitor artifacts.".to_string(),
            };
        }
        return SchedulerHealth {
            state: SchedulerHealthState::Installed,
            details: format!(
                "systemd user timer/service installed ({}, {})",
                service_path.display(),
                timer_path.display()
            ),
            remediation: "Use `cadence monitor disable` to stop runs or `cadence monitor uninstall` to remove scheduler artifacts.".to_string(),
        };
    }

    #[cfg(target_os = "windows")]
    {
        let queried = Command::new("schtasks")
            .args(["/Query", "/TN", WINDOWS_TASK_NAME])
            .output()
            .await;
        match queried {
            Ok(output) if output.status.success() => {
                return SchedulerHealth {
                    state: SchedulerHealthState::Installed,
                    details: format!("Task Scheduler task installed: {}", WINDOWS_TASK_NAME),
                    remediation: "Use `cadence monitor disable` to stop runs or `cadence monitor uninstall` to remove scheduler artifacts.".to_string(),
                };
            }
            Ok(output) => {
                let detail = command_failure_detail(&output);
                if windows_task_query_reports_missing(&detail) {
                    return SchedulerHealth {
                        state: SchedulerHealthState::Missing,
                        details: format!("Task Scheduler task missing: {}", WINDOWS_TASK_NAME),
                        remediation:
                            "Run `cadence monitor enable` or `cadence install` to create it."
                                .to_string(),
                    };
                }

                return SchedulerHealth {
                    state: SchedulerHealthState::Broken,
                    details: format!(
                        "Task Scheduler query failed for {}: {}",
                        WINDOWS_TASK_NAME, detail
                    ),
                    remediation: "Run `cadence install` to repair monitor setup.".to_string(),
                };
            }
            Err(err) => {
                return SchedulerHealth {
                    state: SchedulerHealthState::Broken,
                    details: format!(
                        "Task Scheduler query failed for {}: {}",
                        WINDOWS_TASK_NAME, err
                    ),
                    remediation: "Run `cadence install` to repair monitor setup.".to_string(),
                };
            }
        }
    }

    #[allow(unreachable_code)]
    SchedulerHealth {
        state: SchedulerHealthState::Unsupported,
        details: "scheduler unsupported on this platform".to_string(),
        remediation: "No scheduler action required.".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn macos_scheduler_health_from_probe(
    plist_path: &Path,
    contents: &str,
    loaded: Result<bool>,
) -> SchedulerHealth {
    if !contents.contains("<string>monitor</string>") || !contents.contains("<string>tick</string>")
    {
        return SchedulerHealth {
            state: SchedulerHealthState::Broken,
            details: format!(
                "LaunchAgent exists but contents look invalid: {}",
                plist_path.display()
            ),
            remediation: "Run `cadence install` to rewrite monitor artifacts.".to_string(),
        };
    }

    match loaded {
        Ok(true) => SchedulerHealth {
            state: SchedulerHealthState::Installed,
            details: format!("LaunchAgent installed and loaded: {}", plist_path.display()),
            remediation: "Use `cadence monitor disable` to stop runs or `cadence monitor uninstall` to remove scheduler artifacts.".to_string(),
        },
        Ok(false) => SchedulerHealth {
            state: SchedulerHealthState::Broken,
            details: format!("LaunchAgent exists but is not loaded: {}", plist_path.display()),
            remediation: "Run `cadence monitor enable` or `cadence install` to load it."
                .to_string(),
        },
        Err(err) => SchedulerHealth {
            state: SchedulerHealthState::Broken,
            details: format!("LaunchAgent exists but health probe failed: {err:#}"),
            remediation: "Run `cadence monitor enable` or `cadence install` to repair it."
                .to_string(),
        },
    }
}

#[cfg(target_os = "macos")]
async fn scheduler_health_macos() -> SchedulerHealth {
    let plist_path = match macos_launch_agent_path() {
        Ok(path) => path,
        Err(err) => {
            return SchedulerHealth {
                state: SchedulerHealthState::Broken,
                details: format!("launch agent path unavailable: {err}"),
                remediation: "Run `cadence install` to repair monitor setup.".to_string(),
            };
        }
    };
    if !tokio::fs::try_exists(&plist_path).await.unwrap_or(false) {
        return SchedulerHealth {
            state: SchedulerHealthState::Missing,
            details: format!("LaunchAgent missing: {}", plist_path.display()),
            remediation: "Run `cadence monitor enable` or `cadence install` to create it."
                .to_string(),
        };
    }
    let contents = tokio::fs::read_to_string(&plist_path)
        .await
        .unwrap_or_default();
    macos_scheduler_health_from_probe(
        &plist_path,
        &contents,
        macos_launch_agent_loaded(MACOS_LAUNCH_AGENT_LABEL).await,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::EnvGuard;
    use serial_test::serial;
    use tempfile::TempDir;

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_launch_agent_disabled_from_output_parses_enabled_and_disabled() {
        assert_eq!(
            macos_launch_agent_disabled_from_output(
                "\t\t\"ai.teamcadence.cadence.monitor\" => disabled",
                MACOS_LAUNCH_AGENT_LABEL,
            ),
            Some(true)
        );
        assert_eq!(
            macos_launch_agent_disabled_from_output(
                "\t\t\"ai.teamcadence.cadence.monitor\" => enabled",
                MACOS_LAUNCH_AGENT_LABEL,
            ),
            Some(false)
        );
        assert_eq!(
            macos_launch_agent_disabled_from_output(
                "\t\t\"some.other.label\" => enabled",
                MACOS_LAUNCH_AGENT_LABEL,
            ),
            None
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[serial]
    fn running_under_monitor_launch_agent_detects_matching_xpc_service_name() {
        let guard = EnvGuard::new("XPC_SERVICE_NAME");
        guard.set_str(MACOS_LAUNCH_AGENT_LABEL);
        assert!(running_under_monitor_launch_agent());

        guard.set_str("some.other.label");
        assert!(!running_under_monitor_launch_agent());
    }

    #[tokio::test]
    #[serial]
    async fn monitor_state_round_trips_enabled_and_health_fields() {
        let dir = TempDir::new().expect("tempdir");
        let home = EnvGuard::new("HOME");
        home.set_path(dir.path());

        let state = MonitorState {
            enabled: true,
            last_run_at: Some("2026-03-26T00:00:00Z".to_string()),
            last_success_at: Some("2026-03-26T00:00:01Z".to_string()),
            last_error: Some("none".to_string()),
            last_discovered: 4,
            last_uploaded: 2,
            last_queued: 1,
            last_skipped: 1,
            last_issues: 0,
            last_pending_attempted: 3,
            last_pending_uploaded: 2,
            filtered_session_throttle: BTreeMap::from([(
                "alpha".to_string(),
                FilteredSessionThrottleEntry {
                    updated_at_epoch: 123,
                    reason: FilteredSessionReason::RepoDisabled,
                    next_recheck_at_epoch: 456,
                },
            )]),
        };
        save_state(&state).await.expect("save state");

        let loaded = load_state().await.expect("load state");
        assert!(loaded.enabled);
        assert_eq!(loaded.last_uploaded, 2);
        assert_eq!(loaded.last_pending_attempted, 3);
        assert_eq!(loaded.filtered_session_throttle.len(), 1);
        assert_eq!(
            loaded
                .filtered_session_throttle
                .get("alpha")
                .expect("throttle entry")
                .reason,
            FilteredSessionReason::RepoDisabled
        );
    }

    #[tokio::test]
    #[serial]
    async fn discovery_cursor_round_trips_latest_position() {
        let dir = TempDir::new().expect("tempdir");
        let home = EnvGuard::new("HOME");
        home.set_path(dir.path());

        upsert_discovery_cursor(123, Some("alpha"))
            .await
            .expect("write cursor");
        let record = load_discovery_cursor()
            .await
            .expect("load cursor")
            .expect("cursor record");

        assert_eq!(record.last_scanned_mtime_epoch, 123);
        assert_eq!(record.last_scanned_source_label.as_deref(), Some("alpha"));
    }

    #[test]
    fn cadence_defaults_match_platform_policy() {
        if cfg!(windows) {
            assert_eq!(cadence_secs(), 60);
        } else {
            assert_eq!(cadence_secs(), 30);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_service_targets_monitor_tick() {
        let service = systemd_service_contents(Path::new("/usr/local/bin/cadence"));
        assert!(service.contains("ExecStart=/usr/local/bin/cadence monitor tick"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_scheduler_health_reports_installed_when_launch_agent_is_loaded() {
        let health = macos_scheduler_health_from_probe(
            Path::new("/tmp/cadence-monitor.plist"),
            "<string>monitor</string><string>tick</string>",
            Ok(true),
        );
        assert_eq!(health.state, SchedulerHealthState::Installed);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launch_agent_plist_does_not_write_monitor_logs_to_tmp() {
        let plist = launch_agent_plist(
            "ai.teamcadence.cadence.monitor",
            Path::new("/usr/local/bin/cadence"),
        );
        assert!(!plist.contains("/tmp/cadence-monitor.log"));
        assert!(plist.contains("<string>monitor</string>"));
        assert!(plist.contains("<string>tick</string>"));
    }

    #[test]
    fn windows_task_query_missing_detection_matches_scheduler_errors() {
        assert!(windows_task_query_reports_missing(
            "ERROR: The system cannot find the file specified."
        ));
        assert!(windows_task_query_reports_missing(
            "ERROR: The task does not exist."
        ));
        assert!(!windows_task_query_reports_missing(
            "ERROR: Access is denied."
        ));
    }
}
