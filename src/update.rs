//! Self-update version checking and helper-driven installation for cadence-cli.
//!
//! Queries the GitHub Releases API to determine if a newer version is available,
//! and provides a full self-update flow: download, checksum verification,
//! archive extraction, and manifest-driven installation via `cadence-updater`.
//!
//! The production endpoint is `GITHUB_RELEASES_LATEST_URL`. Tests inject a
//! local HTTP server URL via `check_latest_version_from_url()`.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Output;
use std::process::Stdio;
use std::time::Duration;
use sysinfo::{Pid, System};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::config::CliConfig;
use crate::state_files;
use crate::transport;

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{CloseHandle, WAIT_TIMEOUT},
    Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW},
    System::Threading::{OpenProcess, WaitForSingleObject},
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Production GitHub Releases URL for cadence-cli.
///
/// Uses the web URL (not the API) so that the redirect to the latest tag
/// can be followed without hitting GitHub API rate limits.
pub const GITHUB_RELEASES_LATEST_URL: &str =
    "https://github.com/TeamCadenceAI/cadence-cli/releases/latest";
const TEST_RELEASE_URL_ENV: &str = "CADENCE_TEST_RELEASE_URL";

/// User-Agent header sent with GitHub API requests.
const USER_AGENT: &str = "cadence-cli";

/// HTTP request timeout for version checks.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Updater state file name under `~/.cadence/cli/`.
const UPDATER_STATE_FILE: &str = "updater-state.json";
const UPDATE_STAGING_DIR: &str = "update-staging";
const UPDATE_MANIFEST_FILE: &str = "install-manifest.json";
const UPDATE_IN_PROGRESS_FILE: &str = "update-in-progress.json";
#[cfg(windows)]
const UPDATE_HELPER_RUNTIME_DIR: &str = "update-helper-runtime";

/// Shared activity lock directory/file for hook + deferred sync + updater coordination.
const ACTIVITY_LOCKS_DIR: &str = "locks";
const ACTIVITY_LOCK_FILE: &str = "global-activity.lock";
#[cfg(test)]
const ACTIVITY_LOCK_BLOCKING_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(not(test))]
const ACTIVITY_LOCK_BLOCKING_TIMEOUT: Duration = Duration::from_secs(5 * 60);
#[cfg(test)]
const ACTIVITY_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(20);
#[cfg(not(test))]
const ACTIVITY_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(100);
#[cfg(windows)]
const WINDOWS_SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

/// Retry backoff defaults.
const UPDATE_RETRY_BASE_SECS: u64 = 60;
const UPDATE_RETRY_MAX_SECS: u64 = 8 * 60 * 60;
const UPDATER_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(100);
const UPDATER_WAIT_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(target_os = "linux")]
const SYSTEMD_HELPER_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActivityLockRecord {
    pid: u32,
    #[serde(default)]
    process_started_at_epoch: Option<u64>,
    created_at_epoch: i64,
    hostname: String,
    purpose: String,
}

#[derive(Debug)]
pub struct ActivityLockGuard {
    path: PathBuf,
}

impl Drop for ActivityLockGuard {
    fn drop(&mut self) {
        if release_process_local_activity_lock(&self.path) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdaterState {
    pub last_check_at: Option<String>,
    pub last_attempt_at: Option<String>,
    pub last_success_at: Option<String>,
    pub last_seen_version: Option<String>,
    pub last_installed_version: Option<String>,
    pub consecutive_failures: u32,
    pub next_retry_after: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdaterHealthState {
    Disabled,
    NeverRun,
    Healthy,
    Retrying,
    Failing,
}

#[derive(Debug, Clone)]
pub struct UpdaterHealth {
    pub enabled: bool,
    pub state: UpdaterHealthState,
    pub last_result: String,
    pub last_attempt_at: Option<String>,
    pub next_retry_after: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InstallMode {
    Interactive,
    SilentUnattended,
}

#[derive(Debug, Clone, Copy)]
enum AttemptOutcome {
    NoUpdate,
    HelperLaunched,
    Installed,
    SkippedUnstable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct UpdateInstallManifest {
    target_version: String,
    staged_cadence_path: PathBuf,
    final_cadence_path: PathBuf,
    wait_for_pid: u32,
    #[serde(default)]
    wait_for_pid_started_at_epoch: Option<u64>,
    preserve_disable_state: bool,
    mode: InstallMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct UpdateInProgressRecord {
    target_version: String,
    final_cadence_path: PathBuf,
    initiator_pid: u32,
    #[serde(default)]
    initiator_started_at_epoch: Option<u64>,
    helper_pid: Option<u32>,
    #[serde(default)]
    helper_started_at_epoch: Option<u64>,
    #[serde(default)]
    helper_systemd_unit: Option<String>,
    created_at_epoch: i64,
}

#[derive(Debug)]
struct UpdaterHelperLaunch {
    child: Option<tokio::process::Child>,
    helper_pid: Option<u32>,
    helper_started_at_epoch: Option<u64>,
    helper_systemd_unit: Option<String>,
}

impl UpdaterHelperLaunch {
    async fn abort(mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }

        #[cfg(target_os = "linux")]
        if let Some(unit_name) = self.helper_systemd_unit.as_deref() {
            stop_systemd_user_unit(unit_name).await;
        }
    }
}

#[derive(Debug, Clone)]
struct ExtractedReleasePayload {
    cadence_binary: PathBuf,
    updater_binary: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateCommandStatus {
    Completed,
    HandoffPending,
}

pub const UPDATE_HELPER_PENDING_EXIT_CODE: i32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyAutoUpdateCleanupDisposition {
    Attempted,
    Deferred,
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// Parsed metadata from a GitHub release response.
///
/// Uses `#[serde(default)]` on non-critical fields to tolerate schema expansion
/// and missing optional data without failing deserialization.
#[derive(Debug, Deserialize)]
pub struct LatestRelease {
    /// The git tag for this release (e.g., "v0.3.0").
    pub tag_name: String,

    /// Release assets (binaries, checksums, etc.).
    #[serde(default)]
    pub assets: Vec<ReleaseAsset>,
}

/// A single downloadable asset attached to a GitHub release.
#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseAsset {
    /// Filename of the asset (e.g., "cadence-cli-x86_64-unknown-linux-gnu.tar.gz").
    pub name: String,

    /// Direct download URL for the asset.
    pub browser_download_url: String,
}

/// Filename of the checksums file published alongside release assets.
const CHECKSUMS_FILENAME: &str = "checksums-sha256.txt";

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn host_name() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string())
}

fn parse_rfc3339_to_epoch(value: &str) -> Option<i64> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|dt| dt.unix_timestamp())
}

fn format_epoch_rfc3339(epoch: i64) -> Option<String> {
    time::OffsetDateTime::from_unix_timestamp(epoch)
        .ok()
        .and_then(|dt| {
            dt.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
}

fn updater_state_path() -> Result<PathBuf> {
    Ok(state_files::cadence_dir()?.join(UPDATER_STATE_FILE))
}

fn update_in_progress_path() -> Result<PathBuf> {
    Ok(state_files::cadence_dir()?.join(UPDATE_IN_PROGRESS_FILE))
}

fn activity_lock_path() -> Result<PathBuf> {
    Ok(state_files::cadence_dir()?
        .join(ACTIVITY_LOCKS_DIR)
        .join(ACTIVITY_LOCK_FILE))
}

fn updater_staging_root() -> PathBuf {
    match state_files::cadence_dir() {
        Ok(path) => path.join(UPDATE_STAGING_DIR),
        Err(_) => std::env::temp_dir()
            .join("cadence-cli")
            .join(UPDATE_STAGING_DIR),
    }
}

#[cfg(windows)]
fn updater_helper_runtime_root() -> PathBuf {
    match state_files::cadence_dir() {
        Ok(path) => path.join(UPDATE_HELPER_RUNTIME_DIR),
        Err(_) => std::env::temp_dir()
            .join("cadence-cli")
            .join(UPDATE_HELPER_RUNTIME_DIR),
    }
}

fn process_local_activity_lock_counts()
-> &'static std::sync::Mutex<std::collections::HashMap<PathBuf, usize>> {
    static COUNTS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<PathBuf, usize>>,
    > = std::sync::OnceLock::new();
    COUNTS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn retain_process_local_activity_lock(path: &Path) {
    let mut counts = process_local_activity_lock_counts()
        .lock()
        .expect("activity lock state");
    *counts.entry(path.to_path_buf()).or_insert(0) += 1;
}

fn release_process_local_activity_lock(path: &Path) -> bool {
    let mut counts = process_local_activity_lock_counts()
        .lock()
        .expect("activity lock state");
    match counts.get_mut(path) {
        Some(count) if *count > 1 => {
            *count -= 1;
            false
        }
        Some(_) => {
            counts.remove(path);
            true
        }
        None => false,
    }
}

async fn create_update_staging_dir(target_version: &str) -> Result<PathBuf> {
    let root = updater_staging_root();
    let version = normalize_version_tag(target_version);
    let dir = root.join(format!(
        "{}-{}-{}",
        version,
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    tokio::fs::create_dir_all(&dir).await.with_context(|| {
        format!(
            "failed to create update staging directory {}",
            dir.display()
        )
    })?;
    Ok(dir)
}

async fn load_install_manifest(path: &Path) -> Result<UpdateInstallManifest> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read install manifest {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("failed to parse install manifest {}", path.display()))
}

async fn write_install_manifest(path: &Path, manifest: &UpdateInstallManifest) -> Result<()> {
    state_files::write_json_atomic(path, manifest).await
}

async fn load_updater_state() -> Result<UpdaterState> {
    let path = updater_state_path()?;
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => serde_json::from_str::<UpdaterState>(&content)
            .with_context(|| format!("failed to parse updater state at {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UpdaterState::default()),
        Err(e) => {
            Err(e).with_context(|| format!("failed to read updater state {}", path.display()))
        }
    }
}

async fn save_updater_state(state: &UpdaterState) -> Result<()> {
    let path = updater_state_path()?;
    state_files::write_json_atomic(&path, state).await
}

async fn load_update_in_progress_record(path: &Path) -> Result<Option<UpdateInProgressRecord>> {
    match tokio::fs::read_to_string(path).await {
        Ok(content) => serde_json::from_str::<UpdateInProgressRecord>(&content)
            .map(Some)
            .with_context(|| {
                format!(
                    "failed to parse update in-progress marker {}",
                    path.display()
                )
            }),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| {
            format!(
                "failed to read update in-progress marker {}",
                path.display()
            )
        }),
    }
}

async fn write_update_in_progress_record(record: &UpdateInProgressRecord) -> Result<()> {
    let path = update_in_progress_path()?;
    state_files::write_json_atomic(&path, record).await
}

async fn clear_update_in_progress_record() -> Result<()> {
    let path = update_in_progress_path()?;
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => {
            Err(err).with_context(|| format!("failed to remove update marker {}", path.display()))
        }
    }
}

fn current_process_started_at_epoch() -> Option<u64> {
    process_started_at_epoch(std::process::id())
}

fn process_started_at_epoch(pid: u32) -> Option<u64> {
    if pid == 0 {
        return None;
    }

    let mut system = System::new();
    system.refresh_processes();
    system
        .process(Pid::from_u32(pid))
        .map(|process| process.start_time())
}

pub(crate) fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        if pid == 0 {
            return false;
        }
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if result == 0 {
            return true;
        }
        matches!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM))
    }

    #[cfg(windows)]
    {
        if pid == 0 {
            return false;
        }
        let handle = unsafe { OpenProcess(WINDOWS_SYNCHRONIZE_ACCESS, 0, pid) };
        if handle.is_null() {
            return false;
        }
        let alive = unsafe { WaitForSingleObject(handle, 0) == WAIT_TIMEOUT };
        unsafe {
            CloseHandle(handle);
        }
        alive
    }

    #[cfg(not(any(unix, windows)))]
    {
        let mut system = System::new();
        system.refresh_processes();
        system.process(Pid::from_u32(pid)).is_some()
    }
}

fn pid_matches_recorded_process_start(pid: u32, expected_start: Option<u64>) -> bool {
    if !is_pid_alive(pid) {
        return false;
    }
    match expected_start {
        Some(expected) => process_started_at_epoch(pid) == Some(expected),
        None => true,
    }
}

#[cfg(target_os = "linux")]
fn running_under_systemd_unit() -> bool {
    std::env::var_os("INVOCATION_ID").is_some()
}

#[cfg(target_os = "linux")]
fn systemd_user_manager_available() -> bool {
    let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) else {
        return false;
    };
    runtime_dir.join("bus").exists() || runtime_dir.join("systemd").join("private").exists()
}

#[cfg(target_os = "linux")]
fn should_launch_helper_via_systemd_run() -> bool {
    running_under_systemd_unit() && systemd_user_manager_available()
}

#[cfg(target_os = "linux")]
fn sanitize_systemd_unit_component(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

#[cfg(target_os = "linux")]
fn updater_systemd_unit_name(target_version: &str) -> String {
    format!(
        "cadence-updater-{}-{}-{}.service",
        sanitize_systemd_unit_component(normalize_version_tag(target_version)),
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    )
}

#[cfg(target_os = "linux")]
async fn systemd_user_unit_property(unit_name: &str, property: &str) -> Result<Option<String>> {
    let output = tokio::time::timeout(
        SYSTEMD_HELPER_QUERY_TIMEOUT,
        Command::new("systemctl")
            .args([
                "--user",
                "show",
                "--value",
                "--property",
                property,
                unit_name,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .with_context(|| {
        format!("timed out querying systemd user unit property {property} for {unit_name}")
    })?
    .with_context(|| format!("failed to query systemd user unit property {property}"))?;

    if !output.status.success() {
        return Ok(None);
    }

    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        return Ok(None);
    }

    Ok(Some(value))
}

#[cfg(target_os = "linux")]
async fn systemd_user_unit_main_pid(unit_name: &str) -> Result<Option<u32>> {
    let Some(value) = systemd_user_unit_property(unit_name, "MainPID").await? else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed == "0" {
        return Ok(None);
    }
    trimmed
        .parse::<u32>()
        .map(Some)
        .with_context(|| format!("failed to parse systemd MainPID '{trimmed}' for {unit_name}"))
}

#[cfg(target_os = "linux")]
async fn systemd_user_unit_is_active(unit_name: &str) -> bool {
    match systemd_user_unit_property(unit_name, "ActiveState").await {
        Ok(Some(state)) => matches!(state.as_str(), "active" | "activating" | "reloading"),
        _ => false,
    }
}

#[cfg(target_os = "linux")]
async fn wait_for_systemd_user_unit_main_pid(
    unit_name: &str,
    timeout: Duration,
) -> Result<Option<u32>> {
    let started = tokio::time::Instant::now();
    loop {
        if let Some(pid) = systemd_user_unit_main_pid(unit_name).await? {
            return Ok(Some(pid));
        }
        if started.elapsed() >= timeout {
            return Ok(None);
        }
        tokio::time::sleep(UPDATER_WAIT_POLL_INTERVAL).await;
    }
}

#[cfg(target_os = "linux")]
async fn stop_systemd_user_unit(unit_name: &str) {
    let _ = tokio::time::timeout(
        SYSTEMD_HELPER_QUERY_TIMEOUT,
        Command::new("systemctl")
            .args(["--user", "stop", unit_name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    )
    .await;
}

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

async fn try_create_activity_lock(path: &Path, record: &ActivityLockRecord) -> Result<bool> {
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    let file = opts.open(path).await;
    let mut file = match file {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(err) => return Err(err).with_context(|| format!("create lock {}", path.display())),
    };
    let payload = serde_json::to_vec_pretty(record).context("serialize lock record")?;
    tokio::io::AsyncWriteExt::write_all(&mut file, &payload).await?;
    Ok(true)
}

async fn read_activity_lock_record(path: &Path) -> Result<Option<ActivityLockRecord>> {
    let content = match tokio::fs::read_to_string(path).await {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("read lock {}", path.display()));
        }
    };

    serde_json::from_str::<ActivityLockRecord>(&content)
        .map(Some)
        .with_context(|| format!("parse lock {}", path.display()))
}

async fn activity_lock_owned_by_current_process(path: &Path) -> Result<bool> {
    let Some(record) = read_activity_lock_record(path).await? else {
        return Ok(false);
    };
    if record.pid != std::process::id() {
        return Ok(false);
    }
    if let Some(expected_start) = record.process_started_at_epoch
        && current_process_started_at_epoch() != Some(expected_start)
    {
        return Ok(false);
    }
    Ok(true)
}

async fn clear_stale_activity_lock(path: &Path) -> Result<()> {
    let parsed = match read_activity_lock_record(path).await {
        Ok(Some(parsed)) => parsed,
        Ok(None) => return Ok(()),
        Err(_) => {
            let _ = tokio::fs::remove_file(path).await;
            return Ok(());
        }
    };
    if !is_pid_alive(parsed.pid) {
        let _ = tokio::fs::remove_file(path).await;
        return Ok(());
    }
    if let Some(expected_start) = parsed.process_started_at_epoch
        && process_started_at_epoch(parsed.pid) != Some(expected_start)
    {
        let _ = tokio::fs::remove_file(path).await;
    }
    Ok(())
}

async fn current_update_in_progress_record() -> Result<Option<UpdateInProgressRecord>> {
    let path = update_in_progress_path()?;
    let Some(record) = load_update_in_progress_record(&path).await? else {
        return Ok(None);
    };
    let initiator_active =
        pid_matches_recorded_process_start(record.initiator_pid, record.initiator_started_at_epoch);
    let helper_active = record
        .helper_pid
        .is_some_and(|pid| pid_matches_recorded_process_start(pid, record.helper_started_at_epoch));
    #[cfg(target_os = "linux")]
    let helper_unit_active = if helper_active {
        false
    } else if let Some(unit_name) = record.helper_systemd_unit.as_deref() {
        systemd_user_unit_is_active(unit_name).await
    } else {
        false
    };
    #[cfg(not(target_os = "linux"))]
    let helper_unit_active = false;

    if initiator_active || helper_active || helper_unit_active {
        return Ok(Some(record));
    }
    let _ = tokio::fs::remove_file(&path).await;
    Ok(None)
}

fn update_in_progress_error(record: &UpdateInProgressRecord) -> anyhow::Error {
    anyhow::anyhow!(
        "cadence update to v{} is in progress; retry shortly",
        record.target_version
    )
}

fn update_in_progress_bypass_enabled() -> bool {
    std::env::var("CADENCE_INTERNAL_ALLOW_UPDATE_IN_PROGRESS")
        .ok()
        .as_deref()
        == Some("1")
}

fn activity_lock_record(purpose: &str) -> ActivityLockRecord {
    ActivityLockRecord {
        pid: std::process::id(),
        process_started_at_epoch: current_process_started_at_epoch(),
        created_at_epoch: now_epoch(),
        hostname: host_name(),
        purpose: purpose.to_string(),
    }
}

async fn acquire_activity_lock_blocking_with_timeout(
    purpose: &str,
    timeout: Duration,
    fail_if_update_in_progress: bool,
) -> Result<ActivityLockGuard> {
    let lock_path = activity_lock_path()?;
    if let Some(parent) = lock_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let record = activity_lock_record(purpose);
    let started_at = tokio::time::Instant::now();
    loop {
        if fail_if_update_in_progress
            && !update_in_progress_bypass_enabled()
            && let Some(record) = current_update_in_progress_record().await?
        {
            return Err(update_in_progress_error(&record));
        }
        if try_create_activity_lock(&lock_path, &record).await? {
            retain_process_local_activity_lock(&lock_path);
            return Ok(ActivityLockGuard { path: lock_path });
        }
        if activity_lock_owned_by_current_process(&lock_path).await? {
            retain_process_local_activity_lock(&lock_path);
            return Ok(ActivityLockGuard { path: lock_path });
        }
        clear_stale_activity_lock(&lock_path).await?;
        let elapsed = started_at.elapsed();
        if elapsed >= timeout {
            bail!(
                "timed out waiting for global activity lock after {:?} ({purpose})",
                timeout
            );
        }
        let remaining = timeout.saturating_sub(elapsed);
        tokio::time::sleep(remaining.min(ACTIVITY_LOCK_POLL_INTERVAL)).await;
    }
}

pub async fn acquire_command_activity_lock(purpose: &str) -> Result<ActivityLockGuard> {
    acquire_activity_lock_blocking_with_timeout(purpose, ACTIVITY_LOCK_BLOCKING_TIMEOUT, true).await
}

pub async fn acquire_activity_lock_blocking(purpose: &str) -> Result<ActivityLockGuard> {
    acquire_activity_lock_blocking_with_timeout(purpose, ACTIVITY_LOCK_BLOCKING_TIMEOUT, false)
        .await
}

pub async fn try_acquire_activity_lock_nonblocking(
    purpose: &str,
) -> Result<Option<ActivityLockGuard>> {
    let lock_path = activity_lock_path()?;
    if let Some(parent) = lock_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    clear_stale_activity_lock(&lock_path).await?;
    let record = activity_lock_record(purpose);
    if try_create_activity_lock(&lock_path, &record).await? {
        retain_process_local_activity_lock(&lock_path);
        return Ok(Some(ActivityLockGuard { path: lock_path }));
    }
    if activity_lock_owned_by_current_process(&lock_path).await? {
        retain_process_local_activity_lock(&lock_path);
        return Ok(Some(ActivityLockGuard { path: lock_path }));
    }
    Ok(None)
}

fn retry_delay_secs(failures: u32) -> u64 {
    let exp = failures.saturating_sub(1).min(10);
    let base = UPDATE_RETRY_BASE_SECS.saturating_mul(1u64 << exp);
    let capped = base.min(UPDATE_RETRY_MAX_SECS);
    let jitter = rand08::Rng::gen_range(&mut rand08::thread_rng(), 0..=45);
    capped.saturating_add(jitter)
}

fn is_stable_release_tag(tag: &str) -> bool {
    let normalized = normalize_version_tag(tag);
    semver::Version::parse(normalized)
        .map(|v| v.pre.is_empty())
        .unwrap_or(false)
}

fn update_due_for_retry(state: &UpdaterState, now_epoch_secs: i64) -> bool {
    let Some(next_retry) = &state.next_retry_after else {
        return true;
    };
    let Some(retry_epoch) = parse_rfc3339_to_epoch(next_retry) else {
        return true;
    };
    now_epoch_secs >= retry_epoch
}

// ---------------------------------------------------------------------------
// Version helpers
// ---------------------------------------------------------------------------

/// Returns the compiled-in package version (from Cargo.toml at build time).
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Strips an optional leading `v` or `V` from a version tag.
///
/// GitHub tags commonly use a `v` prefix (e.g., "v0.3.0") while Cargo versions
/// do not. This normalizer ensures consistent parsing.
pub fn normalize_version_tag(tag: &str) -> &str {
    let trimmed = tag.trim();
    trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed)
}

/// Compares two version strings using semver.
///
/// Both `local` and `remote` are normalized (leading `v` stripped) before parsing.
/// Returns `Ordering::Less` if `local < remote` (update available),
/// `Ordering::Equal` if they match, and `Ordering::Greater` if local is newer.
///
/// Returns an error if either version string is not valid semver.
pub fn compare_versions(local: &str, remote: &str) -> Result<Ordering> {
    let local_normalized = normalize_version_tag(local);
    let remote_normalized = normalize_version_tag(remote);

    let local_ver = semver::Version::parse(local_normalized)
        .with_context(|| format!("Failed to parse local version '{local}' as semver"))?;
    let remote_ver = semver::Version::parse(remote_normalized)
        .with_context(|| format!("Failed to parse remote version '{remote}' as semver"))?;

    Ok(local_ver.cmp(&remote_ver))
}

// ---------------------------------------------------------------------------
// Release discovery via HTTP redirect
// ---------------------------------------------------------------------------

/// Fetches the latest release metadata from the production GitHub endpoint.
pub async fn check_latest_version() -> Result<LatestRelease> {
    let release_url = effective_latest_release_url();
    check_latest_version_from_url(&release_url).await
}

/// Fetches the latest release metadata from a given URL.
///
/// Discovers the latest version by following the HTTP redirect from a GitHub
/// releases/latest page, then constructs download URLs for all platform
/// artifacts. This avoids the GitHub API and its rate limits.
///
/// This is the injectable entry point used by tests. The URL should return
/// a 3xx redirect whose Location header ends with the version tag.
pub async fn check_latest_version_from_url(url: &str) -> Result<LatestRelease> {
    let tag = discover_latest_tag(url, REQUEST_TIMEOUT).await?;
    let repo_base = repo_base_from_releases_url(url);
    Ok(build_release_from_tag(&tag, repo_base))
}

/// Discovers the latest release tag by following the GitHub redirect.
///
/// Sends a request to the releases/latest URL and extracts the version tag
/// from the redirect `Location` header without actually following it. This
/// is efficient (single request) and avoids the GitHub API entirely.
async fn discover_latest_tag(url: &str, timeout: Duration) -> Result<String> {
    let client = transport::build_client(
        reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none()),
        "update HTTP client",
    )
    .await?;
    let response = client
        .get(url)
        .send()
        .await
        .context("Failed to connect to release server")?;

    let status = response.status();
    if !status.is_redirection() {
        bail!("Release server returned HTTP {status} — expected a redirect to the latest release");
    }

    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .ok_or_else(|| anyhow::anyhow!("Redirect response missing Location header"))?
        .to_str()
        .context("Location header is not valid UTF-8")?;

    // Extract tag from URL like: https://github.com/REPO/releases/tag/v0.4.1
    let tag = location
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("Could not extract version tag from redirect URL: {location}")
        })?;

    Ok(tag.to_string())
}

/// Constructs a `LatestRelease` from a discovered tag and repo base URL.
///
/// Builds download URLs for all supported platform artifacts and the checksums
/// file using the pattern: `{repo_base}/releases/download/{tag}/{filename}`.
pub fn build_release_from_tag(tag: &str, repo_base_url: &str) -> LatestRelease {
    let download_base = format!("{repo_base_url}/releases/download/{tag}");

    let targets = [
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
        "aarch64-pc-windows-msvc",
    ];

    let mut assets: Vec<ReleaseAsset> = targets
        .iter()
        .map(|t| {
            let name = expected_artifact_name(t);
            ReleaseAsset {
                browser_download_url: format!("{download_base}/{name}"),
                name,
            }
        })
        .collect();

    assets.push(ReleaseAsset {
        name: CHECKSUMS_FILENAME.to_string(),
        browser_download_url: format!("{download_base}/{CHECKSUMS_FILENAME}"),
    });

    LatestRelease {
        tag_name: tag.to_string(),
        assets,
    }
}

/// Strips `/releases/latest` suffix to derive the repository base URL.
///
/// For production URLs like `https://github.com/REPO/releases/latest`, this
/// returns `https://github.com/REPO`. For test URLs without that suffix, the
/// URL is returned unchanged.
fn repo_base_from_releases_url(url: &str) -> &str {
    url.strip_suffix("/releases/latest").unwrap_or(url)
}

fn effective_latest_release_url() -> String {
    std::env::var(TEST_RELEASE_URL_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| GITHUB_RELEASES_LATEST_URL.to_string())
}

// ---------------------------------------------------------------------------
// Artifact selection
// ---------------------------------------------------------------------------

/// Returns the compile-time target triple (e.g., "aarch64-apple-darwin").
pub fn build_target() -> &'static str {
    env!("TARGET")
}

fn cadence_binary_name(target: &str) -> &'static str {
    if target.contains("windows") {
        "cadence.exe"
    } else {
        BINARY_NAME
    }
}

fn updater_binary_name(target: &str) -> &'static str {
    if target.contains("windows") {
        "cadence-updater.exe"
    } else {
        "cadence-updater"
    }
}

/// Determines the expected archive extension for a given target triple.
/// Windows and macOS targets use `.zip`, Linux targets use `.tar.gz`.
pub fn archive_extension_for_target(target: &str) -> &'static str {
    if target.contains("windows") || target.contains("apple-darwin") {
        ".zip"
    } else {
        ".tar.gz"
    }
}

/// Constructs the canonical release artifact filename for a target triple.
///
/// Matches the naming convention in the release workflow:
/// `cadence-cli-{target}.tar.gz` (Unix) or `cadence-cli-{target}.zip` (Windows).
pub fn expected_artifact_name(target: &str) -> String {
    format!(
        "cadence-cli-{target}{}",
        archive_extension_for_target(target)
    )
}

/// Selects the release asset matching the given target triple.
///
/// Searches the asset list for an exact filename match using the canonical
/// naming pattern `cadence-cli-{target}.{ext}`.
pub fn pick_artifact_for_target(assets: &[ReleaseAsset], target: &str) -> Result<ReleaseAsset> {
    let expected = expected_artifact_name(target);
    assets
        .iter()
        .find(|a| a.name == expected)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No release asset found for target '{target}' (expected '{expected}'). \
                 Available assets: [{}]",
                assets
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

/// Finds the checksums asset in the release.
pub fn pick_checksums_asset(assets: &[ReleaseAsset]) -> Result<ReleaseAsset> {
    assets
        .iter()
        .find(|a| a.name == CHECKSUMS_FILENAME)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Release is missing '{CHECKSUMS_FILENAME}' asset. \
                 Cannot verify download integrity."
            )
        })
}

// ---------------------------------------------------------------------------
// HTTP download helpers
// ---------------------------------------------------------------------------

/// Builds a reqwest client with the shared Cadence trust configuration.
async fn build_http_client() -> Result<reqwest::Client> {
    transport::build_client(
        reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(120)),
        "download HTTP client",
    )
    .await
}

/// Downloads a URL to a file in the given directory. Returns the file path.
pub async fn download_to_file(url: &str, dest_dir: &Path, filename: &str) -> Result<PathBuf> {
    let client = build_http_client().await?;
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to connect to download server for '{filename}'"))?;

    let status = response.status();
    if !status.is_success() {
        bail!("Download of '{filename}' failed: HTTP {status} from {url}");
    }

    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("Failed to read response body for '{filename}'"))?;

    let dest_path = dest_dir.join(filename);
    tokio::fs::write(&dest_path, &bytes)
        .await
        .with_context(|| format!("Failed to write '{filename}' to {}", dest_path.display()))?;

    Ok(dest_path)
}

// ---------------------------------------------------------------------------
// Checksum parsing and verification
// ---------------------------------------------------------------------------

/// Parses a GNU coreutils-format checksums file into a map of filename → hex hash.
///
/// Expected format per line: `<64-hex-chars>  <filename>`
/// (two spaces between hash and filename, as produced by `sha256sum`).
/// Blank lines are skipped. Malformed lines produce an error.
pub fn parse_checksums(content: &str) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();

    for (i, line) in content.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }

        // GNU coreutils format: "<hash>  <filename>" (two spaces)
        let Some((hash, filename)) = line.split_once("  ") else {
            bail!(
                "Malformed checksum line {} (expected '<hash>  <filename>'): {line}",
                i + 1
            );
        };

        let hash = hash.trim();
        let filename = filename.trim();

        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!(
                "Invalid SHA256 hash on line {} (expected 64 hex chars, got '{hash}')",
                i + 1
            );
        }

        if filename.is_empty() {
            bail!("Empty filename on checksum line {}", i + 1);
        }

        map.insert(filename.to_string(), hash.to_lowercase());
    }

    if map.is_empty() {
        bail!("Checksums file is empty — no entries found");
    }

    Ok(map)
}

/// Computes the SHA256 digest of a file and returns it as a lowercase hex string.
pub async fn sha256_file(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("Failed to open file for checksum: {}", path.display()))?;

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .await
            .with_context(|| format!("Failed to read file for checksum: {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Verifies that a downloaded artifact matches its expected SHA256 hash.
///
/// `checksums` is the parsed map from `parse_checksums()`.
/// `artifact_name` is the filename key to look up.
/// `artifact_path` is the local file to hash.
pub async fn verify_checksum(
    checksums: &HashMap<String, String>,
    artifact_name: &str,
    artifact_path: &Path,
) -> Result<()> {
    let expected = checksums.get(artifact_name).ok_or_else(|| {
        anyhow::anyhow!(
            "Checksum entry not found for '{artifact_name}' in checksums file. \
             Available entries: [{}]",
            checksums.keys().cloned().collect::<Vec<_>>().join(", ")
        )
    })?;

    let actual = sha256_file(artifact_path).await?;

    if actual != *expected {
        bail!(
            "Checksum verification failed for '{artifact_name}':\n\
             Expected: {expected}\n\
             Actual:   {actual}\n\
             The downloaded file may be corrupted. Aborting update."
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Archive extraction
// ---------------------------------------------------------------------------

/// Binary name inside release archives (without extension).
const BINARY_NAME: &str = "cadence";

fn extract_tar_gz_payload_from_file(
    file: std::fs::File,
    archive_path: &Path,
    dest_dir: &Path,
    target: &str,
) -> Result<ExtractedReleasePayload> {
    let expected_cadence = cadence_binary_name(target);
    let expected_updater = updater_binary_name(target);
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);

    let mut cadence = None;
    let mut updater = None;

    for entry_result in archive.entries().context("Failed to read tar entries")? {
        let mut entry = entry_result.context("Failed to read tar entry")?;
        let file_name = entry
            .path()
            .context("Failed to read tar entry path")?
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();

        if file_name == expected_cadence || file_name == expected_updater {
            let dest = dest_dir.join(&file_name);
            entry
                .unpack(&dest)
                .with_context(|| format!("Failed to extract '{file_name}' from archive"))?;
            if file_name == expected_cadence {
                cadence = Some(dest);
            } else {
                updater = Some(dest);
            }
        }

        if cadence.is_some() && updater.is_some() {
            break;
        }
    }

    let cadence_binary = cadence.ok_or_else(|| {
        anyhow::anyhow!(
            "Archive does not contain '{expected_cadence}' binary: {}",
            archive_path.display()
        )
    })?;
    let updater_binary = updater.ok_or_else(|| {
        anyhow::anyhow!(
            "Archive does not contain '{expected_updater}' binary: {}",
            archive_path.display()
        )
    })?;

    Ok(ExtractedReleasePayload {
        cadence_binary,
        updater_binary,
    })
}

fn extract_zip_payload_from_file(
    file: std::fs::File,
    archive_path: &Path,
    dest_dir: &Path,
    target: &str,
) -> Result<ExtractedReleasePayload> {
    let mut archive = zip::ZipArchive::new(file).context("Failed to read zip archive")?;
    let expected_cadence = cadence_binary_name(target);
    let expected_updater = updater_binary_name(target);
    let mut cadence = None;
    let mut updater = None;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).context("Failed to read zip entry")?;

        let entry_name = entry.name().to_string();
        let file_name = Path::new(&entry_name)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if file_name == expected_cadence || file_name == expected_updater {
            let dest = dest_dir.join(file_name);
            let mut out_file = std::fs::File::create(&dest)
                .with_context(|| format!("Failed to create extracted file: {}", dest.display()))?;
            io::copy(&mut entry, &mut out_file).context("Failed to write extracted binary")?;
            if file_name == expected_cadence {
                cadence = Some(dest);
            } else {
                updater = Some(dest);
            }
        }

        if cadence.is_some() && updater.is_some() {
            break;
        }
    }

    let cadence_binary = cadence.ok_or_else(|| {
        anyhow::anyhow!(
            "Archive does not contain '{expected_cadence}' binary: {}",
            archive_path.display()
        )
    })?;
    let updater_binary = updater.ok_or_else(|| {
        anyhow::anyhow!(
            "Archive does not contain '{expected_updater}' binary: {}",
            archive_path.display()
        )
    })?;

    Ok(ExtractedReleasePayload {
        cadence_binary,
        updater_binary,
    })
}

async fn extract_release_payload(
    archive_path: &Path,
    dest_dir: &Path,
    target: &str,
) -> Result<ExtractedReleasePayload> {
    enum ArchiveKind {
        TarGz,
        Zip,
    }

    let archive_path = archive_path.to_path_buf();
    let dest_dir = dest_dir.to_path_buf();
    let target = target.to_string();
    let name = archive_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let kind = if name.ends_with(".tar.gz") {
        ArchiveKind::TarGz
    } else if name.ends_with(".zip") {
        ArchiveKind::Zip
    } else {
        bail!(
            "Unsupported archive format: '{}'. Expected .tar.gz or .zip",
            archive_path.display()
        );
    };

    let file = tokio::fs::File::open(&archive_path)
        .await
        .with_context(|| format!("Failed to open archive: {}", archive_path.display()))?;
    let std_file = file.into_std().await;

    tokio::task::spawn_blocking(move || match kind {
        ArchiveKind::TarGz => {
            extract_tar_gz_payload_from_file(std_file, &archive_path, &dest_dir, &target)
        }
        ArchiveKind::Zip => {
            extract_zip_payload_from_file(std_file, &archive_path, &dest_dir, &target)
        }
    })
    .await
    .context("archive extraction task failed")?
}

/// Extracts the cadence binary from a release archive (tar.gz or zip).
///
/// Dispatches to the appropriate extractor based on the archive file extension.
pub async fn extract_binary(archive_path: &Path, dest_dir: &Path) -> Result<PathBuf> {
    Ok(
        extract_release_payload(archive_path, dest_dir, build_target())
            .await?
            .cadence_binary,
    )
}

fn staging_cleanup_path(manifest_path: &Path) -> Option<PathBuf> {
    manifest_path.parent().map(Path::to_path_buf)
}

async fn maybe_remove_staging_dir(manifest_path: &Path) {
    let Some(dir) = staging_cleanup_path(manifest_path) else {
        return;
    };
    if let Err(err) = tokio::fs::remove_dir_all(&dir).await {
        ::tracing::warn!(
            event = "updater_staging_cleanup_failed",
            staging_dir = dir.display().to_string(),
            error = %format!("{err:#}")
        );
    }
}

async fn wait_for_pid_to_exit(
    pid: u32,
    expected_start: Option<u64>,
    timeout: Duration,
) -> Result<()> {
    if pid == 0 {
        return Ok(());
    }

    let started = tokio::time::Instant::now();
    while pid_matches_recorded_process_start(pid, expected_start) {
        if started.elapsed() >= timeout {
            bail!("timed out waiting for cadence process {pid} to exit");
        }
        tokio::time::sleep(UPDATER_WAIT_POLL_INTERVAL).await;
    }
    Ok(())
}

fn normalize_process_path_key(path: &Path) -> String {
    let normalized = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    #[cfg(windows)]
    {
        normalized
            .to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase()
    }
    #[cfg(not(windows))]
    {
        normalized.to_string_lossy().into_owned()
    }
}

fn processes_for_executable_path(exe_path: &Path) -> Vec<(u32, Option<u64>)> {
    let expected = normalize_process_path_key(exe_path);
    let mut system = System::new();
    system.refresh_processes();
    system
        .processes()
        .iter()
        .filter_map(|(pid, process)| {
            let exe = process.exe()?;
            (normalize_process_path_key(exe) == expected)
                .then_some((pid.as_u32(), Some(process.start_time())))
        })
        .collect()
}

async fn wait_for_executable_path_to_quiesce(
    exe_path: &Path,
    ignored_processes: &[(u32, Option<u64>)],
    timeout: Duration,
) -> Result<()> {
    let exe = exe_path.to_path_buf();
    let ignored = ignored_processes.to_vec();
    let started = tokio::time::Instant::now();

    loop {
        let exe_for_scan = exe.clone();
        let running_processes =
            tokio::task::spawn_blocking(move || processes_for_executable_path(&exe_for_scan))
                .await
                .context("failed to inspect running cadence processes")?;
        let live_matches: Vec<u32> = running_processes
            .into_iter()
            .filter(|(pid, started_at_epoch)| {
                !ignored
                    .iter()
                    .any(|(ignored_pid, ignored_started_at_epoch)| {
                        *pid == *ignored_pid
                            && match ignored_started_at_epoch {
                                Some(expected) => *started_at_epoch == Some(*expected),
                                None => true,
                            }
                    })
            })
            .map(|(pid, _)| pid)
            .collect();
        if live_matches.is_empty() {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            bail!(
                "timed out waiting for exclusive ownership of {} (pids: {:?})",
                exe.display(),
                live_matches
            );
        }
        tokio::time::sleep(UPDATER_WAIT_POLL_INTERVAL).await;
    }
}

async fn set_executable_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        tokio::fs::set_permissions(path, perms)
            .await
            .with_context(|| {
                format!("failed to set executable permissions on {}", path.display())
            })?;
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

#[cfg(windows)]
fn move_file_replace_existing(from: &Path, to: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let from_wide = wide(from);
    let to_wide = wide(to);
    let result = unsafe {
        MoveFileExW(
            from_wide.as_ptr(),
            to_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        bail!(
            "failed to replace {} with {}: {}",
            to.display(),
            from.display(),
            io::Error::last_os_error()
        );
    }
    Ok(())
}

async fn install_staged_binary(staged_path: &Path, final_path: &Path) -> Result<()> {
    if !tokio::fs::try_exists(staged_path)
        .await
        .with_context(|| format!("failed to inspect staged binary {}", staged_path.display()))?
    {
        bail!("staged binary does not exist: {}", staged_path.display());
    }

    let parent = final_path.parent().ok_or_else(|| {
        anyhow::anyhow!("final install path has no parent: {}", final_path.display())
    })?;
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("failed to create install directory {}", parent.display()))?;

    let file_name = final_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "final install path has no filename: {}",
                final_path.display()
            )
        })?;
    let temp_path = parent.join(format!(
        ".{}.{}.{}.tmp",
        file_name,
        std::process::id(),
        uuid::Uuid::new_v4()
    ));

    tokio::fs::copy(staged_path, &temp_path)
        .await
        .with_context(|| {
            format!(
                "failed to stage replacement binary from {} to {}",
                staged_path.display(),
                temp_path.display()
            )
        })?;
    set_executable_permissions(&temp_path).await?;

    #[cfg(windows)]
    {
        let temp = temp_path.clone();
        let final_dest = final_path.to_path_buf();
        let replace_result = tokio::task::spawn_blocking(move || {
            if final_dest.exists() {
                move_file_replace_existing(&temp, &final_dest)
            } else {
                std::fs::rename(&temp, &final_dest).with_context(|| {
                    format!(
                        "failed to move replacement binary into final install location {}",
                        final_dest.display()
                    )
                })
            }
        })
        .await
        .context("replacement move task failed")?;
        if let Err(err) = replace_result {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(err);
        }
    }

    #[cfg(not(windows))]
    tokio::fs::rename(&temp_path, final_path)
        .await
        .with_context(|| {
            format!(
                "failed to move replacement binary into final install location {}",
                final_path.display()
            )
        })?;

    Ok(())
}

#[cfg(windows)]
async fn prepare_updater_helper_launch_path(
    helper_path: &Path,
    target_version: &str,
) -> Result<PathBuf> {
    let root = updater_helper_runtime_root();
    tokio::fs::create_dir_all(&root)
        .await
        .with_context(|| format!("failed to create helper runtime root {}", root.display()))?;
    let dir = root.join(format!(
        "{}-{}-{}",
        normalize_version_tag(target_version),
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("failed to create helper runtime dir {}", dir.display()))?;
    let launch_path = dir.join(helper_path.file_name().ok_or_else(|| {
        anyhow::anyhow!("helper path has no filename: {}", helper_path.display())
    })?);
    tokio::fs::copy(helper_path, &launch_path)
        .await
        .with_context(|| {
            format!(
                "failed to copy updater helper from {} to {}",
                helper_path.display(),
                launch_path.display()
            )
        })?;
    set_executable_permissions(&launch_path).await?;
    Ok(launch_path)
}

#[cfg(not(windows))]
async fn prepare_updater_helper_launch_path(
    helper_path: &Path,
    _target_version: &str,
) -> Result<PathBuf> {
    Ok(helper_path.to_path_buf())
}

#[cfg(unix)]
fn configure_unix_detached_spawn(command: &mut Command) {
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

async fn launch_updater_helper_as_child(
    launch_path: &Path,
    manifest_path: &Path,
) -> Result<UpdaterHelperLaunch> {
    let mut command = Command::new(launch_path);
    command
        .arg("--manifest")
        .arg(manifest_path)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    #[cfg(unix)]
    configure_unix_detached_spawn(&mut command);
    let child = command.spawn().with_context(|| {
        format!(
            "failed to launch updater helper {} with manifest {}",
            launch_path.display(),
            manifest_path.display()
        )
    })?;
    let helper_pid = child.id();
    Ok(UpdaterHelperLaunch {
        child: Some(child),
        helper_pid,
        helper_started_at_epoch: helper_pid.and_then(process_started_at_epoch),
        helper_systemd_unit: None,
    })
}

#[cfg(target_os = "linux")]
async fn launch_updater_helper_via_systemd(
    launch_path: &Path,
    manifest_path: &Path,
    target_version: &str,
) -> Result<UpdaterHelperLaunch> {
    let unit_name = updater_systemd_unit_name(target_version);
    let output = Command::new("systemd-run")
        .args(["--user", "--quiet", "--collect", "--unit", &unit_name])
        .arg(launch_path)
        .arg("--manifest")
        .arg(manifest_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| {
            format!(
                "failed to launch detached updater helper via systemd-run for manifest {}",
                manifest_path.display()
            )
        })?;
    if !output.status.success() {
        bail!(
            "failed to launch detached updater helper via systemd-run: {}",
            command_failure_detail(&output)
        );
    }

    let helper_pid = wait_for_systemd_user_unit_main_pid(&unit_name, UPDATER_WAIT_TIMEOUT).await?;
    Ok(UpdaterHelperLaunch {
        child: None,
        helper_pid,
        helper_started_at_epoch: helper_pid.and_then(process_started_at_epoch),
        helper_systemd_unit: Some(unit_name),
    })
}

async fn launch_updater_helper(
    helper_path: &Path,
    manifest_path: &Path,
    target_version: &str,
) -> Result<UpdaterHelperLaunch> {
    let launch_path = prepare_updater_helper_launch_path(helper_path, target_version).await?;

    #[cfg(target_os = "linux")]
    if should_launch_helper_via_systemd_run() {
        return launch_updater_helper_via_systemd(&launch_path, manifest_path, target_version)
            .await;
    }

    launch_updater_helper_as_child(&launch_path, manifest_path).await
}

#[cfg(windows)]
async fn maybe_cleanup_updater_helper_runtime_dir() {
    let Ok(current_exe) = std::env::current_exe() else {
        return;
    };
    let Some(runtime_dir) = current_exe.parent() else {
        return;
    };
    let runtime_root = updater_helper_runtime_root();
    if runtime_dir.parent() != Some(runtime_root.as_path()) {
        return;
    }

    let cleanup_command = format!(
        "ping -n 3 127.0.0.1 >NUL && rmdir /s /q \"{}\"",
        runtime_dir.display()
    );
    if let Err(err) = Command::new("cmd")
        .args(["/C", &cleanup_command])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        ::tracing::warn!(
            event = "updater_helper_runtime_cleanup_failed",
            runtime_dir = runtime_dir.display().to_string(),
            error = %format!("{err:#}")
        );
    }
}

#[cfg(not(windows))]
async fn maybe_cleanup_updater_helper_runtime_dir() {}

async fn record_helper_result(manifest: &UpdateInstallManifest, result: &Result<()>) -> Result<()> {
    let now = state_files::now_rfc3339();
    let mut state = load_updater_state().await.unwrap_or_default();
    state.last_attempt_at.get_or_insert_with(|| now.clone());
    state.last_seen_version = Some(manifest.target_version.clone());

    let mapped = match result {
        Ok(()) => Ok(AttemptOutcome::Installed),
        Err(err) => Err(anyhow::anyhow!("{err:#}")),
    };
    apply_background_update_attempt_result(&mut state, &now, mapped, now_epoch());
    save_updater_state(&state).await
}

async fn run_updater_helper_with_manifest(manifest: &UpdateInstallManifest) -> Result<()> {
    ::tracing::info!(
        event = "updater_helper_start",
        pid = std::process::id(),
        ppid = parent_pid_for_logs(),
        target_version = manifest.target_version,
        staged_binary = manifest.staged_cadence_path.display().to_string(),
        final_binary = manifest.final_cadence_path.display().to_string(),
        wait_for_pid = manifest.wait_for_pid,
        mode = ?manifest.mode
    );

    wait_for_pid_to_exit(
        manifest.wait_for_pid,
        manifest.wait_for_pid_started_at_epoch,
        UPDATER_WAIT_TIMEOUT,
    )
    .await?;
    let activity_guard = acquire_activity_lock_blocking("update-helper-install").await?;
    wait_for_executable_path_to_quiesce(
        &manifest.final_cadence_path,
        &[(
            manifest.wait_for_pid,
            manifest.wait_for_pid_started_at_epoch,
        )],
        UPDATER_WAIT_TIMEOUT,
    )
    .await?;
    install_staged_binary(&manifest.staged_cadence_path, &manifest.final_cadence_path).await?;
    drop(activity_guard);

    if let Err(err) = run_install_with_exe(
        &manifest.final_cadence_path,
        manifest.preserve_disable_state,
    )
    .await
    {
        return Err(install_handoff_error(err));
    }

    if matches!(manifest.mode, InstallMode::Interactive) {
        println!(
            "Successfully updated cadence to v{}",
            manifest.target_version
        );
    }

    ::tracing::info!(
        event = "updater_helper_finished",
        pid = std::process::id(),
        ppid = parent_pid_for_logs(),
        target_version = manifest.target_version,
        final_binary = manifest.final_cadence_path.display().to_string()
    );

    Ok(())
}

pub async fn run_updater_helper_from_manifest_path(manifest_path: &Path) -> Result<()> {
    let manifest = load_install_manifest(manifest_path).await?;
    let result = run_updater_helper_with_manifest(&manifest).await;

    if let Err(err) = record_helper_result(&manifest, &result).await {
        eprintln!("Warning: could not record updater result: {err:#}");
    }
    if let Err(err) = clear_update_in_progress_record().await {
        eprintln!("Warning: could not clear update-in-progress marker: {err:#}");
    }
    maybe_remove_staging_dir(manifest_path).await;
    maybe_cleanup_updater_helper_runtime_dir().await;

    result
}

// ---------------------------------------------------------------------------
// Confirmation prompt
// ---------------------------------------------------------------------------

/// Asks the user to confirm the update. Returns `true` if they accept.
///
/// `--yes` always skips the prompt. Otherwise this falls back to the
/// interactive confirmation prompt with [y/N] default No.
pub fn confirm_update(local_version: &str, remote_version: &str, yes: bool) -> Result<bool> {
    // --yes flag always wins
    if yes {
        return Ok(true);
    }

    let prompt = format!("Update cadence v{local_version} → v{remote_version}?");

    // Use dialoguer for interactive prompt with [y/N] default No
    let result = dialoguer::Confirm::new()
        .with_prompt(&prompt)
        .default(false)
        .interact_opt()
        .context("Failed to read user input for update confirmation")?;

    // None means the user pressed Ctrl-C or input was interrupted
    Ok(result.unwrap_or(false))
}

// ---------------------------------------------------------------------------
// Full update orchestration
// ---------------------------------------------------------------------------

/// Runs the full helper-driven self-update flow.
///
/// If `check` is true, only checks and prints whether an update is available.
/// Otherwise, downloads, verifies, extracts, and hands installation off to a
/// detached updater helper.
pub async fn run_update(check: bool, yes: bool) -> Result<UpdateCommandStatus> {
    if check {
        run_update_check().await?;
        return Ok(UpdateCommandStatus::Completed);
    }

    match run_update_install(yes).await? {
        AttemptOutcome::HelperLaunched => Ok(UpdateCommandStatus::HandoffPending),
        AttemptOutcome::Installed | AttemptOutcome::NoUpdate | AttemptOutcome::SkippedUnstable => {
            Ok(UpdateCommandStatus::Completed)
        }
    }
}

/// Check-only path: prints whether an update is available.
async fn run_update_check() -> Result<()> {
    let local = current_version();

    let release = match check_latest_version().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Warning: Unable to check for updates: {e}");
            return Ok(());
        }
    };

    let remote = &release.tag_name;

    match compare_versions(local, remote) {
        Ok(Ordering::Less) => {
            let remote_display = normalize_version_tag(remote);
            println!("Update available: v{local} → v{remote_display}");
        }
        Ok(_) => {
            println!("cadence v{local} is up to date");
        }
        Err(e) => {
            eprintln!("Warning: Unable to compare versions: {e}");
        }
    }

    Ok(())
}

/// Full install path: download, verify, extract, confirm, replace.
async fn run_update_install(yes: bool) -> Result<AttemptOutcome> {
    run_update_install_from_url_mode(
        &effective_latest_release_url(),
        yes,
        InstallMode::Interactive,
    )
    .await
}

/// Install path with injectable URL for testing.
#[allow(dead_code)]
pub async fn run_update_install_from_url(release_url: &str, yes: bool) -> Result<()> {
    let _ = run_update_install_from_url_mode(release_url, yes, InstallMode::Interactive).await?;
    Ok(())
}

async fn run_install_with_exe(exe_path: &Path, preserve_disable_state: bool) -> Result<()> {
    let xpc_service_name = std::env::var("XPC_SERVICE_NAME").ok();
    ::tracing::info!(
        event = "post_update_install_handoff_start",
        pid = std::process::id(),
        ppid = parent_pid_for_logs(),
        exe = exe_path.display().to_string(),
        preserve_disable_state,
        xpc_service_name = xpc_service_name.as_deref().unwrap_or("")
    );
    let mut command = Command::new(exe_path);
    command.arg("install");
    if preserve_disable_state {
        command.arg("--preserve-disable-state");
    }
    let mut child = command
        .env(PASSIVE_CHECK_ENV_VAR, "1")
        .env("CADENCE_INTERNAL_ALLOW_UPDATE_IN_PROGRESS", "1")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            format!(
                "failed to launch bootstrap install with {}",
                exe_path.display()
            )
        })?;
    ::tracing::info!(
        event = "post_update_install_handoff_spawned",
        pid = std::process::id(),
        ppid = parent_pid_for_logs(),
        child_pid = ?child.id(),
        exe = exe_path.display().to_string(),
        xpc_service_name = xpc_service_name.as_deref().unwrap_or("")
    );
    let status = child.wait().await.with_context(|| {
        format!(
            "failed while waiting for bootstrap install with {}",
            exe_path.display()
        )
    })?;
    ::tracing::info!(
        event = "post_update_install_handoff_finished",
        pid = std::process::id(),
        ppid = parent_pid_for_logs(),
        child_pid = ?child.id(),
        status = %status,
        success = status.success(),
        xpc_service_name = xpc_service_name.as_deref().unwrap_or("")
    );

    if status.success() {
        return Ok(());
    }

    bail!("bootstrap install command failed with exit status {status}");
}

async fn run_update_install_from_url_mode(
    release_url: &str,
    yes: bool,
    mode: InstallMode,
) -> Result<AttemptOutcome> {
    let local = current_version();

    // Step 1: Fetch release metadata
    let release = check_latest_version_from_url(release_url)
        .await
        .context("Failed to check for latest release")?;

    let remote = &release.tag_name;
    let remote_display = normalize_version_tag(remote);

    // Step 2: Compare versions
    let ordering =
        compare_versions(local, remote).context("Failed to compare local and remote versions")?;

    if ordering != Ordering::Less {
        if matches!(mode, InstallMode::Interactive) {
            println!("cadence v{local} is already up to date (latest: v{remote_display})");
        }
        return Ok(AttemptOutcome::NoUpdate);
    }

    if !is_stable_release_tag(remote) {
        if matches!(mode, InstallMode::Interactive) {
            println!("Latest release v{remote_display} is pre-release; skipping.");
        }
        return Ok(AttemptOutcome::SkippedUnstable);
    }

    // Step 3: Resolve target artifact and checksums from release assets
    let target = build_target();
    let artifact_asset = pick_artifact_for_target(&release.assets, target)?;
    let checksums_asset = pick_checksums_asset(&release.assets)?;

    // Step 4: Prompt for confirmation
    if matches!(mode, InstallMode::Interactive) && !confirm_update(local, remote_display, yes)? {
        println!("Update cancelled.");
        return Ok(AttemptOutcome::NoUpdate);
    }

    let _activity_guard = acquire_command_activity_lock("self-update").await?;
    let current_exe =
        std::env::current_exe().context("failed to resolve current cadence executable path")?;
    let update_record = UpdateInProgressRecord {
        target_version: remote_display.to_string(),
        final_cadence_path: current_exe.clone(),
        initiator_pid: std::process::id(),
        initiator_started_at_epoch: current_process_started_at_epoch(),
        helper_pid: None,
        helper_started_at_epoch: None,
        helper_systemd_unit: None,
        created_at_epoch: now_epoch(),
    };
    write_update_in_progress_record(&update_record).await?;

    let attempt = async {
        // Step 5: Download to a temporary workspace.
        let tmp_dir = tempfile::tempdir().context("Failed to create temporary directory")?;

        if matches!(mode, InstallMode::Interactive) {
            println!("Downloading cadence v{remote_display}...");
        }

        let checksums_path = download_to_file(
            &checksums_asset.browser_download_url,
            tmp_dir.path(),
            CHECKSUMS_FILENAME,
        )
        .await
        .context("Failed to download checksums file")?;

        let artifact_path = download_to_file(
            &artifact_asset.browser_download_url,
            tmp_dir.path(),
            &artifact_asset.name,
        )
        .await
        .context("Failed to download release archive")?;

        // Step 6: Verify checksum
        let checksums_content = tokio::fs::read_to_string(&checksums_path)
            .await
            .context("Failed to read downloaded checksums file")?;
        let checksums = parse_checksums(&checksums_content)?;
        verify_checksum(&checksums, &artifact_asset.name, &artifact_path).await?;

        // Step 7: Extract the release payload into a persistent staging directory.
        let staging_dir = create_update_staging_dir(remote_display).await?;
        let payload = extract_release_payload(&artifact_path, &staging_dir, target).await?;
        set_executable_permissions(&payload.cadence_binary).await?;
        set_executable_permissions(&payload.updater_binary).await?;

        let manifest = UpdateInstallManifest {
            target_version: remote_display.to_string(),
            staged_cadence_path: payload.cadence_binary.clone(),
            final_cadence_path: current_exe.clone(),
            wait_for_pid: std::process::id(),
            wait_for_pid_started_at_epoch: current_process_started_at_epoch(),
            preserve_disable_state: true,
            mode,
        };
        let manifest_path = staging_dir.join(UPDATE_MANIFEST_FILE);
        write_install_manifest(&manifest_path, &manifest).await?;

        // Step 8: Launch the updater helper and exit cleanly so it can finish the swap.
        ::tracing::info!(
            event = "self_update_helper_launch_start",
            pid = std::process::id(),
            ppid = parent_pid_for_logs(),
            local_version = local,
            remote_version = remote_display,
            helper = payload.updater_binary.display().to_string(),
            manifest = manifest_path.display().to_string(),
            target_install = current_exe.display().to_string(),
            mode = ?mode,
            xpc_service_name = std::env::var("XPC_SERVICE_NAME")
                .ok()
                .as_deref()
                .unwrap_or("")
        );
        let helper_launch =
            match launch_updater_helper(&payload.updater_binary, &manifest_path, remote_display).await {
                Ok(launch) => launch,
                Err(err) => {
                    maybe_remove_staging_dir(&manifest_path).await;
                    return Err(err);
                }
            };
        let helper_record = UpdateInProgressRecord {
            helper_pid: helper_launch.helper_pid,
            helper_started_at_epoch: helper_launch.helper_started_at_epoch,
            helper_systemd_unit: helper_launch.helper_systemd_unit.clone(),
            ..update_record.clone()
        };
        if let Err(err) = write_update_in_progress_record(&helper_record).await {
            helper_launch.abort().await;
            maybe_remove_staging_dir(&manifest_path).await;
            return Err(err).context("failed to persist updater helper pid");
        }
        ::tracing::info!(
            event = "self_update_helper_launch_complete",
            pid = std::process::id(),
            ppid = parent_pid_for_logs(),
            local_version = local,
            remote_version = remote_display,
            mode = ?mode,
            helper_pid = helper_record.helper_pid.unwrap_or_default(),
            helper_systemd_unit = helper_record.helper_systemd_unit.as_deref().unwrap_or(""),
            manifest = manifest_path.display().to_string(),
            current_exe = current_exe.display().to_string(),
            xpc_service_name = std::env::var("XPC_SERVICE_NAME")
                .ok()
                .as_deref()
                .unwrap_or("")
        );

        if matches!(mode, InstallMode::Interactive) {
            println!(
                "Staged cadence v{local} → v{remote_display}. cadence-updater{} will finish installation after this process exits.",
                helper_record
                    .helper_pid
                    .map(|pid| format!(" (pid {pid})"))
                    .unwrap_or_default()
            );
        }

        Ok(AttemptOutcome::HelperLaunched)
    }
    .await;

    if attempt.is_err() {
        let _ = clear_update_in_progress_record().await;
    }

    attempt
}

fn retry_delay_from_state(state: &UpdaterState) -> u64 {
    retry_delay_secs(state.consecutive_failures.max(1))
}

#[doc(hidden)]
pub async fn run_background_auto_update_for_monitor_tick() -> Result<()> {
    #[cfg(test)]
    {
        let test_hook = {
            let mut hook = background_auto_update_test_hook()
                .lock()
                .expect("background auto-update test hook lock");
            hook.as_mut().map(|hook| {
                hook.calls += 1;
                (hook.result.clone(), hook.delay_ms)
            })
        };

        if let Some((result, delay_ms)) = test_hook {
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            return result.map_err(anyhow::Error::msg);
        }
    }

    let mut state = load_updater_state().await.unwrap_or_default();
    if !update_due_for_retry(&state, now_epoch()) {
        return Ok(());
    }

    let now = state_files::now_rfc3339();
    state.last_attempt_at = Some(now.clone());

    let release = match check_latest_version().await {
        Ok(r) => r,
        Err(e) => {
            state.last_check_at = Some(now.clone());
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            state.last_error = Some(format!("{e:#}"));
            let retry_at = now_epoch().saturating_add(retry_delay_from_state(&state) as i64);
            state.next_retry_after = format_epoch_rfc3339(retry_at);
            save_updater_state(&state).await?;
            return Ok(());
        }
    };

    state.last_check_at = Some(now.clone());
    state.last_seen_version = Some(normalize_version_tag(&release.tag_name).to_string());

    if !is_stable_release_tag(&release.tag_name) {
        state.last_error =
            Some("latest release is not stable; waiting for stable release".to_string());
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        let retry_at = now_epoch().saturating_add(retry_delay_from_state(&state) as i64);
        state.next_retry_after = format_epoch_rfc3339(retry_at);
        save_updater_state(&state).await?;
        return Ok(());
    }

    save_updater_state(&state).await?;

    let attempt_result = run_update_install_from_url_mode(
        &effective_latest_release_url(),
        true,
        InstallMode::SilentUnattended,
    )
    .await;
    match attempt_result {
        Ok(AttemptOutcome::HelperLaunched) => {}
        other => {
            apply_background_update_attempt_result(&mut state, &now, other, now_epoch());
            save_updater_state(&state).await?;
        }
    }

    Ok(())
}

pub(crate) fn should_defer_legacy_auto_update_scheduler_cleanup() -> bool {
    #[cfg(target_os = "macos")]
    {
        return std::env::var("XPC_SERVICE_NAME").ok().as_deref() == Some(MACOS_LAUNCH_AGENT_LABEL);
    }

    #[allow(unreachable_code)]
    false
}

pub(crate) async fn cleanup_legacy_auto_update_scheduler_for_monitor_runtime()
-> Result<LegacyAutoUpdateCleanupDisposition> {
    #[cfg(test)]
    {
        let mut hook = legacy_cleanup_test_hook()
            .lock()
            .expect("legacy cleanup test hook lock");
        if let Some(hook) = hook.as_mut() {
            hook.calls += 1;
            return match &hook.result {
                Ok(result) => Ok(*result),
                Err(message) => Err(anyhow::anyhow!(message.clone())),
            };
        }
    }

    if should_defer_legacy_auto_update_scheduler_cleanup() {
        ::tracing::info!(
            event = "legacy_auto_update_scheduler_cleanup_deferred",
            reason = "running_under_legacy_auto_update_scheduler"
        );
        return Ok(LegacyAutoUpdateCleanupDisposition::Deferred);
    }

    uninstall_auto_update_scheduler().await?;
    Ok(LegacyAutoUpdateCleanupDisposition::Attempted)
}

#[cfg(test)]
pub(crate) struct LegacyCleanupTestHook {
    result: std::result::Result<LegacyAutoUpdateCleanupDisposition, String>,
    calls: usize,
}

#[cfg(test)]
fn legacy_cleanup_test_hook() -> &'static std::sync::Mutex<Option<LegacyCleanupTestHook>> {
    static HOOK: std::sync::OnceLock<std::sync::Mutex<Option<LegacyCleanupTestHook>>> =
        std::sync::OnceLock::new();
    HOOK.get_or_init(|| std::sync::Mutex::new(None))
}

#[cfg(test)]
pub(crate) struct LegacyCleanupTestHookGuard;

#[cfg(test)]
impl Drop for LegacyCleanupTestHookGuard {
    fn drop(&mut self) {
        if let Ok(mut hook) = legacy_cleanup_test_hook().lock() {
            *hook = None;
        }
    }
}

#[cfg(test)]
pub(crate) fn install_legacy_cleanup_test_hook(
    result: std::result::Result<LegacyAutoUpdateCleanupDisposition, &'static str>,
) -> LegacyCleanupTestHookGuard {
    let mut hook = legacy_cleanup_test_hook()
        .lock()
        .expect("legacy cleanup test hook lock");
    *hook = Some(LegacyCleanupTestHook {
        result: result.map_err(|message| message.to_string()),
        calls: 0,
    });
    LegacyCleanupTestHookGuard
}

#[cfg(test)]
pub(crate) fn legacy_cleanup_test_hook_calls() -> usize {
    legacy_cleanup_test_hook()
        .lock()
        .expect("legacy cleanup test hook lock")
        .as_ref()
        .map(|hook| hook.calls)
        .unwrap_or_default()
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct BackgroundAutoUpdateTestHook {
    result: std::result::Result<(), String>,
    delay_ms: u64,
    calls: usize,
}

#[cfg(test)]
fn background_auto_update_test_hook()
-> &'static std::sync::Mutex<Option<BackgroundAutoUpdateTestHook>> {
    static HOOK: std::sync::OnceLock<std::sync::Mutex<Option<BackgroundAutoUpdateTestHook>>> =
        std::sync::OnceLock::new();
    HOOK.get_or_init(|| std::sync::Mutex::new(None))
}

#[cfg(test)]
pub(crate) struct BackgroundAutoUpdateTestHookGuard;

#[cfg(test)]
impl Drop for BackgroundAutoUpdateTestHookGuard {
    fn drop(&mut self) {
        if let Ok(mut hook) = background_auto_update_test_hook().lock() {
            *hook = None;
        }
    }
}

#[cfg(test)]
pub(crate) fn install_background_auto_update_test_hook(
    result: std::result::Result<(), &'static str>,
    delay_ms: u64,
) -> BackgroundAutoUpdateTestHookGuard {
    let mut hook = background_auto_update_test_hook()
        .lock()
        .expect("background auto-update test hook lock");
    *hook = Some(BackgroundAutoUpdateTestHook {
        result: result.map_err(|message| message.to_string()),
        delay_ms,
        calls: 0,
    });
    BackgroundAutoUpdateTestHookGuard
}

#[cfg(test)]
pub(crate) fn background_auto_update_test_hook_calls() -> usize {
    background_auto_update_test_hook()
        .lock()
        .expect("background auto-update test hook lock")
        .as_ref()
        .map(|hook| hook.calls)
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
const MACOS_LAUNCH_AGENT_LABEL: &str = "ai.teamcadence.cadence.autoupdate";
#[cfg(target_os = "windows")]
const WINDOWS_TASK_NAME: &str = "Cadence CLI Auto Update";

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn command_failure_detail(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    [stderr, stdout]
        .into_iter()
        .find(|value| !value.is_empty())
        .unwrap_or_else(|| format!("exit status {}", output.status))
}

fn install_handoff_error(err: anyhow::Error) -> anyhow::Error {
    err.context(
        "cadence updated, but the new version could not finish runtime bootstrap automatically",
    )
}

fn apply_background_update_attempt_result(
    state: &mut UpdaterState,
    now: &str,
    attempt_result: Result<AttemptOutcome>,
    current_epoch: i64,
) {
    match attempt_result {
        Ok(AttemptOutcome::Installed) => {
            state.last_success_at = Some(now.to_string());
            state.last_installed_version = state.last_seen_version.clone();
            state.consecutive_failures = 0;
            state.last_error = None;
            state.next_retry_after = None;
        }
        Ok(AttemptOutcome::NoUpdate | AttemptOutcome::SkippedUnstable) => {
            state.last_success_at = Some(now.to_string());
            state.consecutive_failures = 0;
            state.last_error = None;
            state.next_retry_after = None;
        }
        Ok(AttemptOutcome::HelperLaunched) => {}
        Err(err) => {
            let err = format!("{err:#}");
            if err.contains("global activity lock is busy") {
                state.last_error = Some("activity lock busy; updater skipped".to_string());
                let delay = rand08::Rng::gen_range(&mut rand08::thread_rng(), 60..=300);
                state.next_retry_after =
                    format_epoch_rfc3339(current_epoch.saturating_add(delay as i64));
                return;
            }
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            state.last_error = Some(err);
            let retry_at = current_epoch.saturating_add(retry_delay_from_state(state) as i64);
            state.next_retry_after = format_epoch_rfc3339(retry_at);
        }
    }
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
fn macos_launch_agent_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME is required for LaunchAgent provisioning")?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{MACOS_LAUNCH_AGENT_LABEL}.plist")))
}

#[cfg(target_os = "linux")]
fn linux_systemd_paths() -> Result<(PathBuf, PathBuf)> {
    let home = std::env::var("HOME").context("HOME is required for systemd user provisioning")?;
    let user_dir = PathBuf::from(home)
        .join(".config")
        .join("systemd")
        .join("user");
    Ok((
        user_dir.join("cadence-autoupdate.service"),
        user_dir.join("cadence-autoupdate.timer"),
    ))
}

pub async fn uninstall_auto_update_scheduler() -> Result<()> {
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
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let (service_path, timer_path) = linux_systemd_paths()?;
        let _ = Command::new("systemctl")
            .args(["--user", "disable", "--now", "cadence-autoupdate.timer"])
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
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("schtasks")
            .args(["/Delete", "/F", "/TN", WINDOWS_TASK_NAME])
            .status()
            .await;
        return Ok(());
    }

    #[allow(unreachable_code)]
    Ok(())
}

pub fn auto_update_policy_summary() -> &'static str {
    "monitor-driven; stable channel only; no separate auto-update toggle"
}

pub async fn updater_health() -> UpdaterHealth {
    let enabled = crate::monitor::monitor_enabled().await;
    let state = load_updater_state().await.unwrap_or_default();
    derive_updater_health(enabled, &state)
}

fn derive_updater_health(enabled: bool, state: &UpdaterState) -> UpdaterHealth {
    if !enabled {
        return UpdaterHealth {
            enabled,
            state: UpdaterHealthState::Disabled,
            last_result: "monitor disabled".to_string(),
            last_attempt_at: state.last_attempt_at.clone(),
            next_retry_after: None,
            last_error: None,
        };
    }

    if state.last_attempt_at.is_none() {
        return UpdaterHealth {
            enabled,
            state: UpdaterHealthState::NeverRun,
            last_result: "never run".to_string(),
            last_attempt_at: None,
            next_retry_after: None,
            last_error: None,
        };
    }

    if state.consecutive_failures > 0 {
        let health_state = if state.consecutive_failures >= 5 {
            UpdaterHealthState::Failing
        } else {
            UpdaterHealthState::Retrying
        };
        return UpdaterHealth {
            enabled,
            state: health_state,
            last_result: "retry scheduled".to_string(),
            last_attempt_at: state.last_attempt_at.clone(),
            next_retry_after: state.next_retry_after.clone(),
            last_error: state.last_error.clone(),
        };
    }

    UpdaterHealth {
        enabled,
        state: UpdaterHealthState::Healthy,
        last_result: "healthy".to_string(),
        last_attempt_at: state.last_attempt_at.clone(),
        next_retry_after: state.next_retry_after.clone(),
        last_error: state.last_error.clone(),
    }
}

// ---------------------------------------------------------------------------
// Passive background version check
// ---------------------------------------------------------------------------

/// Filename for the last-update-check timestamp cache.
const LAST_UPDATE_CHECK_FILE: &str = "last-update-check";

/// HTTP timeout for the passive background version check (3 seconds).
const PASSIVE_CHECK_TIMEOUT: Duration = Duration::from_secs(3);

/// Environment variable that suppresses passive version checks when set to "1".
const PASSIVE_CHECK_ENV_VAR: &str = "CADENCE_NO_UPDATE_CHECK";

/// Returns the path to the last-update-check timestamp file.
///
/// Returns `None` if the config directory can't be resolved (e.g. no `$HOME`).
fn last_update_check_path() -> Option<PathBuf> {
    Some(CliConfig::config_dir()?.join(LAST_UPDATE_CHECK_FILE))
}

/// Reads the last-update-check timestamp from the given path.
///
/// Accepts both RFC 3339 timestamps and plain epoch seconds (integer).
/// Returns `None` if the file is missing, empty, or contains unparseable content.
pub async fn read_last_check_timestamp(path: &Path) -> Option<std::time::SystemTime> {
    let content = tokio::fs::read_to_string(path).await.ok()?;
    parse_timestamp_string(content.trim())
}

/// Parses a timestamp string that is either RFC 3339 or plain epoch seconds.
fn parse_timestamp_string(s: &str) -> Option<std::time::SystemTime> {
    if s.is_empty() {
        return None;
    }

    // Try epoch seconds first (simple integer)
    if let Ok(epoch) = s.parse::<i64>() {
        if epoch >= 0 {
            return Some(std::time::UNIX_EPOCH + Duration::from_secs(epoch as u64));
        }
        return None;
    }

    // Try RFC 3339 timestamp
    if let Ok(dt) = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339) {
        let epoch = dt.unix_timestamp();
        if epoch >= 0 {
            return Some(std::time::UNIX_EPOCH + Duration::from_secs(epoch as u64));
        }
    }

    None
}

/// Writes the current timestamp to the given path in RFC 3339 format.
///
/// Creates parent directories if needed. Errors are returned (not swallowed)
/// so callers can decide whether to ignore them.
pub async fn write_last_check_timestamp(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    let now = time::OffsetDateTime::now_utc();
    let formatted = now
        .format(&time::format_description::well_known::Rfc3339)
        .context("failed to format current time as RFC 3339")?;
    tokio::fs::write(path, format!("{formatted}\n"))
        .await
        .with_context(|| format!("failed to write timestamp to {}", path.display()))?;
    Ok(())
}

/// Determines whether a passive version check should run.
///
/// Returns `false` (suppressed) when any of these conditions hold:
/// - `CADENCE_NO_UPDATE_CHECK=1` is set
/// - `is_tty` is false (non-interactive environment)
/// - A check was performed within the configured interval
///
/// Returns `true` when:
/// - The timestamp file is missing or unreadable (first run or corrupt)
/// - The elapsed time since last check exceeds the configured interval
///
/// `env_no_update_check` is the value of the `CADENCE_NO_UPDATE_CHECK` env var.
/// `is_tty` indicates whether stdout is a TTY.
/// `config_dir` is the path to the cadence config directory.
pub async fn should_check_for_update(
    env_no_update_check: Option<&str>,
    is_tty: bool,
    config_dir: Option<&Path>,
) -> bool {
    // Suppress when env var is set to "1"
    if env_no_update_check == Some("1") {
        return false;
    }

    // Suppress when not a TTY (CI, piped output, etc.)
    if !is_tty {
        return false;
    }

    // Resolve config directory — if unavailable, allow check (best effort)
    let dir = match config_dir {
        Some(d) => d.to_path_buf(),
        None => match CliConfig::config_dir() {
            Some(d) => d,
            None => return true, // No config dir means first run or broken HOME
        },
    };

    let timestamp_path = dir.join(LAST_UPDATE_CHECK_FILE);

    // If no timestamp file, check is due
    let last_check = match read_last_check_timestamp(&timestamp_path).await {
        Some(ts) => ts,
        None => return true,
    };

    // Load config interval (default 8h, treat parse errors as "check due")
    let interval = CliConfig::load()
        .await
        .ok()
        .and_then(|cfg| cfg.resolved_update_check_interval().ok())
        .unwrap_or(Duration::from_secs(8 * 3600));

    // Check if enough time has elapsed
    match std::time::SystemTime::now().duration_since(last_check) {
        Ok(elapsed) => elapsed >= interval,
        Err(_) => true, // Clock went backward — run check to be safe
    }
}

/// Formats the update notification message shown to users.
pub fn format_update_notification(current: &str, latest: &str) -> String {
    format!(
        "A new version of cadence is available: v{latest} (current: v{current}). Run 'cadence update' to upgrade."
    )
}

/// Performs a passive background version check with a 3-second timeout.
///
/// This is called after normal command execution on non-Update commands.
/// It checks `should_check_for_update()` first, and if due, makes a network
/// request to the GitHub Releases API. On success, it:
/// - Updates the last-check timestamp
/// - Caches the latest version for `cadence status`
/// - Prints a notification to stderr if a newer version is available
///
/// All failures are silently ignored to avoid disrupting the user's workflow.
pub async fn passive_version_check() {
    passive_version_check_from_url(&effective_latest_release_url()).await;
}

/// Injectable version for testing — accepts a custom release URL.
pub async fn passive_version_check_from_url(url: &str) {
    let env_val = std::env::var(PASSIVE_CHECK_ENV_VAR).ok();
    let is_tty = console::Term::stdout().is_term();

    if !should_check_for_update(env_val.as_deref(), is_tty, None).await {
        return;
    }

    // Determine the timestamp path for writing after the check attempt
    let timestamp_path = match last_update_check_path() {
        Some(p) => p,
        None => return, // Can't persist state without config dir
    };

    // Perform the version check with a short timeout
    let check_result = check_latest_version_from_url_with_timeout(url, PASSIVE_CHECK_TIMEOUT).await;

    // Always update the timestamp after an attempt (success or failure)
    // to prevent retry storms on persistent failures
    let _ = write_last_check_timestamp(&timestamp_path).await;

    // Process the result if successful
    let release = match check_result {
        Ok(r) => r,
        Err(_) => return, // Network/parse error — silently ignore
    };

    let remote_tag = &release.tag_name;
    let remote_version = normalize_version_tag(remote_tag);
    let local_version = current_version();

    // Cache the latest version regardless of comparison result
    let _ = crate::config::write_cached_latest_version(remote_version).await;

    // Compare versions — only notify if remote is newer
    if let Ok(Ordering::Less) = compare_versions(local_version, remote_tag) {
        let msg = format_update_notification(local_version, remote_version);
        eprintln!("{msg}");
    }
}

/// Fetches latest release metadata with a custom timeout.
///
/// Used by the passive check path to enforce the 3-second budget.
async fn check_latest_version_from_url_with_timeout(
    url: &str,
    timeout: Duration,
) -> Result<LatestRelease> {
    let tag = discover_latest_tag(url, timeout).await?;
    let repo_base = repo_base_from_releases_url(url);
    Ok(build_release_from_tag(&tag, repo_base))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::io::Write;

    struct EnvGuard {
        key: String,
        original: Option<String>,
    }

    impl EnvGuard {
        fn new(key: &str) -> Self {
            Self {
                key: key.to_string(),
                original: std::env::var(key).ok(),
            }
        }

        fn set(&self, value: &str) {
            unsafe { std::env::set_var(&self.key, value) };
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(v) => unsafe { std::env::set_var(&self.key, v) },
                None => unsafe { std::env::remove_var(&self.key) },
            }
        }
    }

    // -- normalize_version_tag -----------------------------------------------

    #[tokio::test]
    async fn normalize_strips_lowercase_v() {
        assert_eq!(normalize_version_tag("v0.3.0"), "0.3.0");
    }

    #[tokio::test]
    async fn normalize_strips_uppercase_v() {
        assert_eq!(normalize_version_tag("V1.2.3"), "1.2.3");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn legacy_auto_update_scheduler_cleanup_defers_for_matching_xpc_service_name() {
        let guard = EnvGuard::new("XPC_SERVICE_NAME");
        guard.set(MACOS_LAUNCH_AGENT_LABEL);

        assert!(should_defer_legacy_auto_update_scheduler_cleanup());
    }

    #[tokio::test]
    async fn cleanup_legacy_auto_update_scheduler_for_monitor_runtime_uses_test_hook() {
        let _hook =
            install_legacy_cleanup_test_hook(Ok(LegacyAutoUpdateCleanupDisposition::Deferred));

        let disposition = cleanup_legacy_auto_update_scheduler_for_monitor_runtime()
            .await
            .expect("cleanup disposition");

        assert_eq!(disposition, LegacyAutoUpdateCleanupDisposition::Deferred);
        assert_eq!(legacy_cleanup_test_hook_calls(), 1);
    }

    #[tokio::test]
    #[serial]
    async fn monitor_background_auto_update_hook_short_circuits_runtime_path() {
        let _hook = install_background_auto_update_test_hook(Ok(()), 0);

        run_background_auto_update_for_monitor_tick()
            .await
            .expect("monitor background update");

        assert_eq!(background_auto_update_test_hook_calls(), 1);
    }

    #[tokio::test]
    async fn normalize_no_prefix() {
        assert_eq!(normalize_version_tag("0.3.0"), "0.3.0");
    }

    #[tokio::test]
    async fn normalize_trims_whitespace() {
        assert_eq!(normalize_version_tag("  v0.3.0  "), "0.3.0");
        assert_eq!(normalize_version_tag("  0.3.0  "), "0.3.0");
    }

    #[tokio::test]
    async fn normalize_empty_string() {
        assert_eq!(normalize_version_tag(""), "");
    }

    // -- compare_versions ----------------------------------------------------

    #[tokio::test]
    async fn compare_same_versions() {
        assert_eq!(compare_versions("0.2.1", "0.2.1").unwrap(), Ordering::Equal);
    }

    #[tokio::test]
    async fn compare_remote_newer() {
        assert_eq!(compare_versions("0.2.1", "0.3.0").unwrap(), Ordering::Less);
    }

    #[tokio::test]
    async fn compare_local_newer() {
        assert_eq!(
            compare_versions("0.3.0", "0.2.1").unwrap(),
            Ordering::Greater
        );
    }

    #[tokio::test]
    async fn compare_with_v_prefix_on_remote() {
        assert_eq!(compare_versions("0.2.1", "v0.3.0").unwrap(), Ordering::Less);
    }

    #[tokio::test]
    async fn compare_with_v_prefix_on_both() {
        assert_eq!(
            compare_versions("v0.2.1", "v0.2.1").unwrap(),
            Ordering::Equal
        );
    }

    #[tokio::test]
    async fn compare_with_v_prefix_on_local() {
        assert_eq!(
            compare_versions("v0.3.0", "0.2.1").unwrap(),
            Ordering::Greater
        );
    }

    #[tokio::test]
    async fn compare_prerelease_less_than_release() {
        // semver: 0.3.0-beta < 0.3.0
        assert_eq!(
            compare_versions("0.3.0-beta", "0.3.0").unwrap(),
            Ordering::Less
        );
    }

    #[tokio::test]
    async fn compare_prerelease_same() {
        assert_eq!(
            compare_versions("0.3.0-beta.1", "0.3.0-beta.1").unwrap(),
            Ordering::Equal
        );
    }

    #[tokio::test]
    async fn compare_invalid_local_version() {
        let result = compare_versions("not-a-version", "0.3.0");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("local version"));
    }

    #[tokio::test]
    async fn compare_invalid_remote_version() {
        let result = compare_versions("0.2.1", "totally-bogus");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("remote version"));
    }

    #[tokio::test]
    async fn compare_both_invalid() {
        // Should fail on local first
        let result = compare_versions("bad", "also-bad");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn compare_empty_strings() {
        assert!(compare_versions("", "0.3.0").is_err());
        assert!(compare_versions("0.3.0", "").is_err());
    }

    // -- current_version -----------------------------------------------------

    #[tokio::test]
    async fn current_version_is_valid_semver() {
        let ver = current_version();
        assert!(!ver.is_empty(), "current_version() should not be empty");
        assert!(
            semver::Version::parse(ver).is_ok(),
            "current_version() '{ver}' should be valid semver"
        );
    }

    // -- build_release_from_tag -----------------------------------------------

    #[tokio::test]
    async fn build_release_includes_all_targets_and_checksums() {
        let release = build_release_from_tag("v0.3.0", "https://github.com/Org/Repo");
        assert_eq!(release.tag_name, "v0.3.0");
        // 6 platform assets + 1 checksums
        assert_eq!(release.assets.len(), 7);

        // Checksums asset
        let checksums = release
            .assets
            .iter()
            .find(|a| a.name == "checksums-sha256.txt");
        assert!(checksums.is_some());
        assert_eq!(
            checksums.unwrap().browser_download_url,
            "https://github.com/Org/Repo/releases/download/v0.3.0/checksums-sha256.txt"
        );
    }

    #[tokio::test]
    async fn build_release_constructs_correct_download_urls() {
        let release = build_release_from_tag("v1.2.3", "https://github.com/Org/Repo");
        let linux = release
            .assets
            .iter()
            .find(|a| a.name.contains("x86_64-unknown-linux-gnu"))
            .unwrap();
        assert_eq!(
            linux.browser_download_url,
            "https://github.com/Org/Repo/releases/download/v1.2.3/cadence-cli-x86_64-unknown-linux-gnu.tar.gz"
        );
    }

    #[tokio::test]
    async fn build_release_works_with_test_base_url() {
        let release = build_release_from_tag("v0.5.0", "http://127.0.0.1:12345");
        let checksums = release
            .assets
            .iter()
            .find(|a| a.name == "checksums-sha256.txt")
            .unwrap();
        assert_eq!(
            checksums.browser_download_url,
            "http://127.0.0.1:12345/releases/download/v0.5.0/checksums-sha256.txt"
        );
    }

    // -- repo_base_from_releases_url ------------------------------------------

    #[tokio::test]
    async fn repo_base_strips_releases_latest() {
        assert_eq!(
            repo_base_from_releases_url(
                "https://github.com/TeamCadenceAI/cadence-cli/releases/latest"
            ),
            "https://github.com/TeamCadenceAI/cadence-cli"
        );
    }

    #[tokio::test]
    async fn repo_base_preserves_url_without_suffix() {
        assert_eq!(
            repo_base_from_releases_url("http://127.0.0.1:9999"),
            "http://127.0.0.1:9999"
        );
    }

    // -- artifact selection ---------------------------------------------------

    fn make_asset(name: &str) -> ReleaseAsset {
        ReleaseAsset {
            name: name.to_string(),
            browser_download_url: format!("https://example.com/{name}"),
        }
    }

    #[tokio::test]
    async fn expected_artifact_name_linux() {
        assert_eq!(
            expected_artifact_name("x86_64-unknown-linux-gnu"),
            "cadence-cli-x86_64-unknown-linux-gnu.tar.gz"
        );
    }

    #[tokio::test]
    async fn expected_artifact_name_macos() {
        assert_eq!(
            expected_artifact_name("aarch64-apple-darwin"),
            "cadence-cli-aarch64-apple-darwin.zip"
        );
    }

    #[tokio::test]
    async fn expected_artifact_name_windows() {
        assert_eq!(
            expected_artifact_name("x86_64-pc-windows-msvc"),
            "cadence-cli-x86_64-pc-windows-msvc.zip"
        );
    }

    #[tokio::test]
    async fn pick_artifact_exact_match() {
        let assets = vec![
            make_asset("cadence-cli-aarch64-apple-darwin.zip"),
            make_asset("cadence-cli-x86_64-unknown-linux-gnu.tar.gz"),
            make_asset("checksums-sha256.txt"),
        ];
        let result = pick_artifact_for_target(&assets, "x86_64-unknown-linux-gnu").unwrap();
        assert_eq!(result.name, "cadence-cli-x86_64-unknown-linux-gnu.tar.gz");
    }

    #[tokio::test]
    async fn pick_artifact_windows_zip() {
        let assets = vec![
            make_asset("cadence-cli-x86_64-pc-windows-msvc.zip"),
            make_asset("checksums-sha256.txt"),
        ];
        let result = pick_artifact_for_target(&assets, "x86_64-pc-windows-msvc").unwrap();
        assert_eq!(result.name, "cadence-cli-x86_64-pc-windows-msvc.zip");
    }

    #[tokio::test]
    async fn pick_artifact_no_match() {
        let assets = vec![make_asset("cadence-cli-x86_64-unknown-linux-gnu.tar.gz")];
        let result = pick_artifact_for_target(&assets, "aarch64-apple-darwin");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("aarch64-apple-darwin"),
            "error should mention target: {err}"
        );
        assert!(
            err.contains("cadence-cli-aarch64-apple-darwin.zip"),
            "error should show expected name: {err}"
        );
    }

    #[tokio::test]
    async fn pick_artifact_empty_assets() {
        let result = pick_artifact_for_target(&[], "x86_64-unknown-linux-gnu");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn pick_checksums_found() {
        let assets = vec![
            make_asset("cadence-cli-aarch64-apple-darwin.zip"),
            make_asset("checksums-sha256.txt"),
        ];
        let result = pick_checksums_asset(&assets).unwrap();
        assert_eq!(result.name, "checksums-sha256.txt");
    }

    #[tokio::test]
    async fn pick_checksums_missing() {
        let assets = vec![make_asset("cadence-cli-aarch64-apple-darwin.zip")];
        let result = pick_checksums_asset(&assets);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("checksums-sha256.txt")
        );
    }

    // -- checksum parsing ----------------------------------------------------

    #[tokio::test]
    async fn parse_checksums_valid() {
        let content = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  file1.tar.gz\n\
                        1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef  file2.zip\n";
        let map = parse_checksums(content).unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(
            map["file1.tar.gz"],
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        );
        assert_eq!(
            map["file2.zip"],
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
    }

    #[tokio::test]
    async fn parse_checksums_crlf() {
        let content =
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  file.tar.gz\r\n";
        let map = parse_checksums(content).unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("file.tar.gz"));
    }

    #[tokio::test]
    async fn parse_checksums_blank_lines() {
        let content =
            "\na1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  file.tar.gz\n\n";
        let map = parse_checksums(content).unwrap();
        assert_eq!(map.len(), 1);
    }

    #[tokio::test]
    async fn parse_checksums_empty_file() {
        let result = parse_checksums("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[tokio::test]
    async fn parse_checksums_malformed_no_double_space() {
        // Single space instead of double space
        let content =
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2 file.tar.gz\n";
        let result = parse_checksums(content);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Malformed"));
    }

    #[tokio::test]
    async fn parse_checksums_malformed_short_hash() {
        let content = "abc123  file.tar.gz\n";
        let result = parse_checksums(content);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("64 hex"));
    }

    #[tokio::test]
    async fn parse_checksums_malformed_non_hex() {
        let content =
            "ZZZZ567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef  file.tar.gz\n";
        let result = parse_checksums(content);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("64 hex"));
    }

    #[tokio::test]
    async fn parse_checksums_empty_filename() {
        let content = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  \n";
        let result = parse_checksums(content);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Empty filename"));
    }

    // -- checksum verification -----------------------------------------------

    #[tokio::test]
    async fn verify_checksum_match() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("test.bin");
        tokio::fs::write(&file_path, b"hello world").await.unwrap();

        let actual_hash = sha256_file(&file_path).await.unwrap();
        let mut checksums = HashMap::new();
        checksums.insert("test.bin".to_string(), actual_hash);

        verify_checksum(&checksums, "test.bin", &file_path)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn verify_checksum_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("test.bin");
        tokio::fs::write(&file_path, b"hello world").await.unwrap();

        let mut checksums = HashMap::new();
        checksums.insert(
            "test.bin".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );

        let result = verify_checksum(&checksums, "test.bin", &file_path).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Checksum verification failed"), "err: {err}");
        assert!(err.contains("corrupted"), "err: {err}");
    }

    #[tokio::test]
    async fn verify_checksum_missing_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("test.bin");
        tokio::fs::write(&file_path, b"hello world").await.unwrap();

        let checksums = HashMap::new();

        let result = verify_checksum(&checksums, "test.bin", &file_path).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    // -- sha256 helper -------------------------------------------------------

    #[tokio::test]
    async fn sha256_known_value() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("known.bin");
        tokio::fs::write(&file_path, b"hello world").await.unwrap();

        let hash = sha256_file(&file_path).await.unwrap();
        // Known SHA256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[tokio::test]
    async fn sha256_nonexistent_file() {
        let result = sha256_file(Path::new("/nonexistent/path/to/file")).await;
        assert!(result.is_err());
    }

    // -- archive extraction --------------------------------------------------

    #[tokio::test]
    async fn extract_tar_gz_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let cadence_name = cadence_binary_name(build_target()).to_string();
        let updater_name = updater_binary_name(build_target()).to_string();

        // Create a tar.gz archive containing a "cadence" binary
        let archive_path = tmp.path().join("test.tar.gz");
        {
            let file = tokio::fs::File::create(&archive_path).await.unwrap();
            let std_file = file.into_std().await;
            tokio::task::spawn_blocking(move || {
                let encoder =
                    flate2::write::GzEncoder::new(std_file, flate2::Compression::default());
                let mut tar_builder = tar::Builder::new(encoder);

                let content = b"#!/bin/sh\necho hello\n";
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o755);
                header.set_cksum();
                tar_builder
                    .append_data(&mut header, cadence_name, &content[..])
                    .unwrap();

                let updater_content = b"#!/bin/sh\necho updater\n";
                let mut updater_header = tar::Header::new_gnu();
                updater_header.set_size(updater_content.len() as u64);
                updater_header.set_mode(0o755);
                updater_header.set_cksum();
                tar_builder
                    .append_data(&mut updater_header, updater_name, &updater_content[..])
                    .unwrap();
                tar_builder.finish().unwrap();
            })
            .await
            .unwrap();
        }

        let extract_dir = tmp.path().join("out");
        tokio::fs::create_dir_all(&extract_dir).await.unwrap();

        let result = extract_binary(&archive_path, &extract_dir).await.unwrap();
        assert_eq!(
            result.file_name().unwrap(),
            cadence_binary_name(build_target())
        );
        assert!(result.exists());

        let extracted_content = tokio::fs::read(&result).await.unwrap();
        assert_eq!(extracted_content, b"#!/bin/sh\necho hello\n");
    }

    #[tokio::test]
    async fn extract_tar_gz_nested_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let cadence_name = cadence_binary_name(build_target()).to_string();
        let updater_name = updater_binary_name(build_target()).to_string();

        // Create a tar.gz with cadence nested in a subdirectory
        let archive_path = tmp.path().join("nested.tar.gz");
        {
            let file = tokio::fs::File::create(&archive_path).await.unwrap();
            let std_file = file.into_std().await;
            tokio::task::spawn_blocking(move || {
                let encoder =
                    flate2::write::GzEncoder::new(std_file, flate2::Compression::default());
                let mut tar_builder = tar::Builder::new(encoder);

                let content = b"nested binary";
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o755);
                header.set_cksum();
                tar_builder
                    .append_data(&mut header, format!("release/{cadence_name}"), &content[..])
                    .unwrap();

                let updater_content = b"nested updater";
                let mut updater_header = tar::Header::new_gnu();
                updater_header.set_size(updater_content.len() as u64);
                updater_header.set_mode(0o755);
                updater_header.set_cksum();
                tar_builder
                    .append_data(
                        &mut updater_header,
                        format!("release/{updater_name}"),
                        &updater_content[..],
                    )
                    .unwrap();
                tar_builder.finish().unwrap();
            })
            .await
            .unwrap();
        }

        let extract_dir = tmp.path().join("out");
        tokio::fs::create_dir_all(&extract_dir).await.unwrap();

        let result = extract_binary(&archive_path, &extract_dir).await.unwrap();
        assert_eq!(
            result.file_name().unwrap(),
            cadence_binary_name(build_target())
        );
    }

    #[tokio::test]
    async fn extract_tar_gz_no_binary() {
        let tmp = tempfile::tempdir().unwrap();

        let archive_path = tmp.path().join("empty.tar.gz");
        {
            let file = tokio::fs::File::create(&archive_path).await.unwrap();
            let std_file = file.into_std().await;
            tokio::task::spawn_blocking(move || {
                let encoder =
                    flate2::write::GzEncoder::new(std_file, flate2::Compression::default());
                let mut tar_builder = tar::Builder::new(encoder);

                let content = b"readme content";
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                tar_builder
                    .append_data(&mut header, "README.md", &content[..])
                    .unwrap();
                tar_builder.finish().unwrap();
            })
            .await
            .unwrap();
        }

        let extract_dir = tmp.path().join("out");
        tokio::fs::create_dir_all(&extract_dir).await.unwrap();

        let result = extract_binary(&archive_path, &extract_dir).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not contain"));
    }

    #[tokio::test]
    async fn extract_zip_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let cadence_name = cadence_binary_name(build_target()).to_string();
        let updater_name = updater_binary_name(build_target()).to_string();

        let archive_path = tmp.path().join("test.zip");
        {
            let file = tokio::fs::File::create(&archive_path).await.unwrap();
            let std_file = file.into_std().await;
            tokio::task::spawn_blocking(move || {
                let mut zip_writer = zip::ZipWriter::new(std_file);
                let options = zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored);
                zip_writer.start_file(cadence_name, options).unwrap();
                zip_writer.write_all(b"MZ fake exe").unwrap();
                zip_writer.start_file(updater_name, options).unwrap();
                zip_writer.write_all(b"MZ fake updater").unwrap();
                zip_writer.finish().unwrap();
            })
            .await
            .unwrap();
        }

        let extract_dir = tmp.path().join("out");
        tokio::fs::create_dir_all(&extract_dir).await.unwrap();

        let result = extract_binary(&archive_path, &extract_dir).await.unwrap();
        assert_eq!(
            result.file_name().unwrap(),
            cadence_binary_name(build_target())
        );
        assert!(result.exists());
    }

    #[tokio::test]
    async fn extract_zip_no_binary() {
        let tmp = tempfile::tempdir().unwrap();

        let archive_path = tmp.path().join("empty.zip");
        {
            let file = tokio::fs::File::create(&archive_path).await.unwrap();
            let std_file = file.into_std().await;
            tokio::task::spawn_blocking(move || {
                let mut zip_writer = zip::ZipWriter::new(std_file);
                let options = zip::write::SimpleFileOptions::default();
                zip_writer.start_file("README.txt", options).unwrap();
                zip_writer.write_all(b"readme").unwrap();
                zip_writer.finish().unwrap();
            })
            .await
            .unwrap();
        }

        let extract_dir = tmp.path().join("out");
        tokio::fs::create_dir_all(&extract_dir).await.unwrap();

        let result = extract_binary(&archive_path, &extract_dir).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not contain"));
    }

    #[tokio::test]
    async fn extract_unsupported_format() {
        let tmp = tempfile::tempdir().unwrap();
        let archive_path = tmp.path().join("archive.rar");
        tokio::fs::write(&archive_path, b"fake rar").await.unwrap();

        let result = extract_binary(&archive_path, tmp.path()).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unsupported archive")
        );
    }

    // -- archive extension ---------------------------------------------------

    #[tokio::test]
    async fn archive_ext_unix_targets() {
        assert_eq!(archive_extension_for_target("aarch64-apple-darwin"), ".zip");
        assert_eq!(archive_extension_for_target("x86_64-apple-darwin"), ".zip");
        assert_eq!(
            archive_extension_for_target("x86_64-unknown-linux-gnu"),
            ".tar.gz"
        );
        assert_eq!(
            archive_extension_for_target("aarch64-unknown-linux-gnu"),
            ".tar.gz"
        );
    }

    #[tokio::test]
    async fn archive_ext_windows_targets() {
        assert_eq!(
            archive_extension_for_target("x86_64-pc-windows-msvc"),
            ".zip"
        );
        assert_eq!(
            archive_extension_for_target("aarch64-pc-windows-msvc"),
            ".zip"
        );
    }

    // -- build_target --------------------------------------------------------

    #[tokio::test]
    async fn build_target_is_nonempty() {
        let target = build_target();
        assert!(!target.is_empty(), "build_target() should not be empty");
        // Should contain a dash (all canonical triples have dashes)
        assert!(
            target.contains('-'),
            "target should be a triple with dashes: {target}"
        );
    }

    // -- confirm_update ------------------------------------------------------

    #[tokio::test]
    async fn confirm_update_yes_bypass() {
        let result = confirm_update("0.2.1", "0.3.0", true).unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn confirm_update_yes_is_idempotent() {
        let result = confirm_update("0.2.1", "0.3.0", true).unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn confirm_update_without_yes_does_not_auto_accept() {
        let result = confirm_update("0.2.1", "0.3.0", false);
        if let Ok(val) = result {
            assert!(!val, "should not auto-accept without --yes");
        }
    }

    // -- parse_timestamp_string -----------------------------------------------

    #[tokio::test]
    async fn parse_timestamp_epoch_seconds() {
        let ts = parse_timestamp_string("1700000000");
        assert!(ts.is_some());
        let elapsed = ts.unwrap().duration_since(std::time::UNIX_EPOCH).unwrap();
        assert_eq!(elapsed.as_secs(), 1700000000);
    }

    #[tokio::test]
    async fn parse_timestamp_epoch_zero() {
        let ts = parse_timestamp_string("0");
        assert!(ts.is_some());
        let elapsed = ts.unwrap().duration_since(std::time::UNIX_EPOCH).unwrap();
        assert_eq!(elapsed.as_secs(), 0);
    }

    #[tokio::test]
    async fn parse_timestamp_rfc3339() {
        let ts = parse_timestamp_string("2024-01-15T10:30:00Z");
        assert!(ts.is_some());
    }

    #[tokio::test]
    async fn parse_timestamp_rfc3339_with_offset() {
        let ts = parse_timestamp_string("2024-01-15T10:30:00+05:00");
        assert!(ts.is_some());
    }

    #[tokio::test]
    async fn parse_timestamp_empty() {
        assert!(parse_timestamp_string("").is_none());
    }

    #[tokio::test]
    async fn parse_timestamp_garbage() {
        assert!(parse_timestamp_string("not-a-timestamp").is_none());
    }

    #[tokio::test]
    async fn parse_timestamp_negative_epoch() {
        assert!(parse_timestamp_string("-100").is_none());
    }

    #[tokio::test]
    async fn parse_timestamp_float() {
        // Floats are not valid epoch integers
        assert!(parse_timestamp_string("1700000000.5").is_none());
    }

    // -- read/write last_check_timestamp --------------------------------------

    #[tokio::test]
    async fn read_last_check_timestamp_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nonexistent");
        assert!(read_last_check_timestamp(&path).await.is_none());
    }

    #[tokio::test]
    async fn read_last_check_timestamp_empty_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(LAST_UPDATE_CHECK_FILE);
        tokio::fs::write(&path, "").await.unwrap();
        assert!(read_last_check_timestamp(&path).await.is_none());
    }

    #[tokio::test]
    async fn read_last_check_timestamp_whitespace_only() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(LAST_UPDATE_CHECK_FILE);
        tokio::fs::write(&path, "  \n  ").await.unwrap();
        assert!(read_last_check_timestamp(&path).await.is_none());
    }

    #[tokio::test]
    async fn read_last_check_timestamp_valid_epoch() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(LAST_UPDATE_CHECK_FILE);
        tokio::fs::write(&path, "1700000000\n").await.unwrap();
        let ts = read_last_check_timestamp(&path).await;
        assert!(ts.is_some());
        assert_eq!(
            ts.unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1700000000
        );
    }

    #[tokio::test]
    async fn read_last_check_timestamp_valid_rfc3339() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(LAST_UPDATE_CHECK_FILE);
        tokio::fs::write(&path, "2024-01-15T10:30:00Z\n")
            .await
            .unwrap();
        let ts = read_last_check_timestamp(&path).await;
        assert!(ts.is_some());
    }

    #[tokio::test]
    async fn read_last_check_timestamp_malformed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(LAST_UPDATE_CHECK_FILE);
        tokio::fs::write(&path, "not-a-time\n").await.unwrap();
        assert!(read_last_check_timestamp(&path).await.is_none());
    }

    #[tokio::test]
    async fn write_and_read_last_check_timestamp_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(LAST_UPDATE_CHECK_FILE);
        write_last_check_timestamp(&path).await.unwrap();

        let ts = read_last_check_timestamp(&path).await;
        assert!(ts.is_some(), "should read back written timestamp");

        // Timestamp should be recent (within last 10 seconds)
        let elapsed = std::time::SystemTime::now()
            .duration_since(ts.unwrap())
            .unwrap();
        assert!(
            elapsed.as_secs() < 10,
            "timestamp should be recent, got {}s ago",
            elapsed.as_secs()
        );
    }

    #[tokio::test]
    async fn write_last_check_timestamp_creates_parent_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp
            .path()
            .join("sub")
            .join("dir")
            .join(LAST_UPDATE_CHECK_FILE);
        write_last_check_timestamp(&path).await.unwrap();
        assert!(path.exists());
    }

    // -- should_check_for_update -----------------------------------------------

    #[tokio::test]
    async fn should_check_env_var_suppresses() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!should_check_for_update(Some("1"), true, Some(tmp.path())).await);
    }

    #[tokio::test]
    async fn should_check_env_var_other_values_dont_suppress() {
        let tmp = tempfile::tempdir().unwrap();
        // "0", "true", "yes" should NOT suppress — only "1" does
        assert!(should_check_for_update(Some("0"), true, Some(tmp.path())).await);
        assert!(should_check_for_update(Some("true"), true, Some(tmp.path())).await);
        assert!(should_check_for_update(Some(""), true, Some(tmp.path())).await);
    }

    #[tokio::test]
    async fn should_check_non_tty_suppresses() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!should_check_for_update(None, false, Some(tmp.path())).await);
    }

    #[tokio::test]
    async fn should_check_missing_timestamp_runs() {
        let tmp = tempfile::tempdir().unwrap();
        // No timestamp file — check should run
        assert!(should_check_for_update(None, true, Some(tmp.path())).await);
    }

    #[tokio::test]
    async fn should_check_recent_timestamp_skips() {
        let tmp = tempfile::tempdir().unwrap();
        let ts_path = tmp.path().join(LAST_UPDATE_CHECK_FILE);
        // Write a current timestamp
        write_last_check_timestamp(&ts_path).await.unwrap();
        // Should NOT check (just checked)
        assert!(!should_check_for_update(None, true, Some(tmp.path())).await);
    }

    #[tokio::test]
    async fn should_check_old_timestamp_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let ts_path = tmp.path().join(LAST_UPDATE_CHECK_FILE);
        // Write a timestamp from 24 hours ago (well past 8h default)
        let old_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 24 * 3600;
        tokio::fs::write(&ts_path, format!("{old_epoch}\n"))
            .await
            .unwrap();
        assert!(should_check_for_update(None, true, Some(tmp.path())).await);
    }

    #[tokio::test]
    async fn should_check_future_timestamp_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let ts_path = tmp.path().join(LAST_UPDATE_CHECK_FILE);
        // Write a timestamp in the future (clock skew)
        let future_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        tokio::fs::write(&ts_path, format!("{future_epoch}\n"))
            .await
            .unwrap();
        // Clock went "backward" relative to stored time — should check
        assert!(should_check_for_update(None, true, Some(tmp.path())).await);
    }

    #[tokio::test]
    async fn should_check_corrupt_timestamp_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let ts_path = tmp.path().join(LAST_UPDATE_CHECK_FILE);
        tokio::fs::write(&ts_path, "totally-corrupt-data")
            .await
            .unwrap();
        // Corrupt file = can't parse = treat as missing = should check
        assert!(should_check_for_update(None, true, Some(tmp.path())).await);
    }

    #[tokio::test]
    async fn should_check_no_config_dir_runs() {
        // When config_dir is None, fall back to CliConfig::config_dir() internally
        // In test environments this may or may not resolve, but the function
        // should not panic
        let result = should_check_for_update(None, true, None).await;
        // We can't assert true/false deterministically without controlling HOME,
        // but it should not panic
        let _ = result;
    }

    // -- format_update_notification -------------------------------------------

    #[tokio::test]
    async fn format_notification_exact_message() {
        let msg = format_update_notification("0.2.1", "0.3.0");
        assert_eq!(
            msg,
            "A new version of cadence is available: v0.3.0 (current: v0.2.1). Run 'cadence update' to upgrade."
        );
    }

    #[tokio::test]
    async fn format_notification_preserves_version_strings() {
        let msg = format_update_notification("1.0.0", "2.0.0-beta.1");
        assert!(msg.contains("v2.0.0-beta.1"));
        assert!(msg.contains("v1.0.0"));
    }

    // -- auto-update v1 helpers ----------------------------------------------

    #[tokio::test]
    async fn stable_release_filter_accepts_stable_and_rejects_prerelease() {
        assert!(is_stable_release_tag("v1.3.0"));
        assert!(!is_stable_release_tag("v1.4.0-rc.1"));
    }

    #[tokio::test]
    async fn retry_due_respects_next_retry_after() {
        let future = format_epoch_rfc3339(now_epoch() + 300).unwrap();
        let state = UpdaterState {
            next_retry_after: Some(future),
            ..UpdaterState::default()
        };
        assert!(!update_due_for_retry(&state, now_epoch()));
    }

    #[tokio::test]
    async fn updater_health_covers_never_run_retrying_and_disabled() {
        let disabled = derive_updater_health(false, &UpdaterState::default());
        assert_eq!(disabled.state, UpdaterHealthState::Disabled);

        let never = derive_updater_health(true, &UpdaterState::default());
        assert_eq!(never.state, UpdaterHealthState::NeverRun);

        let retrying = derive_updater_health(
            true,
            &UpdaterState {
                last_attempt_at: Some(state_files::now_rfc3339()),
                consecutive_failures: 2,
                next_retry_after: Some(state_files::now_rfc3339()),
                last_error: Some("network".to_string()),
                ..UpdaterState::default()
            },
        );
        assert_eq!(retrying.state, UpdaterHealthState::Retrying);
    }

    #[test]
    fn background_update_attempt_error_records_failure_instead_of_success() {
        let now = "2026-03-29T00:00:00Z";
        let mut state = UpdaterState {
            last_seen_version: Some("1.2.3".to_string()),
            ..UpdaterState::default()
        };

        apply_background_update_attempt_result(
            &mut state,
            now,
            Err(anyhow::anyhow!(
                "cadence updated, but the new version could not finish runtime bootstrap automatically"
            )),
            1_700_000_000,
        );

        assert_eq!(state.last_success_at, None);
        assert_eq!(state.last_installed_version, None);
        assert_eq!(state.consecutive_failures, 1);
        assert!(
            state
                .last_error
                .as_deref()
                .is_some_and(|value| value.contains("runtime bootstrap automatically"))
        );
        assert!(state.next_retry_after.is_some());
    }

    #[tokio::test]
    #[serial]
    async fn activity_lock_nonblocking_skips_when_held() {
        let tmp = tempfile::tempdir().unwrap();
        let home = EnvGuard::new("HOME");
        home.set(tmp.path().to_str().unwrap());

        let mut child = if cfg!(windows) {
            Command::new("cmd")
                .args(["/C", "ping -n 4 127.0.0.1 >NUL"])
                .spawn()
                .expect("spawn holder child")
        } else {
            Command::new("sh")
                .args(["-c", "sleep 0.4"])
                .spawn()
                .expect("spawn holder child")
        };
        let holder_pid = child.id().expect("holder pid");
        let lock_path = activity_lock_path().expect("activity lock path");
        tokio::fs::create_dir_all(lock_path.parent().expect("lock parent"))
            .await
            .expect("create lock dir");
        state_files::write_json_atomic(
            &lock_path,
            &ActivityLockRecord {
                pid: holder_pid,
                process_started_at_epoch: process_started_at_epoch(holder_pid),
                created_at_epoch: now_epoch(),
                hostname: host_name(),
                purpose: "test-holder".to_string(),
            },
        )
        .await
        .expect("seed foreign lock");
        let other = try_acquire_activity_lock_nonblocking("test-other")
            .await
            .expect("try lock");
        assert!(other.is_none());
        child.wait().await.expect("wait holder child");
        clear_stale_activity_lock(&lock_path)
            .await
            .expect("clear stale foreign lock");

        let reacquired = try_acquire_activity_lock_nonblocking("test-after-drop")
            .await
            .expect("reacquire");
        assert!(reacquired.is_some());
    }

    #[tokio::test]
    #[serial]
    async fn activity_lock_reentrant_for_current_process() {
        let tmp = tempfile::tempdir().unwrap();
        let home = EnvGuard::new("HOME");
        home.set(tmp.path().to_str().unwrap());

        let first = acquire_command_activity_lock("test-first")
            .await
            .expect("acquire first lock");
        let second = try_acquire_activity_lock_nonblocking("test-second")
            .await
            .expect("reacquire lock")
            .expect("same-process reacquire should succeed");
        let lock_path = activity_lock_path().expect("activity lock path");
        assert!(
            lock_path.exists(),
            "lock file should exist while guards are held"
        );

        drop(first);
        assert!(
            lock_path.exists(),
            "dropping one guard should not release a reentrant lock"
        );

        drop(second);
        assert!(
            !lock_path.exists(),
            "dropping the final guard should remove the lock file"
        );
    }

    #[tokio::test]
    #[serial]
    async fn command_activity_lock_rejects_active_update_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let home = EnvGuard::new("HOME");
        home.set(tmp.path().to_str().unwrap());

        let mut child = if cfg!(windows) {
            Command::new("cmd")
                .args(["/C", "ping -n 4 127.0.0.1 >NUL"])
                .spawn()
                .expect("spawn marker child")
        } else {
            Command::new("sh")
                .args(["-c", "sleep 0.4"])
                .spawn()
                .expect("spawn marker child")
        };
        let helper_pid = child.id().expect("child pid");
        write_update_in_progress_record(&UpdateInProgressRecord {
            target_version: "9.9.9".to_string(),
            final_cadence_path: tmp
                .path()
                .join("install")
                .join(cadence_binary_name(build_target())),
            initiator_pid: 0,
            initiator_started_at_epoch: None,
            helper_pid: Some(helper_pid),
            helper_started_at_epoch: process_started_at_epoch(helper_pid),
            helper_systemd_unit: None,
            created_at_epoch: now_epoch(),
        })
        .await
        .expect("write update marker");

        let err = acquire_command_activity_lock("test-command")
            .await
            .expect_err("update marker should block new commands");
        assert!(
            err.to_string().contains("update to v9.9.9 is in progress"),
            "unexpected error: {err:#}"
        );

        child.wait().await.expect("wait marker child");
        clear_update_in_progress_record()
            .await
            .expect("clear update marker");
    }

    #[tokio::test]
    #[serial]
    async fn stale_update_in_progress_marker_is_reclaimed() {
        let tmp = tempfile::tempdir().unwrap();
        let home = EnvGuard::new("HOME");
        home.set(tmp.path().to_str().unwrap());

        write_update_in_progress_record(&UpdateInProgressRecord {
            target_version: "9.9.9".to_string(),
            final_cadence_path: tmp
                .path()
                .join("install")
                .join(cadence_binary_name(build_target())),
            initiator_pid: 0,
            initiator_started_at_epoch: None,
            helper_pid: Some(0),
            helper_started_at_epoch: None,
            helper_systemd_unit: None,
            created_at_epoch: now_epoch(),
        })
        .await
        .expect("write stale marker");

        let active = current_update_in_progress_record()
            .await
            .expect("load update marker");
        assert!(active.is_none(), "stale marker should be cleared");
        assert!(
            load_update_in_progress_record(&update_in_progress_path().expect("marker path"))
                .await
                .expect("reload update marker")
                .is_none()
        );
    }

    #[tokio::test]
    #[serial]
    async fn update_in_progress_marker_is_reclaimed_on_pid_start_time_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let home = EnvGuard::new("HOME");
        home.set(tmp.path().to_str().unwrap());

        let mut child = if cfg!(windows) {
            Command::new("cmd")
                .args(["/C", "ping -n 4 127.0.0.1 >NUL"])
                .spawn()
                .expect("spawn marker child")
        } else {
            Command::new("sh")
                .args(["-c", "sleep 0.4"])
                .spawn()
                .expect("spawn marker child")
        };
        let helper_pid = child.id().expect("child pid");
        let mismatched_start = process_started_at_epoch(helper_pid)
            .map(|value| value.saturating_add(1))
            .or(Some(1));
        write_update_in_progress_record(&UpdateInProgressRecord {
            target_version: "9.9.9".to_string(),
            final_cadence_path: tmp
                .path()
                .join("install")
                .join(cadence_binary_name(build_target())),
            initiator_pid: 0,
            initiator_started_at_epoch: None,
            helper_pid: Some(helper_pid),
            helper_started_at_epoch: mismatched_start,
            helper_systemd_unit: None,
            created_at_epoch: now_epoch(),
        })
        .await
        .expect("write stale marker");

        let active = current_update_in_progress_record()
            .await
            .expect("load update marker");
        assert!(
            active.is_none(),
            "mismatched pid start time should clear marker"
        );
        assert!(
            load_update_in_progress_record(&update_in_progress_path().expect("marker path"))
                .await
                .expect("reload update marker")
                .is_none()
        );

        child.wait().await.expect("wait marker child");
    }

    #[tokio::test]
    #[serial]
    #[cfg(windows)]
    async fn prepare_updater_helper_launch_path_moves_helper_out_of_staging_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let home = EnvGuard::new("HOME");
        home.set(tmp.path().to_str().unwrap());

        let staging_dir = tmp.path().join("staging");
        tokio::fs::create_dir_all(&staging_dir)
            .await
            .expect("create staging dir");
        let helper_path = staging_dir.join("cadence-updater.exe");
        tokio::fs::write(&helper_path, b"MZ")
            .await
            .expect("write staged helper");

        let launch_path = prepare_updater_helper_launch_path(&helper_path, "9.9.9")
            .await
            .expect("prepare helper launch path");
        assert!(launch_path.exists(), "launch helper should exist");
        assert!(
            !launch_path.starts_with(&staging_dir),
            "windows helper should not run from the staging directory"
        );
        assert!(
            launch_path.starts_with(updater_helper_runtime_root()),
            "helper launch path should live under the helper runtime root"
        );
    }

    #[tokio::test]
    #[serial]
    #[cfg(target_os = "linux")]
    async fn launch_updater_helper_uses_systemd_run_when_running_inside_systemd_unit() {
        let tmp = tempfile::tempdir().unwrap();
        let path_guard = EnvGuard::new("PATH");
        let invocation_guard = EnvGuard::new("INVOCATION_ID");
        let runtime_guard = EnvGuard::new("XDG_RUNTIME_DIR");
        invocation_guard.set("test-invocation");

        let bin_dir = tmp.path().join("bin");
        let pid_dir = tmp.path().join("pids");
        let runtime_dir = tmp.path().join("runtime");
        tokio::fs::create_dir_all(&bin_dir)
            .await
            .expect("create fake bin dir");
        tokio::fs::create_dir_all(&pid_dir)
            .await
            .expect("create pid dir");
        tokio::fs::create_dir_all(&runtime_dir)
            .await
            .expect("create runtime dir");
        tokio::fs::write(runtime_dir.join("bus"), b"")
            .await
            .expect("write fake runtime bus");
        runtime_guard.set(runtime_dir.to_str().expect("runtime dir utf-8"));

        let helper_started = tmp.path().join("helper-started");
        let helper_path = tmp.path().join("cadence-updater");
        tokio::fs::write(
            &helper_path,
            format!(
                "#!/bin/sh\n\
                 touch '{}'\n\
                 sleep 0.5\n",
                helper_started.display()
            ),
        )
        .await
        .expect("write fake helper");
        set_executable_permissions(&helper_path)
            .await
            .expect("chmod fake helper");

        let systemd_run_path = bin_dir.join("systemd-run");
        tokio::fs::write(
            &systemd_run_path,
            format!(
                "#!/bin/sh\n\
                 unit=\"\"\n\
                 while [ \"$#\" -gt 0 ]; do\n\
                   case \"$1\" in\n\
                     --user|--quiet|--collect)\n\
                       shift\n\
                       ;;\n\
                     --unit)\n\
                       unit=\"$2\"\n\
                       shift 2\n\
                       ;;\n\
                     *)\n\
                       break\n\
                       ;;\n\
                   esac\n\
                 done\n\
                 if [ -z \"$unit\" ]; then\n\
                   echo \"missing unit\" >&2\n\
                   exit 1\n\
                 fi\n\
                 \"$@\" &\n\
                 pid=$!\n\
                 printf '%s\\n' \"$pid\" > '{}/'$unit\n",
                pid_dir.display()
            ),
        )
        .await
        .expect("write fake systemd-run");
        set_executable_permissions(&systemd_run_path)
            .await
            .expect("chmod fake systemd-run");

        let systemctl_path = bin_dir.join("systemctl");
        tokio::fs::write(
            &systemctl_path,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1\" != \"--user\" ]; then\n\
                   exit 1\n\
                 fi\n\
                 shift\n\
                 case \"$1\" in\n\
                   show)\n\
                     shift\n\
                     if [ \"$1\" != \"--value\" ] || [ \"$2\" != \"--property\" ]; then\n\
                       exit 1\n\
                     fi\n\
                     prop=\"$3\"\n\
                     unit=\"$4\"\n\
                     pid_file='{pid_dir}/'$unit\n\
                     case \"$prop\" in\n\
                       MainPID)\n\
                         if [ -f \"$pid_file\" ]; then\n\
                           cat \"$pid_file\"\n\
                         else\n\
                           echo 0\n\
                         fi\n\
                         ;;\n\
                       ActiveState)\n\
                         if [ -f \"$pid_file\" ] && kill -0 \"$(cat \"$pid_file\")\" 2>/dev/null; then\n\
                           echo active\n\
                         else\n\
                           echo inactive\n\
                         fi\n\
                         ;;\n\
                       *)\n\
                         echo \"\"\n\
                         ;;\n\
                     esac\n\
                     ;;\n\
                   stop)\n\
                     shift\n\
                     unit=\"$1\"\n\
                     pid_file='{pid_dir}/'$unit\n\
                     if [ -f \"$pid_file\" ]; then\n\
                       kill \"$(cat \"$pid_file\")\" 2>/dev/null || true\n\
                     fi\n\
                     ;;\n\
                   *)\n\
                     exit 1\n\
                     ;;\n\
                 esac\n",
                pid_dir = pid_dir.display()
            ),
        )
        .await
        .expect("write fake systemctl");
        set_executable_permissions(&systemctl_path)
            .await
            .expect("chmod fake systemctl");

        let original_path = std::env::var("PATH").unwrap_or_default();
        path_guard.set(&format!("{}:{original_path}", bin_dir.display()));

        let manifest_path = tmp.path().join("install-manifest.json");
        tokio::fs::write(&manifest_path, b"{}")
            .await
            .expect("write fake manifest");

        let launch = launch_updater_helper(&helper_path, &manifest_path, "9.9.9")
            .await
            .expect("launch helper via fake systemd");
        assert!(
            launch.child.is_none(),
            "systemd launch should not retain a child handle"
        );
        assert!(
            launch
                .helper_systemd_unit
                .as_deref()
                .is_some_and(|unit| unit.starts_with("cadence-updater-9-9-9-")),
            "unexpected systemd unit: {:?}",
            launch.helper_systemd_unit
        );
        let helper_pid = launch.helper_pid.expect("helper pid from systemd");
        assert_eq!(
            launch.helper_started_at_epoch,
            process_started_at_epoch(helper_pid)
        );

        tokio::time::timeout(Duration::from_secs(5), async {
            while !helper_started.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("helper should start");

        wait_for_pid_to_exit(
            helper_pid,
            launch.helper_started_at_epoch,
            Duration::from_secs(5),
        )
        .await
        .expect("wait for fake helper exit");
    }

    #[tokio::test]
    #[serial]
    #[cfg(target_os = "linux")]
    async fn launch_updater_helper_falls_back_without_systemd_user_manager() {
        let tmp = tempfile::tempdir().unwrap();
        let invocation_guard = EnvGuard::new("INVOCATION_ID");
        let runtime_guard = EnvGuard::new("XDG_RUNTIME_DIR");
        invocation_guard.set("test-invocation");
        runtime_guard.set(tmp.path().to_str().expect("tmp path utf-8"));

        let helper_started = tmp.path().join("helper-started");
        let helper_path = tmp.path().join("cadence-updater");
        tokio::fs::write(
            &helper_path,
            format!(
                "#!/bin/sh\n\
                 touch '{}'\n\
                 sleep 0.2\n",
                helper_started.display()
            ),
        )
        .await
        .expect("write fake helper");
        set_executable_permissions(&helper_path)
            .await
            .expect("chmod fake helper");

        let manifest_path = tmp.path().join("install-manifest.json");
        tokio::fs::write(&manifest_path, b"{}")
            .await
            .expect("write fake manifest");

        let launch = launch_updater_helper(&helper_path, &manifest_path, "9.9.9")
            .await
            .expect("launch helper without systemd user manager");
        assert!(launch.child.is_some(), "expected child-process fallback");
        assert!(
            launch.helper_systemd_unit.is_none(),
            "systemd unit should not be recorded when no user manager is reachable"
        );

        tokio::time::timeout(Duration::from_secs(5), async {
            while !helper_started.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("helper should start");

        let mut child = launch.child.expect("child-process fallback handle");
        let status = child.wait().await.expect("wait for fake helper exit");
        assert!(
            status.success(),
            "unexpected fallback helper status: {status}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn activity_lock_blocking_times_out_when_held() {
        let tmp = tempfile::tempdir().unwrap();
        let home = EnvGuard::new("HOME");
        home.set(tmp.path().to_str().unwrap());

        let mut child = if cfg!(windows) {
            Command::new("cmd")
                .args(["/C", "ping -n 4 127.0.0.1 >NUL"])
                .spawn()
                .expect("spawn holder child")
        } else {
            Command::new("sh")
                .args(["-c", "sleep 0.4"])
                .spawn()
                .expect("spawn holder child")
        };
        let holder_pid = child.id().expect("holder pid");
        let lock_path = activity_lock_path().expect("activity lock path");
        tokio::fs::create_dir_all(lock_path.parent().expect("lock parent"))
            .await
            .expect("create lock dir");
        state_files::write_json_atomic(
            &lock_path,
            &ActivityLockRecord {
                pid: holder_pid,
                process_started_at_epoch: process_started_at_epoch(holder_pid),
                created_at_epoch: now_epoch(),
                hostname: host_name(),
                purpose: "test-holder".to_string(),
            },
        )
        .await
        .expect("seed foreign lock");
        let err = acquire_activity_lock_blocking_with_timeout(
            "test-waiter",
            Duration::from_millis(75),
            false,
        )
        .await
        .expect_err("timeout");
        assert!(
            err.to_string()
                .contains("timed out waiting for global activity lock"),
            "unexpected error: {err:#}"
        );

        child.wait().await.expect("wait holder child");
    }

    #[tokio::test]
    #[serial]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn uninstall_scheduler_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let home = EnvGuard::new("HOME");
        home.set(tmp.path().to_str().unwrap());

        uninstall_auto_update_scheduler()
            .await
            .expect("first uninstall");
        uninstall_auto_update_scheduler()
            .await
            .expect("second uninstall");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn run_install_with_exe_invokes_install_with_preserved_disable_state() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let script = tmp.path().join("cadence");
        let args_log = tmp.path().join("args.log");
        let env_log = tmp.path().join("env.log");
        let script_contents = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"{}\"\nprintf '%s' \"$CADENCE_NO_UPDATE_CHECK\" > \"{}\"\n",
            args_log.display(),
            env_log.display()
        );
        tokio::fs::write(&script, script_contents)
            .await
            .expect("write script");

        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .await
            .expect("chmod script");

        run_install_with_exe(&script, true)
            .await
            .expect("run install with exe");

        let args = tokio::fs::read_to_string(&args_log)
            .await
            .expect("read args log");
        assert_eq!(args, "install\n--preserve-disable-state\n");

        let env = tokio::fs::read_to_string(&env_log)
            .await
            .expect("read env log");
        assert_eq!(env, "1");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn run_install_with_exe_surfaces_command_failure() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let script = tmp.path().join("cadence");
        tokio::fs::write(&script, "#!/bin/sh\nexit 7\n")
            .await
            .expect("write script");

        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .await
            .expect("chmod script");

        let err = run_install_with_exe(&script, true)
            .await
            .expect_err("expected install handoff failure");
        assert!(
            err.to_string().contains("bootstrap install command failed"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn install_manifest_round_trip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let manifest_path = tmp.path().join("install-manifest.json");
        let manifest = UpdateInstallManifest {
            target_version: "9.9.9".to_string(),
            staged_cadence_path: tmp.path().join("staged").join("cadence"),
            final_cadence_path: tmp.path().join("install").join("cadence"),
            wait_for_pid: 4242,
            wait_for_pid_started_at_epoch: Some(123),
            preserve_disable_state: true,
            mode: InstallMode::SilentUnattended,
        };

        write_install_manifest(&manifest_path, &manifest)
            .await
            .expect("write manifest");
        let loaded = load_install_manifest(&manifest_path)
            .await
            .expect("load manifest");
        assert_eq!(loaded, manifest);
    }

    #[tokio::test]
    async fn wait_for_pid_to_exit_observes_short_lived_child() {
        let mut child = if cfg!(windows) {
            Command::new("cmd")
                .args(["/C", "ping -n 2 127.0.0.1 >NUL"])
                .spawn()
                .expect("spawn wait child")
        } else {
            Command::new("sh")
                .args(["-c", "sleep 0.2"])
                .spawn()
                .expect("spawn wait child")
        };

        let pid = child.id().expect("child pid");
        let pid_started_at = process_started_at_epoch(pid);
        let reap_child =
            tokio::spawn(async move { child.wait().await.expect("wait child status") });
        wait_for_pid_to_exit(pid, pid_started_at, Duration::from_secs(5))
            .await
            .expect("wait for child exit");
        let status = reap_child.await.expect("join child wait");
        assert!(status.success());
    }

    #[tokio::test]
    #[serial]
    async fn record_helper_result_persists_installed_version() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = EnvGuard::new("HOME");
        home.set(tmp.path().to_str().unwrap());

        let manifest = UpdateInstallManifest {
            target_version: "9.9.9".to_string(),
            staged_cadence_path: tmp.path().join("staged").join("cadence"),
            final_cadence_path: tmp.path().join("install").join("cadence"),
            wait_for_pid: 0,
            wait_for_pid_started_at_epoch: None,
            preserve_disable_state: true,
            mode: InstallMode::Interactive,
        };

        record_helper_result(&manifest, &Ok(()))
            .await
            .expect("record helper result");
        let state = load_updater_state().await.expect("load updater state");
        assert_eq!(state.last_installed_version.as_deref(), Some("9.9.9"));
        assert_eq!(state.consecutive_failures, 0);
    }

    // -- check_latest_version_from_url_with_timeout ---------------------------

    #[tokio::test]
    async fn check_with_timeout_connection_refused() {
        let result = check_latest_version_from_url_with_timeout(
            "http://127.0.0.1:1/nonexistent",
            Duration::from_millis(100),
        )
        .await;
        assert!(result.is_err());
    }
}
