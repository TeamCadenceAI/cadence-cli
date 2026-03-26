//! Self-update version checking and self-replace for cadence-cli.
//!
//! Queries the GitHub Releases API to determine if a newer version is available,
//! and provides a full self-update flow: download, checksum verification,
//! archive extraction, and in-place binary replacement.
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
use std::process::{Output, Stdio};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::config::CliConfig;
use crate::transport;

#[cfg(not(any(unix, windows)))]
use sysinfo::{Pid, System};
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{CloseHandle, WAIT_TIMEOUT},
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

/// User-Agent header sent with GitHub API requests.
const USER_AGENT: &str = "cadence-cli";

/// HTTP request timeout for version checks.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Updater state file name under `~/.cadence/cli/`.
const UPDATER_STATE_FILE: &str = "updater-state.json";

/// Shared activity lock directory/file for hook + deferred sync + updater coordination.
const ACTIVITY_LOCKS_DIR: &str = "locks";
const ACTIVITY_LOCK_FILE: &str = "global-activity.lock";
const ACTIVITY_LOCK_STALE_SECS: i64 = 15 * 60;
const ACTIVITY_LOCK_POLL_INTERVAL_MS: u64 = 20;
const ACTIVITY_LOCK_BLOCKING_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(windows)]
const WINDOWS_SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

/// Scheduler cadence and jitter defaults.
const AUTO_UPDATE_INTERVAL_SECS: u64 = 60 * 60;
const AUTO_UPDATE_JITTER_SECS: u64 = 5 * 60;

/// Retry backoff defaults.
const UPDATE_RETRY_BASE_SECS: u64 = 60;
const UPDATE_RETRY_MAX_SECS: u64 = 8 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActivityLockRecord {
    pid: u32,
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
        let _ = std::fs::remove_file(&self.path);
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

#[derive(Debug, Clone, Copy)]
enum InstallMode {
    Interactive,
    SilentUnattended,
}

#[derive(Debug, Clone, Copy)]
enum AttemptOutcome {
    NoUpdate,
    Installed,
    SkippedUnstable,
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

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
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

fn cadence_dir() -> Result<PathBuf> {
    CliConfig::config_dir().ok_or_else(|| {
        anyhow::anyhow!("cannot determine cadence config directory: $HOME is not set")
    })
}

pub async fn persist_auto_update_enabled() -> Result<bool> {
    let mut cfg = CliConfig::load().await?;
    if cfg.auto_update == Some(true) {
        return Ok(false);
    }
    cfg.auto_update = Some(true);
    cfg.save().await?;
    Ok(true)
}

pub async fn ensure_auto_update_enabled_and_reconciled() -> Result<SchedulerProvisionResult> {
    let _ = persist_auto_update_enabled().await?;
    reconcile_scheduler_for_auto_update_enabled(true).await
}

fn update_confirmation_config(mode: InstallMode, config: Option<&CliConfig>) -> Option<bool> {
    if matches!(mode, InstallMode::Interactive) {
        return config.map(CliConfig::auto_update_enabled);
    }
    None
}

fn updater_state_path() -> Result<PathBuf> {
    Ok(cadence_dir()?.join(UPDATER_STATE_FILE))
}

fn activity_lock_path() -> Result<PathBuf> {
    Ok(cadence_dir()?
        .join(ACTIVITY_LOCKS_DIR)
        .join(ACTIVITY_LOCK_FILE))
}

async fn write_json_atomic<T: ?Sized + Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("path has no parent: {}", path.display()))?;
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("failed to create directory {}", parent.display()))?;
    let tmp = path.with_extension("tmp");
    let payload = serde_json::to_vec_pretty(value).context("failed to serialize JSON")?;
    tokio::fs::write(&tmp, payload)
        .await
        .with_context(|| format!("failed to write temporary file {}", tmp.display()))?;
    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!("failed to atomically replace {}", path.display()))?;
    Ok(())
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
    write_json_atomic(&path, state).await
}

fn is_pid_alive(pid: u32) -> bool {
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
        return alive;
    }

    #[cfg(not(any(unix, windows)))]
    {
        let mut system = System::new();
        system.refresh_processes();
        return system.process(Pid::from_u32(pid)).is_some();
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

async fn clear_stale_activity_lock(path: &Path) -> Result<()> {
    let content = match tokio::fs::read_to_string(path).await {
        Ok(v) => v,
        Err(_) => {
            let _ = tokio::fs::remove_file(path).await;
            return Ok(());
        }
    };
    let parsed = match serde_json::from_str::<ActivityLockRecord>(&content) {
        Ok(v) => v,
        Err(_) => {
            let _ = tokio::fs::remove_file(path).await;
            return Ok(());
        }
    };
    let age = now_epoch().saturating_sub(parsed.created_at_epoch);
    // If owner process is gone or lock is stale, reclaim it.
    if age > ACTIVITY_LOCK_STALE_SECS || !is_pid_alive(parsed.pid) {
        let _ = tokio::fs::remove_file(path).await;
    }
    Ok(())
}

pub async fn acquire_activity_lock_blocking(purpose: &str) -> Result<ActivityLockGuard> {
    acquire_activity_lock_blocking_with_timeout(purpose, ACTIVITY_LOCK_BLOCKING_TIMEOUT).await
}

async fn acquire_activity_lock_blocking_with_timeout(
    purpose: &str,
    timeout: Duration,
) -> Result<ActivityLockGuard> {
    let lock_path = activity_lock_path()?;
    if let Some(parent) = lock_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let record = ActivityLockRecord {
        pid: std::process::id(),
        created_at_epoch: now_epoch(),
        hostname: host_name(),
        purpose: purpose.to_string(),
    };
    let started_at = tokio::time::Instant::now();
    loop {
        if try_create_activity_lock(&lock_path, &record).await? {
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
        tokio::time::sleep(remaining.min(Duration::from_millis(ACTIVITY_LOCK_POLL_INTERVAL_MS)))
            .await;
    }
}

pub async fn try_acquire_activity_lock_nonblocking(
    purpose: &str,
) -> Result<Option<ActivityLockGuard>> {
    let lock_path = activity_lock_path()?;
    if let Some(parent) = lock_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    clear_stale_activity_lock(&lock_path).await?;
    let record = ActivityLockRecord {
        pid: std::process::id(),
        created_at_epoch: now_epoch(),
        hostname: host_name(),
        purpose: purpose.to_string(),
    };
    if try_create_activity_lock(&lock_path, &record).await? {
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
    check_latest_version_from_url(GITHUB_RELEASES_LATEST_URL).await
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

// ---------------------------------------------------------------------------
// Artifact selection
// ---------------------------------------------------------------------------

/// Returns the compile-time target triple (e.g., "aarch64-apple-darwin").
pub fn build_target() -> &'static str {
    env!("TARGET")
}

/// Determines the expected archive extension for a given target triple.
/// Windows targets use `.zip`, all others use `.tar.gz`.
pub fn archive_extension_for_target(target: &str) -> &'static str {
    if target.contains("windows") {
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

/// Extracts the cadence binary from a tar.gz archive into `dest_dir`.
/// Returns the path to the extracted binary.
fn extract_tar_gz_from_file(
    file: std::fs::File,
    archive_path: &Path,
    dest_dir: &Path,
) -> Result<PathBuf> {
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);

    let mut found = None;
    for entry_result in archive.entries().context("Failed to read tar entries")? {
        let mut entry = entry_result.context("Failed to read tar entry")?;
        let entry_path = entry.path().context("Failed to read tar entry path")?;

        // Match the binary name at any nesting depth
        let file_name = entry_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if file_name == BINARY_NAME {
            let dest = dest_dir.join(BINARY_NAME);
            entry
                .unpack(&dest)
                .with_context(|| format!("Failed to extract '{BINARY_NAME}' from archive"))?;
            found = Some(dest);
            break;
        }
    }

    found.ok_or_else(|| {
        anyhow::anyhow!(
            "Archive does not contain '{BINARY_NAME}' binary: {}",
            archive_path.display()
        )
    })
}

/// Extracts the cadence binary from a zip archive into `dest_dir`.
/// Returns the path to the extracted binary.
fn extract_zip_from_file(
    file: std::fs::File,
    archive_path: &Path,
    dest_dir: &Path,
) -> Result<PathBuf> {
    let mut archive = zip::ZipArchive::new(file).context("Failed to read zip archive")?;

    let binary_name_exe = format!("{BINARY_NAME}.exe");

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).context("Failed to read zip entry")?;

        let entry_name = entry.name().to_string();
        let file_name = Path::new(&entry_name)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if file_name == BINARY_NAME || file_name == binary_name_exe {
            let dest = dest_dir.join(file_name);
            let mut out_file = std::fs::File::create(&dest)
                .with_context(|| format!("Failed to create extracted file: {}", dest.display()))?;
            io::copy(&mut entry, &mut out_file).context("Failed to write extracted binary")?;
            return Ok(dest);
        }
    }

    bail!(
        "Archive does not contain '{BINARY_NAME}' or '{binary_name_exe}' binary: {}",
        archive_path.display()
    )
}

/// Extracts the cadence binary from a release archive (tar.gz or zip).
///
/// Dispatches to the appropriate extractor based on the archive file extension.
pub async fn extract_binary(archive_path: &Path, dest_dir: &Path) -> Result<PathBuf> {
    enum ArchiveKind {
        TarGz,
        Zip,
    }

    let archive_path = archive_path.to_path_buf();
    let dest_dir = dest_dir.to_path_buf();
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
        ArchiveKind::TarGz => extract_tar_gz_from_file(std_file, &archive_path, &dest_dir),
        ArchiveKind::Zip => extract_zip_from_file(std_file, &archive_path, &dest_dir),
    })
    .await
    .context("archive extraction task failed")?
}

// ---------------------------------------------------------------------------
// Binary replacement
// ---------------------------------------------------------------------------

/// Replaces the currently running binary with the file at `replacement_path`.
///
/// Uses the `self_replace` crate for cross-platform atomic replacement.
pub fn self_replace_binary(replacement_path: &Path) -> Result<()> {
    if !replacement_path.exists() {
        bail!(
            "Replacement binary does not exist: {}",
            replacement_path.display()
        );
    }

    self_replace::self_replace(replacement_path).with_context(|| {
        format!(
            "Failed to replace the running binary. \
             This may be a permissions issue — try running with elevated privileges.\n\
             Replacement file: {}",
            replacement_path.display()
        )
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Confirmation prompt
// ---------------------------------------------------------------------------

/// Asks the user to confirm the update. Returns `true` if they accept.
///
/// Precedence (highest wins):
/// 1. `yes` (`--yes` CLI flag) — always skips prompt
/// 2. `auto_update_config` — if `Some(true)`, skips prompt (from config `auto_update = true`)
/// 3. Interactive prompt — asks user with [y/N] default No
pub fn confirm_update(
    local_version: &str,
    remote_version: &str,
    yes: bool,
    auto_update_config: Option<bool>,
) -> Result<bool> {
    // --yes flag always wins
    if yes {
        return Ok(true);
    }

    // Config-driven auto-update skips prompt when true
    if auto_update_config.unwrap_or(false) {
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

/// Runs the full self-update flow.
///
/// If `check` is true, only checks and prints whether an update is available.
/// Otherwise, downloads, verifies, extracts, and replaces the running binary.
pub async fn run_update(check: bool, yes: bool) -> Result<bool> {
    if check {
        run_update_check().await?;
        return Ok(false);
    }

    Ok(matches!(
        run_update_install(yes).await?,
        AttemptOutcome::Installed
    ))
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
    run_update_install_from_url_mode(GITHUB_RELEASES_LATEST_URL, yes, InstallMode::Interactive)
        .await
}

/// Install path with injectable URL for testing.
#[allow(dead_code)]
pub async fn run_update_install_from_url(release_url: &str, yes: bool) -> Result<()> {
    let _ = run_update_install_from_url_mode(release_url, yes, InstallMode::Interactive).await?;
    Ok(())
}

async fn run_install_with_updated_binary(preserve_disable_state: bool) -> Result<()> {
    let current_exe = std::env::current_exe()
        .context("failed to resolve current cadence executable path after self-update")?;
    run_install_with_exe(&current_exe, preserve_disable_state).await
}

async fn run_install_with_exe(exe_path: &Path, preserve_disable_state: bool) -> Result<()> {
    let mut command = Command::new(exe_path);
    command.arg("install");
    if preserve_disable_state {
        command.arg("--preserve-disable-state");
    }
    let status = command
        .env(PASSIVE_CHECK_ENV_VAR, "1")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .with_context(|| {
            format!(
                "failed to launch bootstrap install with {}",
                exe_path.display()
            )
        })?;

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

    let config = if matches!(mode, InstallMode::Interactive) {
        // Manual update keeps config load strict to preserve existing UX.
        Some(CliConfig::load().await.context(
            "Failed to load config. Check ~/.cadence/cli/config.toml for syntax errors.",
        )?)
    } else {
        None
    };

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
    // Precedence: --yes > config auto_update > interactive prompt
    if matches!(mode, InstallMode::Interactive)
        && !confirm_update(
            local,
            remote_display,
            yes,
            update_confirmation_config(mode, config.as_ref()),
        )?
    {
        println!("Update cancelled.");
        return Ok(AttemptOutcome::NoUpdate);
    }

    let _activity_guard = if matches!(mode, InstallMode::SilentUnattended) {
        Some(
            try_acquire_activity_lock_nonblocking("auto-update")
                .await?
                .ok_or_else(|| anyhow::anyhow!("global activity lock is busy"))?,
        )
    } else {
        None
    };

    // Step 5: Download to temp directory
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

    // Step 7: Extract binary
    let extract_dir = tmp_dir.path().join("extracted");
    tokio::fs::create_dir_all(&extract_dir)
        .await
        .context("Failed to create extraction directory")?;
    let new_binary = extract_binary(&artifact_path, &extract_dir).await?;

    // Step 8: Set executable permission on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        tokio::fs::set_permissions(&new_binary, perms)
            .await
            .context("Failed to set executable permissions on extracted binary")?;
    }

    // Step 9: Replace running binary
    self_replace_binary(&new_binary)?;

    if let Err(err) = run_install_with_updated_binary(true).await {
        report_best_effort_post_upgrade_failure(
            mode,
            "the new version could not finish runtime bootstrap automatically",
            "Run `cadence install` to reconcile background monitoring and clean up legacy Cadence hook ownership.",
            &err,
        );
    }

    if matches!(mode, InstallMode::Interactive) {
        println!("Successfully updated cadence v{local} → v{remote_display}");
    }

    Ok(AttemptOutcome::Installed)
}

async fn apply_auto_update_jitter() {
    let jitter = rand08::Rng::gen_range(&mut rand08::thread_rng(), 0..=AUTO_UPDATE_JITTER_SECS);
    if jitter > 0 {
        tokio::time::sleep(Duration::from_secs(jitter)).await;
    }
}

fn retry_delay_from_state(state: &UpdaterState) -> u64 {
    retry_delay_secs(state.consecutive_failures.max(1))
}

pub async fn run_background_auto_update() -> Result<()> {
    apply_auto_update_jitter().await;

    let mut state = load_updater_state().await.unwrap_or_default();
    let now = now_rfc3339();
    state.last_attempt_at = Some(now.clone());

    let config = CliConfig::load().await.unwrap_or_default();
    if !config.auto_update_enabled() {
        state.last_error = None;
        state.consecutive_failures = 0;
        state.next_retry_after = None;
        save_updater_state(&state).await?;
        return Ok(());
    }

    if !update_due_for_retry(&state, now_epoch()) {
        return Ok(());
    }

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

    match run_update_install_from_url_mode(
        GITHUB_RELEASES_LATEST_URL,
        true,
        InstallMode::SilentUnattended,
    )
    .await
    {
        Ok(AttemptOutcome::Installed) => {
            state.last_success_at = Some(now.clone());
            state.last_installed_version = state.last_seen_version.clone();
            state.consecutive_failures = 0;
            state.last_error = None;
            state.next_retry_after = None;
            save_updater_state(&state).await?;
        }
        Ok(AttemptOutcome::NoUpdate | AttemptOutcome::SkippedUnstable) => {
            state.last_success_at = Some(now.clone());
            state.consecutive_failures = 0;
            state.last_error = None;
            state.next_retry_after = None;
            save_updater_state(&state).await?;
        }
        Err(e) => {
            let err = format!("{e:#}");
            if err.contains("global activity lock is busy") {
                // Lock contention is expected when hooks/sync are active; retry soon.
                state.last_error = Some("activity lock busy; updater skipped".to_string());
                let delay = rand08::Rng::gen_range(&mut rand08::thread_rng(), 60..=300);
                state.next_retry_after =
                    format_epoch_rfc3339(now_epoch().saturating_add(delay as i64));
                save_updater_state(&state).await?;
                return Ok(());
            }
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            state.last_error = Some(err);
            let retry_at = now_epoch().saturating_add(retry_delay_from_state(&state) as i64);
            state.next_retry_after = format_epoch_rfc3339(retry_at);
            save_updater_state(&state).await?;
        }
    }

    Ok(())
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

#[cfg(target_os = "macos")]
const MACOS_LAUNCH_AGENT_LABEL: &str = "ai.teamcadence.cadence.autoupdate";
#[cfg(target_os = "windows")]
const WINDOWS_TASK_NAME: &str = "Cadence CLI Auto Update";

#[cfg(target_os = "windows")]
fn auto_update_interval_hours() -> u64 {
    (AUTO_UPDATE_INTERVAL_SECS / 3600).max(1)
}

#[cfg(target_os = "windows")]
fn scheduler_command_line(exe_path: &Path) -> String {
    format!("\"{}\" hook auto-update", exe_path.display())
}

fn command_failure_detail(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    [stderr, stdout]
        .into_iter()
        .find(|value| !value.is_empty())
        .unwrap_or_else(|| format!("exit status {}", output.status))
}

fn report_best_effort_post_upgrade_failure(
    mode: InstallMode,
    what: &str,
    remediation: &str,
    err: &anyhow::Error,
) {
    if matches!(mode, InstallMode::Interactive) {
        eprintln!("Warning: cadence updated, but {what}: {err:#}");
        if !remediation.is_empty() {
            eprintln!("{remediation}");
        }
        return;
    }

    ::tracing::warn!(
        event = "post_upgrade_followup_failed",
        task = what,
        remediation,
        error = %format!("{err:#}")
    );
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
    <string>hook</string>
    <string>auto-update</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>{interval}</integer>
  <key>RandomDelay</key><integer>{jitter}</integer>
  <key>StandardOutPath</key><string>/tmp/cadence-autoupdate.log</string>
  <key>StandardErrorPath</key><string>/tmp/cadence-autoupdate.log</string>
</dict>
</plist>
"#,
        exe = exe_path.display(),
        interval = AUTO_UPDATE_INTERVAL_SECS,
        jitter = AUTO_UPDATE_JITTER_SECS
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
        "[Unit]\nDescription=Cadence CLI unattended auto-update\n\n[Service]\nType=oneshot\nExecStart={} hook auto-update\n",
        exe_path.display()
    )
}

#[cfg(target_os = "linux")]
fn systemd_timer_contents() -> String {
    format!(
        "[Unit]\nDescription=Cadence CLI unattended auto-update timer\n\n[Timer]\nOnBootSec=5m\nOnUnitActiveSec={}s\nRandomizedDelaySec={}s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
        AUTO_UPDATE_INTERVAL_SECS, AUTO_UPDATE_JITTER_SECS
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
        user_dir.join("cadence-autoupdate.service"),
        user_dir.join("cadence-autoupdate.timer"),
    ))
}

pub async fn provision_auto_update_scheduler() -> Result<SchedulerProvisionResult> {
    let exe =
        std::env::current_exe().context("failed to resolve current cadence executable path")?;
    provision_auto_update_scheduler_for_exe(&exe).await
}

pub async fn provision_auto_update_scheduler_for_exe(
    exe: &Path,
) -> Result<SchedulerProvisionResult> {
    #[cfg(target_os = "macos")]
    {
        let plist_path = macos_launch_agent_path()?;
        let agents_dir = plist_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("invalid launch agent path"))?;
        tokio::fs::create_dir_all(&agents_dir).await?;
        let plist = launch_agent_plist(MACOS_LAUNCH_AGENT_LABEL, exe);
        tokio::fs::write(&plist_path, plist).await?;

        // `bootstrap` leaves this user LaunchAgent as a transient partial import on macOS 15,
        // so the service disappears after the first RunAtLoad execution. Use the documented
        // `load -w` path here because it leaves the LaunchAgent registered for future intervals.
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

        let load = launchctl_file_operation("load", &plist_path).await?;
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
        if daemon_reload.as_ref().is_ok_and(|s| s.success()) {
            let _ = Command::new("systemctl")
                .args(["--user", "enable", "--now", "cadence-autoupdate.timer"])
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
        let schedule_hours = auto_update_interval_hours().to_string();
        let _ = Command::new("schtasks")
            .args([
                "/Create",
                "/F",
                "/SC",
                "HOURLY",
                "/MO",
                &schedule_hours,
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

pub async fn uninstall_auto_update_scheduler() -> Result<SchedulerUninstallResult> {
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
            removed: out.as_ref().is_ok_and(|s| s.success()),
            description: WINDOWS_TASK_NAME.to_string(),
        });
    }

    #[allow(unreachable_code)]
    Ok(SchedulerUninstallResult {
        removed: false,
        description: "scheduler unsupported on this platform".to_string(),
    })
}

pub async fn reconcile_scheduler_for_auto_update_enabled(
    enabled: bool,
) -> Result<SchedulerProvisionResult> {
    if enabled {
        return provision_auto_update_scheduler().await;
    }
    let removed = uninstall_auto_update_scheduler().await?;
    Ok(SchedulerProvisionResult {
        configured: false,
        description: format!(
            "disabled; cleaned scheduler artifacts ({})",
            removed.description
        ),
    })
}

pub async fn scheduler_health() -> SchedulerHealth {
    #[cfg(target_os = "macos")]
    {
        return scheduler_health_macos().await;
    }

    #[cfg(target_os = "linux")]
    {
        let (service_path, timer_path) = match linux_systemd_paths() {
            Ok(v) => v,
            Err(e) => {
                return SchedulerHealth {
                    state: SchedulerHealthState::Broken,
                    details: format!("systemd user path unavailable: {e}"),
                    remediation: "Run `cadence install` to repair scheduler setup.".to_string(),
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
                remediation:
                    "Run `cadence auto-update enable` or `cadence install` to create them."
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
                remediation: "Run `cadence install` to reconcile scheduler artifacts.".to_string(),
            };
        }
        let service_contents = tokio::fs::read_to_string(&service_path)
            .await
            .unwrap_or_default();
        if !service_contents.contains("hook auto-update") {
            return SchedulerHealth {
                state: SchedulerHealthState::Broken,
                details: format!(
                    "systemd service exists but command is invalid: {}",
                    service_path.display()
                ),
                remediation: "Run `cadence install` to rewrite scheduler artifacts.".to_string(),
            };
        }
        return SchedulerHealth {
            state: SchedulerHealthState::Installed,
            details: format!(
                "systemd user timer/service installed ({}, {})",
                service_path.display(),
                timer_path.display()
            ),
            remediation: "Use `cadence auto-update disable` to opt out or `cadence auto-update uninstall` to remove scheduler artifacts.".to_string(),
        };
    }

    #[cfg(target_os = "windows")]
    {
        let queried = Command::new("schtasks")
            .args(["/Query", "/TN", WINDOWS_TASK_NAME])
            .status()
            .await;
        if queried.as_ref().is_ok_and(|s| s.success()) {
            return SchedulerHealth {
                state: SchedulerHealthState::Installed,
                details: format!("Task Scheduler task installed: {}", WINDOWS_TASK_NAME),
                remediation: "Use `cadence auto-update disable` to opt out or `cadence auto-update uninstall` to remove scheduler artifacts.".to_string(),
            };
        }
        return SchedulerHealth {
            state: SchedulerHealthState::Missing,
            details: format!("Task Scheduler task missing: {}", WINDOWS_TASK_NAME),
            remediation: "Run `cadence auto-update enable` or `cadence install` to create it."
                .to_string(),
        };
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
    if !contents.contains("<string>auto-update</string>") {
        return SchedulerHealth {
            state: SchedulerHealthState::Broken,
            details: format!(
                "LaunchAgent exists but contents look invalid: {}",
                plist_path.display()
            ),
            remediation: "Run `cadence install` to rewrite scheduler artifacts.".to_string(),
        };
    }

    match loaded {
        Ok(true) => SchedulerHealth {
            state: SchedulerHealthState::Installed,
            details: format!("LaunchAgent installed and loaded: {}", plist_path.display()),
            remediation: "Use `cadence auto-update disable` to opt out or `cadence auto-update uninstall` to remove scheduler artifacts.".to_string(),
        },
        Ok(false) => SchedulerHealth {
            state: SchedulerHealthState::Broken,
            details: format!(
                "LaunchAgent exists but is not loaded in launchd: {}",
                plist_path.display()
            ),
            remediation: "Run `cadence auto-update enable` or `cadence install` to load it."
                .to_string(),
        },
        Err(err) => SchedulerHealth {
            state: SchedulerHealthState::Broken,
            details: format!("LaunchAgent health check failed: {err}"),
            remediation: "Run `cadence auto-update enable` or `cadence install` to repair it."
                .to_string(),
        },
    }
}

#[cfg(target_os = "macos")]
async fn scheduler_health_macos() -> SchedulerHealth {
    let plist_path = match macos_launch_agent_path() {
        Ok(v) => v,
        Err(e) => {
            return SchedulerHealth {
                state: SchedulerHealthState::Broken,
                details: format!("LaunchAgent path unavailable: {e}"),
                remediation: "Run `cadence install` to repair scheduler setup.".to_string(),
            };
        }
    };
    if !tokio::fs::try_exists(&plist_path).await.unwrap_or(false) {
        return SchedulerHealth {
            state: SchedulerHealthState::Missing,
            details: format!("missing LaunchAgent {}", plist_path.display()),
            remediation: "Run `cadence auto-update enable` or `cadence install` to create it."
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

pub fn auto_update_policy_summary() -> &'static str {
    "hourly checks; stable channel only; prereleases are excluded by default"
}

pub async fn updater_health() -> UpdaterHealth {
    let cfg = CliConfig::load().await.unwrap_or_default();
    let enabled = cfg.auto_update_enabled();
    let state = load_updater_state().await.unwrap_or_default();
    derive_updater_health(enabled, &state)
}

fn derive_updater_health(enabled: bool, state: &UpdaterState) -> UpdaterHealth {
    if !enabled {
        return UpdaterHealth {
            enabled,
            state: UpdaterHealthState::Disabled,
            last_result: "disabled".to_string(),
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
    passive_version_check_from_url(GITHUB_RELEASES_LATEST_URL).await;
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
            "cadence-cli-aarch64-apple-darwin.tar.gz"
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
            make_asset("cadence-cli-aarch64-apple-darwin.tar.gz"),
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
            err.contains("cadence-cli-aarch64-apple-darwin.tar.gz"),
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
            make_asset("cadence-cli-aarch64-apple-darwin.tar.gz"),
            make_asset("checksums-sha256.txt"),
        ];
        let result = pick_checksums_asset(&assets).unwrap();
        assert_eq!(result.name, "checksums-sha256.txt");
    }

    #[tokio::test]
    async fn pick_checksums_missing() {
        let assets = vec![make_asset("cadence-cli-aarch64-apple-darwin.tar.gz")];
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
                    .append_data(&mut header, "cadence", &content[..])
                    .unwrap();
                tar_builder.finish().unwrap();
            })
            .await
            .unwrap();
        }

        let extract_dir = tmp.path().join("out");
        tokio::fs::create_dir_all(&extract_dir).await.unwrap();

        let result = extract_binary(&archive_path, &extract_dir).await.unwrap();
        assert_eq!(result.file_name().unwrap(), "cadence");
        assert!(result.exists());

        let extracted_content = tokio::fs::read(&result).await.unwrap();
        assert_eq!(extracted_content, b"#!/bin/sh\necho hello\n");
    }

    #[tokio::test]
    async fn extract_tar_gz_nested_binary() {
        let tmp = tempfile::tempdir().unwrap();

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
                    .append_data(&mut header, "release/cadence", &content[..])
                    .unwrap();
                tar_builder.finish().unwrap();
            })
            .await
            .unwrap();
        }

        let extract_dir = tmp.path().join("out");
        tokio::fs::create_dir_all(&extract_dir).await.unwrap();

        let result = extract_binary(&archive_path, &extract_dir).await.unwrap();
        assert_eq!(result.file_name().unwrap(), "cadence");
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

        let archive_path = tmp.path().join("test.zip");
        {
            let file = tokio::fs::File::create(&archive_path).await.unwrap();
            let std_file = file.into_std().await;
            tokio::task::spawn_blocking(move || {
                let mut zip_writer = zip::ZipWriter::new(std_file);
                let options = zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored);
                zip_writer.start_file("cadence.exe", options).unwrap();
                zip_writer.write_all(b"MZ fake exe").unwrap();
                zip_writer.finish().unwrap();
            })
            .await
            .unwrap();
        }

        let extract_dir = tmp.path().join("out");
        tokio::fs::create_dir_all(&extract_dir).await.unwrap();

        let result = extract_binary(&archive_path, &extract_dir).await.unwrap();
        assert_eq!(result.file_name().unwrap(), "cadence.exe");
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

    // -- self_replace_binary -------------------------------------------------

    #[tokio::test]
    async fn self_replace_nonexistent_source() {
        let result = self_replace_binary(Path::new("/nonexistent/path"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    // -- archive extension ---------------------------------------------------

    #[tokio::test]
    async fn archive_ext_unix_targets() {
        assert_eq!(
            archive_extension_for_target("aarch64-apple-darwin"),
            ".tar.gz"
        );
        assert_eq!(
            archive_extension_for_target("x86_64-apple-darwin"),
            ".tar.gz"
        );
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

    // -- confirm_update (precedence matrix) ----------------------------------

    #[tokio::test]
    async fn confirm_update_yes_bypass() {
        // --yes flag should skip prompt and return true
        let result = confirm_update("0.2.1", "0.3.0", true, None).unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn confirm_update_yes_overrides_config_false() {
        // --yes wins even when config says auto_update=false
        let result = confirm_update("0.2.1", "0.3.0", true, Some(false)).unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn confirm_update_yes_overrides_config_true() {
        // --yes wins over config=true (both are "yes", should still bypass)
        let result = confirm_update("0.2.1", "0.3.0", true, Some(true)).unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn confirm_update_auto_config_true_skips_prompt() {
        // auto_update=true should skip prompt without --yes
        let result = confirm_update("0.2.1", "0.3.0", false, Some(true)).unwrap();
        assert!(result);
    }

    #[tokio::test]
    #[serial]
    async fn persist_auto_update_enabled_overrides_explicit_disable() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = EnvGuard::new("HOME");
        home.set(tmp.path().to_str().expect("home path utf8"));

        let cfg = CliConfig {
            auto_update: Some(false),
            ..CliConfig::default()
        };
        cfg.save().await.expect("save config");

        let changed = persist_auto_update_enabled()
            .await
            .expect("persist auto-update enabled");
        assert!(changed);

        let saved = CliConfig::load().await.expect("load config");
        assert_eq!(saved.auto_update, Some(true));
    }

    #[tokio::test]
    async fn update_confirmation_config_preserves_manual_auto_update_preference() {
        let cfg = CliConfig {
            auto_update: Some(true),
            ..CliConfig::default()
        };
        assert_eq!(
            update_confirmation_config(InstallMode::Interactive, Some(&cfg)),
            Some(true)
        );
        assert_eq!(
            update_confirmation_config(InstallMode::SilentUnattended, Some(&cfg)),
            None
        );

        let cfg = CliConfig {
            auto_update: Some(false),
            ..CliConfig::default()
        };
        assert_eq!(
            update_confirmation_config(InstallMode::Interactive, Some(&cfg)),
            Some(false)
        );
    }

    #[tokio::test]
    async fn confirm_update_auto_config_false_no_yes_would_prompt() {
        // auto_update=false, no --yes: would go to interactive prompt.
        // We can't test the actual prompt here without a TTY,
        // but we verify the None/false config path doesn't auto-accept.
        // The dialoguer prompt will fail or return None in non-interactive.
        // Skip this test in CI — just verify the yes/auto paths cover all branches.
    }

    #[tokio::test]
    async fn confirm_update_config_none_no_yes_would_prompt() {
        // No config, no --yes: same as auto_update=false — would prompt.
        // Confirm that None acts like false.
        let result = confirm_update("0.2.1", "0.3.0", false, None);
        // In a non-interactive test, this either fails or returns false.
        // The key assertion is that it does NOT return Ok(true).
        if let Ok(val) = result {
            assert!(!val, "should not auto-accept without --yes or config");
        }
        // Err is acceptable in non-interactive environments
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
                last_attempt_at: Some(now_rfc3339()),
                consecutive_failures: 2,
                next_retry_after: Some(now_rfc3339()),
                last_error: Some("network".to_string()),
                ..UpdaterState::default()
            },
        );
        assert_eq!(retrying.state, UpdaterHealthState::Retrying);
    }

    #[tokio::test]
    #[serial]
    async fn activity_lock_nonblocking_skips_when_held() {
        let tmp = tempfile::tempdir().unwrap();
        let home = EnvGuard::new("HOME");
        home.set(tmp.path().to_str().unwrap());

        let lock = acquire_activity_lock_blocking("test-holder")
            .await
            .expect("acquire lock");
        let other = try_acquire_activity_lock_nonblocking("test-other")
            .await
            .expect("try lock");
        assert!(other.is_none());
        drop(lock);

        let reacquired = try_acquire_activity_lock_nonblocking("test-after-drop")
            .await
            .expect("reacquire");
        assert!(reacquired.is_some());
    }

    #[tokio::test]
    #[serial]
    async fn activity_lock_blocking_times_out_when_held() {
        let tmp = tempfile::tempdir().unwrap();
        let home = EnvGuard::new("HOME");
        home.set(tmp.path().to_str().unwrap());

        let _lock = acquire_activity_lock_blocking("test-holder")
            .await
            .expect("acquire lock");
        let err =
            acquire_activity_lock_blocking_with_timeout("test-waiter", Duration::from_millis(75))
                .await
                .expect_err("timeout");
        assert!(
            err.to_string()
                .contains("timed out waiting for global activity lock"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    #[serial]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn uninstall_scheduler_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let home = EnvGuard::new("HOME");
        home.set(tmp.path().to_str().unwrap());

        let first = uninstall_auto_update_scheduler()
            .await
            .expect("first uninstall");
        let second = uninstall_auto_update_scheduler()
            .await
            .expect("second uninstall");
        assert!(!first.removed);
        assert!(!second.removed);
    }

    #[tokio::test]
    #[serial]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn scheduler_health_reports_missing_without_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let home = EnvGuard::new("HOME");
        home.set(tmp.path().to_str().unwrap());

        let health = scheduler_health().await;
        assert_eq!(health.state, SchedulerHealthState::Missing);
    }

    #[tokio::test]
    #[serial]
    #[cfg(target_os = "linux")]
    async fn reconcile_enabled_then_disabled_is_consistent() {
        let tmp = tempfile::tempdir().unwrap();
        let home = EnvGuard::new("HOME");
        home.set(tmp.path().to_str().unwrap());

        let exe = PathBuf::from("/usr/local/bin/cadence");
        let enabled = provision_auto_update_scheduler_for_exe(&exe)
            .await
            .expect("provision scheduler");
        assert!(enabled.configured);

        let health_after_enable = scheduler_health().await;
        assert_eq!(health_after_enable.state, SchedulerHealthState::Installed);

        let _ = reconcile_scheduler_for_auto_update_enabled(false)
            .await
            .expect("disable reconcile");
        let health_after_disable = scheduler_health().await;
        assert_eq!(health_after_disable.state, SchedulerHealthState::Missing);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn launch_agent_plist_points_to_current_executable() {
        let exe = PathBuf::from("/usr/local/bin/cadence");
        let plist = launch_agent_plist("ai.teamcadence.cadence.autoupdate", &exe);
        assert!(plist.contains("/usr/local/bin/cadence"));
        assert!(plist.contains("<string>auto-update</string>"));
        assert!(plist.contains("<key>StartInterval</key>"));
        assert!(plist.contains("<integer>3600</integer>"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_scheduler_health_reports_installed_when_launch_agent_is_loaded() {
        let plist_path = PathBuf::from("/tmp/ai.teamcadence.cadence.autoupdate.plist");
        let health = macos_scheduler_health_from_probe(
            &plist_path,
            "<string>auto-update</string>",
            Ok(true),
        );
        assert_eq!(health.state, SchedulerHealthState::Installed);
        assert!(health.details.contains("installed and loaded"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn systemd_timer_and_service_include_expected_schedule_and_command() {
        let exe = PathBuf::from("/usr/local/bin/cadence");
        let service = systemd_service_contents(&exe);
        let timer = systemd_timer_contents();
        assert!(service.contains("ExecStart=/usr/local/bin/cadence hook auto-update"));
        assert!(timer.contains("OnUnitActiveSec=3600s"));
        assert!(timer.contains("RandomizedDelaySec=300s"));
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
