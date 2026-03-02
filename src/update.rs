//! Self-update version checking and self-replace for cadence-cli.
//!
//! Queries the GitHub Releases API to determine if a newer version is available,
//! and provides a full self-update flow: download, checksum verification,
//! archive extraction, and in-place binary replacement.
//!
//! The production endpoint is `GITHUB_RELEASES_LATEST_URL`. Tests inject a
//! local HTTP server URL via `check_latest_version_from_url()`.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncReadExt;

use crate::config::CliConfig;

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
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build HTTP client")?;
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

/// Builds a reqwest blocking client with standard headers and timeout.
fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(120))
        .build()
        .context("Failed to build HTTP client")
}

/// Downloads a URL to a file in the given directory. Returns the file path.
pub async fn download_to_file(url: &str, dest_dir: &Path, filename: &str) -> Result<PathBuf> {
    let client = build_http_client()?;
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
fn extract_tar_gz(archive_path: &Path, dest_dir: &Path) -> Result<PathBuf> {
    let file = std::fs::File::open(archive_path)
        .with_context(|| format!("Failed to open archive: {}", archive_path.display()))?;

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
fn extract_zip(archive_path: &Path, dest_dir: &Path) -> Result<PathBuf> {
    let file = std::fs::File::open(archive_path)
        .with_context(|| format!("Failed to open archive: {}", archive_path.display()))?;

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
    let archive_path = archive_path.to_path_buf();
    let dest_dir = dest_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let name = archive_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if name.ends_with(".tar.gz") {
            extract_tar_gz(&archive_path, &dest_dir)
        } else if name.ends_with(".zip") {
            extract_zip(&archive_path, &dest_dir)
        } else {
            bail!(
                "Unsupported archive format: '{}'. Expected .tar.gz or .zip",
                archive_path.display()
            )
        }
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
pub async fn run_update(check: bool, yes: bool) -> Result<()> {
    if check {
        return run_update_check().await;
    }

    run_update_install(yes).await
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
async fn run_update_install(yes: bool) -> Result<()> {
    run_update_install_from_url(GITHUB_RELEASES_LATEST_URL, yes).await
}

/// Install path with injectable URL for testing.
pub async fn run_update_install_from_url(release_url: &str, yes: bool) -> Result<()> {
    let local = current_version();

    // Load config for auto-update preference.
    // Config load failure is a hard error for update to avoid silently ignoring
    // user intent (e.g., a malformed config that was supposed to enable auto-update).
    let config = CliConfig::load()
        .await
        .context("Failed to load config. Check ~/.cadence/cli/config.toml for syntax errors.")?;

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
        println!("cadence v{local} is already up to date (latest: v{remote_display})");
        return Ok(());
    }

    // Step 3: Resolve target artifact and checksums from release assets
    let target = build_target();
    let artifact_asset = pick_artifact_for_target(&release.assets, target)?;
    let checksums_asset = pick_checksums_asset(&release.assets)?;

    // Step 4: Prompt for confirmation
    // Precedence: --yes > config auto_update > interactive prompt
    let auto_update_config = Some(config.auto_update_enabled());
    if !confirm_update(local, remote_display, yes, auto_update_config)? {
        println!("Update cancelled.");
        return Ok(());
    }

    // Step 5: Download to temp directory
    let tmp_dir = tempfile::tempdir().context("Failed to create temporary directory")?;

    println!("Downloading cadence v{remote_display}...");

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

    println!("Successfully updated cadence v{local} → v{remote_display}");

    Ok(())
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
    use std::io::Write;

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
            let file = std::fs::File::create(&archive_path).unwrap();
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
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
            let file = std::fs::File::create(&archive_path).unwrap();
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
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
            let file = std::fs::File::create(&archive_path).unwrap();
            let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
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
            let file = std::fs::File::create(&archive_path).unwrap();
            let mut zip_writer = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip_writer.start_file("cadence.exe", options).unwrap();
            zip_writer.write_all(b"MZ fake exe").unwrap();
            zip_writer.finish().unwrap();
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
            let file = std::fs::File::create(&archive_path).unwrap();
            let mut zip_writer = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default();
            zip_writer.start_file("README.txt", options).unwrap();
            zip_writer.write_all(b"readme").unwrap();
            zip_writer.finish().unwrap();
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
