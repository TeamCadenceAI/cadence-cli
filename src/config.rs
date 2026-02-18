//! Local config file module for API credentials and settings.
//!
//! Persists API credentials in `$HOME/.cadence/cli/config.toml`
//! so the CLI can authenticate with the AI Barometer API across sessions.
//!
//! The config path intentionally uses a hardcoded `$HOME/.cadence/cli` base on
//! all platforms rather than platform-aware config directories. This keeps the
//! config path predictable across environments.

// This module is a foundation for future auth/keys specs. The public API will
// be consumed once those command handlers are added. Suppress dead_code until then.
#![allow(dead_code)]

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Hardcoded default API URL for the AI Barometer service.
pub const DEFAULT_API_URL: &str = "https://dash.teamcadence.ai";

/// Environment variable name for overriding the API URL.
const API_URL_ENV_VAR: &str = "AI_BAROMETER_API_URL";

/// Primary config root directory under `$HOME/`.
const CONFIG_ROOT_DIR_NAME: &str = ".cadence";

/// Primary config subdirectory under `$HOME/.cadence/`.
const CONFIG_SUBDIR_NAME: &str = "cli";

/// Config file name.
const CONFIG_FILE_NAME: &str = "config.toml";

/// Default update check interval: 8 hours in seconds.
const DEFAULT_UPDATE_CHECK_INTERVAL_SECS: u64 = 8 * 60 * 60;

/// Cache file for the latest known release version.
pub const LATEST_VERSION_CACHE_FILE: &str = "latest-available-version";

/// Result of resolving the effective API URL through the layered config system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedApiUrl {
    /// The resolved URL value.
    pub url: String,
    /// Whether the resolved URL uses a non-HTTPS scheme (user should be warned).
    pub is_non_https: bool,
}

/// Local CLI configuration for API credentials and settings.
///
/// Persisted as TOML at `$HOME/.cadence/cli/config.toml`.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct CliConfig {
    /// API base URL for the AI Barometer service.
    pub api_url: Option<String>,
    /// Authentication token from OAuth flow.
    pub token: Option<String>,
    /// GitHub login name associated with the token.
    pub github_login: Option<String>,
    /// Token expiry timestamp (ISO 8601 string).
    pub expires_at: Option<String>,
    /// When true, `cadence update` skips the confirmation prompt.
    pub auto_update: Option<bool>,
    /// How often the passive background version check runs (e.g., "8h", "24h", "1d").
    pub update_check_interval: Option<String>,
}

impl CliConfig {
    /// Resolve the config file path: `$HOME/.cadence/cli/config.toml`.
    ///
    /// Returns `None` if `$HOME` cannot be determined.
    pub fn config_path() -> Option<PathBuf> {
        Self::config_path_with_home(home_dir()?.as_path())
    }

    /// Resolve the config file path relative to a given home directory.
    ///
    /// This is the internal implementation used by both production code and tests.
    fn config_path_with_home(home: &Path) -> Option<PathBuf> {
        Some(
            home.join(CONFIG_ROOT_DIR_NAME)
                .join(CONFIG_SUBDIR_NAME)
                .join(CONFIG_FILE_NAME),
        )
    }

    /// Load config from disk. Returns defaults if the config file does not exist.
    ///
    /// Parse errors and I/O errors (other than file-not-found) are surfaced as
    /// hard failures to prevent silently operating on corrupted state.
    pub fn load() -> Result<Self> {
        let path = match Self::config_path() {
            Some(p) => p,
            None => return Ok(Self::default()),
        };
        Self::load_from(&path)
    }

    /// Load config from a specific path. Returns defaults if the file does not exist.
    fn load_from(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents)
                .with_context(|| format!("failed to parse config file at {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => {
                Err(e).with_context(|| format!("failed to read config file at {}", path.display()))
            }
        }
    }

    /// Save config to disk, creating parent directories if needed.
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()
            .ok_or_else(|| anyhow::anyhow!("cannot determine config path: $HOME is not set"))?;
        self.save_to(&path)
    }

    /// Save config to a specific path, creating parent directories if needed.
    fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create config directory at {}", parent.display())
            })?;
        }
        let contents = toml::to_string_pretty(self).context("failed to serialize config")?;
        std::fs::write(path, &contents)
            .with_context(|| format!("failed to write config file at {}", path.display()))?;
        Ok(())
    }

    /// Remove authentication credentials (token, login, expires_at) and save.
    ///
    /// Preserves `api_url`. This operation is idempotent — clearing already-absent
    /// fields is a no-op aside from the save.
    pub fn clear_token(&mut self) -> Result<()> {
        self.token = None;
        self.github_login = None;
        self.expires_at = None;
        self.save()
    }

    /// Clear token credentials and save to a specific path.
    fn clear_token_to(&mut self, path: &Path) -> Result<()> {
        self.token = None;
        self.github_login = None;
        self.expires_at = None;
        self.save_to(path)
    }

    /// Returns whether auto-update is enabled.
    ///
    /// Defaults to `false` when `auto_update` is absent from config.
    pub fn auto_update_enabled(&self) -> bool {
        self.auto_update.unwrap_or(false)
    }

    /// Resolves the update check interval as a `Duration`.
    ///
    /// Uses the configured `update_check_interval` if present and valid,
    /// otherwise falls back to the default of 8 hours.
    /// Returns an error if the configured value is present but malformed.
    pub fn resolved_update_check_interval(&self) -> Result<Duration> {
        match &self.update_check_interval {
            Some(s) => parse_duration_string(s),
            None => Ok(Duration::from_secs(DEFAULT_UPDATE_CHECK_INTERVAL_SECS)),
        }
    }

    /// Returns the config directory path: `$HOME/.cadence/cli/`.
    ///
    /// Returns `None` if `$HOME` cannot be determined.
    pub fn config_dir() -> Option<PathBuf> {
        Self::config_dir_with_home(home_dir()?.as_path())
    }

    /// Returns the config directory path relative to a given home directory.
    pub fn config_dir_with_home(home: &Path) -> Option<PathBuf> {
        Some(home.join(CONFIG_ROOT_DIR_NAME).join(CONFIG_SUBDIR_NAME))
    }

    /// Resolve the effective API URL using layered config precedence.
    ///
    /// Priority (highest wins):
    /// 1. `cli_override` — the `--api-url` CLI flag value for this invocation
    /// 2. `AI_BAROMETER_API_URL` environment variable
    /// 3. `api_url` field from the persisted config file
    /// 4. Hardcoded default: `https://dash.teamcadence.ai`
    ///
    /// Empty or whitespace-only values at any layer are treated as absent and
    /// fall through to the next layer.
    ///
    /// Returns a [`ResolvedApiUrl`] containing the resolved URL and a flag
    /// indicating whether the URL is non-HTTPS (callers should print a warning).
    pub fn resolve_api_url(&self, cli_override: Option<&str>) -> ResolvedApiUrl {
        self.resolve_api_url_with_env(cli_override, std::env::var(API_URL_ENV_VAR).ok())
    }

    /// Internal resolver that accepts the env var value as a parameter for testability.
    fn resolve_api_url_with_env(
        &self,
        cli_override: Option<&str>,
        env_value: Option<String>,
    ) -> ResolvedApiUrl {
        let url = non_empty_trimmed(cli_override.map(|s| s.to_string()))
            .or_else(|| non_empty_trimmed(env_value))
            .or_else(|| non_empty_trimmed(self.api_url.clone()))
            .unwrap_or_else(|| DEFAULT_API_URL.to_string());

        let is_non_https = !url.starts_with("https://");
        ResolvedApiUrl { url, is_non_https }
    }
}

/// Parses a human-readable duration string into a `Duration`.
///
/// Accepted formats: `<positive-integer>h` (hours) or `<positive-integer>d` (days).
/// Whitespace around the value is trimmed. Zero and negative values are rejected.
/// Only lowercase suffixes are accepted to keep the format unambiguous.
///
/// # Examples
///
/// ```
/// # use std::time::Duration;
/// assert_eq!(cadence_cli::config::parse_duration_string("8h").unwrap(), Duration::from_secs(28800));
/// assert_eq!(cadence_cli::config::parse_duration_string("1d").unwrap(), Duration::from_secs(86400));
/// assert!(cadence_cli::config::parse_duration_string("0h").is_err());
/// ```
pub fn parse_duration_string(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        bail!("Duration string is empty");
    }

    let (num_str, unit) = s.split_at(s.len() - 1);
    let multiplier: u64 = match unit {
        "h" => 3600,
        "d" => 86400,
        _ => bail!("Invalid duration unit '{unit}' in '{s}'. Expected 'h' (hours) or 'd' (days)"),
    };

    if num_str.is_empty() {
        bail!("Missing numeric value in duration '{s}'");
    }

    let value: u64 = num_str
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid numeric value in duration '{s}': {e}"))?;

    if value == 0 {
        bail!("Duration must be positive, got '{s}'");
    }

    value
        .checked_mul(multiplier)
        .map(Duration::from_secs)
        .ok_or_else(|| {
            anyhow::anyhow!("Duration overflow: '{s}' exceeds maximum representable duration")
        })
}

/// Reads the cached latest-available version from the config directory.
///
/// Returns `None` if the cache file is absent, empty, or unreadable.
/// This is intentionally non-failing to keep `cadence status` resilient.
pub fn read_cached_latest_version() -> Option<String> {
    let dir = CliConfig::config_dir()?;
    read_cached_latest_version_from_dir(&dir)
}

/// Reads the cached latest-available version from a specific directory.
///
/// Trims whitespace and strips a leading `v`/`V` prefix if present.
/// Returns `None` if the file is absent, empty, or not valid UTF-8.
pub fn read_cached_latest_version_from_dir(dir: &Path) -> Option<String> {
    let path = dir.join(LATEST_VERSION_CACHE_FILE);
    let content = std::fs::read_to_string(&path).ok()?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Strip optional v prefix for consistency
    let version = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    if version.is_empty() {
        return None;
    }
    Some(version.to_string())
}

/// Writes the latest discovered release version to the cache file.
///
/// The version is trimmed and written as a single line. The `v` prefix, if present,
/// is preserved in the file; the reader strips it on read.
///
/// Creates the config directory if it doesn't exist. Returns an error if
/// the home directory can't be resolved or the file can't be written.
pub fn write_cached_latest_version(version: &str) -> Result<()> {
    let dir = CliConfig::config_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot determine config directory: $HOME is not set"))?;
    write_cached_latest_version_to_dir(version, &dir)
}

/// Writes the latest discovered release version to a specific directory.
///
/// Exposed for testing with temp directories.
pub fn write_cached_latest_version_to_dir(version: &str, dir: &Path) -> Result<()> {
    let trimmed = version.trim();
    if trimmed.is_empty() {
        bail!("cannot cache empty version string");
    }
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create config directory at {}", dir.display()))?;
    let path = dir.join(LATEST_VERSION_CACHE_FILE);
    std::fs::write(&path, format!("{trimmed}\n"))
        .with_context(|| format!("failed to write version cache at {}", path.display()))?;
    Ok(())
}

/// Return the trimmed value if non-empty after trimming, otherwise `None`.
fn non_empty_trimmed(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        let trimmed = v.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

/// Resolve the user's home directory from the `HOME` environment variable.
fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::TempDir;

    /// Helper: build a config file path inside a temp dir used as fake $HOME.
    fn config_path_in(home: &Path) -> PathBuf {
        CliConfig::config_path_with_home(home).unwrap()
    }

    /// Helper: save/restore an env var around a closure.
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

        fn remove(&self) {
            unsafe { std::env::remove_var(&self.key) };
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

    // -----------------------------------------------------------------------
    // CliConfig struct defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_config_all_none() {
        let cfg = CliConfig::default();
        assert_eq!(cfg.api_url, None);
        assert_eq!(cfg.token, None);
        assert_eq!(cfg.github_login, None);
        assert_eq!(cfg.expires_at, None);
    }

    // -----------------------------------------------------------------------
    // Config path resolution
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_path_with_home() {
        let home = PathBuf::from("/home/tester");
        let path = CliConfig::config_path_with_home(&home).unwrap();
        assert_eq!(path, PathBuf::from("/home/tester/.cadence/cli/config.toml"));
    }

    #[test]
    #[serial]
    fn test_config_path_uses_home_env() {
        let guard = EnvGuard::new("HOME");
        guard.set("/tmp/fake-home");

        let path = CliConfig::config_path().unwrap();
        assert_eq!(
            path,
            PathBuf::from("/tmp/fake-home/.cadence/cli/config.toml")
        );
        drop(guard);
    }

    #[test]
    #[serial]
    fn test_config_path_returns_none_when_home_missing() {
        let guard = EnvGuard::new("HOME");
        guard.remove();

        let path = CliConfig::config_path();
        assert!(path.is_none());
        drop(guard);
    }

    // -----------------------------------------------------------------------
    // load() — missing file returns defaults
    // -----------------------------------------------------------------------

    #[test]
    fn test_load_missing_file_returns_defaults() {
        let tmp = TempDir::new().unwrap();
        let path = config_path_in(tmp.path());
        // File does not exist
        let cfg = CliConfig::load_from(&path).unwrap();
        assert_eq!(cfg, CliConfig::default());
    }

    // -----------------------------------------------------------------------
    // load() — empty file returns defaults (all fields optional)
    // -----------------------------------------------------------------------

    #[test]
    fn test_load_empty_file_returns_defaults() {
        let tmp = TempDir::new().unwrap();
        let path = config_path_in(tmp.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "").unwrap();

        let cfg = CliConfig::load_from(&path).unwrap();
        assert_eq!(cfg, CliConfig::default());
    }

    // -----------------------------------------------------------------------
    // load() — partial fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_load_partial_fields() {
        let tmp = TempDir::new().unwrap();
        let path = config_path_in(tmp.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "api_url = \"https://custom.example.com\"\n").unwrap();

        let cfg = CliConfig::load_from(&path).unwrap();
        assert_eq!(cfg.api_url, Some("https://custom.example.com".to_string()));
        assert_eq!(cfg.token, None);
        assert_eq!(cfg.github_login, None);
        assert_eq!(cfg.expires_at, None);
    }

    // -----------------------------------------------------------------------
    // load() — malformed TOML returns error
    // -----------------------------------------------------------------------

    #[test]
    fn test_load_malformed_toml_returns_error() {
        let tmp = TempDir::new().unwrap();
        let path = config_path_in(tmp.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "this is not valid toml {{{").unwrap();

        let result = CliConfig::load_from(&path);
        assert!(result.is_err());
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(
            err_msg.contains("failed to parse config file"),
            "expected parse error context, got: {}",
            err_msg
        );
    }

    // -----------------------------------------------------------------------
    // save() / load() roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn test_save_load_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = config_path_in(tmp.path());

        let cfg = CliConfig {
            api_url: Some("https://api.example.com".to_string()),
            token: Some("tok_abc123".to_string()),
            github_login: Some("octocat".to_string()),
            expires_at: Some("2025-12-31T23:59:59Z".to_string()),
            ..Default::default()
        };
        cfg.save_to(&path).unwrap();

        let loaded = CliConfig::load_from(&path).unwrap();
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn test_save_creates_parent_directories() {
        let tmp = TempDir::new().unwrap();
        let path = config_path_in(tmp.path());
        // Parent dir should NOT exist yet
        assert!(!path.parent().unwrap().exists());

        let cfg = CliConfig::default();
        cfg.save_to(&path).unwrap();

        assert!(path.exists());
    }

    #[test]
    fn test_save_overwrites_existing_file() {
        let tmp = TempDir::new().unwrap();
        let path = config_path_in(tmp.path());

        let cfg1 = CliConfig {
            token: Some("first".to_string()),
            ..Default::default()
        };
        cfg1.save_to(&path).unwrap();

        let cfg2 = CliConfig {
            token: Some("second".to_string()),
            ..Default::default()
        };
        cfg2.save_to(&path).unwrap();

        let loaded = CliConfig::load_from(&path).unwrap();
        assert_eq!(loaded.token, Some("second".to_string()));
    }

    // -----------------------------------------------------------------------
    // clear_token()
    // -----------------------------------------------------------------------

    #[test]
    fn test_clear_token_removes_credentials_preserves_api_url() {
        let tmp = TempDir::new().unwrap();
        let path = config_path_in(tmp.path());

        let mut cfg = CliConfig {
            api_url: Some("https://custom.example.com".to_string()),
            token: Some("tok_abc".to_string()),
            github_login: Some("user".to_string()),
            expires_at: Some("2025-01-01T00:00:00Z".to_string()),
            ..Default::default()
        };
        cfg.save_to(&path).unwrap();
        cfg.clear_token_to(&path).unwrap();

        // In-memory state
        assert_eq!(cfg.api_url, Some("https://custom.example.com".to_string()));
        assert_eq!(cfg.token, None);
        assert_eq!(cfg.github_login, None);
        assert_eq!(cfg.expires_at, None);

        // On-disk state
        let loaded = CliConfig::load_from(&path).unwrap();
        assert_eq!(
            loaded.api_url,
            Some("https://custom.example.com".to_string())
        );
        assert_eq!(loaded.token, None);
        assert_eq!(loaded.github_login, None);
        assert_eq!(loaded.expires_at, None);
    }

    #[test]
    fn test_clear_token_idempotent() {
        let tmp = TempDir::new().unwrap();
        let path = config_path_in(tmp.path());

        let mut cfg = CliConfig {
            api_url: Some("https://api.example.com".to_string()),
            ..Default::default()
        };
        // Clearing when no credentials exist should succeed
        cfg.clear_token_to(&path).unwrap();
        assert_eq!(cfg.api_url, Some("https://api.example.com".to_string()));
        assert_eq!(cfg.token, None);
    }

    // -----------------------------------------------------------------------
    // resolve_api_url() — precedence tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_default_when_nothing_set() {
        let cfg = CliConfig::default();
        let resolved = cfg.resolve_api_url_with_env(None, None);
        assert_eq!(resolved.url, DEFAULT_API_URL);
        assert!(!resolved.is_non_https);
    }

    #[test]
    fn test_resolve_file_overrides_default() {
        let cfg = CliConfig {
            api_url: Some("https://file.example.com".to_string()),
            ..Default::default()
        };
        let resolved = cfg.resolve_api_url_with_env(None, None);
        assert_eq!(resolved.url, "https://file.example.com");
        assert!(!resolved.is_non_https);
    }

    #[test]
    fn test_resolve_env_overrides_file() {
        let cfg = CliConfig {
            api_url: Some("https://file.example.com".to_string()),
            ..Default::default()
        };
        let resolved =
            cfg.resolve_api_url_with_env(None, Some("https://env.example.com".to_string()));
        assert_eq!(resolved.url, "https://env.example.com");
    }

    #[test]
    fn test_resolve_cli_overrides_env() {
        let cfg = CliConfig {
            api_url: Some("https://file.example.com".to_string()),
            ..Default::default()
        };
        let resolved = cfg.resolve_api_url_with_env(
            Some("https://cli.example.com"),
            Some("https://env.example.com".to_string()),
        );
        assert_eq!(resolved.url, "https://cli.example.com");
    }

    #[test]
    fn test_resolve_cli_overrides_all() {
        let cfg = CliConfig {
            api_url: Some("https://file.example.com".to_string()),
            ..Default::default()
        };
        let resolved = cfg.resolve_api_url_with_env(
            Some("https://cli.example.com"),
            Some("https://env.example.com".to_string()),
        );
        assert_eq!(resolved.url, "https://cli.example.com");
        assert!(!resolved.is_non_https);
    }

    // -----------------------------------------------------------------------
    // resolve_api_url() — empty/whitespace values fall through
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_empty_cli_override_falls_through() {
        let cfg = CliConfig {
            api_url: Some("https://file.example.com".to_string()),
            ..Default::default()
        };
        let resolved = cfg.resolve_api_url_with_env(Some(""), None);
        assert_eq!(resolved.url, "https://file.example.com");
    }

    #[test]
    fn test_resolve_whitespace_cli_override_falls_through() {
        let cfg = CliConfig {
            api_url: Some("https://file.example.com".to_string()),
            ..Default::default()
        };
        let resolved = cfg.resolve_api_url_with_env(Some("   "), None);
        assert_eq!(resolved.url, "https://file.example.com");
    }

    #[test]
    fn test_resolve_empty_env_falls_through() {
        let cfg = CliConfig {
            api_url: Some("https://file.example.com".to_string()),
            ..Default::default()
        };
        let resolved = cfg.resolve_api_url_with_env(None, Some("".to_string()));
        assert_eq!(resolved.url, "https://file.example.com");
    }

    #[test]
    fn test_resolve_whitespace_env_falls_through() {
        let cfg = CliConfig::default();
        let resolved = cfg.resolve_api_url_with_env(None, Some("  \t  ".to_string()));
        assert_eq!(resolved.url, DEFAULT_API_URL);
    }

    #[test]
    fn test_resolve_empty_file_value_falls_to_default() {
        let cfg = CliConfig {
            api_url: Some("".to_string()),
            ..Default::default()
        };
        let resolved = cfg.resolve_api_url_with_env(None, None);
        assert_eq!(resolved.url, DEFAULT_API_URL);
    }

    // -----------------------------------------------------------------------
    // resolve_api_url() — non-HTTPS warning
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_non_https_from_cli_warns() {
        let cfg = CliConfig::default();
        let resolved = cfg.resolve_api_url_with_env(Some("http://localhost:8080"), None);
        assert_eq!(resolved.url, "http://localhost:8080");
        assert!(resolved.is_non_https);
    }

    #[test]
    fn test_resolve_non_https_from_env_warns() {
        let cfg = CliConfig::default();
        let resolved =
            cfg.resolve_api_url_with_env(None, Some("http://staging.example.com".to_string()));
        assert_eq!(resolved.url, "http://staging.example.com");
        assert!(resolved.is_non_https);
    }

    #[test]
    fn test_resolve_non_https_from_file_warns() {
        let cfg = CliConfig {
            api_url: Some("http://file.example.com".to_string()),
            ..Default::default()
        };
        let resolved = cfg.resolve_api_url_with_env(None, None);
        assert_eq!(resolved.url, "http://file.example.com");
        assert!(resolved.is_non_https);
    }

    #[test]
    fn test_resolve_https_no_warning() {
        let cfg = CliConfig {
            api_url: Some("https://secure.example.com".to_string()),
            ..Default::default()
        };
        let resolved = cfg.resolve_api_url_with_env(None, None);
        assert!(!resolved.is_non_https);
    }

    #[test]
    fn test_resolve_ftp_scheme_warns() {
        let cfg = CliConfig::default();
        let resolved = cfg.resolve_api_url_with_env(Some("ftp://files.example.com"), None);
        assert!(resolved.is_non_https);
    }

    #[test]
    fn test_resolve_file_scheme_warns() {
        let cfg = CliConfig::default();
        let resolved = cfg.resolve_api_url_with_env(Some("file:///tmp/mock-api"), None);
        assert!(resolved.is_non_https);
    }

    // -----------------------------------------------------------------------
    // resolve_api_url() — trimming behavior
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_trims_cli_override() {
        let cfg = CliConfig::default();
        let resolved = cfg.resolve_api_url_with_env(Some("  https://trimmed.example.com  "), None);
        assert_eq!(resolved.url, "https://trimmed.example.com");
    }

    #[test]
    fn test_resolve_trims_env_value() {
        let cfg = CliConfig::default();
        let resolved =
            cfg.resolve_api_url_with_env(None, Some("  https://trimmed.example.com  ".to_string()));
        assert_eq!(resolved.url, "https://trimmed.example.com");
    }

    // -----------------------------------------------------------------------
    // non_empty_trimmed() helper
    // -----------------------------------------------------------------------

    #[test]
    fn test_non_empty_trimmed_none() {
        assert_eq!(non_empty_trimmed(None), None);
    }

    #[test]
    fn test_non_empty_trimmed_empty() {
        assert_eq!(non_empty_trimmed(Some("".to_string())), None);
    }

    #[test]
    fn test_non_empty_trimmed_whitespace() {
        assert_eq!(non_empty_trimmed(Some("   ".to_string())), None);
    }

    #[test]
    fn test_non_empty_trimmed_value() {
        assert_eq!(
            non_empty_trimmed(Some(" hello ".to_string())),
            Some("hello".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // Integration: resolve_api_url with real env var
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_resolve_api_url_reads_real_env_var() {
        let guard = EnvGuard::new(API_URL_ENV_VAR);
        guard.set("https://from-env.example.com");

        let cfg = CliConfig::default();
        let resolved = cfg.resolve_api_url(None);
        assert_eq!(resolved.url, "https://from-env.example.com");

        drop(guard);
    }

    #[test]
    #[serial]
    fn test_resolve_api_url_env_var_absent_uses_default() {
        let guard = EnvGuard::new(API_URL_ENV_VAR);
        guard.remove();

        let cfg = CliConfig::default();
        let resolved = cfg.resolve_api_url(None);
        assert_eq!(resolved.url, DEFAULT_API_URL);

        drop(guard);
    }

    // -----------------------------------------------------------------------
    // auto_update defaults and resolver
    // -----------------------------------------------------------------------

    #[test]
    fn test_auto_update_default_is_none() {
        let cfg = CliConfig::default();
        assert_eq!(cfg.auto_update, None);
    }

    #[test]
    fn test_auto_update_enabled_defaults_false() {
        let cfg = CliConfig::default();
        assert!(!cfg.auto_update_enabled());
    }

    #[test]
    fn test_auto_update_enabled_explicit_true() {
        let cfg = CliConfig {
            auto_update: Some(true),
            ..Default::default()
        };
        assert!(cfg.auto_update_enabled());
    }

    #[test]
    fn test_auto_update_enabled_explicit_false() {
        let cfg = CliConfig {
            auto_update: Some(false),
            ..Default::default()
        };
        assert!(!cfg.auto_update_enabled());
    }

    #[test]
    fn test_auto_update_roundtrip_toml() {
        let tmp = TempDir::new().unwrap();
        let path = config_path_in(tmp.path());

        let cfg = CliConfig {
            auto_update: Some(true),
            update_check_interval: Some("24h".to_string()),
            ..Default::default()
        };
        cfg.save_to(&path).unwrap();

        let loaded = CliConfig::load_from(&path).unwrap();
        assert_eq!(loaded.auto_update, Some(true));
        assert_eq!(loaded.update_check_interval, Some("24h".to_string()));
    }

    #[test]
    fn test_auto_update_absent_in_toml_loads_as_none() {
        let tmp = TempDir::new().unwrap();
        let path = config_path_in(tmp.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "api_url = \"https://example.com\"\n").unwrap();

        let loaded = CliConfig::load_from(&path).unwrap();
        assert_eq!(loaded.auto_update, None);
        assert_eq!(loaded.update_check_interval, None);
        assert!(!loaded.auto_update_enabled());
    }

    // -----------------------------------------------------------------------
    // update_check_interval resolver
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_check_interval_default_8h() {
        let cfg = CliConfig::default();
        let interval = cfg.resolved_update_check_interval().unwrap();
        assert_eq!(interval, Duration::from_secs(8 * 3600));
    }

    #[test]
    fn test_update_check_interval_explicit_24h() {
        let cfg = CliConfig {
            update_check_interval: Some("24h".to_string()),
            ..Default::default()
        };
        let interval = cfg.resolved_update_check_interval().unwrap();
        assert_eq!(interval, Duration::from_secs(24 * 3600));
    }

    #[test]
    fn test_update_check_interval_explicit_1d() {
        let cfg = CliConfig {
            update_check_interval: Some("1d".to_string()),
            ..Default::default()
        };
        let interval = cfg.resolved_update_check_interval().unwrap();
        assert_eq!(interval, Duration::from_secs(86400));
    }

    #[test]
    fn test_update_check_interval_invalid_returns_error() {
        let cfg = CliConfig {
            update_check_interval: Some("invalid".to_string()),
            ..Default::default()
        };
        assert!(cfg.resolved_update_check_interval().is_err());
    }

    // -----------------------------------------------------------------------
    // parse_duration_string
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_duration_8h() {
        assert_eq!(
            parse_duration_string("8h").unwrap(),
            Duration::from_secs(28800)
        );
    }

    #[test]
    fn test_parse_duration_24h() {
        assert_eq!(
            parse_duration_string("24h").unwrap(),
            Duration::from_secs(86400)
        );
    }

    #[test]
    fn test_parse_duration_1d() {
        assert_eq!(
            parse_duration_string("1d").unwrap(),
            Duration::from_secs(86400)
        );
    }

    #[test]
    fn test_parse_duration_7d() {
        assert_eq!(
            parse_duration_string("7d").unwrap(),
            Duration::from_secs(7 * 86400)
        );
    }

    #[test]
    fn test_parse_duration_trims_whitespace() {
        assert_eq!(
            parse_duration_string("  8h  ").unwrap(),
            Duration::from_secs(28800)
        );
    }

    #[test]
    fn test_parse_duration_zero_hours_rejected() {
        let result = parse_duration_string("0h");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("positive"),
            "should mention 'positive'"
        );
    }

    #[test]
    fn test_parse_duration_zero_days_rejected() {
        let result = parse_duration_string("0d");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_duration_negative_rejected() {
        let result = parse_duration_string("-1h");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_duration_empty_rejected() {
        let result = parse_duration_string("");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("empty"),
            "should mention 'empty'"
        );
    }

    #[test]
    fn test_parse_duration_invalid_unit() {
        let result = parse_duration_string("8m");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid duration unit"),
            "should mention invalid unit"
        );
    }

    #[test]
    fn test_parse_duration_uppercase_rejected() {
        let result = parse_duration_string("8H");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid duration unit"),
            "uppercase should be rejected"
        );
    }

    #[test]
    fn test_parse_duration_uppercase_d_rejected() {
        let result = parse_duration_string("1D");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_duration_no_number() {
        let result = parse_duration_string("h");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("Missing numeric"),
            "should mention missing number"
        );
    }

    #[test]
    fn test_parse_duration_overflow() {
        let result = parse_duration_string("999999999999999999999999h");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_duration_non_numeric() {
        let result = parse_duration_string("abch");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_duration_float_rejected() {
        let result = parse_duration_string("1.5h");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Latest version cache reader
    // -----------------------------------------------------------------------

    #[test]
    fn test_read_cached_latest_version_missing_file() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(read_cached_latest_version_from_dir(tmp.path()), None);
    }

    #[test]
    fn test_read_cached_latest_version_empty_file() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(LATEST_VERSION_CACHE_FILE), "").unwrap();
        assert_eq!(read_cached_latest_version_from_dir(tmp.path()), None);
    }

    #[test]
    fn test_read_cached_latest_version_whitespace_only() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(LATEST_VERSION_CACHE_FILE), "  \n  ").unwrap();
        assert_eq!(read_cached_latest_version_from_dir(tmp.path()), None);
    }

    #[test]
    fn test_read_cached_latest_version_valid() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(LATEST_VERSION_CACHE_FILE), "0.3.0\n").unwrap();
        assert_eq!(
            read_cached_latest_version_from_dir(tmp.path()),
            Some("0.3.0".to_string())
        );
    }

    #[test]
    fn test_read_cached_latest_version_with_v_prefix() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(LATEST_VERSION_CACHE_FILE), "v0.3.0\n").unwrap();
        assert_eq!(
            read_cached_latest_version_from_dir(tmp.path()),
            Some("0.3.0".to_string())
        );
    }

    #[test]
    fn test_read_cached_latest_version_just_v() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join(LATEST_VERSION_CACHE_FILE), "v").unwrap();
        assert_eq!(read_cached_latest_version_from_dir(tmp.path()), None);
    }

    // -----------------------------------------------------------------------
    // config_dir helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_dir_with_home() {
        let home = PathBuf::from("/home/tester");
        let dir = CliConfig::config_dir_with_home(&home).unwrap();
        assert_eq!(dir, PathBuf::from("/home/tester/.cadence/cli"));
    }

    // -----------------------------------------------------------------------
    // write_cached_latest_version
    // -----------------------------------------------------------------------

    #[test]
    fn test_write_cached_latest_version_roundtrip() {
        let tmp = TempDir::new().unwrap();
        write_cached_latest_version_to_dir("0.4.0", tmp.path()).unwrap();
        assert_eq!(
            read_cached_latest_version_from_dir(tmp.path()),
            Some("0.4.0".to_string())
        );
    }

    #[test]
    fn test_write_cached_latest_version_with_v_prefix() {
        let tmp = TempDir::new().unwrap();
        write_cached_latest_version_to_dir("v0.4.0", tmp.path()).unwrap();
        // Reader strips the v prefix
        assert_eq!(
            read_cached_latest_version_from_dir(tmp.path()),
            Some("0.4.0".to_string())
        );
    }

    #[test]
    fn test_write_cached_latest_version_creates_dir() {
        let tmp = TempDir::new().unwrap();
        let sub = tmp.path().join("nested").join("dir");
        write_cached_latest_version_to_dir("1.0.0", &sub).unwrap();
        assert_eq!(
            read_cached_latest_version_from_dir(&sub),
            Some("1.0.0".to_string())
        );
    }

    #[test]
    fn test_write_cached_latest_version_empty_rejected() {
        let tmp = TempDir::new().unwrap();
        let result = write_cached_latest_version_to_dir("", tmp.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_write_cached_latest_version_whitespace_rejected() {
        let tmp = TempDir::new().unwrap();
        let result = write_cached_latest_version_to_dir("  \n  ", tmp.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_write_cached_latest_version_overwrites() {
        let tmp = TempDir::new().unwrap();
        write_cached_latest_version_to_dir("0.3.0", tmp.path()).unwrap();
        write_cached_latest_version_to_dir("0.4.0", tmp.path()).unwrap();
        assert_eq!(
            read_cached_latest_version_from_dir(tmp.path()),
            Some("0.4.0".to_string())
        );
    }
}
