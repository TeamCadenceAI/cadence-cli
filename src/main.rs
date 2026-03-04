mod agents;
mod api_client;
mod backfill_log;
mod config;
mod deferred_sync;
mod git;
mod keychain;
mod login;
mod note;
mod output;
mod pgp_keys;
mod push;
mod scanner;
mod sync_pending;
mod update;

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::{Parser, Subcommand};
use console::Term;
use dialoguer::{Confirm, theme::ColorfulTheme};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Duration;
use tokio::sync::OnceCell;

use crate::keychain::KeychainStore;

const KEYCHAIN_SERVICE: &str = "cadence-cli";
const KEYCHAIN_AUTH_TOKEN_ACCOUNT: &str = "auth_token";
const LOGIN_TIMEOUT_SECS: u64 = 120;
const API_TIMEOUT_SECS: u64 = 5;
static API_URL_OVERRIDE: OnceCell<String> = OnceCell::const_new();

/// Cadence CLI: store AI coding agent sessions in Git refs.
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

    /// List sessions indexed for branch/user.
    Sessions {
        #[command(subcommand)]
        command: Option<SessionsCommand>,

        /// List sessions for all discovered repos instead of only current repo.
        #[arg(long)]
        all: bool,
    },

    /// Show Cadence CLI status for the current repository.
    Status,

    /// Diagnose hook and session-ref configuration issues.
    Doctor,

    /// Check for and install updates.
    Update {
        /// Only check if a newer version is available; do not download or install.
        #[arg(long)]
        check: bool,

        /// Skip confirmation prompt when installing an update.
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// View or modify CLI configuration.
    Config {
        #[command(subcommand)]
        config_command: Option<ConfigCommand>,
    },

    /// Manage encryption for local + API recipients.
    Keys {
        #[command(subcommand)]
        keys_command: Option<KeysCommands>,
    },

    /// Clear session refs and re-backfill.
    ///
    /// Deletes local and remote session refs, then re-runs backfill.
    Gc {
        /// How far back to re-backfill, e.g. "30d" for 30 days.
        #[arg(long, default_value = "30d")]
        since: String,

        /// Confirm destructive operation (required).
        #[arg(long)]
        confirm: bool,
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
enum HookCommand {
    /// Post-commit hook: attempt to attach AI session note to HEAD.
    PostCommit,
    /// Pre-push hook: sync session refs with the push remote.
    PrePush {
        /// Remote name provided by git.
        remote: String,
        /// Remote URL provided by git.
        url: String,
    },
    /// Deferred sync worker: process queued session-ref sync jobs.
    DeferredSync {
        /// Repository path to sync (defaults to current repository).
        #[arg(long)]
        repo: Option<PathBuf>,
        /// Remote name to sync (defaults to push remote or origin).
        #[arg(long)]
        remote: Option<String>,
        /// Process queued pending sync jobs.
        #[arg(long)]
        all_pending: bool,
        /// Internal: background worker mode.
        #[arg(long)]
        background: bool,
        /// Max pending jobs to process in this invocation.
        #[arg(long, default_value_t = 4)]
        max_items: usize,
        /// Max time budget for this invocation in milliseconds.
        #[arg(long, default_value_t = 8000)]
        time_budget_ms: u64,
    },
}

#[derive(Subcommand, Debug)]
enum SessionsCommand {
    /// List sessions for branch + current committer.
    List {
        /// List sessions for all discovered repos instead of only current repo.
        #[arg(long)]
        all: bool,
    },
    /// Audit branch indexing and flag likely overindexed sessions.
    Audit {
        /// Audit all discovered repos instead of only current repo.
        #[arg(long)]
        all: bool,
        /// Include non-problematic sessions in output.
        #[arg(long)]
        show_ok: bool,
    },
    /// Inspect a session by UID prefix / session_id / label text.
    Inspect {
        /// Query string (session UID prefix, session_id, or label substring).
        query: String,
        /// Search all discovered repos instead of only current repo.
        #[arg(long)]
        all: bool,
        /// Print the full stored record + session_content for each match.
        #[arg(long)]
        raw: bool,
    },
}

#[derive(Subcommand, Debug)]
enum KeysCommands {
    /// Set up encryption with local + API recipients.
    Setup,
    /// Show encryption status for local + API recipients.
    Status,
    /// Disable encryption and clear cached keys.
    Disable,
    /// Refresh the cached API public key.
    Refresh,
}

// ---------------------------------------------------------------------------
// Hook error taxonomy
// ---------------------------------------------------------------------------

/// Error classification for the post-commit hook.
///
/// The hook must normally never block a commit (all errors are swallowed).
/// The single exception is when encryption is configured but fails —
/// in that case the hook MUST exit non-zero to prevent unencrypted notes.
enum HookError {
    /// Encryption was configured but failed. The hook must propagate
    /// this as a non-zero exit to block the commit.
    EncryptionFailed(String),
    /// Any other error (session not found, git error, etc.). These are
    /// logged as notes and the commit proceeds.
    Soft(anyhow::Error),
}

impl From<anyhow::Error> for HookError {
    fn from(e: anyhow::Error) -> Self {
        HookError::Soft(e)
    }
}

// ---------------------------------------------------------------------------
// Shared encryption helper
// ---------------------------------------------------------------------------

/// How note content should be encrypted before storage.
#[derive(Clone)]
enum EncryptionMethod {
    /// Pure-Rust rpgp encryption using user + API public keys.
    RpgpMulti { user_key: String, api_key: String },
    /// Encryption configured but keys are unavailable.
    Unavailable(String),
    /// No encryption configured — notes are stored as plaintext.
    None,
}

impl EncryptionMethod {
    /// Returns `true` when encryption is configured.
    fn is_configured(&self) -> bool {
        !matches!(self, EncryptionMethod::None)
    }
}

/// Resolve how note encryption should be performed.
///
/// If `ai.cadence.keys.userFingerprint` is unset, returns `None`.
/// If set but keys are unavailable, returns `Unavailable` with a reason.
async fn resolve_encryption_method() -> Result<EncryptionMethod> {
    let Some(user_fingerprint) = pgp_keys::get_user_fingerprint().await? else {
        return Ok(EncryptionMethod::None);
    };

    let user_key = match pgp_keys::load_cached_user_public_key().await {
        Ok(Some(key)) => Some(key),
        Ok(None) => None,
        Err(e) => {
            return Ok(EncryptionMethod::Unavailable(format!(
                "failed to read cached local key: {e}"
            )));
        }
    };

    let api_key = match resolve_api_public_key_cache(false).await {
        Ok(Some(key)) => Some(key),
        Ok(None) => None,
        Err(e) => {
            return Ok(EncryptionMethod::Unavailable(format!(
                "failed to fetch API public key: {e}"
            )));
        }
    };

    match (user_key, api_key) {
        (Some(user_key), Some(api_key)) => Ok(EncryptionMethod::RpgpMulti { user_key, api_key }),
        _ => Ok(EncryptionMethod::Unavailable(format!(
            "encryption configured for key {user_fingerprint}, but keys are missing"
        ))),
    }
}

/// Encode canonical session object bytes: compress with zstd, optionally encrypt
/// (binary, not armored), then store as a git blob.
///
/// Returns `(blob_sha, encoding)`.
async fn encode_and_store_session_object_at(
    repo: Option<&std::path::Path>,
    session_object_bytes: &[u8],
    method: &EncryptionMethod,
) -> Result<(String, note::ContentEncoding)> {
    let compressed = tokio::task::spawn_blocking({
        let data = session_object_bytes.to_vec();
        move || note::compress_bytes(&data)
    })
    .await
    .context("session object compression task failed")?
    .context("session object compression failed")?;

    // Step 2: Optionally encrypt (binary, not armored)
    let (encoded, encoding) = match method {
        EncryptionMethod::RpgpMulti { user_key, api_key } => {
            let encrypted = pgp_keys::encrypt_to_public_keys_binary(
                &compressed,
                &[user_key.clone(), api_key.clone()],
            )
            .context("session object encryption failed")?;
            (encrypted, note::ContentEncoding::ZstdPgp)
        }
        EncryptionMethod::Unavailable(reason) => {
            anyhow::bail!("encryption unavailable: {}", reason);
        }
        EncryptionMethod::None => (compressed, note::ContentEncoding::Zstd),
    };

    let blob_sha = git::store_blob_at(repo, &encoded)
        .await
        .context("failed to store canonical session blob")?;

    Ok((blob_sha, encoding))
}

const API_PUBLIC_KEY_MAX_AGE_DAYS: i64 = 7;

fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

fn api_url_override() -> Option<&'static str> {
    API_URL_OVERRIDE.get().map(String::as_str)
}

/// Resolve the cached API public key, refreshing if needed.
async fn resolve_api_public_key_cache(force_refresh: bool) -> Result<Option<String>> {
    let cached_key = pgp_keys::load_cached_api_public_key().await.unwrap_or(None);
    let metadata = pgp_keys::load_api_public_key_metadata()
        .await
        .unwrap_or(None);

    let stale = metadata
        .as_ref()
        .map(|m| pgp_keys::api_public_key_cache_stale(m, API_PUBLIC_KEY_MAX_AGE_DAYS))
        .unwrap_or(true);

    if !force_refresh && !stale && cached_key.is_some() {
        return Ok(cached_key);
    }

    let cfg = config::CliConfig::load().await?;
    let resolved = cfg.resolve_api_url(api_url_override());
    let client = api_client::ApiClient::new(&resolved.url);
    let keys_url = format!("{}/api/keys/public", resolved.url.trim_end_matches('/'));
    let api_key = client
        .get_api_public_key()
        .await
        .with_context(|| format!("failed to fetch API public key from {keys_url}"))?;

    let meta = pgp_keys::ApiPublicKeyMetadata {
        fingerprint: api_key.fingerprint.clone(),
        fetched_at: now_rfc3339(),
        created_at: api_key.created_at.clone(),
        rotated_at: api_key.rotated_at.clone(),
        version: api_key.version.clone(),
    };
    pgp_keys::save_api_public_key_cache(&api_key.armored_public_key, &meta).await?;

    if let Err(e) =
        git::config_set_global(pgp_keys::API_FINGERPRINT_KEY, &api_key.fingerprint).await
    {
        output::note(&format!(
            "Could not save API fingerprint to git config: {e}"
        ));
    }

    Ok(Some(api_key.armored_public_key))
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
/// 4. Write `~/.git-hooks/pre-push` shim script
/// 5. Make shims executable (chmod +x)
/// 6. If `--org` provided, persist org filter to global git config
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

fn pre_push_hook_content() -> String {
    format!(
        "#!/bin/sh\nexec {} hook pre-push \"$1\" \"$2\"\n",
        hook_command_exe()
    )
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

async fn cadence_hooks_installed(hooks_dir: &Path) -> (bool, bool) {
    let post_path = hooks_dir.join("post-commit");
    let post_installed = match tokio::fs::read_to_string(&post_path).await {
        Ok(content) => is_cadence_hook(&content),
        Err(_) => false,
    };

    let pre_path = hooks_dir.join("pre-push");
    let pre_installed = match tokio::fs::read_to_string(&pre_path).await {
        Ok(content) => is_cadence_hook(&content),
        Err(_) => false,
    };

    (post_installed, pre_installed)
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

    let home = match home_override {
        Some(h) => h.to_path_buf(),
        None => agents::home_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine home directory"))?,
    };

    let hooks_dir = home.join(".git-hooks");
    let hooks_dir_str = hooks_dir.to_string_lossy().to_string();

    // Track whether any step failed (but continue regardless)
    let mut had_errors = false;

    // Step 1: Set git config --global core.hooksPath ~/.git-hooks
    match git::config_set_global("core.hooksPath", &hooks_dir_str).await {
        Ok(()) => {
            output::success("Updated", &format!("core.hooksPath = {}", hooks_dir_str));
        }
        Err(e) => {
            output::fail("Failed", &format!("to set core.hooksPath ({})", e));
            had_errors = true;
        }
    }

    // Step 2: Create ~/.git-hooks/ directory if missing
    if !tokio::fs::try_exists(&hooks_dir).await.unwrap_or(false) {
        match tokio::fs::create_dir_all(&hooks_dir).await {
            Ok(()) => {
                output::success("Created", &hooks_dir_str);
            }
            Err(e) => {
                output::fail("Failed", &format!("to create {} ({})", hooks_dir_str, e));
                had_errors = true;
            }
        }
    } else {
        output::detail(&format!(
            "Hooks directory already exists: {}",
            hooks_dir_str
        ));
    }

    // Step 3 & 4: Write post-commit shim and make it executable
    let shim_path = hooks_dir.join("post-commit");
    let shim_content = post_commit_hook_content();

    // Check if hook already exists
    let should_write = if tokio::fs::try_exists(&shim_path).await.unwrap_or(false) {
        match tokio::fs::read_to_string(&shim_path).await {
            Ok(existing) => {
                if is_cadence_hook(&existing) {
                    output::detail("Post-commit hook already installed; updating");
                    true
                } else {
                    // Back up the existing hook before overwriting
                    let backup_path = hooks_dir.join("post-commit.pre-cadence");
                    match tokio::fs::copy(&shim_path, &backup_path).await {
                        Ok(_) => {
                            output::note(&format!(
                                "Existing post-commit hook saved to {}",
                                backup_path.display()
                            ));
                        }
                        Err(e) => {
                            output::note(&format!(
                                "Could not back up existing post-commit hook ({})",
                                e
                            ));
                        }
                    }
                    true
                }
            }
            Err(_) => {
                output::note(&format!(
                    "Could not read existing {}; overwriting",
                    shim_path.display()
                ));
                true
            }
        }
    } else {
        true
    };

    if should_write {
        match tokio::fs::write(&shim_path, shim_content).await {
            Ok(()) => {
                output::success(
                    "Wrote",
                    &format!("post-commit hook ({})", shim_path.display()),
                );

                // Make executable (Unix only)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o755);
                    match tokio::fs::set_permissions(&shim_path, perms).await {
                        Ok(()) => {
                            output::detail(&format!("Made {} executable", shim_path.display()));
                        }
                        Err(e) => {
                            output::fail(
                                "Failed",
                                &format!("to make {} executable ({})", shim_path.display(), e),
                            );
                            had_errors = true;
                        }
                    }
                }
            }
            Err(e) => {
                output::fail(
                    "Failed",
                    &format!("to write {} ({})", shim_path.display(), e),
                );
                had_errors = true;
            }
        }
    }

    // Step 4b: Write pre-push shim and make it executable
    let pre_push_path = hooks_dir.join("pre-push");
    let pre_push_content = pre_push_hook_content();

    let should_write_pre_push = if tokio::fs::try_exists(&pre_push_path).await.unwrap_or(false) {
        match tokio::fs::read_to_string(&pre_push_path).await {
            Ok(existing) => {
                if is_cadence_hook(&existing) {
                    output::detail("Pre-push hook already installed; updating");
                    true
                } else {
                    let backup_path = hooks_dir.join("pre-push.pre-cadence");
                    match tokio::fs::copy(&pre_push_path, &backup_path).await {
                        Ok(_) => {
                            output::note(&format!(
                                "Existing pre-push hook saved to {}",
                                backup_path.display()
                            ));
                        }
                        Err(e) => {
                            output::note(&format!(
                                "Could not back up existing pre-push hook ({})",
                                e
                            ));
                        }
                    }
                    true
                }
            }
            Err(_) => {
                output::note(&format!(
                    "Could not read existing {}; overwriting",
                    pre_push_path.display()
                ));
                true
            }
        }
    } else {
        true
    };

    if should_write_pre_push {
        match tokio::fs::write(&pre_push_path, pre_push_content).await {
            Ok(()) => {
                output::success(
                    "Wrote",
                    &format!("pre-push hook ({})", pre_push_path.display()),
                );

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o755);
                    match tokio::fs::set_permissions(&pre_push_path, perms).await {
                        Ok(()) => {
                            output::detail(&format!("Made {} executable", pre_push_path.display()));
                        }
                        Err(e) => {
                            output::fail(
                                "Failed",
                                &format!("to make {} executable ({})", pre_push_path.display(), e),
                            );
                            had_errors = true;
                        }
                    }
                }
            }
            Err(e) => {
                output::fail(
                    "Failed",
                    &format!("to write {} ({})", pre_push_path.display(), e),
                );
                had_errors = true;
            }
        }
    }

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

    // Step 5.5: Optional encryption setup
    println!();
    if let Err(e) = run_install_encryption_setup().await {
        output::fail("Install", &format!("stopped ({})", e));
        return Err(e);
    }

    // Step 5.6: Optional auto-update preference prompt
    run_install_auto_update_prompt().await;

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

    let keychain = keychain::KeyringStore::new(KEYCHAIN_SERVICE);
    if let Err(e) = keychain
        .set(KEYCHAIN_AUTH_TOKEN_ACCOUNT, &exchanged.token)
        .await
    {
        output::note(&format!(
            "Could not store token in OS keychain (using config fallback): {e}"
        ));
    }

    output::success("Login", &format!("authenticated as {}", exchanged.login));
    output::detail(&format!("Token expires at {}", exchanged.expires_at));
    Ok(())
}

async fn run_logout() -> Result<()> {
    let mut cfg = config::CliConfig::load().await?;
    let resolved = cfg.resolve_api_url(api_url_override());

    if let Some(token) = resolve_cli_auth_token(&cfg).await {
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

    let keychain = keychain::KeyringStore::new(KEYCHAIN_SERVICE);
    if let Err(e) = keychain.delete(KEYCHAIN_AUTH_TOKEN_ACCOUNT).await {
        output::note(&format!("Could not clear OS keychain token: {e}"));
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

async fn resolve_cli_auth_token(cfg: &config::CliConfig) -> Option<String> {
    let keychain = keychain::KeyringStore::new(KEYCHAIN_SERVICE);
    match keychain.get(KEYCHAIN_AUTH_TOKEN_ACCOUNT).await {
        Ok(Some(token)) if !token.trim().is_empty() => Some(token),
        Ok(_) | Err(_) => cfg.token.clone().filter(|t| !t.trim().is_empty()),
    }
}

async fn report_backfill_completion(window_days: i32, stats: BackfillSyncStats) {
    let cfg = match config::CliConfig::load().await {
        Ok(cfg) => cfg,
        Err(_) => return,
    };

    let token = match resolve_cli_auth_token(&cfg).await {
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
/// This function swallows all errors and returns `Ok(())` EXCEPT when
/// encryption is configured and fails — in that case it returns `Err` to
/// block the commit (non-zero exit). This is the only case where the hook
/// intentionally fails.
///
/// The outer wrapper uses `std::panic::catch_unwind` to catch panics, and
/// pattern-matches on `HookError` to distinguish commit-blocking
/// failures from soft failures that should be swallowed.
async fn run_hook_post_commit() -> Result<()> {
    // Catch-all: catch panics
    let result = tokio::spawn(async { hook_post_commit_inner().await }).await;

    let final_result = match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(HookError::EncryptionFailed(msg))) => {
            output::fail("Encryption", &format!("failed ({})", msg));
            anyhow::bail!("Encryption configured but failed: {}", msg);
        }
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

/// The pre-push hook handler. Must never block the push.
async fn run_hook_pre_push(remote: &str, url: &str) -> Result<()> {
    let remote = remote.to_string();
    let url = url.to_string();
    let result = tokio::spawn(async move { hook_pre_push_inner(&remote, &url).await }).await;

    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            output::note(&format!("Hook issue: {}", e));
        }
        Err(e) => {
            if !e.is_panic() {
                output::note(&format!("Hook task failed: {}", e));
            }
            output::note("Hook panicked (please report this issue)");
        }
    }

    eprintln!();
    Ok(())
}

/// Inner implementation of the post-commit hook.
///
/// Returns `HookError::EncryptionFailed` if encryption is configured but
/// fails — this is the only case where the hook blocks the commit. All other
/// errors are wrapped in `HookError::Soft` and swallowed by the caller.
async fn hook_post_commit_inner() -> std::result::Result<(), HookError> {
    // Step 0: Per-repo enabled check — if disabled, skip EVERYTHING
    if !git::check_enabled().await {
        return Ok(());
    }

    // Step 1: Get repo root
    let repo_root = git::repo_root().await?;
    let repo_root_str = repo_root.to_string_lossy().to_string();

    // Step 1.25: Org filter gating — skip all attachment if mismatched
    match git::repo_matches_org_filter(&repo_root).await {
        Ok(true) => {}
        Ok(false) => return Ok(()),
        Err(e) => return Err(HookError::Soft(e)),
    }

    // Step 1.5: Resolve encryption method once for this invocation
    let encryption_method = resolve_encryption_method().await.map_err(|e| {
        // Config read failure is a soft error — don't block commit
        HookError::Soft(e)
    })?;

    let storing_progress = hook_status_spinner_start("Storing AI sessions");
    let scanned = match ingest_recent_sessions_for_repo(
        &repo_root,
        &repo_root_str,
        POST_COMMIT_MATCH_WINDOW_SECS,
        &encryption_method,
    )
    .await
    {
        Ok(scanned) => {
            hook_status_spinner_finish_ok(storing_progress, "Storing AI sessions");
            scanned
        }
        Err(e) => {
            hook_status_spinner_finish_err(storing_progress, "Storing AI sessions");
            return Err(if encryption_method.is_configured() {
                HookError::EncryptionFailed(format!("{:#}", e))
            } else {
                HookError::Soft(e)
            });
        }
    };
    if output::is_verbose() {
        output::detail(&format!("ingested {} recent sessions", scanned));
    }

    Ok(())
}

/// Inner implementation of the pre-push hook.
async fn hook_pre_push_inner(remote: &str, _url: &str) -> Result<()> {
    if !git::check_enabled().await {
        return Ok(());
    }

    if push::should_push_remote(remote).await {
        let repo_root = git::repo_root().await?;
        let repo_root_str = repo_root.to_string_lossy().to_string();
        let encryption_method = resolve_encryption_method()
            .await
            .unwrap_or_else(|e| EncryptionMethod::Unavailable(format!("{e}")));
        if let Err(e) =
            ingest_incremental_sessions_for_repo(&repo_root, &repo_root_str, &encryption_method)
                .await
        {
            output::note(&format!("Pre-push ingest issue: {}", e));
        }
        let queue_progress = hook_status_spinner_start("Queueing AI session sync");
        deferred_sync::enqueue_pending_sync(&repo_root, remote).await?;
        let _ = deferred_sync::spawn_background_sync(&repo_root, remote).await;
        hook_status_spinner_finish_ok(queue_progress, "Queueing AI session sync");
    }

    Ok(())
}

const POST_COMMIT_MATCH_WINDOW_SECS: i64 = 1_800;

/// Stored canonical session object info.
struct SessionIngestInfo {
    session_uid: String,
    blob_sha: String,
    encoding: note::ContentEncoding,
}

const INDEX_TARGET_SIZE_BYTES: usize = 128 * 1024;
const INDEX_HARD_SIZE_BYTES: usize = 256 * 1024;

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

fn format_unix_rfc3339(epoch: i64) -> Option<String> {
    let dt = time::OffsetDateTime::from_unix_timestamp(epoch).ok()?;
    dt.format(&time::format_description::well_known::Rfc3339)
        .ok()
}

async fn branch_key_for_repo(repo: &std::path::Path) -> String {
    let remote = git::resolve_push_remote_at(repo)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "origin".to_string());
    let branch = git::current_branch_at(repo)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "detached/unknown".to_string());
    format!("{remote}/{branch}")
}

async fn branch_keys_for_repo_and_commits(
    repo: &std::path::Path,
    commits: &[String],
) -> Vec<String> {
    let remote = git::resolve_push_remote_at(repo)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "origin".to_string());
    let mut branch_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for commit in commits {
        if let Ok(branches) = git::branches_containing_commit_at(repo, commit).await {
            for branch in branches {
                if !branch.is_empty() {
                    branch_names.insert(branch);
                }
            }
        }
    }

    if branch_names.is_empty()
        && let Ok(Some(current)) = git::current_branch_at(repo).await
    {
        branch_names.insert(current);
    }

    if branch_names.is_empty() {
        branch_names.insert("detached/unknown".to_string());
    }

    branch_names
        .into_iter()
        .map(|branch| format!("{remote}/{branch}"))
        .collect()
}

async fn committer_key_hash_for_repo(repo: &std::path::Path) -> String {
    let email = git::config_get_at(repo, "user.email")
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "unknown".to_string());
    note::hash_key(email.trim().to_ascii_lowercase().as_str())
}

fn normalize_observed_commits(commits: Option<&[String]>) -> Vec<String> {
    let mut out: Vec<String> = commits
        .unwrap_or_default()
        .iter()
        .map(|c| c.trim().to_ascii_lowercase())
        .filter(|c| c.len() >= 7 && c.len() <= 40 && c.bytes().all(|b| b.is_ascii_hexdigit()))
        .collect();
    out.sort();
    out.dedup();
    out
}

#[allow(clippy::too_many_arguments)]
async fn ingest_session_from_log(
    agent_type: &scanner::AgentType,
    session_id: &str,
    repo_str: &str,
    observed_commits: Option<&[String]>,
    session_log: &str,
    confidence: note::Confidence,
    method: &EncryptionMethod,
    session_start: Option<i64>,
    match_score: Option<f64>,
    match_reasons: Option<&[String]>,
    repo: Option<&std::path::Path>,
    explicit_branch_keys: Option<&[String]>,
) -> Result<SessionIngestInfo> {
    let repo_path = match repo {
        Some(r) => r.to_path_buf(),
        None => git::repo_root().await?,
    };
    let content_sha256 = note::content_sha256(session_log);
    let session_uid = note::compute_session_uid(
        agent_type,
        session_id,
        repo_str,
        session_start,
        &content_sha256,
    );
    let observed_commits = normalize_observed_commits(observed_commits);
    let ingested_at = session_start
        .and_then(format_unix_rfc3339)
        .unwrap_or_else(note::now_rfc3339);
    let touched_paths = Vec::new();
    let mut branch_keys: Vec<String> = explicit_branch_keys
        .map(|keys| keys.to_vec())
        .unwrap_or_default();
    if branch_keys.is_empty() {
        branch_keys.push(branch_key_for_repo(&repo_path).await);
    }
    branch_keys.sort();
    branch_keys.dedup();
    let branch_key = branch_keys
        .first()
        .cloned()
        .unwrap_or_else(|| "detached/unknown".to_string());
    let committer_key_hash = committer_key_hash_for_repo(&repo_path).await;
    let repo_remote_url = match git::resolve_push_remote_at(&repo_path).await {
        Ok(Some(remote)) => git::remote_url_at(&repo_path, &remote).await.ok().flatten(),
        _ => None,
    };

    let record = note::SessionRecord {
        session_uid: session_uid.clone(),
        agent: agent_type.to_string(),
        session_id: session_id.to_string(),
        repo_root: repo_str.to_string(),
        repo_remote_url,
        branch_key: branch_key.clone(),
        committer_key_hash: committer_key_hash.clone(),
        session_start,
        session_end: session_start,
        content_sha256,
        observed_commits,
        time_window: session_start.map(|start| note::TimeWindow { start, end: start }),
        cwd: Some(repo_str.to_string()),
        touched_paths,
        match_signals: Some(note::MatchSignals {
            confidence: confidence.to_string(),
            score: match_score,
            reasons: match_reasons.unwrap_or_default().to_vec(),
        }),
        ingested_at: ingested_at.clone(),
        cli_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let session_bytes = note::serialize_session_object(record, session_log.to_string())?;
    let _ = git::migrate_legacy_session_ref_at(Some(&repo_path)).await?;
    let (blob_sha, encoding) =
        encode_and_store_session_object_at(Some(&repo_path), &session_bytes, method).await?;
    let fanout_path = git::fanout_path_for_key_hash(&session_uid)?;
    git::ensure_blob_referenced_in_ref_at(
        &repo_path,
        git::SESSION_DATA_REF,
        &fanout_path,
        &blob_sha,
        "cadence session data",
    )
    .await?;

    let index_entry = note::IndexEntry {
        session_uid: session_uid.clone(),
        session_blob_sha: blob_sha.clone(),
        session_start,
        agent: agent_type.to_string(),
        ingested_at,
    };
    let line = note::serialize_index_entry_line(&index_entry)?;
    for key in &branch_keys {
        git::append_index_entry_at(
            &repo_path,
            git::SESSION_INDEX_BRANCH_REF,
            &note::hash_key(key),
            &line,
            INDEX_TARGET_SIZE_BYTES,
            INDEX_HARD_SIZE_BYTES,
            "cadence branch index",
        )
        .await?;
    }
    git::append_index_entry_at(
        &repo_path,
        git::SESSION_INDEX_COMMITTER_REF,
        &committer_key_hash,
        &line,
        INDEX_TARGET_SIZE_BYTES,
        INDEX_HARD_SIZE_BYTES,
        "cadence committer index",
    )
    .await?;

    Ok(SessionIngestInfo {
        session_uid,
        blob_sha,
        encoding,
    })
}

async fn ingest_recent_sessions_for_repo(
    repo_root: &std::path::Path,
    repo_root_str: &str,
    since_secs: i64,
    method: &EncryptionMethod,
) -> Result<usize> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let files = agents::discover_recent_sessions(now, since_secs).await;
    let mut ingested = 0usize;

    for log in files {
        let metadata = session_log_metadata(&log).await;
        let Some(cwd) = metadata.cwd else {
            continue;
        };
        let Ok(resolved_repo) = git::repo_root_at(std::path::Path::new(&cwd)).await else {
            continue;
        };
        if resolved_repo != repo_root {
            continue;
        }

        let session_id = metadata
            .session_id
            .as_deref()
            .unwrap_or("unknown")
            .to_string();
        let agent = metadata
            .agent_type
            .clone()
            .unwrap_or(scanner::AgentType::Claude);
        let session_start = session_log_time_range(&log).await.map(|(start, _)| start);
        let observed_commits = session_log_commit_hashes(&log).await;
        let explicit_branch_keys =
            branch_keys_for_repo_and_commits(repo_root, &observed_commits).await;
        let session_log = match session_log_content_async(&log).await {
            Some(content) => content,
            None => continue,
        };
        let match_reasons = if log.match_reasons.is_empty() {
            None
        } else {
            Some(log.match_reasons.as_slice())
        };

        let info = ingest_session_from_log(
            &agent,
            &session_id,
            repo_root_str,
            Some(&observed_commits),
            &session_log,
            note::Confidence::ScoredMatch,
            method,
            session_start,
            None,
            match_reasons,
            Some(repo_root),
            Some(&explicit_branch_keys),
        )
        .await?;
        ingested += 1;
        if output::is_verbose() {
            output::detail(&format!(
                "session uid {} stored as {} ({})",
                info.session_uid, info.blob_sha, info.encoding
            ));
        }
    }

    Ok(ingested)
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

async fn session_log_time_range(log: &agents::SessionLog) -> Option<(i64, i64)> {
    match &log.source {
        agents::SessionSource::File(path) => scanner::session_time_range(path).await,
        agents::SessionSource::Inline { content, .. } => scanner::session_time_range_str(content),
    }
}

async fn session_log_commit_hashes(log: &agents::SessionLog) -> Vec<String> {
    match &log.source {
        agents::SessionSource::File(path) => scanner::extract_commit_hashes(path).await,
        agents::SessionSource::Inline { content, .. } => {
            scanner::extract_commit_hashes_str(content)
        }
    }
}

async fn session_log_content_async(log: &agents::SessionLog) -> Option<String> {
    match &log.source {
        agents::SessionSource::File(path) => tokio::fs::read_to_string(path).await.ok(),
        agents::SessionSource::Inline { content, .. } => Some(content.clone()),
    }
}

async fn ingest_incremental_sessions_for_repo(
    repo_root: &std::path::Path,
    repo_root_str: &str,
    method: &EncryptionMethod,
) -> Result<usize> {
    let remote = git::resolve_push_remote_at(repo_root)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "origin".to_string());
    let committer_hash = committer_key_hash_for_repo(repo_root).await;
    let mut local_branches = git::local_branches_at(repo_root).await.unwrap_or_default();
    if local_branches.is_empty()
        && let Ok(Some(current)) = git::current_branch_at(repo_root).await
    {
        local_branches.push(current);
    }
    local_branches.sort();
    local_branches.dedup();

    let branch_keys: Vec<String> = local_branches
        .iter()
        .map(|branch| format!("{remote}/{branch}"))
        .collect();
    let branch_key_hashes: Vec<String> = branch_keys.iter().map(|k| note::hash_key(k)).collect();

    let mut cursor_values = Vec::new();
    if let Some(rec) = sync_pending::load_cursor(
        repo_root_str,
        sync_pending::ScopeType::Committer,
        &committer_hash,
    )
    .await?
    {
        cursor_values.push(rec.last_scanned_mtime_epoch);
    }
    for key_hash in &branch_key_hashes {
        if let Some(rec) =
            sync_pending::load_cursor(repo_root_str, sync_pending::ScopeType::Branch, key_hash)
                .await?
        {
            cursor_values.push(rec.last_scanned_mtime_epoch);
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let fallback_since = now - 30 * 86_400;
    let min_cursor = cursor_values.into_iter().min().unwrap_or(fallback_since);
    let since_secs = (now - min_cursor).max(0);
    let files = agents::discover_recent_sessions(now, since_secs).await;

    let mut ingested = 0usize;
    let mut max_mtime = min_cursor;
    for log in files {
        let Some(mtime) = log.updated_at else {
            continue;
        };
        if mtime <= min_cursor {
            continue;
        }
        if mtime > max_mtime {
            max_mtime = mtime;
        }

        let metadata = session_log_metadata(&log).await;
        let Some(cwd) = metadata.cwd else {
            continue;
        };
        let Ok(resolved_repo) = git::repo_root_at(std::path::Path::new(&cwd)).await else {
            continue;
        };
        if resolved_repo != repo_root {
            continue;
        }

        let session_id = metadata
            .session_id
            .as_deref()
            .unwrap_or("unknown")
            .to_string();
        let agent = metadata
            .agent_type
            .clone()
            .unwrap_or(scanner::AgentType::Claude);
        let observed_commits = session_log_commit_hashes(&log).await;
        let explicit_branch_keys =
            branch_keys_for_repo_and_commits(repo_root, &observed_commits).await;
        let session_start = session_log_time_range(&log).await.map(|(start, _)| start);
        let session_log = match session_log_content_async(&log).await {
            Some(content) => content,
            None => continue,
        };
        let match_reasons = if log.match_reasons.is_empty() {
            None
        } else {
            Some(log.match_reasons.as_slice())
        };

        let info = ingest_session_from_log(
            &agent,
            &session_id,
            repo_root_str,
            Some(&observed_commits),
            &session_log,
            note::Confidence::ScoredMatch,
            method,
            session_start,
            None,
            match_reasons,
            Some(repo_root),
            Some(&explicit_branch_keys),
        )
        .await?;
        ingested += 1;
        if output::is_verbose() {
            output::detail(&format!(
                "pre-push incremental: session uid {} stored as {} ({})",
                info.session_uid, info.blob_sha, info.encoding
            ));
        }
    }

    sync_pending::upsert_cursor(
        repo_root_str,
        sync_pending::ScopeType::Committer,
        &committer_hash,
        max_mtime,
    )
    .await?;
    for key_hash in &branch_key_hashes {
        sync_pending::upsert_cursor(
            repo_root_str,
            sync_pending::ScopeType::Branch,
            key_hash,
            max_mtime,
        )
        .await?;
    }

    Ok(ingested)
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

/// The backfill subcommand: backfill AI session notes for recent commits.
///
/// This scans ALL Claude and Codex log directories (not scoped to any
/// single repo), finds commit hashes in session logs, resolves repos
/// from session metadata, and attaches notes where missing.
///
/// Properties:
/// - Can take minutes for large log directories
/// - Prints verbose progress throughout
/// - All errors are non-fatal (logged and continued)
/// - Always syncs and pushes canonical session refs per repository
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
    commit_hashes: Vec<String>,
}

#[derive(Default)]
struct RepoBackfillStats {
    sessions_seen: usize,
    attached: usize,
    skipped: usize,
    errors: usize,
    fallback_attached: usize,
    commits_found: usize,
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
    encryption_method: EncryptionMethod,
    repo_progress: Option<ProgressBar>,
    backfill_logger: backfill_log::BackfillLogger,
) -> RepoBackfillStats {
    let mut stats = RepoBackfillStats::default();
    let planned_units: u64 = sessions
        .iter()
        .map(|s| {
            if s.commit_hashes.is_empty() {
                1_u64
            } else {
                s.commit_hashes.len() as u64
            }
        })
        .sum::<u64>()
        .max(1);
    if let Some(pb) = &repo_progress {
        pb.set_length(planned_units);
        pb.set_message("starting");
    }

    let repo_root = match sessions.first() {
        Some(session) => session.repo_root.clone(),
        None => {
            backfill_logger.event(
                "repo_skipped",
                serde_json::json!({
                    "repo_display": repo_display.as_str(),
                    "reason": "no_sessions",
                }),
            );
            if let Some(pb) = &repo_progress {
                pb.finish_with_message("no sessions");
            }
            return stats;
        }
    };
    let repo_root_str = repo_root.to_string_lossy().to_string();

    backfill_logger.event(
        "repo_started",
        serde_json::json!({
            "repo_display": repo_display.as_str(),
            "repo_root": repo_root_str.as_str(),
            "sessions": sessions.len(),
            "planned_units": planned_units,
            "sync_remote_before_attach": true,
            "do_push": true,
        }),
    );

    match git::repo_matches_org_filter(&repo_root).await {
        Ok(true) => {}
        Ok(false) => {
            backfill_logger.event(
                "repo_skipped",
                serde_json::json!({
                    "repo_display": repo_display.as_str(),
                    "repo_root": repo_root_str.as_str(),
                    "reason": "org_filter",
                }),
            );
            if let Some(pb) = &repo_progress {
                pb.finish_with_message("skipped (org filter)");
            }
            return stats;
        }
        Err(e) => {
            output::detail(&format!("{}: org filter check failed: {}", repo_display, e));
            stats.errors += 1;
            backfill_logger.event(
                "repo_error",
                serde_json::json!({
                    "repo_display": repo_display.as_str(),
                    "repo_root": repo_root_str.as_str(),
                    "stage": "org_filter_check",
                    "error": e.to_string(),
                }),
            );
            if let Some(pb) = &repo_progress {
                pb.finish_with_message("error (org filter)");
            }
            return stats;
        }
    }

    let repo_enabled = git::check_enabled_at(&repo_root).await;
    if !repo_enabled {
        backfill_logger.event(
            "repo_skipped",
            serde_json::json!({
                "repo_display": repo_display.as_str(),
                "repo_root": repo_root_str.as_str(),
                "reason": "disabled",
            }),
        );
        if let Some(pb) = &repo_progress {
            pb.finish_with_message("skipped (disabled)");
        }
        return stats;
    }

    let repo_remote = {
        let remote = match git::resolve_push_remote_at(&repo_root).await {
            Ok(Some(remote)) => remote,
            _ => "origin".to_string(),
        };
        backfill_logger.event(
            "repo_remote_sync_started",
            serde_json::json!({
                "repo_display": repo_display.as_str(),
                "repo_root": repo_root_str.as_str(),
                "remote": remote.as_str(),
            }),
        );
        match push::fetch_merge_notes_for_remote_at(&repo_root, &remote).await {
            Ok(()) => {
                backfill_logger.event(
                    "repo_remote_sync_completed",
                    serde_json::json!({
                        "repo_display": repo_display.as_str(),
                        "repo_root": repo_root_str.as_str(),
                        "remote": remote.as_str(),
                    }),
                );
            }
            Err(e) => {
                backfill_logger.event(
                    "repo_remote_sync_error",
                    serde_json::json!({
                        "repo_display": repo_display.as_str(),
                        "repo_root": repo_root_str.as_str(),
                        "remote": remote.as_str(),
                        "error": e.to_string(),
                    }),
                );
            }
        }
        remote
    };

    for session in sessions {
        stats.sessions_seen += 1;
        let commit_hashes = session.commit_hashes.clone();
        stats.commits_found += commit_hashes.len();
        let session_file = session.log.source_label();
        let agent_type = session
            .metadata
            .agent_type
            .clone()
            .unwrap_or(scanner::AgentType::Claude);
        backfill_logger.event(
            "repo_session_started",
            serde_json::json!({
                "repo_display": repo_display.as_str(),
                "repo_root": repo_root_str.as_str(),
                "session_id": session.session_id.as_str(),
                "file": session_file,
                "agent": agent_type.to_string(),
                "observed_commits": commit_hashes.len(),
            }),
        );

        let session_log = match session_log_content_async(&session.log).await {
            Some(content) => content,
            None => {
                stats.errors += 1;
                backfill_logger.event(
                    "session_error",
                    serde_json::json!({
                        "repo_display": repo_display.as_str(),
                        "repo_root": repo_root_str.as_str(),
                        "session_id": session.session_id.as_str(),
                        "file": session.log.source_label(),
                        "stage": "read_session_log",
                        "error": "failed to read session log",
                    }),
                );
                if let Some(pb) = &repo_progress {
                    pb.inc(1);
                }
                continue;
            }
        };
        let repo_str = session.repo_root.to_string_lossy().to_string();
        let session_start = session_log_time_range(&session.log)
            .await
            .map(|(start, _)| start);

        let branch_keys =
            branch_keys_for_repo_and_commits(&session.repo_root, &commit_hashes).await;
        match ingest_session_from_log(
            &agent_type,
            &session.session_id,
            &repo_str,
            Some(&commit_hashes),
            &session_log,
            note::Confidence::ScoredMatch,
            &encryption_method,
            session_start,
            None,
            if session.log.match_reasons.is_empty() {
                None
            } else {
                Some(session.log.match_reasons.as_slice())
            },
            Some(&session.repo_root),
            Some(&branch_keys),
        )
        .await
        {
            Ok(info) => {
                stats.attached += 1;
                backfill_logger.event(
                    "session_uploaded",
                    serde_json::json!({
                        "repo_display": repo_display.as_str(),
                        "repo_root": repo_root_str.as_str(),
                        "session_id": session.session_id.as_str(),
                        "file": session.log.source_label(),
                        "session_uid": info.session_uid,
                        "session_blob": info.blob_sha,
                    }),
                );
            }
            Err(e) => {
                stats.errors += 1;
                backfill_logger.event(
                    "session_upload_error",
                    serde_json::json!({
                        "repo_display": repo_display.as_str(),
                        "repo_root": repo_root_str.as_str(),
                        "session_id": session.session_id.as_str(),
                        "file": session.log.source_label(),
                        "error": e.to_string(),
                    }),
                );
            }
        }
        if let Some(pb) = &repo_progress {
            pb.inc(1);
            pb.set_message(format!(
                "sessions={}, uploaded={}, issues={}",
                stats.sessions_seen, stats.attached, stats.errors
            ));
        }
    }

    backfill_logger.event(
        "repo_push_started",
        serde_json::json!({
            "repo_display": repo_display.as_str(),
            "repo_root": repo_root_str.as_str(),
            "remote": repo_remote.as_str(),
        }),
    );
    push::attempt_push_remote_at_quiet(&repo_root, &repo_remote).await;
    backfill_logger.event(
        "repo_push_completed",
        serde_json::json!({
            "repo_display": repo_display.as_str(),
            "repo_root": repo_root_str.as_str(),
            "remote": repo_remote.as_str(),
        }),
    );

    if let Some(pb) = &repo_progress {
        pb.finish_with_message(format!(
            "done: sessions={}, commits={}, uploaded={}, skipped={}, issues={}",
            stats.sessions_seen, stats.commits_found, stats.attached, stats.skipped, stats.errors
        ));
    }

    backfill_logger.event(
        "repo_completed",
        serde_json::json!({
            "repo_display": repo_display.as_str(),
            "repo_root": repo_root_str.as_str(),
            "sessions_seen": stats.sessions_seen,
            "commits_found": stats.commits_found,
            "attached": stats.attached,
            "fallback_attached": stats.fallback_attached,
            "skipped": stats.skipped,
            "errors": stats.errors,
        }),
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

    let backfill_logger = match backfill_log::BackfillLogger::new().await {
        Ok(logger) => {
            if let Some(path) = logger.path() {
                output::detail(&format!("Backfill diagnostics: {}", path.display()));
            }
            logger
        }
        Err(e) => {
            output::detail(&format!("Backfill diagnostics unavailable: {e}"));
            backfill_log::BackfillLogger::disabled()
        }
    };

    // Resolve encryption method once for this backfill run
    let encryption_method = match resolve_encryption_method().await {
        Ok(method) => method,
        Err(e) => EncryptionMethod::Unavailable(format!("{e}")),
    };

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

    backfill_logger.event(
        "backfill_started",
        serde_json::json!({
            "cli_version": env!("CARGO_PKG_VERSION"),
            "since": since,
            "since_secs": since_secs,
            "since_days": since_days,
            "do_push": true,
            "sync_remote_before_attach": true,
            "repo_filter": repo_filter.map(|p| p.to_string_lossy().to_string()),
            "use_progress": use_progress,
        }),
    );

    // Step 2: Find all session files modified within the --since window
    backfill_logger.event(
        "scan_recent_files_started",
        serde_json::json!({
            "now_epoch": now,
            "since_secs": since_secs,
        }),
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
    backfill_logger.event(
        "scan_recent_files_completed",
        serde_json::json!({
            "files_found": files.len(),
            "agent_counts": agent_counts,
        }),
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
    let mut attached = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;
    let mut fallback_attached = 0usize;
    let mut sessions_by_repo: std::collections::BTreeMap<String, Vec<SessionInfo>> =
        std::collections::BTreeMap::new();
    let mut repo_root_cache: std::collections::HashMap<String, std::path::PathBuf> =
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
            backfill_logger.event(
                "session_discovery_skipped",
                serde_json::json!({
                    "file": file_path.as_str(),
                    "reason": "missing_session_metadata",
                }),
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
                backfill_logger.event(
                    "session_discovery_skipped",
                    serde_json::json!({
                        "file": file_path.as_str(),
                        "session_id": metadata.session_id,
                        "reason": "missing_cwd",
                    }),
                );
                if let Some(ref pb) = progress {
                    pb.inc(1);
                }
                continue;
            }
        };

        let repo_root = if let Some(cached) = repo_root_cache.get(&cwd) {
            cached.clone()
        } else {
            let cwd_path = std::path::Path::new(&cwd);
            let resolved = match git::repo_root_at(cwd_path).await {
                Ok(r) => r,
                Err(e) => {
                    backfill_logger.event(
                        "session_discovery_skipped",
                        serde_json::json!({
                            "file": file_path.as_str(),
                            "session_id": metadata.session_id,
                            "cwd": cwd,
                            "reason": "repo_root_lookup_failed",
                            "error": e.to_string(),
                        }),
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

        // If a repo filter is set, skip sessions that don't match.
        if let Some(filter) = repo_filter
            && repo_root != filter
        {
            backfill_logger.event(
                "session_discovery_skipped",
                serde_json::json!({
                    "file": file_path.as_str(),
                    "session_id": metadata.session_id,
                    "cwd": cwd,
                    "repo_root": repo_root.to_string_lossy(),
                    "reason": "repo_filter_mismatch",
                    "repo_filter": filter.to_string_lossy(),
                }),
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
                    backfill_logger.event(
                        "repo_display_fallback",
                        serde_json::json!({
                            "file": file_path.as_str(),
                            "session_id": session_id.as_str(),
                            "repo_root": repo_root.to_string_lossy(),
                            "error": e.to_string(),
                        }),
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

        let commit_hashes = session_log_commit_hashes(log).await;
        let agent_label = metadata
            .agent_type
            .clone()
            .unwrap_or(scanner::AgentType::Claude)
            .to_string();
        backfill_logger.event(
            "session_enqueued",
            serde_json::json!({
                "file": file_path.as_str(),
                "session_id": session_id.as_str(),
                "cwd": cwd,
                "repo_root": repo_root.to_string_lossy(),
                "repo_display": repo_display.as_str(),
                "agent": agent_label,
                "commit_hashes": commit_hashes.len(),
            }),
        );

        sessions_by_repo
            .entry(repo_display.clone())
            .or_default()
            .push(SessionInfo {
                log: log.clone(),
                session_id,
                repo_root,
                metadata,
                commit_hashes,
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
    backfill_logger.event(
        "repo_workers_started",
        serde_json::json!({
            "total_repos": total_repos,
            "concurrency": concurrency,
        }),
    );
    if let Some(mp) = &multi {
        mp.set_draw_target(ProgressDrawTarget::stderr());
        mp.set_move_cursor(true);
    }

    for (repo_display, sessions) in sessions_by_repo {
        let permit = semaphore.clone().acquire_owned().await?;
        let method = encryption_method.clone();
        backfill_logger.event(
            "repo_worker_queued",
            serde_json::json!({
                "repo_display": repo_display.as_str(),
                "sessions": sessions.len(),
            }),
        );
        let per_repo_bar = if let Some(mp) = &multi {
            let total_units: u64 = sessions
                .iter()
                .map(|s| {
                    if s.commit_hashes.is_empty() {
                        1_u64
                    } else {
                        s.commit_hashes.len() as u64
                    }
                })
                .sum::<u64>()
                .max(1);
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
        let backfill_logger = backfill_logger.clone();
        join_set.spawn(async move {
            let _permit = permit;
            Ok::<RepoBackfillStats, tokio::task::JoinError>(
                process_repo_backfill(
                    repo_display,
                    sessions,
                    method,
                    per_repo_bar,
                    backfill_logger,
                )
                .await,
            )
        });
    }

    while let Some(joined) = join_set.join_next().await {
        match joined {
            Ok(Ok(repo_stats)) => {
                attached += repo_stats.attached;
                skipped += repo_stats.skipped;
                errors += repo_stats.errors;
                fallback_attached += repo_stats.fallback_attached;
                backfill_logger.event(
                    "repo_worker_result",
                    serde_json::json!({
                        "attached": repo_stats.attached,
                        "fallback_attached": repo_stats.fallback_attached,
                        "sessions_seen": repo_stats.sessions_seen,
                        "skipped": repo_stats.skipped,
                        "errors": repo_stats.errors,
                        "commits_found": repo_stats.commits_found,
                    }),
                );
            }
            Ok(Err(e)) => {
                errors += 1;
                output::detail(&format!("repo worker failed: {}", e));
                backfill_logger.event(
                    "repo_worker_error",
                    serde_json::json!({
                        "error": e.to_string(),
                    }),
                );
            }
            Err(e) => {
                errors += 1;
                output::detail(&format!("repo task join failed: {}", e));
                backfill_logger.event(
                    "repo_worker_join_error",
                    serde_json::json!({
                        "error": e.to_string(),
                    }),
                );
            }
        }
    }

    // Final summary
    output::success(
        "Backfill",
        &format!(
            "{} uploaded, {} fallback uploaded, {} skipped, {} issues",
            attached, fallback_attached, skipped, errors
        ),
    );
    let issues = if errors > 0 {
        vec![format!("{errors} issue(s) encountered during backfill")]
    } else {
        Vec::new()
    };
    report_backfill_completion(
        since_days as i32,
        BackfillSyncStats {
            notes_attached: attached as i64,
            notes_skipped: skipped as i64,
            issues,
            repos_scanned: total_repos as i32,
        },
    )
    .await;
    backfill_logger.event(
        "backfill_completed",
        serde_json::json!({
            "attached": attached,
            "fallback_attached": fallback_attached,
            "skipped": skipped,
            "errors": errors,
            "repos_scanned": total_repos,
            "since_days": since_days,
            "do_push": true,
        }),
    );
    Ok(())
}

fn parse_ls_tree_line(line: &str) -> Option<(String, String, String)> {
    let (meta, name) = line.split_once('\t')?;
    let mut parts = meta.split_whitespace();
    let _mode = parts.next()?;
    let kind = parts.next()?.to_string();
    let sha = parts.next()?.to_string();
    Some((kind, sha, name.to_string()))
}

async fn list_index_entries_for_key(
    repo: &std::path::Path,
    ref_name: &str,
    key_hash: &str,
) -> Result<Vec<note::IndexEntry>> {
    if !git::ref_exists_at(Some(repo), ref_name).await? {
        return Ok(Vec::new());
    }
    let fanout = git::fanout_path_for_key_hash(key_hash)?;
    let mut split = fanout.splitn(2, '/');
    let dir = split.next().unwrap_or("");
    let file_prefix = split.next().unwrap_or("");
    if dir.is_empty() || file_prefix.is_empty() {
        return Ok(Vec::new());
    }

    let root_tree = format!("{ref_name}^{{tree}}");
    let mut dir_tree_sha: Option<String> = None;
    for line in git::list_tree_entries_at(Some(repo), &root_tree).await? {
        if let Some((kind, sha, name)) = parse_ls_tree_line(&line)
            && kind == "tree"
            && name == dir
        {
            dir_tree_sha = Some(sha);
            break;
        }
    }
    let Some(tree_sha) = dir_tree_sha else {
        return Ok(Vec::new());
    };

    let mut shard_blobs: Vec<(String, String)> = Vec::new();
    for line in git::list_tree_entries_at(Some(repo), &tree_sha).await? {
        if let Some((kind, sha, name)) = parse_ls_tree_line(&line)
            && kind == "blob"
            && name.starts_with(&format!("{file_prefix}--"))
            && name.ends_with(".ndjson")
        {
            shard_blobs.push((name, sha));
        }
    }
    shard_blobs.sort_by(|a, b| a.0.cmp(&b.0));

    let mut entries = Vec::new();
    for (_name, sha) in shard_blobs {
        let data = git::read_blob_at(Some(repo), &sha).await?;
        let text = String::from_utf8_lossy(&data);
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<note::IndexEntry>(trimmed) {
                entries.push(entry);
            }
        }
    }
    Ok(entries)
}

fn short_session_uid(uid: &str) -> String {
    uid.chars().take(12).collect()
}

fn truncate_with_ellipsis(value: &str, max_chars: usize) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut out = trimmed.chars().take(max_chars).collect::<String>();
    if trimmed.chars().count() > max_chars {
        out.push('…');
    }
    out
}

fn one_line_excerpt(text: &str, max_chars: usize) -> Option<String> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('{') && !line.starts_with('['))?;
    let normalized = line.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return None;
    }
    let mut out = normalized.chars().take(max_chars).collect::<String>();
    if normalized.chars().count() > max_chars {
        out.push('…');
    }
    Some(out)
}

fn jsonl_prompt_excerpt(text: &str, max_chars: usize) -> Option<String> {
    fn codex_user_prompt_title(prompt: &str, max_chars: usize) -> Option<String> {
        let trimmed = prompt.trim();
        if trimmed.is_empty() {
            return None;
        }

        if let Some((_, tail)) = trimmed.rsplit_once("My request for Codex:") {
            let line = tail
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty() && !line.starts_with("```"))?;
            let out = truncate_with_ellipsis(line, max_chars);
            if !out.is_empty() {
                return Some(out);
            }
        }

        for line in trimmed.lines().map(str::trim) {
            if line.is_empty()
                || line.starts_with("```")
                || line.starts_with("# AGENTS.md instructions")
                || line.starts_with("# Context from my IDE setup:")
                || line.starts_with("## Active file:")
                || line.starts_with("## Open tabs:")
                || line.starts_with("<INSTRUCTIONS>")
                || line.starts_with("</INSTRUCTIONS>")
            {
                continue;
            }
            let out = truncate_with_ellipsis(line, max_chars);
            if !out.is_empty() {
                return Some(out);
            }
        }

        let out = truncate_with_ellipsis(trimmed, max_chars);
        if out.is_empty() { None } else { Some(out) }
    }

    let mut latest_prompt: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };

        if value.get("type").and_then(|v| v.as_str()) == Some("user")
            && let Some(content) = value.get("content").and_then(|v| v.as_str())
        {
            let out = codex_user_prompt_title(content, max_chars);
            if out.is_some() {
                return out;
            }
        }

        if let Some(title) = value.pointer("/payload/title").and_then(|v| v.as_str()) {
            let out = truncate_with_ellipsis(title, max_chars);
            if !out.is_empty() {
                latest_prompt = Some(out);
            }
        }

        if let Some(input) = value.get("input") {
            if let Some(text) = input.as_str() {
                let out = codex_user_prompt_title(text, max_chars);
                if out.is_some() {
                    latest_prompt = out;
                }
            } else if let Some(map) = input.as_object() {
                let keys = [
                    "prompt",
                    "query",
                    "user_query",
                    "userQuery",
                    "request",
                    "text",
                ];
                for key in keys {
                    if let Some(text) = map.get(key).and_then(|v| v.as_str()) {
                        let out = codex_user_prompt_title(text, max_chars);
                        if out.is_some() {
                            latest_prompt = out;
                            break;
                        }
                    }
                }
            }
        }

        let is_user_message = value.pointer("/payload/type").and_then(|v| v.as_str())
            == Some("message")
            && value.pointer("/payload/role").and_then(|v| v.as_str()) == Some("user");
        if is_user_message
            && let Some(items) = value.pointer("/payload/content").and_then(|v| v.as_array())
        {
            for item in items {
                if item.get("type").and_then(|v| v.as_str()) == Some("input_text")
                    && let Some(prompt) = item.get("text").and_then(|v| v.as_str())
                {
                    let out = codex_user_prompt_title(prompt, max_chars);
                    if out.is_some() {
                        latest_prompt = out;
                    }
                }
            }
        }

        if value.pointer("/payload/type").and_then(|v| v.as_str()) == Some("message")
            && value.pointer("/payload/role").and_then(|v| v.as_str()) == Some("user")
            && let Some(prompt) = value.pointer("/payload/text").and_then(|v| v.as_str())
        {
            let out = codex_user_prompt_title(prompt, max_chars);
            if out.is_some() {
                latest_prompt = out;
            }
        }
    }
    latest_prompt
}

async fn load_decrypted_session_blob(blob: &[u8]) -> Option<Vec<u8>> {
    if serde_json::from_slice::<note::SessionEnvelope>(blob).is_ok() {
        return Some(blob.to_vec());
    }

    if let Ok(decoded) = zstd_decode_all_async(blob.to_vec()).await
        && serde_json::from_slice::<note::SessionEnvelope>(&decoded).is_ok()
    {
        return Some(decoded);
    }

    let private_key = pgp_keys::load_cached_user_private_key()
        .await
        .ok()
        .flatten()?;
    let fingerprint = pgp_keys::get_user_fingerprint().await.ok().flatten()?;
    let keychain = keychain::KeyringStore::new(KEYCHAIN_SERVICE);
    let passphrase = keychain.get(&fingerprint).await.ok().flatten()?;
    let decrypted =
        pgp_keys::decrypt_with_private_key_binary(blob, &private_key, &passphrase).ok()?;

    if let Ok(decoded) = zstd_decode_all_async(decrypted.clone()).await
        && serde_json::from_slice::<note::SessionEnvelope>(&decoded).is_ok()
    {
        return Some(decoded);
    }
    if serde_json::from_slice::<note::SessionEnvelope>(&decrypted).is_ok() {
        return Some(decrypted);
    }
    None
}

async fn zstd_decode_all_async(data: Vec<u8>) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || zstd::decode_all(std::io::Cursor::new(data)))
        .await
        .context("zstd decode task failed")?
        .context("zstd decode failed")
}

async fn build_local_session_labels_for_repo(
    repo: &std::path::Path,
) -> std::collections::HashMap<String, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let mut labels = std::collections::HashMap::new();
    for log in agents::discover_recent_sessions(now, 90 * 86_400).await {
        let metadata = session_log_metadata(&log).await;
        let Some(cwd) = metadata.cwd else {
            continue;
        };
        let Ok(file_repo_root) = git::repo_root_at(std::path::Path::new(&cwd)).await else {
            continue;
        };
        if file_repo_root != repo {
            continue;
        }
        let session_log = match session_log_content_async(&log).await {
            Some(content) => content,
            None => continue,
        };
        let session_id = metadata.session_id.as_deref().unwrap_or("unknown");
        let agent = metadata.agent_type.unwrap_or(scanner::AgentType::Claude);
        let session_start = session_log_time_range(&log).await.map(|(start, _)| start);
        let content_sha256 = note::content_sha256(&session_log);
        let session_uid = note::compute_session_uid(
            &agent,
            session_id,
            &file_repo_root.to_string_lossy(),
            session_start,
            &content_sha256,
        );

        let label = one_line_excerpt(&session_log, 72)
            .or_else(|| jsonl_prompt_excerpt(&session_log, 72))
            .unwrap_or_else(|| format!("session {}", truncate_with_ellipsis(session_id, 24)));
        labels.entry(session_uid).or_insert(label);
    }
    labels
}

async fn session_display_label(
    repo: &std::path::Path,
    entry: &note::IndexEntry,
    local_labels: &std::collections::HashMap<String, String>,
) -> String {
    if let Some(local) = local_labels.get(&entry.session_uid) {
        return local.clone();
    }
    let fallback = format!("session {}", short_session_uid(&entry.session_uid));
    let blob = match git::read_blob_at(Some(repo), &entry.session_blob_sha).await {
        Ok(data) => data,
        Err(_) => return fallback,
    };
    let decoded_blob = match load_decrypted_session_blob(&blob).await {
        Some(data) => data,
        None => return fallback,
    };
    let envelope = match serde_json::from_slice::<note::SessionEnvelope>(&decoded_blob) {
        Ok(parsed) => parsed,
        Err(_) => return fallback,
    };

    if let Some(excerpt) = one_line_excerpt(&envelope.session_content, 72) {
        return excerpt;
    }
    if let Some(excerpt) = jsonl_prompt_excerpt(&envelope.session_content, 72) {
        return excerpt;
    }
    if !envelope.record.session_id.trim().is_empty() {
        return format!(
            "session {}",
            truncate_with_ellipsis(&envelope.record.session_id, 24)
        );
    }
    fallback
}

async fn discovered_repos_for_sessions() -> Vec<std::path::PathBuf> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let mut repos = std::collections::BTreeSet::new();
    for log in agents::discover_recent_sessions(now, 90 * 86_400).await {
        let metadata = session_log_metadata(&log).await;
        let Some(cwd) = metadata.cwd else {
            continue;
        };
        let cwd_path = std::path::Path::new(&cwd);
        if let Ok(repo_root) = git::repo_root_at(cwd_path).await {
            repos.insert(repo_root);
        }
    }
    repos.into_iter().collect()
}

async fn print_sessions_for_repo(repo: &std::path::Path) -> Result<()> {
    let repo_str = repo.to_string_lossy();
    let branch_key_hash = note::hash_key(&branch_key_for_repo(repo).await);
    let committer_hash = committer_key_hash_for_repo(repo).await;

    let mut branch_entries =
        list_index_entries_for_key(repo, git::SESSION_INDEX_BRANCH_REF, &branch_key_hash).await?;
    branch_entries.sort_by(|a, b| b.session_start.cmp(&a.session_start));
    branch_entries.dedup_by(|a, b| a.session_uid == b.session_uid);

    let mut user_entries =
        list_index_entries_for_key(repo, git::SESSION_INDEX_COMMITTER_REF, &committer_hash).await?;
    user_entries.sort_by(|a, b| b.session_start.cmp(&a.session_start));
    user_entries.dedup_by(|a, b| a.session_uid == b.session_uid);
    let local_labels = build_local_session_labels_for_repo(repo).await;

    output::action("Repo", &repo_str);
    output::detail("Branch sessions:");
    for entry in branch_entries.iter().take(10) {
        let label = session_display_label(repo, entry, &local_labels).await;
        output::detail(&format!(
            "  {} {} {}",
            entry.session_start.unwrap_or_default(),
            entry.agent,
            label
        ));
    }
    let shown = user_entries.len().min(10);
    output::detail(&format!(
        "User sessions (last {} of {}):",
        shown,
        user_entries.len()
    ));
    for entry in user_entries.iter().take(shown) {
        let label = session_display_label(repo, entry, &local_labels).await;
        output::detail(&format!(
            "  {} {} {}",
            entry.session_start.unwrap_or_default(),
            entry.agent,
            label
        ));
    }
    Ok(())
}

async fn run_sessions_list(all: bool) -> Result<()> {
    if all {
        let repos = discovered_repos_for_sessions().await;
        if repos.is_empty() {
            output::note("No repositories discovered from recent sessions.");
            return Ok(());
        }
        for repo in repos {
            let _ = print_sessions_for_repo(&repo).await;
        }
        return Ok(());
    }

    let repo = git::repo_root()
        .await
        .map_err(|_| anyhow::anyhow!("not in a git repository. Use `cadence sessions --all`."))?;
    print_sessions_for_repo(&repo).await
}

async fn load_session_envelope_for_entry(
    repo: &std::path::Path,
    entry: &note::IndexEntry,
) -> Option<note::SessionEnvelope> {
    let blob = git::read_blob_at(Some(repo), &entry.session_blob_sha)
        .await
        .ok()?;
    let decoded = load_decrypted_session_blob(&blob).await?;
    serde_json::from_slice::<note::SessionEnvelope>(&decoded).ok()
}

async fn repo_local_branches(repo: &std::path::Path) -> Vec<String> {
    let mut branches = git::local_branches_at(repo).await.unwrap_or_default();
    if branches.is_empty()
        && let Ok(Some(current)) = git::current_branch_at(repo).await
    {
        branches.push(current);
    }
    branches.sort();
    branches.dedup();
    branches
}

async fn sessions_audit_repo(repo: &std::path::Path, show_ok: bool) -> Result<()> {
    let repo_label = repo.to_string_lossy().to_string();
    let remote = git::resolve_push_remote_at(repo)
        .await?
        .unwrap_or_else(|| "origin".to_string());
    let branches = repo_local_branches(repo).await;
    let local_labels = build_local_session_labels_for_repo(repo).await;
    let mut contains_cache: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    output::action("Audit", &repo_label);
    output::detail(&format!(
        "remote={}, local_branches={}",
        remote,
        branches.len()
    ));

    let mut total_sessions = 0usize;
    let mut related = 0usize;
    let mut commitless = 0usize;
    let mut unresolved = 0usize;
    let mut overindexed = 0usize;

    for branch in branches {
        let branch_key = format!("{remote}/{branch}");
        let key_hash = note::hash_key(&branch_key);
        let mut entries =
            list_index_entries_for_key(repo, git::SESSION_INDEX_BRANCH_REF, &key_hash).await?;
        entries.sort_by(|a, b| b.session_start.cmp(&a.session_start));
        entries.dedup_by(|a, b| a.session_uid == b.session_uid);
        if entries.is_empty() {
            continue;
        }

        output::detail(&format!(
            "branch={} indexed_sessions={}",
            branch,
            entries.len()
        ));
        for entry in entries {
            total_sessions += 1;
            let label = session_display_label(repo, &entry, &local_labels).await;
            let observed_commits = load_session_envelope_for_entry(repo, &entry)
                .await
                .map(|env| env.record.observed_commits)
                .unwrap_or_default();

            if observed_commits.is_empty() {
                commitless += 1;
                if show_ok {
                    output::detail(&format!(
                        "  OK commitless-fallback uid={} {}",
                        short_session_uid(&entry.session_uid),
                        label
                    ));
                }
                continue;
            }

            let mut branch_match = false;
            let mut any_resolution = false;
            let mut resolved_branches: std::collections::BTreeSet<String> =
                std::collections::BTreeSet::new();
            for commit in &observed_commits {
                let containing = if let Some(cached) = contains_cache.get(commit) {
                    cached.clone()
                } else {
                    let resolved = git::branches_containing_commit_at(repo, commit)
                        .await
                        .unwrap_or_default();
                    contains_cache.insert(commit.clone(), resolved.clone());
                    resolved
                };
                if !containing.is_empty() {
                    any_resolution = true;
                    for b in &containing {
                        resolved_branches.insert(b.clone());
                    }
                }
                if containing.iter().any(|b| b == &branch) {
                    branch_match = true;
                }
            }

            if branch_match {
                related += 1;
                if show_ok {
                    output::detail(&format!(
                        "  OK related uid={} {}",
                        short_session_uid(&entry.session_uid),
                        label
                    ));
                }
            } else if any_resolution {
                overindexed += 1;
                output::detail(&format!(
                    "  WARN overindexed uid={} branch={} related_to={:?} {}",
                    short_session_uid(&entry.session_uid),
                    branch,
                    resolved_branches.into_iter().collect::<Vec<_>>(),
                    label
                ));
            } else {
                unresolved += 1;
                output::detail(&format!(
                    "  WARN unresolved-commits uid={} {}",
                    short_session_uid(&entry.session_uid),
                    label
                ));
            }
        }
    }

    output::detail(&format!(
        "summary: total={}, related={}, commitless={}, unresolved={}, overindexed={}",
        total_sessions, related, commitless, unresolved, overindexed
    ));
    if commitless > 0 {
        output::detail(
            "note: commitless sessions are indexed by ingest-time branch fallback; overindex checks are strongest when observed_commits are present.",
        );
    }
    Ok(())
}

async fn run_sessions_audit(all: bool, show_ok: bool) -> Result<()> {
    if all {
        let repos = discovered_repos_for_sessions().await;
        if repos.is_empty() {
            output::note("No repositories discovered from recent sessions.");
            return Ok(());
        }
        for repo in repos {
            let _ = sessions_audit_repo(&repo, show_ok).await;
        }
        return Ok(());
    }
    let repo = git::repo_root().await.map_err(|_| {
        anyhow::anyhow!("not in a git repository. Use `cadence sessions audit --all`.")
    })?;
    sessions_audit_repo(&repo, show_ok).await
}

async fn run_sessions_inspect(query: &str, all: bool, raw: bool) -> Result<()> {
    let repos = if all {
        discovered_repos_for_sessions().await
    } else {
        vec![git::repo_root().await.map_err(|_| {
            anyhow::anyhow!(
                "not in a git repository. Use `cadence sessions inspect --all <query>`."
            )
        })?]
    };
    if repos.is_empty() {
        output::note("No repositories discovered from recent sessions.");
        return Ok(());
    }

    let query_lc = query.to_ascii_lowercase();
    let mut matches = 0usize;
    for repo in repos {
        let local_labels = build_local_session_labels_for_repo(&repo).await;
        let committer_hash = committer_key_hash_for_repo(&repo).await;
        let mut user_entries =
            list_index_entries_for_key(&repo, git::SESSION_INDEX_COMMITTER_REF, &committer_hash)
                .await?;
        user_entries.sort_by(|a, b| b.session_start.cmp(&a.session_start));
        user_entries.dedup_by(|a, b| a.session_uid == b.session_uid);

        let remote = git::resolve_push_remote_at(&repo)
            .await?
            .unwrap_or_else(|| "origin".to_string());
        let branches = repo_local_branches(&repo).await;

        for entry in user_entries {
            let envelope = load_session_envelope_for_entry(&repo, &entry).await;
            let session_id = envelope
                .as_ref()
                .map(|e| e.record.session_id.as_str())
                .unwrap_or("");
            let label = session_display_label(&repo, &entry, &local_labels).await;
            let matches_query = entry.session_uid.starts_with(query)
                || session_id.to_ascii_lowercase().contains(&query_lc)
                || label.to_ascii_lowercase().contains(&query_lc);
            if !matches_query {
                continue;
            }
            matches += 1;
            output::action("Match", &repo.to_string_lossy());
            output::detail(&format!(
                "uid={} start={} agent={} label={}",
                entry.session_uid,
                entry.session_start.unwrap_or_default(),
                entry.agent,
                label
            ));

            let mut branch_hits = Vec::new();
            for branch in &branches {
                let key_hash = note::hash_key(&format!("{remote}/{branch}"));
                let mut branch_entries =
                    list_index_entries_for_key(&repo, git::SESSION_INDEX_BRANCH_REF, &key_hash)
                        .await?;
                branch_entries.sort_by(|a, b| b.session_start.cmp(&a.session_start));
                branch_entries.dedup_by(|a, b| a.session_uid == b.session_uid);
                if branch_entries
                    .iter()
                    .any(|e| e.session_uid == entry.session_uid)
                {
                    branch_hits.push(branch.clone());
                }
            }
            output::detail(&format!("branches={:?}", branch_hits));
            if let Some(env) = envelope {
                output::detail(&format!(
                    "observed_commits={} session_id={}",
                    env.record.observed_commits.len(),
                    env.record.session_id
                ));
                if raw {
                    output::detail("raw_record:");
                    let raw_record = serde_json::to_string_pretty(&env.record)?;
                    for line in raw_record.lines() {
                        output::detail(line);
                    }
                    output::detail("raw_session_content:");
                    for line in env.session_content.lines() {
                        output::detail(line);
                    }
                }
            } else if raw {
                output::detail("raw unavailable: unable to decrypt/parse session envelope");
            }
        }
    }

    if matches == 0 {
        output::note("No matching sessions found.");
    }
    Ok(())
}

async fn run_sessions(command: Option<SessionsCommand>, all: bool) -> Result<()> {
    match command {
        None => run_sessions_list(all).await,
        Some(SessionsCommand::List { all }) => run_sessions_list(all).await,
        Some(SessionsCommand::Audit { all, show_ok }) => run_sessions_audit(all, show_ok).await,
        Some(SessionsCommand::Inspect { query, all, raw }) => {
            run_sessions_inspect(&query, all, raw).await
        }
    }
}

/// The status subcommand: show Cadence CLI configuration and state.
///
/// Displays:
/// - Current repo root (or a message if not in a git repo)
/// - Effective hooks path and whether the post-commit/pre-push shims are installed
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
                let (post_installed, pre_installed) = cadence_hooks_installed(&hooks_dir).await;
                let post_str = if post_installed { "yes" } else { "no" };
                let pre_str = if pre_installed { "yes" } else { "no" };
                output::detail_to_with_tty(
                    w,
                    &format!(
                        "Hooks path: {} (post-commit: {}, pre-push: {})",
                        path, post_str, pre_str
                    ),
                    false,
                );

                if !post_installed || !pre_installed {
                    output::note_to_with_tty(
                        w,
                        "Cadence hooks are not fully installed in the active hooksPath.",
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
        let (post_installed, pre_installed) = cadence_hooks_installed(&hooks_dir).await;
        let post_str = if post_installed { "yes" } else { "no" };
        let pre_str = if pre_installed { "yes" } else { "no" };
        output::detail_to_with_tty(
            w,
            &format!(
                "Hooks path: {} (post-commit: {}, pre-push: {})",
                path, post_str, pre_str
            ),
            false,
        );
    } else {
        output::detail_to_with_tty(w, "Hooks path: (not configured)", false);
    }

    if let Some(ref root) = repo_root {
        let has_data_ref = git::ref_exists_at(Some(root), git::SESSION_DATA_REF)
            .await
            .unwrap_or(false);
        let has_branch_ref = git::ref_exists_at(Some(root), git::SESSION_INDEX_BRANCH_REF)
            .await
            .unwrap_or(false);
        let has_committer_ref = git::ref_exists_at(Some(root), git::SESSION_INDEX_COMMITTER_REF)
            .await
            .unwrap_or(false);
        output::detail_to_with_tty(
            w,
            &format!(
                "Session refs: data={} branch-index={} committer-index={}",
                if has_data_ref { "yes" } else { "no" },
                if has_branch_ref { "yes" } else { "no" },
                if has_committer_ref { "yes" } else { "no" }
            ),
            false,
        );
    }

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

    Ok(())
}

async fn run_doctor() -> Result<()> {
    run_doctor_inner(&mut std::io::stderr()).await
}

async fn run_doctor_inner(w: &mut dyn std::io::Write) -> Result<()> {
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
            let (post_installed, pre_installed) = cadence_hooks_installed(&hooks_dir).await;
            output::detail_to_with_tty(
                w,
                &format!(
                    "Global hooks: {} (post-commit: {}, pre-push: {})",
                    path,
                    if post_installed { "yes" } else { "no" },
                    if pre_installed { "yes" } else { "no" }
                ),
                false,
            );
            if !post_installed || !pre_installed {
                output::fail_to_with_tty(
                    w,
                    "Fail",
                    "Cadence global hooks are not fully installed",
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
                let (post_installed, pre_installed) = cadence_hooks_installed(&hooks_dir).await;
                output::detail_to_with_tty(
                    w,
                    &format!(
                        "Active hooks: {} (post-commit: {}, pre-push: {})",
                        active_path,
                        if post_installed { "yes" } else { "no" },
                        if pre_installed { "yes" } else { "no" }
                    ),
                    false,
                );
                if !post_installed || !pre_installed {
                    output::fail_to_with_tty(
                        w,
                        "Fail",
                        "Active hooksPath does not contain Cadence hooks",
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

    if let Some(root) = repo_root.as_ref() {
        let has_data_ref = git::ref_exists_at(Some(root), git::SESSION_DATA_REF)
            .await
            .unwrap_or(false);
        let has_branch_ref = git::ref_exists_at(Some(root), git::SESSION_INDEX_BRANCH_REF)
            .await
            .unwrap_or(false);
        let has_committer_ref = git::ref_exists_at(Some(root), git::SESSION_INDEX_COMMITTER_REF)
            .await
            .unwrap_or(false);
        output::detail_to_with_tty(
            w,
            &format!(
                "Session refs: data={} branch-index={} committer-index={}",
                if has_data_ref { "yes" } else { "no" },
                if has_branch_ref { "yes" } else { "no" },
                if has_committer_ref { "yes" } else { "no" }
            ),
            false,
        );
    }

    if issues == 0 {
        output::success_to_with_tty(w, "Doctor", "all checks passed", false);
        Ok(())
    } else {
        output::fail_to_with_tty(w, "Doctor", &format!("{} issue(s) found", issues), false);
        anyhow::bail!("doctor found {} issue(s)", issues);
    }
}

// ---------------------------------------------------------------------------
// Keys status command
// ---------------------------------------------------------------------------

struct KeysStatusReport {
    user_fingerprint: Option<String>,
    user_fingerprint_error: Option<String>,
    user_public_key_cached: bool,
    user_private_key_cached: bool,
    api_public_key_cached: bool,
    api_metadata: Option<pgp_keys::ApiPublicKeyMetadata>,
}

impl KeysStatusReport {
    async fn collect() -> Self {
        let (user_fingerprint, user_fingerprint_error) =
            match pgp_keys::get_user_fingerprint().await {
                Ok(v) => (v, None),
                Err(e) => (None, Some(format!("{}", e))),
            };
        let user_public_key_cached = pgp_keys::load_cached_user_public_key()
            .await
            .ok()
            .flatten()
            .is_some();
        let user_private_key_cached = pgp_keys::load_cached_user_private_key()
            .await
            .ok()
            .flatten()
            .is_some();
        let api_public_key_cached = pgp_keys::load_cached_api_public_key()
            .await
            .ok()
            .flatten()
            .is_some();
        let api_metadata = pgp_keys::load_api_public_key_metadata()
            .await
            .ok()
            .flatten();

        KeysStatusReport {
            user_fingerprint,
            user_fingerprint_error,
            user_public_key_cached,
            user_private_key_cached,
            api_public_key_cached,
            api_metadata,
        }
    }

    fn summary(&self) -> &'static str {
        if self.user_fingerprint.is_none() {
            return "disabled (plaintext mode)";
        }
        if !self.user_public_key_cached || !self.api_public_key_cached {
            return "configured but keys unavailable";
        }
        "enabled (dual recipient)"
    }
}

fn render_keys_status(
    w: &mut dyn std::io::Write,
    report: &KeysStatusReport,
) -> std::io::Result<()> {
    let is_tty = Term::stdout().is_term();
    let label = |text: &str| {
        if is_tty {
            console::style(text).bold().to_string()
        } else {
            text.to_string()
        }
    };
    let value = |text: &str, color: console::Color| {
        if is_tty {
            console::style(text).fg(color).to_string()
        } else {
            text.to_string()
        }
    };

    match (&report.user_fingerprint, &report.user_fingerprint_error) {
        (Some(f), _) => writeln!(
            w,
            "{} {}",
            label("Local key fingerprint:"),
            value(f, console::Color::Cyan)
        )?,
        (None, Some(err)) => writeln!(
            w,
            "{} {}",
            label("Local key fingerprint:"),
            value(&format!("unavailable ({})", err), console::Color::Red)
        )?,
        (None, None) => writeln!(
            w,
            "{} {}",
            label("Local key fingerprint:"),
            value("not set", console::Color::Yellow)
        )?,
    }

    writeln!(
        w,
        "{} {}",
        label("Local public key cached:"),
        value(
            if report.user_public_key_cached {
                "yes"
            } else {
                "no"
            },
            if report.user_public_key_cached {
                console::Color::Green
            } else {
                console::Color::Yellow
            }
        )
    )?;

    writeln!(
        w,
        "{} {}",
        label("Local private key cached:"),
        value(
            if report.user_private_key_cached {
                "yes"
            } else {
                "no"
            },
            if report.user_private_key_cached {
                console::Color::Green
            } else {
                console::Color::Yellow
            }
        )
    )?;

    let api_cache_detail = if let Some(meta) = &report.api_metadata {
        format!("yes (fetched {})", meta.fetched_at)
    } else if report.api_public_key_cached {
        "yes".to_string()
    } else {
        "no".to_string()
    };

    writeln!(
        w,
        "{} {}",
        label("API public key cached:"),
        value(
            &api_cache_detail,
            if report.api_public_key_cached {
                console::Color::Green
            } else {
                console::Color::Yellow
            }
        )
    )?;

    let summary = report.summary();
    let summary_color = if summary.contains("enabled") {
        console::Color::Green
    } else {
        console::Color::Yellow
    };
    writeln!(
        w,
        "{} {}",
        label("Encryption:"),
        value(summary, summary_color)
    )?;

    Ok(())
}

async fn run_keys_status() -> Result<()> {
    let report = KeysStatusReport::collect().await;
    let _ = render_keys_status(&mut std::io::stdout(), &report);
    Ok(())
}

async fn run_keys_setup() -> Result<()> {
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        anyhow::bail!("cadence keys setup requires an interactive TTY. Run from a terminal.");
    }
    let mut prompter = DialoguerPrompter::new();
    run_keys_setup_inner(&mut prompter, &mut std::io::stdout(), true).await
}

async fn run_keys_refresh() -> Result<()> {
    let _ = resolve_api_public_key_cache(true).await?;
    output::success("API", "public key refreshed.");
    Ok(())
}

async fn run_keys_disable() -> Result<()> {
    let _ = git::config_unset_global(pgp_keys::USER_FINGERPRINT_KEY).await;
    let _ = git::config_unset_global(pgp_keys::API_FINGERPRINT_KEY).await;

    if let Some(path) = pgp_keys::user_public_key_cache_path() {
        let _ = tokio::fs::remove_file(path).await;
    }
    if let Some(path) = pgp_keys::user_private_key_cache_path() {
        let _ = tokio::fs::remove_file(path).await;
    }
    if let Some(path) = pgp_keys::api_public_key_cache_path() {
        let _ = tokio::fs::remove_file(path).await;
    }
    if let Some(path) = pgp_keys::api_public_key_meta_path() {
        let _ = tokio::fs::remove_file(path).await;
    }

    output::success("Encryption", "disabled.");
    Ok(())
}

/// Optional encryption setup during install. Returns `Ok(())` if setup was
/// skipped or completed, and `Err` if install should abort before backfill.
async fn run_install_encryption_setup() -> Result<()> {
    if !output::is_stderr_tty() || !Term::stdout().is_term() {
        return Ok(());
    }

    let mut stdout = std::io::stdout();
    let is_tty = Term::stdout().is_term();
    let mut prompter = DialoguerPrompter::new();

    output::action_to_with_tty(&mut stdout, "Encryption", "setup", is_tty);
    output::detail_to_with_tty(
        &mut stdout,
        "Protect attached session notes so only you and the Cadence API can read them.",
        is_tty,
    );

    let Some(enable) = prompter
        .confirm("Encrypt attached session notes? (Recommended)", &mut stdout)
        .await?
    else {
        output::note_to_with_tty(&mut stdout, "Skipping encryption setup.", is_tty);
        return Ok(());
    };

    if !enable {
        output::note_to_with_tty(
            &mut stdout,
            "Notes will be stored in plaintext. You can enable encryption later with `cadence keys setup`.",
            is_tty,
        );
        return Ok(());
    }

    if let Err(e) = run_keys_setup_inner(&mut prompter, &mut stdout, false).await {
        output::note_to_with_tty(
            &mut stdout,
            &format!("Encryption setup incomplete: {e:#}"),
            is_tty,
        );
        anyhow::bail!("encryption setup failed");
    }

    let recipient = git::config_get_global(pgp_keys::USER_FINGERPRINT_KEY)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    if recipient.trim().is_empty() {
        output::fail_to_with_tty(
            &mut stdout,
            "Encryption",
            "setup did not complete. Install will stop before backfill.",
            is_tty,
        );
        anyhow::bail!("encryption setup incomplete");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Install: auto-update preference prompt
// ---------------------------------------------------------------------------

/// Prompt the user to enable automatic updates during install.
///
/// This is non-critical: failures are logged but never abort install.
/// Skipped silently if stdin is not a TTY or auto_update is already configured.
async fn run_install_auto_update_prompt() {
    let cfg = match config::CliConfig::load().await {
        Ok(c) => c,
        Err(_) => return,
    };
    let config_path = match config::CliConfig::config_path() {
        Some(p) => p,
        None => return,
    };
    let mut prompter = DialoguerPrompter::new();
    run_install_auto_update_prompt_inner(&mut prompter, &cfg, &config_path).await;
}

/// Testable inner implementation of the auto-update prompt.
///
/// Accepts injectable prompter and config path for testing.
async fn run_install_auto_update_prompt_inner(
    prompter: &mut dyn Prompter,
    cfg: &config::CliConfig,
    config_path: &std::path::Path,
) {
    // Skip if not a TTY
    if !output::is_stderr_tty() || !Term::stdout().is_term() {
        return;
    }

    // Skip if auto_update is already set (user already made a choice)
    if cfg.auto_update.is_some() {
        return;
    }

    let mut stdout = std::io::stdout();
    let is_tty = Term::stdout().is_term();

    println!();
    output::action_to_with_tty(&mut stdout, "Auto-update", "setup", is_tty);
    output::detail_to_with_tty(
        &mut stdout,
        "Cadence can automatically install updates when available.",
        is_tty,
    );

    let response = prompter
        .confirm("Enable automatic updates?", &mut stdout)
        .await;
    match response {
        Ok(Some(enabled)) => {
            let value = if enabled { "true" } else { "false" };
            let mut cfg = cfg.clone();
            if let Err(e) = cfg.set_key(config::ConfigKey::AutoUpdate, value) {
                output::note_to_with_tty(
                    &mut stdout,
                    &format!("Could not save auto-update preference: {e}"),
                    is_tty,
                );
            } else if let Err(e) = cfg.save_to(config_path).await {
                output::note_to_with_tty(
                    &mut stdout,
                    &format!("Could not save auto-update preference: {e}"),
                    is_tty,
                );
            } else if enabled {
                output::success_to_with_tty(
                    &mut stdout,
                    "Auto-update",
                    "enabled. Change anytime with `cadence config set auto_update false`.",
                    is_tty,
                );
            } else {
                output::detail_to_with_tty(
                    &mut stdout,
                    "Auto-update disabled. Run `cadence update` to check manually.",
                    is_tty,
                );
            }
        }
        Ok(None) | Err(_) => {
            // User cancelled or error — skip silently
        }
    }
}

// ---------------------------------------------------------------------------
// Keys setup: prompter abstraction
// ---------------------------------------------------------------------------

#[async_trait]
trait Prompter {
    async fn confirm(
        &mut self,
        prompt: &str,
        writer: &mut dyn std::io::Write,
    ) -> Result<Option<bool>>;
}

struct DialoguerPrompter {}

impl DialoguerPrompter {
    fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Prompter for DialoguerPrompter {
    async fn confirm(
        &mut self,
        prompt: &str,
        _writer: &mut dyn std::io::Write,
    ) -> Result<Option<bool>> {
        let prompt = prompt.to_string();
        let result = tokio::task::spawn_blocking(move || {
            Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt(prompt)
                .interact()
        })
        .await
        .context("prompt task failed")?;
        match result {
            Ok(value) => Ok(Some(value)),
            Err(dialoguer::Error::IO(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                Ok(None)
            }
            Err(err) => Err(err.into()),
        }
    }
}

async fn required_git_value(key: &str, label: &str) -> Result<String> {
    let value = git::config_get_global(key).await?.unwrap_or_default();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("Missing git {}. Run `git config --global {}`", label, key);
    }
    Ok(trimmed.to_string())
}

fn cadence_email(email: &str) -> Result<String> {
    let trimmed = email.trim();
    let (local, domain) = trimmed
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("Invalid git email: {trimmed}"))?;
    let local = if local.contains("+cadence") {
        local.to_string()
    } else {
        format!("{local}+cadence")
    };
    Ok(format!("{local}@{domain}"))
}

fn generate_passphrase() -> String {
    use rand::TryRngCore;
    let mut bytes = [0u8; 32];
    let mut rng = rand::rngs::OsRng;
    rng.try_fill_bytes(&mut bytes)
        .expect("OS RNG unavailable while generating passphrase");
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// Keys setup: inner testable runner
// ---------------------------------------------------------------------------

/// Inner implementation of `keys setup` that accepts injectable I/O.
async fn run_keys_setup_inner(
    prompter: &mut dyn Prompter,
    writer: &mut dyn std::io::Write,
    show_intro: bool,
) -> Result<()> {
    let is_tty = Term::stdout().is_term();
    if show_intro {
        output::action_to_with_tty(writer, "Encryption", "setup", is_tty);
        output::detail_to_with_tty(
            writer,
            "Encrypt attached session notes so only you and the Cadence API can read them.",
            is_tty,
        );
        writeln!(writer)?;
    }

    let name = required_git_value("user.name", "user.name").await?;
    let email = required_git_value("user.email", "user.email").await?;
    let cadence_email = cadence_email(&email)?;
    let identity = format!("{} <{}>", name.trim(), cadence_email.trim());
    output::detail_to_with_tty(writer, &format!("Using Git identity: {identity}"), is_tty);

    let cached_public = pgp_keys::load_cached_user_public_key()
        .await
        .context("failed to read cached local public key")?;
    let cached_private = pgp_keys::load_cached_user_private_key()
        .await
        .context("failed to read cached local private key")?;

    if resolve_api_public_key_cache(true).await?.is_none() {
        anyhow::bail!("failed to fetch API public key");
    }

    let fingerprint = if let (Some(public), Some(_private)) =
        (cached_public.as_ref(), cached_private.as_ref())
    {
        output::detail_to_with_tty(writer, "Reusing cached local keypair.", is_tty);
        pgp_keys::fingerprint_from_public_key(public)?
    } else {
        let Some(store_in_keychain) = prompter
            .confirm(
                "Store encryption passphrase in OS keychain? (Recommended)",
                writer,
            )
            .await?
        else {
            anyhow::bail!("setup cancelled");
        };
        if !store_in_keychain {
            anyhow::bail!("encryption setup requires storing the passphrase in the OS keychain");
        }

        output::detail_to_with_tty(
            writer,
            "Generating a new encryption keypair (this may take a moment)...",
            is_tty,
        );

        let passphrase = generate_passphrase();
        let (armored_public_key, armored_private_key, fingerprint) =
            pgp_keys::generate_user_keypair(&identity, &passphrase)
                .context("failed to generate new keypair")?;

        let keychain = keychain::KeyringStore::new("cadence-cli");
        keychain
            .set(&fingerprint, &passphrase)
            .await
            .context("failed to store passphrase in OS keychain")?;

        pgp_keys::save_user_keys(&armored_public_key, &armored_private_key)
            .await
            .context("failed to cache local keys")?;

        fingerprint
    };

    git::config_set_global(pgp_keys::USER_FINGERPRINT_KEY, &fingerprint)
        .await
        .context("failed to save user fingerprint to git config")?;

    writeln!(writer, "Local key fingerprint: {}", fingerprint)?;
    if let Ok(Some(api_fpr)) = pgp_keys::get_api_fingerprint().await {
        writeln!(writer, "API key fingerprint: {}", api_fpr)?;
    }
    output::success_to_with_tty(writer, "Encryption", "ready.", is_tty);

    Ok(())
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
// GC: clear bloated notes and re-backfill
// ---------------------------------------------------------------------------

async fn run_gc(since: &str, confirm: bool) -> Result<()> {
    let session_refs = [
        git::SESSION_DATA_REF,
        git::SESSION_INDEX_BRANCH_REF,
        git::SESSION_INDEX_COMMITTER_REF,
    ];

    // Validate the --since value early so we fail before any destructive work.
    let since_secs = parse_since_duration(since)?;
    let since_days = since_secs / 86_400;

    let repo_root = git::repo_root().await?;

    if !confirm {
        output::note("This will DELETE all local and remote AI session refs for this repo,");
        output::note("then re-backfill them in the optimized v2 format.");
        output::detail(&format!("Re-backfill window: last {} days", since_days));
        for ref_name in &session_refs {
            output::detail(&format!("Local ref:  {}  → deleted", ref_name));
            output::detail(&format!("Remote ref: {}  → deleted", ref_name));
        }
        output::detail("Then: cadence backfill --since <window>");
        eprintln!();
        output::fail("Aborted", "pass --confirm to proceed.");
        anyhow::bail!("gc requires --confirm to proceed");
    }

    // Resolve push remote (e.g. "origin").
    let remote = git::resolve_push_remote_at(&repo_root).await?;

    // Step 1: Delete remote session refs.
    if let Some(ref remote_name) = remote {
        output::action(
            "GC",
            &format!("Deleting remote session refs on '{}'", remote_name),
        );
        for ref_name in &session_refs {
            match git::delete_remote_ref_at(Some(&repo_root), remote_name, ref_name).await {
                Ok(()) => output::detail(&format!(
                    "Remote session ref deleted (or did not exist): {ref_name}"
                )),
                Err(e) => output::detail(&format!(
                    "Could not delete remote ref (continuing): {} ({})",
                    ref_name, e
                )),
            }
        }
    } else {
        output::detail("No push remote found; skipping remote ref deletion.");
    }

    // Step 2: Delete local session refs.
    output::action("GC", "Deleting local session refs");
    for ref_name in &session_refs {
        match git::delete_local_ref_at(Some(&repo_root), ref_name).await {
            Ok(()) => output::detail(&format!(
                "Local session ref deleted (or did not exist): {ref_name}"
            )),
            Err(e) => output::detail(&format!(
                "Could not delete local ref (continuing): {} ({})",
                ref_name, e
            )),
        }
    }

    // Step 3: Re-backfill in v2 format with push enabled (scoped to this repo).
    output::action(
        "GC",
        &format!("Re-backfilling (last {} days) with push", since_days),
    );
    run_backfill_inner(since, Some(&repo_root)).await?;

    output::success("GC", "Complete. Session refs were regenerated.");
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

    let is_update_command = matches!(cli.command, Command::Update { .. });

    // Opportunistic sweep of pending sync jobs for normal CLI flows.
    if !matches!(cli.command, Command::Hook { .. }) {
        let _ = deferred_sync::run_sync_command(deferred_sync::SyncRunOptions {
            repo: None,
            remote: None,
            all_pending: true,
            background: false,
            max_items: 2,
            time_budget_ms: std::env::var("CADENCE_SYNC_LOCK_SWEEP_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(|secs| secs * 1000)
                .unwrap_or(1500),
        })
        .await;
    }

    let result = match cli.command {
        Command::Install { org } => run_install(org).await,
        Command::Hook { hook_command } => match hook_command {
            HookCommand::PostCommit => run_hook_post_commit().await,
            HookCommand::PrePush { remote, url } => run_hook_pre_push(&remote, &url).await,
            HookCommand::DeferredSync {
                repo,
                remote,
                all_pending,
                background,
                max_items,
                time_budget_ms,
            } => {
                run_sync(
                    repo,
                    remote,
                    all_pending,
                    background,
                    max_items,
                    time_budget_ms,
                )
                .await
            }
        },
        Command::Backfill { since } => run_backfill(&since).await,
        Command::Login => run_login().await,
        Command::Logout => run_logout().await,
        Command::Sessions { command, all } => run_sessions(command, all).await,
        Command::Status => run_status().await,
        Command::Config { config_command } => match config_command.unwrap_or(ConfigCommand::List) {
            ConfigCommand::Set { key, value } => run_config_set(&key, &value).await,
            ConfigCommand::Get { key } => run_config_get(&key).await,
            ConfigCommand::List => run_config_list().await,
        },
        Command::Doctor => run_doctor().await,
        Command::Update { check, yes } => run_update(check, yes).await,
        Command::Keys { keys_command } => match keys_command.unwrap_or(KeysCommands::Status) {
            KeysCommands::Setup => run_keys_setup().await,
            KeysCommands::Status => run_keys_status().await,
            KeysCommands::Disable => run_keys_disable().await,
            KeysCommands::Refresh => run_keys_refresh().await,
        },
        Command::Gc { since, confirm } => run_gc(&since, confirm).await,
    };

    // Passive background version check: run after successful command execution
    // on all non-Update commands. Failures are silently ignored.
    if result.is_ok() && !is_update_command {
        update::passive_version_check().await;
    }

    if let Err(e) = result {
        output::fail("Failed", &format!("{}", e));
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn cli_parses_keys_setup() {
        let cli = Cli::parse_from(["cadence", "keys", "setup"]);
        match cli.command {
            Command::Keys { keys_command } => {
                assert!(matches!(keys_command, Some(KeysCommands::Setup)));
            }
            _ => panic!("expected Keys command"),
        }
    }

    #[test]
    fn cli_parses_keys_status_default() {
        let cli = Cli::parse_from(["cadence", "keys"]);
        match cli.command {
            Command::Keys { keys_command } => {
                assert!(keys_command.is_none());
            }
            _ => panic!("expected Keys command"),
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

    #[test]
    fn cli_parses_keys_disable() {
        let cli = Cli::parse_from(["cadence", "keys", "disable"]);
        match cli.command {
            Command::Keys { keys_command } => {
                assert!(matches!(keys_command, Some(KeysCommands::Disable)));
            }
            _ => panic!("expected Keys command"),
        }
    }

    #[test]
    fn cli_parses_keys_refresh() {
        let cli = Cli::parse_from(["cadence", "keys", "refresh"]);
        match cli.command {
            Command::Keys { keys_command } => {
                assert!(matches!(keys_command, Some(KeysCommands::Refresh)));
            }
            _ => panic!("expected Keys command"),
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
            Command::Doctor => {}
            _ => panic!("expected Doctor command"),
        }
    }

    #[test]
    fn cli_parses_hook_deferred_sync_defaults() {
        let cli = Cli::parse_from(["cadence", "hook", "deferred-sync"]);
        match cli.command {
            Command::Hook { hook_command } => match hook_command {
                HookCommand::DeferredSync {
                    repo,
                    remote,
                    all_pending,
                    background,
                    max_items,
                    time_budget_ms,
                } => {
                    assert!(repo.is_none());
                    assert!(remote.is_none());
                    assert!(!all_pending);
                    assert!(!background);
                    assert_eq!(max_items, 4);
                    assert_eq!(time_budget_ms, 8000);
                }
                _ => panic!("expected DeferredSync hook command"),
            },
            _ => panic!("expected Hook command"),
        }
    }

    #[test]
    fn cli_parses_sessions_default() {
        let cli = Cli::parse_from(["cadence", "sessions"]);
        match cli.command {
            Command::Sessions { command, all } => {
                assert!(command.is_none());
                assert!(!all);
            }
            _ => panic!("expected Sessions command"),
        }
    }

    #[test]
    fn cli_parses_sessions_all() {
        let cli = Cli::parse_from(["cadence", "sessions", "--all"]);
        match cli.command {
            Command::Sessions { command, all } => {
                assert!(command.is_none());
                assert!(all);
            }
            _ => panic!("expected Sessions command"),
        }
    }

    #[test]
    fn cli_parses_sessions_audit() {
        let cli = Cli::parse_from(["cadence", "sessions", "audit", "--all"]);
        match cli.command {
            Command::Sessions { command, all } => {
                assert!(!all);
                assert!(matches!(
                    command,
                    Some(SessionsCommand::Audit {
                        all: true,
                        show_ok: false
                    })
                ));
            }
            _ => panic!("expected Sessions command"),
        }
    }

    #[test]
    fn cli_parses_sessions_inspect() {
        let cli = Cli::parse_from(["cadence", "sessions", "inspect", "abc123"]);
        match cli.command {
            Command::Sessions { command, all } => {
                assert!(!all);
                assert!(matches!(
                    command,
                    Some(SessionsCommand::Inspect {
                        query,
                        all: false,
                        raw: false
                    }) if query == "abc123"
                ));
            }
            _ => panic!("expected Sessions command"),
        }
    }

    #[test]
    fn cli_parses_sessions_inspect_raw() {
        let cli = Cli::parse_from(["cadence", "sessions", "inspect", "abc123", "--raw"]);
        match cli.command {
            Command::Sessions { command, all } => {
                assert!(!all);
                assert!(matches!(
                    command,
                    Some(SessionsCommand::Inspect {
                        query,
                        all: false,
                        raw: true
                    }) if query == "abc123"
                ));
            }
            _ => panic!("expected Sessions command"),
        }
    }

    #[test]
    fn cli_parses_sessions_list_subcommand() {
        let cli = Cli::parse_from(["cadence", "sessions", "list", "--all"]);
        match cli.command {
            Command::Sessions { command, all } => {
                assert!(!all);
                assert!(matches!(command, Some(SessionsCommand::List { all: true })));
            }
            _ => panic!("expected Sessions command"),
        }
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

    #[test]
    fn match_window_defaults_are_stable() {
        assert_eq!(POST_COMMIT_MATCH_WINDOW_SECS, 1_800);
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

    #[tokio::test(flavor = "multi_thread")]
    async fn ingest_session_without_commit_writes_data_and_indexes() {
        let repo = init_repo().await;
        run_git(
            repo.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:example-org/example-repo.git",
            ],
        )
        .await;

        let session_log = include_str!("../tests/fixtures/backfill/session_no_ranked.jsonl");
        let info = ingest_session_from_log(
            &scanner::AgentType::Claude,
            "aaa111",
            &repo.path().to_string_lossy(),
            None,
            session_log,
            note::Confidence::TimeWindowMatch,
            &EncryptionMethod::None,
            Some(1_707_526_800),
            None,
            None,
            Some(repo.path()),
            None,
        )
        .await
        .expect("ingest");

        assert_eq!(info.blob_sha.len(), 40);
        assert!(
            git::ref_exists_at(Some(repo.path()), git::SESSION_DATA_REF)
                .await
                .expect("data ref exists")
        );
        assert!(
            git::ref_exists_at(Some(repo.path()), git::SESSION_INDEX_BRANCH_REF)
                .await
                .expect("branch index ref exists")
        );
        assert!(
            git::ref_exists_at(Some(repo.path()), git::SESSION_INDEX_COMMITTER_REF)
                .await
                .expect("committer index ref exists")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ingest_session_with_explicit_branch_keys_indexes_each_branch() {
        let repo = init_repo().await;
        run_git(
            repo.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:example-org/example-repo.git",
            ],
        )
        .await;

        let branch_keys = vec!["origin/main".to_string(), "origin/feature/test".to_string()];
        let session_log = include_str!("../tests/fixtures/backfill/session_no_ranked.jsonl");
        let info = ingest_session_from_log(
            &scanner::AgentType::Claude,
            "multi-branch",
            &repo.path().to_string_lossy(),
            None,
            session_log,
            note::Confidence::TimeWindowMatch,
            &EncryptionMethod::None,
            Some(1_707_526_800),
            None,
            None,
            Some(repo.path()),
            Some(&branch_keys),
        )
        .await
        .expect("ingest");

        for key in branch_keys {
            let mut entries = list_index_entries_for_key(
                repo.path(),
                git::SESSION_INDEX_BRANCH_REF,
                &note::hash_key(&key),
            )
            .await
            .expect("list branch entries");
            entries.sort_by(|a, b| b.ingested_at.cmp(&a.ingested_at));
            assert!(entries.iter().any(|e| e.session_uid == info.session_uid));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ingest_session_is_stable_across_commit_hints_when_observed_commits_match() {
        let repo = init_repo().await;
        run_git(
            repo.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:example-org/example-repo.git",
            ],
        )
        .await;
        tokio::fs::write(repo.path().join("file2.txt"), "x")
            .await
            .expect("write file2");
        run_git(repo.path(), &["add", "file2.txt"]).await;
        run_git(repo.path(), &["commit", "-m", "second"]).await;

        let first = run_git(repo.path(), &["rev-list", "--max-count=1", "HEAD~1"]).await;
        let second = run_git(repo.path(), &["rev-parse", "HEAD"]).await;
        let observed = vec![first.clone(), second.clone()];
        let session_log = include_str!("../tests/fixtures/backfill/session_no_ranked.jsonl");

        let first_info = ingest_session_from_log(
            &scanner::AgentType::Claude,
            "stable-1",
            &repo.path().to_string_lossy(),
            Some(&observed),
            session_log,
            note::Confidence::ExactHashMatch,
            &EncryptionMethod::None,
            Some(1_707_526_800),
            None,
            None,
            Some(repo.path()),
            None,
        )
        .await
        .expect("first ingest");

        let second_info = ingest_session_from_log(
            &scanner::AgentType::Claude,
            "stable-1",
            &repo.path().to_string_lossy(),
            Some(&observed),
            session_log,
            note::Confidence::ExactHashMatch,
            &EncryptionMethod::None,
            Some(1_707_526_800),
            None,
            None,
            Some(repo.path()),
            None,
        )
        .await
        .expect("second ingest");

        assert_eq!(first_info.blob_sha, second_info.blob_sha);
        assert_eq!(first_info.session_uid, second_info.session_uid);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn backfill_uploads_session_when_no_candidate_commits() {
        let repo = init_repo().await;
        let session_file = repo.path().join("session-no-candidate.jsonl");
        tokio::fs::write(
            &session_file,
            r#"{"timestamp":"2001-01-01T00:00:00Z","session_id":"no-candidate","cwd":"/tmp/repo"}"#,
        )
        .await
        .expect("write session file");
        let metadata = scanner::SessionMetadata {
            session_id: Some("no-candidate".to_string()),
            cwd: Some(repo.path().to_string_lossy().to_string()),
            agent_type: Some(scanner::AgentType::Claude),
        };
        let stats = process_repo_backfill(
            "example-org/example-repo".to_string(),
            vec![SessionInfo {
                log: agents::SessionLog {
                    agent_type: scanner::AgentType::Claude,
                    source: agents::SessionSource::File(session_file),
                    updated_at: Some(0),
                    match_reasons: Vec::new(),
                },
                session_id: "no-candidate".to_string(),
                repo_root: repo.path().to_path_buf(),
                metadata,
                commit_hashes: Vec::new(),
            }],
            EncryptionMethod::None,
            None,
            backfill_log::BackfillLogger::disabled(),
        )
        .await;

        assert_eq!(stats.attached, 1);
        assert!(
            git::ref_exists_at(Some(repo.path()), git::SESSION_DATA_REF)
                .await
                .expect("data ref exists")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn backfill_uploads_session_when_explicit_commits_are_unavailable() {
        let repo = init_repo().await;
        let session_file = repo.path().join("session-missing-commit.jsonl");
        tokio::fs::write(
            &session_file,
            r#"{"timestamp":"2026-02-10T01:00:00Z","session_id":"missing-commit","cwd":"/tmp/repo"}"#,
        )
        .await
        .expect("write session file");
        let metadata = scanner::SessionMetadata {
            session_id: Some("missing-commit".to_string()),
            cwd: Some(repo.path().to_string_lossy().to_string()),
            agent_type: Some(scanner::AgentType::Claude),
        };
        let stats = process_repo_backfill(
            "example-org/example-repo".to_string(),
            vec![SessionInfo {
                log: agents::SessionLog {
                    agent_type: scanner::AgentType::Claude,
                    source: agents::SessionSource::File(session_file),
                    updated_at: Some(0),
                    match_reasons: Vec::new(),
                },
                session_id: "missing-commit".to_string(),
                repo_root: repo.path().to_path_buf(),
                metadata,
                commit_hashes: vec!["deadbeef".to_string()],
            }],
            EncryptionMethod::None,
            None,
            backfill_log::BackfillLogger::disabled(),
        )
        .await;

        assert_eq!(stats.attached, 1);
        assert!(
            git::ref_exists_at(Some(repo.path()), git::SESSION_DATA_REF)
                .await
                .expect("data ref exists")
        );
        assert!(
            git::ref_exists_at(Some(repo.path()), git::SESSION_INDEX_BRANCH_REF)
                .await
                .expect("branch index ref exists")
        );
        assert!(
            git::ref_exists_at(Some(repo.path()), git::SESSION_INDEX_COMMITTER_REF)
                .await
                .expect("committer index ref exists")
        );
    }

    #[test]
    fn jsonl_prompt_excerpt_extracts_codex_user_prompt() {
        let content = r#"{"type":"session_meta","payload":{"id":"abc"}}
{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"Show a short excerpt or a title instead of the long ID on the sessions list"}]}}"#;
        let excerpt = jsonl_prompt_excerpt(content, 72).expect("extract prompt");
        assert!(excerpt.starts_with("Show a short excerpt or a title"));
    }

    #[test]
    fn jsonl_prompt_excerpt_extracts_payload_title() {
        let content =
            r#"{"type":"event","payload":{"title":"Fix session list labels for codex logs"}}"#;
        let excerpt = jsonl_prompt_excerpt(content, 72).expect("extract title");
        assert_eq!(excerpt, "Fix session list labels for codex logs");
    }

    #[test]
    fn jsonl_prompt_excerpt_extracts_warp_input_prompt() {
        let content = r#"{"type":"warp_ai_query","input":{"prompt":"Summarize the warp query format for Cadence"}}"#;
        let excerpt = jsonl_prompt_excerpt(content, 72).expect("extract prompt");
        assert!(excerpt.starts_with("Summarize the warp query format"));
    }

    #[test]
    fn jsonl_prompt_excerpt_prefers_normalized_user_turn() {
        let content = r#"{"type":"user","content":"Review the Warp output and summarize tool calls"}
{"type":"warp_ai_query","input":{"prompt":"fallback prompt"}}"#;
        let excerpt = jsonl_prompt_excerpt(content, 72).expect("extract prompt");
        assert!(excerpt.starts_with("Review the Warp output"));
    }
}
async fn run_sync(
    repo: Option<PathBuf>,
    remote: Option<String>,
    all_pending: bool,
    background: bool,
    max_items: usize,
    time_budget_ms: u64,
) -> Result<()> {
    deferred_sync::run_sync_command(deferred_sync::SyncRunOptions {
        repo,
        remote,
        all_pending,
        background,
        max_items,
        time_budget_ms,
    })
    .await
}
