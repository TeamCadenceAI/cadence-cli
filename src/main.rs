mod agents;
mod api_client;
mod config;
mod git;
mod keychain;
mod note;
mod output;
mod pending;
mod pgp_keys;
mod push;
mod scanner;
mod update;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use console::Term;
use dialoguer::{Confirm, theme::ColorfulTheme};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process;

use crate::keychain::KeychainStore;

/// Cadence CLI: attach AI coding agent session logs to Git commits via git notes.
///
/// Provides provenance and measurement of AI-assisted development
/// without polluting commit history.
#[derive(Parser, Debug)]
#[command(name = "cadence", version, about)]
struct Cli {
    /// Enable verbose logging (e.g., git commands and output).
    #[arg(long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Install Cadence CLI: set up git hooks and run initial hydration.
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

    /// Backfill AI session notes for recent commits.
    Hydrate {
        /// How far back to scan, e.g. "7d" for 7 days.
        #[arg(long, default_value = "7d")]
        since: String,

        /// Push notes to remote after hydration.
        #[arg(long)]
        push: bool,
    },

    /// Retry attaching notes for pending (unresolved) commits.
    Retry,

    /// Show Cadence CLI status for the current repository.
    /// Inspect linked git notes.
    Notes {
        #[command(subcommand)]
        notes_command: NotesCommand,
    },

    /// Show Cadence CLI status for the current repository.
    Status,

    /// Diagnose hook and notes-rewrite configuration issues.
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

    /// Manage encryption for local + API recipients.
    Keys {
        #[command(subcommand)]
        keys_command: Option<KeysCommands>,
    },

    /// Clear bloated notes and re-hydrate in the optimized v2 format.
    ///
    /// Deletes the local and remote notes refs, then re-runs hydration
    /// to regenerate notes with payload deduplication and compression.
    Gc {
        /// How far back to re-hydrate, e.g. "30d" for 30 days.
        #[arg(long, default_value = "30d")]
        since: String,

        /// Confirm destructive operation (required).
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Subcommand, Debug)]
enum NotesCommand {
    /// List commits and mark ones that have AI session notes.
    List {
        /// Git notes ref to inspect.
        #[arg(long, default_value = "refs/notes/ai-sessions")]
        notes_ref: String,
    },
}

#[derive(Subcommand, Debug)]
enum HookCommand {
    /// Post-commit hook: attempt to attach AI session note to HEAD.
    PostCommit,
    /// Pre-push hook: sync notes with the push remote.
    PrePush {
        /// Remote name provided by git.
        remote: String,
        /// Remote URL provided by git.
        url: String,
    },
    /// Background retry with exponential backoff (hidden, internal use only).
    #[command(hide = true)]
    PostCommitRetry {
        /// Full commit hash to resolve.
        commit: String,
        /// Absolute path to the repository root.
        repo: String,
        /// Unix epoch timestamp of the commit.
        timestamp: i64,
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
fn resolve_encryption_method() -> Result<EncryptionMethod> {
    let Some(user_fingerprint) = pgp_keys::get_user_fingerprint()? else {
        return Ok(EncryptionMethod::None);
    };

    let user_key = match pgp_keys::load_cached_user_public_key() {
        Ok(Some(key)) => Some(key),
        Ok(None) => None,
        Err(e) => {
            return Ok(EncryptionMethod::Unavailable(format!(
                "failed to read cached local key: {e}"
            )));
        }
    };

    let api_key = match resolve_api_public_key_cache(false) {
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

/// Encode a session log payload: compress with zstd, optionally encrypt
/// (binary, not armored), store as a git blob in a specific repository.
///
/// Returns `(blob_sha, payload_sha256, encoding)`.
fn encode_and_store_payload_at(
    repo: Option<&std::path::Path>,
    session_log: &str,
    method: &EncryptionMethod,
) -> Result<(String, String, note::PayloadEncoding)> {
    let payload_sha256 = note::payload_sha256(session_log);

    // Step 1: Compress with zstd
    let compressed =
        note::compress_payload(session_log.as_bytes()).context("payload compression failed")?;

    // Step 2: Optionally encrypt (binary, not armored)
    let (encoded, encoding) = match method {
        EncryptionMethod::RpgpMulti { user_key, api_key } => {
            let encrypted = pgp_keys::encrypt_to_public_keys_binary(
                &compressed,
                &[user_key.clone(), api_key.clone()],
            )
            .context("payload encryption failed")?;
            (encrypted, note::PayloadEncoding::ZstdPgp)
        }
        EncryptionMethod::Unavailable(reason) => {
            anyhow::bail!("encryption unavailable: {}", reason);
        }
        EncryptionMethod::None => (compressed, note::PayloadEncoding::Zstd),
    };

    // Step 3: Store as a git blob
    let blob_sha = git::store_blob_at(repo, &encoded).context("failed to store payload blob")?;

    Ok((blob_sha, payload_sha256, encoding))
}

const API_PUBLIC_KEY_MAX_AGE_DAYS: i64 = 7;

fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Resolve the cached API public key, refreshing if needed.
fn resolve_api_public_key_cache(force_refresh: bool) -> Result<Option<String>> {
    let cached_key = pgp_keys::load_cached_api_public_key().unwrap_or(None);
    let metadata = pgp_keys::load_api_public_key_metadata().unwrap_or(None);

    let stale = metadata
        .as_ref()
        .map(|m| pgp_keys::api_public_key_cache_stale(m, API_PUBLIC_KEY_MAX_AGE_DAYS))
        .unwrap_or(true);

    if !force_refresh && !stale && cached_key.is_some() {
        return Ok(cached_key);
    }

    let cfg = config::CliConfig::load()?;
    let resolved = cfg.resolve_api_url(None);
    let client = api_client::ApiClient::new(&resolved.url);
    let keys_url = format!("{}/api/keys/public", resolved.url.trim_end_matches('/'));
    let api_key = client
        .get_api_public_key()
        .with_context(|| format!("failed to fetch API public key from {keys_url}"))?;

    let meta = pgp_keys::ApiPublicKeyMetadata {
        fingerprint: api_key.fingerprint.clone(),
        fetched_at: now_rfc3339(),
        created_at: api_key.created_at.clone(),
        rotated_at: api_key.rotated_at.clone(),
        version: api_key.version.clone(),
    };
    pgp_keys::save_api_public_key_cache(&api_key.armored_public_key, &meta)?;

    if let Err(e) = git::config_set_global(pgp_keys::API_FINGERPRINT_KEY, &api_key.fingerprint) {
        output::note(&format!(
            "Could not save API fingerprint to git config: {e}"
        ));
    }

    Ok(Some(api_key.armored_public_key))
}

// ---------------------------------------------------------------------------
// Subcommand dispatch
// ---------------------------------------------------------------------------

/// The install subcommand: set up global git hooks and run initial hydration.
///
/// Steps:
/// 1. Set `git config --global core.hooksPath ~/.git-hooks`
/// 2. Configure git-notes rewrite safety for rebase/amend
/// 3. Create `~/.git-hooks/` directory if missing
/// 4. Write `~/.git-hooks/post-commit` shim script
/// 5. Write `~/.git-hooks/pre-push` shim script
/// 6. Make shims executable (chmod +x)
/// 7. If `--org` provided, persist org filter to global git config
/// 8. Run hydration for the last 30 days
///
/// Errors at each step are reported but do not prevent subsequent steps
/// from being attempted.
fn run_install(org: Option<String>) -> Result<()> {
    run_install_inner(org, None)
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

fn config_bool_or_default(value: Option<&str>, default: bool) -> bool {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("true" | "yes" | "on" | "1") => true,
        Some("false" | "no" | "off" | "0") => false,
        Some(_) => default,
        None => default,
    }
}

fn notes_rewrite_ref_present(refs: &[String], target: &str) -> bool {
    refs.iter().any(|value| value.trim() == target)
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

fn cadence_hooks_installed(hooks_dir: &Path) -> (bool, bool) {
    let post_path = hooks_dir.join("post-commit");
    let post_installed = match std::fs::read_to_string(&post_path) {
        Ok(content) => is_cadence_hook(&content),
        Err(_) => false,
    };

    let pre_path = hooks_dir.join("pre-push");
    let pre_installed = match std::fs::read_to_string(&pre_path) {
        Ok(content) => is_cadence_hook(&content),
        Err(_) => false,
    };

    (post_installed, pre_installed)
}

fn ensure_notes_rewrite_config() -> Result<()> {
    git::config_set_global("notes.rewrite.rebase", "true")
        .context("failed to set notes.rewrite.rebase=true")?;
    git::config_set_global("notes.rewrite.amend", "true")
        .context("failed to set notes.rewrite.amend=true")?;

    let refs = git::config_get_global_all("notes.rewriteRef")
        .context("failed to inspect notes.rewriteRef")?;
    if !notes_rewrite_ref_present(&refs, git::NOTES_REF) {
        git::config_add_global("notes.rewriteRef", git::NOTES_REF)
            .context("failed to add Cadence notes rewrite ref")?;
    }

    Ok(())
}

/// Inner implementation of install, accepting an optional home directory override
/// for testability. If `home_override` is `None`, uses the real home directory.
fn run_install_inner(org: Option<String>, home_override: Option<&std::path::Path>) -> Result<()> {
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
    match git::config_set_global("core.hooksPath", &hooks_dir_str) {
        Ok(()) => {
            output::success("Updated", &format!("core.hooksPath = {}", hooks_dir_str));
        }
        Err(e) => {
            output::fail("Failed", &format!("to set core.hooksPath ({})", e));
            had_errors = true;
        }
    }

    // Step 1.5: Ensure notes survive commit rewrites (rebase/amend).
    match ensure_notes_rewrite_config() {
        Ok(()) => {
            output::success(
                "Updated",
                &format!("notes rewrite configured for {}", git::NOTES_REF),
            );
        }
        Err(e) => {
            output::fail("Failed", &format!("to configure notes rewrite ({})", e));
            had_errors = true;
        }
    }

    // Step 2: Create ~/.git-hooks/ directory if missing
    if !hooks_dir.exists() {
        match std::fs::create_dir_all(&hooks_dir) {
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
    let should_write = if shim_path.exists() {
        match std::fs::read_to_string(&shim_path) {
            Ok(existing) => {
                if is_cadence_hook(&existing) {
                    output::detail("Post-commit hook already installed; updating");
                    true
                } else {
                    // Back up the existing hook before overwriting
                    let backup_path = hooks_dir.join("post-commit.pre-cadence");
                    match std::fs::copy(&shim_path, &backup_path) {
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
        match std::fs::write(&shim_path, shim_content) {
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
                    match std::fs::set_permissions(&shim_path, perms) {
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

    let should_write_pre_push = if pre_push_path.exists() {
        match std::fs::read_to_string(&pre_push_path) {
            Ok(existing) => {
                if is_cadence_hook(&existing) {
                    output::detail("Pre-push hook already installed; updating");
                    true
                } else {
                    let backup_path = hooks_dir.join("pre-push.pre-cadence");
                    match std::fs::copy(&pre_push_path, &backup_path) {
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
        match std::fs::write(&pre_push_path, pre_push_content) {
            Ok(()) => {
                output::success(
                    "Wrote",
                    &format!("pre-push hook ({})", pre_push_path.display()),
                );

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o755);
                    match std::fs::set_permissions(&pre_push_path, perms) {
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
        match git::config_set_global("ai.cadence.org", org_value) {
            Ok(()) => {
                output::success("Updated", &format!("org filter = {}", org_value));
            }
            Err(e) => {
                output::fail("Failed", &format!("to set org filter ({})", e));
                had_errors = true;
            }
        }
    }

    // Step 5.5: Optional encryption setup (before hydration)
    if let Err(e) = run_install_encryption_setup() {
        output::fail("Install", &format!("stopped ({})", e));
        return Err(e);
    }

    // Step 6: Run hydration for the last 7 days
    output::action("Hydrating", "recent sessions (last 30 days)");
    let hydrate_start = std::time::Instant::now();
    if let Err(e) = run_hydrate("30d", true) {
        output::fail("Hydration", &format!("stopped ({})", e));
        had_errors = true;
    }
    output::success(
        "Hydration",
        &format!("done in {} ms", hydrate_start.elapsed().as_millis()),
    );

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
fn run_hook_post_commit() -> Result<()> {
    // Catch-all: catch panics
    let result = std::panic::catch_unwind(|| -> std::result::Result<(), HookError> {
        hook_post_commit_inner()
    });

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
        Err(_) => {
            output::note("Hook panicked (please report this issue)");
            Ok(())
        }
    };

    eprintln!();
    final_result
}

/// The pre-push hook handler. Must never block the push.
fn run_hook_pre_push(remote: &str, url: &str) -> Result<()> {
    let remote = remote.to_string();
    let url = url.to_string();
    let result = std::panic::catch_unwind(|| -> Result<()> { hook_pre_push_inner(&remote, &url) });

    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            output::note(&format!("Hook issue: {}", e));
        }
        Err(_) => {
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
fn hook_post_commit_inner() -> std::result::Result<(), HookError> {
    // Step 0: Per-repo enabled check — if disabled, skip EVERYTHING
    if !git::check_enabled() {
        return Ok(());
    }

    // Step 1: Get repo root, HEAD hash, HEAD timestamp
    let repo_root = git::repo_root()?;
    let head_hash = git::head_hash()?;
    let head_timestamp = git::head_timestamp()?;
    let repo_root_str = repo_root.to_string_lossy().to_string();

    // Step 1.25: Org filter gating — skip all attachment if mismatched
    match git::repo_matches_org_filter(&repo_root) {
        Ok(true) => {}
        Ok(false) => return Ok(()),
        Err(e) => return Err(HookError::Soft(e)),
    }

    // Step 1.5: Resolve encryption method once for this invocation
    let encryption_method = resolve_encryption_method().map_err(|e| {
        // Config read failure is a soft error — don't block commit
        HookError::Soft(e)
    })?;

    // Step 2: Deduplication — if note already exists, exit early
    if git::note_exists(&head_hash)? {
        // Note already attached (e.g., by hydrate). Clean up stale pending record.
        let _ = pending::remove(&head_hash);
        return Ok(());
    }

    // Step 3: Collect candidate files across all agents
    let candidate_files = agents::all_candidate_files(&repo_root, head_timestamp, 600);

    // Step 5: Run scanner to find session match
    let session_match = scanner::find_session_for_commit(&head_hash, &candidate_files);

    let mut attached = false;
    if let Some(ref matched) = session_match {
        // Step 6a: Parse metadata and verify match
        let metadata = scanner::parse_session_metadata(&matched.file_path);

        if scanner::verify_match(&metadata, &repo_root, &head_hash) {
            // Read the full session log. If the read fails (permissions,
            // file deleted between match and read, etc.), fall through to
            // the pending path so it can be retried later.
            //
            // Note: `read_to_string` loads the entire file into memory.
            // This is acceptable because session logs are typically small
            // (tens of KB to a few MB).
            let session_log = match std::fs::read_to_string(&matched.file_path) {
                Ok(content) => content,
                Err(e) => {
                    output::note(&format!("Could not read session log ({})", e));
                    if let Err(e) =
                        pending::write_pending(&head_hash, &repo_root_str, head_timestamp)
                    {
                        output::note(&format!("Could not write pending record ({})", e));
                    }
                    spawn_background_retry(&head_hash, &repo_root_str, head_timestamp);
                    // Skip note attachment; retry will pick this up later
                    return Ok(());
                }
            };

            let session_id = metadata.session_id.as_deref().unwrap_or("unknown");
            let session_start =
                scanner::session_time_range(&matched.file_path).map(|(start, _)| start);

            // Attach the note (encryption failure blocks the commit when configured)
            attach_note_from_log(
                &matched.agent_type,
                session_id,
                &repo_root_str,
                &head_hash,
                &session_log,
                note::Confidence::ExactHashMatch,
                &encryption_method,
                session_start,
            )
            .map_err(|e| {
                if encryption_method.is_configured() {
                    HookError::EncryptionFailed(format!("{:#}", e))
                } else {
                    HookError::Soft(e)
                }
            })?;

            log_attached_session(&matched.agent_type, session_id, &head_hash, false);

            attached = true;
        }
    }

    if !attached {
        // Step 6b: No exact match found — attempt time-based fallback
        if let Some(fallback) =
            fallback_match_for_commit(head_timestamp, &repo_root, &candidate_files, 600)
        {
            let session_log = match std::fs::read_to_string(&fallback.file_path) {
                Ok(content) => content,
                Err(e) => {
                    output::note(&format!("Could not read session log ({})", e));
                    if let Err(e) =
                        pending::write_pending(&head_hash, &repo_root_str, head_timestamp)
                    {
                        output::note(&format!("Could not write pending record ({})", e));
                    }
                    spawn_background_retry(&head_hash, &repo_root_str, head_timestamp);
                    return Ok(());
                }
            };

            let session_start =
                scanner::session_time_range(&fallback.file_path).map(|(start, _)| start);

            attach_note_from_log(
                &fallback.agent_type,
                &fallback.session_id,
                &repo_root_str,
                &head_hash,
                &session_log,
                note::Confidence::TimeWindowMatch,
                &encryption_method,
                session_start,
            )
            .map_err(|e| {
                if encryption_method.is_configured() {
                    HookError::EncryptionFailed(format!("{:#}", e))
                } else {
                    HookError::Soft(e)
                }
            })?;

            log_attached_session(&fallback.agent_type, &fallback.session_id, &head_hash, true);

            attached = true;
        }
    }

    if !attached {
        // No match found — write pending record
        if let Err(e) = pending::write_pending(&head_hash, &repo_root_str, head_timestamp) {
            output::note(&format!("Could not write pending record ({})", e));
        }
        spawn_background_retry(&head_hash, &repo_root_str, head_timestamp);
    }

    // Step 7: Retry pending commits for this repo (uses same encryption method)
    retry_pending_for_repo(&repo_root_str, &repo_root, &encryption_method);

    Ok(())
}

/// Inner implementation of the pre-push hook.
fn hook_pre_push_inner(remote: &str, _url: &str) -> Result<()> {
    if !git::check_enabled() {
        return Ok(());
    }

    if push::should_push_remote(remote) {
        let sync_start = std::time::Instant::now();
        push::sync_notes_for_remote(remote);
        if output::is_verbose() {
            output::detail(&format!(
                "Pre-push sync in {} ms",
                sync_start.elapsed().as_millis()
            ));
        }
    }

    Ok(())
}

fn agent_display_name(agent: &scanner::AgentType) -> &'static str {
    match agent {
        scanner::AgentType::Claude => "Claude Code",
        scanner::AgentType::Codex => "Codex",
        scanner::AgentType::Cursor => "Cursor",
        scanner::AgentType::Copilot => "GitHub Copilot",
        scanner::AgentType::Antigravity => "Antigravity",
    }
}

fn log_attached_session(
    agent: &scanner::AgentType,
    session_id: &str,
    commit_hash: &str,
    is_fallback: bool,
) {
    let mut message = format!(
        "Attached {} session {} to commit {}",
        agent_display_name(agent),
        session_id,
        &commit_hash[..7]
    );
    if is_fallback {
        message.push_str(" (time window match)");
    }
    output::success("[Cadence]", &message);
}

/// Maximum number of retry attempts before a pending record is abandoned.
///
/// After this many attempts, the pending record is removed and a note
/// is logged. This prevents unbounded retries for commits that can never
/// be resolved (e.g., the session log was deleted or the commit was from
/// a different machine).
const MAX_RETRY_ATTEMPTS: u32 = 20;

/// Backoff schedule for background retry (in seconds).
/// Total wait: 1 + 2 + 4 + 8 + 16 + 32 = 63 seconds.
const BACKGROUND_RETRY_DELAYS: &[u64] = &[1, 2, 4, 8, 16, 32];

/// If two fallback candidates are within this many seconds, treat as ambiguous.
const FALLBACK_AMBIGUITY_MARGIN_SECS: i64 = 120;

/// Expand session time ranges by this many seconds when matching commits.
const FALLBACK_RANGE_BUFFER_SECS: i64 = 300;

struct FallbackMatch {
    file_path: std::path::PathBuf,
    agent_type: scanner::AgentType,
    session_id: String,
}

fn file_mtime_epoch(path: &std::path::Path) -> Option<i64> {
    let metadata = std::fs::metadata(path).ok()?;
    let mtime = metadata.modified().ok()?;
    let mtime_epoch = mtime.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64;
    Some(mtime_epoch)
}

fn metadata_repo_matches(metadata: &scanner::SessionMetadata, repo_root: &std::path::Path) -> bool {
    let cwd = match &metadata.cwd {
        Some(c) => c,
        None => return false,
    };
    let cwd_path = std::path::Path::new(cwd);
    match git::repo_root_at(cwd_path) {
        Ok(cwd_repo_root) => {
            let canonical_repo = repo_root
                .canonicalize()
                .unwrap_or_else(|_| repo_root.to_path_buf());
            let canonical_cwd_repo = cwd_repo_root.canonicalize().unwrap_or(cwd_repo_root);
            canonical_repo == canonical_cwd_repo
        }
        Err(_) => false,
    }
}

fn fallback_match_for_commit(
    commit_time: i64,
    repo_root: &std::path::Path,
    candidate_files: &[std::path::PathBuf],
    time_window: i64,
) -> Option<FallbackMatch> {
    let mut candidates: Vec<(i64, std::path::PathBuf, scanner::SessionMetadata)> = Vec::new();

    for file_path in candidate_files {
        let metadata = scanner::parse_session_metadata(file_path);
        if !metadata_repo_matches(&metadata, repo_root) {
            continue;
        }

        let distance = if let Some((start_ts, end_ts)) = scanner::session_time_range(file_path) {
            let start = start_ts - FALLBACK_RANGE_BUFFER_SECS;
            let end = end_ts + FALLBACK_RANGE_BUFFER_SECS;
            if commit_time >= start && commit_time <= end {
                0
            } else {
                let d1 = (commit_time - start_ts).abs();
                let d2 = (commit_time - end_ts).abs();
                d1.min(d2)
            }
        } else {
            let mtime = match file_mtime_epoch(file_path) {
                Some(t) => t,
                None => continue,
            };
            (commit_time - mtime).abs()
        };

        if distance <= time_window {
            candidates.push((distance, file_path.clone(), metadata));
        }
    }

    if candidates.is_empty() {
        return None;
    }

    candidates.sort_by_key(|(distance, _, _)| *distance);
    if candidates.len() >= 2 {
        let diff = (candidates[1].0 - candidates[0].0).abs();
        if diff <= FALLBACK_AMBIGUITY_MARGIN_SECS {
            return None;
        }
    }

    let (_, file_path, metadata) = candidates.remove(0);
    let agent_type = metadata
        .agent_type
        .clone()
        .unwrap_or(scanner::AgentType::Claude);
    let session_id = metadata
        .session_id
        .as_deref()
        .unwrap_or("unknown")
        .to_string();

    Some(FallbackMatch {
        file_path,
        agent_type,
        session_id,
    })
}

/// Pre-computed payload blob info for deduplication across commits.
///
/// When a session produces multiple commits, the payload is stored once and
/// the same `PayloadInfo` is reused for each pointer note.
struct PayloadInfo {
    blob_sha: String,
    payload_sha256: String,
    encoding: note::PayloadEncoding,
}

#[allow(clippy::too_many_arguments)]
fn attach_note_from_log(
    agent_type: &scanner::AgentType,
    session_id: &str,
    repo_str: &str,
    commit: &str,
    session_log: &str,
    confidence: note::Confidence,
    method: &EncryptionMethod,
    session_start: Option<i64>,
) -> Result<()> {
    attach_note_from_log_v2(
        agent_type,
        session_id,
        repo_str,
        commit,
        session_log,
        confidence,
        method,
        session_start,
        None, // no pre-stored payload — will store a new blob
        None, // use CWD repo
    )
}

/// V2 attach: stores payload as a separate blob, attaches a lightweight pointer note.
///
/// If `existing_payload` is provided, reuses the already-stored blob (dedup).
/// If `repo` is provided, operates in that repo instead of CWD.
#[allow(clippy::too_many_arguments)]
fn attach_note_from_log_v2(
    agent_type: &scanner::AgentType,
    session_id: &str,
    repo_str: &str,
    commit: &str,
    session_log: &str,
    confidence: note::Confidence,
    method: &EncryptionMethod,
    session_start: Option<i64>,
    existing_payload: Option<&PayloadInfo>,
    repo: Option<&std::path::Path>,
) -> Result<()> {
    // Reuse existing payload blob or create a new one
    let (blob_sha, payload_sha256, encoding) = match existing_payload {
        Some(info) => (
            info.blob_sha.clone(),
            info.payload_sha256.clone(),
            info.encoding,
        ),
        None => encode_and_store_payload_at(repo, session_log, method)?,
    };

    // Build the v2 pointer note
    let note_content = note::format_v2(
        agent_type,
        session_id,
        repo_str,
        commit,
        confidence,
        session_start,
        &blob_sha,
        &payload_sha256,
        encoding,
    )?;

    // Pointer note stays plaintext — only the payload blob is encrypted.
    // This lets the API index metadata without needing decryption keys.
    match repo {
        Some(r) => git::add_note_at(r, commit, &note_content)?,
        None => git::add_note(commit, &note_content)?,
    }
    Ok(())
}

/// Spawn a detached background process that retries resolving a commit
/// with exponential backoff over ~1 minute.
///
/// Uses `spawn()` (non-blocking) — parent returns immediately, child is
/// reparented to init/launchd when parent exits. stdio is null so the
/// child has no terminal association.
///
/// Failures to spawn are silently ignored — the pending system handles
/// long-term retry as a fallback.
fn spawn_background_retry(commit: &str, repo: &str, timestamp: i64) {
    // Never spawn background processes during tests — they outlive the test
    // and cascade into thousands of orphaned processes.
    if cfg!(test) {
        return;
    }
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return,
    };
    let _ = std::process::Command::new(&exe)
        .args([
            "hook",
            "post-commit-retry",
            commit,
            repo,
            &timestamp.to_string(),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Background retry handler: retries resolving a single commit with
/// exponential backoff.
///
/// This runs as a detached background process spawned by `spawn_background_retry`.
/// It sleeps between attempts and exits silently on success, exhaustion, or error.
/// The pending system handles long-term retry if this process fails.
fn run_hook_post_commit_retry(commit: &str, repo: &str, timestamp: i64) -> Result<()> {
    let repo_root = std::path::Path::new(repo);

    // Resolve encryption method once for this retry process
    let encryption_method = match resolve_encryption_method() {
        Ok(method) => method,
        Err(e) => EncryptionMethod::Unavailable(format!("{e}")),
    };

    for delay in BACKGROUND_RETRY_DELAYS {
        std::thread::sleep(std::time::Duration::from_secs(*delay));

        match try_resolve_single_commit(commit, repo, repo_root, timestamp, 600, &encryption_method)
        {
            ResolveResult::Attached => {
                let _ = pending::remove(commit);
                return Ok(());
            }
            ResolveResult::AlreadyExists => {
                let _ = pending::remove(commit);
                return Ok(());
            }
            ResolveResult::NotFound | ResolveResult::TransientError => {
                // Continue to next backoff step
            }
        }
    }

    // Exhausted all retries — exit silently. The pending system handles
    // long-term retry on the next commit.
    Ok(())
}

/// Result of attempting to resolve a single pending commit.
enum ResolveResult {
    /// Note was successfully attached.
    Attached,
    /// Note already existed (resolved by another mechanism).
    AlreadyExists,
    /// No session match found.
    NotFound,
    /// A transient error occurred (file unreadable, format error, git error).
    TransientError,
}

/// Try to resolve a single commit by scanning session logs and attaching a note.
///
/// This is the shared resolution logic used by both `retry_pending_for_repo`
/// (synchronous retry on next commit) and `run_hook_post_commit_retry`
/// (background retry with exponential backoff).
///
/// The `time_window` parameter controls how wide the candidate file mtime
/// window is (in seconds). The initial hook uses 600s (±10 min), retries
/// use 86400s (±24 hours).
///
/// The `method` parameter controls optional encryption. In the retry
/// path, encryption failure is treated as a transient error (not commit-blocking).
fn try_resolve_single_commit(
    commit: &str,
    repo_str: &str,
    repo_root: &std::path::Path,
    commit_time: i64,
    time_window: i64,
    method: &EncryptionMethod,
) -> ResolveResult {
    // Check if note already exists
    match git::note_exists(commit) {
        Ok(true) => return ResolveResult::AlreadyExists,
        Ok(false) => {}
        Err(_) => return ResolveResult::TransientError,
    }

    // Collect candidate files across all agents
    let candidate_files = agents::all_candidate_files(repo_root, commit_time, time_window);

    let session_match = scanner::find_session_for_commit(commit, &candidate_files);

    let matched = match session_match {
        Some(m) => m,
        None => {
            if let Some(fallback) =
                fallback_match_for_commit(commit_time, repo_root, &candidate_files, time_window)
            {
                let session_log = match std::fs::read_to_string(&fallback.file_path) {
                    Ok(content) => content,
                    Err(_) => return ResolveResult::TransientError,
                };

                let session_start =
                    scanner::session_time_range(&fallback.file_path).map(|(start, _)| start);

                if attach_note_from_log(
                    &fallback.agent_type,
                    &fallback.session_id,
                    repo_str,
                    commit,
                    &session_log,
                    note::Confidence::TimeWindowMatch,
                    method,
                    session_start,
                )
                .is_ok()
                {
                    output::success(
                        "Retry",
                        &format!(
                            "attached session {} to commit {} (time window match)",
                            fallback.session_id,
                            &commit[..std::cmp::min(7, commit.len())]
                        ),
                    );

                    return ResolveResult::Attached;
                }
                return ResolveResult::TransientError;
            }

            return ResolveResult::NotFound;
        }
    };

    let metadata = scanner::parse_session_metadata(&matched.file_path);

    if !scanner::verify_match(&metadata, repo_root, commit) {
        if let Some(fallback) =
            fallback_match_for_commit(commit_time, repo_root, &candidate_files, time_window)
        {
            let session_log = match std::fs::read_to_string(&fallback.file_path) {
                Ok(content) => content,
                Err(_) => return ResolveResult::TransientError,
            };

            let session_start =
                scanner::session_time_range(&fallback.file_path).map(|(start, _)| start);

            if attach_note_from_log(
                &fallback.agent_type,
                &fallback.session_id,
                repo_str,
                commit,
                &session_log,
                note::Confidence::TimeWindowMatch,
                method,
                session_start,
            )
            .is_ok()
            {
                output::success(
                    "Retry",
                    &format!(
                        "attached session {} to commit {} (time window match)",
                        fallback.session_id,
                        &commit[..std::cmp::min(7, commit.len())]
                    ),
                );

                return ResolveResult::Attached;
            }
            return ResolveResult::TransientError;
        }

        return ResolveResult::NotFound;
    }

    let session_log = match std::fs::read_to_string(&matched.file_path) {
        Ok(content) => content,
        Err(_) => return ResolveResult::TransientError,
    };

    let session_id = metadata.session_id.as_deref().unwrap_or("unknown");
    let session_start = scanner::session_time_range(&matched.file_path).map(|(start, _)| start);

    if attach_note_from_log(
        &matched.agent_type,
        session_id,
        repo_str,
        commit,
        &session_log,
        note::Confidence::ExactHashMatch,
        method,
        session_start,
    )
    .is_ok()
    {
        output::success(
            "Retry",
            &format!(
                "attached session {} to commit {}",
                session_id,
                &commit[..std::cmp::min(7, commit.len())]
            ),
        );

        ResolveResult::Attached
    } else {
        ResolveResult::TransientError
    }
}

/// Attempt to resolve pending commits for the given repository.
///
/// This is a best-effort operation. Any errors during retry are logged
/// and silently ignored. For each pending record:
/// - If note already exists: remove the pending record (success).
/// - If max attempts exceeded: remove the pending record (abandoned).
/// - If session match is found and verified: attach note, remove pending record.
/// - Otherwise: increment the attempt counter and leave for next time.
///
/// Pending retries use a much wider time window than the initial hook
/// (24 hours instead of 10 minutes) because the commit could be old and
/// the session log file may have been modified since the commit was created.
///
/// The `method` parameter controls optional encryption. Encryption
/// failures in the retry path are treated as transient errors.
fn retry_pending_for_repo(repo_str: &str, repo_root: &std::path::Path, method: &EncryptionMethod) {
    match git::repo_matches_org_filter(repo_root) {
        Ok(true) => {}
        Ok(false) => return,
        Err(e) => {
            output::note(&format!("Org filter check failed: {}", e));
            return;
        }
    }

    let mut pending_records = match pending::list_for_repo(repo_str) {
        Ok(records) => records,
        Err(_) => return,
    };

    for record in &mut pending_records {
        // Check if max retry attempts exceeded -- abandon the record
        if record.attempts >= MAX_RETRY_ATTEMPTS {
            output::note(&format!(
                "Abandoning pending commit {} after {} attempts",
                &record.commit[..std::cmp::min(7, record.commit.len())],
                record.attempts
            ));
            let _ = pending::remove(&record.commit);
            continue;
        }

        match try_resolve_single_commit(
            &record.commit,
            repo_str,
            repo_root,
            record.commit_time,
            86_400,
            method,
        ) {
            ResolveResult::Attached | ResolveResult::AlreadyExists => {
                let _ = pending::remove(&record.commit);
            }
            ResolveResult::NotFound | ResolveResult::TransientError => {
                let _ = pending::increment(record);
            }
        }
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

/// The hydrate subcommand: backfill AI session notes for recent commits.
///
/// This scans ALL Claude and Codex log directories (not scoped to any
/// single repo), finds commit hashes in session logs, resolves repos
/// from session metadata, and attaches notes where missing.
///
/// Properties:
/// - Can take minutes for large log directories
/// - Prints verbose progress throughout
/// - All errors are non-fatal (logged and continued)
/// - Does NOT auto-push by default (use `--push` flag)
fn run_hydrate(since: &str, do_push: bool) -> Result<()> {
    run_hydrate_inner(since, do_push, None)
}

/// Inner implementation of hydrate that accepts an optional repo filter.
///
/// When `repo_filter` is `Some`, only sessions whose resolved repo root
/// matches the given path are processed. Used by `cadence gc` to scope
/// re-hydration to the current repository.
fn run_hydrate_inner(
    since: &str,
    do_push: bool,
    repo_filter: Option<&std::path::Path>,
) -> Result<()> {
    let since_secs = parse_since_duration(since)?;
    let since_days = since_secs / 86_400;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Resolve encryption method once for this hydration run
    let encryption_method = match resolve_encryption_method() {
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

    // Step 2: Find all session files modified within the --since window
    let files = agents::all_recent_files(now, since_secs);
    if let Some(pb) = spinner {
        pb.finish_and_clear();
    }
    output::action("Scanned", &format!("agent logs (last {} days)", since_days));
    output::detail(&format!("Found {} session logs", files.len()));
    if !files.is_empty() {
        let mut counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for file in &files {
            let agent = scanner::agent_type_from_path(file).to_string();
            *counts.entry(agent).or_insert(0) += 1;
        }
        let summary = counts
            .into_iter()
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

    // Step 3: Pre-process each file to resolve repo and group by repo display
    struct SessionInfo {
        file: std::path::PathBuf,
        session_id: String,
        repo_root: std::path::PathBuf,
        metadata: scanner::SessionMetadata,
    }

    let mut sessions_by_repo: std::collections::BTreeMap<String, Vec<SessionInfo>> =
        std::collections::BTreeMap::new();

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

    for file in &files {
        let metadata = scanner::parse_session_metadata(file);

        // Skip files with no session metadata (e.g., file-history-snapshot files)
        if metadata.session_id.is_none() && metadata.cwd.is_none() {
            continue;
        }

        // Skip sessions with no cwd silently — we can't determine the repo
        let cwd = match &metadata.cwd {
            Some(c) => c.clone(),
            None => continue,
        };

        let cwd_path = std::path::Path::new(&cwd);

        // Skip sessions whose cwd isn't a git repo (silently)
        let repo_root = match git::repo_root_at(cwd_path) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // If a repo filter is set, skip sessions that don't match.
        if let Some(filter) = repo_filter
            && repo_root != filter
        {
            continue;
        }

        let session_id = metadata
            .session_id
            .as_deref()
            .unwrap_or("unknown")
            .to_string();

        // Determine repo display: prefer remote URL, fall back to directory name
        let repo_display = match git::first_remote_url_at(&repo_root) {
            Ok(Some(url)) => url,
            _ => repo_root
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        };

        sessions_by_repo
            .entry(repo_display.clone())
            .or_default()
            .push(SessionInfo {
                file: file.clone(),
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

    // Step 4: Process sessions grouped by repo
    for (repo_display, sessions) in &sessions_by_repo {
        output::action("Repository", repo_display);

        let repo_root = match sessions.first() {
            Some(session) => session.repo_root.clone(),
            None => continue,
        };

        match git::repo_matches_org_filter(&repo_root) {
            Ok(true) => {}
            Ok(false) => {
                output::detail("Org filter does not match; skipping");
                continue;
            }
            Err(e) => {
                output::detail(&format!("Org filter check failed: {}", e));
                continue;
            }
        }

        let repo_remote = if let Ok(Some(remote)) = git::resolve_push_remote_at(&repo_root) {
            let fetch_start = std::time::Instant::now();
            match push::fetch_merge_notes_for_remote_at(&repo_root, &remote) {
                Ok(()) => {
                    output::detail(&format!(
                        "Fetched notes from {} in {} ms",
                        remote,
                        fetch_start.elapsed().as_millis()
                    ));
                }
                Err(e) => {
                    output::note(&format!("Could not fetch notes from {}: {}", remote, e));
                }
            }
            Some(remote)
        } else {
            None
        };

        let session_progress = if use_progress && sessions.len() > 1 {
            let pb = ProgressBar::new(sessions.len() as u64);
            pb.set_draw_target(ProgressDrawTarget::stderr());
            pb.set_style(
                ProgressStyle::with_template("{spinner:.cyan} {pos}/{len} {msg}")
                    .unwrap_or_else(|_| ProgressStyle::default_bar()),
            );
            pb.enable_steady_tick(std::time::Duration::from_millis(120));
            Some(pb)
        } else {
            None
        };

        let print_detail = |msg: &str| {
            if let Some(ref pb) = session_progress {
                pb.println(output::format_detail(msg));
            } else {
                output::detail(msg);
            }
        };

        let mut repo_total = 0usize;
        let mut repo_with_commits = 0usize;
        let mut repo_without_commits = 0usize;

        for session in sessions {
            repo_total += 1;

            let session_display = if session.session_id.len() > 8 {
                &session.session_id[..8]
            } else {
                &session.session_id
            };

            // Use a labeled block so all exit paths reach the progress increment
            'process_session: {
                // Update progress bar with current session
                if let Some(ref pb) = session_progress {
                    pb.set_message(format!("{} — extracting commits", session_display));
                }

                // Extract all commit hashes from the session log
                let commit_hashes = scanner::extract_commit_hashes(&session.file);

                if commit_hashes.is_empty() {
                    repo_without_commits += 1;

                    if !git::check_enabled_at(&session.repo_root) {
                        break 'process_session;
                    }

                    let header = format!("{} |", session_display);

                    if let Some(ref pb) = session_progress {
                        pb.set_message(format!("{} — scanning timestamps", session_display));
                    }

                    let time_range =
                        if let Some((start, end)) = scanner::session_time_range(&session.file) {
                            Some((start, end))
                        } else {
                            // Fall back to file mtime ± 24 hours
                            let mtime = match file_mtime_epoch(&session.file) {
                                Some(t) => t,
                                None => {
                                    print_detail(&format!(
                                        "{} no timestamps or file mtime; skipping",
                                        header
                                    ));
                                    break 'process_session;
                                }
                            };
                            Some((mtime - 86_400, mtime + 86_400))
                        };

                    let (start_ts, end_ts) = match time_range {
                        Some(r) => r,
                        None => {
                            print_detail(&format!("{} no timestamps; skipping", header));
                            break 'process_session;
                        }
                    };

                    let commits =
                        match git::commits_in_time_range(&session.repo_root, start_ts, end_ts) {
                            Ok(c) => c,
                            Err(e) => {
                                print_detail(&format!(
                                    "{} problem scanning commits: {}",
                                    header, e
                                ));
                                errors += 1;
                                break 'process_session;
                            }
                        };

                    if commits.len() != 1 {
                        let status = if commits.is_empty() {
                            "no commits in time window"
                        } else {
                            "ambiguous commits in time window"
                        };
                        print_detail(&format!("{} {}", header, status));
                        break 'process_session;
                    }

                    let hash = &commits[0];
                    match git::note_exists_at(&session.repo_root, hash) {
                        Ok(true) => {
                            skipped += 1;
                            print_detail(&format!(
                                "{} commit {} already attached",
                                header,
                                &hash[..7]
                            ));
                            break 'process_session;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            print_detail(&format!(
                                "{} problem checking note for {}: {}",
                                header,
                                &hash[..7],
                                e
                            ));
                            errors += 1;
                            break 'process_session;
                        }
                    }

                    if let Some(ref pb) = session_progress {
                        pb.set_message(format!("{} — reading session log", session_display));
                    }

                    let session_log = match std::fs::read_to_string(&session.file) {
                        Ok(content) => content,
                        Err(e) => {
                            print_detail(&format!("{} could not read session log: {}", header, e));
                            errors += 1;
                            break 'process_session;
                        }
                    };

                    let agent_type = session
                        .metadata
                        .agent_type
                        .clone()
                        .unwrap_or(scanner::AgentType::Claude);
                    let repo_str = session.repo_root.to_string_lossy().to_string();
                    let session_start =
                        scanner::session_time_range(&session.file).map(|(start, _)| start);

                    match attach_note_from_log_v2(
                        &agent_type,
                        &session.session_id,
                        &repo_str,
                        hash,
                        &session_log,
                        note::Confidence::TimeWindowMatch,
                        &encryption_method,
                        session_start,
                        None,
                        Some(&session.repo_root),
                    ) {
                        Ok(()) => {
                            attached += 1;
                            fallback_attached += 1;
                            print_detail(&format!(
                                "{} commit {} attached (time window match)",
                                header,
                                &hash[..7]
                            ));
                        }
                        Err(e) => {
                            print_detail(&format!(
                                "{} could not attach note to {}: {}",
                                header,
                                &hash[..7],
                                e
                            ));
                            errors += 1;
                        }
                    }

                    break 'process_session;
                }

                repo_with_commits += 1;

                if !git::check_enabled_at(&session.repo_root) {
                    break 'process_session;
                }

                // For each hash, attach note if missing.
                // Buffer messages so we can combine a single status with the header.
                let mut session_attached = 0usize;
                let mut session_skipped = 0usize;
                let mut messages: Vec<String> = Vec::new();

                let header = format!("{} |", session_display);

                if let Some(ref pb) = session_progress {
                    pb.set_message(format!("{} — attaching notes", session_display));
                }

                // Pre-compute metadata shared across all commits in this session
                let agent_type = session
                    .metadata
                    .agent_type
                    .clone()
                    .unwrap_or(scanner::AgentType::Claude);
                let repo_str = session.repo_root.to_string_lossy().to_string();
                let session_start =
                    scanner::session_time_range(&session.file).map(|(start, _)| start);

                // Lazily store the payload blob once for this session.
                // We defer reading until we know at least one commit needs a note.
                let mut payload_info: Option<PayloadInfo> = None;

                for hash in &commit_hashes {
                    // Verify the commit exists in the resolved repo
                    match git::commit_exists_at(&session.repo_root, hash) {
                        Ok(true) => {}
                        Ok(false) => {
                            // Commit does not exist in this repo -- could be from a
                            // different repo or could be rebased away. Skip silently.
                            continue;
                        }
                        Err(e) => {
                            messages.push(format!("problem checking commit {}: {}", &hash[..7], e));
                            errors += 1;
                            continue;
                        }
                    }

                    // Check dedup: skip if note already exists
                    match git::note_exists_at(&session.repo_root, hash) {
                        Ok(true) => {
                            session_skipped += 1;
                            skipped += 1;
                            continue;
                        }
                        Ok(false) => {} // Need to attach
                        Err(e) => {
                            messages.push(format!(
                                "problem checking note for {}: {}",
                                &hash[..7],
                                e
                            ));
                            errors += 1;
                            continue;
                        }
                    }

                    // Lazily encode and store the payload blob on first need
                    if payload_info.is_none() {
                        let session_log = match std::fs::read_to_string(&session.file) {
                            Ok(content) => content,
                            Err(e) => {
                                messages.push(format!("could not read session log: {}", e));
                                errors += 1;
                                break;
                            }
                        };
                        match encode_and_store_payload_at(
                            Some(&session.repo_root),
                            &session_log,
                            &encryption_method,
                        ) {
                            Ok((blob_sha, sha256, encoding)) => {
                                payload_info = Some(PayloadInfo {
                                    blob_sha,
                                    payload_sha256: sha256,
                                    encoding,
                                });
                            }
                            Err(e) => {
                                messages.push(format!("could not store payload: {}", e));
                                errors += 1;
                                break;
                            }
                        }
                    }

                    let info = payload_info.as_ref().unwrap();

                    // Attach v2 pointer note reusing the shared blob
                    match attach_note_from_log_v2(
                        &agent_type,
                        &session.session_id,
                        &repo_str,
                        hash,
                        "", // session_log not used when existing_payload is provided
                        note::Confidence::ExactHashMatch,
                        &encryption_method,
                        session_start,
                        Some(info),
                        Some(&session.repo_root),
                    ) {
                        Ok(()) => {
                            messages.push(format!("commit {} attached", &hash[..7]));
                            session_attached += 1;
                            attached += 1;
                        }
                        Err(e) => {
                            messages.push(format!(
                                "could not attach note to {}: {}",
                                &hash[..7],
                                e
                            ));
                            errors += 1;
                        }
                    }
                }

                // Summarise skipped commits as a single message
                if session_attached == 0 && session_skipped > 0 {
                    messages.push(format!("{} already attached", session_skipped));
                }

                // Print: combine header + single message on one line, or multi-line
                if messages.len() <= 1 {
                    let status = messages
                        .first()
                        .map(|s| s.as_str())
                        .unwrap_or("nothing to do");
                    print_detail(&format!("{} {}", header, status));
                } else {
                    print_detail(&header);
                    for msg in &messages {
                        print_detail(&format!("  {}", msg));
                    }
                }
            }

            // Always increment progress after processing each session
            if let Some(ref pb) = session_progress {
                pb.inc(1);
            }
        }

        if let Some(ref pb) = session_progress {
            pb.finish_and_clear();
        }

        // Per-repo summary (printed after progress bar is cleared)
        output::detail(&format!(
            "{} sessions, {} with commits, {} without",
            repo_total, repo_with_commits, repo_without_commits
        ));

        // Push notes for this repo if requested
        if do_push && let Some(ref remote) = repo_remote {
            push::attempt_push_remote_at(&repo_root, remote);
        }
    }

    // Final summary
    output::success(
        "Hydrate",
        &format!(
            "{} attached, {} fallback attached, {} skipped, {} issues",
            attached, fallback_attached, skipped, errors
        ),
    );

    Ok(())
}

fn run_retry() -> Result<()> {
    let repo_root = git::repo_root()?;
    let repo_str = repo_root.to_string_lossy().to_string();

    let pending_count = pending::list_for_repo(&repo_str)
        .map(|r| r.len())
        .unwrap_or(0);

    if pending_count == 0 {
        output::detail("No pending commits for this repo");
        return Ok(());
    }

    // Resolve encryption method once for this retry run
    let encryption_method = match resolve_encryption_method() {
        Ok(method) => method,
        Err(e) => EncryptionMethod::Unavailable(format!("{e}")),
    };

    output::action("Retrying", &format!("{} pending commit(s)", pending_count));
    retry_pending_for_repo(&repo_str, &repo_root, &encryption_method);

    let remaining = pending::list_for_repo(&repo_str)
        .map(|r| r.len())
        .unwrap_or(0);
    let resolved = pending_count - remaining;
    output::success(
        "Retry",
        &format!("{} resolved, {} still pending", resolved, remaining),
    );

    Ok(())
}

/// The status subcommand: show Cadence CLI configuration and state.
///
/// Displays:
/// - Current repo root (or a message if not in a git repo)
/// - Effective hooks path and whether the post-commit/pre-push shims are installed
/// - Warning when a repo-local hooksPath overrides global Cadence hooks
/// - Notes rewrite safety for rebase/amend
/// - Number of pending retries for the current repo
/// - Org filter config (if any)
/// - Per-repo enabled/disabled status
///
/// All output is user-facing and written to stderr.
/// Handles being called outside a git repo gracefully.
fn run_status() -> Result<()> {
    run_status_inner(&mut std::io::stderr())
}

fn run_status_inner(w: &mut dyn std::io::Write) -> Result<()> {
    output::action_to_with_tty(w, "Status", "", false);

    // --- Repo root ---
    let repo_root = match git::repo_root() {
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
    let global_hooks_path = git::config_get_global("core.hooksPath").ok().flatten();
    if let Some(ref root) = repo_root {
        match git::config_get_at(root, "core.hooksPath").ok().flatten() {
            Some(path) => {
                let hooks_dir = resolve_hooks_path(Some(root), &path);
                let (post_installed, pre_installed) = cadence_hooks_installed(&hooks_dir);
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

        if let Ok(Some(local_hooks_path)) = git::config_get_local_at(root, "core.hooksPath")
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
        let (post_installed, pre_installed) = cadence_hooks_installed(&hooks_dir);
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

    // --- Notes rewrite safety (rebase/amend) ---
    let rewrite_refs = git::config_get_global_all("notes.rewriteRef").unwrap_or_default();
    let rewrite_ref_enabled = notes_rewrite_ref_present(&rewrite_refs, git::NOTES_REF);
    let rebase_value = git::config_get_global("notes.rewrite.rebase")
        .ok()
        .flatten();
    let amend_value = git::config_get_global("notes.rewrite.amend").ok().flatten();
    let rebase_enabled = config_bool_or_default(rebase_value.as_deref(), true);
    let amend_enabled = config_bool_or_default(amend_value.as_deref(), true);
    output::detail_to_with_tty(
        w,
        &format!(
            "Notes rewrite: {}={} rebase={} amend={}",
            git::NOTES_REF,
            if rewrite_ref_enabled { "yes" } else { "no" },
            if rebase_enabled { "on" } else { "off" },
            if amend_enabled { "on" } else { "off" }
        ),
        false,
    );

    if !rewrite_ref_enabled || !rebase_enabled || !amend_enabled {
        output::note_to_with_tty(
            w,
            "Rebase/amend may orphan Cadence notes until rewrite settings are fixed.",
            false,
        );
        if !rewrite_ref_enabled {
            output::detail_to_with_tty(
                w,
                &format!(
                    "Run `git config --global --add notes.rewriteRef {}`",
                    git::NOTES_REF
                ),
                false,
            );
        }
        if !rebase_enabled {
            output::detail_to_with_tty(
                w,
                "Run `git config --global notes.rewrite.rebase true`",
                false,
            );
        }
        if !amend_enabled {
            output::detail_to_with_tty(
                w,
                "Run `git config --global notes.rewrite.amend true`",
                false,
            );
        }
    }

    // --- Pending retries ---
    if let Some(ref root) = repo_root {
        let repo_str = root.to_string_lossy().to_string();
        let pending_count = pending::list_for_repo(&repo_str)
            .map(|r| r.len())
            .unwrap_or(0);
        output::detail_to_with_tty(w, &format!("Pending retries: {}", pending_count), false);
    } else {
        output::detail_to_with_tty(w, "Pending retries: (n/a - not in a repo)", false);
    }

    // --- Org filter ---
    match git::config_get_global("ai.cadence.org") {
        Ok(Some(org)) => {
            output::detail_to_with_tty(w, &format!("Org filter: {}", org), false);
        }
        _ => {
            output::detail_to_with_tty(w, "Org filter: (none)", false);
        }
    }

    // --- Per-repo enabled/disabled ---
    if repo_root.is_some() {
        let enabled = git::check_enabled();
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

fn run_doctor() -> Result<()> {
    run_doctor_inner(&mut std::io::stderr())
}

fn run_doctor_inner(w: &mut dyn std::io::Write) -> Result<()> {
    output::action_to_with_tty(w, "Doctor", "", false);

    let mut issues = 0usize;

    let repo_root = match git::repo_root() {
        Ok(root) => {
            output::detail_to_with_tty(w, &format!("Repo: {}", root.to_string_lossy()), false);
            Some(root)
        }
        Err(_) => {
            output::detail_to_with_tty(w, "Repo: (not in a git repository)", false);
            None
        }
    };

    let global_hooks_path = match git::config_get_global("core.hooksPath") {
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
            let (post_installed, pre_installed) = cadence_hooks_installed(&hooks_dir);
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
        match git::config_get_at(root, "core.hooksPath") {
            Ok(Some(active_path)) => {
                let hooks_dir = resolve_hooks_path(Some(root), &active_path);
                let (post_installed, pre_installed) = cadence_hooks_installed(&hooks_dir);
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
            git::config_get_local_at(root, "core.hooksPath"),
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

    let rewrite_refs = match git::config_get_global_all("notes.rewriteRef") {
        Ok(refs) => refs,
        Err(e) => {
            output::fail_to_with_tty(
                w,
                "Fail",
                &format!("could not read notes.rewriteRef ({e})"),
                false,
            );
            issues += 1;
            Vec::new()
        }
    };
    let rewrite_ref_enabled = notes_rewrite_ref_present(&rewrite_refs, git::NOTES_REF);
    let rebase_enabled = config_bool_or_default(
        git::config_get_global("notes.rewrite.rebase")
            .ok()
            .flatten()
            .as_deref(),
        true,
    );
    let amend_enabled = config_bool_or_default(
        git::config_get_global("notes.rewrite.amend")
            .ok()
            .flatten()
            .as_deref(),
        true,
    );

    output::detail_to_with_tty(
        w,
        &format!(
            "Notes rewrite: {}={} rebase={} amend={}",
            git::NOTES_REF,
            if rewrite_ref_enabled { "yes" } else { "no" },
            if rebase_enabled { "on" } else { "off" },
            if amend_enabled { "on" } else { "off" }
        ),
        false,
    );

    if !rewrite_ref_enabled {
        output::fail_to_with_tty(
            w,
            "Fail",
            &format!("notes.rewriteRef missing {}", git::NOTES_REF),
            false,
        );
        output::detail_to_with_tty(
            w,
            &format!(
                "Run `git config --global --add notes.rewriteRef {}`",
                git::NOTES_REF
            ),
            false,
        );
        issues += 1;
    }
    if !rebase_enabled {
        output::fail_to_with_tty(w, "Fail", "notes.rewrite.rebase is disabled", false);
        output::detail_to_with_tty(
            w,
            "Run `git config --global notes.rewrite.rebase true`",
            false,
        );
        issues += 1;
    }
    if !amend_enabled {
        output::fail_to_with_tty(w, "Fail", "notes.rewrite.amend is disabled", false);
        output::detail_to_with_tty(
            w,
            "Run `git config --global notes.rewrite.amend true`",
            false,
        );
        issues += 1;
    }

    if issues == 0 {
        output::success_to_with_tty(w, "Doctor", "all checks passed", false);
        Ok(())
    } else {
        output::fail_to_with_tty(w, "Doctor", &format!("{} issue(s) found", issues), false);
        anyhow::bail!("doctor found {} issue(s)", issues);
    }
}

/// The notes list subcommand: show recent commits with note markers.
///
/// Output format:
/// - `* <short> <date> <subject>` if note exists
/// - `  <short> <date> <subject>` otherwise
fn run_notes_list(notes_ref: &str) -> Result<()> {
    let entries = git::list_commits_with_note_markers(notes_ref)?;
    output::action("Notes", "list");
    output::detail(&format!("Notes ref: {}", notes_ref));
    for entry in entries {
        if entry.has_note {
            output::detail(&format!(
                "* {} {} {}",
                entry.short, entry.date, entry.subject
            ));
        } else {
            output::detail(&format!(
                "  {} {} {}",
                entry.short, entry.date, entry.subject
            ));
        }
    }
    Ok(())
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
    fn collect() -> Self {
        let (user_fingerprint, user_fingerprint_error) = match pgp_keys::get_user_fingerprint() {
            Ok(v) => (v, None),
            Err(e) => (None, Some(format!("{}", e))),
        };
        let user_public_key_cached = pgp_keys::load_cached_user_public_key()
            .ok()
            .flatten()
            .is_some();
        let user_private_key_cached = pgp_keys::load_cached_user_private_key()
            .ok()
            .flatten()
            .is_some();
        let api_public_key_cached = pgp_keys::load_cached_api_public_key()
            .ok()
            .flatten()
            .is_some();
        let api_metadata = pgp_keys::load_api_public_key_metadata().ok().flatten();

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

fn run_keys_status() -> Result<()> {
    let report = KeysStatusReport::collect();
    let _ = render_keys_status(&mut std::io::stdout(), &report);
    Ok(())
}

fn run_keys_setup() -> Result<()> {
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        anyhow::bail!("cadence keys setup requires an interactive TTY. Run from a terminal.");
    }
    let mut prompter = DialoguerPrompter::new();
    run_keys_setup_inner(&mut prompter, &mut std::io::stdout(), true)
}

fn run_keys_refresh() -> Result<()> {
    let _ = resolve_api_public_key_cache(true)?;
    output::success("API", "public key refreshed.");
    Ok(())
}

fn run_keys_disable() -> Result<()> {
    let _ = git::config_unset_global(pgp_keys::USER_FINGERPRINT_KEY);
    let _ = git::config_unset_global(pgp_keys::API_FINGERPRINT_KEY);

    if let Some(path) = pgp_keys::user_public_key_cache_path() {
        let _ = std::fs::remove_file(path);
    }
    if let Some(path) = pgp_keys::user_private_key_cache_path() {
        let _ = std::fs::remove_file(path);
    }
    if let Some(path) = pgp_keys::api_public_key_cache_path() {
        let _ = std::fs::remove_file(path);
    }
    if let Some(path) = pgp_keys::api_public_key_meta_path() {
        let _ = std::fs::remove_file(path);
    }

    output::success("Encryption", "disabled.");
    Ok(())
}

/// Optional encryption setup during install. Returns `Ok(())` if setup was
/// skipped or completed, and `Err` if install should abort before hydration.
fn run_install_encryption_setup() -> Result<()> {
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

    let Some(enable) =
        prompter.confirm("Encrypt attached session notes? (Recommended)", &mut stdout)?
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

    if let Err(e) = run_keys_setup_inner(&mut prompter, &mut stdout, false) {
        output::note_to_with_tty(
            &mut stdout,
            &format!("Encryption setup incomplete: {e:#}"),
            is_tty,
        );
        anyhow::bail!("encryption setup failed");
    }

    let recipient = git::config_get_global(pgp_keys::USER_FINGERPRINT_KEY)
        .ok()
        .flatten()
        .unwrap_or_default();
    if recipient.trim().is_empty() {
        output::fail_to_with_tty(
            &mut stdout,
            "Encryption",
            "setup did not complete. Install will stop before hydration.",
            is_tty,
        );
        anyhow::bail!("encryption setup incomplete");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Keys setup: prompter abstraction
// ---------------------------------------------------------------------------

trait Prompter {
    fn confirm(&mut self, prompt: &str, writer: &mut dyn std::io::Write) -> Result<Option<bool>>;
}

struct DialoguerPrompter {
    theme: ColorfulTheme,
}

impl DialoguerPrompter {
    fn new() -> Self {
        Self {
            theme: ColorfulTheme::default(),
        }
    }
}

impl Prompter for DialoguerPrompter {
    fn confirm(&mut self, prompt: &str, _writer: &mut dyn std::io::Write) -> Result<Option<bool>> {
        let result = Confirm::with_theme(&self.theme)
            .with_prompt(prompt)
            .interact();
        match result {
            Ok(value) => Ok(Some(value)),
            Err(dialoguer::Error::IO(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                Ok(None)
            }
            Err(err) => Err(err.into()),
        }
    }
}

fn required_git_value(key: &str, label: &str) -> Result<String> {
    let value = git::config_get_global(key)?.unwrap_or_default();
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
fn run_keys_setup_inner(
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

    let name = required_git_value("user.name", "user.name")?;
    let email = required_git_value("user.email", "user.email")?;
    let cadence_email = cadence_email(&email)?;
    let identity = format!("{} <{}>", name.trim(), cadence_email.trim());
    output::detail_to_with_tty(writer, &format!("Using Git identity: {identity}"), is_tty);

    let cached_public = pgp_keys::load_cached_user_public_key()
        .context("failed to read cached local public key")?;
    let cached_private = pgp_keys::load_cached_user_private_key()
        .context("failed to read cached local private key")?;

    if resolve_api_public_key_cache(true)?.is_none() {
        anyhow::bail!("failed to fetch API public key");
    }

    let fingerprint = if let (Some(public), Some(_private)) =
        (cached_public.as_ref(), cached_private.as_ref())
    {
        output::detail_to_with_tty(writer, "Reusing cached local keypair.", is_tty);
        pgp_keys::fingerprint_from_public_key(public)?
    } else {
        let Some(store_in_keychain) = prompter.confirm(
            "Store encryption passphrase in OS keychain? (Recommended)",
            writer,
        )?
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
            .context("failed to store passphrase in OS keychain")?;

        pgp_keys::save_user_keys(&armored_public_key, &armored_private_key)
            .context("failed to cache local keys")?;

        fingerprint
    };

    git::config_set_global(pgp_keys::USER_FINGERPRINT_KEY, &fingerprint)
        .context("failed to save user fingerprint to git config")?;

    writeln!(writer)?;
    output::success_to_with_tty(writer, "Encryption", "ready.", is_tty);
    writeln!(writer, "Local key fingerprint: {}", fingerprint)?;
    if let Ok(Some(api_fpr)) = pgp_keys::get_api_fingerprint() {
        writeln!(writer, "API key fingerprint: {}", api_fpr)?;
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
fn run_update(check: bool, yes: bool) -> Result<()> {
    update::run_update(check, yes)
}

// ---------------------------------------------------------------------------
// GC: clear bloated notes and re-hydrate
// ---------------------------------------------------------------------------

fn run_gc(since: &str, confirm: bool) -> Result<()> {
    // Validate the --since value early so we fail before any destructive work.
    let since_secs = parse_since_duration(since)?;
    let since_days = since_secs / 86_400;

    let repo_root = git::repo_root()?;

    if !confirm {
        output::note("This will DELETE all local and remote AI session notes for this repo,");
        output::note("then re-hydrate them in the optimized v2 format.");
        output::detail(&format!("Re-hydration window: last {} days", since_days));
        output::detail("Local ref:  refs/notes/ai-sessions  → deleted");
        output::detail("Remote ref: refs/notes/ai-sessions  → deleted");
        output::detail("Then: cadence hydrate --since <window> --push");
        eprintln!();
        output::fail("Aborted", "pass --confirm to proceed.");
        anyhow::bail!("gc requires --confirm to proceed");
    }

    // Resolve push remote (e.g. "origin").
    let remote = git::resolve_push_remote_at(&repo_root)?;

    // Step 1: Delete remote notes ref.
    if let Some(ref remote_name) = remote {
        output::action(
            "GC",
            &format!("Deleting remote notes ref on '{}'", remote_name),
        );
        match git::delete_remote_ref_at(Some(&repo_root), remote_name, git::NOTES_REF) {
            Ok(()) => output::detail("Remote notes ref deleted (or did not exist)."),
            Err(e) => output::detail(&format!("Could not delete remote ref (continuing): {e}")),
        }
    } else {
        output::detail("No push remote found; skipping remote ref deletion.");
    }

    // Step 2: Delete local notes ref.
    output::action("GC", "Deleting local notes ref");
    match git::delete_local_ref_at(Some(&repo_root), git::NOTES_REF) {
        Ok(()) => output::detail("Local notes ref deleted (or did not exist)."),
        Err(e) => output::detail(&format!("Could not delete local ref (continuing): {e}")),
    }

    // Step 3: Re-hydrate in v2 format with push enabled (scoped to this repo).
    output::action(
        "GC",
        &format!("Re-hydrating (last {} days) with push", since_days),
    );
    run_hydrate_inner(since, true, Some(&repo_root))?;

    output::success("GC", "Complete. Notes have been regenerated in v2 format.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();
    output::set_verbose(cli.verbose);

    let is_update_command = matches!(cli.command, Command::Update { .. });

    let result = match cli.command {
        Command::Install { org } => run_install(org),
        Command::Hook { hook_command } => match hook_command {
            HookCommand::PostCommit => run_hook_post_commit(),
            HookCommand::PrePush { remote, url } => run_hook_pre_push(&remote, &url),
            HookCommand::PostCommitRetry {
                commit,
                repo,
                timestamp,
            } => run_hook_post_commit_retry(&commit, &repo, timestamp),
        },
        Command::Hydrate { since, push } => run_hydrate(&since, push),
        Command::Retry => run_retry(),
        Command::Notes { notes_command } => match notes_command {
            NotesCommand::List { notes_ref } => run_notes_list(&notes_ref),
        },
        Command::Status => run_status(),
        Command::Doctor => run_doctor(),
        Command::Update { check, yes } => run_update(check, yes),
        Command::Keys { keys_command } => match keys_command.unwrap_or(KeysCommands::Status) {
            KeysCommands::Setup => run_keys_setup(),
            KeysCommands::Status => run_keys_status(),
            KeysCommands::Disable => run_keys_disable(),
            KeysCommands::Refresh => run_keys_refresh(),
        },
        Command::Gc { since, confirm } => run_gc(&since, confirm),
    };

    // Passive background version check: run after successful command execution
    // on all non-Update commands. Failures are silently ignored.
    if result.is_ok() && !is_update_command {
        update::passive_version_check();
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

    #[test]
    fn cli_parses_doctor() {
        let cli = Cli::parse_from(["cadence", "doctor"]);
        match cli.command {
            Command::Doctor => {}
            _ => panic!("expected Doctor command"),
        }
    }

    #[test]
    fn config_bool_or_default_parses_common_values() {
        assert!(config_bool_or_default(Some("true"), false));
        assert!(config_bool_or_default(Some("YES"), false));
        assert!(!config_bool_or_default(Some("false"), true));
        assert!(!config_bool_or_default(Some("0"), true));
        assert!(config_bool_or_default(Some("unexpected"), true));
        assert!(!config_bool_or_default(None, false));
    }

    #[test]
    fn notes_rewrite_ref_present_checks_exact_ref() {
        let refs = vec![
            "refs/notes/commits".to_string(),
            "refs/notes/ai-sessions".to_string(),
        ];
        assert!(notes_rewrite_ref_present(&refs, "refs/notes/ai-sessions"));
        assert!(!notes_rewrite_ref_present(&refs, "refs/notes/other"));
    }

    #[test]
    fn resolve_hooks_path_uses_repo_root_for_relative_paths() {
        let repo = TempDir::new().expect("tempdir");
        let resolved = resolve_hooks_path(Some(repo.path()), ".git/hooks");
        assert_eq!(resolved, repo.path().join(".git/hooks"));
    }

    #[test]
    fn paths_equivalent_matches_relative_and_absolute_same_target() {
        let repo = TempDir::new().expect("tempdir");
        let hooks_dir = repo.path().join(".git/hooks");
        std::fs::create_dir_all(&hooks_dir).expect("create hooks dir");

        let absolute = hooks_dir.clone();
        let relative = repo.path().join(".git/./hooks");
        assert!(paths_equivalent(&absolute, &relative));
    }
}
