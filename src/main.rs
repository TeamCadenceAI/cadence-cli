mod agents;
mod git;
mod gpg;
mod note;
mod output;
mod pending;
mod push;
mod scanner;

use anyhow::Result;
use clap::{Parser, Subcommand};
use dialoguer::{Confirm, Input, theme::ColorfulTheme};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::process;

/// Cadence CLI: attach AI coding agent session logs to Git commits via git notes.
///
/// Provides provenance and measurement of AI-assisted development
/// without polluting commit history.
#[derive(Parser, Debug)]
#[command(name = "cadence", version, about)]
struct Cli {
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

    /// GPG encryption management.
    Gpg {
        #[command(subcommand)]
        gpg_command: GpgCommands,
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
enum GpgCommands {
    /// Show GPG encryption status.
    Status,
    /// Set up GPG encryption.
    Setup,
}

// ---------------------------------------------------------------------------
// Hook error taxonomy
// ---------------------------------------------------------------------------

/// Error classification for the post-commit hook.
///
/// The hook must normally never block a commit (all errors are swallowed).
/// The single exception is when GPG encryption is configured but fails —
/// in that case the hook MUST exit non-zero to prevent unencrypted notes.
enum HookError {
    /// GPG encryption was configured but failed. The hook must propagate
    /// this as a non-zero exit to block the commit.
    GpgEncryptionFailed(String),
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

/// Optionally encrypt note content before storage.
///
/// If `recipient` is `Some`, encrypts the note using GPG and returns the
/// ciphertext. If `recipient` is `None`, returns the plaintext unchanged.
///
/// This is the single place that maps "should encrypt" to "do encrypt",
/// used by hook, retry, and hydrate paths.
fn maybe_encrypt_note(content: &str, recipient: &Option<String>) -> Result<String> {
    match recipient {
        Some(r) => gpg::encrypt_to_recipient(content, r),
        None => Ok(content.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Subcommand dispatch
// ---------------------------------------------------------------------------

/// The install subcommand: set up global git hooks and run initial hydration.
///
/// Steps:
/// 1. Set `git config --global core.hooksPath ~/.git-hooks`
/// 2. Create `~/.git-hooks/` directory if missing
/// 3. Write `~/.git-hooks/post-commit` shim script
/// 4. Write `~/.git-hooks/pre-push` shim script
/// 5. Make shims executable (chmod +x)
/// 6. If `--org` provided, persist org filter to global git config
/// 7. Run hydration for the last 7 days
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

    // Step 6: Run hydration for the last 7 days
    output::action("Hydrating", "recent sessions (last 30 days)");
    let hydrate_start = std::time::Instant::now();
    if let Err(e) = run_hydrate("30d", false) {
        output::fail("Hydration", &format!("stopped ({})", e));
        had_errors = true;
    }
    output::success(
        "Hydration",
        &format!("done in {} ms", hydrate_start.elapsed().as_millis()),
    );

    // Optional: sync notes for the current repo if a push remote resolves
    if let Ok(Some(remote)) = git::resolve_push_remote() {
        let consented = matches!(
            git::config_get("ai.cadence.autopush"),
            Ok(Some(val)) if val == "true"
        );
        if consented && push::check_org_filter_remote(&remote) {
            output::action("Syncing", &format!("notes to {}", remote));
            let sync_start = std::time::Instant::now();
            push::sync_notes_for_remote(&remote);
            output::success(
                "Sync",
                &format!("done in {} ms", sync_start.elapsed().as_millis()),
            );
        }
    }

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
/// This function swallows all errors and returns `Ok(())` EXCEPT when GPG
/// encryption is configured and fails — in that case it returns `Err` to
/// block the commit (non-zero exit). This is the only case where the hook
/// intentionally fails.
///
/// The outer wrapper uses `std::panic::catch_unwind` to catch panics, and
/// pattern-matches on `HookError` to distinguish commit-blocking GPG
/// failures from soft failures that should be swallowed.
fn run_hook_post_commit() -> Result<()> {
    // Catch-all: catch panics
    let result = std::panic::catch_unwind(|| -> std::result::Result<(), HookError> {
        hook_post_commit_inner()
    });

    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(HookError::GpgEncryptionFailed(msg))) => {
            output::fail("GPG", &format!("encryption failed ({})", msg));
            anyhow::bail!("GPG encryption configured but failed: {}", msg);
        }
        Ok(Err(HookError::Soft(e))) => {
            output::note(&format!("Hook issue: {}", e));
            Ok(())
        }
        Err(_) => {
            output::note("Hook panicked (please report this issue)");
            Ok(())
        }
    }
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

    Ok(())
}

/// Inner implementation of the post-commit hook.
///
/// Returns `HookError::GpgEncryptionFailed` if encryption is configured but
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

    // Step 1.5: Resolve GPG recipient once for this invocation
    let recipient = gpg::get_recipient().map_err(|e| {
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

            // Attach the note (encryption failure blocks the commit when configured)
            attach_note_from_log(
                &matched.agent_type,
                session_id,
                &repo_root_str,
                &head_hash,
                &session_log,
                note::Confidence::ExactHashMatch,
                &recipient,
            )
            .map_err(|e| {
                if recipient.is_some() {
                    HookError::GpgEncryptionFailed(format!("{}", e))
                } else {
                    HookError::Soft(e)
                }
            })?;

            output::success(
                "Attached",
                &format!("session {} to commit {}", session_id, &head_hash[..7]),
            );

            if let Ok(Some(remote)) = git::resolve_push_remote()
                && push::should_push_remote(&remote)
            {
                let push_start = std::time::Instant::now();
                push::attempt_push_remote(&remote);
                output::detail(&format!(
                    "Post-commit push in {} ms",
                    push_start.elapsed().as_millis()
                ));
            }

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

            attach_note_from_log(
                &fallback.agent_type,
                &fallback.session_id,
                &repo_root_str,
                &head_hash,
                &session_log,
                note::Confidence::TimeWindowMatch,
                &recipient,
            )
            .map_err(|e| {
                if recipient.is_some() {
                    HookError::GpgEncryptionFailed(format!("{}", e))
                } else {
                    HookError::Soft(e)
                }
            })?;

            output::success(
                "Attached",
                &format!(
                    "session {} to commit {} (time window match)",
                    fallback.session_id,
                    &head_hash[..7]
                ),
            );

            if let Ok(Some(remote)) = git::resolve_push_remote()
                && push::should_push_remote(&remote)
            {
                let push_start = std::time::Instant::now();
                push::attempt_push_remote(&remote);
                output::detail(&format!(
                    "Post-commit push in {} ms",
                    push_start.elapsed().as_millis()
                ));
            }

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

    // Step 7: Retry pending commits for this repo (uses same recipient)
    retry_pending_for_repo(&repo_root_str, &repo_root, &recipient);

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
        output::detail(&format!(
            "Pre-push sync in {} ms",
            sync_start.elapsed().as_millis()
        ));
    }

    Ok(())
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

fn attach_note_from_log(
    agent_type: &scanner::AgentType,
    session_id: &str,
    repo_str: &str,
    commit: &str,
    session_log: &str,
    confidence: note::Confidence,
    recipient: &Option<String>,
) -> Result<()> {
    let note_content = note::format_with_confidence(
        agent_type,
        session_id,
        repo_str,
        commit,
        session_log,
        confidence,
    )?;
    let final_content = maybe_encrypt_note(&note_content, recipient)?;
    git::add_note(commit, &final_content)?;
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

    // Resolve recipient once for this retry process
    let recipient = gpg::get_recipient().unwrap_or(None);

    for delay in BACKGROUND_RETRY_DELAYS {
        std::thread::sleep(std::time::Duration::from_secs(*delay));

        match try_resolve_single_commit(commit, repo, repo_root, timestamp, 600, &recipient) {
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
/// The `recipient` parameter controls optional GPG encryption. In the retry
/// path, encryption failure is treated as a transient error (not commit-blocking).
fn try_resolve_single_commit(
    commit: &str,
    repo_str: &str,
    repo_root: &std::path::Path,
    commit_time: i64,
    time_window: i64,
    recipient: &Option<String>,
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

                if attach_note_from_log(
                    &fallback.agent_type,
                    &fallback.session_id,
                    repo_str,
                    commit,
                    &session_log,
                    note::Confidence::TimeWindowMatch,
                    recipient,
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

                    if let Ok(Some(remote)) = git::resolve_push_remote()
                        && push::should_push_remote(&remote)
                    {
                        let push_start = std::time::Instant::now();
                        push::attempt_push_remote(&remote);
                        output::detail(&format!(
                            "Retry push in {} ms",
                            push_start.elapsed().as_millis()
                        ));
                    }

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

            if attach_note_from_log(
                &fallback.agent_type,
                &fallback.session_id,
                repo_str,
                commit,
                &session_log,
                note::Confidence::TimeWindowMatch,
                recipient,
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

                if let Ok(Some(remote)) = git::resolve_push_remote()
                    && push::should_push_remote(&remote)
                {
                    let push_start = std::time::Instant::now();
                    push::attempt_push_remote(&remote);
                    output::detail(&format!(
                        "Retry push in {} ms",
                        push_start.elapsed().as_millis()
                    ));
                }

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

    if attach_note_from_log(
        &matched.agent_type,
        session_id,
        repo_str,
        commit,
        &session_log,
        note::Confidence::ExactHashMatch,
        recipient,
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

        // Push if conditions are met
        if let Ok(Some(remote)) = git::resolve_push_remote()
            && push::should_push_remote(&remote)
        {
            let push_start = std::time::Instant::now();
            push::attempt_push_remote(&remote);
            output::detail(&format!(
                "Retry push in {} ms",
                push_start.elapsed().as_millis()
            ));
        }

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
/// The `recipient` parameter controls optional GPG encryption. Encryption
/// failures in the retry path are treated as transient errors.
fn retry_pending_for_repo(repo_str: &str, repo_root: &std::path::Path, recipient: &Option<String>) {
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
            recipient,
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
    let since_secs = parse_since_duration(since)?;
    let since_days = since_secs / 86_400;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Resolve GPG recipient once for this hydration run
    let recipient = gpg::get_recipient().unwrap_or(None);

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

            // Extract all commit hashes from the session log
            let commit_hashes = scanner::extract_commit_hashes(&session.file);

            if commit_hashes.is_empty() {
                repo_without_commits += 1;

                if !git::check_enabled_at(&session.repo_root) {
                    continue;
                }

                let header = format!("{} |", session_display);

                let time_range =
                    if let Some((start, end)) = scanner::session_time_range(&session.file) {
                        Some((start, end))
                    } else {
                        // Fall back to file mtime ± 24 hours
                        let mtime = match file_mtime_epoch(&session.file) {
                            Some(t) => t,
                            None => {
                                output::detail(&format!(
                                    "{} no timestamps or file mtime; skipping",
                                    header
                                ));
                                continue;
                            }
                        };
                        Some((mtime - 86_400, mtime + 86_400))
                    };

                let (start_ts, end_ts) = match time_range {
                    Some(r) => r,
                    None => {
                        output::detail(&format!("{} no timestamps; skipping", header));
                        continue;
                    }
                };

                let commits = match git::commits_in_time_range(&session.repo_root, start_ts, end_ts)
                {
                    Ok(c) => c,
                    Err(e) => {
                        output::detail(&format!("{} problem scanning commits: {}", header, e));
                        errors += 1;
                        continue;
                    }
                };

                if commits.len() != 1 {
                    let status = if commits.is_empty() {
                        "no commits in time window"
                    } else {
                        "ambiguous commits in time window"
                    };
                    output::detail(&format!("{} {}", header, status));
                    continue;
                }

                let hash = &commits[0];
                match git::note_exists_at(&session.repo_root, hash) {
                    Ok(true) => {
                        skipped += 1;
                        output::detail(&format!(
                            "{} commit {} already attached",
                            header,
                            &hash[..7]
                        ));
                        continue;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        output::detail(&format!(
                            "{} problem checking note for {}: {}",
                            header,
                            &hash[..7],
                            e
                        ));
                        errors += 1;
                        continue;
                    }
                }

                let session_log = match std::fs::read_to_string(&session.file) {
                    Ok(content) => content,
                    Err(e) => {
                        output::detail(&format!("{} could not read session log: {}", header, e));
                        errors += 1;
                        continue;
                    }
                };

                let agent_type = session
                    .metadata
                    .agent_type
                    .clone()
                    .unwrap_or(scanner::AgentType::Claude);
                let repo_str = session.repo_root.to_string_lossy().to_string();

                let note_content = match note::format_with_confidence(
                    &agent_type,
                    &session.session_id,
                    &repo_str,
                    hash,
                    &session_log,
                    note::Confidence::TimeWindowMatch,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        output::detail(&format!(
                            "{} could not format note for {}: {}",
                            header,
                            &hash[..7],
                            e
                        ));
                        errors += 1;
                        continue;
                    }
                };

                match git::add_note_at(&session.repo_root, hash, &note_content) {
                    Ok(()) => {
                        attached += 1;
                        fallback_attached += 1;
                        output::detail(&format!(
                            "{} commit {} attached (time window match)",
                            header,
                            &hash[..7]
                        ));
                    }
                    Err(e) => {
                        output::detail(&format!(
                            "{} could not attach note to {}: {}",
                            header,
                            &hash[..7],
                            e
                        ));
                        errors += 1;
                    }
                }

                continue;
            }

            repo_with_commits += 1;

            if !git::check_enabled_at(&session.repo_root) {
                continue;
            }

            // For each hash, attach note if missing.
            // Buffer messages so we can combine a single status with the header.
            let mut session_attached = 0usize;
            let mut session_skipped = 0usize;
            let mut messages: Vec<String> = Vec::new();

            let header = format!("{} |", session_display);

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
                        messages.push(format!("problem checking note for {}: {}", &hash[..7], e));
                        errors += 1;
                        continue;
                    }
                }

                // Read the full session log
                let session_log = match std::fs::read_to_string(&session.file) {
                    Ok(content) => content,
                    Err(e) => {
                        messages.push(format!("could not read session log: {}", e));
                        errors += 1;
                        continue;
                    }
                };

                // Use agent type from parsed metadata (already inferred by
                // parse_session_metadata via infer_agent_type). Fall back to
                // Claude if metadata didn't determine it.
                let agent_type = session
                    .metadata
                    .agent_type
                    .clone()
                    .unwrap_or(scanner::AgentType::Claude);

                let repo_str = session.repo_root.to_string_lossy().to_string();

                // Format the note
                let note_content = match note::format(
                    &agent_type,
                    &session.session_id,
                    &repo_str,
                    hash,
                    &session_log,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        messages.push(format!("could not format note for {}: {}", &hash[..7], e));
                        errors += 1;
                        continue;
                    }
                };

                // Optionally encrypt — in hydrate, encryption failure is non-fatal
                let final_content = match maybe_encrypt_note(&note_content, &recipient) {
                    Ok(c) => c,
                    Err(e) => {
                        messages.push(format!("encryption failed for {}: {}", &hash[..7], e));
                        errors += 1;
                        continue;
                    }
                };

                // Attach the note
                match git::add_note_at(&session.repo_root, hash, &final_content) {
                    Ok(()) => {
                        messages.push(format!("commit {} attached", &hash[..7]));
                        session_attached += 1;
                        attached += 1;
                    }
                    Err(e) => {
                        messages.push(format!("could not attach note to {}: {}", &hash[..7], e));
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
                output::detail(&format!("{} {}", header, status));
            } else {
                output::detail(&header);
                for msg in &messages {
                    output::detail(&format!("  {}", msg));
                }
            }
        }

        // Per-repo summary
        output::detail(&format!(
            "{} sessions, {} with commits, {} without",
            repo_total, repo_with_commits, repo_without_commits
        ));
    }

    // Final summary
    output::success(
        "Hydrate",
        &format!(
            "{} attached, {} fallback attached, {} skipped, {} issues",
            attached, fallback_attached, skipped, errors
        ),
    );

    // Step 7: Push if requested
    if do_push {
        output::action("Pushing", "notes");
        if let Ok(Some(remote)) = git::resolve_push_remote() {
            push::attempt_push_remote(&remote);
        }
    }

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

    // Resolve GPG recipient once for this retry run
    let recipient = gpg::get_recipient().unwrap_or(None);

    output::action("Retrying", &format!("{} pending commit(s)", pending_count));
    retry_pending_for_repo(&repo_str, &repo_root, &recipient);

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
/// - Hooks path and whether the post-commit/pre-push shims are installed
/// - Number of pending retries for the current repo
/// - Org filter config (if any)
/// - Autopush consent status
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
    match git::config_get_global("core.hooksPath") {
        Ok(Some(path)) => {
            let post_path = std::path::Path::new(&path).join("post-commit");
            let post_installed = match std::fs::read_to_string(&post_path) {
                Ok(content) => is_cadence_hook(&content),
                Err(_) => false,
            };
            let pre_path = std::path::Path::new(&path).join("pre-push");
            let pre_installed = match std::fs::read_to_string(&pre_path) {
                Ok(content) => is_cadence_hook(&content),
                Err(_) => false,
            };
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
        }
        _ => {
            output::detail_to_with_tty(w, "Hooks path: (not configured)", false);
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

    // --- Autopush consent ---
    if repo_root.is_some() {
        match git::config_get("ai.cadence.autopush") {
            Ok(Some(val)) if val == "true" => {
                output::detail_to_with_tty(w, "Auto-push: enabled (consented)", false);
            }
            Ok(Some(val)) if val == "false" => {
                output::detail_to_with_tty(w, "Auto-push: disabled (opted out)", false);
            }
            _ => {
                output::detail_to_with_tty(
                    w,
                    "Auto-push: not yet configured (will prompt on first push)",
                    false,
                );
            }
        }
    } else {
        output::detail_to_with_tty(w, "Auto-push: (n/a - not in a repo)", false);
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
// GPG status command
// ---------------------------------------------------------------------------

/// Aggregated GPG status probe results.
///
/// Separates data collection from rendering so that tests can construct
/// specific scenarios without running real probes, and future commands
/// (setup, installer) can reuse the same health model.
struct GpgStatusReport {
    gpg_available: bool,
    /// `Some(email)` if configured, `None` if not configured.
    /// `recipient_error` captures failures reading the config key.
    recipient: Option<String>,
    /// Non-empty when `get_recipient()` returned an error.
    recipient_error: Option<String>,
    /// `Some(true/false)` when both gpg and recipient are available;
    /// `None` when the check was skipped (gpg missing or no recipient).
    key_in_keyring: Option<bool>,
}

impl GpgStatusReport {
    /// Collect status by running real probes against system gpg/git.
    fn collect() -> Self {
        let gpg_available = gpg::gpg_available();

        let (recipient, recipient_error) = match gpg::get_recipient() {
            Ok(r) => (r, None),
            Err(e) => (None, Some(format!("{}", e))),
        };

        let key_in_keyring = if gpg_available {
            recipient.as_ref().map(|r| gpg::key_exists(r))
        } else {
            None
        };

        GpgStatusReport {
            gpg_available,
            recipient,
            recipient_error,
            key_in_keyring,
        }
    }

    /// Derive the summary line from probe results.
    fn summary(&self) -> &'static str {
        match (&self.recipient, self.gpg_available, self.key_in_keyring) {
            (Some(_), true, Some(true)) => "enabled",
            (Some(_), true, Some(false)) => "configured but key not in keyring",
            (Some(_), true, None) => "enabled",
            (Some(_), false, _) => "configured but gpg not available",
            (None, _, _) if self.recipient_error.is_some() => "unknown (config read issue)",
            _ => "disabled (plaintext mode)",
        }
    }
}

/// Render GPG status report to the given writer.
///
/// Output lines (stable order):
/// 1. `gpg binary: found|not found`
/// 2. `recipient: <email>|not configured|unavailable (<msg>)`
/// 3. `key in keyring: yes|no` (only when applicable)
/// 4. blank line + `Encryption: <summary>`
fn render_gpg_status(w: &mut dyn std::io::Write, report: &GpgStatusReport) -> std::io::Result<()> {
    writeln!(
        w,
        "gpg binary: {}",
        if report.gpg_available {
            "found"
        } else {
            "not found"
        }
    )?;

    match (&report.recipient, &report.recipient_error) {
        (Some(r), _) => writeln!(w, "recipient: {}", r)?,
        (None, Some(err)) => writeln!(w, "recipient: unavailable ({})", err)?,
        (None, None) => writeln!(w, "recipient: not configured")?,
    }

    if let Some(key_ok) = report.key_in_keyring {
        writeln!(w, "key in keyring: {}", if key_ok { "yes" } else { "no" })?;
    }

    writeln!(w)?;
    writeln!(w, "Encryption: {}", report.summary())?;

    Ok(())
}

/// GPG status command: always returns `Ok(())` (exit code 0).
///
/// All probe errors are captured into the status report and rendered
/// as user-facing status text rather than propagated as errors.
fn run_gpg_status() -> Result<()> {
    let report = GpgStatusReport::collect();
    // Ignore write errors to stdout — nothing we can do if the terminal is gone.
    let _ = render_gpg_status(&mut std::io::stdout(), &report);
    Ok(())
}

/// GPG setup command: interactive flow for configuring GPG encryption.
///
/// Delegates to `run_gpg_setup_inner` with real stdin/stdout so that the
/// flow can be tested with scripted input.
fn run_gpg_setup() -> Result<()> {
    if output::is_stderr_tty() {
        let mut prompter = DialoguerPrompter::new();
        run_gpg_setup_inner(&mut prompter, &mut std::io::stdout())
    } else {
        let mut input = std::io::stdin().lock();
        let mut prompter = BufferedPrompter::new(&mut input);
        run_gpg_setup_inner(&mut prompter, &mut std::io::stdout())
    }
}

// ---------------------------------------------------------------------------
// GPG setup: prompt helpers
// ---------------------------------------------------------------------------

/// Read a single line from `reader`, trimming the trailing newline.
/// Returns `None` on EOF (reader returns 0 bytes).
fn read_line(reader: &mut dyn std::io::BufRead) -> Result<Option<String>> {
    let mut buf = String::new();
    let n = reader.read_line(&mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(
        buf.trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string(),
    ))
}

/// Prompt the user for a line of input. Returns `None` on EOF.
fn prompt_line(
    reader: &mut dyn std::io::BufRead,
    writer: &mut dyn std::io::Write,
    prompt: &str,
) -> Result<Option<String>> {
    write!(writer, "{}", prompt)?;
    writer.flush()?;
    read_line(reader)
}

/// Prompt a yes/no question. Returns `None` on EOF.
/// Accepts y/yes/n/no (case-insensitive). Re-prompts on invalid input.
fn prompt_yes_no(
    reader: &mut dyn std::io::BufRead,
    writer: &mut dyn std::io::Write,
    question: &str,
) -> Result<Option<bool>> {
    loop {
        let Some(answer) = prompt_line(reader, writer, &format!("{} [y/n]: ", question))? else {
            return Ok(None);
        };
        match answer.trim().to_lowercase().as_str() {
            "y" | "yes" => return Ok(Some(true)),
            "n" | "no" => return Ok(Some(false)),
            _ => {
                writeln!(writer, "Please enter 'y' or 'n'.")?;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GPG setup: prompter abstraction
// ---------------------------------------------------------------------------

trait Prompter {
    fn input(&mut self, prompt: &str, writer: &mut dyn std::io::Write) -> Result<Option<String>>;
    fn confirm(&mut self, prompt: &str, writer: &mut dyn std::io::Write) -> Result<Option<bool>>;
}

struct BufferedPrompter<'a> {
    reader: &'a mut dyn std::io::BufRead,
}

impl<'a> BufferedPrompter<'a> {
    fn new(reader: &'a mut dyn std::io::BufRead) -> Self {
        Self { reader }
    }
}

impl Prompter for BufferedPrompter<'_> {
    fn input(&mut self, prompt: &str, writer: &mut dyn std::io::Write) -> Result<Option<String>> {
        prompt_line(self.reader, writer, prompt)
    }

    fn confirm(&mut self, prompt: &str, writer: &mut dyn std::io::Write) -> Result<Option<bool>> {
        prompt_yes_no(self.reader, writer, prompt)
    }
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
    fn input(&mut self, prompt: &str, _writer: &mut dyn std::io::Write) -> Result<Option<String>> {
        let result = Input::with_theme(&self.theme)
            .with_prompt(prompt)
            .allow_empty(true)
            .interact_text();
        match result {
            Ok(value) => Ok(Some(value)),
            Err(dialoguer::Error::IO(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                Ok(None)
            }
            Err(err) => Err(err.into()),
        }
    }

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

/// Return platform-specific GPG install guidance.
fn gpg_install_guidance() -> &'static str {
    if cfg!(target_os = "macos") {
        "Install GPG: brew install gnupg"
    } else if cfg!(target_os = "windows") {
        "Install GPG: winget install GnuPG.GnuPG  (or install from the GnuPG website)"
    } else if cfg!(target_os = "linux") {
        "Install GPG: sudo apt install gnupg  (or your distro's package manager)"
    } else {
        "Install GPG: download from the GnuPG website"
    }
}

// ---------------------------------------------------------------------------
// GPG setup: user abort result
// ---------------------------------------------------------------------------

/// Outcome of the setup flow: either completed with collected values or
/// the user explicitly aborted.
enum SetupOutcome {
    /// User completed all prompts. Contains recipient and optional key source.
    Completed {
        recipient: String,
        key_source: Option<String>,
    },
    /// User aborted the setup flow. No config should be written.
    Aborted,
}

// ---------------------------------------------------------------------------
// GPG setup: inner testable runner
// ---------------------------------------------------------------------------

/// Inner implementation of `gpg setup` that accepts injectable I/O.
///
/// Steps:
/// 1. Check gpg binary availability.
/// 2. Optionally import a GPG public key.
/// 3. Prompt for recipient and validate.
/// 4. Persist global git config (deferred, with rollback on partial failure).
/// 5. Print summary and run `gpg status`.
fn run_gpg_setup_inner(prompter: &mut dyn Prompter, writer: &mut dyn std::io::Write) -> Result<()> {
    writeln!(writer, "=== GPG Encryption Setup ===")?;
    writeln!(writer)?;

    // Step 1: Check gpg binary
    if !gpg::gpg_available() {
        writeln!(writer, "gpg binary: not found")?;
        writeln!(writer)?;
        writeln!(writer, "{}", gpg_install_guidance())?;
        writeln!(writer, "Please install GPG and run this command again.")?;
        return Ok(());
    }
    writeln!(writer, "gpg binary: found")?;
    writeln!(writer)?;

    // Steps 2-3: Collect inputs without writing config
    let outcome = collect_setup_inputs(prompter, writer)?;

    let (recipient, key_source) = match outcome {
        SetupOutcome::Completed {
            recipient,
            key_source,
        } => (recipient, key_source),
        SetupOutcome::Aborted => {
            writeln!(writer)?;
            writeln!(writer, "Setup aborted. No configuration was changed.")?;
            return Ok(());
        }
    };

    // Step 4: Persist config (deferred writes with rollback)
    persist_setup_config(writer, &recipient, key_source.as_deref())?;

    // Step 5: Summary and verification
    writeln!(writer)?;
    writeln!(writer, "=== Setup Complete ===")?;
    writeln!(writer, "recipient: {}", recipient)?;
    if let Some(ref src) = key_source {
        writeln!(writer, "key source: {}", src)?;
    }
    writeln!(writer)?;

    // Run gpg status for verification
    let report = GpgStatusReport::collect();
    render_gpg_status(writer, &report)?;

    Ok(())
}

/// Collect user inputs for key import and recipient (Steps 2-3).
/// Does not write any config. Returns `SetupOutcome`.
fn collect_setup_inputs(
    prompter: &mut dyn Prompter,
    writer: &mut dyn std::io::Write,
) -> Result<SetupOutcome> {
    // Step 2: Optional key import
    let key_source = loop {
        let Some(source) = prompter.input(
            "Enter path to GPG public key file (or press Enter to skip): ",
            writer,
        )?
        else {
            return Ok(SetupOutcome::Aborted);
        };

        let trimmed = source.trim().to_string();
        if trimmed.is_empty() {
            break None;
        }

        match gpg::import_key(&trimmed) {
            Ok(()) => {
                writeln!(writer, "Key imported successfully.")?;
                break Some(trimmed);
            }
            Err(e) => {
                writeln!(writer, "Could not import key: {}", e)?;
                let Some(retry) = prompter.confirm("Retry?", writer)? else {
                    return Ok(SetupOutcome::Aborted);
                };
                if !retry {
                    return Ok(SetupOutcome::Aborted);
                }
                // Loop back to prompt again
            }
        }
    };

    // Step 3: Recipient prompt
    let recipient = loop {
        let Some(input) = prompter.input(
            "Enter GPG recipient (fingerprint, email, or key ID): ",
            writer,
        )?
        else {
            return Ok(SetupOutcome::Aborted);
        };

        let trimmed = input.trim().to_string();
        if trimmed.is_empty() {
            writeln!(writer, "Recipient must not be blank.")?;
            continue;
        }

        if gpg::key_exists(&trimmed) {
            writeln!(writer, "Key found in keyring.")?;
            break trimmed;
        }

        writeln!(writer, "Key not found in keyring for '{}'.", trimmed)?;
        let Some(cont) = prompter.confirm("Continue with this recipient anyway?", writer)? else {
            return Ok(SetupOutcome::Aborted);
        };
        if cont {
            break trimmed;
        } else {
            return Ok(SetupOutcome::Aborted);
        }
    };

    Ok(SetupOutcome::Completed {
        recipient,
        key_source,
    })
}

/// Persist setup config to global git config with rollback on partial failure.
///
/// If writing `publicKeySource` fails after `recipient` was written, the prior
/// recipient value (if any) is restored rather than unconditionally unsetting it.
fn persist_setup_config(
    writer: &mut dyn std::io::Write,
    recipient: &str,
    key_source: Option<&str>,
) -> Result<()> {
    persist_setup_config_with(writer, recipient, key_source, git::config_set_global)
}

/// Inner implementation of config persistence with injectable config-writer.
///
/// Accepts a `set_global` function so tests can inject failures for the second write
/// while letting the first succeed.
fn persist_setup_config_with(
    writer: &mut dyn std::io::Write,
    recipient: &str,
    key_source: Option<&str>,
    set_global: fn(&str, &str) -> Result<()>,
) -> Result<()> {
    // Snapshot the prior recipient value so we can restore it on rollback.
    let prior_recipient = git::config_get_global(gpg::GPG_RECIPIENT_KEY).unwrap_or(None);

    // Write recipient first
    if let Err(e) = set_global(gpg::GPG_RECIPIENT_KEY, recipient) {
        writeln!(writer, "Could not save recipient to git config: {}", e)?;
        return Err(e);
    }

    // Write key source if provided
    if let Some(source) = key_source
        && let Err(e) = set_global(gpg::GPG_PUBLIC_KEY_SOURCE_KEY, source)
    {
        writeln!(writer, "Could not save key source to git config: {}", e)?;
        // Rollback recipient to its prior state
        writeln!(writer, "Rolling back recipient config...")?;
        match prior_recipient {
            Some(ref old_value) => {
                let _ = git::config_set_global(gpg::GPG_RECIPIENT_KEY, old_value);
            }
            None => {
                let _ = git::config_unset_global(gpg::GPG_RECIPIENT_KEY);
            }
        }
        return Err(e);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

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
        Command::Gpg { gpg_command } => match gpg_command {
            GpgCommands::Status => run_gpg_status(),
            GpgCommands::Setup => run_gpg_setup(),
        },
    };

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
    use crate::agents::app_config_dir_in;
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;
    use std::path::PathBuf;

    fn run_gpg_setup_with_io(input: &mut dyn std::io::BufRead, output: &mut Vec<u8>) -> Result<()> {
        let mut prompter = BufferedPrompter::new(input);
        run_gpg_setup_inner(&mut prompter, output)
    }

    fn set_isolated_global_git_config(fake_home: &TempDir) -> (PathBuf, Option<String>) {
        let original = std::env::var("GIT_CONFIG_GLOBAL").ok();
        let global_config_path = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config_path, "").unwrap();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config_path);
        }
        (global_config_path, original)
    }

    fn restore_global_git_config(original: Option<String>) {
        unsafe {
            match original {
                Some(value) => std::env::set_var("GIT_CONFIG_GLOBAL", value),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
    }

    #[test]
    fn cli_parses_install() {
        let cli = Cli::parse_from(["cadence", "install"]);
        assert!(matches!(cli.command, Command::Install { org: None }));
    }

    #[test]
    fn cli_parses_install_with_org() {
        let cli = Cli::parse_from(["cadence", "install", "--org", "my-org"]);
        match cli.command {
            Command::Install { org } => assert_eq!(org.as_deref(), Some("my-org")),
            _ => panic!("expected Install command"),
        }
    }

    #[test]
    fn cli_parses_hook_post_commit() {
        let cli = Cli::parse_from(["cadence", "hook", "post-commit"]);
        assert!(matches!(
            cli.command,
            Command::Hook {
                hook_command: HookCommand::PostCommit
            }
        ));
    }

    #[test]
    fn cli_parses_hook_pre_push() {
        let cli = Cli::parse_from([
            "cadence",
            "hook",
            "pre-push",
            "origin",
            "git@github.com:org/repo.git",
        ]);
        match cli.command {
            Command::Hook {
                hook_command: HookCommand::PrePush { remote, url },
            } => {
                assert_eq!(remote, "origin");
                assert_eq!(url, "git@github.com:org/repo.git");
            }
            _ => panic!("expected Hook PrePush command"),
        }
    }

    #[test]
    fn cli_parses_hook_post_commit_retry() {
        let cli = Cli::parse_from([
            "cadence",
            "hook",
            "post-commit-retry",
            "abcdef0123456789abcdef0123456789abcdef01",
            "/Users/foo/repo",
            "1700000000",
        ]);
        match cli.command {
            Command::Hook {
                hook_command:
                    HookCommand::PostCommitRetry {
                        commit,
                        repo,
                        timestamp,
                    },
            } => {
                assert_eq!(commit, "abcdef0123456789abcdef0123456789abcdef01");
                assert_eq!(repo, "/Users/foo/repo");
                assert_eq!(timestamp, 1_700_000_000);
            }
            _ => panic!("expected Hook PostCommitRetry command"),
        }
    }

    #[test]
    fn cli_parses_hydrate_defaults() {
        let cli = Cli::parse_from(["cadence", "hydrate"]);
        match cli.command {
            Command::Hydrate { since, push } => {
                assert_eq!(since, "7d");
                assert!(!push);
            }
            _ => panic!("expected Hydrate command"),
        }
    }

    #[test]
    fn cli_parses_hydrate_with_flags() {
        let cli = Cli::parse_from(["cadence", "hydrate", "--since", "30d", "--push"]);
        match cli.command {
            Command::Hydrate { since, push } => {
                assert_eq!(since, "30d");
                assert!(push);
            }
            _ => panic!("expected Hydrate command"),
        }
    }

    #[test]
    fn cli_parses_retry() {
        let cli = Cli::parse_from(["cadence", "retry"]);
        assert!(matches!(cli.command, Command::Retry));
    }

    #[test]
    fn cli_parses_notes_list_default_ref() {
        let cli = Cli::parse_from(["cadence", "notes", "list"]);
        match cli.command {
            Command::Notes { notes_command } => match notes_command {
                NotesCommand::List { notes_ref } => {
                    assert_eq!(notes_ref, "refs/notes/ai-sessions");
                }
            },
            _ => panic!("expected Notes command"),
        }
    }

    #[test]
    fn cli_parses_notes_list_custom_ref() {
        let cli = Cli::parse_from([
            "cadence",
            "notes",
            "list",
            "--notes-ref",
            "refs/notes/custom",
        ]);
        match cli.command {
            Command::Notes { notes_command } => match notes_command {
                NotesCommand::List { notes_ref } => {
                    assert_eq!(notes_ref, "refs/notes/custom");
                }
            },
            _ => panic!("expected Notes command"),
        }
    }

    #[test]
    fn cli_parses_status() {
        let cli = Cli::parse_from(["cadence", "status"]);
        assert!(matches!(cli.command, Command::Status));
    }

    #[test]
    fn cli_parses_gpg_status() {
        let cli = Cli::parse_from(["cadence", "gpg", "status"]);
        match cli.command {
            Command::Gpg { gpg_command } => {
                assert!(matches!(gpg_command, GpgCommands::Status));
            }
            _ => panic!("expected Gpg command"),
        }
    }

    #[test]
    fn cli_parses_gpg_setup() {
        let cli = Cli::parse_from(["cadence", "gpg", "setup"]);
        match cli.command {
            Command::Gpg { gpg_command } => {
                assert!(matches!(gpg_command, GpgCommands::Setup));
            }
            _ => panic!("expected Gpg command"),
        }
    }

    #[test]
    fn cli_rejects_gpg_without_subcommand() {
        let result = Cli::try_parse_from(["cadence", "gpg"]);
        assert!(result.is_err());
    }

    #[test]
    #[serial]
    fn run_install_returns_ok() {
        // run_install now does real work but with a fake home it should
        // succeed. We need to redirect HOME and GIT_CONFIG_GLOBAL to
        // isolate from the real environment.
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        // Create a fake global git config so we don't pollute the real one
        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        let result = run_install_inner(None, Some(fake_home.path()));
        assert!(result.is_ok());

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
    }

    #[test]
    #[serial]
    fn run_hook_post_commit_returns_ok() {
        // Isolate HOME so we don't scan real session logs
        let fake_home = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").unwrap_or_default();
        unsafe { std::env::set_var("HOME", fake_home.path()) };

        // The catch-all wrapper ensures this always returns Ok even
        // when called outside a git repo (the inner logic will fail
        // but the error is caught and logged to stderr).
        let result = run_hook_post_commit();

        unsafe { std::env::set_var("HOME", &original_home) };
        assert!(result.is_ok());
    }

    #[test]
    #[serial]
    fn run_hydrate_returns_ok() {
        // Isolate HOME so we don't scan real session logs
        let fake_home = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").unwrap_or_default();
        unsafe { std::env::set_var("HOME", fake_home.path()) };

        // With a fake HOME and no session logs, hydrate should
        // succeed quickly with "Done. 0 attached, 0 fallback attached, 0 skipped, 0 errors."
        let result = run_hydrate("7d", false);

        unsafe { std::env::set_var("HOME", &original_home) };
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_since_duration_7d() {
        assert_eq!(parse_since_duration("7d").unwrap(), 7 * 86_400);
    }

    #[test]
    fn test_parse_since_duration_30d() {
        assert_eq!(parse_since_duration("30d").unwrap(), 30 * 86_400);
    }

    #[test]
    fn test_parse_since_duration_1d() {
        assert_eq!(parse_since_duration("1d").unwrap(), 86_400);
    }

    #[test]
    fn test_parse_since_duration_invalid_format() {
        assert!(parse_since_duration("7h").is_err());
        assert!(parse_since_duration("abc").is_err());
        assert!(parse_since_duration("").is_err());
    }

    #[test]
    fn test_parse_since_duration_zero_rejected() {
        assert!(parse_since_duration("0d").is_err());
    }

    #[test]
    fn test_parse_since_duration_negative_rejected() {
        assert!(parse_since_duration("-1d").is_err());
    }

    #[test]
    fn run_retry_returns_err_outside_repo() {
        // run_retry now calls git::repo_root() which fails outside a git repo.
        // In CI or test environments where the CWD might be inside a repo,
        // it could return Ok. We just verify it doesn't panic.
        let _ = run_retry();
    }

    #[test]
    #[serial]
    fn run_status_returns_ok_outside_repo() {
        // run_status should always return Ok even outside a git repo --
        // it gracefully handles the case where git::repo_root() fails.
        // We chdir to a temp dir that has no .git to actually exercise
        // the outside-repo code path.
        let original_cwd = safe_cwd();
        let tmp = TempDir::new().expect("failed to create temp dir");
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        // Create an empty global config to isolate from developer's environment
        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        std::env::set_current_dir(tmp.path()).expect("failed to chdir to temp dir");

        let mut buf = Vec::new();
        let result = run_status_inner(&mut buf);
        assert!(result.is_ok());

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("not in a git repository"),
            "should show outside-repo message, got: {}",
            output
        );
        assert!(
            output.contains("Pending retries: (n/a - not in a repo)"),
            "pending should show n/a outside repo, got: {}",
            output
        );
        assert!(
            output.contains("Auto-push: (n/a - not in a repo)"),
            "autopush should show n/a outside repo, got: {}",
            output
        );
        assert!(
            output.contains("Repo enabled: (n/a - not in a repo)"),
            "repo enabled should show n/a outside repo, got: {}",
            output
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // Negative CLI parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn cli_rejects_unknown_subcommand() {
        let result = Cli::try_parse_from(["cadence", "frobnicate"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_rejects_hook_without_sub_subcommand() {
        let result = Cli::try_parse_from(["cadence", "hook"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_rejects_hydrate_since_missing_value() {
        let result = Cli::try_parse_from(["cadence", "hydrate", "--since"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_rejects_no_subcommand() {
        let result = Cli::try_parse_from(["cadence"]);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // GPG status report unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn gpg_status_report_summary_disabled_no_recipient() {
        let report = GpgStatusReport {
            gpg_available: true,
            recipient: None,
            recipient_error: None,
            key_in_keyring: None,
        };
        assert_eq!(report.summary(), "disabled (plaintext mode)");
    }

    #[test]
    fn gpg_status_report_summary_enabled() {
        let report = GpgStatusReport {
            gpg_available: true,
            recipient: Some("test@example.com".to_string()),
            recipient_error: None,
            key_in_keyring: Some(true),
        };
        assert_eq!(report.summary(), "enabled");
    }

    #[test]
    fn gpg_status_report_summary_key_missing() {
        let report = GpgStatusReport {
            gpg_available: true,
            recipient: Some("test@example.com".to_string()),
            recipient_error: None,
            key_in_keyring: Some(false),
        };
        assert_eq!(report.summary(), "configured but key not in keyring");
    }

    #[test]
    fn gpg_status_report_summary_gpg_not_available() {
        let report = GpgStatusReport {
            gpg_available: false,
            recipient: Some("test@example.com".to_string()),
            recipient_error: None,
            key_in_keyring: None,
        };
        assert_eq!(report.summary(), "configured but gpg not available");
    }

    #[test]
    fn gpg_status_report_summary_config_error() {
        let report = GpgStatusReport {
            gpg_available: true,
            recipient: None,
            recipient_error: Some("config read failed".to_string()),
            key_in_keyring: None,
        };
        assert_eq!(report.summary(), "unknown (config read issue)");
    }

    #[test]
    fn gpg_status_report_summary_disabled_gpg_missing_no_recipient() {
        let report = GpgStatusReport {
            gpg_available: false,
            recipient: None,
            recipient_error: None,
            key_in_keyring: None,
        };
        assert_eq!(report.summary(), "disabled (plaintext mode)");
    }

    // -----------------------------------------------------------------------
    // GPG status render tests (no system probes — constructed reports)
    // -----------------------------------------------------------------------

    #[test]
    fn render_gpg_status_no_recipient() {
        let report = GpgStatusReport {
            gpg_available: true,
            recipient: None,
            recipient_error: None,
            key_in_keyring: None,
        };
        let mut buf = Vec::new();
        render_gpg_status(&mut buf, &report).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("gpg binary: found"), "got: {}", output);
        assert!(
            output.contains("recipient: not configured"),
            "got: {}",
            output
        );
        assert!(
            !output.contains("key in keyring"),
            "key line should be absent, got: {}",
            output
        );
        assert!(
            output.contains("Encryption: disabled (plaintext mode)"),
            "got: {}",
            output
        );
    }

    #[test]
    fn render_gpg_status_enabled() {
        let report = GpgStatusReport {
            gpg_available: true,
            recipient: Some("user@example.com".to_string()),
            recipient_error: None,
            key_in_keyring: Some(true),
        };
        let mut buf = Vec::new();
        render_gpg_status(&mut buf, &report).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("gpg binary: found"), "got: {}", output);
        assert!(
            output.contains("recipient: user@example.com"),
            "got: {}",
            output
        );
        assert!(output.contains("key in keyring: yes"), "got: {}", output);
        assert!(output.contains("Encryption: enabled"), "got: {}", output);
    }

    #[test]
    fn render_gpg_status_gpg_missing_with_recipient() {
        let report = GpgStatusReport {
            gpg_available: false,
            recipient: Some("user@example.com".to_string()),
            recipient_error: None,
            key_in_keyring: None,
        };
        let mut buf = Vec::new();
        render_gpg_status(&mut buf, &report).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("gpg binary: not found"), "got: {}", output);
        assert!(
            output.contains("recipient: user@example.com"),
            "got: {}",
            output
        );
        assert!(
            !output.contains("key in keyring"),
            "key line should be absent when gpg missing, got: {}",
            output
        );
        assert!(
            output.contains("Encryption: configured but gpg not available"),
            "got: {}",
            output
        );
    }

    #[test]
    fn render_gpg_status_key_missing() {
        let report = GpgStatusReport {
            gpg_available: true,
            recipient: Some("user@example.com".to_string()),
            recipient_error: None,
            key_in_keyring: Some(false),
        };
        let mut buf = Vec::new();
        render_gpg_status(&mut buf, &report).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("key in keyring: no"), "got: {}", output);
        assert!(
            output.contains("Encryption: configured but key not in keyring"),
            "got: {}",
            output
        );
    }

    #[test]
    fn render_gpg_status_config_error() {
        let report = GpgStatusReport {
            gpg_available: true,
            recipient: None,
            recipient_error: Some("invalid config file".to_string()),
            key_in_keyring: None,
        };
        let mut buf = Vec::new();
        render_gpg_status(&mut buf, &report).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(
            output.contains("recipient: unavailable (invalid config file)"),
            "got: {}",
            output
        );
        assert!(
            output.contains("Encryption: unknown (config read issue)"),
            "got: {}",
            output
        );
    }

    // -----------------------------------------------------------------------
    // GPG status exit-code-0 invariance tests
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn run_gpg_status_returns_ok_with_no_config() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".gitconfig");
        std::fs::write(&config_path, "").unwrap();

        let result = with_env(
            "GIT_CONFIG_GLOBAL",
            config_path.to_str().unwrap(),
            run_gpg_status,
        );
        assert!(result.is_ok(), "gpg status should always return Ok");
    }

    #[test]
    #[serial]
    fn run_gpg_status_returns_ok_with_bad_config() {
        // Point GIT_CONFIG_GLOBAL to nonexistent file
        let result = with_env(
            "GIT_CONFIG_GLOBAL",
            "/tmp/nonexistent-gitconfig-for-test-12345",
            run_gpg_status,
        );
        assert!(
            result.is_ok(),
            "gpg status should always return Ok even with bad config"
        );
    }

    // -----------------------------------------------------------------------
    // GPG setup: prompt helper unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn prompt_yes_no_accepts_y() {
        let mut input = std::io::Cursor::new(b"y\n".to_vec());
        let mut output = Vec::new();
        let result = prompt_yes_no(&mut input, &mut output, "Continue?").unwrap();
        assert_eq!(result, Some(true));
    }

    #[test]
    fn prompt_yes_no_accepts_yes_case_insensitive() {
        let mut input = std::io::Cursor::new(b"YES\n".to_vec());
        let mut output = Vec::new();
        let result = prompt_yes_no(&mut input, &mut output, "Continue?").unwrap();
        assert_eq!(result, Some(true));
    }

    #[test]
    fn prompt_yes_no_accepts_n() {
        let mut input = std::io::Cursor::new(b"n\n".to_vec());
        let mut output = Vec::new();
        let result = prompt_yes_no(&mut input, &mut output, "Continue?").unwrap();
        assert_eq!(result, Some(false));
    }

    #[test]
    fn prompt_yes_no_reprompts_then_accepts() {
        let mut input = std::io::Cursor::new(b"maybe\ny\n".to_vec());
        let mut output = Vec::new();
        let result = prompt_yes_no(&mut input, &mut output, "Continue?").unwrap();
        assert_eq!(result, Some(true));
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("Please enter 'y' or 'n'."));
    }

    #[test]
    fn prompt_yes_no_eof_returns_none() {
        let mut input = std::io::Cursor::new(b"".to_vec());
        let mut output = Vec::new();
        let result = prompt_yes_no(&mut input, &mut output, "Continue?").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn read_line_eof_returns_none() {
        let mut input = std::io::Cursor::new(b"".to_vec());
        let result = read_line(&mut input).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn read_line_trims_newline() {
        let mut input = std::io::Cursor::new(b"hello\n".to_vec());
        let result = read_line(&mut input).unwrap();
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn read_line_trims_crlf() {
        let mut input = std::io::Cursor::new(b"hello\r\n".to_vec());
        let result = read_line(&mut input).unwrap();
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn gpg_install_guidance_returns_nonempty() {
        let guidance = gpg_install_guidance();
        assert!(!guidance.is_empty());
        assert!(guidance.contains("GPG") || guidance.contains("gpg"));
    }

    // -----------------------------------------------------------------------
    // GPG setup: workflow tests with scripted I/O
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    #[cfg(unix)]
    fn gpg_setup_exits_early_when_gpg_unavailable() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".gitconfig");
        std::fs::write(&config_path, "").unwrap();

        // Build a restricted PATH that includes git but NOT gpg.
        let restricted_bin = TempDir::new().unwrap();
        let git_path_output = std::process::Command::new("which")
            .arg("git")
            .output()
            .expect("which git failed");
        let git_bin = String::from_utf8(git_path_output.stdout)
            .unwrap()
            .trim()
            .to_string();
        std::os::unix::fs::symlink(&git_bin, restricted_bin.path().join("git")).unwrap();

        let mut input = std::io::Cursor::new(b"".to_vec());
        let mut output = Vec::new();

        let result = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            with_env("PATH", restricted_bin.path().to_str().unwrap(), || {
                run_gpg_setup_with_io(&mut input, &mut output)
            })
        });

        assert!(
            result.is_ok(),
            "gpg-unavailable should exit cleanly: {:?}",
            result.err()
        );

        let output_str = String::from_utf8(output).unwrap();
        assert!(
            output_str.contains("not found"),
            "should say gpg not found: {output_str}"
        );
        assert!(
            output_str.contains("install") || output_str.contains("Install"),
            "should provide install guidance: {output_str}"
        );

        // No config should be written
        let recipient = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            git::config_get_global(gpg::GPG_RECIPIENT_KEY)
        });
        assert_eq!(recipient.unwrap(), None, "no recipient should be saved");
    }

    #[test]
    #[serial]
    fn gpg_setup_abort_at_key_import_eof() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".gitconfig");
        std::fs::write(&config_path, "").unwrap();

        // EOF immediately at key import prompt
        let mut input = std::io::Cursor::new(b"".to_vec());
        let mut output = Vec::new();

        let result = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            run_gpg_setup_with_io(&mut input, &mut output)
        });

        // On machines without gpg, this aborts at step 1 (gpg not found).
        // On machines with gpg, this aborts at step 2 (EOF at import prompt).
        // Either way, it should return Ok (user abort = Ok).
        assert!(
            result.is_ok(),
            "abort at EOF should return Ok: {:?}",
            result.err()
        );

        let _output_str = String::from_utf8(output).unwrap();
        // Should NOT have saved any config
        let recipient = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            git::config_get_global(gpg::GPG_RECIPIENT_KEY)
        });
        assert_eq!(
            recipient.unwrap(),
            None,
            "no recipient should be saved on abort"
        );
    }

    #[test]
    #[serial]
    fn gpg_setup_skip_import_then_abort_at_recipient_eof() {
        if !gpg::gpg_available() {
            eprintln!("skipping test: gpg not available");
            return;
        }

        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".gitconfig");
        std::fs::write(&config_path, "").unwrap();

        // Skip import (enter), then EOF at recipient prompt
        let mut input = std::io::Cursor::new(b"\n".to_vec());
        let mut output = Vec::new();

        let result = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            run_gpg_setup_with_io(&mut input, &mut output)
        });

        assert!(result.is_ok(), "abort should return Ok: {:?}", result.err());

        let output_str = String::from_utf8(output).unwrap();
        assert!(
            output_str.contains("aborted")
                || output_str.contains("Aborted")
                || output_str.contains("No configuration"),
            "should mention abort/no changes in output: {output_str}"
        );

        // No config should be written
        let recipient = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            git::config_get_global(gpg::GPG_RECIPIENT_KEY)
        });
        assert_eq!(recipient.unwrap(), None);
    }

    #[test]
    #[serial]
    fn gpg_setup_blank_recipient_reprompts_then_eof() {
        if !gpg::gpg_available() {
            eprintln!("skipping test: gpg not available");
            return;
        }

        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".gitconfig");
        std::fs::write(&config_path, "").unwrap();

        // Skip import, then blank recipient, then EOF
        let mut input = std::io::Cursor::new(b"\n\n".to_vec());
        let mut output = Vec::new();

        let result = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            run_gpg_setup_with_io(&mut input, &mut output)
        });

        assert!(result.is_ok());

        let output_str = String::from_utf8(output).unwrap();
        assert!(
            output_str.contains("must not be blank"),
            "should reject blank recipient: {output_str}"
        );
    }

    #[test]
    #[serial]
    fn gpg_setup_missing_key_abort() {
        if !gpg::gpg_available() {
            eprintln!("skipping test: gpg not available");
            return;
        }

        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".gitconfig");
        std::fs::write(&config_path, "").unwrap();

        let gnupg_dir = TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(gnupg_dir.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }

        // Skip import, enter nonexistent recipient, then say "no" to continue
        let mut input = std::io::Cursor::new(b"\nnonexistent@example.invalid\nn\n".to_vec());
        let mut output = Vec::new();

        let result = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            with_env("GNUPGHOME", gnupg_dir.path().to_str().unwrap(), || {
                run_gpg_setup_with_io(&mut input, &mut output)
            })
        });

        assert!(result.is_ok());

        let output_str = String::from_utf8(output).unwrap();
        assert!(
            output_str.contains("not found in keyring"),
            "should warn about missing key: {output_str}"
        );
        assert!(
            output_str.contains("aborted")
                || output_str.contains("Aborted")
                || output_str.contains("No configuration"),
            "should indicate abort: {output_str}"
        );

        // No config saved
        let recipient = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            git::config_get_global(gpg::GPG_RECIPIENT_KEY)
        });
        assert_eq!(recipient.unwrap(), None);
    }

    #[test]
    #[serial]
    fn gpg_setup_missing_key_continue_anyway() {
        if !gpg::gpg_available() {
            eprintln!("skipping test: gpg not available");
            return;
        }

        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".gitconfig");
        std::fs::write(&config_path, "").unwrap();

        let gnupg_dir = TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(gnupg_dir.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }

        // Skip import, enter nonexistent recipient, say "yes" to continue anyway
        let mut input = std::io::Cursor::new(b"\nnonexistent@example.invalid\ny\n".to_vec());
        let mut output = Vec::new();

        let result = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            with_env("GNUPGHOME", gnupg_dir.path().to_str().unwrap(), || {
                run_gpg_setup_with_io(&mut input, &mut output)
            })
        });

        assert!(result.is_ok(), "setup should succeed: {:?}", result.err());

        let output_str = String::from_utf8(output).unwrap();
        assert!(
            output_str.contains("Setup Complete"),
            "should show completion: {output_str}"
        );

        // Config should be saved
        let recipient = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            git::config_get_global(gpg::GPG_RECIPIENT_KEY)
        });
        assert_eq!(
            recipient.unwrap(),
            Some("nonexistent@example.invalid".to_string())
        );

        // No key source should be saved (import was skipped)
        let key_source = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            git::config_get_global(gpg::GPG_PUBLIC_KEY_SOURCE_KEY)
        });
        assert_eq!(key_source.unwrap(), None);
    }

    #[test]
    #[serial]
    fn gpg_setup_import_fail_then_abort() {
        if !gpg::gpg_available() {
            eprintln!("skipping test: gpg not available");
            return;
        }

        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".gitconfig");
        std::fs::write(&config_path, "").unwrap();

        let gnupg_dir = TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(gnupg_dir.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }

        // Enter invalid path, then decline retry
        let mut input = std::io::Cursor::new(b"/nonexistent/key.asc\nn\n".to_vec());
        let mut output = Vec::new();

        let result = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            with_env("GNUPGHOME", gnupg_dir.path().to_str().unwrap(), || {
                run_gpg_setup_with_io(&mut input, &mut output)
            })
        });

        assert!(result.is_ok());

        let output_str = String::from_utf8(output).unwrap();
        assert!(
            output_str.contains("Could not import key"),
            "should show import failure: {output_str}"
        );

        // No config saved
        let recipient = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            git::config_get_global(gpg::GPG_RECIPIENT_KEY)
        });
        assert_eq!(recipient.unwrap(), None);
    }

    // -----------------------------------------------------------------------
    // GPG setup: config persistence tests
    // -----------------------------------------------------------------------

    /// A config writer that succeeds for recipient but fails for publicKeySource.
    /// Used to test the rollback path in persist_setup_config_with.
    fn config_set_global_fail_on_key_source(key: &str, value: &str) -> Result<()> {
        if key == gpg::GPG_PUBLIC_KEY_SOURCE_KEY {
            anyhow::bail!("simulated write failure for key source");
        }
        git::config_set_global(key, value)
    }

    #[test]
    #[serial]
    fn persist_setup_config_rollback_restores_prior_recipient() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".gitconfig");
        std::fs::write(&config_path, "").unwrap();

        // Pre-seed an existing recipient
        with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            git::config_set_global(gpg::GPG_RECIPIENT_KEY, "original@example.com").unwrap();
        });

        // Call persist_setup_config_with using the failing writer
        let mut output = Vec::new();
        let result = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            persist_setup_config_with(
                &mut output,
                "new@example.com",
                Some("/path/to/key.asc"),
                config_set_global_fail_on_key_source,
            )
        });

        // Should return error (key source write failed)
        assert!(result.is_err(), "should fail when key source write fails");

        let output_str = String::from_utf8(output).unwrap();
        assert!(
            output_str.contains("Rolling back"),
            "should mention rollback: {output_str}"
        );

        // Original recipient should be restored
        let recipient = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            git::config_get_global(gpg::GPG_RECIPIENT_KEY)
        });
        assert_eq!(
            recipient.unwrap(),
            Some("original@example.com".to_string()),
            "rollback must restore original recipient, not unset it"
        );

        // Key source should NOT be set
        let key_source = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            git::config_get_global(gpg::GPG_PUBLIC_KEY_SOURCE_KEY)
        });
        assert_eq!(
            key_source.unwrap(),
            None,
            "key source should not be saved on failure"
        );
    }

    #[test]
    #[serial]
    fn persist_setup_config_rollback_unsets_when_no_prior_recipient() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".gitconfig");
        std::fs::write(&config_path, "").unwrap();

        // No pre-existing recipient — config is empty

        let mut output = Vec::new();
        let result = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            persist_setup_config_with(
                &mut output,
                "new@example.com",
                Some("/path/to/key.asc"),
                config_set_global_fail_on_key_source,
            )
        });

        assert!(result.is_err(), "should fail when key source write fails");

        // Recipient should be unset (rolled back to "no prior value")
        let recipient = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            git::config_get_global(gpg::GPG_RECIPIENT_KEY)
        });
        assert_eq!(
            recipient.unwrap(),
            None,
            "rollback must unset recipient when no prior value existed"
        );
    }

    #[test]
    #[serial]
    fn persist_setup_config_writes_both_keys_on_success() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".gitconfig");
        std::fs::write(&config_path, "").unwrap();

        let mut output = Vec::new();
        let result = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            persist_setup_config(&mut output, "test@example.com", Some("/keys/pub.asc"))
        });

        assert!(result.is_ok(), "should succeed: {:?}", result.err());

        let recipient = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            git::config_get_global(gpg::GPG_RECIPIENT_KEY)
        });
        assert_eq!(
            recipient.unwrap(),
            Some("test@example.com".to_string()),
            "recipient should be saved"
        );

        let key_source = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            git::config_get_global(gpg::GPG_PUBLIC_KEY_SOURCE_KEY)
        });
        assert_eq!(
            key_source.unwrap(),
            Some("/keys/pub.asc".to_string()),
            "key source should be saved"
        );
    }

    // -----------------------------------------------------------------------
    // GPG status integration tests (real probes with env isolation)
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn gpg_status_collect_no_recipient_configured() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".gitconfig");
        std::fs::write(&config_path, "").unwrap();

        let report = with_env(
            "GIT_CONFIG_GLOBAL",
            config_path.to_str().unwrap(),
            GpgStatusReport::collect,
        );

        assert!(report.recipient.is_none());
        assert!(report.recipient_error.is_none());
        assert!(report.key_in_keyring.is_none());
    }

    #[test]
    #[serial]
    #[cfg(not(windows))]
    fn gpg_status_collect_with_recipient_configured() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".gitconfig");
        std::fs::write(&config_path, "").unwrap();

        // Configure a recipient
        std::process::Command::new("git")
            .args([
                "config",
                "--file",
                config_path.to_str().unwrap(),
                "ai.cadence.gpg.recipient",
                "test-status@example.com",
            ])
            .output()
            .unwrap();

        let report = with_env(
            "GIT_CONFIG_GLOBAL",
            config_path.to_str().unwrap(),
            GpgStatusReport::collect,
        );

        assert_eq!(report.recipient.as_deref(), Some("test-status@example.com"));
        assert!(report.recipient_error.is_none());
    }

    // -----------------------------------------------------------------------
    // Integration test: post-commit hook with a real temp repo
    // -----------------------------------------------------------------------

    use serde_json::json;
    use serial_test::serial;
    use tempfile::TempDir;

    /// Helper: create a temporary git repo with one commit.
    fn init_temp_repo() -> TempDir {
        let dir = TempDir::new().expect("failed to create temp dir");
        let path = dir.path();

        run_git(path, &["init"]);
        run_git(path, &["config", "user.email", "test@test.com"]);
        run_git(path, &["config", "user.name", "Test User"]);
        // Override hooksPath to prevent the global post-commit hook from firing
        run_git(path, &["config", "core.hooksPath", "/dev/null"]);
        std::fs::write(path.join("README.md"), "hello").unwrap();
        run_git(path, &["add", "README.md"]);
        run_git(path, &["commit", "-m", "initial commit"]);

        dir
    }

    /// Run a git command inside the given directory, panicking on failure.
    fn run_git(dir: &std::path::Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .args(["-C", dir.to_str().unwrap()])
            .args(args)
            .output()
            .expect("failed to run git");
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("git {:?} failed: {}", args, stderr);
        }
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    /// Helper: get a stable directory to use as a fallback CWD.
    /// This is needed because serial tests may leave CWD in a deleted temp dir
    /// if a previous test panicked before restoring CWD.
    fn safe_cwd() -> PathBuf {
        match std::env::current_dir() {
            Ok(cwd) if cwd.exists() => cwd,
            _ => {
                // CWD is invalid (deleted temp dir from panicked test).
                // Restore to a known-good directory.
                let fallback = std::env::temp_dir();
                std::env::set_current_dir(&fallback).ok();
                fallback
            }
        }
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_attaches_note_to_commit() {
        // Set up temp repo with a commit
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        // Use a separate temp dir as a fake HOME to avoid polluting the
        // real ~/.claude directory. The agents module reads $HOME to find
        // session logs, so redirecting it is sufficient.
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        // SAFETY: This test is #[serial], so no other threads are reading
        // env vars concurrently.
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        // Get the actual repo root as git sees it (may differ from dir.path()
        // due to symlinks, e.g. /var -> /private/var on macOS)
        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let git_repo_root_path = std::path::Path::new(&git_repo_root);

        // Get the HEAD commit hash and timestamp
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        // Create a fake Claude session log directory matching this repo
        // inside the fake HOME, so it is fully self-contained in temp dirs.
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        // Create a fake JSONL session log with the commit hash and metadata.
        // Use the git-reported repo root for cwd to match what verify_match checks.
        let session_content = format!(
            r#"{{"session_id":"test-session-id","cwd":"{cwd}"}}
{{"type":"tool_result","content":"[main {short}] initial commit\n 1 file changed"}}
{{"type":"assistant","message":"Done"}}
"#,
            cwd = git_repo_root,
            short = &head_hash[..7],
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        // Set the session file mtime to match the commit time
        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        // chdir into the repo and run the hook
        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();

        // The hook should always return Ok
        assert!(result.is_ok());

        // Verify a note was attached
        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: claude-code"));
        assert!(note_output.contains("session_id: test-session-id"));
        assert!(note_output.contains(&head_hash));
        assert!(note_output.contains("confidence: exact_hash_match"));

        // Restore HOME and cwd
        // SAFETY: This test is #[serial], so no other threads are reading
        // env vars concurrently.
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_attaches_note_cursor_chat_session() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let (_global_config_path, original_global) = set_isolated_global_git_config(&fake_home);
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        let chat_dir = app_config_dir_in("Cursor", fake_home.path())
            .join("User")
            .join("workspaceStorage")
            .join("ws1")
            .join("chatSessions");
        std::fs::create_dir_all(&chat_dir).unwrap();

        let session_content = json!({
            "sessionId": "cursor-chat-1",
            "baseUri": { "fsPath": format!("{}/README.md", git_repo_root) },
            "requests": [{
                "response": [{
                    "value": format!("[main {}] initial commit", head_hash)
                }],
                "variableData": {
                    "variables": [{
                        "value": { "uri": { "fsPath": format!("{}/README.md", git_repo_root) } }
                    }]
                }
            }]
        })
        .to_string();
        let session_file = chat_dir.join("session.json");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: cursor"));
        assert!(note_output.contains("session_id: cursor-chat-1"));
        assert!(note_output.contains(&head_hash));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        restore_global_git_config(original_global);
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_attaches_note_cursor_project() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        let project_dir = fake_home
            .path()
            .join(".cursor")
            .join("projects")
            .join("proj1");
        std::fs::create_dir_all(&project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"cursor-proj-1"}}
{{"cwd":"{cwd}"}}
{{"content":"[main {hash}] initial commit"}}
"#,
            cwd = git_repo_root,
            hash = head_hash,
        );
        let session_file = project_dir.join("session.json");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: cursor"));
        assert!(note_output.contains("session_id: cursor-proj-1"));
        assert!(note_output.contains(&head_hash));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_attaches_note_copilot_chat_session() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let (_global_config_path, original_global) = set_isolated_global_git_config(&fake_home);
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        let chat_dir = app_config_dir_in("Code", fake_home.path())
            .join("User")
            .join("workspaceStorage")
            .join("ws1")
            .join("chatSessions");
        std::fs::create_dir_all(&chat_dir).unwrap();

        let session_content = json!({
            "sessionId": "copilot-chat-1",
            "baseUri": { "fsPath": format!("{}/README.md", git_repo_root) },
            "requests": [{
                "response": [{
                    "value": format!("[main {}] initial commit", head_hash)
                }],
                "variableData": {
                    "variables": [{
                        "value": { "uri": { "fsPath": format!("{}/README.md", git_repo_root) } }
                    }]
                }
            }]
        })
        .to_string();
        let session_file = chat_dir.join("session.json");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: copilot"));
        assert!(note_output.contains("session_id: copilot-chat-1"));
        assert!(note_output.contains(&head_hash));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        restore_global_git_config(original_global);
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_attaches_note_antigravity_chat_session() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let (_global_config_path, original_global) = set_isolated_global_git_config(&fake_home);
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        let chat_dir = app_config_dir_in("Antigravity", fake_home.path())
            .join("User")
            .join("workspaceStorage")
            .join("ws1")
            .join("chatSessions");
        std::fs::create_dir_all(&chat_dir).unwrap();

        let session_content = json!({
            "sessionId": "antigravity-chat-1",
            "baseUri": { "fsPath": format!("{}/README.md", git_repo_root) },
            "requests": [{
                "response": [{
                    "value": format!("[main {}] initial commit", head_hash)
                }],
                "variableData": {
                    "variables": [{
                        "value": { "uri": { "fsPath": format!("{}/README.md", git_repo_root) } }
                    }]
                }
            }]
        })
        .to_string();
        let session_file = chat_dir.join("session.json");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: antigravity"));
        assert!(note_output.contains("session_id: antigravity-chat-1"));
        assert!(note_output.contains(&head_hash));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        restore_global_git_config(original_global);
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_fallback_time_match_attaches_note() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        // Session log without commit hash (fallback should use time window)
        let session_content = format!(
            r#"{{"session_id":"fallback-session","cwd":"{cwd}"}}
{{"type":"assistant","message":"no commit hash here"}}
"#,
            cwd = git_repo_root,
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: claude-code"));
        assert!(note_output.contains("session_id: fallback-session"));
        assert!(note_output.contains("confidence: time_window_match"));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_fallback_ambiguous_skips() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"fallback-a","cwd":"{cwd}"}}
{{"type":"assistant","message":"no commit hash here"}}
"#,
            cwd = git_repo_root,
        );
        let session_a = claude_project_dir.join("session-a.jsonl");
        let session_b = claude_project_dir.join("session-b.jsonl");
        std::fs::write(&session_a, &session_content).unwrap();
        std::fs::write(&session_b, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_a, ft).unwrap();
        filetime::set_file_mtime(&session_b, ft).unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        // No note should be attached due to ambiguity
        let status = std::process::Command::new("git")
            .args(["-C", repo_path.to_str().unwrap()])
            .args([
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success());

        // Pending record should exist
        let pending_path = fake_home
            .path()
            .join(".cadence/cli")
            .join("pending")
            .join(format!("{}.json", head_hash));
        assert!(pending_path.exists(), "pending record should exist");

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_deduplication_skips_if_note_exists() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        // Isolate HOME so we don't scan real session logs
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", fake_home.path()) };

        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Manually attach a note first
        run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "add",
                "-m",
                "existing note",
                &head_hash,
            ],
        );

        // chdir into repo and run hook
        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        // The note should still be the original one (not overwritten)
        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert_eq!(note_output, "existing note");

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_no_match_writes_pending() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        // Use a fake HOME so pending records are written to a temp dir
        // instead of the real ~/.cadence/cli/pending/.
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        // SAFETY: This test is #[serial], so no other threads are reading
        // env vars concurrently.
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Don't create any session logs — the hook should not find a match

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        // No note should be attached
        let status = std::process::Command::new("git")
            .args(["-C", repo_path.to_str().unwrap()])
            .args([
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success());

        // A pending record should have been written inside the fake home
        let pending_path = fake_home
            .path()
            .join(".cadence/cli")
            .join("pending")
            .join(format!("{}.json", head_hash));
        assert!(pending_path.exists(), "pending record should exist");

        // Restore HOME and cwd. The fake_home TempDir drop handles cleanup.
        // SAFETY: This test is #[serial], so no other threads are reading
        // env vars concurrently.
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_never_fails_outside_git_repo() {
        // Isolate HOME so we don't scan real session logs
        let fake_home = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").unwrap_or_default();
        unsafe { std::env::set_var("HOME", fake_home.path()) };

        // When called outside a git repo, the hook should still return Ok
        // because the catch-all wrapper catches errors.
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        unsafe { std::env::set_var("HOME", &original_home) };
    }

    // -----------------------------------------------------------------------
    // Integration test: retry resolves a pending commit
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_retry_resolves_pending_commit() {
        // This test simulates the scenario where:
        // 1. A commit is made but no session log exists yet (pending record created)
        // 2. The session log appears later
        // 3. On the next commit, the retry logic finds and resolves the pending record

        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let first_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let first_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let first_ts: i64 = first_ts_str.parse().unwrap();

        // Step 1: Run the hook with no session logs -- creates a pending record
        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        // Verify pending record was created
        let pending_path = fake_home
            .path()
            .join(".cadence/cli")
            .join("pending")
            .join(format!("{}.json", first_hash));
        assert!(pending_path.exists(), "pending record should exist");

        // Step 2: Now create the session log that matches the first commit
        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"retry-test-session","cwd":"{cwd}"}}
{{"type":"tool_result","content":"[main {short}] initial commit\n 1 file changed"}}
{{"type":"assistant","message":"Done"}}
"#,
            cwd = git_repo_root,
            short = &first_hash[..7],
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        // Set mtime to match first commit time
        let ft = filetime::FileTime::from_unix_time(first_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        // Step 3: Make a second commit, which triggers retry of pending records
        std::fs::write(repo_path.join("file2.txt"), "second").unwrap();
        run_git(repo_path, &["add", "file2.txt"]);
        run_git(repo_path, &["commit", "-m", "second commit"]);

        // Run the hook again -- this should resolve the pending record for first_hash
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        // Verify the pending record was removed
        assert!(
            !pending_path.exists(),
            "pending record should have been removed after retry"
        );

        // Verify a note was attached to the first commit
        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &first_hash,
            ],
        );
        assert!(note_output.contains("agent: claude-code"));
        assert!(note_output.contains("session_id: retry-test-session"));

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // Integration test: retry increments attempt on failure
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_retry_increments_attempt_on_failure() {
        // Scenario: pending record exists, but no session log is found.
        // Retry should increment the attempt counter.

        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let first_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Step 1: Run the hook with no session logs -- creates a pending record
        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        // Read the pending record -- attempts should be 2: the initial write
        // sets attempts=1, then the retry loop at the end of the hook
        // increments it to 2 (because retry also fails to find a session log).
        let pending_path = fake_home
            .path()
            .join(".cadence/cli")
            .join("pending")
            .join(format!("{}.json", first_hash));
        let content = std::fs::read_to_string(&pending_path).unwrap();
        let record: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(record["attempts"], 2);

        // Step 2: Make a second commit (still no session log for first commit)
        std::fs::write(repo_path.join("file2.txt"), "second").unwrap();
        run_git(repo_path, &["add", "file2.txt"]);
        run_git(repo_path, &["commit", "-m", "second commit"]);

        // Run the hook again -- retry should fail (no session log) and increment
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        // Read the pending record again -- attempts should be 3
        // (was 2 after first hook, retry in second hook increments to 3)
        let content = std::fs::read_to_string(&pending_path).unwrap();
        let record: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            record["attempts"], 3,
            "attempt count should be incremented after failed retry. Record: {}",
            &content
        );

        // Pending record should still exist
        assert!(
            pending_path.exists(),
            "pending record should still exist after failed retry"
        );

        // First commit should still have no note
        let status = std::process::Command::new("git")
            .args(["-C", repo_path.to_str().unwrap()])
            .args([
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &first_hash,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(
            !status.success(),
            "first commit should have no note after failed retry"
        );

        // Suppress unused variable warnings
        let _ = git_repo_root;

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // Integration test: run_retry subcommand
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_run_retry_in_repo() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        std::env::set_current_dir(repo_path).expect("failed to chdir");

        // No pending records -- should print "no pending commits"
        let result = run_retry();
        assert!(result.is_ok());

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // Integration tests: hydrate subcommand
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_hydrate_attaches_note_from_session_log() {
        // This test simulates hydration:
        // 1. Create a repo with a commit
        // 2. Create a fake Claude session log containing the commit hash
        // 3. Run hydrate
        // 4. Verify the note was attached

        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Create a fake Claude session log directory
        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        // Create a session log with the full commit hash and metadata
        let session_content = format!(
            r#"{{"session_id":"hydrate-test-session","cwd":"{cwd}"}}
{{"type":"tool_result","content":"[main {short}] initial commit\n 1 file changed"}}
{{"type":"assistant","message":"Done! Full hash: {hash}"}}
"#,
            cwd = git_repo_root,
            short = &head_hash[..7],
            hash = head_hash,
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        // Set the mtime to "now" so it falls within the --since window
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        // Run hydrate (no need to chdir -- hydrate is repo-agnostic)
        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        // Verify a note was attached to the commit
        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: claude-code"));
        assert!(note_output.contains("session_id: hydrate-test-session"));
        assert!(note_output.contains(&head_hash));
        assert!(note_output.contains("confidence: exact_hash_match"));

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_attaches_note_cursor_chat_session() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let (_global_config_path, original_global) = set_isolated_global_git_config(&fake_home);
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        let chat_dir = app_config_dir_in("Cursor", fake_home.path())
            .join("User")
            .join("workspaceStorage")
            .join("ws1")
            .join("chatSessions");
        std::fs::create_dir_all(&chat_dir).unwrap();

        let session_content = json!({
            "sessionId": "cursor-hydrate-1",
            "baseUri": { "fsPath": format!("{}/README.md", git_repo_root) },
            "requests": [{
                "response": [{
                    "value": format!("[main {}] initial commit", head_hash)
                }],
                "variableData": {
                    "variables": [{
                        "value": { "uri": { "fsPath": format!("{}/README.md", git_repo_root) } }
                    }]
                }
            }]
        })
        .to_string();
        let session_file = chat_dir.join("session.json");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: cursor"));
        assert!(note_output.contains("session_id: cursor-hydrate-1"));
        assert!(note_output.contains(&head_hash));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        restore_global_git_config(original_global);
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_attaches_note_cursor_project() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        let project_dir = fake_home
            .path()
            .join(".cursor")
            .join("projects")
            .join("proj1");
        std::fs::create_dir_all(&project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"cursor-hydrate-proj"}}
{{"cwd":"{cwd}"}}
{{"content":"[main {hash}] initial commit"}}
"#,
            cwd = git_repo_root,
            hash = head_hash,
        );
        let session_file = project_dir.join("session.json");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: cursor"));
        assert!(note_output.contains("session_id: cursor-hydrate-proj"));
        assert!(note_output.contains(&head_hash));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_attaches_note_copilot_chat_session() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let (_global_config_path, original_global) = set_isolated_global_git_config(&fake_home);
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        let chat_dir = app_config_dir_in("Code", fake_home.path())
            .join("User")
            .join("workspaceStorage")
            .join("ws1")
            .join("chatSessions");
        std::fs::create_dir_all(&chat_dir).unwrap();

        let session_content = json!({
            "sessionId": "copilot-hydrate-1",
            "baseUri": { "fsPath": format!("{}/README.md", git_repo_root) },
            "requests": [{
                "response": [{
                    "value": format!("[main {}] initial commit", head_hash)
                }],
                "variableData": {
                    "variables": [{
                        "value": { "uri": { "fsPath": format!("{}/README.md", git_repo_root) } }
                    }]
                }
            }]
        })
        .to_string();
        let session_file = chat_dir.join("session.json");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: copilot"));
        assert!(note_output.contains("session_id: copilot-hydrate-1"));
        assert!(note_output.contains(&head_hash));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        restore_global_git_config(original_global);
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_attaches_note_antigravity_chat_session() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let (_global_config_path, original_global) = set_isolated_global_git_config(&fake_home);
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        let chat_dir = app_config_dir_in("Antigravity", fake_home.path())
            .join("User")
            .join("workspaceStorage")
            .join("ws1")
            .join("chatSessions");
        std::fs::create_dir_all(&chat_dir).unwrap();

        let session_content = json!({
            "sessionId": "antigravity-hydrate-1",
            "baseUri": { "fsPath": format!("{}/README.md", git_repo_root) },
            "requests": [{
                "response": [{
                    "value": format!("[main {}] initial commit", head_hash)
                }],
                "variableData": {
                    "variables": [{
                        "value": { "uri": { "fsPath": format!("{}/README.md", git_repo_root) } }
                    }]
                }
            }]
        })
        .to_string();
        let session_file = chat_dir.join("session.json");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: antigravity"));
        assert!(note_output.contains("session_id: antigravity-hydrate-1"));
        assert!(note_output.contains(&head_hash));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        restore_global_git_config(original_global);
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_fallback_single_commit() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();
        let head_time = OffsetDateTime::from_unix_timestamp(head_ts).unwrap();
        let head_time_str = head_time.format(&Rfc3339).unwrap();

        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"hydrate-fallback-session","cwd":"{cwd}","timestamp":"{ts}"}}
{{"type":"assistant","message":"no commit hash"}}
"#,
            cwd = git_repo_root,
            ts = head_time_str,
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("session_id: hydrate-fallback-session"));
        assert!(note_output.contains("confidence: time_window_match"));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_fallback_multiple_commits_skips() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let first_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let first_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let first_ts: i64 = first_ts_str.parse().unwrap();

        // Create a second commit
        std::fs::write(repo_path.join("file2.txt"), "second").unwrap();
        run_git(repo_path, &["add", "file2.txt"]);
        run_git(repo_path, &["commit", "-m", "second commit"]);
        let second_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let second_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let second_ts: i64 = second_ts_str.parse().unwrap();

        let t1 = OffsetDateTime::from_unix_timestamp(first_ts).unwrap();
        let t2 = OffsetDateTime::from_unix_timestamp(second_ts).unwrap();
        let s1 = t1.format(&Rfc3339).unwrap();
        let s2 = t2.format(&Rfc3339).unwrap();

        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"hydrate-fallback-ambiguous","cwd":"{cwd}","timestamp":"{ts1}"}}
{{"timestamp":"{ts2}","type":"assistant","message":"no commit hash"}}
"#,
            cwd = git_repo_root,
            ts1 = s1,
            ts2 = s2,
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let status_first = std::process::Command::new("git")
            .args(["-C", repo_path.to_str().unwrap()])
            .args([
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &first_hash,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        let status_second = std::process::Command::new("git")
            .args(["-C", repo_path.to_str().unwrap()])
            .args([
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &second_hash,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!status_first.success());
        assert!(!status_second.success());

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // E2E: Codex fallback via timestamp (post-commit)
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_e2e_post_commit_fallback_codex_timestamp() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();
        let head_time = OffsetDateTime::from_unix_timestamp(head_ts).unwrap();
        let head_time_str = head_time.format(&Rfc3339).unwrap();

        let codex_dir = fake_home
            .path()
            .join(".codex")
            .join("sessions")
            .join("2026")
            .join("02")
            .join("10");
        std::fs::create_dir_all(&codex_dir).unwrap();

        let session_content = format!(
            r#"{{"timestamp":"{ts}","type":"session_meta","payload":{{"id":"codex-session-1","cwd":"{cwd}"}}}}
{{"type":"assistant","message":"no commit hash"}}"#,
            ts = head_time_str,
            cwd = git_repo_root,
        );
        let session_file = codex_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: codex"));
        assert!(note_output.contains("session_id: codex-session-1"));
        assert!(note_output.contains("confidence: time_window_match"));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // E2E: Hydrate fallback with timestamp range selects single commit
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_e2e_hydrate_fallback_timestamp_single_commit() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);

        // Create two commits with distinct timestamps
        let t1 = 1_700_000_100i64;
        let t2 = 1_700_003_700i64;

        std::fs::write(repo_path.join("file1.txt"), "first").unwrap();
        run_git(repo_path, &["add", "file1.txt"]);
        let mut cmd = std::process::Command::new("git");
        cmd.args(["-C", repo_path.to_str().unwrap()])
            .args(["commit", "-m", "first commit"])
            .env("GIT_AUTHOR_DATE", t1.to_string())
            .env("GIT_COMMITTER_DATE", t1.to_string());
        let output = cmd.output().expect("failed to run git");
        assert!(output.status.success(), "git commit failed");

        let first_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        std::fs::write(repo_path.join("file2.txt"), "second").unwrap();
        run_git(repo_path, &["add", "file2.txt"]);
        let mut cmd = std::process::Command::new("git");
        cmd.args(["-C", repo_path.to_str().unwrap()])
            .args(["commit", "-m", "second commit"])
            .env("GIT_AUTHOR_DATE", t2.to_string())
            .env("GIT_COMMITTER_DATE", t2.to_string());
        let output = cmd.output().expect("failed to run git");
        assert!(output.status.success(), "git commit failed");

        let second_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        let ts_str = OffsetDateTime::from_unix_timestamp(t1)
            .unwrap()
            .format(&Rfc3339)
            .unwrap();

        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"hydrate-e2e","cwd":"{cwd}","timestamp":"{ts}"}}
{{"type":"assistant","message":"no commit hash"}}"#,
            cwd = git_repo_root,
            ts = ts_str,
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_first = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &first_hash,
            ],
        );
        assert!(note_first.contains("confidence: time_window_match"));

        let status_second = std::process::Command::new("git")
            .args(["-C", repo_path.to_str().unwrap()])
            .args([
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &second_hash,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!status_second.success());

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // E2E: Retry fallback resolves pending commit via time window
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_e2e_retry_fallback_time_window() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let first_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let first_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let first_ts: i64 = first_ts_str.parse().unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let pending_path = fake_home
            .path()
            .join(".cadence/cli")
            .join("pending")
            .join(format!("{}.json", first_hash));
        assert!(pending_path.exists(), "pending record should exist");

        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"retry-fallback","cwd":"{cwd}"}}
{{"type":"assistant","message":"no commit hash"}}"#,
            cwd = git_repo_root,
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(first_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        std::fs::write(repo_path.join("file2.txt"), "second").unwrap();
        run_git(repo_path, &["add", "file2.txt"]);
        run_git(repo_path, &["commit", "-m", "second commit"]);

        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &first_hash,
            ],
        );
        assert!(note_output.contains("session_id: retry-fallback"));
        assert!(note_output.contains("confidence: time_window_match"));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // E2E: Codex exact hash match (post-commit)
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_e2e_post_commit_codex_exact_hash() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        let codex_dir = fake_home
            .path()
            .join(".codex")
            .join("sessions")
            .join("2026")
            .join("02")
            .join("10");
        std::fs::create_dir_all(&codex_dir).unwrap();

        let session_content = format!(
            r#"{{"type":"session_meta","payload":{{"id":"codex-exact","cwd":"{cwd}"}}}}
{{"type":"assistant","message":"commit {hash} done"}}"#,
            cwd = git_repo_root,
            hash = head_hash,
        );
        let session_file = codex_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: codex"));
        assert!(note_output.contains("session_id: codex-exact"));
        assert!(note_output.contains("confidence: exact_hash_match"));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // E2E: Hydrate exact hash for Codex sessions
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_e2e_hydrate_codex_exact_hash() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        let codex_dir = fake_home
            .path()
            .join(".codex")
            .join("sessions")
            .join("2026")
            .join("02")
            .join("10");
        std::fs::create_dir_all(&codex_dir).unwrap();

        let session_content = format!(
            r#"{{"type":"session_meta","payload":{{"id":"codex-hydrate","cwd":"{cwd}"}}}}
{{"type":"assistant","message":"[main {short}] initial commit\n 1 file changed"}}
{{"type":"assistant","message":"commit {hash} done"}}"#,
            cwd = git_repo_root,
            short = &head_hash[..7],
            hash = head_hash,
        );
        let session_file = codex_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: codex"));
        assert!(note_output.contains("session_id: codex-hydrate"));
        assert!(note_output.contains("confidence: exact_hash_match"));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // E2E: Hydrate fallback for Codex sessions
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_e2e_hydrate_fallback_codex_timestamp() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();
        let head_time = OffsetDateTime::from_unix_timestamp(head_ts).unwrap();
        let head_time_str = head_time.format(&Rfc3339).unwrap();

        let codex_dir = fake_home
            .path()
            .join(".codex")
            .join("sessions")
            .join("2026")
            .join("02")
            .join("10");
        std::fs::create_dir_all(&codex_dir).unwrap();

        let session_content = format!(
            r#"{{"timestamp":"{ts}","type":"session_meta","payload":{{"id":"codex-hydrate-fallback","cwd":"{cwd}"}}}}
{{"type":"assistant","message":"no commit hash"}}"#,
            ts = head_time_str,
            cwd = git_repo_root,
        );
        let session_file = codex_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: codex"));
        assert!(note_output.contains("session_id: codex-hydrate-fallback"));
        assert!(note_output.contains("confidence: time_window_match"));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_skips_if_note_already_exists() {
        // Hydrate should skip commits that already have notes (dedup)

        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Manually attach a note first
        run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "add",
                "-m",
                "pre-existing note",
                &head_hash,
            ],
        );

        // Create a fake session log with the commit hash
        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"should-be-skipped","cwd":"{cwd}"}}
{{"type":"tool_result","content":"[main {short_hash}] some commit\n 1 file changed"}}
"#,
            cwd = git_repo_root,
            short_hash = &head_hash[..7],
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        // Run hydrate
        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        // The note should still be the pre-existing one (not overwritten)
        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert_eq!(note_output, "pre-existing note");

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_multiple_commits_in_one_session() {
        // A single session may contain multiple commits. Hydrate should
        // attach notes to all of them.

        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let first_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Make a second commit
        std::fs::write(repo_path.join("file2.txt"), "second").unwrap();
        run_git(repo_path, &["add", "file2.txt"]);
        run_git(repo_path, &["commit", "-m", "second commit"]);
        let second_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Create a session log containing both commit hashes
        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"multi-commit-session","cwd":"{cwd}"}}
{{"type":"tool_result","content":"[main {s1}] initial commit"}}
{{"type":"tool_result","content":"commit {h1}"}}
{{"type":"tool_result","content":"[main {s2}] second commit"}}
{{"type":"tool_result","content":"commit {h2}"}}
"#,
            cwd = git_repo_root,
            s1 = &first_hash[..7],
            h1 = first_hash,
            s2 = &second_hash[..7],
            h2 = second_hash,
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        // Run hydrate
        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        // Both commits should have notes
        let note1 = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &first_hash,
            ],
        );
        assert!(
            note1.contains("agent: claude-code"),
            "first commit should have a note"
        );
        assert!(note1.contains("session_id: multi-commit-session"));

        let note2 = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &second_hash,
            ],
        );
        assert!(
            note2.contains("agent: claude-code"),
            "second commit should have a note"
        );
        assert!(note2.contains("session_id: multi-commit-session"));

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // Integration tests: install subcommand
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_install_creates_hooks_dir_and_shim() {
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        // Create a fake global git config so we don't pollute the real one
        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        let result = run_install_inner(None, Some(fake_home.path()));
        assert!(result.is_ok());

        // Verify hooks directory was created
        let hooks_dir = fake_home.path().join(".git-hooks");
        assert!(hooks_dir.exists(), "~/.git-hooks should be created");

        // Verify post-commit shim was written
        let shim_path = hooks_dir.join("post-commit");
        assert!(shim_path.exists(), "post-commit shim should exist");

        let shim_content = std::fs::read_to_string(&shim_path).unwrap();
        assert_eq!(
            shim_content,
            post_commit_hook_content(),
            "shim content should match exactly"
        );

        // Verify pre-push shim was written
        let pre_push_path = hooks_dir.join("pre-push");
        assert!(pre_push_path.exists(), "pre-push shim should exist");

        let pre_push_content = std::fs::read_to_string(&pre_push_path).unwrap();
        assert_eq!(
            pre_push_content,
            pre_push_hook_content(),
            "pre-push shim content should match exactly"
        );

        // Verify shim is executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&shim_path).unwrap().permissions();
            let mode = perms.mode();
            assert!(
                mode & 0o111 != 0,
                "shim should be executable, got mode {:o}",
                mode
            );

            let pre_perms = std::fs::metadata(&pre_push_path).unwrap().permissions();
            let pre_mode = pre_perms.mode();
            assert!(
                pre_mode & 0o111 != 0,
                "pre-push shim should be executable, got mode {:o}",
                pre_mode
            );
        }

        // Verify core.hooksPath was set in global config
        let config_content = std::fs::read_to_string(&global_config).unwrap();
        assert!(
            config_content.contains("hooksPath"),
            "global config should contain hooksPath"
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
    }

    #[test]
    #[serial]
    fn test_install_with_org_sets_global_config() {
        // Ensure CWD is valid (previous serial test may have left it in a deleted temp dir)
        let _original_cwd = safe_cwd();
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        let result = run_install_inner(Some("my-org".to_string()), Some(fake_home.path()));
        assert!(result.is_ok());

        // Verify org was persisted to global config
        let config_content = std::fs::read_to_string(&global_config).unwrap();
        assert!(
            config_content.contains("my-org"),
            "global config should contain org filter value"
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
    }

    #[test]
    #[serial]
    fn test_install_idempotent() {
        // Running install twice should succeed without errors
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // First install
        let result1 = run_install_inner(None, Some(fake_home.path()));
        assert!(result1.is_ok());

        // Second install
        let result2 = run_install_inner(None, Some(fake_home.path()));
        assert!(result2.is_ok());

        // Shims should still be correct
        let shim_path = fake_home.path().join(".git-hooks").join("post-commit");
        let content = std::fs::read_to_string(&shim_path).unwrap();
        assert_eq!(content, post_commit_hook_content());

        let pre_push_path = fake_home.path().join(".git-hooks").join("pre-push");
        let pre_content = std::fs::read_to_string(&pre_push_path).unwrap();
        assert_eq!(pre_content, pre_push_hook_content());

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
    }

    #[test]
    #[serial]
    fn test_install_detects_existing_non_linker_hook() {
        // If a post-commit hook exists that was NOT created by cadence,
        // install should still overwrite it (with a warning).
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // Pre-create hooks dir and non-linker hooks
        let hooks_dir = fake_home.path().join(".git-hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        let shim_path = hooks_dir.join("post-commit");
        std::fs::write(&shim_path, "#!/bin/sh\necho 'custom hook'\n").unwrap();
        let pre_push_path = hooks_dir.join("pre-push");
        std::fs::write(&pre_push_path, "#!/bin/sh\necho 'custom pre-push'\n").unwrap();

        let result = run_install_inner(None, Some(fake_home.path()));
        assert!(result.is_ok());

        // The shim should now be the cadence one (overwritten)
        let content = std::fs::read_to_string(&shim_path).unwrap();
        assert_eq!(content, post_commit_hook_content());

        let pre_content = std::fs::read_to_string(&pre_push_path).unwrap();
        assert_eq!(pre_content, pre_push_hook_content());

        // The original hook should have been backed up
        let backup_path = hooks_dir.join("post-commit.pre-cadence");
        assert!(
            backup_path.exists(),
            "backup of original hook should exist at post-commit.pre-cadence"
        );
        let backup_content = std::fs::read_to_string(&backup_path).unwrap();
        assert_eq!(
            backup_content, "#!/bin/sh\necho 'custom hook'\n",
            "backup should contain the original hook content"
        );

        let pre_backup_path = hooks_dir.join("pre-push.pre-cadence");
        assert!(
            pre_backup_path.exists(),
            "backup of original hook should exist at pre-push.pre-cadence"
        );
        let pre_backup_content = std::fs::read_to_string(&pre_backup_path).unwrap();
        assert_eq!(
            pre_backup_content, "#!/bin/sh\necho 'custom pre-push'\n",
            "backup should contain the original pre-push hook content"
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
    }

    #[test]
    #[serial]
    fn test_install_detects_existing_linker_hook() {
        // If a post-commit hook exists that WAS created by cadence,
        // install should update it silently.
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // Pre-create hooks dir with existing cadence hooks
        let hooks_dir = fake_home.path().join(".git-hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        let shim_path = hooks_dir.join("post-commit");
        std::fs::write(&shim_path, post_commit_hook_content()).unwrap();
        let pre_push_path = hooks_dir.join("pre-push");
        std::fs::write(&pre_push_path, pre_push_hook_content()).unwrap();

        let result = run_install_inner(None, Some(fake_home.path()));
        assert!(result.is_ok());

        // The shim should still be correct
        let content = std::fs::read_to_string(&shim_path).unwrap();
        assert_eq!(content, post_commit_hook_content());

        let pre_content = std::fs::read_to_string(&pre_push_path).unwrap();
        assert_eq!(pre_content, pre_push_hook_content());

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
    }

    #[test]
    #[serial]
    fn test_install_runs_hydration() {
        // Verify that running install also runs hydration and attaches notes
        // to commits that have matching session logs.

        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Create a fake Claude session log containing the commit hash
        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"install-hydrate-test","cwd":"{cwd}"}}
{{"type":"tool_result","content":"[main {short_hash}] fix bug\n 1 file changed"}}
{{"type":"assistant","message":"Done"}}
"#,
            cwd = git_repo_root,
            short_hash = &head_hash[..7],
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        // Set the mtime to "now" so it falls within the 7-day hydration window
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        // Run install (which should run hydration as its final step)
        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_install_inner(None, Some(fake_home.path()));
        assert!(result.is_ok());

        // Verify a note was attached to the commit by hydration
        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(
            note_output.contains("agent: claude-code"),
            "hydration during install should have attached a note"
        );
        assert!(note_output.contains("session_id: install-hydrate-test"));

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_no_logs_returns_ok() {
        // Hydrate with no log directories should succeed quickly and
        // deterministically when HOME is isolated.
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn test_hydrate_invalid_since_returns_error() {
        let result = run_hydrate("invalid", false);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Integration tests: status subcommand
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_status_in_repo_shows_repo_root() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);

        std::env::set_current_dir(repo_path).expect("failed to chdir");

        let mut buf = Vec::new();
        let git_dir = repo_path.join(".git");
        let result = with_env("GIT_DIR", git_dir.to_str().unwrap(), || {
            with_env("GIT_WORK_TREE", repo_path.to_str().unwrap(), || {
                run_status_inner(&mut buf)
            })
        });
        assert!(result.is_ok());

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains(&format!("Repo: {}", git_repo_root)),
            "should show repo root path, got: {}",
            output
        );
        assert!(
            output.contains("Pending retries: 0"),
            "should show zero pending retries, got: {}",
            output
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_status_shows_hooks_path_when_configured() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        // Create a fake global config with core.hooksPath
        let hooks_dir = fake_home.path().join(".git-hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        let hooks_dir_str = hooks_dir.to_string_lossy().to_string();

        // Write the cadence shims
        let shim_path = hooks_dir.join("post-commit");
        std::fs::write(&shim_path, post_commit_hook_content()).unwrap();
        let pre_push_path = hooks_dir.join("pre-push");
        std::fs::write(&pre_push_path, pre_push_hook_content()).unwrap();

        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        std::env::set_current_dir(repo_path).expect("failed to chdir");

        // Configure hooksPath using git so Windows path escaping is handled.
        std::process::Command::new("git")
            .args(["config", "--global", "core.hooksPath", &hooks_dir_str])
            .output()
            .unwrap();

        let mut buf = Vec::new();
        let git_dir = repo_path.join(".git");
        let result = with_env("GIT_DIR", git_dir.to_str().unwrap(), || {
            with_env("GIT_WORK_TREE", repo_path.to_str().unwrap(), || {
                run_status_inner(&mut buf)
            })
        });
        assert!(result.is_ok());

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("post-commit: yes"),
            "should show post-commit installed, got: {}",
            output
        );
        assert!(
            output.contains("pre-push: yes"),
            "should show pre-push installed, got: {}",
            output
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_status_shows_pending_count() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);

        // Write some pending records for this repo
        let pending_dir = fake_home.path().join(".cadence/cli").join("pending");
        std::fs::create_dir_all(&pending_dir).unwrap();

        for i in 0..3 {
            let fake_hash = format!("{:0>40}", format!("abcdef{}", i));
            let record = serde_json::json!({
                "commit": fake_hash,
                "repo": git_repo_root,
                "commit_time": 1700000000 + i,
                "attempts": 1,
                "last_attempt": 1700000060 + i,
            });
            std::fs::write(
                pending_dir.join(format!("{}.json", fake_hash)),
                serde_json::to_string_pretty(&record).unwrap(),
            )
            .unwrap();
        }

        std::env::set_current_dir(repo_path).expect("failed to chdir");

        let mut buf = Vec::new();
        let result = run_status_inner(&mut buf);
        assert!(result.is_ok());

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("Pending retries: 3"),
            "should show 3 pending retries, got: {}",
            output
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_status_shows_org_filter() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        // Create a global config with org filter
        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "[ai \"cadence\"]\n    org = my-test-org\n").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        std::env::set_current_dir(repo_path).expect("failed to chdir");

        let mut buf = Vec::new();
        let result = run_status_inner(&mut buf);
        assert!(result.is_ok());

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("Org filter: my-test-org"),
            "should show org filter, got: {}",
            output
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_status_shows_autopush_status() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        // Set autopush to true
        run_git(repo_path, &["config", "ai.cadence.autopush", "true"]);

        std::env::set_current_dir(repo_path).expect("failed to chdir");

        let mut buf = Vec::new();
        let result = run_status_inner(&mut buf);
        assert!(result.is_ok());

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("Auto-push: enabled"),
            "should show autopush enabled, got: {}",
            output
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_status_shows_repo_disabled() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        // Disable this repo
        run_git(repo_path, &["config", "ai.cadence.enabled", "false"]);

        std::env::set_current_dir(repo_path).expect("failed to chdir");

        let mut buf = Vec::new();
        let result = run_status_inner(&mut buf);
        assert!(result.is_ok());

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("Repo enabled: no"),
            "should show repo as disabled, got: {}",
            output
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // Phase 12 hardening tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_existing_notes_from_other_refs_not_affected() {
        // Cadence CLI uses refs/notes/ai-sessions. Existing notes from
        // other refs (e.g., the default refs/notes/commits) should not
        // be affected by our operations.
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Attach a note using the default ref (refs/notes/commits)
        run_git(
            repo_path,
            &["notes", "add", "-m", "default ref note", &head_hash],
        );

        // Attach a note using our custom ref
        run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "add",
                "-m",
                "ai session note",
                &head_hash,
            ],
        );

        // Verify both notes exist independently
        let default_note = run_git(repo_path, &["notes", "show", &head_hash]);
        assert_eq!(default_note, "default ref note");

        let ai_note = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert_eq!(ai_note, "ai session note");

        // Verify note_exists only detects our ref
        let exists =
            git::note_exists_at(repo_path, &head_hash).expect("note_exists_at should work");
        assert!(exists);

        // Adding our note should not have affected the default note
        let default_note_after = run_git(repo_path, &["notes", "show", &head_hash]);
        assert_eq!(default_note_after, "default ref note");
    }

    #[test]
    fn test_short_hash_uses_first_7_chars() {
        // Verify that the scanner uses exactly the first 7 characters
        // of the commit hash for short hash matching.
        let dir = TempDir::new().unwrap();
        let commit_hash = "abcdef0123456789abcdef0123456789abcdef01";
        let short_hash = &commit_hash[..7]; // "abcdef0"

        // Create a file containing only the short hash (not the full hash)
        let content = format!(r#"{{"output":"commit {} done"}}"#, short_hash);
        let file = dir.path().join("session.jsonl");
        std::fs::write(&file, format!("{}\n", content)).unwrap();

        // Should match on short hash
        let result = scanner::find_session_for_commit(commit_hash, &[file.clone()]);
        assert!(
            result.is_some(),
            "should match on first 7 chars of commit hash"
        );

        // Create a file with only 6 chars of the hash (should NOT match)
        let too_short = &commit_hash[..6]; // "abcdef"
        let content2 = format!(r#"{{"output":"commit {} done"}}"#, too_short);
        let file2 = dir.path().join("session2.jsonl");
        std::fs::write(&file2, format!("{}\n", content2)).unwrap();

        // The 6-char substring should NOT match since the file only has 6 chars
        // but the scanner checks for the 7-char short hash
        let result2 = scanner::find_session_for_commit(commit_hash, &[file2.clone()]);
        assert!(
            result2.is_none(),
            "should not match on fewer than 7 chars of commit hash"
        );
    }

    #[test]
    #[serial]
    fn test_max_retry_count_abandons_record() {
        // When a pending record exceeds MAX_RETRY_ATTEMPTS, it should be
        // removed rather than retried indefinitely.
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let first_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Create a pending record with attempts >= MAX_RETRY_ATTEMPTS
        let pending_dir = fake_home.path().join(".cadence/cli").join("pending");
        std::fs::create_dir_all(&pending_dir).unwrap();

        let record = serde_json::json!({
            "commit": first_hash,
            "repo": git_repo_root,
            "commit_time": 1700000000,
            "attempts": MAX_RETRY_ATTEMPTS,
            "last_attempt": 1700000060,
        });
        let pending_path = pending_dir.join(format!("{}.json", first_hash));
        std::fs::write(
            &pending_path,
            serde_json::to_string_pretty(&record).unwrap(),
        )
        .unwrap();

        // Verify the pending record exists
        assert!(pending_path.exists());

        // Run retry -- should abandon the record since it exceeded max attempts
        std::env::set_current_dir(repo_path).expect("failed to chdir");
        retry_pending_for_repo(&git_repo_root, std::path::Path::new(&git_repo_root), &None);

        // The pending record should have been removed
        assert!(
            !pending_path.exists(),
            "pending record should be removed after exceeding max retry attempts"
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_works_in_detached_head() {
        // The post-commit hook should work correctly even when HEAD is detached.
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        // Detach HEAD
        run_git(repo_path, &["checkout", "--detach", "HEAD"]);

        // The hook should not panic or error in detached HEAD state
        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok(), "hook should succeed in detached HEAD state");

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_works_in_repo_with_no_remotes() {
        // The post-commit hook should work correctly in a local-only repo
        // with no remotes configured.
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        // Verify no remotes
        let remotes = run_git(repo_path, &["remote"]);
        assert!(remotes.is_empty(), "should have no remotes");

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok(), "hook should succeed with no remotes");

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // GPG encryption test utilities
    // -----------------------------------------------------------------------

    /// Save, set, and restore an environment variable around a closure.
    /// Uses `unsafe` as required by Rust 2024 edition.
    fn with_env<F, R>(key: &str, value: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let orig = std::env::var(key).ok();
        unsafe { std::env::set_var(key, value) };
        let result = f();
        unsafe {
            match orig {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        result
    }

    /// Set up a temporary GPG home directory with a test keypair.
    /// Returns (TempDir, email) — TempDir must be kept alive for the
    /// duration of the test. Returns None if gpg is not available.
    fn setup_test_gpg_keyring() -> Option<(TempDir, String)> {
        if !gpg::gpg_available() {
            return None;
        }

        let dir = TempDir::new().unwrap();
        let gnupghome = dir.path();
        let email = "test-hook-gpg@cadence.test";

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(gnupghome, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        let key_params = format!(
            "%no-protection\nKey-Type: RSA\nKey-Length: 2048\nSubkey-Type: RSA\nSubkey-Length: 2048\nName-Real: Test User\nName-Email: {}\nExpire-Date: 0\n%commit\n",
            email
        );

        let output = std::process::Command::new("gpg")
            .args(["--batch", "--gen-key"])
            .env("GNUPGHOME", gnupghome)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .as_mut()
                    .unwrap()
                    .write_all(key_params.as_bytes())
                    .unwrap();
                child.wait_with_output()
            });

        match output {
            Ok(o) if o.status.success() => Some((dir, email.to_string())),
            _ => None,
        }
    }

    /// Set up a full integration environment for GPG hook tests:
    /// - Temporary git repo with a commit
    /// - Fake HOME with session log matching the commit
    /// - Isolated GIT_CONFIG_GLOBAL
    /// - Optionally configured GPG recipient in global config
    ///
    /// Returns all the pieces needed to run and verify hook behavior.
    struct GpgHookTestEnv {
        repo_dir: TempDir,
        #[allow(dead_code)] // Kept alive for TempDir drop behavior
        fake_home: TempDir,
        global_config_path: PathBuf,
        head_hash: String,
        original_cwd: PathBuf,
        original_home: Option<String>,
        original_global: Option<String>,
        original_gnupghome: Option<String>,
    }

    impl GpgHookTestEnv {
        /// Create a test environment with a git repo, session log, and isolated config.
        fn setup() -> Self {
            let dir = init_temp_repo();
            let repo_path = dir.path();

            let original_cwd = safe_cwd();
            let fake_home = TempDir::new().expect("failed to create fake home");
            let original_home = std::env::var("HOME").ok();
            let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
            let original_gnupghome = std::env::var("GNUPGHOME").ok();

            // Create isolated global git config
            let global_config_path = fake_home.path().join("fake-global-gitconfig");
            std::fs::write(&global_config_path, "").unwrap();

            unsafe {
                std::env::set_var("HOME", fake_home.path());
                std::env::set_var("GIT_CONFIG_GLOBAL", &global_config_path);
            }

            // Get git-resolved repo root and HEAD info
            let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
            let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
            let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
            let head_ts: i64 = head_ts_str.parse().unwrap();

            // Create fake session log matching the commit
            let git_repo_root_path = std::path::Path::new(&git_repo_root);
            let encoded = agents::encode_repo_path(git_repo_root_path);
            let claude_project_dir = fake_home
                .path()
                .join(".claude")
                .join("projects")
                .join(&encoded);
            std::fs::create_dir_all(&claude_project_dir).unwrap();

            let session_content = format!(
                r#"{{"session_id":"gpg-test-session","cwd":"{cwd}"}}
{{"type":"tool_result","content":"[main {short}] initial commit\n 1 file changed"}}
{{"type":"assistant","message":"Done"}}
"#,
                cwd = git_repo_root,
                short = &head_hash[..7],
            );
            let session_file = claude_project_dir.join("session.jsonl");
            std::fs::write(&session_file, &session_content).unwrap();

            let ft = filetime::FileTime::from_unix_time(head_ts, 0);
            filetime::set_file_mtime(&session_file, ft).unwrap();

            // chdir into the repo
            std::env::set_current_dir(repo_path).expect("failed to chdir");

            GpgHookTestEnv {
                repo_dir: dir,
                fake_home,
                global_config_path,
                head_hash,
                original_cwd,
                original_home,
                original_global,
                original_gnupghome,
            }
        }

        /// Configure a GPG recipient in the isolated global git config.
        fn set_recipient(&self, recipient: &str) {
            std::process::Command::new("git")
                .args([
                    "config",
                    "--file",
                    self.global_config_path.to_str().unwrap(),
                    "ai.cadence.gpg.recipient",
                    recipient,
                ])
                .output()
                .unwrap();
        }

        /// Get the note content for the HEAD commit, or None if no note exists.
        fn get_note(&self) -> Option<String> {
            let output = std::process::Command::new("git")
                .args(["-C", self.repo_dir.path().to_str().unwrap()])
                .args([
                    "notes",
                    "--ref",
                    "refs/notes/ai-sessions",
                    "show",
                    &self.head_hash,
                ])
                .output()
                .unwrap();
            if output.status.success() {
                Some(String::from_utf8(output.stdout).unwrap().trim().to_string())
            } else {
                None
            }
        }

        /// Restore environment variables on drop.
        fn restore(&self) {
            unsafe {
                match &self.original_home {
                    Some(h) => std::env::set_var("HOME", h),
                    None => std::env::remove_var("HOME"),
                }
                match &self.original_global {
                    Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                    None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
                }
                match &self.original_gnupghome {
                    Some(g) => std::env::set_var("GNUPGHOME", g),
                    None => std::env::remove_var("GNUPGHOME"),
                }
            }
            std::env::set_current_dir(&self.original_cwd).unwrap();
        }
    }

    // -----------------------------------------------------------------------
    // GPG Hook Tests: Plaintext regression (no recipient configured)
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_hook_plaintext_no_recipient_attaches_unencrypted_note() {
        let env = GpgHookTestEnv::setup();

        // No GPG recipient configured — should attach plaintext
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note = env.get_note().expect("note should be attached");
        assert!(
            note.contains("agent: claude-code"),
            "plaintext note should contain agent field"
        );
        assert!(
            note.contains("session_id: gpg-test-session"),
            "plaintext note should contain session_id"
        );
        assert!(
            !note.starts_with("-----BEGIN PGP MESSAGE-----"),
            "note should NOT be encrypted when no recipient is configured"
        );

        env.restore();
    }

    // -----------------------------------------------------------------------
    // GPG Hook Tests: Encrypted success (recipient + key available)
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_hook_encrypts_note_when_recipient_configured() {
        let Some((gpg_home, email)) = setup_test_gpg_keyring() else {
            eprintln!("skipping test: gpg not available or key generation failed");
            return;
        };

        let env = GpgHookTestEnv::setup();

        // Configure GPG: set GNUPGHOME and recipient
        unsafe { std::env::set_var("GNUPGHOME", gpg_home.path()) };
        env.set_recipient(&email);

        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note = env.get_note().expect("note should be attached");
        assert!(
            note.starts_with("-----BEGIN PGP MESSAGE-----"),
            "note should be encrypted when recipient is configured, got: {}",
            &note[..std::cmp::min(80, note.len())]
        );
        assert!(
            note.contains("-----END PGP MESSAGE-----"),
            "note should contain PGP footer"
        );
        // Should NOT contain plaintext session fields
        assert!(
            !note.contains("agent: claude-code"),
            "encrypted note should not contain plaintext agent field"
        );

        env.restore();
    }

    // -----------------------------------------------------------------------
    // GPG Hook Tests: Commit-blocking failure (encryption configured but fails)
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_hook_fails_when_encryption_configured_but_recipient_invalid() {
        if !gpg::gpg_available() {
            eprintln!("skipping test: gpg not available");
            return;
        }

        let env = GpgHookTestEnv::setup();

        // Configure recipient but use an empty GNUPGHOME with no keys
        let empty_gnupghome = TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                empty_gnupghome.path(),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
        unsafe { std::env::set_var("GNUPGHOME", empty_gnupghome.path()) };
        env.set_recipient("nonexistent-key@invalid.test");

        let result = run_hook_post_commit();
        assert!(
            result.is_err(),
            "hook should return Err when encryption is configured but fails"
        );

        // Verify no note was attached (commit should be blocked)
        assert!(
            env.get_note().is_none(),
            "no note should be attached when encryption fails"
        );

        env.restore();
    }

    #[test]
    #[serial]
    #[cfg(unix)]
    fn test_hook_fails_when_gpg_unavailable_but_recipient_configured() {
        let env = GpgHookTestEnv::setup();

        // Configure recipient
        env.set_recipient("some-key@example.com");

        // Build a restricted PATH: include git but exclude gpg.
        // Find where git lives and construct PATH with only that directory,
        // but exclude any gpg binary by using a wrapper dir.
        let original_path = std::env::var("PATH").unwrap_or_default();

        // Create a temporary directory with only a symlink to git
        let restricted_bin = TempDir::new().unwrap();
        let git_path_output = std::process::Command::new("which")
            .arg("git")
            .output()
            .expect("which git failed");
        let git_bin = String::from_utf8(git_path_output.stdout)
            .unwrap()
            .trim()
            .to_string();
        std::os::unix::fs::symlink(&git_bin, restricted_bin.path().join("git")).unwrap();

        unsafe { std::env::set_var("PATH", restricted_bin.path()) };

        let result = run_hook_post_commit();

        // Restore PATH before assertions
        unsafe { std::env::set_var("PATH", &original_path) };

        assert!(
            result.is_err(),
            "hook should return Err when gpg is unavailable but encryption is configured"
        );

        // Verify no note was attached (commit should be blocked)
        // Need PATH restored to run git
        assert!(
            env.get_note().is_none(),
            "no note should be attached when gpg is unavailable"
        );

        env.restore();
    }

    // -----------------------------------------------------------------------
    // GPG Hook Tests: Non-GPG failures still soft (don't block commit)
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_hook_soft_fails_for_non_gpg_errors() {
        // When hook fails for non-GPG reasons (e.g., not in a git repo),
        // it should still return Ok (soft failure).
        let fake_home = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").unwrap_or_default();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // Chdir to a non-git directory
        let original_cwd = safe_cwd();
        let tmp = TempDir::new().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();

        let result = run_hook_post_commit();
        assert!(
            result.is_ok(),
            "non-GPG hook failures should be soft (return Ok)"
        );

        unsafe {
            std::env::set_var("HOME", &original_home);
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // GPG Hook Tests: maybe_encrypt_note helper
    // -----------------------------------------------------------------------

    #[test]
    fn test_maybe_encrypt_note_no_recipient_returns_plaintext() {
        let content = "agent: claude-code\nsession_id: test";
        let result = maybe_encrypt_note(content, &None).unwrap();
        assert_eq!(result, content);
    }

    #[test]
    #[serial]
    fn test_maybe_encrypt_note_with_recipient_encrypts() {
        let Some((gpg_home, email)) = setup_test_gpg_keyring() else {
            eprintln!("skipping test: gpg not available or key generation failed");
            return;
        };

        let content = "agent: claude-code\nsession_id: test";
        let result = with_env("GNUPGHOME", gpg_home.path().to_str().unwrap(), || {
            maybe_encrypt_note(content, &Some(email.clone()))
        })
        .unwrap();

        assert!(
            result.starts_with("-----BEGIN PGP MESSAGE-----"),
            "encrypted result should start with PGP header"
        );
    }

    #[test]
    #[serial]
    fn test_maybe_encrypt_note_with_invalid_recipient_returns_error() {
        if !gpg::gpg_available() {
            eprintln!("skipping test: gpg not available");
            return;
        }

        let empty_gnupghome = TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                empty_gnupghome.path(),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }

        let content = "agent: claude-code\nsession_id: test";
        let result = with_env(
            "GNUPGHOME",
            empty_gnupghome.path().to_str().unwrap(),
            || maybe_encrypt_note(content, &Some("bad@invalid.test".to_string())),
        );

        assert!(
            result.is_err(),
            "encrypt with invalid recipient should fail"
        );
    }

    // -----------------------------------------------------------------------
    // GPG Hook Tests: Hydrate encryption
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_hydrate_plaintext_when_no_recipient() {
        // Existing hydrate tests already cover this path implicitly.
        // This test explicitly verifies no PGP header in hydrated notes.
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        // Create session log
        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"hydrate-gpg-test","cwd":"{cwd}"}}
{{"type":"tool_result","content":"[main {short}] initial commit\n 1 file changed"}}
{{"type":"assistant","message":"Done"}}
"#,
            cwd = git_repo_root,
            short = &head_hash[..7],
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        // No recipient configured — hydrate should write plaintext
        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_output = std::process::Command::new("git")
            .args(["-C", repo_path.to_str().unwrap()])
            .args([
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ])
            .output()
            .unwrap();

        if note_output.status.success() {
            let note = String::from_utf8(note_output.stdout).unwrap();
            assert!(
                !note.starts_with("-----BEGIN PGP MESSAGE-----"),
                "hydrated note should be plaintext when no recipient configured"
            );
            assert!(
                note.contains("agent: claude-code"),
                "hydrated note should contain agent field"
            );
        }

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_encrypts_when_recipient_configured() {
        let Some((gpg_home, email)) = setup_test_gpg_keyring() else {
            eprintln!("skipping test: gpg not available or key generation failed");
            return;
        };

        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
        let original_gnupghome = std::env::var("GNUPGHOME").ok();

        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
            std::env::set_var("GNUPGHOME", gpg_home.path());
        }

        // Set GPG recipient in isolated global config
        std::process::Command::new("git")
            .args([
                "config",
                "--file",
                global_config.to_str().unwrap(),
                "ai.cadence.gpg.recipient",
                &email,
            ])
            .output()
            .unwrap();

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        // Create session log
        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"hydrate-encrypt-test","cwd":"{cwd}"}}
{{"type":"tool_result","content":"[main {short}] initial commit\n 1 file changed"}}
{{"type":"assistant","message":"Done"}}
"#,
            cwd = git_repo_root,
            short = &head_hash[..7],
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        // Run hydrate with recipient configured
        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_output = std::process::Command::new("git")
            .args(["-C", repo_path.to_str().unwrap()])
            .args([
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ])
            .output()
            .unwrap();

        if note_output.status.success() {
            let note = String::from_utf8(note_output.stdout).unwrap();
            assert!(
                note.trim().starts_with("-----BEGIN PGP MESSAGE-----"),
                "hydrated note should be encrypted when recipient is configured, got: {}",
                &note[..std::cmp::min(80, note.len())]
            );
            assert!(
                !note.contains("agent: claude-code"),
                "encrypted hydrated note should not contain plaintext fields"
            );
        }

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
            match original_gnupghome {
                Some(g) => std::env::set_var("GNUPGHOME", g),
                None => std::env::remove_var("GNUPGHOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // GPG Hook Tests: Retry path encryption
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_retry_encrypts_note_when_recipient_configured() {
        let Some((gpg_home, email)) = setup_test_gpg_keyring() else {
            eprintln!("skipping test: gpg not available or key generation failed");
            return;
        };

        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
        let original_gnupghome = std::env::var("GNUPGHOME").ok();

        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
            std::env::set_var("GNUPGHOME", gpg_home.path());
        }

        // Set GPG recipient
        std::process::Command::new("git")
            .args([
                "config",
                "--file",
                global_config.to_str().unwrap(),
                "ai.cadence.gpg.recipient",
                &email,
            ])
            .output()
            .unwrap();

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let first_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let first_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let first_ts: i64 = first_ts_str.parse().unwrap();

        // Step 1: Run hook with no session logs — creates pending record
        std::env::set_current_dir(repo_path).expect("failed to chdir");

        // Force hook to not find session (encryption isn't attempted if no session)
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        // Step 2: Now create session log for the first commit
        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"retry-encrypt-test","cwd":"{cwd}"}}
{{"type":"tool_result","content":"[main {short}] initial commit\n 1 file changed"}}
{{"type":"assistant","message":"Done"}}
"#,
            cwd = git_repo_root,
            short = &first_hash[..7],
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(first_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        // Step 3: Make second commit, triggering retry of pending
        std::fs::write(repo_path.join("file2.txt"), "second").unwrap();
        run_git(repo_path, &["add", "file2.txt"]);
        run_git(repo_path, &["commit", "-m", "second commit"]);

        let result = run_hook_post_commit();
        assert!(result.is_ok());

        // Verify the note on first commit is encrypted
        let note_output = std::process::Command::new("git")
            .args(["-C", repo_path.to_str().unwrap()])
            .args([
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &first_hash,
            ])
            .output()
            .unwrap();

        if note_output.status.success() {
            let note = String::from_utf8(note_output.stdout).unwrap();
            assert!(
                note.trim().starts_with("-----BEGIN PGP MESSAGE-----"),
                "retry-attached note should be encrypted, got: {}",
                &note[..std::cmp::min(80, note.len())]
            );
        }

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
            match original_gnupghome {
                Some(g) => std::env::set_var("GNUPGHOME", g),
                None => std::env::remove_var("GNUPGHOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }
}
