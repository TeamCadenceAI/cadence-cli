mod agents;
mod git;
mod note;
mod pending;
mod push;
mod scanner;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::process;

/// AI Barometer: attach AI coding agent session logs to Git commits via git notes.
///
/// Provides provenance and measurement of AI-assisted development
/// without polluting commit history.
#[derive(Parser, Debug)]
#[command(name = "ai-barometer", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Install AI Barometer: set up git hooks and run initial hydration.
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

    /// Show AI Barometer status for the current repository.
    Status,
}

#[derive(Subcommand, Debug)]
enum HookCommand {
    /// Post-commit hook: attempt to attach AI session note to HEAD.
    PostCommit,
}

// ---------------------------------------------------------------------------
// Subcommand dispatch
// ---------------------------------------------------------------------------

fn run_install(org: Option<String>) -> Result<()> {
    eprintln!(
        "[ai-barometer] install: org={:?} (not yet implemented)",
        org
    );
    Ok(())
}

/// The post-commit hook handler. This is the critical hot path.
///
/// CRITICAL: This function must NEVER fail the commit. All errors are caught
/// and logged as warnings. The function always exits 0.
///
/// The outer wrapper uses `std::panic::catch_unwind` to catch panics, and
/// an inner `Result` to catch all other errors. Any failure is logged to
/// stderr with the `[ai-barometer]` prefix and silently ignored.
fn run_hook_post_commit() -> Result<()> {
    // Catch-all: catch panics
    let result = std::panic::catch_unwind(|| -> Result<()> { hook_post_commit_inner() });

    match result {
        Ok(Ok(())) => {} // Success
        Ok(Err(e)) => {
            eprintln!("[ai-barometer] warning: hook failed: {}", e);
        }
        Err(_) => {
            eprintln!("[ai-barometer] warning: hook panicked (this is a bug)");
        }
    }

    // Always succeed — never block the commit
    Ok(())
}

/// Inner implementation of the post-commit hook.
///
/// This function is allowed to return errors — the caller (`run_hook_post_commit`)
/// catches all errors and panics.
fn hook_post_commit_inner() -> Result<()> {
    // Step 0: Per-repo enabled check — if disabled, skip EVERYTHING
    if !git::check_enabled() {
        return Ok(());
    }

    // Step 1: Get repo root, HEAD hash, HEAD timestamp
    let repo_root = git::repo_root()?;
    let head_hash = git::head_hash()?;
    let head_timestamp = git::head_timestamp()?;
    let repo_root_str = repo_root.to_string_lossy().to_string();

    // Step 2: Deduplication — if note already exists, exit early
    if git::note_exists(&head_hash)? {
        return Ok(());
    }

    // Step 3: Collect candidate log directories from agents
    let mut candidate_dirs = Vec::new();
    candidate_dirs.extend(agents::claude::log_dirs(&repo_root));
    candidate_dirs.extend(agents::codex::log_dirs(&repo_root));

    // Step 4: Filter candidate files by ±10 min (600 sec) window
    let candidate_files = agents::candidate_files(&candidate_dirs, head_timestamp, 600);

    // Step 5: Run scanner to find session match
    let session_match = scanner::find_session_for_commit(&head_hash, &candidate_files);

    if let Some(ref matched) = session_match {
        // Step 6a: Parse metadata and verify match
        let metadata = scanner::parse_session_metadata(&matched.file_path);

        if scanner::verify_match(&metadata, &repo_root, &head_hash) {
            // Read the full session log. If the read fails (permissions,
            // file deleted between match and read, etc.), fall through to
            // the pending path so it can be retried later.
            let session_log = match std::fs::read_to_string(&matched.file_path) {
                Ok(content) => content,
                Err(e) => {
                    eprintln!("[ai-barometer] warning: failed to read session log: {}", e);
                    if let Err(e) =
                        pending::write_pending(&head_hash, &repo_root_str, head_timestamp)
                    {
                        eprintln!(
                            "[ai-barometer] warning: failed to write pending record: {}",
                            e
                        );
                    }
                    // Skip note attachment; retry will pick this up later
                    return Ok(());
                }
            };

            let session_id = metadata.session_id.as_deref().unwrap_or("unknown");

            // Format the note
            let note_content = note::format(
                &matched.agent_type,
                session_id,
                &repo_root_str,
                &head_hash,
                &session_log,
            )?;

            // Attach the note
            git::add_note(&head_hash, &note_content)?;

            eprintln!(
                "[ai-barometer] attached session {} to commit {}",
                session_id,
                &head_hash[..7]
            );

            // Push notes if conditions are met (consent, org filter, remote exists)
            if push::should_push(&repo_root) {
                push::attempt_push();
            }
        } else {
            // Verification failed — treat as no match, write pending
            if let Err(e) = pending::write_pending(&head_hash, &repo_root_str, head_timestamp) {
                eprintln!(
                    "[ai-barometer] warning: failed to write pending record: {}",
                    e
                );
            }
        }
    } else {
        // Step 6b: No match found — write pending record
        if let Err(e) = pending::write_pending(&head_hash, &repo_root_str, head_timestamp) {
            eprintln!(
                "[ai-barometer] warning: failed to write pending record: {}",
                e
            );
        }
    }

    // Step 7: Retry pending commits for this repo (stub — Phase 7 will implement fully)
    retry_pending_for_repo(&repo_root_str, &repo_root);

    Ok(())
}

/// Attempt to resolve pending commits for the given repository.
///
/// This is a best-effort operation. Any errors during retry are logged
/// and silently ignored. For each pending record:
/// - If note already exists: remove the pending record (success).
/// - If session match is found and verified: attach note, remove pending record.
/// - Otherwise: increment the attempt counter and leave for next time.
///
/// Pending retries use a much wider time window than the initial hook
/// (24 hours instead of 10 minutes) because the commit could be old and
/// the session log file may have been modified since the commit was created.
fn retry_pending_for_repo(repo_str: &str, repo_root: &std::path::Path) {
    let mut pending_records = match pending::list_for_repo(repo_str) {
        Ok(records) => records,
        Err(_) => return,
    };

    for record in &mut pending_records {
        // Skip if note already exists (may have been resolved by another mechanism)
        match git::note_exists(&record.commit) {
            Ok(true) => {
                // Already resolved -- remove pending record
                let _ = pending::remove(&record.commit);
                continue;
            }
            Ok(false) => {} // Still pending, try to resolve
            Err(_) => continue,
        }

        // Collect candidate dirs and files for this commit.
        // Use a 24-hour (86400 sec) window for retries instead of the
        // 10-minute window used in the hook. The session log file mtime
        // may differ significantly from the commit time if the agent
        // continued working after the commit.
        let mut candidate_dirs = Vec::new();
        candidate_dirs.extend(agents::claude::log_dirs(repo_root));
        candidate_dirs.extend(agents::codex::log_dirs(repo_root));

        let candidate_files = agents::candidate_files(&candidate_dirs, record.commit_time, 86_400);

        let session_match = scanner::find_session_for_commit(&record.commit, &candidate_files);

        if let Some(ref matched) = session_match {
            let metadata = scanner::parse_session_metadata(&matched.file_path);

            if scanner::verify_match(&metadata, repo_root, &record.commit) {
                let session_log = match std::fs::read_to_string(&matched.file_path) {
                    Ok(content) => content,
                    Err(_) => {
                        // File unreadable; increment and try again later
                        let _ = pending::increment(record);
                        continue;
                    }
                };

                let session_id = metadata.session_id.as_deref().unwrap_or("unknown");

                let note_content = match note::format(
                    &matched.agent_type,
                    session_id,
                    repo_str,
                    &record.commit,
                    &session_log,
                ) {
                    Ok(c) => c,
                    Err(_) => {
                        let _ = pending::increment(record);
                        continue;
                    }
                };

                if git::add_note(&record.commit, &note_content).is_ok() {
                    eprintln!(
                        "[ai-barometer] retry: attached session {} to commit {}",
                        session_id,
                        &record.commit[..std::cmp::min(7, record.commit.len())]
                    );
                    let _ = pending::remove(&record.commit);

                    // Push if conditions are met
                    if push::should_push(repo_root) {
                        push::attempt_push();
                    }
                } else {
                    let _ = pending::increment(record);
                }
            } else {
                // Verification failed -- increment attempt count
                let _ = pending::increment(record);
            }
        } else {
            // No match found -- increment attempt count
            let _ = pending::increment(record);
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

    // Step 1: Collect all log directories (repo-agnostic)
    eprintln!(
        "[ai-barometer] Scanning Claude logs (last {} days)...",
        since_days
    );
    let claude_dirs = agents::claude::all_log_dirs();

    eprintln!(
        "[ai-barometer] Scanning Codex logs (last {} days)...",
        since_days
    );
    let codex_dirs = agents::codex::all_log_dirs();

    let mut all_dirs = Vec::new();
    all_dirs.extend(claude_dirs);
    all_dirs.extend(codex_dirs);

    // Step 2: Find all .jsonl files modified within the --since window
    let files = agents::recent_files(&all_dirs, now, since_secs);
    eprintln!("[ai-barometer] Found {} session logs", files.len());

    // Counters for final summary
    let mut attached = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;

    // Step 3: Process each file
    for file in &files {
        // Parse metadata to get session_id and cwd
        let metadata = scanner::parse_session_metadata(file);
        let session_id = metadata
            .session_id
            .as_deref()
            .unwrap_or("unknown")
            .to_string();

        // Determine repo name for display (last path component of cwd)
        let repo_display = metadata
            .cwd
            .as_ref()
            .and_then(|c| {
                std::path::Path::new(c)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
            })
            .unwrap_or_else(|| "unknown".to_string());

        // Show short session_id for display (first 8 chars or full if shorter)
        let session_display = if session_id.len() > 8 {
            &session_id[..8]
        } else {
            &session_id
        };

        eprintln!(
            "[ai-barometer] -> session {} (repo: {})",
            session_display, repo_display
        );

        // Step 4: Extract all commit hashes from the session log
        let commit_hashes = scanner::extract_commit_hashes(file);

        if commit_hashes.is_empty() {
            eprintln!("[ai-barometer]   no commit hashes found, skipping");
            skipped += 1;
            continue;
        }

        // Step 5: For each hash, resolve repo and attach note if missing
        for hash in &commit_hashes {
            // Resolve repo from session cwd
            let cwd = match &metadata.cwd {
                Some(c) => c.clone(),
                None => {
                    eprintln!(
                        "[ai-barometer]   no cwd in session metadata, skipping commit {}",
                        &hash[..7]
                    );
                    errors += 1;
                    continue;
                }
            };

            let cwd_path = std::path::Path::new(&cwd);

            // Resolve the repo root from the session's cwd
            let repo_root = match git::repo_root_at(cwd_path) {
                Ok(r) => r,
                Err(_) => {
                    eprintln!("[ai-barometer]   repo missing for cwd {}, skipped", cwd);
                    errors += 1;
                    continue;
                }
            };

            // Check if AI Barometer is enabled for this repo
            if !git::check_enabled_at(&repo_root) {
                continue;
            }

            // Verify the commit exists in the resolved repo
            match git::commit_exists_at(&repo_root, hash) {
                Ok(true) => {}
                Ok(false) => {
                    // Commit does not exist in this repo -- could be from a
                    // different repo or could be rebased away. Skip silently.
                    continue;
                }
                Err(e) => {
                    eprintln!(
                        "[ai-barometer]   error checking commit {}: {}",
                        &hash[..7],
                        e
                    );
                    errors += 1;
                    continue;
                }
            }

            // Check dedup: skip if note already exists
            match git::note_exists_at(&repo_root, hash) {
                Ok(true) => {
                    // Note already exists -- skip
                    skipped += 1;
                    continue;
                }
                Ok(false) => {} // Need to attach
                Err(e) => {
                    eprintln!(
                        "[ai-barometer]   error checking note for {}: {}",
                        &hash[..7],
                        e
                    );
                    errors += 1;
                    continue;
                }
            }

            // Read the full session log
            let session_log = match std::fs::read_to_string(file) {
                Ok(content) => content,
                Err(e) => {
                    eprintln!("[ai-barometer]   failed to read session log: {}", e);
                    errors += 1;
                    continue;
                }
            };

            // Use agent type from parsed metadata (already inferred by
            // parse_session_metadata via infer_agent_type). Fall back to
            // Claude if metadata didn't determine it.
            let agent_type = metadata
                .agent_type
                .clone()
                .unwrap_or(scanner::AgentType::Claude);

            let repo_str = repo_root.to_string_lossy().to_string();

            // Format the note
            let note_content =
                match note::format(&agent_type, &session_id, &repo_str, hash, &session_log) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!(
                            "[ai-barometer]   failed to format note for {}: {}",
                            &hash[..7],
                            e
                        );
                        errors += 1;
                        continue;
                    }
                };

            // Attach the note
            match git::add_note_at(&repo_root, hash, &note_content) {
                Ok(()) => {
                    eprintln!("[ai-barometer]   commit {} attached", &hash[..7]);
                    attached += 1;
                }
                Err(e) => {
                    eprintln!(
                        "[ai-barometer]   failed to attach note to {}: {}",
                        &hash[..7],
                        e
                    );
                    errors += 1;
                }
            }
        }
    }

    // Step 6: Print summary
    eprintln!(
        "[ai-barometer] Done. {} attached, {} skipped, {} errors.",
        attached, skipped, errors
    );

    // Step 7: Push if requested
    if do_push {
        eprintln!("[ai-barometer] Pushing notes...");
        push::attempt_push();
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
        eprintln!("[ai-barometer] no pending commits for this repo");
        return Ok(());
    }

    eprintln!(
        "[ai-barometer] retrying {} pending commit(s)...",
        pending_count
    );
    retry_pending_for_repo(&repo_str, &repo_root);

    let remaining = pending::list_for_repo(&repo_str)
        .map(|r| r.len())
        .unwrap_or(0);
    let resolved = pending_count - remaining;
    eprintln!(
        "[ai-barometer] retry complete: {} resolved, {} still pending",
        resolved, remaining
    );

    Ok(())
}

fn run_status() -> Result<()> {
    eprintln!("[ai-barometer] status (not yet implemented)");
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
        },
        Command::Hydrate { since, push } => run_hydrate(&since, push),
        Command::Retry => run_retry(),
        Command::Status => run_status(),
    };

    if let Err(e) = result {
        eprintln!("[ai-barometer] error: {}", e);
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_install() {
        let cli = Cli::parse_from(["ai-barometer", "install"]);
        assert!(matches!(cli.command, Command::Install { org: None }));
    }

    #[test]
    fn cli_parses_install_with_org() {
        let cli = Cli::parse_from(["ai-barometer", "install", "--org", "my-org"]);
        match cli.command {
            Command::Install { org } => assert_eq!(org.as_deref(), Some("my-org")),
            _ => panic!("expected Install command"),
        }
    }

    #[test]
    fn cli_parses_hook_post_commit() {
        let cli = Cli::parse_from(["ai-barometer", "hook", "post-commit"]);
        assert!(matches!(
            cli.command,
            Command::Hook {
                hook_command: HookCommand::PostCommit
            }
        ));
    }

    #[test]
    fn cli_parses_hydrate_defaults() {
        let cli = Cli::parse_from(["ai-barometer", "hydrate"]);
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
        let cli = Cli::parse_from(["ai-barometer", "hydrate", "--since", "30d", "--push"]);
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
        let cli = Cli::parse_from(["ai-barometer", "retry"]);
        assert!(matches!(cli.command, Command::Retry));
    }

    #[test]
    fn cli_parses_status() {
        let cli = Cli::parse_from(["ai-barometer", "status"]);
        assert!(matches!(cli.command, Command::Status));
    }

    #[test]
    fn run_install_returns_ok() {
        assert!(run_install(None).is_ok());
    }

    #[test]
    fn run_hook_post_commit_returns_ok() {
        // The catch-all wrapper ensures this always returns Ok even
        // when called outside a git repo (the inner logic will fail
        // but the error is caught and logged to stderr).
        assert!(run_hook_post_commit().is_ok());
    }

    #[test]
    fn run_hydrate_returns_ok() {
        // run_hydrate now does real work: parses --since, scans log dirs.
        // With a valid duration string and no session logs on disk, it should
        // succeed and print a "Done. 0 attached, 0 skipped, 0 errors." summary.
        assert!(run_hydrate("7d", false).is_ok());
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
    fn run_status_returns_ok() {
        assert!(run_status().is_ok());
    }

    // -----------------------------------------------------------------------
    // Negative CLI parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn cli_rejects_unknown_subcommand() {
        let result = Cli::try_parse_from(["ai-barometer", "frobnicate"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_rejects_hook_without_sub_subcommand() {
        let result = Cli::try_parse_from(["ai-barometer", "hook"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_rejects_hydrate_since_missing_value() {
        let result = Cli::try_parse_from(["ai-barometer", "hydrate", "--since"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_rejects_no_subcommand() {
        let result = Cli::try_parse_from(["ai-barometer"]);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Integration test: post-commit hook with a real temp repo
    // -----------------------------------------------------------------------

    use serial_test::serial;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Helper: create a temporary git repo with one commit.
    fn init_temp_repo() -> TempDir {
        let dir = TempDir::new().expect("failed to create temp dir");
        let path = dir.path();

        run_git(path, &["init"]);
        run_git(path, &["config", "user.email", "test@test.com"]);
        run_git(path, &["config", "user.name", "Test User"]);
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
    fn test_hook_post_commit_deduplication_skips_if_note_exists() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

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

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_no_match_writes_pending() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        // Use a fake HOME so pending records are written to a temp dir
        // instead of the real ~/.ai-barometer/pending/.
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
            .join(".ai-barometer")
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
    fn test_hook_post_commit_never_fails_outside_git_repo() {
        // When called outside a git repo, the hook should still return Ok
        // because the catch-all wrapper catches errors.
        // Note: we don't chdir -- just call it in whatever CWD we have.
        // If the current dir IS a git repo, inner logic may succeed; that's fine.
        // The important thing is that it NEVER returns Err.
        let result = run_hook_post_commit();
        assert!(result.is_ok());
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
            .join(".ai-barometer")
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
            .join(".ai-barometer")
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
{{"type":"tool_result","content":"commit {hash}"}}
"#,
            cwd = git_repo_root,
            hash = head_hash,
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

    #[test]
    fn test_hydrate_no_logs_returns_ok() {
        // Hydrate with no log directories should succeed gracefully
        // (we don't need to redirect HOME here -- if HOME exists but
        // has no .claude or .codex dirs, hydrate still succeeds)
        let result = run_hydrate("7d", false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hydrate_invalid_since_returns_error() {
        let result = run_hydrate("invalid", false);
        assert!(result.is_err());
    }
}
