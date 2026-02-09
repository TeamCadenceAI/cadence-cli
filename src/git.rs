//! Git utility helpers.
//!
//! All functions shell out to `git` via `std::process::Command`.
//! The notes ref used throughout is `refs/notes/ai-sessions`.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The dedicated git notes ref for AI session data.
const NOTES_REF: &str = "refs/notes/ai-sessions";

/// Validate that a commit hash is a valid hex string of 7-40 characters.
///
/// This prevents flag injection (e.g., passing `--help` as a commit) and
/// ensures we only pass well-formed refs to git.
pub(crate) fn validate_commit_hash(commit: &str) -> Result<()> {
    let is_valid =
        commit.len() >= 7 && commit.len() <= 40 && commit.bytes().all(|b| b.is_ascii_hexdigit());
    if !is_valid {
        bail!(
            "invalid commit hash {:?}: must be 7-40 lowercase hex characters",
            commit
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

/// Run a git command and return its stdout as a trimmed `String`.
/// Returns an error if the command exits with a non-zero status.
fn git_output(args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .output()
        .context("failed to execute git")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git {} failed (exit {}): {}",
            args.join(" "),
            output.status,
            stderr.trim()
        );
    }

    let stdout = String::from_utf8(output.stdout).context("git output was not valid UTF-8")?;
    Ok(stdout.trim().to_string())
}

/// Run a git command and return whether it succeeded (exit code 0).
/// Does not treat non-zero exit as an error — just returns `false`.
fn git_succeeds(args: &[&str]) -> Result<bool> {
    let status = Command::new("git")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("failed to execute git")?;
    Ok(status.success())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check whether AI Barometer is enabled for the current repository.
///
/// Reads `git config ai.barometer.enabled`. If the value is exactly
/// `"false"`, returns `false` -- the caller should skip ALL processing
/// (session scanning, note attachment, pending records, push, retry).
/// Any other value (including unset) returns `true`.
///
/// This is placed in the `git` module (not `push`) because it gates
/// the entire hook lifecycle, not just the push decision.
pub fn check_enabled() -> bool {
    match config_get("ai.barometer.enabled") {
        Ok(Some(val)) => val != "false",
        // Unset or error: default to enabled
        _ => true,
    }
}

/// Check whether AI Barometer is enabled for a specific repository directory.
///
/// This is the directory-parameterised version of [`check_enabled`], for use
/// by commands that operate on repos other than the CWD (e.g., `hydrate`).
///
/// Reads `git -C <repo> config ai.barometer.enabled`. If the value is exactly
/// `"false"`, returns `false`. Any other value (including unset) returns `true`.
pub(crate) fn check_enabled_at(repo: &Path) -> bool {
    let repo_str = repo.to_string_lossy();
    let output = Command::new("git")
        .args(["-C", &repo_str, "config", "--get", "ai.barometer.enabled"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let value = String::from_utf8_lossy(&o.stdout).trim().to_string();
            value != "false"
        }
        // Unset (exit code 1) or error: default to enabled
        _ => true,
    }
}

/// Return the repository root (`git rev-parse --show-toplevel`).
pub fn repo_root() -> Result<PathBuf> {
    let path = git_output(&["rev-parse", "--show-toplevel"])?;
    Ok(PathBuf::from(path))
}

/// Return the repository root for a given working directory.
///
/// Runs `git -C <dir> rev-parse --show-toplevel`. This handles the case
/// where `dir` is a subdirectory of the repo.
pub(crate) fn repo_root_at(dir: &Path) -> Result<PathBuf> {
    let dir_str = dir.to_string_lossy();
    let output = Command::new("git")
        .args(["-C", &dir_str, "rev-parse", "--show-toplevel"])
        .output()
        .context("failed to execute git rev-parse --show-toplevel")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git rev-parse --show-toplevel failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8(output.stdout).context("git output was not valid UTF-8")?;
    Ok(PathBuf::from(stdout.trim()))
}

/// Check whether an AI-session note already exists for the given commit,
/// in a specific repository directory.
///
/// This is the directory-parameterised version of [`note_exists`], for use
/// by commands that operate on repos other than the CWD (e.g., `hydrate`).
pub(crate) fn note_exists_at(repo: &Path, commit: &str) -> Result<bool> {
    validate_commit_hash(commit)?;
    let repo_str = repo.to_string_lossy();
    let status = Command::new("git")
        .args([
            "-C", &repo_str, "notes", "--ref", NOTES_REF, "show", "--", commit,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("failed to execute git notes show")?;
    Ok(status.success())
}

/// Attach an AI-session note to a commit in a specific repository directory.
///
/// This is the directory-parameterised version of [`add_note`], for use
/// by commands that operate on repos other than the CWD (e.g., `hydrate`).
///
/// **Precondition:** Callers must check [`note_exists_at`] first and skip if
/// a note is already present.
pub(crate) fn add_note_at(repo: &Path, commit: &str, content: &str) -> Result<()> {
    validate_commit_hash(commit)?;
    let repo_str = repo.to_string_lossy();
    let output = Command::new("git")
        .args([
            "-C", &repo_str, "notes", "--ref", NOTES_REF, "add", "-m", content, "--", commit,
        ])
        .output()
        .context("failed to execute git notes add")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git notes add failed: {}", stderr.trim());
    }
    Ok(())
}

/// Check whether a commit exists in a given repository.
///
/// Runs `git -C <repo> cat-file -t -- <commit>` and checks for success.
/// The `--` separator prevents the commit argument from being interpreted
/// as a flag.
pub(crate) fn commit_exists_at(repo: &Path, commit: &str) -> Result<bool> {
    let repo_str = repo.to_string_lossy();
    let status = Command::new("git")
        .args(["-C", &repo_str, "cat-file", "-t", "--", commit])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("failed to execute git cat-file")?;
    Ok(status.success())
}

/// Return the full 40-character SHA of HEAD.
pub fn head_hash() -> Result<String> {
    git_output(&["rev-parse", "HEAD"])
}

/// Return the commit timestamp of HEAD as a Unix epoch `i64`.
pub fn head_timestamp() -> Result<i64> {
    let ts_str = git_output(&["show", "-s", "--format=%ct", "HEAD"])?;
    ts_str
        .parse::<i64>()
        .context("failed to parse HEAD timestamp as i64")
}

/// Check whether an AI-session note already exists for the given commit.
pub fn note_exists(commit: &str) -> Result<bool> {
    validate_commit_hash(commit)?;
    git_succeeds(&["notes", "--ref", NOTES_REF, "show", "--", commit])
}

/// Attach an AI-session note to the given commit.
///
/// **Precondition:** Callers must check [`note_exists`] first and skip if a note
/// is already present. `git notes add` will fail if a note already exists for the
/// given commit. The PLAN.md deduplication rules require checking before attaching:
/// "if a note already exists, treat as success, do nothing."
pub fn add_note(commit: &str, content: &str) -> Result<()> {
    validate_commit_hash(commit)?;
    let output = Command::new("git")
        .args([
            "notes", "--ref", NOTES_REF, "add", "-m", content, "--", commit,
        ])
        .output()
        .context("failed to execute git notes add")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git notes add failed: {}", stderr.trim());
    }
    Ok(())
}

/// Push the AI-session notes ref to `origin`.
pub fn push_notes() -> Result<()> {
    let output = Command::new("git")
        .args(["push", "origin", NOTES_REF])
        .output()
        .context("failed to execute git push")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git push notes failed: {}", stderr.trim());
    }
    Ok(())
}

/// Check whether the repository has at least one configured remote.
///
/// Returns `Ok(false)` if `git remote` fails (e.g., not in a git repository)
/// rather than propagating the error. This matches the `git_succeeds` pattern
/// used by `note_exists` and makes the function safe to call defensively.
pub fn has_upstream() -> Result<bool> {
    match git_output(&["remote"]) {
        Ok(remotes) => Ok(!remotes.is_empty()),
        Err(_) => Ok(false),
    }
}

/// Extract the owner/org from the first remote URL.
///
/// Supports:
/// - SSH:   `git@github.com:org/repo.git`
/// - HTTPS: `https://github.com/org/repo.git`
///
/// Returns `None` if no remote is configured or the URL cannot be parsed.
///
/// **Note:** Only inspects the first remote. Use [`remote_orgs`] to check all
/// remotes (needed for org filtering per PLAN.md).
pub fn remote_org() -> Result<Option<String>> {
    let remotes = git_output(&["remote"])?;
    let first_remote = match remotes.lines().next() {
        Some(r) => r,
        None => return Ok(None),
    };

    let url = git_output(&["remote", "get-url", first_remote])?;
    Ok(parse_org_from_url(&url))
}

/// Extract owner/org from ALL remote URLs.
///
/// Returns a deduplicated list of org names extracted from all configured
/// remotes. Deduplication is case-insensitive (e.g., `My-Org` and `my-org`
/// from different remotes are considered the same org; only the first
/// encountered variant is kept). This is used for org filtering: "Extract
/// owner from **all** Git remotes. If **any** remote matches org, allowed."
/// (PLAN.md)
///
/// Returns an empty Vec if no remotes are configured or no URLs can be parsed.
pub fn remote_orgs() -> Result<Vec<String>> {
    let remotes = git_output(&["remote"])?;
    let mut orgs = Vec::new();

    for remote_name in remotes.lines() {
        if remote_name.is_empty() {
            continue;
        }
        if let Ok(url) = git_output(&["remote", "get-url", remote_name])
            && let Some(org) = parse_org_from_url(&url)
            && !orgs
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(&org))
        {
            orgs.push(org);
        }
    }

    Ok(orgs)
}

/// Parse the owner/org segment from a git remote URL.
///
/// This is a pure function extracted for testability.
pub fn parse_org_from_url(url: &str) -> Option<String> {
    // SSH: git@github.com:org/repo.git
    if let Some(after_colon) = url.strip_prefix("git@").and_then(|s| {
        // Find the colon that separates host from path
        s.split_once(':').map(|(_, path)| path)
    }) {
        let org = after_colon.split('/').next()?;
        if org.is_empty() {
            return None;
        }
        return Some(org.to_string());
    }

    // HTTPS: https://github.com/org/repo.git
    if url.starts_with("https://") || url.starts_with("http://") {
        // Split on '/' and take the path segments after the host
        let without_scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))?;
        let mut segments = without_scheme.split('/');
        let _host = segments.next(); // e.g. "github.com"
        let org = segments.next()?;
        if org.is_empty() {
            return None;
        }
        return Some(org.to_string());
    }

    None
}

/// Read a git config value. Returns `Ok(None)` if the key is not set.
///
/// Distinguishes exit code 1 (key not set) from other exit codes (e.g., 2 for
/// invalid config file) to avoid silently swallowing genuine errors.
pub fn config_get(key: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .args(["config", "--get", key])
        .output()
        .context("failed to execute git config --get")?;

    if !output.status.success() {
        // Exit code 1 means the key is not set — that is not an error.
        // Any other non-zero exit (e.g., code 2 for corrupt config) is a real error.
        let code = output.status.code().unwrap_or(-1);
        if code != 1 {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "git config --get {:?} failed (exit {}): {}",
                key,
                code,
                stderr.trim()
            );
        }
        return Ok(None);
    }

    let value =
        String::from_utf8(output.stdout).context("git config output was not valid UTF-8")?;
    Ok(Some(value.trim().to_string()))
}

/// Read a git config value from global scope. Returns `Ok(None)` if the key is not set.
///
/// Uses `--global` flag to read only the global config, not repo-local.
/// This is used for settings like `ai.barometer.org` that are set at install time.
pub fn config_get_global(key: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .args(["config", "--global", "--get", key])
        .output()
        .context("failed to execute git config --global --get")?;

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        if code != 1 {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "git config --global --get {:?} failed (exit {}): {}",
                key,
                code,
                stderr.trim()
            );
        }
        return Ok(None);
    }

    let value =
        String::from_utf8(output.stdout).context("git config output was not valid UTF-8")?;
    Ok(Some(value.trim().to_string()))
}

/// Write a git config value (repo-local scope).
pub fn config_set(key: &str, value: &str) -> Result<()> {
    let output = Command::new("git")
        .args(["config", key, value])
        .output()
        .context("failed to execute git config set")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git config set failed: {}", stderr.trim());
    }
    Ok(())
}

/// Write a git config value in global scope (`--global`).
///
/// Used by the `install` subcommand to persist settings like
/// `core.hooksPath` and `ai.barometer.org` globally.
pub fn config_set_global(key: &str, value: &str) -> Result<()> {
    let output = Command::new("git")
        .args(["config", "--global", key, value])
        .output()
        .context("failed to execute git config --global set")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git config --global set failed: {}", stderr.trim());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::process::Command;
    use tempfile::TempDir;

    /// Helper: create a temporary git repo with one commit.
    /// Returns the TempDir (which cleans up on drop) and sets the
    /// working directory for the test by returning a guard.
    ///
    /// Note: since we cannot change the process-wide CWD safely in
    /// parallel tests, all git commands in tests must use `-C <path>`.
    /// We provide a `git_in` helper for this.
    fn init_temp_repo() -> TempDir {
        let dir = TempDir::new().expect("failed to create temp dir");
        let path = dir.path();

        // git init
        run_git(path, &["init"]);
        // Set required user config for commits
        run_git(path, &["config", "user.email", "test@test.com"]);
        run_git(path, &["config", "user.name", "Test User"]);
        // Create an initial commit
        std::fs::write(path.join("README.md"), "hello").unwrap();
        run_git(path, &["add", "README.md"]);
        run_git(path, &["commit", "-m", "initial commit"]);

        dir
    }

    /// Run a git command inside the given directory, panicking on failure.
    fn run_git(dir: &std::path::Path, args: &[&str]) -> String {
        let output = Command::new("git")
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

    /// Run one of our git module functions inside a specific directory
    /// by temporarily overriding GIT_DIR behaviour via `-C`.
    /// Since our public functions don't take a path arg (they rely on cwd),
    /// we use a wrapper approach: spawn a git command with `-C`.
    fn git_output_in(dir: &std::path::Path, args: &[&str]) -> Result<String> {
        let output = Command::new("git")
            .args(["-C", dir.to_str().unwrap()])
            .args(args)
            .output()
            .context("failed to execute git")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("git {} failed: {}", args.join(" "), stderr.trim());
        }

        let stdout = String::from_utf8(output.stdout).context("git output was not valid UTF-8")?;
        Ok(stdout.trim().to_string())
    }

    // -----------------------------------------------------------------------
    // repo_root — tested via direct git command in temp dir
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_root() {
        let dir = init_temp_repo();
        let root = git_output_in(dir.path(), &["rev-parse", "--show-toplevel"]).unwrap();
        let root_path = PathBuf::from(&root);
        // The root should be the temp dir (possibly canonicalized)
        assert!(root_path.exists());
        // The root should contain the README we created
        assert!(root_path.join("README.md").exists());
    }

    // -----------------------------------------------------------------------
    // head_hash
    // -----------------------------------------------------------------------

    #[test]
    fn test_head_hash() {
        let dir = init_temp_repo();
        let hash = git_output_in(dir.path(), &["rev-parse", "HEAD"]).unwrap();
        // Full SHA is 40 hex characters
        assert_eq!(hash.len(), 40);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -----------------------------------------------------------------------
    // head_timestamp
    // -----------------------------------------------------------------------

    #[test]
    fn test_head_timestamp() {
        let dir = init_temp_repo();
        let ts_str = git_output_in(dir.path(), &["show", "-s", "--format=%ct", "HEAD"]).unwrap();
        let ts: i64 = ts_str.parse().unwrap();
        // Should be a reasonable Unix timestamp (after 2020)
        assert!(ts > 1_577_836_800);
    }

    // -----------------------------------------------------------------------
    // note_exists + add_note
    // -----------------------------------------------------------------------

    #[test]
    fn test_note_exists_false_then_true_after_add() {
        let dir = init_temp_repo();
        let path = dir.path();
        let hash = run_git(path, &["rev-parse", "HEAD"]);

        // No note yet
        let status = Command::new("git")
            .args(["-C", path.to_str().unwrap()])
            .args(["notes", "--ref", NOTES_REF, "show", &hash])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success());

        // Add a note
        run_git(
            path,
            &[
                "notes",
                "--ref",
                NOTES_REF,
                "add",
                "-m",
                "test note content",
                &hash,
            ],
        );

        // Now note exists
        let status = Command::new("git")
            .args(["-C", path.to_str().unwrap()])
            .args(["notes", "--ref", NOTES_REF, "show", &hash])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());

        // Verify content
        let note_content =
            git_output_in(path, &["notes", "--ref", NOTES_REF, "show", &hash]).unwrap();
        assert_eq!(note_content, "test note content");
    }

    // -----------------------------------------------------------------------
    // has_upstream
    // -----------------------------------------------------------------------

    #[test]
    fn test_has_upstream_false_when_no_remote() {
        let dir = init_temp_repo();
        let remotes = git_output_in(dir.path(), &["remote"]).unwrap();
        assert!(remotes.is_empty());
    }

    #[test]
    fn test_has_upstream_true_when_remote_added() {
        let dir = init_temp_repo();
        let path = dir.path();
        run_git(
            path,
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/test-org/test-repo.git",
            ],
        );
        let remotes = git_output_in(path, &["remote"]).unwrap();
        assert!(!remotes.is_empty());
    }

    // -----------------------------------------------------------------------
    // remote_org (via parse_org_from_url — pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_org_from_ssh_url() {
        let org = parse_org_from_url("git@github.com:my-org/my-repo.git");
        assert_eq!(org, Some("my-org".to_string()));
    }

    #[test]
    fn test_parse_org_from_https_url() {
        let org = parse_org_from_url("https://github.com/other-org/some-repo.git");
        assert_eq!(org, Some("other-org".to_string()));
    }

    #[test]
    fn test_parse_org_from_http_url() {
        let org = parse_org_from_url("http://github.com/http-org/repo.git");
        assert_eq!(org, Some("http-org".to_string()));
    }

    #[test]
    fn test_parse_org_from_unknown_url() {
        let org = parse_org_from_url("svn://example.com/repo");
        assert_eq!(org, None);
    }

    #[test]
    fn test_parse_org_empty_url() {
        let org = parse_org_from_url("");
        assert_eq!(org, None);
    }

    // -----------------------------------------------------------------------
    // remote_org (integration test with temp repo)
    // -----------------------------------------------------------------------

    #[test]
    fn test_remote_org_integration() {
        let dir = init_temp_repo();
        let path = dir.path();
        run_git(
            path,
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:acme-corp/widgets.git",
            ],
        );
        let url = git_output_in(path, &["remote", "get-url", "origin"]).unwrap();
        let org = parse_org_from_url(&url);
        assert_eq!(org, Some("acme-corp".to_string()));
    }

    // -----------------------------------------------------------------------
    // config_get + config_set
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_get_missing_key() {
        let dir = init_temp_repo();
        let path = dir.path();
        let output = Command::new("git")
            .args(["-C", path.to_str().unwrap()])
            .args(["config", "--get", "ai.barometer.nonexistent"])
            .output()
            .unwrap();
        // Should exit non-zero (key not set)
        assert!(!output.status.success());
    }

    #[test]
    fn test_config_set_then_get() {
        let dir = init_temp_repo();
        let path = dir.path();

        // Set a config value
        run_git(path, &["config", "ai.barometer.autopush", "true"]);

        // Read it back
        let value = git_output_in(path, &["config", "--get", "ai.barometer.autopush"]).unwrap();
        assert_eq!(value, "true");
    }

    #[test]
    fn test_config_overwrite() {
        let dir = init_temp_repo();
        let path = dir.path();

        run_git(path, &["config", "ai.barometer.org", "first-org"]);
        run_git(path, &["config", "ai.barometer.org", "second-org"]);

        let value = git_output_in(path, &["config", "--get", "ai.barometer.org"]).unwrap();
        assert_eq!(value, "second-org");
    }

    // -----------------------------------------------------------------------
    // Multiple commits — verify head_hash changes
    // -----------------------------------------------------------------------

    #[test]
    fn test_head_hash_changes_after_new_commit() {
        let dir = init_temp_repo();
        let path = dir.path();

        let hash1 = run_git(path, &["rev-parse", "HEAD"]);

        // Make another commit
        std::fs::write(path.join("file2.txt"), "content").unwrap();
        run_git(path, &["add", "file2.txt"]);
        run_git(path, &["commit", "-m", "second commit"]);

        let hash2 = run_git(path, &["rev-parse", "HEAD"]);

        assert_ne!(hash1, hash2);
        assert_eq!(hash2.len(), 40);
    }

    // -----------------------------------------------------------------------
    // validate_commit_hash
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_commit_hash_valid_short() {
        assert!(validate_commit_hash("abcdef0").is_ok());
    }

    #[test]
    fn test_validate_commit_hash_valid_full() {
        assert!(validate_commit_hash("abcdef0123456789abcdef0123456789abcdef01").is_ok());
    }

    #[test]
    fn test_validate_commit_hash_rejects_flag_injection() {
        assert!(validate_commit_hash("--help").is_err());
    }

    #[test]
    fn test_validate_commit_hash_rejects_too_short() {
        assert!(validate_commit_hash("abc").is_err());
    }

    #[test]
    fn test_validate_commit_hash_rejects_non_hex() {
        assert!(validate_commit_hash("ghijklm").is_err());
    }

    #[test]
    fn test_validate_commit_hash_rejects_empty() {
        assert!(validate_commit_hash("").is_err());
    }

    #[test]
    fn test_validate_commit_hash_rejects_too_long() {
        assert!(validate_commit_hash("a".repeat(41).as_str()).is_err());
    }

    // -----------------------------------------------------------------------
    // parse_org_from_url — edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_org_from_url_https_with_trailing_slash() {
        // Trailing slash after org — org segment should still parse
        let org = parse_org_from_url("https://github.com/org/");
        assert_eq!(org, Some("org".to_string()));
    }

    #[test]
    fn test_parse_org_from_url_https_host_only() {
        // No org segment after host
        let org = parse_org_from_url("https://github.com/");
        assert_eq!(org, None);
    }

    #[test]
    fn test_parse_org_from_url_https_host_no_trailing_slash() {
        let org = parse_org_from_url("https://github.com");
        assert_eq!(org, None);
    }

    #[test]
    fn test_parse_org_from_url_ssh_nested_path() {
        // SSH with nested paths — org is the first segment after the colon
        let org = parse_org_from_url("git@github.com:org/sub/repo.git");
        assert_eq!(org, Some("org".to_string()));
    }

    #[test]
    fn test_parse_org_from_url_https_with_port() {
        let org = parse_org_from_url("https://github.com:443/org/repo.git");
        // The host segment is "github.com:443", org is next path segment
        assert_eq!(org, Some("org".to_string()));
    }

    #[test]
    fn test_parse_org_from_url_https_with_auth() {
        // URL with authentication credentials embedded
        let org = parse_org_from_url("https://user:pass@github.com/org/repo.git");
        // "user:pass@github.com" is treated as host, "org" is the org
        assert_eq!(org, Some("org".to_string()));
    }

    // -----------------------------------------------------------------------
    // Public API tests — use set_current_dir, must run serially
    //
    // These tests exercise the actual Rust wrapper functions against temp
    // repos to ensure the wrappers (argument order, trim, error mapping)
    // work correctly, not just the underlying git commands.
    // -----------------------------------------------------------------------

    /// Helper: create a temp repo and chdir into it. Returns the TempDir
    /// (must be kept alive to prevent cleanup) and the original cwd for
    /// restoration.
    fn enter_temp_repo() -> (TempDir, PathBuf) {
        let original_cwd = std::env::current_dir().expect("failed to get cwd");
        let dir = init_temp_repo();
        std::env::set_current_dir(dir.path()).expect("failed to chdir into temp repo");
        (dir, original_cwd)
    }

    #[test]
    #[serial]
    fn test_api_repo_root() {
        let (_dir, original_cwd) = enter_temp_repo();
        let root = repo_root().expect("repo_root failed");
        assert!(root.join("README.md").exists());
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_api_head_hash() {
        let (_dir, original_cwd) = enter_temp_repo();
        let hash = head_hash().expect("head_hash failed");
        assert_eq!(hash.len(), 40);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_api_head_timestamp() {
        let (_dir, original_cwd) = enter_temp_repo();
        let ts = head_timestamp().expect("head_timestamp failed");
        assert!(ts > 1_577_836_800); // After 2020
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_api_note_exists_and_add_note() {
        let (_dir, original_cwd) = enter_temp_repo();
        let hash = head_hash().expect("head_hash failed");

        // No note yet
        assert!(!note_exists(&hash).expect("note_exists failed"));

        // Add a note via the public API
        add_note(&hash, "test session data").expect("add_note failed");

        // Now it should exist
        assert!(note_exists(&hash).expect("note_exists failed after add"));

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_api_has_upstream_no_remote() {
        let (_dir, original_cwd) = enter_temp_repo();
        assert!(!has_upstream().expect("has_upstream failed"));
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_api_has_upstream_with_remote() {
        let (dir, original_cwd) = enter_temp_repo();
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/test-org/test-repo.git",
            ],
        );
        assert!(has_upstream().expect("has_upstream failed"));
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_api_remote_org_no_remote() {
        let (_dir, original_cwd) = enter_temp_repo();
        let org = remote_org().expect("remote_org failed");
        assert_eq!(org, None);
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_api_remote_org_with_remote() {
        let (dir, original_cwd) = enter_temp_repo();
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:acme-corp/widgets.git",
            ],
        );
        let org = remote_org().expect("remote_org failed");
        assert_eq!(org, Some("acme-corp".to_string()));
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_api_config_get_missing() {
        let (_dir, original_cwd) = enter_temp_repo();
        let val = config_get("ai.barometer.nonexistent").expect("config_get failed");
        assert_eq!(val, None);
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_api_config_set_then_get() {
        let (_dir, original_cwd) = enter_temp_repo();
        config_set("ai.barometer.autopush", "true").expect("config_set failed");
        let val = config_get("ai.barometer.autopush").expect("config_get failed");
        assert_eq!(val, Some("true".to_string()));
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // check_enabled
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_check_enabled_default_true() {
        let (_dir, original_cwd) = enter_temp_repo();

        // No config set -- should default to enabled
        assert!(check_enabled());

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_check_enabled_explicitly_true() {
        let (dir, original_cwd) = enter_temp_repo();

        run_git(dir.path(), &["config", "ai.barometer.enabled", "true"]);
        assert!(check_enabled());

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_check_enabled_explicitly_false() {
        let (dir, original_cwd) = enter_temp_repo();

        run_git(dir.path(), &["config", "ai.barometer.enabled", "false"]);
        assert!(!check_enabled());

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_check_enabled_other_value_treated_as_true() {
        let (dir, original_cwd) = enter_temp_repo();

        run_git(dir.path(), &["config", "ai.barometer.enabled", "yes"]);
        assert!(check_enabled());

        std::env::set_current_dir(original_cwd).unwrap();
    }
}
