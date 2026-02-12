//! Agent log discovery module.
//!
//! Discovers AI coding agent session logs (Claude Code, Codex) on disk
//! and filters candidate files by modification time relative to a commit.

pub mod antigravity;
pub mod claude;
pub mod codex;
pub mod copilot;
pub mod cursor;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// Encode a repository path into the format Claude Code uses for project directories.
///
/// Replaces all `/` characters with `-`. The leading `/` becomes a leading `-`.
///
/// # Examples
/// - `/Users/foo/bar` -> `-Users-foo-bar`
/// - `/home/user/dev/my-repo` -> `-home-user-dev-my-repo`
pub fn encode_repo_path(path: &Path) -> String {
    let path_str = path.to_string_lossy();
    path_str.replace('/', "-")
}

/// Filter files in the given directories whose modification time falls within
/// +/- `window_secs` of `commit_time`, and whose extension matches `exts`.
pub fn candidate_files_with_exts(
    dirs: &[PathBuf],
    commit_time: i64,
    window_secs: i64,
    exts: &[&str],
) -> Vec<PathBuf> {
    let mut results = Vec::new();

    for dir in dirs {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let path = entry.path();

            // Only consider files with matching extensions
            let ext = match path.extension().and_then(|e| e.to_str()) {
                Some(e) => e.to_ascii_lowercase(),
                None => continue,
            };
            if !exts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(&ext))
            {
                continue;
            }

            // Only consider regular files (not directories).
            // Use fs::metadata instead of entry.metadata() so that symlinks
            // are followed -- entry.metadata() uses lstat on Unix, which
            // would cause symlinked files to be skipped.
            let metadata = match fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !metadata.is_file() {
                continue;
            }

            // Check modification time against the commit time window
            let mtime = match metadata.modified() {
                Ok(t) => t,
                Err(_) => continue,
            };

            let mtime_epoch = match mtime.duration_since(UNIX_EPOCH) {
                Ok(d) => d.as_secs() as i64,
                Err(_) => continue, // mtime before Unix epoch -- skip
            };

            let diff = (mtime_epoch - commit_time).abs();
            if diff <= window_secs {
                results.push(path);
            }
        }
    }

    results
}

/// Find files in the given directories whose modification time is within
/// `since_secs` of `now`, and whose extension matches `exts`.
pub fn recent_files_with_exts(
    dirs: &[PathBuf],
    now: i64,
    since_secs: i64,
    exts: &[&str],
) -> Vec<PathBuf> {
    let cutoff = now - since_secs;
    let mut results = Vec::new();

    for dir in dirs {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let path = entry.path();

            // Only consider files with matching extensions
            let ext = match path.extension().and_then(|e| e.to_str()) {
                Some(e) => e.to_ascii_lowercase(),
                None => continue,
            };
            if !exts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(&ext))
            {
                continue;
            }

            // Only consider regular files (follow symlinks)
            let metadata = match fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !metadata.is_file() {
                continue;
            }

            // Check modification time
            let mtime = match metadata.modified() {
                Ok(t) => t,
                Err(_) => continue,
            };

            let mtime_epoch = match mtime.duration_since(UNIX_EPOCH) {
                Ok(d) => d.as_secs() as i64,
                Err(_) => continue,
            };

            if mtime_epoch >= cutoff {
                results.push(path);
            }
        }
    }

    results
}

/// Resolve the user's home directory.
///
/// Returns `None` if the home directory cannot be determined.
/// Uses the `HOME` environment variable, which works on Unix/macOS.
pub fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

/// Recursively find directories named `chatSessions` under a workspaceStorage root.
pub fn find_chat_session_dirs(root: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let path = entry.path();
            if path.is_dir() {
                if path.file_name().and_then(|n| n.to_str()) == Some("chatSessions") {
                    results.push(path);
                } else {
                    stack.push(path);
                }
            }
        }
    }

    results
}

/// Collect candidate files across all supported agents for a specific commit.
pub fn all_candidate_files(repo_root: &Path, commit_time: i64, window_secs: i64) -> Vec<PathBuf> {
    let mut results = Vec::new();

    let mut claude_dirs = Vec::new();
    claude_dirs.extend(claude::log_dirs(repo_root));
    results.extend(candidate_files_with_exts(
        &claude_dirs,
        commit_time,
        window_secs,
        &["jsonl"],
    ));

    let codex_dirs = codex::log_dirs();
    results.extend(candidate_files_with_exts(
        &codex_dirs,
        commit_time,
        window_secs,
        &["jsonl"],
    ));

    let cursor_dirs = cursor::log_dirs();
    results.extend(candidate_files_with_exts(
        &cursor_dirs,
        commit_time,
        window_secs,
        &["json", "txt"],
    ));

    let copilot_dirs = copilot::log_dirs();
    results.extend(candidate_files_with_exts(
        &copilot_dirs,
        commit_time,
        window_secs,
        &["json"],
    ));

    let antigravity_dirs = antigravity::log_dirs();
    results.extend(candidate_files_with_exts(
        &antigravity_dirs,
        commit_time,
        window_secs,
        &["json"],
    ));

    results
}

/// Collect recent files across all supported agents.
pub fn all_recent_files(now: i64, since_secs: i64) -> Vec<PathBuf> {
    let mut results = Vec::new();

    let claude_dirs = claude::all_log_dirs();
    results.extend(recent_files_with_exts(
        &claude_dirs,
        now,
        since_secs,
        &["jsonl"],
    ));

    let codex_dirs = codex::all_log_dirs();
    results.extend(recent_files_with_exts(
        &codex_dirs,
        now,
        since_secs,
        &["jsonl"],
    ));

    let cursor_dirs = cursor::all_log_dirs();
    results.extend(recent_files_with_exts(
        &cursor_dirs,
        now,
        since_secs,
        &["json", "txt"],
    ));

    let copilot_dirs = copilot::all_log_dirs();
    results.extend(recent_files_with_exts(
        &copilot_dirs,
        now,
        since_secs,
        &["json"],
    ));

    let antigravity_dirs = antigravity::all_log_dirs();
    results.extend(recent_files_with_exts(
        &antigravity_dirs,
        now,
        since_secs,
        &["json"],
    ));

    results
}

/// Set a file's modification time to a specific Unix epoch timestamp.
///
/// This is a test helper exposed at the module level for use by submodule tests.
/// Uses the `filetime` crate for cross-platform correctness (avoids timezone
/// issues with the `touch` command).
#[cfg(test)]
pub(crate) fn set_file_mtime(path: &Path, epoch_secs: i64) {
    let ft = filetime::FileTime::from_unix_time(epoch_secs, 0);
    filetime::set_file_mtime(path, ft).expect("failed to set file mtime");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // encode_repo_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_typical_path() {
        let path = Path::new("/Users/foo/bar");
        assert_eq!(encode_repo_path(path), "-Users-foo-bar");
    }

    #[test]
    fn test_encode_deep_path() {
        let path = Path::new("/home/user/dev/my-repo");
        assert_eq!(encode_repo_path(path), "-home-user-dev-my-repo");
    }

    #[test]
    fn test_encode_root_path() {
        let path = Path::new("/");
        assert_eq!(encode_repo_path(path), "-");
    }

    #[test]
    fn test_encode_single_component() {
        let path = Path::new("/myrepo");
        assert_eq!(encode_repo_path(path), "-myrepo");
    }

    #[test]
    fn test_encode_path_with_hyphens() {
        let path = Path::new("/Users/my-user/my-project");
        assert_eq!(encode_repo_path(path), "-Users-my-user-my-project");
    }

    #[test]
    fn test_encode_preserves_dots() {
        let path = Path::new("/Users/foo/bar.baz");
        assert_eq!(encode_repo_path(path), "-Users-foo-bar.baz");
    }

    // -----------------------------------------------------------------------
    // candidate_files
    // -----------------------------------------------------------------------

    #[test]
    fn test_candidate_files_within_window() {
        let dir = TempDir::new().unwrap();
        let commit_time: i64 = 1_700_000_000;

        // Create a .jsonl file and set its mtime to commit_time
        let file = dir.path().join("session.jsonl");
        fs::write(&file, "{}").unwrap();
        set_file_mtime(&file, commit_time);

        let result =
            candidate_files_with_exts(&[dir.path().to_path_buf()], commit_time, 600, &["jsonl"]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], file);
    }

    #[test]
    fn test_candidate_files_at_window_boundary() {
        let dir = TempDir::new().unwrap();
        let commit_time: i64 = 1_700_000_000;
        let window: i64 = 600;

        // File at exactly +window seconds (should be included, diff == window)
        let file = dir.path().join("boundary.jsonl");
        fs::write(&file, "{}").unwrap();
        set_file_mtime(&file, commit_time + window);

        let result =
            candidate_files_with_exts(&[dir.path().to_path_buf()], commit_time, window, &["jsonl"]);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_candidate_files_outside_window() {
        let dir = TempDir::new().unwrap();
        let commit_time: i64 = 1_700_000_000;
        let window: i64 = 600;

        // File at +window+1 seconds (should be excluded)
        let file = dir.path().join("too-late.jsonl");
        fs::write(&file, "{}").unwrap();
        set_file_mtime(&file, commit_time + window + 1);

        let result =
            candidate_files_with_exts(&[dir.path().to_path_buf()], commit_time, window, &["jsonl"]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_candidate_files_before_window() {
        let dir = TempDir::new().unwrap();
        let commit_time: i64 = 1_700_000_000;
        let window: i64 = 600;

        // File at -window-1 seconds (should be excluded)
        let file = dir.path().join("too-early.jsonl");
        fs::write(&file, "{}").unwrap();
        set_file_mtime(&file, commit_time - window - 1);

        let result =
            candidate_files_with_exts(&[dir.path().to_path_buf()], commit_time, window, &["jsonl"]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_candidate_files_ignores_non_jsonl() {
        let dir = TempDir::new().unwrap();
        let commit_time: i64 = 1_700_000_000;

        // Create a .txt file with matching mtime
        let txt_file = dir.path().join("session.txt");
        fs::write(&txt_file, "{}").unwrap();
        set_file_mtime(&txt_file, commit_time);

        // Create a .json file (not .jsonl)
        let json_file = dir.path().join("session.json");
        fs::write(&json_file, "{}").unwrap();
        set_file_mtime(&json_file, commit_time);

        let result =
            candidate_files_with_exts(&[dir.path().to_path_buf()], commit_time, 600, &["jsonl"]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_candidate_files_multiple_dirs() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();
        let commit_time: i64 = 1_700_000_000;

        let file1 = dir1.path().join("a.jsonl");
        fs::write(&file1, "{}").unwrap();
        set_file_mtime(&file1, commit_time);

        let file2 = dir2.path().join("b.jsonl");
        fs::write(&file2, "{}").unwrap();
        set_file_mtime(&file2, commit_time);

        let result = candidate_files_with_exts(
            &[dir1.path().to_path_buf(), dir2.path().to_path_buf()],
            commit_time,
            600,
            &["jsonl"],
        );
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_candidate_files_empty_dirs() {
        let result = candidate_files_with_exts(&[], 1_700_000_000, 600, &["jsonl"]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_candidate_files_nonexistent_dir() {
        let result = candidate_files_with_exts(
            &[PathBuf::from("/nonexistent/dir/that/does/not/exist")],
            1_700_000_000,
            600,
            &["jsonl"],
        );
        assert!(result.is_empty());
    }

    #[test]
    fn test_candidate_files_mixed_in_and_out_of_window() {
        let dir = TempDir::new().unwrap();
        let commit_time: i64 = 1_700_000_000;
        let window: i64 = 600;

        // In window
        let in_file = dir.path().join("in.jsonl");
        fs::write(&in_file, "{}").unwrap();
        set_file_mtime(&in_file, commit_time + 300);

        // Out of window
        let out_file = dir.path().join("out.jsonl");
        fs::write(&out_file, "{}").unwrap();
        set_file_mtime(&out_file, commit_time + 1000);

        let result =
            candidate_files_with_exts(&[dir.path().to_path_buf()], commit_time, window, &["jsonl"]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], in_file);
    }

    #[test]
    fn test_candidate_files_ignores_directories_with_jsonl_name() {
        let dir = TempDir::new().unwrap();
        let commit_time: i64 = 1_700_000_000;

        // Create a directory named something.jsonl (should be ignored)
        let fake_dir = dir.path().join("sneaky.jsonl");
        fs::create_dir(&fake_dir).unwrap();

        let result =
            candidate_files_with_exts(&[dir.path().to_path_buf()], commit_time, 600, &["jsonl"]);
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // recent_files
    // -----------------------------------------------------------------------

    #[test]
    fn test_recent_files_within_window() {
        let dir = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        let since_secs: i64 = 7 * 86_400; // 7 days

        // File modified recently (within window)
        let file = dir.path().join("recent.jsonl");
        fs::write(&file, "{}").unwrap();
        set_file_mtime(&file, now - 3 * 86_400); // 3 days ago

        let result =
            recent_files_with_exts(&[dir.path().to_path_buf()], now, since_secs, &["jsonl"]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], file);
    }

    #[test]
    fn test_recent_files_outside_window() {
        let dir = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        let since_secs: i64 = 7 * 86_400; // 7 days

        // File modified too long ago
        let file = dir.path().join("old.jsonl");
        fs::write(&file, "{}").unwrap();
        set_file_mtime(&file, now - 10 * 86_400); // 10 days ago

        let result =
            recent_files_with_exts(&[dir.path().to_path_buf()], now, since_secs, &["jsonl"]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_recent_files_at_boundary() {
        let dir = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        let since_secs: i64 = 7 * 86_400;

        // File at exact cutoff (mtime == now - since_secs)
        let file = dir.path().join("boundary.jsonl");
        fs::write(&file, "{}").unwrap();
        set_file_mtime(&file, now - since_secs); // exactly at the cutoff

        let result =
            recent_files_with_exts(&[dir.path().to_path_buf()], now, since_secs, &["jsonl"]);
        assert_eq!(result.len(), 1, "file at exact cutoff should be included");
    }

    #[test]
    fn test_recent_files_ignores_non_jsonl() {
        let dir = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;

        let txt_file = dir.path().join("session.txt");
        fs::write(&txt_file, "{}").unwrap();
        set_file_mtime(&txt_file, now);

        let result = recent_files_with_exts(&[dir.path().to_path_buf()], now, 86_400, &["jsonl"]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_recent_files_empty_dirs() {
        let result = recent_files_with_exts(&[], 1_700_000_000, 86_400, &["jsonl"]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_recent_files_nonexistent_dir() {
        let result = recent_files_with_exts(
            &[PathBuf::from("/nonexistent/dir")],
            1_700_000_000,
            86_400,
            &["jsonl"],
        );
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // home_dir
    // -----------------------------------------------------------------------

    #[test]
    fn test_home_dir_returns_some() {
        // In a normal test environment, HOME should be set
        let home = home_dir();
        assert!(home.is_some());
        assert!(home.unwrap().is_absolute());
    }
}
