//! Agent log discovery module.
//!
//! Discovers AI coding agent session logs (Claude Code, Codex) on disk
//! and filters candidate files by modification time relative to a commit.

pub mod claude;
pub mod codex;

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

/// Filter `.jsonl` files in the given directories whose modification time
/// falls within +/- `window_secs` of `commit_time`.
///
/// - `dirs`: directories to search for `.jsonl` files
/// - `commit_time`: Unix epoch timestamp of the commit
/// - `window_secs`: maximum absolute difference in seconds between file mtime and commit_time
///
/// Files that cannot be read or whose metadata is unavailable are silently skipped.
pub fn candidate_files(dirs: &[PathBuf], commit_time: i64, window_secs: i64) -> Vec<PathBuf> {
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

            // Only consider .jsonl files
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }

            // Only consider regular files (not directories or symlinks)
            let metadata = match entry.metadata() {
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

/// Resolve the user's home directory.
///
/// Returns `None` if the home directory cannot be determined.
/// Uses the `HOME` environment variable, which works on Unix/macOS.
pub fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
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

        let result = candidate_files(&[dir.path().to_path_buf()], commit_time, 600);
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

        let result = candidate_files(&[dir.path().to_path_buf()], commit_time, window);
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

        let result = candidate_files(&[dir.path().to_path_buf()], commit_time, window);
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

        let result = candidate_files(&[dir.path().to_path_buf()], commit_time, window);
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

        let result = candidate_files(&[dir.path().to_path_buf()], commit_time, 600);
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

        let result = candidate_files(
            &[dir1.path().to_path_buf(), dir2.path().to_path_buf()],
            commit_time,
            600,
        );
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_candidate_files_empty_dirs() {
        let result = candidate_files(&[], 1_700_000_000, 600);
        assert!(result.is_empty());
    }

    #[test]
    fn test_candidate_files_nonexistent_dir() {
        let result = candidate_files(
            &[PathBuf::from("/nonexistent/dir/that/does/not/exist")],
            1_700_000_000,
            600,
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

        let result = candidate_files(&[dir.path().to_path_buf()], commit_time, window);
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

        let result = candidate_files(&[dir.path().to_path_buf()], commit_time, 600);
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
