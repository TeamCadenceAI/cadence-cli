//! Claude Code agent log discovery.
//!
//! Claude Code stores session logs under `~/.claude/projects/<encoded-path>/`.
//! The encoded path replaces `/` with `-` in the absolute repo path.
//! For example, a repo at `/Users/foo/bar` produces a directory named
//! `-Users-foo-bar` under `~/.claude/projects/`.

use std::fs;
use std::path::{Path, PathBuf};

use super::{encode_repo_path, home_dir};

/// Return ALL directories under `~/.claude/projects/`.
///
/// Unlike `log_dirs`, this function is not scoped to a specific repository.
/// It returns every project directory, for use by the `backfill` command
/// which needs to scan all sessions regardless of repo.
///
/// Returns an empty `Vec` if:
/// - The home directory cannot be resolved
/// - `~/.claude/projects/` does not exist
pub fn all_log_dirs() -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    all_log_dirs_in(&home)
}

/// Internal: find ALL Claude log directories under a given home directory.
///
/// Separated from `all_log_dirs` for testability.
fn all_log_dirs_in(home: &Path) -> Vec<PathBuf> {
    let projects_dir = home.join(".claude").join("projects");
    let entries = match fs::read_dir(&projects_dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut dirs = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();
        if path.is_dir() {
            dirs.push(path);
        }
    }

    dirs
}

/// Return directories under `~/.claude/projects/` whose names exactly
/// match the encoded form of `repo_path`.
///
/// Returns an empty `Vec` if:
/// - The home directory cannot be resolved
/// - `~/.claude/projects/` does not exist
/// - No matching directories are found
pub fn log_dirs(repo_path: &Path) -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    log_dirs_in(repo_path, &home)
}

/// Internal: find Claude log directories under a given home directory.
///
/// Separated from `log_dirs` for testability -- tests pass a temp directory
/// instead of the real home, avoiding `unsafe` env var manipulation.
fn log_dirs_in(repo_path: &Path, home: &Path) -> Vec<PathBuf> {
    let projects_dir = home.join(".claude").join("projects");
    let entries = match fs::read_dir(&projects_dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let encoded = encode_repo_path(repo_path);

    let mut dirs = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        // Check if the directory name matches the encoded repo path.
        // We require the encoded path to be the complete directory name to
        // avoid false positives: e.g., searching for `/Users/foo/bar`
        // (encoded as `-Users-foo-bar`) should NOT match a directory for
        // `/Users/foo/bar-extra` (encoded as `-Users-foo-bar-extra`).
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        if name == encoded {
            dirs.push(path);
        }
    }

    dirs
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_log_dirs_finds_matching_directory() {
        let home = TempDir::new().unwrap();
        let projects_dir = home.path().join(".claude").join("projects");
        fs::create_dir_all(&projects_dir).unwrap();

        // Create a directory with the exact encoded name
        let encoded = encode_repo_path(Path::new("/Users/foo/bar"));
        let matching_dir = projects_dir.join(&encoded);
        fs::create_dir(&matching_dir).unwrap();

        // Create a non-matching directory
        let other_dir = projects_dir.join("unrelated-project");
        fs::create_dir(&other_dir).unwrap();

        let result = log_dirs_in(Path::new("/Users/foo/bar"), home.path());

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], matching_dir);
    }

    #[test]
    fn test_log_dirs_returns_empty_when_no_match() {
        let home = TempDir::new().unwrap();
        let projects_dir = home.path().join(".claude").join("projects");
        fs::create_dir_all(&projects_dir).unwrap();

        // Create directories that don't match
        fs::create_dir(projects_dir.join("some-other-project")).unwrap();

        let result = log_dirs_in(Path::new("/Users/foo/bar"), home.path());

        assert!(result.is_empty());
    }

    #[test]
    fn test_log_dirs_returns_empty_when_projects_dir_missing() {
        let home = TempDir::new().unwrap();
        // Don't create .claude/projects/

        let result = log_dirs_in(Path::new("/Users/foo/bar"), home.path());

        assert!(result.is_empty());
    }

    #[test]
    fn test_log_dirs_does_not_match_longer_paths() {
        let home = TempDir::new().unwrap();
        let projects_dir = home.path().join(".claude").join("projects");
        fs::create_dir_all(&projects_dir).unwrap();

        let encoded = encode_repo_path(Path::new("/Users/foo/bar"));
        // Exact match should be found
        let dir1 = projects_dir.join(encoded.clone());
        // A longer encoded path (e.g. for /Users/foo/bar-extra) should NOT match
        let dir2 = projects_dir.join(format!("{encoded}-extra"));
        fs::create_dir(&dir1).unwrap();
        fs::create_dir(&dir2).unwrap();

        let result = log_dirs_in(Path::new("/Users/foo/bar"), home.path());

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], dir1);
    }

    #[test]
    fn test_log_dirs_ignores_files_in_projects_dir() {
        let home = TempDir::new().unwrap();
        let projects_dir = home.path().join(".claude").join("projects");
        fs::create_dir_all(&projects_dir).unwrap();

        let encoded = encode_repo_path(Path::new("/Users/foo/bar"));
        // Create a file (not a directory) with a matching name
        let file = projects_dir.join(encoded);
        fs::write(&file, "not a directory").unwrap();

        let result = log_dirs_in(Path::new("/Users/foo/bar"), home.path());

        assert!(result.is_empty());
    }

    #[test]
    fn test_log_dirs_exact_encoded_match() {
        let home = TempDir::new().unwrap();
        let projects_dir = home.path().join(".claude").join("projects");
        fs::create_dir_all(&projects_dir).unwrap();

        // Directory name is exactly the encoded path
        let encoded = encode_repo_path(Path::new("/Users/foo/bar"));
        let dir = projects_dir.join(&encoded);
        fs::create_dir(&dir).unwrap();

        let result = log_dirs_in(Path::new("/Users/foo/bar"), home.path());

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], dir);
    }

    // -----------------------------------------------------------------------
    // all_log_dirs_in
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_log_dirs_returns_all_directories() {
        let home = TempDir::new().unwrap();
        let projects_dir = home.path().join(".claude").join("projects");
        fs::create_dir_all(&projects_dir).unwrap();

        // Create multiple project directories
        fs::create_dir(projects_dir.join("-Users-foo-bar")).unwrap();
        fs::create_dir(projects_dir.join("-Users-baz-qux")).unwrap();
        fs::create_dir(projects_dir.join("-home-user-project")).unwrap();

        let result = all_log_dirs_in(home.path());
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_all_log_dirs_returns_empty_when_no_projects_dir() {
        let home = TempDir::new().unwrap();
        let result = all_log_dirs_in(home.path());
        assert!(result.is_empty());
    }

    #[test]
    fn test_all_log_dirs_ignores_files() {
        let home = TempDir::new().unwrap();
        let projects_dir = home.path().join(".claude").join("projects");
        fs::create_dir_all(&projects_dir).unwrap();

        // Create a file (not a directory)
        fs::write(projects_dir.join("some-file"), "not a dir").unwrap();
        // Create a directory
        fs::create_dir(projects_dir.join("-Users-foo-bar")).unwrap();

        let result = all_log_dirs_in(home.path());
        assert_eq!(result.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Phase 12 hardening: missing ~/.claude/ directory
    // -----------------------------------------------------------------------

    #[test]
    fn test_log_dirs_graceful_when_claude_dir_missing() {
        // If ~/.claude/ does not exist at all (not just projects/),
        // log_dirs should return an empty Vec, not error.
        let home = TempDir::new().unwrap();
        // Don't create .claude/ at all

        let result = log_dirs_in(Path::new("/Users/foo/bar"), home.path());
        assert!(result.is_empty());
    }

    #[test]
    fn test_all_log_dirs_graceful_when_claude_dir_missing() {
        // Same for all_log_dirs: missing ~/.claude/ should not error.
        let home = TempDir::new().unwrap();
        let result = all_log_dirs_in(home.path());
        assert!(result.is_empty());
    }

    #[test]
    fn test_log_dirs_hardcoded_roundtrip() {
        // This test uses a hardcoded directory name (not computed via
        // encode_repo_path) to catch encoding bugs. If encode_repo_path
        // has a bug, the other tests that use it to compute both the
        // directory name and the search term would still pass. This test
        // breaks that circularity.
        let home = TempDir::new().unwrap();
        let projects_dir = home.path().join(".claude").join("projects");
        fs::create_dir_all(&projects_dir).unwrap();

        // Hardcoded: the encoding of "/Users/dave/dev/my-project" must be
        // "-Users-dave-dev-my-project" (every / replaced with -)
        let hardcoded_dir = projects_dir.join("-Users-dave-dev-my-project");
        fs::create_dir(&hardcoded_dir).unwrap();

        let result = log_dirs_in(Path::new("/Users/dave/dev/my-project"), home.path());

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], hardcoded_dir);
    }
}
