//! Claude Code agent log discovery.
//!
//! Claude Code stores session logs under `~/.claude/projects/<encoded-path>/`.
//! The encoded path replaces `/` with `-` in the absolute repo path.
//! For example, a repo at `/Users/foo/bar` produces directories matching
//! `~/.claude/projects/*-Users-foo-bar*`.

use std::fs;
use std::path::{Path, PathBuf};

use super::{encode_repo_path, home_dir};

/// Return directories under `~/.claude/projects/` whose names contain
/// the encoded form of `repo_path`.
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

        // Check if the directory name contains the encoded repo path
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        if name.contains(&encoded) {
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

        // Create a matching directory
        let encoded = encode_repo_path(Path::new("/Users/foo/bar"));
        let matching_dir = projects_dir.join(format!("abc{encoded}xyz"));
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
    fn test_log_dirs_finds_multiple_matching_directories() {
        let home = TempDir::new().unwrap();
        let projects_dir = home.path().join(".claude").join("projects");
        fs::create_dir_all(&projects_dir).unwrap();

        let encoded = encode_repo_path(Path::new("/Users/foo/bar"));
        // Claude may have multiple directories for the same repo (e.g. with suffixes)
        let dir1 = projects_dir.join(encoded.clone());
        let dir2 = projects_dir.join(format!("{encoded}-v2"));
        fs::create_dir(&dir1).unwrap();
        fs::create_dir(&dir2).unwrap();

        let result = log_dirs_in(Path::new("/Users/foo/bar"), home.path());

        assert_eq!(result.len(), 2);
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
}
