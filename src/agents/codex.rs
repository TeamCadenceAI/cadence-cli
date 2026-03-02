//! Codex agent log discovery.
//!
//! Codex stores session logs under `~/.codex/sessions/`.
//! Unlike Claude Code, Codex session directories are not scoped to a
//! specific repo path -- all sessions live in a flat directory.

use std::path::{Path, PathBuf};

use super::home_dir;

/// Return ALL directories containing `.jsonl` files under `~/.codex/sessions/`.
///
/// Codex stores session logs in a date-based directory hierarchy:
/// `~/.codex/sessions/YYYY/MM/DD/*.jsonl`. This function recursively
/// traverses the hierarchy to find the leaf directories that actually
/// contain session log files.
///
/// Used by the `backfill` command to scan all sessions regardless of repo.
#[allow(dead_code)]
pub fn all_log_dirs() -> Vec<PathBuf> {
    block_on_io(async {
        let home = match home_dir() {
            Some(h) => h,
            None => return Vec::new(),
        };
        log_dirs_in(&home).await
    })
}

#[allow(dead_code)]
fn block_on_io<T>(fut: impl std::future::Future<Output = T>) -> T {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(fut))
    } else {
        tokio::runtime::Runtime::new()
            .expect("failed to create tokio runtime")
            .block_on(fut)
    }
}

pub async fn all_log_dirs_async() -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    log_dirs_in(&home).await
}

/// Internal: find Codex session directories under a given home directory.
///
/// Recursively traverses `~/.codex/sessions/` to find directories that
/// contain `.jsonl` files, since Codex uses a date-based hierarchy
/// (YYYY/MM/DD/) rather than flat directories.
///
/// Separated from `log_dirs` for testability -- tests pass a temp directory
/// instead of the real home, avoiding `unsafe` env var manipulation.
async fn log_dirs_in(home: &Path) -> Vec<PathBuf> {
    let codex_home = std::env::var("CODEX_HOME").ok().map(PathBuf::from);
    log_dirs_in_with_codex_home(home, codex_home.as_deref()).await
}

async fn log_dirs_in_with_codex_home(home: &Path, codex_home: Option<&Path>) -> Vec<PathBuf> {
    let mut session_roots = vec![home.join(".codex").join("sessions")];
    if let Some(custom_home) = codex_home {
        let candidate = custom_home.join("sessions");
        if !session_roots.contains(&candidate) {
            session_roots.push(candidate);
        }
    }

    let mut dirs = Vec::new();
    for root in &session_roots {
        collect_dirs_with_jsonl(root, &mut dirs).await;
    }
    dirs.sort();
    dirs.dedup();
    dirs
}

/// Recursively collect directories that contain at least one `.jsonl` file.
async fn collect_dirs_with_jsonl(root: &Path, results: &mut Vec<PathBuf>) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        let mut has_jsonl = false;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if !has_jsonl && path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                has_jsonl = true;
            }
        }

        if has_jsonl {
            results.push(dir);
        }
    }
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
    fn test_log_dirs_finds_directories_with_jsonl_files() {
        let home = TempDir::new().unwrap();
        let sessions_dir = home.path().join(".codex").join("sessions");

        // Create Codex-style date hierarchy with .jsonl files
        let day1 = sessions_dir.join("2026").join("02").join("10");
        let day2 = sessions_dir.join("2026").join("02").join("09");
        fs::create_dir_all(&day1).unwrap();
        fs::create_dir_all(&day2).unwrap();
        fs::write(day1.join("session-abc.jsonl"), "{}").unwrap();
        fs::write(day2.join("session-def.jsonl"), "{}").unwrap();

        let result = block_on_io(log_dirs_in(home.path()));

        assert_eq!(result.len(), 2);
        assert!(result.contains(&day1));
        assert!(result.contains(&day2));
    }

    #[test]
    fn test_log_dirs_skips_empty_directories() {
        let home = TempDir::new().unwrap();
        let sessions_dir = home.path().join(".codex").join("sessions");

        // Directory with jsonl file
        let day1 = sessions_dir.join("2026").join("02").join("10");
        fs::create_dir_all(&day1).unwrap();
        fs::write(day1.join("session.jsonl"), "{}").unwrap();

        // Empty directory (no jsonl files)
        let day2 = sessions_dir.join("2026").join("02").join("09");
        fs::create_dir_all(&day2).unwrap();

        let result = block_on_io(log_dirs_in(home.path()));

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], day1);
    }

    #[test]
    fn test_log_dirs_returns_empty_when_sessions_dir_missing() {
        let home = TempDir::new().unwrap();
        // Don't create .codex/sessions/

        let result = block_on_io(log_dirs_in(home.path()));

        assert!(result.is_empty());
    }

    #[test]
    fn test_log_dirs_ignores_non_jsonl_files() {
        let home = TempDir::new().unwrap();
        let sessions_dir = home.path().join(".codex").join("sessions");
        let day_dir = sessions_dir.join("2026").join("01").join("01");
        fs::create_dir_all(&day_dir).unwrap();

        // Only a .txt file, no .jsonl
        fs::write(day_dir.join("not-a-session.txt"), "content").unwrap();

        let result = block_on_io(log_dirs_in(home.path()));

        assert!(result.is_empty());
    }

    #[test]
    fn test_log_dirs_finds_flat_and_nested_dirs() {
        // Handles both flat directories and date-based hierarchy
        let home = TempDir::new().unwrap();
        let sessions_dir = home.path().join(".codex").join("sessions");

        // Nested date directory
        let nested = sessions_dir.join("2026").join("02").join("10");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("session.jsonl"), "{}").unwrap();

        // Flat directory at top level (in case Codex format changes)
        let flat = sessions_dir.join("flat-session");
        fs::create_dir_all(&flat).unwrap();
        fs::write(flat.join("session.jsonl"), "{}").unwrap();

        let result = block_on_io(log_dirs_in(home.path()));

        assert_eq!(result.len(), 2);
        assert!(result.contains(&nested));
        assert!(result.contains(&flat));
    }

    // -----------------------------------------------------------------------
    // Phase 12 hardening: missing ~/.codex/ directory
    // -----------------------------------------------------------------------

    #[test]
    fn test_log_dirs_graceful_when_codex_dir_missing() {
        // If ~/.codex/ does not exist at all, log_dirs should return
        // an empty Vec, not error.
        let home = TempDir::new().unwrap();
        // Don't create .codex/ at all

        let result = block_on_io(log_dirs_in(home.path()));
        assert!(result.is_empty());
    }

    #[test]
    fn test_log_dirs_empty_sessions_directory() {
        let home = TempDir::new().unwrap();
        let sessions_dir = home.path().join(".codex").join("sessions");
        fs::create_dir_all(&sessions_dir).unwrap();
        // Sessions dir exists but is empty

        let result = block_on_io(log_dirs_in(home.path()));

        assert!(result.is_empty());
    }

    #[test]
    fn test_log_dirs_supports_codex_home_override() {
        let home = TempDir::new().unwrap();
        let codex_home = TempDir::new().unwrap();
        let override_day = codex_home
            .path()
            .join("sessions")
            .join("2026")
            .join("02")
            .join("10");
        fs::create_dir_all(&override_day).unwrap();
        fs::write(override_day.join("zed-session.jsonl"), "{}").unwrap();

        let result = block_on_io(log_dirs_in_with_codex_home(
            home.path(),
            Some(codex_home.path()),
        ));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], override_day);
    }

    #[test]
    fn test_log_dirs_dedupes_default_and_override_roots() {
        let home = TempDir::new().unwrap();
        let shared_home = home.path().join(".codex");
        let day = shared_home
            .join("sessions")
            .join("2026")
            .join("02")
            .join("10");
        fs::create_dir_all(&day).unwrap();
        fs::write(day.join("session.jsonl"), "{}").unwrap();

        let result = block_on_io(log_dirs_in_with_codex_home(home.path(), Some(&shared_home)));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], day);
    }
}
