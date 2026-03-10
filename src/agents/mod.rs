//! Agent log discovery module.
//!
//! Discovers AI coding agent session logs on disk
//! and filters candidate files by modification time relative to a cutoff window.

pub mod amp_code;
pub mod antigravity;
pub mod claude;
pub mod cline;
pub mod codex;
pub mod copilot;
pub mod cursor;
pub mod kiro;
pub mod opencode;
pub mod roo_code;
pub mod warp;
pub mod windsurf;

use crate::scanner::AgentType;
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

#[async_trait]
pub trait AgentExplorer {
    async fn discover_recent(&self, now: i64, since_secs: i64) -> Vec<SessionLog>;
}

#[derive(Debug, Clone)]
pub enum SessionSource {
    File(PathBuf),
    Inline { label: String, content: String },
}

#[derive(Debug, Clone)]
pub struct SessionLog {
    pub agent_type: AgentType,
    pub source: SessionSource,
    pub updated_at: Option<i64>,
}

impl SessionLog {
    pub fn source_label(&self) -> String {
        match &self.source {
            SessionSource::File(path) => path.to_string_lossy().to_string(),
            SessionSource::Inline { label, .. } => label.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveredFile {
    pub path: PathBuf,
    pub mtime_epoch: i64,
}

/// Find files in the given directories whose modification time is within
/// `since_secs` of `now`, and whose extension matches `exts`.
pub async fn recent_files_with_exts(
    dirs: &[PathBuf],
    now: i64,
    since_secs: i64,
    exts: &[&str],
) -> Vec<DiscoveredFile> {
    let cutoff = now - since_secs;
    let mut results = Vec::new();

    for dir in dirs {
        let mut entries = match tokio::fs::read_dir(dir).await {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        while let Ok(Some(entry)) = entries.next_entry().await {
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
            let metadata = match tokio::fs::metadata(&path).await {
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
                results.push(DiscoveredFile { path, mtime_epoch });
            }
        }
    }

    results
}

/// Recursively collect directories that contain at least one file with
/// an extension listed in `exts` (case-insensitive).
pub async fn collect_dirs_with_exts(root: &Path, results: &mut Vec<PathBuf>, exts: &[&str]) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        let mut has_match = false;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let file_type = match entry.file_type().await {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file()
                && !has_match
                && let Some(ext) = path.extension().and_then(|e| e.to_str())
                && exts.iter().any(|allowed| allowed.eq_ignore_ascii_case(ext))
            {
                has_match = true;
            }
        }

        if has_match {
            results.push(dir);
        }
    }
}

/// Resolve the user's home directory.
///
/// Returns `None` if the home directory cannot be determined.
/// Uses `HOME` on Unix/macOS and `USERPROFILE`/`HOMEDRIVE`+`HOMEPATH` on Windows.
pub fn home_dir() -> Option<PathBuf> {
    if let Ok(home) = std::env::var("HOME") {
        return Some(PathBuf::from(home));
    }
    if let Ok(profile) = std::env::var("USERPROFILE") {
        return Some(PathBuf::from(profile));
    }
    let drive = std::env::var("HOMEDRIVE").ok();
    let path = std::env::var("HOMEPATH").ok();
    match (drive, path) {
        (Some(drive), Some(path)) => Some(PathBuf::from(format!("{}{}", drive, path))),
        _ => None,
    }
}

pub fn app_config_dir_in(app: &str, home: &Path) -> PathBuf {
    let is_real_home = home_dir().as_deref() == Some(home);

    if cfg!(target_os = "macos") {
        home.join("Library").join("Application Support").join(app)
    } else if cfg!(target_os = "windows") {
        if is_real_home && let Ok(appdata) = std::env::var("APPDATA") {
            PathBuf::from(appdata).join(app)
        } else {
            home.join("AppData").join("Roaming").join(app)
        }
    } else {
        let base = if is_real_home {
            std::env::var("XDG_CONFIG_HOME")
                .ok()
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".config"))
        } else {
            home.join(".config")
        };
        base.join(app)
    }
}

/// Recursively find directories named `chatSessions` under a workspaceStorage root.
pub async fn find_chat_session_dirs(root: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let file_type = match entry.file_type().await {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };
            if file_type.is_dir() {
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

/// Collect recent session logs across all supported agents.
pub async fn discover_recent_sessions(now: i64, since_secs: i64) -> Vec<SessionLog> {
    let (
        claude_logs,
        codex_logs,
        cursor_logs,
        copilot_logs,
        cline_logs,
        roo_logs,
        opencode_logs,
        kiro_logs,
        amp_logs,
        antigravity_logs,
        windsurf_logs,
        warp_logs,
    ) = tokio::join!(
        claude::ClaudeExplorer.discover_recent(now, since_secs),
        codex::CodexExplorer.discover_recent(now, since_secs),
        cursor::CursorExplorer.discover_recent(now, since_secs),
        copilot::CopilotExplorer.discover_recent(now, since_secs),
        cline::ClineExplorer.discover_recent(now, since_secs),
        roo_code::RooCodeExplorer.discover_recent(now, since_secs),
        opencode::OpenCodeExplorer.discover_recent(now, since_secs),
        kiro::KiroExplorer.discover_recent(now, since_secs),
        amp_code::AmpCodeExplorer.discover_recent(now, since_secs),
        antigravity::AntigravityExplorer.discover_recent(now, since_secs),
        windsurf::WindsurfExplorer.discover_recent(now, since_secs),
        warp::WarpExplorer.discover_recent(now, since_secs),
    );

    let mut results = Vec::new();
    results.extend(claude_logs);
    results.extend(codex_logs);
    results.extend(cursor_logs);
    results.extend(copilot_logs);
    results.extend(cline_logs);
    results.extend(roo_logs);
    results.extend(opencode_logs);
    results.extend(kiro_logs);
    results.extend(amp_logs);
    results.extend(antigravity_logs);
    results.extend(windsurf_logs);
    results.extend(warp_logs);
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
    use serial_test::serial;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // recent_files
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_recent_files_within_window() {
        let dir = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        let since_secs: i64 = 7 * 86_400; // 7 days

        // File modified recently (within window)
        let file = dir.path().join("recent.jsonl");
        tokio::fs::write(&file, "{}").await.unwrap();
        set_file_mtime(&file, now - 3 * 86_400); // 3 days ago

        let result =
            recent_files_with_exts(&[dir.path().to_path_buf()], now, since_secs, &["jsonl"]).await;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].path, file);
    }

    #[tokio::test]
    async fn test_recent_files_outside_window() {
        let dir = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        let since_secs: i64 = 7 * 86_400; // 7 days

        // File modified too long ago
        let file = dir.path().join("old.jsonl");
        tokio::fs::write(&file, "{}").await.unwrap();
        set_file_mtime(&file, now - 10 * 86_400); // 10 days ago

        let result =
            recent_files_with_exts(&[dir.path().to_path_buf()], now, since_secs, &["jsonl"]).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_recent_files_at_boundary() {
        let dir = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        let since_secs: i64 = 7 * 86_400;

        // File at exact cutoff (mtime == now - since_secs)
        let file = dir.path().join("boundary.jsonl");
        tokio::fs::write(&file, "{}").await.unwrap();
        set_file_mtime(&file, now - since_secs); // exactly at the cutoff

        let result =
            recent_files_with_exts(&[dir.path().to_path_buf()], now, since_secs, &["jsonl"]).await;
        assert_eq!(result.len(), 1, "file at exact cutoff should be included");
    }

    #[tokio::test]
    async fn test_recent_files_ignores_non_jsonl() {
        let dir = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;

        let txt_file = dir.path().join("session.txt");
        tokio::fs::write(&txt_file, "{}").await.unwrap();
        set_file_mtime(&txt_file, now);

        let result =
            recent_files_with_exts(&[dir.path().to_path_buf()], now, 86_400, &["jsonl"]).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_recent_files_empty_dirs() {
        let result = recent_files_with_exts(&[], 1_700_000_000, 86_400, &["jsonl"]).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_recent_files_nonexistent_dir() {
        let result = recent_files_with_exts(
            &[PathBuf::from("/nonexistent/dir")],
            1_700_000_000,
            86_400,
            &["jsonl"],
        )
        .await;
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

    #[test]
    #[serial]
    fn test_home_dir_falls_back_to_userprofile() {
        let home_backup = std::env::var("HOME").ok();
        let userprofile_backup = std::env::var("USERPROFILE").ok();
        let homedrive_backup = std::env::var("HOMEDRIVE").ok();
        let homepath_backup = std::env::var("HOMEPATH").ok();

        unsafe {
            std::env::remove_var("HOME");
            std::env::remove_var("HOMEDRIVE");
            std::env::remove_var("HOMEPATH");
            std::env::set_var("USERPROFILE", "/tmp/test-userprofile");
        }

        let result = home_dir();
        assert_eq!(result, Some(PathBuf::from("/tmp/test-userprofile")));

        match home_backup {
            Some(v) => unsafe { std::env::set_var("HOME", v) },
            None => unsafe { std::env::remove_var("HOME") },
        }
        match userprofile_backup {
            Some(v) => unsafe { std::env::set_var("USERPROFILE", v) },
            None => unsafe { std::env::remove_var("USERPROFILE") },
        }
        match homedrive_backup {
            Some(v) => unsafe { std::env::set_var("HOMEDRIVE", v) },
            None => unsafe { std::env::remove_var("HOMEDRIVE") },
        }
        match homepath_backup {
            Some(v) => unsafe { std::env::set_var("HOMEPATH", v) },
            None => unsafe { std::env::remove_var("HOMEPATH") },
        }
    }

    #[test]
    fn test_app_config_dir_in_platform() {
        let home = PathBuf::from("/home/tester");
        let dir = app_config_dir_in("Code", &home);
        if cfg!(target_os = "macos") {
            assert_eq!(
                dir,
                PathBuf::from("/home/tester/Library/Application Support/Code")
            );
        } else if cfg!(target_os = "windows") {
            assert_eq!(dir, home.join("AppData").join("Roaming").join("Code"));
        } else {
            assert_eq!(dir, home.join(".config").join("Code"));
        }
    }
}
