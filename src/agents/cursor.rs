//! Cursor agent log discovery.
//!
//! Cursor stores chat sessions in two places:
//! - VS Code style chatSessions:
//!   - macOS: ~/Library/Application Support/Cursor/User/workspaceStorage/*/chatSessions/*.json
//!   - Linux: ~/.config/Cursor/User/workspaceStorage/*/chatSessions/*.json
//!   - Windows: %APPDATA%\\Cursor\\User\\workspaceStorage\\*\\chatSessions\\*.json
//! - Cursor projects:
//!   ~/.cursor/projects/<workspace-id>/*.{json,txt}

use std::fs;
use std::path::{Path, PathBuf};

use super::{app_config_dir_in, find_chat_session_dirs, home_dir};

/// Return all Cursor log directories for use by the post-commit hook.
pub fn log_dirs() -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    log_dirs_in(&home)
}

/// Return all Cursor log directories for hydrate (not repo-scoped).
pub fn all_log_dirs() -> Vec<PathBuf> {
    log_dirs()
}

fn log_dirs_in(home: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // VS Code style chatSessions.
    let ws_root = app_config_dir_in("Cursor", home)
        .join("User")
        .join("workspaceStorage");
    dirs.extend(find_chat_session_dirs(&ws_root));

    // Cursor projects directory (scan recursively for json/txt files).
    let projects_dir = home.join(".cursor").join("projects");
    collect_dirs_with_exts(&projects_dir, &mut dirs, &["json", "txt"]);

    dirs
}

/// Recursively collect directories that contain at least one file with a matching extension.
fn collect_dirs_with_exts(dir: &Path, results: &mut Vec<PathBuf>, exts: &[&str]) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    let mut has_match = false;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();
        if path.is_dir() {
            collect_dirs_with_exts(&path, results, exts);
        } else if !has_match
            && let Some(ext) = path.extension().and_then(|e| e.to_str())
            && exts.iter().any(|allowed| allowed.eq_ignore_ascii_case(ext))
        {
            has_match = true;
        }
    }

    if has_match {
        results.push(dir.to_path_buf());
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::app_config_dir_in;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_cursor_log_dirs_collects_chat_sessions_and_projects() {
        let home = TempDir::new().unwrap();

        let ws_root = app_config_dir_in("Cursor", home.path())
            .join("User")
            .join("workspaceStorage")
            .join("abc")
            .join("chatSessions");
        fs::create_dir_all(&ws_root).unwrap();

        let projects_dir = home.path().join(".cursor").join("projects").join("p1");
        fs::create_dir_all(&projects_dir).unwrap();
        fs::write(projects_dir.join("session.txt"), "content").unwrap();

        let dirs = log_dirs_in(home.path());

        assert!(dirs.contains(&ws_root));
        assert!(dirs.contains(&projects_dir));
    }
}
