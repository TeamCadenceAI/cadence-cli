//! Claude Code agent log discovery.
//!
//! Claude Code stores transcript logs under `~/.claude/projects/<encoded-path>/`.
//! The Claude desktop app also writes session manifests under
//! `~/Library/Application Support/Claude/claude-code-sessions/` (or the
//! platform-equivalent config directory), which can advance a session's recency
//! even when the underlying transcript file is not the freshest file on disk.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::{
    AgentExplorer, SessionLog, SessionSource, app_config_dir_in, collect_dirs_with_exts, home_dir,
    recent_files_with_exts,
};
use crate::scanner::AgentType;
use async_trait::async_trait;

pub struct ClaudeExplorer;

#[async_trait]
impl AgentExplorer for ClaudeExplorer {
    async fn discover_recent(&self, now: i64, since_secs: i64) -> Vec<SessionLog> {
        let home = match home_dir() {
            Some(h) => h,
            None => return Vec::new(),
        };
        discover_recent_in(&home, now, since_secs).await
    }
}

/// Internal: find ALL Claude log directories under a given home directory.
///
/// Separated from `all_log_dirs` for testability.
async fn all_log_dirs_in(home: &Path) -> Vec<PathBuf> {
    let projects_dir = home.join(".claude").join("projects");
    let mut entries = match tokio::fs::read_dir(&projects_dir).await {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut dirs = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.is_dir() {
            dirs.push(path);
        }
    }

    dirs
}

async fn desktop_manifest_dirs_in(home: &Path) -> Vec<PathBuf> {
    let root = app_config_dir_in("Claude", home).join("claude-code-sessions");
    let mut dirs = Vec::new();
    collect_dirs_with_exts(&root, &mut dirs, &["json"]).await;
    dirs
}

async fn discover_recent_in(home: &Path, now: i64, since_secs: i64) -> Vec<SessionLog> {
    let project_dirs = all_log_dirs_in(home).await;
    let mut discovered: HashMap<String, SessionLog> =
        recent_files_with_exts(&project_dirs, now, since_secs, &["jsonl"])
            .await
            .into_iter()
            .map(|file| {
                let log = SessionLog {
                    agent_type: AgentType::Claude,
                    source: SessionSource::File(file.path),
                    updated_at: Some(file.mtime_epoch),
                };
                (log.source_label(), log)
            })
            .collect();

    let manifest_dirs = desktop_manifest_dirs_in(home).await;
    for manifest in recent_files_with_exts(&manifest_dirs, now, since_secs, &["json"]).await {
        let log =
            desktop_manifest_session_log(home, &project_dirs, manifest.path, manifest.mtime_epoch)
                .await;
        merge_session_log(&mut discovered, log);
    }

    let mut logs = discovered.into_values().collect::<Vec<_>>();
    logs.sort_by(|a, b| {
        a.updated_at
            .unwrap_or_default()
            .cmp(&b.updated_at.unwrap_or_default())
            .then_with(|| a.source_label().cmp(&b.source_label()))
    });
    logs
}

async fn desktop_manifest_session_log(
    home: &Path,
    project_dirs: &[PathBuf],
    manifest_path: PathBuf,
    manifest_mtime_epoch: i64,
) -> SessionLog {
    let content = tokio::fs::read_to_string(&manifest_path)
        .await
        .unwrap_or_default();
    if let Some(cli_session_id) = parse_cli_session_id(&content)
        && let Some(transcript_path) =
            resolve_cli_transcript_path(project_dirs, &cli_session_id).await
    {
        return SessionLog {
            agent_type: AgentType::Claude,
            source: SessionSource::File(transcript_path),
            updated_at: Some(manifest_mtime_epoch),
        };
    }

    let label = format!(
        "claude-desktop:{}",
        manifest_path
            .strip_prefix(home)
            .unwrap_or(&manifest_path)
            .display()
    );
    SessionLog {
        agent_type: AgentType::Claude,
        source: SessionSource::Inline {
            label,
            content: fallback_manifest_content(&content),
        },
        updated_at: Some(manifest_mtime_epoch),
    }
}

async fn resolve_cli_transcript_path(
    project_dirs: &[PathBuf],
    cli_session_id: &str,
) -> Option<PathBuf> {
    for dir in project_dirs {
        let candidate = dir.join(format!("{cli_session_id}.jsonl"));
        if tokio::fs::try_exists(&candidate).await.unwrap_or(false) {
            return Some(candidate);
        }
    }
    None
}

fn parse_cli_session_id(content: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(content)
        .ok()?
        .get("cliSessionId")?
        .as_str()
        .map(ToOwned::to_owned)
}

fn fallback_manifest_content(content: &str) -> String {
    let mut value = match serde_json::from_str::<serde_json::Value>(content) {
        Ok(value) => value,
        Err(_) => return content.to_string(),
    };

    let cli_session_id = value
        .get("cliSessionId")
        .and_then(|candidate| candidate.as_str())
        .map(ToOwned::to_owned);

    if let Some(cli_session_id) = cli_session_id
        && let Some(object) = value.as_object_mut()
    {
        object.insert(
            "sessionId".to_string(),
            serde_json::Value::String(cli_session_id),
        );
    }

    value.to_string()
}

fn merge_session_log(discovered: &mut HashMap<String, SessionLog>, incoming: SessionLog) {
    let key = incoming.source_label();
    match discovered.get(&key) {
        None => {
            discovered.insert(key, incoming);
        }
        Some(existing) => {
            if incoming.updated_at.unwrap_or_default() > existing.updated_at.unwrap_or_default() {
                discovered.insert(key, incoming);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::set_file_mtime;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // all_log_dirs_in
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_all_log_dirs_returns_all_directories() {
        let home = TempDir::new().unwrap();
        let projects_dir = home.path().join(".claude").join("projects");
        tokio::fs::create_dir_all(&projects_dir).await.unwrap();

        // Create multiple project directories
        tokio::fs::create_dir(projects_dir.join("-Users-foo-bar"))
            .await
            .unwrap();
        tokio::fs::create_dir(projects_dir.join("-Users-baz-qux"))
            .await
            .unwrap();
        tokio::fs::create_dir(projects_dir.join("-home-user-project"))
            .await
            .unwrap();

        let result = all_log_dirs_in(home.path()).await;
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_all_log_dirs_returns_empty_when_no_projects_dir() {
        let home = TempDir::new().unwrap();
        let result = all_log_dirs_in(home.path()).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_all_log_dirs_ignores_files() {
        let home = TempDir::new().unwrap();
        let projects_dir = home.path().join(".claude").join("projects");
        tokio::fs::create_dir_all(&projects_dir).await.unwrap();

        // Create a file (not a directory)
        tokio::fs::write(projects_dir.join("some-file"), "not a dir")
            .await
            .unwrap();
        // Create a directory
        tokio::fs::create_dir(projects_dir.join("-Users-foo-bar"))
            .await
            .unwrap();

        let result = all_log_dirs_in(home.path()).await;
        assert_eq!(result.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Phase 12 hardening: missing ~/.claude/ directory
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_all_log_dirs_graceful_when_claude_dir_missing() {
        // Same for all_log_dirs: missing ~/.claude/ should not error.
        let home = TempDir::new().unwrap();
        let result = all_log_dirs_in(home.path()).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_discover_recent_uses_desktop_manifest_recency_for_cli_transcript() {
        let home = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        let since_secs: i64 = 86_400;

        let project_dir = home
            .path()
            .join(".claude")
            .join("projects")
            .join("-Users-foo-bar");
        tokio::fs::create_dir_all(&project_dir).await.unwrap();

        let transcript = project_dir.join("cli-session.jsonl");
        tokio::fs::write(&transcript, "{}\n").await.unwrap();
        set_file_mtime(&transcript, now - (since_secs + 10));

        let manifest_dir = home
            .path()
            .join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude-code-sessions")
            .join("workspace")
            .join("window");
        tokio::fs::create_dir_all(&manifest_dir).await.unwrap();

        let manifest = manifest_dir.join("local_session.json");
        tokio::fs::write(
            &manifest,
            r#"{"sessionId":"local-session","cliSessionId":"cli-session","cwd":"/Users/foo/bar"}"#,
        )
        .await
        .unwrap();
        set_file_mtime(&manifest, now - 5);

        let logs = discover_recent_in(home.path(), now, since_secs).await;
        assert_eq!(logs.len(), 1);
        match &logs[0].source {
            SessionSource::File(path) => assert_eq!(path, &transcript),
            SessionSource::Inline { .. } => panic!("expected transcript file source"),
        }
        assert_eq!(logs[0].updated_at, Some(now - 5));
    }

    #[tokio::test]
    async fn test_discover_recent_falls_back_to_manifest_when_cli_transcript_missing() {
        let home = TempDir::new().unwrap();
        let now: i64 = 1_700_000_000;
        let since_secs: i64 = 86_400;

        let manifest_dir = home
            .path()
            .join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude-code-sessions")
            .join("workspace")
            .join("window");
        tokio::fs::create_dir_all(&manifest_dir).await.unwrap();

        let manifest = manifest_dir.join("local_session.json");
        tokio::fs::write(
            &manifest,
            r#"{"sessionId":"local-session","cliSessionId":"cli-session","cwd":"/Users/foo/bar"}"#,
        )
        .await
        .unwrap();
        set_file_mtime(&manifest, now - 5);

        let logs = discover_recent_in(home.path(), now, since_secs).await;
        assert_eq!(logs.len(), 1);
        match &logs[0].source {
            SessionSource::Inline { label, content } => {
                assert!(label.starts_with("claude-desktop:"));
                assert!(content.contains("\"sessionId\":\"cli-session\""));
            }
            SessionSource::File(path) => panic!("unexpected file source: {}", path.display()),
        }
        assert_eq!(logs[0].updated_at, Some(now - 5));
    }
}
