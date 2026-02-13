//! Upload audit log for notes push attempts.
//!
//! Stores append-only JSONL events at:
//! `~/.ai-session-commit-linker/uploads.jsonl`

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

const LOG_FILE_NAME: &str = "uploads.jsonl";
const NOTES_REF: &str = "refs/notes/ai-sessions";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadTrigger {
    Hook,
    Hydrate,
    Retry,
}

impl UploadTrigger {
    pub fn as_str(self) -> &'static str {
        match self {
            UploadTrigger::Hook => "hook",
            UploadTrigger::Hydrate => "hydrate",
            UploadTrigger::Retry => "retry",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadEvent {
    pub id: String,
    pub time: i64,
    pub repo: String,
    pub remote: String,
    pub notes_ref: String,
    pub status: String,
    pub error: Option<String>,
    pub trigger: String,
}

#[derive(Debug, Clone)]
pub struct UploadSummary {
    pub uploads_last_7d: usize,
    pub last: Option<UploadEvent>,
}

fn state_dir_in(home: &Path) -> Result<PathBuf> {
    let dir = home.join(".ai-session-commit-linker");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

fn log_path_in(home: &Path) -> Result<PathBuf> {
    Ok(state_dir_in(home)?.join(LOG_FILE_NAME))
}

fn log_path() -> Result<PathBuf> {
    let home =
        crate::agents::home_dir().ok_or_else(|| anyhow::anyhow!("cannot determine home dir"))?;
    log_path_in(&home)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn make_event_id(
    time: i64,
    repo: &str,
    trigger: &str,
    status: &str,
    error: Option<&str>,
) -> String {
    let seed = format!(
        "{}|{}|{}|{}|{}",
        time,
        repo,
        trigger,
        status,
        error.unwrap_or("")
    );
    let hash = Sha256::digest(seed.as_bytes());
    format!("{:x}", hash)[..12].to_string()
}

fn append_event_to(path: &Path, event: &UploadEvent) -> Result<()> {
    let line = serde_json::to_string(event)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{}", line)?;
    Ok(())
}

fn read_events_from(path: &Path) -> Result<Vec<UploadEvent>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut events = Vec::new();

    for line in reader.lines() {
        let line = match line {
            Ok(v) => v,
            Err(_) => continue,
        };
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<UploadEvent>(&line) {
            events.push(event);
        }
    }

    Ok(events)
}

pub fn record_push_attempt(
    repo: &str,
    remote: &str,
    trigger: UploadTrigger,
    success: bool,
    error: Option<&str>,
) -> Result<()> {
    let time = now_unix();
    let status = if success { "success" } else { "failed" };
    let event = UploadEvent {
        id: make_event_id(time, repo, trigger.as_str(), status, error),
        time,
        repo: repo.to_string(),
        remote: remote.to_string(),
        notes_ref: NOTES_REF.to_string(),
        status: status.to_string(),
        error: error.map(ToString::to_string),
        trigger: trigger.as_str().to_string(),
    };

    let path = log_path()?;
    append_event_to(&path, &event)
}

pub fn list_events(since_secs: Option<i64>) -> Result<Vec<UploadEvent>> {
    let path = log_path()?;
    let mut events = read_events_from(&path)?;
    if let Some(window) = since_secs {
        let cutoff = now_unix() - window;
        events.retain(|e| e.time >= cutoff);
    }
    events.sort_by(|a, b| b.time.cmp(&a.time));
    Ok(events)
}

pub fn get_event(id: &str) -> Result<Option<UploadEvent>> {
    let path = log_path()?;
    let events = read_events_from(&path)?;
    Ok(events.into_iter().find(|e| e.id == id))
}

pub fn summary_last_7d() -> Result<UploadSummary> {
    let events = list_events(Some(7 * 86_400))?;
    let last = events.first().cloned();
    Ok(UploadSummary {
        uploads_last_7d: events.len(),
        last,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_append_and_read_events() {
        let home = TempDir::new().unwrap();
        let path = log_path_in(home.path()).unwrap();
        let event = UploadEvent {
            id: "abc123".to_string(),
            time: 1_700_000_000,
            repo: "/tmp/repo".to_string(),
            remote: "git@github.com:org/repo.git".to_string(),
            notes_ref: NOTES_REF.to_string(),
            status: "success".to_string(),
            error: None,
            trigger: "hook".to_string(),
        };

        append_event_to(&path, &event).unwrap();
        let events = read_events_from(&path).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "abc123");
    }

    #[test]
    fn test_read_events_skips_invalid_lines() {
        let home = TempDir::new().unwrap();
        let path = log_path_in(home.path()).unwrap();
        std::fs::write(
            &path,
            "{\"id\":\"ok\",\"time\":1,\"repo\":\"/r\",\"remote\":\"origin\",\"notes_ref\":\"refs/notes/ai-sessions\",\"status\":\"success\",\"error\":null,\"trigger\":\"hook\"}\nnot-json\n",
        )
        .unwrap();

        let events = read_events_from(&path).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "ok");
    }
}
