//! OpenCode log discovery and normalization.
//!
//! OpenCode stores session metadata and conversation fragments across:
//! - `storage/session/**.json`
//! - `storage/message/**.json`
//! - `storage/part/**.json`
//!
//! This module normalizes those fragments into one synthetic JSONL session log
//! per OpenCode session ID.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use super::{AgentExplorer, SessionLog, SessionSource, home_dir};
use crate::scanner::AgentType;
use async_trait::async_trait;
use serde_json::{Value, json};

pub struct OpenCodeExplorer;

#[async_trait]
impl AgentExplorer for OpenCodeExplorer {
    async fn discover_recent(&self, now: i64, since_secs: i64) -> Vec<SessionLog> {
        let roots = data_roots();
        discover_recent_in(&roots, now, since_secs).await
    }
}

fn data_roots() -> Vec<PathBuf> {
    if let Ok(override_dir) = std::env::var("OPENCODE_DATA_DIR") {
        return vec![PathBuf::from(override_dir)];
    }

    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };

    if cfg!(target_os = "macos") {
        vec![
            home.join("Library")
                .join("Application Support")
                .join("opencode"),
        ]
    } else if cfg!(target_os = "windows") {
        if let Ok(appdata) = std::env::var("APPDATA") {
            vec![PathBuf::from(appdata).join("opencode")]
        } else {
            vec![home.join("AppData").join("Roaming").join("opencode")]
        }
    } else {
        vec![home.join(".local").join("share").join("opencode")]
    }
}

#[derive(Debug, Clone)]
struct SessionRecord {
    directory: Option<String>,
    title: Option<String>,
    source_file: String,
    created_at: Option<i64>,
    updated_at: Option<i64>,
    file_mtime: Option<i64>,
    raw: Value,
}

#[derive(Debug, Clone)]
struct MessageRecord {
    id: String,
    session_id: String,
    role: Option<String>,
    source_file: String,
    created_at: Option<i64>,
    file_mtime: Option<i64>,
    raw: Value,
}

#[derive(Debug, Clone)]
struct PartRecord {
    id: String,
    message_id: Option<String>,
    session_id: Option<String>,
    part_type: Option<String>,
    source_file: String,
    created_at: Option<i64>,
    file_mtime: Option<i64>,
    raw: Value,
}

async fn discover_recent_in(roots: &[PathBuf], now: i64, since_secs: i64) -> Vec<SessionLog> {
    let cutoff = now - since_secs;

    let mut sessions: HashMap<String, SessionRecord> = HashMap::new();
    let mut messages_by_session: BTreeMap<String, Vec<MessageRecord>> = BTreeMap::new();
    let mut parts_by_session: BTreeMap<String, Vec<PartRecord>> = BTreeMap::new();
    let mut message_to_session: HashMap<String, String> = HashMap::new();

    for root in roots {
        let session_dir = root.join("storage").join("session");
        let message_dir = root.join("storage").join("message");
        let part_dir = root.join("storage").join("part");

        for candidate in collect_recent_json_files(&session_dir, cutoff).await {
            let path = candidate.path;
            let Some(value) = read_json(&path).await else {
                continue;
            };
            let Some(session_id) = value
                .get("id")
                .or_else(|| value.get("sessionID"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            let session_id = session_id.to_string();

            let created_at = value
                .pointer("/time/created")
                .and_then(parse_epoch_from_json_value);
            let updated_at = value
                .pointer("/time/updated")
                .and_then(parse_epoch_from_json_value)
                .or(created_at);

            let record = SessionRecord {
                directory: value
                    .get("directory")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                title: value
                    .get("title")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                source_file: path.to_string_lossy().to_string(),
                created_at,
                updated_at,
                file_mtime: candidate.mtime_epoch,
                raw: value,
            };

            match sessions.get(&session_id) {
                None => {
                    sessions.insert(session_id, record);
                }
                Some(existing) => {
                    let record_recency =
                        record.updated_at.or(record.file_mtime).unwrap_or_default();
                    let existing_recency = existing
                        .updated_at
                        .or(existing.file_mtime)
                        .unwrap_or_default();
                    if record_recency > existing_recency {
                        sessions.insert(session_id, record);
                    }
                }
            }
        }

        for candidate in collect_recent_json_files(&message_dir, cutoff).await {
            let path = candidate.path;
            let Some(value) = read_json(&path).await else {
                continue;
            };
            let Some(session_id) = value.get("sessionID").and_then(Value::as_str) else {
                continue;
            };
            let Some(message_id) = value.get("id").and_then(Value::as_str) else {
                continue;
            };

            let record = MessageRecord {
                id: message_id.to_string(),
                session_id: session_id.to_string(),
                role: value
                    .get("role")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                source_file: path.to_string_lossy().to_string(),
                created_at: value
                    .pointer("/time/created")
                    .and_then(parse_epoch_from_json_value),
                file_mtime: candidate.mtime_epoch,
                raw: value,
            };

            message_to_session.insert(record.id.clone(), record.session_id.clone());
            messages_by_session
                .entry(record.session_id.clone())
                .or_default()
                .push(record);
        }

        for candidate in collect_recent_json_files(&part_dir, cutoff).await {
            let path = candidate.path;
            let Some(value) = read_json(&path).await else {
                continue;
            };
            let part_id = value
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("unknown-part")
                .to_string();

            let message_id = value
                .get("messageID")
                .and_then(Value::as_str)
                .map(str::to_string);
            let session_id = value
                .get("sessionID")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| {
                    message_id
                        .as_ref()
                        .and_then(|id| message_to_session.get(id).cloned())
                });

            let record = PartRecord {
                id: part_id,
                message_id,
                session_id: session_id.clone(),
                part_type: value
                    .get("type")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                source_file: path.to_string_lossy().to_string(),
                created_at: value
                    .pointer("/time/created")
                    .and_then(parse_epoch_from_json_value),
                file_mtime: candidate.mtime_epoch,
                raw: value,
            };

            if let Some(session_id) = session_id {
                parts_by_session.entry(session_id).or_default().push(record);
            }
        }
    }

    let mut session_ids: HashSet<String> = HashSet::new();
    session_ids.extend(sessions.keys().cloned());
    session_ids.extend(messages_by_session.keys().cloned());
    session_ids.extend(parts_by_session.keys().cloned());

    let mut output = Vec::new();
    let mut sorted_ids: Vec<_> = session_ids.into_iter().collect();
    sorted_ids.sort();

    for session_id in sorted_ids {
        let session_record = sessions.get(&session_id);
        let mut messages = messages_by_session.remove(&session_id).unwrap_or_default();
        let mut parts = parts_by_session.remove(&session_id).unwrap_or_default();

        messages.sort_by(|a, b| {
            a.created_at
                .unwrap_or_default()
                .cmp(&b.created_at.unwrap_or_default())
                .then(a.id.cmp(&b.id))
        });
        parts.sort_by(|a, b| {
            a.created_at
                .unwrap_or_default()
                .cmp(&b.created_at.unwrap_or_default())
                .then(a.id.cmp(&b.id))
        });

        let mut lines = Vec::new();
        let mut max_updated = 0i64;

        let session_created = session_record.and_then(|s| s.created_at);
        let session_updated = session_record.and_then(|s| s.updated_at);
        let cwd = session_record.and_then(|s| s.directory.clone());
        let title = session_record.and_then(|s| s.title.clone());
        let source_file = session_record.map(|s| s.source_file.clone());

        if let Some(ts) = session_updated
            .or(session_created)
            .or_else(|| session_record.and_then(|s| s.file_mtime))
        {
            max_updated = max_updated.max(ts);
        }

        let session_meta = json!({
            "type": "session_meta",
            "source": "opencode",
            "sessionID": session_id,
            "session_id": session_id,
            "directory": cwd,
            "cwd": session_record.and_then(|s| s.directory.clone()),
            "title": title,
            "source_file": source_file,
            "time": {
                "created": session_created,
                "updated": session_updated,
            },
            "payload": session_record.map(|s| s.raw.clone()),
        });
        lines.push(session_meta.to_string());

        for message in messages {
            if let Some(ts) = message.created_at.or(message.file_mtime) {
                max_updated = max_updated.max(ts);
            }
            let event = json!({
                "type": "message",
                "source": "opencode",
                "sessionID": message.session_id,
                "messageID": message.id,
                "role": message.role,
                "time": {
                    "created": message.created_at,
                },
                "source_file": message.source_file,
                "payload": message.raw,
            });
            lines.push(event.to_string());
        }

        for part in parts {
            if let Some(ts) = part.created_at.or(part.file_mtime) {
                max_updated = max_updated.max(ts);
            }
            let event = json!({
                "type": "part",
                "source": "opencode",
                "sessionID": part.session_id,
                "messageID": part.message_id,
                "partID": part.id,
                "partType": part.part_type,
                "time": {
                    "created": part.created_at,
                },
                "source_file": part.source_file,
                "payload": part.raw,
            });
            lines.push(event.to_string());
        }

        if max_updated == 0 {
            continue;
        }
        if max_updated < cutoff {
            continue;
        }

        output.push(SessionLog {
            agent_type: AgentType::OpenCode,
            source: SessionSource::Inline {
                label: format!("opencode:{session_id}"),
                content: lines.join("\n"),
            },
            updated_at: Some(max_updated),
        });
    }

    output
}

#[derive(Debug)]
struct JsonCandidate {
    path: PathBuf,
    mtime_epoch: Option<i64>,
}

async fn collect_recent_json_files(root: &Path, cutoff: i64) -> Vec<JsonCandidate> {
    let mut out = Vec::new();
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
                stack.push(path);
            } else if file_type.is_file()
                && path.extension().and_then(|e| e.to_str()) == Some("json")
            {
                let mtime_epoch = file_mtime_epoch(&path).await;
                if mtime_epoch.is_some_and(|mtime| mtime < cutoff) {
                    continue;
                }
                out.push(JsonCandidate { path, mtime_epoch });
            }
        }
    }

    out
}

async fn read_json(path: &Path) -> Option<Value> {
    let content = tokio::fs::read_to_string(path).await.ok()?;
    serde_json::from_str::<Value>(&content).ok()
}

async fn file_mtime_epoch(path: &Path) -> Option<i64> {
    let metadata = tokio::fs::metadata(path).await.ok()?;
    let modified = metadata.modified().ok()?;
    let duration = modified.duration_since(UNIX_EPOCH).ok()?;
    Some(duration.as_secs() as i64)
}

fn parse_epoch_from_json_value(value: &Value) -> Option<i64> {
    if let Some(v) = value.as_i64() {
        if v > 1_000_000_000_000 {
            return Some(v / 1000);
        }
        if v > 0 {
            return Some(v);
        }
    }

    if let Some(v) = value.as_u64() {
        if v > 1_000_000_000_000 {
            return Some((v / 1000) as i64);
        }
        if v > 0 {
            return Some(v as i64);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::set_file_mtime;

    async fn write_json(path: &Path, value: &str) {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.unwrap();
        }
        tokio::fs::write(path, value).await.unwrap();
    }

    #[tokio::test]
    async fn test_opencode_normalizes_session_messages_and_parts() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();

        write_json(
            &root
                .join("storage")
                .join("session")
                .join("global")
                .join("ses_1.json"),
            r#"{"id":"ses_1","directory":"/repo","time":{"created":1772602456612,"updated":1772602457665}}"#,
        )
        .await;

        write_json(
            &root
                .join("storage")
                .join("message")
                .join("ses_1")
                .join("msg_1.json"),
            r#"{"id":"msg_1","sessionID":"ses_1","role":"user","time":{"created":1772602458000}}"#,
        )
        .await;

        write_json(
            &root
                .join("storage")
                .join("part")
                .join("msg_1")
                .join("prt_1.json"),
            r#"{"id":"prt_1","sessionID":"ses_1","messageID":"msg_1","type":"text","time":{"created":1772602459000}}"#,
        )
        .await;

        let logs = discover_recent_in(&[root.to_path_buf()], 1_772_602_700, 9_999_999).await;
        assert_eq!(logs.len(), 1);

        match &logs[0].source {
            SessionSource::Inline { label, content } => {
                assert_eq!(label, "opencode:ses_1");
                assert!(content.contains("\"type\":\"session_meta\""));
                assert!(content.contains("\"type\":\"message\""));
                assert!(content.contains("\"type\":\"part\""));
                assert!(content.contains("\"sessionID\":\"ses_1\""));
            }
            SessionSource::File(_) => panic!("expected inline session"),
        }
    }

    #[tokio::test]
    async fn test_opencode_filters_by_cutoff_using_latest_fragment_time() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();

        write_json(
            &root
                .join("storage")
                .join("session")
                .join("global")
                .join("ses_old.json"),
            r#"{"id":"ses_old","time":{"updated":1000}}"#,
        )
        .await;

        let logs = discover_recent_in(&[root.to_path_buf()], 10_000, 100).await;
        assert!(logs.is_empty());
    }

    #[tokio::test]
    async fn test_opencode_partial_data_still_emits_session() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();

        write_json(
            &root
                .join("storage")
                .join("message")
                .join("ses_partial")
                .join("msg_1.json"),
            r#"{"id":"msg_1","sessionID":"ses_partial","role":"user","time":{"created":1772602458000}}"#,
        )
        .await;

        let logs = discover_recent_in(&[root.to_path_buf()], 1_772_602_700, 9_999_999).await;
        assert_eq!(logs.len(), 1);
        match &logs[0].source {
            SessionSource::Inline { label, content } => {
                assert_eq!(label, "opencode:ses_partial");
                assert!(content.contains("\"type\":\"session_meta\""));
                assert!(content.contains("\"type\":\"message\""));
            }
            SessionSource::File(_) => panic!("expected inline session"),
        }
    }

    #[tokio::test]
    async fn test_opencode_untimestamped_session_uses_file_mtime_for_cutoff() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();

        let session_file = root
            .join("storage")
            .join("session")
            .join("global")
            .join("ses_untimed.json");
        write_json(&session_file, r#"{"id":"ses_untimed","directory":"/repo"}"#).await;
        set_file_mtime(&session_file, 100);

        let logs = discover_recent_in(&[root.to_path_buf()], 10_000, 100).await;
        assert!(logs.is_empty());

        set_file_mtime(&session_file, 9_950);
        let logs = discover_recent_in(&[root.to_path_buf()], 10_000, 100).await;
        assert_eq!(logs.len(), 1);
    }

    #[tokio::test]
    async fn test_opencode_prefers_newer_mtime_when_updated_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();

        let older = root
            .join("storage")
            .join("session")
            .join("global")
            .join("ses_dupe_old.json");
        write_json(&older, r#"{"id":"ses_dupe","directory":"/old"}"#).await;
        set_file_mtime(&older, 1_000);

        let newer = root
            .join("storage")
            .join("session")
            .join("workspace")
            .join("ses_dupe_new.json");
        write_json(&newer, r#"{"id":"ses_dupe","directory":"/new"}"#).await;
        set_file_mtime(&newer, 2_000);

        let logs = discover_recent_in(&[root.to_path_buf()], 3_000, 5_000).await;
        assert_eq!(logs.len(), 1);

        match &logs[0].source {
            SessionSource::Inline { content, .. } => assert!(content.contains("\"cwd\":\"/new\"")),
            SessionSource::File(_) => panic!("expected inline session"),
        }
    }
}
