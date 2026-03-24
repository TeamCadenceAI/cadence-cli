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
use rusqlite::{Connection, OpenFlags, params};
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

    data_roots_for_home(&home)
}

fn data_roots_for_home(home: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    // OpenCode's CLI resolves data storage through xdg-basedir, so the primary
    // session root is `$XDG_DATA_HOME/opencode` or `~/.local/share/opencode`
    // across platforms. Keep older native app roots as fallbacks.
    if let Ok(xdg_data_home) = std::env::var("XDG_DATA_HOME") {
        roots.push(PathBuf::from(xdg_data_home).join("opencode"));
    } else {
        roots.push(home.join(".local").join("share").join("opencode"));
    }

    if cfg!(target_os = "macos") {
        roots.push(
            home.join("Library")
                .join("Application Support")
                .join("opencode"),
        );
    } else if cfg!(target_os = "windows") {
        if let Ok(appdata) = std::env::var("APPDATA") {
            roots.push(PathBuf::from(appdata).join("opencode"));
        } else {
            roots.push(home.join("AppData").join("Roaming").join("opencode"));
        }
    }

    roots.sort();
    roots.dedup();
    roots
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

        if let Ok(Some(db_records)) = tokio::task::spawn_blocking({
            let root = root.clone();
            move || query_recent_db_records(&root, cutoff)
        })
        .await
        {
            merge_session_records(&mut sessions, db_records.sessions);
            merge_message_records(
                &mut message_to_session,
                &mut messages_by_session,
                db_records.messages,
            );
            merge_part_records(&mut parts_by_session, db_records.parts);
        }
    }

    render_session_logs(cutoff, sessions, messages_by_session, parts_by_session)
}

fn render_session_logs(
    cutoff: i64,
    sessions: HashMap<String, SessionRecord>,
    mut messages_by_session: BTreeMap<String, Vec<MessageRecord>>,
    mut parts_by_session: BTreeMap<String, Vec<PartRecord>>,
) -> Vec<SessionLog> {
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

fn merge_session_records(
    sessions: &mut HashMap<String, SessionRecord>,
    incoming: Vec<(String, SessionRecord)>,
) {
    for (session_id, record) in incoming {
        match sessions.get(&session_id) {
            None => {
                sessions.insert(session_id, record);
            }
            Some(existing) => {
                let record_recency = record.updated_at.or(record.file_mtime).unwrap_or_default();
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
}

fn merge_message_records(
    message_to_session: &mut HashMap<String, String>,
    messages_by_session: &mut BTreeMap<String, Vec<MessageRecord>>,
    incoming: Vec<MessageRecord>,
) {
    for record in incoming {
        message_to_session.insert(record.id.clone(), record.session_id.clone());
        messages_by_session
            .entry(record.session_id.clone())
            .or_default()
            .push(record);
    }
}

fn merge_part_records(
    parts_by_session: &mut BTreeMap<String, Vec<PartRecord>>,
    incoming: Vec<PartRecord>,
) {
    for record in incoming {
        if let Some(session_id) = record.session_id.clone() {
            parts_by_session.entry(session_id).or_default().push(record);
        }
    }
}

#[derive(Debug, Default)]
struct DbRecords {
    sessions: Vec<(String, SessionRecord)>,
    messages: Vec<MessageRecord>,
    parts: Vec<PartRecord>,
}

fn query_recent_db_records(root: &Path, cutoff: i64) -> Option<DbRecords> {
    let db_path = root.join("opencode.db");
    if !db_path.exists() {
        return None;
    }

    let conn = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    let recent_session_ids = recent_db_session_ids(&conn, cutoff);
    if recent_session_ids.is_empty() {
        return Some(DbRecords::default());
    }

    Some(DbRecords {
        sessions: fetch_db_sessions(&conn, &db_path, &recent_session_ids),
        messages: fetch_db_messages(&conn, &db_path, &recent_session_ids),
        parts: fetch_db_parts(&conn, &db_path, &recent_session_ids),
    })
}

fn recent_db_session_ids(conn: &Connection, cutoff: i64) -> HashSet<String> {
    let mut ids = HashSet::new();

    for query in [
        "SELECT id FROM session WHERE COALESCE(time_updated, time_created) >= ?1",
        "SELECT DISTINCT session_id FROM message WHERE COALESCE(time_updated, time_created) >= ?1",
        "SELECT DISTINCT session_id FROM part WHERE COALESCE(time_updated, time_created) >= ?1",
    ] {
        let Ok(mut stmt) = conn.prepare(query) else {
            continue;
        };
        let Ok(rows) = stmt.query_map(params![cutoff * 1000], |row| row.get::<_, String>(0)) else {
            continue;
        };
        for id in rows.flatten() {
            ids.insert(id);
        }
    }

    ids
}

fn fetch_db_sessions(
    conn: &Connection,
    db_path: &Path,
    session_ids: &HashSet<String>,
) -> Vec<(String, SessionRecord)> {
    if let Ok(mut stmt) =
        conn.prepare("SELECT id, directory, title, time_created, time_updated, data FROM session")
    {
        let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1).ok(),
                row.get::<_, String>(2).ok(),
                row.get::<_, i64>(3).ok(),
                row.get::<_, i64>(4).ok(),
                row.get::<_, String>(5).ok(),
            ))
        }) else {
            return Vec::new();
        };

        return rows
            .flatten()
            .filter(|(session_id, ..)| session_ids.contains(session_id))
            .map(
                |(session_id, directory, title, time_created, time_updated, raw_json)| {
                    build_db_session_record(
                        db_path,
                        session_id,
                        directory,
                        title,
                        time_created,
                        time_updated,
                        raw_json,
                    )
                },
            )
            .collect();
    }

    let Ok(mut stmt) =
        conn.prepare("SELECT id, directory, title, time_created, time_updated FROM session")
    else {
        return Vec::new();
    };

    let Ok(rows) = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1).ok(),
            row.get::<_, String>(2).ok(),
            row.get::<_, i64>(3).ok(),
            row.get::<_, i64>(4).ok(),
        ))
    }) else {
        return Vec::new();
    };

    rows.flatten()
        .filter(|(session_id, ..)| session_ids.contains(session_id))
        .map(
            |(session_id, directory, title, time_created, time_updated)| {
                build_db_session_record(
                    db_path,
                    session_id,
                    directory,
                    title,
                    time_created,
                    time_updated,
                    None,
                )
            },
        )
        .collect()
}

fn build_db_session_record(
    db_path: &Path,
    session_id: String,
    directory: Option<String>,
    title: Option<String>,
    time_created: Option<i64>,
    time_updated: Option<i64>,
    raw_json: Option<String>,
) -> (String, SessionRecord) {
    let raw = raw_json
        .as_deref()
        .and_then(parse_json)
        .unwrap_or_else(|| json!({}));
    let raw = merge_json_object(
        raw,
        json!({
            "id": session_id,
            "directory": directory,
            "title": title,
            "time": {
                "created": normalize_db_epoch(time_created),
                "updated": normalize_db_epoch(time_updated),
            }
        }),
    );
    let record = SessionRecord {
        directory,
        title,
        source_file: format!("{}#session/{}", db_path.display(), session_id),
        created_at: normalize_db_epoch(time_created),
        updated_at: normalize_db_epoch(time_updated),
        file_mtime: None,
        raw,
    };
    (session_id, record)
}

fn fetch_db_messages(
    conn: &Connection,
    db_path: &Path,
    session_ids: &HashSet<String>,
) -> Vec<MessageRecord> {
    let Ok(mut stmt) =
        conn.prepare("SELECT id, session_id, time_created, time_updated, data FROM message")
    else {
        return Vec::new();
    };

    let Ok(rows) = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2).ok(),
            row.get::<_, i64>(3).ok(),
            row.get::<_, String>(4).ok(),
        ))
    }) else {
        return Vec::new();
    };

    rows.flatten()
        .filter(|(_, session_id, ..)| session_ids.contains(session_id))
        .map(|(id, session_id, time_created, time_updated, raw_json)| {
            let raw = raw_json
                .as_deref()
                .and_then(parse_json)
                .unwrap_or_else(|| json!({}));
            let raw = merge_json_object(
                raw,
                json!({
                    "id": id,
                    "sessionID": session_id,
                    "time": {
                        "created": normalize_db_epoch(time_created),
                        "updated": normalize_db_epoch(time_updated),
                    }
                }),
            );

            MessageRecord {
                id: id.clone(),
                session_id: session_id.clone(),
                role: raw.get("role").and_then(Value::as_str).map(str::to_string),
                source_file: format!("{}#message/{}", db_path.display(), id),
                created_at: raw
                    .pointer("/time/created")
                    .and_then(parse_epoch_from_json_value)
                    .or_else(|| normalize_db_epoch(time_created))
                    .or_else(|| normalize_db_epoch(time_updated)),
                file_mtime: None,
                raw,
            }
        })
        .collect()
}

fn fetch_db_parts(
    conn: &Connection,
    db_path: &Path,
    session_ids: &HashSet<String>,
) -> Vec<PartRecord> {
    let Ok(mut stmt) = conn
        .prepare("SELECT id, message_id, session_id, time_created, time_updated, data FROM part")
    else {
        return Vec::new();
    };

    let Ok(rows) = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3).ok(),
            row.get::<_, i64>(4).ok(),
            row.get::<_, String>(5).ok(),
        ))
    }) else {
        return Vec::new();
    };

    rows.flatten()
        .filter(|(_, _, session_id, ..)| session_ids.contains(session_id))
        .map(
            |(id, message_id, session_id, time_created, time_updated, raw_json)| {
                let raw = raw_json
                    .as_deref()
                    .and_then(parse_json)
                    .unwrap_or_else(|| json!({}));
                let raw = merge_json_object(
                    raw,
                    json!({
                        "id": id,
                        "messageID": message_id,
                        "sessionID": session_id,
                        "time": {
                            "created": normalize_db_epoch(time_created),
                            "updated": normalize_db_epoch(time_updated),
                        }
                    }),
                );

                PartRecord {
                    id: id.clone(),
                    message_id: Some(message_id),
                    session_id: Some(session_id),
                    part_type: raw.get("type").and_then(Value::as_str).map(str::to_string),
                    source_file: format!("{}#part/{}", db_path.display(), id),
                    created_at: raw
                        .pointer("/time/created")
                        .and_then(parse_epoch_from_json_value)
                        .or_else(|| normalize_db_epoch(time_created))
                        .or_else(|| normalize_db_epoch(time_updated)),
                    file_mtime: None,
                    raw,
                }
            },
        )
        .collect()
}

fn parse_json(raw_json: &str) -> Option<Value> {
    serde_json::from_str(raw_json).ok()
}

fn merge_json_object(base: Value, fallback: Value) -> Value {
    match (base, fallback) {
        (Value::Object(mut base), Value::Object(fallback)) => {
            for (key, value) in fallback {
                base.entry(key).or_insert(value);
            }
            Value::Object(base)
        }
        (base, _) => base,
    }
}

fn normalize_db_epoch(value: Option<i64>) -> Option<i64> {
    value.and_then(|epoch| parse_epoch_from_json_value(&Value::from(epoch)))
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
    use rusqlite::Connection;
    use serial_test::serial;

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

    #[tokio::test]
    async fn test_opencode_discovers_recent_sqlite_sessions() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        let db_path = root.join("opencode.db");
        let conn = Connection::open(&db_path).unwrap();

        conn.execute_batch(
            "
            CREATE TABLE session (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                directory TEXT NOT NULL,
                title TEXT NOT NULL,
                version TEXT NOT NULL,
                time_created INTEGER NOT NULL,
                time_updated INTEGER NOT NULL,
                data TEXT NOT NULL
            );
            CREATE TABLE message (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                time_created INTEGER NOT NULL,
                time_updated INTEGER NOT NULL,
                data TEXT NOT NULL
            );
            CREATE TABLE part (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                time_created INTEGER NOT NULL,
                time_updated INTEGER NOT NULL,
                data TEXT NOT NULL
            );
            ",
        )
        .unwrap();

        conn.execute(
            "INSERT INTO session (id, project_id, directory, title, version, time_created, time_updated, data)
             VALUES (?1, 'global', '/repo', 'SQLite session', '1.0.0', ?2, ?3, ?4)",
            rusqlite::params![
                "ses_db",
                1_772_602_456_000_i64,
                1_772_602_557_000_i64,
                r#"{"slug":"sqlite-session"}"#,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message (id, session_id, time_created, time_updated, data)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                "msg_db",
                "ses_db",
                1_772_602_558_000_i64,
                1_772_602_558_000_i64,
                r#"{"role":"user","time":{"created":1772602558000}}"#,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO part (id, message_id, session_id, time_created, time_updated, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                "prt_db",
                "msg_db",
                "ses_db",
                1_772_602_559_000_i64,
                1_772_602_559_000_i64,
                r#"{"type":"text","text":"hello"}"#,
            ],
        )
        .unwrap();

        let logs = discover_recent_in(&[root.to_path_buf()], 1_772_602_700, 9_999_999).await;
        assert_eq!(logs.len(), 1);

        match &logs[0].source {
            SessionSource::Inline { label, content } => {
                assert_eq!(label, "opencode:ses_db");
                assert!(content.contains("\"source\":\"opencode\""));
                assert!(content.contains("\"sessionID\":\"ses_db\""));
                assert!(content.contains("\"messageID\":\"msg_db\""));
                assert!(content.contains("\"partID\":\"prt_db\""));
                assert!(content.contains("\"cwd\":\"/repo\""));
            }
            SessionSource::File(_) => panic!("expected inline session"),
        }
    }

    #[tokio::test]
    async fn test_opencode_discovers_sqlite_sessions_without_session_data_column() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        let db_path = root.join("opencode.db");
        let conn = Connection::open(&db_path).unwrap();

        conn.execute_batch(
            "
            CREATE TABLE session (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                directory TEXT NOT NULL,
                title TEXT NOT NULL,
                time_created INTEGER NOT NULL,
                time_updated INTEGER NOT NULL
            );
            CREATE TABLE message (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                time_created INTEGER NOT NULL,
                time_updated INTEGER NOT NULL,
                data TEXT NOT NULL
            );
            CREATE TABLE part (
                id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                time_created INTEGER NOT NULL,
                time_updated INTEGER NOT NULL,
                data TEXT NOT NULL
            );
            ",
        )
        .unwrap();

        conn.execute(
            "INSERT INTO session (id, project_id, directory, title, time_created, time_updated)
             VALUES (?1, 'workspace', '/Users/zack/dev/cadence-cli', 'DB-only session', ?2, ?3)",
            rusqlite::params![
                "ses_db_nodata",
                1_774_323_440_000_i64,
                1_774_324_993_000_i64
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message (id, session_id, time_created, time_updated, data)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                "msg_db_nodata",
                "ses_db_nodata",
                1_774_324_993_000_i64,
                1_774_324_993_000_i64,
                r#"{"role":"user"}"#,
            ],
        )
        .unwrap();

        let logs = discover_recent_in(&[root.to_path_buf()], 1_774_324_994, 10_000).await;
        assert_eq!(logs.len(), 1);

        match &logs[0].source {
            SessionSource::Inline { label, content } => {
                assert_eq!(label, "opencode:ses_db_nodata");
                assert!(content.contains("\"sessionID\":\"ses_db_nodata\""));
                assert!(content.contains("\"cwd\":\"/Users/zack/dev/cadence-cli\""));
                assert!(content.contains("\"directory\":\"/Users/zack/dev/cadence-cli\""));
            }
            SessionSource::File(_) => panic!("expected inline session"),
        }
    }

    #[test]
    fn test_data_roots_include_xdg_location() {
        let home = Path::new("/Users/tester");
        let roots = data_roots_for_home(home);

        assert!(roots.contains(&home.join(".local").join("share").join("opencode")));
        if cfg!(target_os = "macos") {
            assert!(
                roots.contains(
                    &home
                        .join("Library")
                        .join("Application Support")
                        .join("opencode")
                )
            );
        }
    }

    #[test]
    #[serial]
    fn test_data_roots_honor_xdg_data_home() {
        let previous = std::env::var_os("XDG_DATA_HOME");
        unsafe {
            std::env::set_var("XDG_DATA_HOME", "/tmp/opencode-xdg");
        }

        let roots = data_roots_for_home(Path::new("/Users/tester"));

        match previous {
            Some(value) => unsafe {
                std::env::set_var("XDG_DATA_HOME", value);
            },
            None => unsafe {
                std::env::remove_var("XDG_DATA_HOME");
            },
        }

        assert!(roots.contains(&PathBuf::from("/tmp/opencode-xdg").join("opencode")));
    }
}
