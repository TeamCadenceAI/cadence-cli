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
use rusqlite::{Connection, OpenFlags, params, params_from_iter};
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
    parent_session_id: Option<String>,
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
                parent_session_id: value
                    .get("parentID")
                    .or_else(|| value.get("parentSessionID"))
                    .or_else(|| value.get("parent_id"))
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
    let clusters = build_session_clusters(&sessions, &messages_by_session, &parts_by_session);
    let mut output = Vec::new();
    for cluster in clusters {
        let session_record = sessions.get(&cluster.root_session_id);
        let mut lines = Vec::new();
        let mut max_updated = 0i64;

        let session_created = session_record.and_then(|s| s.created_at);
        let session_updated = session_record.and_then(|s| s.updated_at);
        let cwd = cluster.cwd.clone();
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
            "sessionID": cluster.root_session_id,
            "session_id": cluster.root_session_id,
            "rootSessionID": cluster.root_session_id,
            "sessionRole": "root",
            "directory": cwd,
            "cwd": cwd,
            "title": title,
            "source_file": source_file,
            "clusterSessionCount": cluster.session_ids.len(),
            "childSessionIDs": cluster.child_session_ids,
            "stitchedFromSessionIDs": cluster.session_ids,
            "time": {
                "created": session_created,
                "updated": session_updated,
            },
            "payload": session_record.map(|s| s.raw.clone()),
        });
        lines.push(session_meta.to_string());

        let mut ordered_records = Vec::new();

        for session_id in &cluster.session_ids {
            if let Some(record) = sessions.get(session_id)
                && let Some(ts) = record
                    .updated_at
                    .or(record.created_at)
                    .or(record.file_mtime)
            {
                max_updated = max_updated.max(ts);
            }

            if session_id == &cluster.root_session_id {
                continue;
            }

            if let Some(record) = sessions.get(session_id) {
                ordered_records.push(RenderedClusterRecord {
                    timestamp: record
                        .created_at
                        .or(record.updated_at)
                        .or(record.file_mtime),
                    kind_rank: 0,
                    session_id: session_id.clone(),
                    record_id: session_id.clone(),
                    line: json!({
                        "type": "session_member",
                        "source": "opencode",
                        "rootSessionID": cluster.root_session_id,
                        "originSessionID": session_id,
                        "sessionRole": "child",
                        "parentSessionID": session_parent_link(record),
                        "time": {
                            "created": record.created_at,
                            "updated": record.updated_at,
                        },
                        "source_file": record.source_file,
                        "payload": record.raw,
                    })
                    .to_string(),
                });
            }
        }

        for session_id in &cluster.session_ids {
            let mut messages = messages_by_session.remove(session_id).unwrap_or_default();
            messages.sort_by(|a, b| {
                a.created_at
                    .unwrap_or_default()
                    .cmp(&b.created_at.unwrap_or_default())
                    .then(a.id.cmp(&b.id))
            });

            let parent_session_id = sessions.get(session_id).and_then(session_parent_link);
            let session_role = if session_id == &cluster.root_session_id {
                "root"
            } else {
                "child"
            };

            for message in messages {
                if let Some(ts) = message.created_at.or(message.file_mtime) {
                    max_updated = max_updated.max(ts);
                }
                ordered_records.push(RenderedClusterRecord {
                    timestamp: message.created_at.or(message.file_mtime),
                    kind_rank: 1,
                    session_id: message.session_id.clone(),
                    record_id: message.id.clone(),
                    line: json!({
                        "type": "message",
                        "source": "opencode",
                        "rootSessionID": cluster.root_session_id,
                        "originSessionID": message.session_id,
                        "sessionRole": session_role,
                        "parentSessionID": parent_session_id,
                        "sessionID": message.session_id,
                        "messageID": message.id,
                        "role": message.role,
                        "time": {
                            "created": message.created_at,
                        },
                        "source_file": message.source_file,
                        "payload": message.raw,
                    })
                    .to_string(),
                });
            }
        }

        for session_id in &cluster.session_ids {
            let mut parts = parts_by_session.remove(session_id).unwrap_or_default();
            parts.sort_by(|a, b| {
                a.created_at
                    .unwrap_or_default()
                    .cmp(&b.created_at.unwrap_or_default())
                    .then(a.id.cmp(&b.id))
            });

            let parent_session_id = sessions.get(session_id).and_then(session_parent_link);
            let session_role = if session_id == &cluster.root_session_id {
                "root"
            } else {
                "child"
            };

            for part in parts {
                if let Some(ts) = part.created_at.or(part.file_mtime) {
                    max_updated = max_updated.max(ts);
                }
                ordered_records.push(RenderedClusterRecord {
                    timestamp: part.created_at.or(part.file_mtime),
                    kind_rank: 2,
                    session_id: part.session_id.clone().unwrap_or_default(),
                    record_id: part.id.clone(),
                    line: json!({
                        "type": "part",
                        "source": "opencode",
                        "rootSessionID": cluster.root_session_id,
                        "originSessionID": part.session_id,
                        "sessionRole": session_role,
                        "parentSessionID": parent_session_id,
                        "sessionID": part.session_id,
                        "messageID": part.message_id,
                        "partID": part.id,
                        "partType": part.part_type,
                        "time": {
                            "created": part.created_at,
                        },
                        "source_file": part.source_file,
                        "payload": part.raw,
                    })
                    .to_string(),
                });
            }
        }

        ordered_records.sort_by(|a, b| {
            a.timestamp
                .unwrap_or_default()
                .cmp(&b.timestamp.unwrap_or_default())
                .then(a.kind_rank.cmp(&b.kind_rank))
                .then(a.session_id.cmp(&b.session_id))
                .then(a.record_id.cmp(&b.record_id))
        });

        for record in ordered_records {
            lines.push(record.line);
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
                label: format!("opencode:{}", cluster.root_session_id),
                content: lines.join("\n"),
            },
            updated_at: Some(max_updated),
        });
    }

    output
}

#[derive(Debug, Clone)]
struct OpenCodeSessionCluster {
    root_session_id: String,
    session_ids: Vec<String>,
    child_session_ids: Vec<String>,
    cwd: Option<String>,
}

#[derive(Debug, Clone)]
struct RenderedClusterRecord {
    timestamp: Option<i64>,
    kind_rank: u8,
    session_id: String,
    record_id: String,
    line: String,
}

fn build_session_clusters(
    sessions: &HashMap<String, SessionRecord>,
    messages_by_session: &BTreeMap<String, Vec<MessageRecord>>,
    parts_by_session: &BTreeMap<String, Vec<PartRecord>>,
) -> Vec<OpenCodeSessionCluster> {
    let mut session_ids: HashSet<String> = HashSet::new();
    session_ids.extend(sessions.keys().cloned());
    session_ids.extend(messages_by_session.keys().cloned());
    session_ids.extend(parts_by_session.keys().cloned());

    let mut root_to_sessions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut resolved_roots: HashMap<String, String> = HashMap::new();

    for session_id in session_ids {
        let root_session_id = resolve_root_session_id(&session_id, sessions, &mut resolved_roots);
        root_to_sessions
            .entry(root_session_id)
            .or_default()
            .push(session_id);
    }

    let mut clusters = Vec::new();
    for (root_session_id, mut cluster_session_ids) in root_to_sessions {
        cluster_session_ids.sort_by_key(|session_id| session_sort_tuple(session_id, sessions));
        if let Some(root_idx) = cluster_session_ids
            .iter()
            .position(|id| id == &root_session_id)
        {
            cluster_session_ids.swap(0, root_idx);
        }

        let cwd = sessions
            .get(&root_session_id)
            .and_then(|record| record.directory.clone())
            .or_else(|| {
                cluster_session_ids.iter().find_map(|session_id| {
                    sessions
                        .get(session_id)
                        .and_then(|record| record.directory.clone())
                })
            });

        let child_session_ids = cluster_session_ids
            .iter()
            .filter(|session_id| *session_id != &root_session_id)
            .cloned()
            .collect();

        clusters.push(OpenCodeSessionCluster {
            root_session_id,
            session_ids: cluster_session_ids,
            child_session_ids,
            cwd,
        });
    }

    clusters.sort_by(|a, b| {
        cluster_sort_tuple(a, sessions)
            .cmp(&cluster_sort_tuple(b, sessions))
            .then(a.root_session_id.cmp(&b.root_session_id))
    });
    clusters
}

fn resolve_root_session_id(
    session_id: &str,
    sessions: &HashMap<String, SessionRecord>,
    resolved_roots: &mut HashMap<String, String>,
) -> String {
    if let Some(root) = resolved_roots.get(session_id) {
        return root.clone();
    }

    let mut lineage = Vec::new();
    let mut seen = HashSet::new();
    let mut current = session_id.to_string();

    loop {
        if let Some(root) = resolved_roots.get(&current) {
            let root = root.clone();
            for id in lineage {
                resolved_roots.insert(id, root.clone());
            }
            return root;
        }

        if !seen.insert(current.clone()) {
            let mut cycle: Vec<_> = seen.into_iter().collect();
            cycle.sort_by(|a, b| {
                session_sort_tuple(a, sessions).cmp(&session_sort_tuple(b, sessions))
            });
            let root = cycle
                .into_iter()
                .next()
                .unwrap_or_else(|| session_id.to_string());
            for id in lineage {
                resolved_roots.insert(id, root.clone());
            }
            return root;
        }

        lineage.push(current.clone());
        let Some(parent_session_id) = sessions
            .get(&current)
            .and_then(session_parent_link)
            .filter(|parent| parent != &current)
        else {
            for id in lineage {
                resolved_roots.insert(id, current.clone());
            }
            return current;
        };

        if !sessions.contains_key(&parent_session_id) {
            for id in lineage {
                resolved_roots.insert(id, current.clone());
            }
            return current;
        }

        current = parent_session_id;
    }
}

fn session_parent_link(record: &SessionRecord) -> Option<String> {
    record.parent_session_id.clone().or_else(|| {
        record
            .raw
            .get("parentID")
            .or_else(|| record.raw.get("parentSessionID"))
            .or_else(|| record.raw.get("parent_id"))
            .and_then(Value::as_str)
            .map(str::to_string)
    })
}

fn session_sort_tuple(
    session_id: &str,
    sessions: &HashMap<String, SessionRecord>,
) -> (i64, i64, String) {
    let created = sessions
        .get(session_id)
        .and_then(|record| record.created_at)
        .unwrap_or_default();
    let updated = sessions
        .get(session_id)
        .and_then(|record| record.updated_at.or(record.file_mtime))
        .unwrap_or_default();
    (created, updated, session_id.to_string())
}

fn cluster_sort_tuple(
    cluster: &OpenCodeSessionCluster,
    sessions: &HashMap<String, SessionRecord>,
) -> (i64, i64) {
    let created = sessions
        .get(&cluster.root_session_id)
        .and_then(|record| record.created_at)
        .unwrap_or_default();
    let updated = cluster
        .session_ids
        .iter()
        .filter_map(|session_id| {
            sessions.get(session_id).and_then(|record| {
                record
                    .updated_at
                    .or(record.created_at)
                    .or(record.file_mtime)
            })
        })
        .max()
        .unwrap_or_default();
    (created, updated)
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

                let (mut merged, fallback) = if record_recency > existing_recency {
                    (record, existing)
                } else {
                    (existing.clone(), &record)
                };

                if merged.parent_session_id.is_none() {
                    merged.parent_session_id = fallback.parent_session_id.clone();
                }
                if merged.directory.is_none() {
                    merged.directory = fallback.directory.clone();
                }
                if merged.title.is_none() {
                    merged.title = fallback.title.clone();
                }

                sessions.insert(session_id, merged);
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
        let messages = messages_by_session
            .entry(record.session_id.clone())
            .or_default();

        if let Some(existing) = messages
            .iter_mut()
            .find(|existing| existing.id == record.id)
        {
            if message_record_recency(&record) > message_record_recency(existing) {
                *existing = record;
            }
            continue;
        }

        messages.push(record);
    }
}

fn merge_part_records(
    parts_by_session: &mut BTreeMap<String, Vec<PartRecord>>,
    incoming: Vec<PartRecord>,
) {
    for record in incoming {
        if let Some(session_id) = record.session_id.clone() {
            let parts = parts_by_session.entry(session_id).or_default();

            if let Some(existing) = parts.iter_mut().find(|existing| existing.id == record.id) {
                if part_record_recency(&record) > part_record_recency(existing) {
                    *existing = record;
                }
                continue;
            }

            parts.push(record);
        }
    }
}

fn message_record_recency(record: &MessageRecord) -> i64 {
    record.created_at.or(record.file_mtime).unwrap_or_default()
}

fn part_record_recency(record: &PartRecord) -> i64 {
    record.created_at.or(record.file_mtime).unwrap_or_default()
}

#[derive(Debug, Default)]
struct DbRecords {
    sessions: Vec<(String, SessionRecord)>,
    messages: Vec<MessageRecord>,
    parts: Vec<PartRecord>,
}

struct DbSessionRowData {
    session_id: String,
    parent_session_id: Option<String>,
    directory: Option<String>,
    title: Option<String>,
    time_created: Option<i64>,
    time_updated: Option<i64>,
    raw_json: Option<String>,
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
    let cluster_session_ids = db_session_ids_with_ancestors(&conn, &recent_session_ids);

    Some(DbRecords {
        sessions: fetch_db_sessions(&conn, &db_path, &cluster_session_ids),
        messages: fetch_db_messages(&conn, &db_path, &cluster_session_ids),
        parts: fetch_db_parts(&conn, &db_path, &cluster_session_ids),
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

fn db_session_ids_with_ancestors(
    conn: &Connection,
    session_ids: &HashSet<String>,
) -> HashSet<String> {
    let mut all_ids = session_ids.clone();
    let mut frontier = session_ids.clone();

    while !frontier.is_empty() {
        let placeholders = sql_in_placeholders(frontier.len());
        let Ok(mut stmt) = conn.prepare(&format!(
            "SELECT id, parent_id FROM session WHERE id IN ({placeholders})"
        )) else {
            break;
        };

        let Ok(rows) = stmt.query_map(params_from_iter(frontier.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1).ok().flatten(),
            ))
        }) else {
            break;
        };

        let mut next_frontier = HashSet::new();
        for (_, parent_id) in rows.flatten() {
            if let Some(parent_id) = parent_id
                && all_ids.insert(parent_id.clone())
            {
                next_frontier.insert(parent_id);
            }
        }
        frontier = next_frontier;
    }

    all_ids
}

fn fetch_db_sessions(
    conn: &Connection,
    db_path: &Path,
    session_ids: &HashSet<String>,
) -> Vec<(String, SessionRecord)> {
    if session_ids.is_empty() {
        return Vec::new();
    }

    let placeholders = sql_in_placeholders(session_ids.len());

    if let Ok(mut stmt) = conn.prepare(&format!(
        "SELECT id, parent_id, directory, title, time_created, time_updated, data FROM session WHERE id IN ({placeholders})"
    )) {
        let Ok(rows) = stmt.query_map(params_from_iter(session_ids.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1).ok().flatten(),
                row.get::<_, String>(2).ok(),
                row.get::<_, String>(3).ok(),
                row.get::<_, i64>(4).ok(),
                row.get::<_, i64>(5).ok(),
                row.get::<_, String>(6).ok(),
            ))
        }) else {
            return Vec::new();
        };

        return rows
            .flatten()
            .map(
                |(session_id, parent_session_id, directory, title, time_created, time_updated, raw_json)| {
                    build_db_session_record(
                        db_path,
                        DbSessionRowData {
                            session_id,
                            parent_session_id,
                            directory,
                            title,
                            time_created,
                            time_updated,
                            raw_json,
                        },
                    )
                },
            )
            .collect();
    }

    if let Ok(mut stmt) = conn.prepare(&format!(
        "SELECT id, directory, title, time_created, time_updated, data FROM session WHERE id IN ({placeholders})"
    )) {
        let Ok(rows) = stmt.query_map(params_from_iter(session_ids.iter()), |row| {
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
            .map(
                |(session_id, directory, title, time_created, time_updated, raw_json)| {
                    build_db_session_record(
                        db_path,
                        DbSessionRowData {
                            session_id,
                            parent_session_id: None,
                            directory,
                            title,
                            time_created,
                            time_updated,
                            raw_json,
                        },
                    )
                },
            )
            .collect();
    }

    if let Ok(mut stmt) = conn.prepare(&format!(
        "SELECT id, parent_id, directory, title, time_created, time_updated FROM session WHERE id IN ({placeholders})"
    )) {
        let Ok(rows) = stmt.query_map(params_from_iter(session_ids.iter()), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1).ok().flatten(),
                row.get::<_, String>(2).ok(),
                row.get::<_, String>(3).ok(),
                row.get::<_, i64>(4).ok(),
                row.get::<_, i64>(5).ok(),
            ))
        }) else {
            return Vec::new();
        };

        return rows
            .flatten()
            .map(
                |(session_id, parent_session_id, directory, title, time_created, time_updated)| {
                    build_db_session_record(
                        db_path,
                        DbSessionRowData {
                            session_id,
                            parent_session_id,
                            directory,
                            title,
                            time_created,
                            time_updated,
                            raw_json: None,
                        },
                    )
                },
            )
            .collect();
    }

    let Ok(mut stmt) = conn.prepare(&format!(
        "SELECT id, directory, title, time_created, time_updated FROM session WHERE id IN ({placeholders})"
    )) else {
        return Vec::new();
    };

    let Ok(rows) = stmt.query_map(params_from_iter(session_ids.iter()), |row| {
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
        .map(
            |(session_id, directory, title, time_created, time_updated)| {
                build_db_session_record(
                    db_path,
                    DbSessionRowData {
                        session_id,
                        parent_session_id: None,
                        directory,
                        title,
                        time_created,
                        time_updated,
                        raw_json: None,
                    },
                )
            },
        )
        .collect()
}

fn build_db_session_record(db_path: &Path, row: DbSessionRowData) -> (String, SessionRecord) {
    let DbSessionRowData {
        session_id,
        parent_session_id,
        directory,
        title,
        time_created,
        time_updated,
        raw_json,
    } = row;

    let raw = raw_json
        .as_deref()
        .and_then(parse_json)
        .unwrap_or_else(|| json!({}));
    let raw = merge_json_object(
        raw,
        json!({
            "id": session_id.clone(),
            "parentID": parent_session_id.clone(),
            "directory": directory.clone(),
            "title": title.clone(),
            "time": {
                "created": normalize_db_epoch(time_created),
                "updated": normalize_db_epoch(time_updated),
            }
        }),
    );
    let record = SessionRecord {
        directory,
        title,
        parent_session_id,
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
    if session_ids.is_empty() {
        return Vec::new();
    }

    let placeholders = sql_in_placeholders(session_ids.len());
    let Ok(mut stmt) = conn.prepare(&format!(
        "SELECT id, session_id, time_created, time_updated, data FROM message WHERE session_id IN ({placeholders})"
    ))
    else {
        return Vec::new();
    };

    let Ok(rows) = stmt.query_map(params_from_iter(session_ids.iter()), |row| {
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
    if session_ids.is_empty() {
        return Vec::new();
    }

    let placeholders = sql_in_placeholders(session_ids.len());
    let Ok(mut stmt) = conn.prepare(&format!(
        "SELECT id, message_id, session_id, time_created, time_updated, data FROM part WHERE session_id IN ({placeholders})"
    ))
    else {
        return Vec::new();
    };

    let Ok(rows) = stmt.query_map(params_from_iter(session_ids.iter()), |row| {
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

fn sql_in_placeholders(count: usize) -> String {
    vec!["?"; count].join(", ")
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

    fn session_record(
        directory: Option<&str>,
        parent_session_id: Option<&str>,
        created_at: Option<i64>,
        updated_at: Option<i64>,
    ) -> SessionRecord {
        SessionRecord {
            directory: directory.map(str::to_string),
            title: Some("session".to_string()),
            parent_session_id: parent_session_id.map(str::to_string),
            source_file: "session.json".to_string(),
            created_at,
            updated_at,
            file_mtime: None,
            raw: json!({
                "directory": directory,
                "parentID": parent_session_id,
                "time": {
                    "created": created_at,
                    "updated": updated_at,
                }
            }),
        }
    }

    fn message_record(session_id: &str, id: &str, created_at: i64) -> MessageRecord {
        MessageRecord {
            id: id.to_string(),
            session_id: session_id.to_string(),
            role: Some("assistant".to_string()),
            source_file: format!("{id}.json"),
            created_at: Some(created_at),
            file_mtime: None,
            raw: json!({
                "id": id,
                "sessionID": session_id,
                "time": {
                    "created": created_at,
                }
            }),
        }
    }

    fn inline_content(log: &SessionLog) -> &str {
        match &log.source {
            SessionSource::Inline { content, .. } => content,
            SessionSource::File(_) => panic!("expected inline session"),
        }
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

    #[tokio::test]
    async fn test_opencode_deduplicates_mixed_file_and_sqlite_records() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();

        write_json(
            &root
                .join("storage")
                .join("session")
                .join("global")
                .join("ses_mixed.json"),
            r#"{"id":"ses_mixed","directory":"/repo","time":{"created":1772602456000,"updated":1772602457000}}"#,
        )
        .await;
        write_json(
            &root
                .join("storage")
                .join("message")
                .join("ses_mixed")
                .join("msg_same.json"),
            r#"{"id":"msg_same","sessionID":"ses_mixed","role":"user","time":{"created":1772602458000}}"#,
        )
        .await;
        write_json(
            &root
                .join("storage")
                .join("part")
                .join("msg_same")
                .join("prt_same.json"),
            r#"{"id":"prt_same","sessionID":"ses_mixed","messageID":"msg_same","type":"text","time":{"created":1772602459000}}"#,
        )
        .await;

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
             VALUES (?1, 'global', '/repo', 'Mixed session', '1.0.0', ?2, ?3, ?4)",
            rusqlite::params![
                "ses_mixed",
                1_772_602_456_000_i64,
                1_772_602_557_000_i64,
                r#"{"slug":"mixed-session"}"#,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message (id, session_id, time_created, time_updated, data)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                "msg_same",
                "ses_mixed",
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
                "prt_same",
                "msg_same",
                "ses_mixed",
                1_772_602_559_000_i64,
                1_772_602_559_000_i64,
                r#"{"type":"text","text":"hello from db"}"#,
            ],
        )
        .unwrap();

        let logs = discover_recent_in(&[root.to_path_buf()], 1_772_602_700, 9_999_999).await;
        assert_eq!(logs.len(), 1);

        match &logs[0].source {
            SessionSource::Inline { content, .. } => {
                assert_eq!(content.matches("\"id\":\"msg_same\"").count(), 1);
                assert_eq!(content.matches("\"partID\":\"prt_same\"").count(), 1);
            }
            SessionSource::File(_) => panic!("expected inline session"),
        }
    }

    #[test]
    fn test_opencode_renders_one_log_for_root_and_child_cluster() {
        let mut sessions = HashMap::new();
        sessions.insert(
            "ses_root".to_string(),
            session_record(Some("/repo"), None, Some(100), Some(150)),
        );
        sessions.insert(
            "ses_child".to_string(),
            session_record(Some("/repo"), Some("ses_root"), Some(120), Some(180)),
        );

        let mut messages_by_session = BTreeMap::new();
        messages_by_session.insert(
            "ses_child".to_string(),
            vec![message_record("ses_child", "msg_child", 170)],
        );

        let logs = render_session_logs(0, sessions, messages_by_session, BTreeMap::new());
        assert_eq!(logs.len(), 1);
        match &logs[0].source {
            SessionSource::Inline { label, content } => {
                assert_eq!(label, "opencode:ses_root");
                assert!(content.contains("\"clusterSessionCount\":2"));
                assert!(content.contains("\"childSessionIDs\":[\"ses_child\"]"));
                assert!(content.contains("\"type\":\"session_member\""));
                assert!(content.contains("\"originSessionID\":\"ses_child\""));
                assert!(content.contains("\"parentSessionID\":\"ses_root\""));
                let session_meta_idx = content.find("\"type\":\"session_meta\"").unwrap();
                let session_member_idx = content.find("\"type\":\"session_member\"").unwrap();
                let child_message_idx = content.find("\"messageID\":\"msg_child\"").unwrap();
                assert!(session_meta_idx < session_member_idx);
                assert!(session_member_idx < child_message_idx);
            }
            SessionSource::File(_) => panic!("expected inline session"),
        }
    }

    #[test]
    fn test_opencode_renders_multiple_children_under_one_root() {
        let mut sessions = HashMap::new();
        sessions.insert(
            "ses_root".to_string(),
            session_record(Some("/repo"), None, Some(100), Some(150)),
        );
        sessions.insert(
            "ses_child_a".to_string(),
            session_record(Some("/repo"), Some("ses_root"), Some(120), Some(170)),
        );
        sessions.insert(
            "ses_child_b".to_string(),
            session_record(Some("/repo"), Some("ses_root"), Some(125), Some(190)),
        );

        let logs = render_session_logs(0, sessions, BTreeMap::new(), BTreeMap::new());
        assert_eq!(logs.len(), 1);
        let content = inline_content(&logs[0]);
        assert!(content.contains("\"childSessionIDs\":[\"ses_child_a\",\"ses_child_b\"]"));
    }

    #[test]
    fn test_opencode_leaves_unrelated_sessions_separate() {
        let mut sessions = HashMap::new();
        sessions.insert(
            "ses_one".to_string(),
            session_record(Some("/repo-one"), None, Some(100), Some(150)),
        );
        sessions.insert(
            "ses_two".to_string(),
            session_record(Some("/repo-two"), None, Some(200), Some(250)),
        );

        let logs = render_session_logs(0, sessions, BTreeMap::new(), BTreeMap::new());
        assert_eq!(logs.len(), 2);
    }

    #[test]
    fn test_opencode_cluster_recency_tracks_newer_child_activity() {
        let mut sessions = HashMap::new();
        sessions.insert(
            "ses_root".to_string(),
            session_record(Some("/repo"), None, Some(100), Some(110)),
        );
        sessions.insert(
            "ses_child".to_string(),
            session_record(Some("/repo"), Some("ses_root"), Some(120), Some(130)),
        );

        let mut messages_by_session = BTreeMap::new();
        messages_by_session.insert(
            "ses_child".to_string(),
            vec![message_record("ses_child", "msg_child", 400)],
        );

        let logs = render_session_logs(0, sessions, messages_by_session, BTreeMap::new());
        assert_eq!(logs[0].updated_at, Some(400));
    }

    #[test]
    fn test_opencode_root_cwd_falls_back_to_child_directory() {
        let mut sessions = HashMap::new();
        sessions.insert(
            "ses_root".to_string(),
            session_record(None, None, Some(100), Some(150)),
        );
        sessions.insert(
            "ses_child".to_string(),
            session_record(
                Some("/repo-from-child"),
                Some("ses_root"),
                Some(120),
                Some(180),
            ),
        );

        let logs = render_session_logs(0, sessions, BTreeMap::new(), BTreeMap::new());
        let content = inline_content(&logs[0]);
        let metadata = crate::scanner::parse_session_metadata_str(content);
        assert_eq!(metadata.session_id, Some("ses_root".to_string()));
        assert_eq!(metadata.cwd, Some("/repo-from-child".to_string()));
    }

    #[tokio::test]
    async fn test_opencode_discovers_child_activity_under_root_upload_identity() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();
        let db_path = root.join("opencode.db");
        let conn = Connection::open(&db_path).unwrap();

        conn.execute_batch(
            "
            CREATE TABLE session (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                parent_id TEXT,
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
            "INSERT INTO session (id, project_id, parent_id, directory, title, version, time_created, time_updated, data)
             VALUES (?1, 'workspace', NULL, '/repo', 'root', '1.0.0', ?2, ?3, ?4)",
            rusqlite::params![
                "ses_root",
                1_700_000_000_000_i64,
                1_700_000_001_000_i64,
                r#"{"slug":"root"}"#,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO session (id, project_id, parent_id, directory, title, version, time_created, time_updated, data)
             VALUES (?1, 'workspace', ?2, '/repo', 'child', '1.0.0', ?3, ?4, ?5)",
            rusqlite::params![
                "ses_child",
                "ses_root",
                1_700_000_100_000_i64,
                1_700_000_200_000_i64,
                r#"{"slug":"child"}"#,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO message (id, session_id, time_created, time_updated, data)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                "msg_child",
                "ses_child",
                1_700_000_300_000_i64,
                1_700_000_300_000_i64,
                r#"{"role":"assistant","time":{"created":1700000300000}}"#,
            ],
        )
        .unwrap();

        let logs = discover_recent_in(&[root.to_path_buf()], 1_700_000_400, 500).await;
        assert_eq!(logs.len(), 1);
        match &logs[0].source {
            SessionSource::Inline { label, content } => {
                assert_eq!(label, "opencode:ses_root");
                assert!(content.contains("\"originSessionID\":\"ses_child\""));
                assert!(content.contains("\"parentSessionID\":\"ses_root\""));
            }
            SessionSource::File(_) => panic!("expected inline session"),
        }
        assert_eq!(logs[0].updated_at, Some(1_700_000_300));
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
