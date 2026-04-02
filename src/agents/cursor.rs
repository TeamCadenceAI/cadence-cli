//! Cursor agent log discovery.
//!
//! Cursor stores sessions in a few different local formats:
//! - Legacy/VS Code style `chatSessions/*.json`
//! - Agent transcript JSONL files under `~/.cursor/projects/*/agent-transcripts/**`
//! - Desktop composer state split across `workspaceStorage/*` and `globalStorage/state.vscdb`

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{MAIN_SEPARATOR, Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use rusqlite::{Connection, OpenFlags, params};
use serde_json::{Value, json};

use super::{
    AgentExplorer, SessionLog, SessionSource, app_config_dir_in, find_chat_session_dirs, home_dir,
    recent_files_with_exts,
};
use crate::scanner::{self, AgentType};

const CURSOR_PROJECT_SKIP_DIRS: &[&str] = &["mcps", "agent-tools", "terminals"];
const CURSOR_PATH_DECODE_MAX_CANDIDATES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CursorSourcePriority {
    LegacyChatSession = 0,
    AgentTranscript = 1,
    StoreDb = 2,
    DesktopComposer = 3,
}

#[derive(Debug, Clone)]
struct CursorDiscoveredSession {
    canonical_id: Option<String>,
    workspace_hint: Option<String>,
    content_len: usize,
    priority: CursorSourcePriority,
    log: SessionLog,
}

#[allow(dead_code)]
/// Return all Cursor log directories for use by the post-commit hook.
pub async fn log_dirs() -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    log_dirs_in(&home).await
}

#[allow(dead_code)]
/// Return all Cursor log directories for backfill (not repo-scoped).
pub async fn all_log_dirs() -> Vec<PathBuf> {
    log_dirs().await
}

pub struct CursorExplorer;

#[async_trait]
impl AgentExplorer for CursorExplorer {
    async fn discover_recent(&self, now: i64, since_secs: i64) -> Vec<SessionLog> {
        let home = match home_dir() {
            Some(h) => h,
            None => return Vec::new(),
        };
        discover_recent_in(&home, now, since_secs).await
    }
}

async fn discover_recent_in(home: &Path, now: i64, since_secs: i64) -> Vec<SessionLog> {
    let mut discovered: HashMap<String, CursorDiscoveredSession> = HashMap::new();

    let ws_root = app_config_dir_in("Cursor", home)
        .join("User")
        .join("workspaceStorage");
    let chat_session_dirs = find_chat_session_dirs(&ws_root).await;
    for file in recent_files_with_exts(&chat_session_dirs, now, since_secs, &["json"]).await {
        let metadata = scanner::parse_session_metadata(&file.path).await;
        let candidate = CursorDiscoveredSession {
            canonical_id: metadata.session_id,
            workspace_hint: metadata.cwd,
            content_len: 0,
            priority: CursorSourcePriority::LegacyChatSession,
            log: SessionLog {
                agent_type: AgentType::Cursor,
                source: SessionSource::File(file.path),
                updated_at: Some(file.mtime_epoch),
            },
        };
        merge_cursor_session(&mut discovered, candidate);
    }

    for candidate in discover_agent_transcripts(home, now, since_secs).await {
        merge_cursor_session(&mut discovered, candidate);
    }

    for candidate in discover_store_db_sessions(home, now, since_secs).await {
        merge_cursor_session(&mut discovered, candidate);
    }

    let desktop_logs = discover_desktop_sessions(home, now, since_secs).await;
    for candidate in desktop_logs {
        merge_cursor_session(&mut discovered, candidate);
    }

    let mut logs = discovered
        .into_values()
        .map(|candidate| candidate.log)
        .collect::<Vec<_>>();

    logs.sort_by(|a, b| {
        a.updated_at
            .unwrap_or_default()
            .cmp(&b.updated_at.unwrap_or_default())
            .then_with(|| a.source_label().cmp(&b.source_label()))
    });
    logs
}

#[allow(dead_code)]
async fn log_dirs_in(home: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    let ws_root = app_config_dir_in("Cursor", home)
        .join("User")
        .join("workspaceStorage");
    dirs.extend(find_chat_session_dirs(&ws_root).await);

    let projects_dir = home.join(".cursor").join("projects");
    dirs.extend(collect_agent_transcript_dirs(&projects_dir).await);

    dirs
}

async fn collect_agent_transcript_dirs(root: &Path) -> Vec<PathBuf> {
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

            if !file_type.is_dir() {
                continue;
            }

            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };

            if CURSOR_PROJECT_SKIP_DIRS.contains(&name) {
                continue;
            }

            if name == "agent-transcripts" {
                out.push(path);
                continue;
            }

            stack.push(path);
        }
    }

    out
}

async fn discover_agent_transcripts(
    home: &Path,
    now: i64,
    since_secs: i64,
) -> Vec<CursorDiscoveredSession> {
    let cutoff = now - since_secs;
    let projects_dir = home.join(".cursor").join("projects");
    let transcript_dirs = collect_agent_transcript_dirs(&projects_dir).await;
    let workspace_map = collect_workspace_paths(home).await;
    let mut workspace_decode_cache: HashMap<String, Option<String>> = HashMap::new();
    let mut out = Vec::new();

    for dir in transcript_dirs {
        let mut stack = vec![dir.clone()];
        while let Some(current) = stack.pop() {
            let mut entries = match tokio::fs::read_dir(&current).await {
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
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }
                if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
                    continue;
                }

                let metadata = match tokio::fs::metadata(&path).await {
                    Ok(metadata) => metadata,
                    Err(_) => continue,
                };
                let mtime_epoch = match metadata.modified() {
                    Ok(mtime) => match mtime.duration_since(UNIX_EPOCH) {
                        Ok(d) => d.as_secs() as i64,
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                };
                if mtime_epoch < cutoff {
                    continue;
                }

                let Some(session_id) = path.file_stem().and_then(|stem| stem.to_str()) else {
                    continue;
                };
                let workspace_key = path
                    .strip_prefix(&projects_dir)
                    .ok()
                    .and_then(|relative| relative.components().next())
                    .map(|component| component.as_os_str().to_string_lossy().to_string());
                let cwd = if let Some(workspace_key) = workspace_key.as_deref() {
                    if let Some(path) = workspace_map.get(workspace_key).cloned() {
                        Some(path)
                    } else {
                        if let Some(cached) = workspace_decode_cache.get(workspace_key) {
                            cached.clone()
                        } else {
                            let decoded = decode_cursor_workspace_path(workspace_key).await;
                            workspace_decode_cache
                                .insert(workspace_key.to_string(), decoded.clone());
                            decoded
                        }
                    }
                } else {
                    None
                };
                let content = match tokio::fs::read_to_string(&path).await {
                    Ok(content) => content,
                    Err(_) => continue,
                };
                let label = path.to_string_lossy().to_string();
                let source = SessionSource::Inline {
                    label,
                    content: prepend_cursor_metadata_line(
                        &content,
                        session_id,
                        cwd.as_deref(),
                        None,
                        "agent_transcript",
                    ),
                };
                out.push(CursorDiscoveredSession {
                    canonical_id: Some(session_id.to_string()),
                    workspace_hint: cwd,
                    content_len: content.len(),
                    priority: CursorSourcePriority::AgentTranscript,
                    log: SessionLog {
                        agent_type: AgentType::Cursor,
                        source,
                        updated_at: Some(mtime_epoch),
                    },
                });
            }
        }
    }

    out
}

async fn collect_workspace_paths(home: &Path) -> HashMap<String, String> {
    let ws_root = app_config_dir_in("Cursor", home)
        .join("User")
        .join("workspaceStorage");
    let mut out = HashMap::new();
    let mut entries = match tokio::fs::read_dir(&ws_root).await {
        Ok(entries) => entries,
        Err(_) => return out,
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let workspace_dir = entry.path();
        if !entry
            .file_type()
            .await
            .map(|ft| ft.is_dir())
            .unwrap_or(false)
        {
            continue;
        }
        let workspace_json = workspace_dir.join("workspace.json");
        let Ok(content) = tokio::fs::read_to_string(&workspace_json).await else {
            continue;
        };
        let Some(path) = parse_workspace_json_path(&content) else {
            continue;
        };
        let encoded_key = encode_cursor_project_workspace_key(Path::new(&path));
        out.entry(encoded_key).or_insert(path);
    }

    out
}

async fn discover_store_db_sessions(
    home: &Path,
    now: i64,
    since_secs: i64,
) -> Vec<CursorDiscoveredSession> {
    let chats_root = home.join(".cursor").join("chats");
    if !tokio::fs::try_exists(&chats_root).await.unwrap_or(false) {
        return Vec::new();
    }

    let cutoff = now - since_secs;
    let chats_root = chats_root.clone();
    tokio::task::spawn_blocking(move || query_cursor_store_db_sessions(&chats_root, cutoff))
        .await
        .unwrap_or_default()
}

async fn discover_desktop_sessions(
    home: &Path,
    now: i64,
    since_secs: i64,
) -> Vec<CursorDiscoveredSession> {
    let ws_root = app_config_dir_in("Cursor", home)
        .join("User")
        .join("workspaceStorage");
    let global_db = app_config_dir_in("Cursor", home)
        .join("User")
        .join("globalStorage")
        .join("state.vscdb");

    if !global_db.exists() || !ws_root.exists() {
        return Vec::new();
    }

    let ws_root = ws_root.clone();
    let global_db = global_db.clone();
    tokio::task::spawn_blocking(move || {
        query_cursor_desktop_sessions(&ws_root, &global_db, now, since_secs)
    })
    .await
    .unwrap_or_default()
}

fn query_cursor_desktop_sessions(
    ws_root: &Path,
    global_db: &Path,
    now: i64,
    since_secs: i64,
) -> Vec<CursorDiscoveredSession> {
    let cutoff_ms = (now - since_secs) * 1000;
    let global = match open_sqlite_readonly(global_db) {
        Ok(conn) => conn,
        Err(_) => return Vec::new(),
    };
    let mut logs = Vec::new();
    let workspace_dirs = match std::fs::read_dir(ws_root) {
        Ok(entries) => entries,
        Err(_) => return logs,
    };

    for workspace_entry in workspace_dirs.flatten() {
        let workspace_dir = workspace_entry.path();
        if !workspace_dir.is_dir() {
            continue;
        }

        let workspace_db = workspace_dir.join("state.vscdb");
        let workspace_json = workspace_dir.join("workspace.json");
        if !workspace_db.exists() || !workspace_json.exists() {
            continue;
        }

        let cwd = std::fs::read_to_string(&workspace_json)
            .ok()
            .and_then(|content| parse_workspace_json_path(&content));

        let workspace = match open_sqlite_readonly(&workspace_db) {
            Ok(conn) => conn,
            Err(_) => continue,
        };
        let Some(composer_data_raw) = sqlite_query_string(
            &workspace,
            "SELECT value FROM ItemTable WHERE key = 'composer.composerData'",
            params![],
        ) else {
            continue;
        };
        let composers = parse_workspace_composers(&composer_data_raw);
        for composer in composers {
            if composer.last_updated_at < cutoff_ms {
                continue;
            }
            let Some(content) = build_desktop_cursor_session_content(
                &global,
                &composer.composer_id,
                cwd.as_deref(),
            ) else {
                continue;
            };
            logs.push(CursorDiscoveredSession {
                canonical_id: Some(composer.composer_id.clone()),
                workspace_hint: cwd.clone(),
                content_len: content.len(),
                priority: CursorSourcePriority::DesktopComposer,
                log: SessionLog {
                    agent_type: AgentType::Cursor,
                    source: SessionSource::Inline {
                        label: format!(
                            "cursor-desktop:{}:{}",
                            workspace_dir
                                .file_name()
                                .and_then(|name| name.to_str())
                                .unwrap_or("workspace"),
                            composer.composer_id
                        ),
                        content,
                    },
                    updated_at: Some(composer.last_updated_at / 1000),
                },
            });
        }
    }

    logs
}

fn open_sqlite_readonly(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let _ = conn.busy_timeout(Duration::from_millis(200));
    Ok(conn)
}

fn sqlite_query_string<P>(conn: &Connection, sql: &str, params: P) -> Option<String>
where
    P: rusqlite::Params,
{
    conn.query_row(sql, params, |row| row.get::<_, String>(0))
        .ok()
}

fn parse_workspace_json_path(content: &str) -> Option<String> {
    let value = serde_json::from_str::<Value>(content).ok()?;
    value
        .get("folder")
        .or_else(|| value.get("path"))
        .and_then(Value::as_str)
        .map(normalize_cursor_workspace_path)
}

fn encode_cursor_project_workspace_key(path: &Path) -> String {
    use std::path::Component;

    let mut encoded = String::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                let raw = prefix.as_os_str().to_string_lossy();
                if let Some(drive) = raw.strip_suffix(':') {
                    encoded.push_str(drive);
                    encoded.push_str("--");
                } else if !raw.is_empty() {
                    if !encoded.is_empty() && !encoded.ends_with('-') {
                        encoded.push('-');
                    }
                    encoded.push_str(&raw.replace(['/', '\\', ':'], "-"));
                }
            }
            Component::RootDir => {}
            Component::Normal(segment) => {
                let segment = segment.to_string_lossy();
                if segment.is_empty() {
                    continue;
                }
                if !encoded.is_empty() && !encoded.ends_with('-') {
                    encoded.push('-');
                }
                encoded.push_str(&segment);
            }
            Component::CurDir | Component::ParentDir => {}
        }
    }
    encoded
}

fn normalize_cursor_workspace_path(path: &str) -> String {
    let trimmed = path.strip_prefix("file://").unwrap_or(path);
    if cfg!(target_os = "windows") && trimmed.starts_with('/') && trimmed.len() > 3 {
        trimmed[1..].to_string()
    } else {
        trimmed.to_string()
    }
}

#[derive(Debug, Clone)]
struct WorkspaceComposerHead {
    composer_id: String,
    last_updated_at: i64,
}

fn parse_workspace_composers(raw: &str) -> Vec<WorkspaceComposerHead> {
    let value = match serde_json::from_str::<Value>(raw) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    value
        .get("allComposers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            Some(WorkspaceComposerHead {
                composer_id: entry.get("composerId")?.as_str()?.to_string(),
                last_updated_at: entry
                    .get("lastUpdatedAt")
                    .and_then(Value::as_i64)
                    .or_else(|| entry.get("createdAt").and_then(Value::as_i64))?,
            })
        })
        .collect()
}

fn build_desktop_cursor_session_content(
    global: &Connection,
    composer_id: &str,
    cwd: Option<&str>,
) -> Option<String> {
    let composer_raw = sqlite_query_string(
        global,
        "SELECT value FROM cursorDiskKV WHERE key = ?1",
        params![format!("composerData:{composer_id}")],
    )?;
    let composer = serde_json::from_str::<Value>(&composer_raw).ok()?;
    let model = composer
        .pointer("/modelConfig/modelName")
        .or_else(|| composer.pointer("/lastUsedModel/name"))
        .or_else(|| composer.pointer("/model/name"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty());

    let mut header_ids = composer
        .get("fullConversationHeadersOnly")
        .and_then(Value::as_array)
        .map(|headers| {
            headers
                .iter()
                .filter_map(|header| header.get("bubbleId").and_then(Value::as_str))
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    header_ids.extend(extract_bubble_ids_from_value(
        composer.get("conversation").unwrap_or(&Value::Null),
    ));
    header_ids.extend(extract_bubble_ids_from_value(
        composer.get("conversationMap").unwrap_or(&Value::Null),
    ));
    dedupe_preserving_order(&mut header_ids);

    let mut bubbles = query_cursor_bubbles(global, composer_id);
    if header_ids.is_empty() {
        header_ids.extend(bubbles.keys().cloned());
        header_ids.sort();
    }

    let mut lines = Vec::new();
    lines.push(
        json!({
            "sessionId": composer_id,
            "session_id": composer_id,
            "cwd": cwd,
            "workspacePath": cwd,
            "model": model,
            "createdAt": composer.get("createdAt").and_then(Value::as_i64),
            "lastUpdatedAt": composer.get("lastUpdatedAt").and_then(Value::as_i64),
            "cursor_source": "desktop_state_vscdb",
            "workspaceId": composer.get("workspaceId").and_then(Value::as_str),
        })
        .to_string(),
    );

    for bubble_id in header_ids {
        let Some(bubble) = bubbles.remove(&bubble_id) else {
            continue;
        };
        let Some(role) = cursor_role_for_value(&bubble) else {
            continue;
        };
        let Some(content) = extract_cursor_bubble_text(&bubble) else {
            continue;
        };
        lines.push(
            json!({
                "role": role,
                "content": content,
                "timestamp": bubble.get("createdAt").and_then(Value::as_str),
                "model": bubble.pointer("/modelInfo/modelName").and_then(Value::as_str).or(model),
                "bubbleId": bubble_id,
            })
            .to_string(),
        );
    }

    if lines.len() == 1 {
        None
    } else {
        Some(lines.join("\n"))
    }
}

fn query_cursor_bubbles(global: &Connection, composer_id: &str) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    let Ok(mut stmt) =
        global.prepare("SELECT key, value FROM cursorDiskKV WHERE key LIKE ?1 ORDER BY key")
    else {
        return out;
    };
    let pattern = format!("bubbleId:{composer_id}:%");
    let Ok(rows) = stmt.query_map(params![pattern], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    }) else {
        return out;
    };

    for row in rows.flatten() {
        let Some(bubble_id) = row.0.rsplit(':').next() else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&row.1) else {
            continue;
        };
        out.insert(bubble_id.to_string(), value);
    }
    out
}

fn cursor_role_for_type(kind: Option<i64>) -> Option<&'static str> {
    match kind {
        Some(1) => Some("user"),
        Some(2) => Some("assistant"),
        _ => None,
    }
}

fn cursor_role_for_value(value: &Value) -> Option<&'static str> {
    cursor_role_for_type(value.get("type").and_then(Value::as_i64)).or_else(|| {
        value
            .get("role")
            .and_then(Value::as_str)
            .and_then(|role| match role {
                "user" => Some("user"),
                "assistant" => Some("assistant"),
                _ => None,
            })
    })
}

fn extract_cursor_bubble_text(bubble: &Value) -> Option<String> {
    for key in ["text", "markdown", "content", "description"] {
        if let Some(text) = bubble.get(key).and_then(Value::as_str) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    for pointer in [
        "/toolFormerData/rawArgs",
        "/toolFormerData/result",
        "/toolFormerData/output",
        "/toolResult/output",
        "/errorDetails/message",
    ] {
        if let Some(text) = bubble.pointer(pointer).and_then(Value::as_str) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    if let Some(rich_text) = bubble.get("richText").and_then(Value::as_str)
        && let Ok(parsed) = serde_json::from_str::<Value>(rich_text)
    {
        let mut fragments = Vec::new();
        collect_rich_text_fragments(&parsed, &mut fragments);
        let joined = fragments.join(" ").trim().to_string();
        if !joined.is_empty() {
            return Some(joined);
        }
    }

    None
}

fn extract_bubble_ids_from_value(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_bubble_ids(value, &mut out);
    out
}

fn dedupe_preserving_order(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn collect_bubble_ids(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for key in ["bubbleId", "id"] {
                if let Some(id) = map.get(key).and_then(Value::as_str)
                    && !id.trim().is_empty()
                {
                    out.push(id.to_string());
                }
            }
            for child in map.values() {
                collect_bubble_ids(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_bubble_ids(item, out);
            }
        }
        _ => {}
    }
}

fn collect_rich_text_fragments(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(text) = map.get("text").and_then(Value::as_str) {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    out.push(trimmed.to_string());
                }
            }
            if let Some(children) = map.get("children").and_then(Value::as_array) {
                for child in children {
                    collect_rich_text_fragments(child, out);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_rich_text_fragments(item, out);
            }
        }
        _ => {}
    }
}

fn prepend_cursor_metadata_line(
    content: &str,
    session_id: &str,
    cwd: Option<&str>,
    model: Option<&str>,
    source_kind: &str,
) -> String {
    let metadata = json!({
        "sessionId": session_id,
        "session_id": session_id,
        "cwd": cwd,
        "workspacePath": cwd,
        "model": model,
        "cursor_source": source_kind,
    })
    .to_string();
    if content.is_empty() {
        metadata
    } else {
        format!("{metadata}\n{content}")
    }
}

async fn decode_cursor_workspace_path(encoded: &str) -> Option<String> {
    let decoded = decode_cursor_workspace_path_buf(encoded).await?;
    Some(decoded.to_string_lossy().to_string())
}

fn initial_cursor_path_state(trimmed: &str) -> (PathBuf, usize) {
    if MAIN_SEPARATOR == '\\' {
        let bytes = trimmed.as_bytes();
        if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() {
            let drive = char::from(bytes[0]);
            if bytes[1] == b'-' && bytes[2] == b'-' {
                return (PathBuf::from(format!("{drive}:{MAIN_SEPARATOR}")), 3);
            }
        }
    }

    (PathBuf::from(MAIN_SEPARATOR.to_string()), 0)
}

async fn decode_cursor_workspace_path_buf(encoded: &str) -> Option<PathBuf> {
    if encoded.trim().is_empty() {
        return None;
    }

    let mut stack = vec![initial_cursor_path_state(encoded)];
    let mut checked_candidates = 0usize;
    while let Some((prefix, start_idx)) = stack.pop() {
        if start_idx >= encoded.len() {
            return Some(prefix);
        }

        let mut next = Vec::new();
        let bytes = encoded.as_bytes();
        for end_idx in (start_idx + 1..=encoded.len()).rev() {
            if end_idx != encoded.len() && bytes[end_idx] != b'-' {
                continue;
            }

            checked_candidates += 1;
            if checked_candidates > CURSOR_PATH_DECODE_MAX_CANDIDATES {
                return None;
            }

            let segment = &encoded[start_idx..end_idx];
            if segment.is_empty() {
                continue;
            }

            let candidate = prefix.join(segment);
            if tokio::fs::try_exists(&candidate).await.unwrap_or(false) {
                let next_idx = if end_idx == encoded.len() {
                    end_idx
                } else {
                    end_idx + 1
                };
                next.push((candidate, next_idx));
            }
        }

        stack.extend(next);
    }

    None
}

fn merge_cursor_session(
    discovered: &mut HashMap<String, CursorDiscoveredSession>,
    incoming: CursorDiscoveredSession,
) {
    let key = cursor_discovered_key(&incoming);
    match discovered.get(&key) {
        None => {
            discovered.insert(key, incoming);
        }
        Some(existing) => {
            if should_replace_cursor_candidate(existing, &incoming) {
                discovered.insert(key, incoming);
            }
        }
    }
}

fn cursor_discovered_key(candidate: &CursorDiscoveredSession) -> String {
    match (&candidate.canonical_id, &candidate.workspace_hint) {
        (Some(session_id), Some(cwd)) => format!("{session_id}::{cwd}"),
        (Some(session_id), None) => format!("{session_id}::"),
        (None, Some(cwd)) => format!("::<{cwd}>"),
        (None, None) => candidate.log.source_label(),
    }
}

fn should_replace_cursor_candidate(
    existing: &CursorDiscoveredSession,
    incoming: &CursorDiscoveredSession,
) -> bool {
    if incoming.priority != existing.priority {
        return incoming.priority > existing.priority;
    }
    if incoming.content_len != existing.content_len {
        return incoming.content_len > existing.content_len;
    }
    incoming.log.updated_at.unwrap_or_default() > existing.log.updated_at.unwrap_or_default()
}

fn query_cursor_store_db_sessions(chats_root: &Path, cutoff: i64) -> Vec<CursorDiscoveredSession> {
    let mut out = Vec::new();
    let mut stack = vec![chats_root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = match std::fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.file_name().and_then(|name| name.to_str()) != Some("store.db") {
                continue;
            }
            let Some(candidate) = build_cursor_store_db_session(&path) else {
                continue;
            };
            if candidate.log.updated_at.unwrap_or_default() < cutoff {
                continue;
            }
            out.push(candidate);
        }
    }
    out
}

fn build_cursor_store_db_session(path: &Path) -> Option<CursorDiscoveredSession> {
    let conn = open_sqlite_readonly(path).ok()?;
    let mut records = Vec::new();
    let mut meta_values = Vec::new();
    for table in ["meta", "blobs"] {
        if !sqlite_table_exists(&conn, table) {
            continue;
        }
        let rows = sqlite_table_string_rows(&conn, table);
        meta_values.extend(rows.iter().map(|(_, value)| value.clone()));
        records.extend(rows);
    }
    if records.is_empty() {
        return None;
    }

    let metadata = parse_cursor_store_db_metadata(&meta_values)?;
    let content = build_cursor_store_db_content(&metadata, &records)?;
    let file_mtime = std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    let metadata_updated_at = metadata
        .updated_at
        .or(metadata.created_at)
        .map(normalize_epoch_guess)
        .unwrap_or_default();
    let updated_at = file_mtime.max(metadata_updated_at);
    Some(CursorDiscoveredSession {
        canonical_id: Some(metadata.session_id.clone()),
        workspace_hint: metadata.cwd.clone(),
        content_len: content.len(),
        priority: CursorSourcePriority::StoreDb,
        log: SessionLog {
            agent_type: AgentType::Cursor,
            source: SessionSource::Inline {
                label: format!("cursor-store:{}", path.display()),
                content,
            },
            updated_at: Some(updated_at),
        },
    })
}

#[derive(Debug, Clone)]
struct CursorStoreDbMetadata {
    session_id: String,
    cwd: Option<String>,
    model: Option<String>,
    created_at: Option<i64>,
    updated_at: Option<i64>,
}

fn parse_cursor_store_db_metadata(values: &[String]) -> Option<CursorStoreDbMetadata> {
    let mut session_id = None;
    let mut cwd = None;
    let mut model = None;
    let mut created_at = None;
    let mut updated_at = None;

    for value in values {
        let Ok(json) = serde_json::from_str::<Value>(value) else {
            continue;
        };
        session_id = session_id
            .or_else(|| find_string_in_value(&json, &["agentId", "sessionId", "composerId", "id"]));
        cwd = cwd.or_else(|| {
            find_string_in_value(
                &json,
                &[
                    "workspacePath",
                    "cwd",
                    "workingDirectory",
                    "working_directory",
                    "path",
                ],
            )
        });
        model =
            model.or_else(|| find_string_in_value(&json, &["lastUsedModel", "modelName", "model"]));
        created_at = created_at.or_else(|| find_i64_in_value(&json, &["createdAt", "created_at"]));
        updated_at = updated_at
            .or_else(|| find_i64_in_value(&json, &["lastUpdatedAt", "updatedAt", "updated_at"]));
    }

    Some(CursorStoreDbMetadata {
        session_id: session_id?,
        cwd,
        model,
        created_at,
        updated_at,
    })
}

fn build_cursor_store_db_content(
    metadata: &CursorStoreDbMetadata,
    records: &[(String, String)],
) -> Option<String> {
    let mut lines = vec![
        json!({
            "sessionId": metadata.session_id,
            "session_id": metadata.session_id,
            "cwd": metadata.cwd,
            "workspacePath": metadata.cwd,
            "model": metadata.model,
            "createdAt": metadata.created_at,
            "lastUpdatedAt": metadata.updated_at,
            "cursor_source": "store_db",
        })
        .to_string(),
    ];
    let mut seen = HashSet::new();
    for (_, value) in records {
        let Ok(json) = serde_json::from_str::<Value>(value) else {
            continue;
        };
        for message in extract_cursor_message_candidates(&json) {
            let fingerprint = format!("{}:{}", message.role, message.content);
            if !seen.insert(fingerprint) {
                continue;
            }
            lines.push(
                json!({
                    "role": message.role,
                    "content": message.content,
                    "timestamp": message.timestamp,
                    "model": message.model,
                })
                .to_string(),
            );
        }
    }
    if lines.len() <= 1 {
        None
    } else {
        Some(lines.join("\n"))
    }
}

#[derive(Debug, Clone)]
struct CursorMessageCandidate {
    role: String,
    content: String,
    timestamp: Option<i64>,
    model: Option<String>,
}

fn extract_cursor_message_candidates(value: &Value) -> Vec<CursorMessageCandidate> {
    let mut out = Vec::new();
    collect_cursor_message_candidates(value, &mut out);
    out
}

fn collect_cursor_message_candidates(value: &Value, out: &mut Vec<CursorMessageCandidate>) {
    match value {
        Value::Object(map) => {
            let role = map
                .get("role")
                .and_then(Value::as_str)
                .or_else(|| map.get("type").and_then(Value::as_str));
            let content = map
                .get("content")
                .and_then(Value::as_str)
                .or_else(|| map.get("text").and_then(Value::as_str))
                .or_else(|| map.get("markdown").and_then(Value::as_str));
            if let (Some(role), Some(content)) = (role, content)
                && matches!(role, "user" | "assistant")
                && !content.trim().is_empty()
            {
                out.push(CursorMessageCandidate {
                    role: role.to_string(),
                    content: content.trim().to_string(),
                    timestamp: map
                        .get("createdAt")
                        .and_then(Value::as_i64)
                        .or_else(|| map.get("timestamp").and_then(Value::as_i64)),
                    model: map
                        .get("model")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                        .or_else(|| {
                            value
                                .pointer("/modelInfo/modelName")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                        }),
                });
            }
            for child in map.values() {
                collect_cursor_message_candidates(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_cursor_message_candidates(item, out);
            }
        }
        _ => {}
    }
}

fn find_string_in_value(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(map) => {
            for key in keys {
                if let Some(string) = map.get(*key).and_then(Value::as_str)
                    && !string.trim().is_empty()
                {
                    return Some(string.to_string());
                }
            }
            for child in map.values() {
                if let Some(found) = find_string_in_value(child, keys) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => items
            .iter()
            .find_map(|item| find_string_in_value(item, keys)),
        _ => None,
    }
}

fn find_i64_in_value(value: &Value, keys: &[&str]) -> Option<i64> {
    match value {
        Value::Object(map) => {
            for key in keys {
                if let Some(number) = map.get(*key).and_then(Value::as_i64) {
                    return Some(number);
                }
            }
            for child in map.values() {
                if let Some(found) = find_i64_in_value(child, keys) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => items.iter().find_map(|item| find_i64_in_value(item, keys)),
        _ => None,
    }
}

fn normalize_epoch_guess(value: i64) -> i64 {
    if value > 100_000_000_000 {
        value / 1000
    } else {
        value
    }
}

fn sqlite_table_exists(conn: &Connection, table: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1 LIMIT 1",
        params![table],
        |_| Ok(()),
    )
    .is_ok()
}

fn sqlite_table_string_rows(conn: &Connection, table: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let direct_sql = format!("SELECT key, CAST(value AS TEXT) FROM {table}");
    if let Ok(mut stmt) = conn.prepare(&direct_sql)
        && let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
    {
        out.extend(
            rows.flatten()
                .filter(|(_, value)| looks_like_jsonish(value)),
        );
        if !out.is_empty() {
            return out;
        }
    }

    let pragma = format!("PRAGMA table_info({table})");
    let Ok(mut info_stmt) = conn.prepare(&pragma) else {
        return out;
    };
    let Ok(columns) = info_stmt.query_map([], |row| row.get::<_, String>(1)) else {
        return out;
    };
    let columns = columns.flatten().collect::<Vec<_>>();
    if columns.is_empty() {
        return out;
    }
    let sql = format!("SELECT * FROM {table}");
    let Ok(mut stmt) = conn.prepare(&sql) else {
        return out;
    };
    let Ok(mut rows) = stmt.query([]) else {
        return out;
    };
    while let Ok(Some(row)) = rows.next() {
        let mut key = None;
        let mut value = None;
        for (idx, column) in columns.iter().enumerate() {
            if key.is_none()
                && (column == "key" || column == "id" || column.ends_with("Id"))
                && let Ok(text) = row.get::<_, String>(idx)
            {
                key = Some(text);
            }
            if value.is_none()
                && let Ok(text) = row.get::<_, String>(idx)
                && looks_like_jsonish(&text)
            {
                value = Some(text);
            }
            if value.is_none()
                && let Ok(bytes) = row.get::<_, Vec<u8>>(idx)
                && let Ok(text) = String::from_utf8(bytes)
                && looks_like_jsonish(&text)
            {
                value = Some(text);
            }
        }
        if let Some(value) = value {
            out.push((key.unwrap_or_else(|| table.to_string()), value));
        }
    }
    out
}

fn looks_like_jsonish(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.starts_with('{') || trimmed.starts_with('[')
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::app_config_dir_in;
    use crate::scanner;
    use tempfile::TempDir;

    fn create_cursor_db(path: &Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value BLOB);
             CREATE TABLE cursorDiskKV (key TEXT PRIMARY KEY, value BLOB);",
        )
        .unwrap();
        conn
    }

    fn create_cursor_store_db(path: &Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB);
             CREATE TABLE blobs (key TEXT PRIMARY KEY, value BLOB);",
        )
        .unwrap();
        conn
    }

    async fn write_workspace(path: &Path, folder: &str, composer_id: &str, updated_at: i64) {
        tokio::fs::create_dir_all(path).await.unwrap();
        tokio::fs::write(
            path.join("workspace.json"),
            json!({ "folder": folder }).to_string(),
        )
        .await
        .unwrap();
        let db = create_cursor_db(&path.join("state.vscdb"));
        db.execute(
            "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)",
            params![
                "composer.composerData",
                json!({
                    "allComposers": [{
                        "composerId": composer_id,
                        "lastUpdatedAt": updated_at,
                        "createdAt": updated_at - 1000,
                    }]
                })
                .to_string()
            ],
        )
        .unwrap();
    }

    fn seed_global_cursor_session(path: &Path, composer_id: &str) {
        let db = create_cursor_db(path);
        db.execute(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?1, ?2)",
            params![
                format!("composerData:{composer_id}"),
                json!({
                    "composerId": composer_id,
                    "createdAt": 1_775_083_355_225i64,
                    "lastUpdatedAt": 1_775_083_382_256i64,
                    "modelConfig": { "modelName": "composer-2" },
                    "fullConversationHeadersOnly": [
                        { "bubbleId": "u1", "type": 1 },
                        { "bubbleId": "a1", "type": 2 }
                    ]
                })
                .to_string()
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?1, ?2)",
            params![
                format!("bubbleId:{composer_id}:u1"),
                json!({
                    "type": 1,
                    "text": "Explain the architecture",
                    "createdAt": "2026-04-01T22:42:55.658Z",
                    "modelInfo": { "modelName": "composer-2" }
                })
                .to_string()
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO cursorDiskKV (key, value) VALUES (?1, ?2)",
            params![
                format!("bubbleId:{composer_id}:a1"),
                json!({
                    "type": 2,
                    "markdown": "Here is the architecture.",
                    "createdAt": "2026-04-01T22:42:57.468Z"
                })
                .to_string()
            ],
        )
        .unwrap();
    }

    fn seed_cursor_store_db(path: &Path, session_id: &str) {
        let db = create_cursor_store_db(path);
        db.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)",
            params![
                "sessionMeta",
                json!({
                    "agentId": session_id,
                    "workspacePath": "/Users/zack/dev/cadence-cli",
                    "lastUsedModel": "claude-sonnet-4",
                    "createdAt": 1_775_083_355_225i64,
                    "lastUpdatedAt": 1_775_083_382_256i64,
                })
                .to_string()
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO blobs (key, value) VALUES (?1, ?2)",
            params![
                "message-1",
                json!({
                    "messages": [
                        {"role": "user", "content": "Investigate the outage", "createdAt": 1_775_083_355_225i64},
                        {"role": "assistant", "content": "Here is the outage analysis.", "createdAt": 1_775_083_382_256i64}
                    ]
                })
                .to_string()
            ],
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_cursor_log_dirs_collects_chat_sessions_and_agent_transcripts() {
        let home = TempDir::new().unwrap();

        let ws_root = app_config_dir_in("Cursor", home.path())
            .join("User")
            .join("workspaceStorage")
            .join("abc")
            .join("chatSessions");
        tokio::fs::create_dir_all(&ws_root).await.unwrap();

        let transcripts_dir = home
            .path()
            .join(".cursor")
            .join("projects")
            .join("Users-zack-dev-cadence-cli")
            .join("agent-transcripts")
            .join("conversation");
        tokio::fs::create_dir_all(&transcripts_dir).await.unwrap();
        tokio::fs::write(transcripts_dir.join("conversation.jsonl"), "{}\n")
            .await
            .unwrap();

        let dirs = log_dirs_in(home.path()).await;

        assert!(dirs.contains(&ws_root));
        assert!(dirs.iter().any(|dir| dir.ends_with("agent-transcripts")));
    }

    #[tokio::test]
    async fn test_cursor_log_dirs_ignore_non_session_project_dirs() {
        let home = TempDir::new().unwrap();
        let agent_tools_dir = home
            .path()
            .join(".cursor")
            .join("projects")
            .join("p1")
            .join("agent-tools");
        tokio::fs::create_dir_all(&agent_tools_dir).await.unwrap();
        tokio::fs::write(agent_tools_dir.join("tool.txt"), "content")
            .await
            .unwrap();

        let terminals_dir = home
            .path()
            .join(".cursor")
            .join("projects")
            .join("p1")
            .join("terminals");
        tokio::fs::create_dir_all(&terminals_dir).await.unwrap();
        tokio::fs::write(terminals_dir.join("1.txt"), "content")
            .await
            .unwrap();

        let dirs = log_dirs_in(home.path()).await;
        assert!(dirs.is_empty());
    }

    #[tokio::test]
    async fn test_cursor_discovers_agent_transcript_and_recovers_metadata() {
        let home = TempDir::new().unwrap();
        let repo_root = home
            .path()
            .join("Users")
            .join("zack")
            .join("dev")
            .join("cadence-cli");
        tokio::fs::create_dir_all(&repo_root).await.unwrap();

        let transcript = home
            .path()
            .join(".cursor")
            .join("projects")
            .join(encode_cursor_project_workspace_key(&repo_root))
            .join("agent-transcripts")
            .join("abc")
            .join("abc.jsonl");
        tokio::fs::create_dir_all(transcript.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(
            &transcript,
            "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"hi\"}]}}\n",
        )
        .await
        .unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let logs = discover_recent_in(home.path(), now, 3600).await;
        assert_eq!(logs.len(), 1);

        let content = match &logs[0].source {
            SessionSource::Inline { content, .. } => content,
            SessionSource::File(_) => panic!("expected inline transcript"),
        };
        let metadata = scanner::parse_session_metadata_str(content);
        assert_eq!(metadata.session_id.as_deref(), Some("abc"));
        assert_eq!(
            metadata.cwd.as_deref(),
            Some(repo_root.to_string_lossy().as_ref())
        );
    }

    #[tokio::test]
    async fn test_cursor_discovers_desktop_state_vscdb_sessions() {
        let home = TempDir::new().unwrap();
        let global_dir = app_config_dir_in("Cursor", home.path())
            .join("User")
            .join("globalStorage");
        tokio::fs::create_dir_all(&global_dir).await.unwrap();
        seed_global_cursor_session(&global_dir.join("state.vscdb"), "composer-1");

        let workspace_dir = app_config_dir_in("Cursor", home.path())
            .join("User")
            .join("workspaceStorage")
            .join("workspace-1");
        write_workspace(
            &workspace_dir,
            if cfg!(windows) {
                "file:///C:/cursor-test-workspace"
            } else {
                "file:///tmp/cursor-test-workspace"
            },
            "composer-1",
            1_775_083_382_256i64,
        )
        .await;

        let logs = discover_recent_in(home.path(), 1_775_083_400, 3600).await;
        assert_eq!(logs.len(), 1);
        let content = match &logs[0].source {
            SessionSource::Inline { content, .. } => content,
            SessionSource::File(_) => panic!("expected inline desktop log"),
        };
        let metadata = scanner::parse_session_metadata_str(content);
        assert_eq!(metadata.session_id.as_deref(), Some("composer-1"));
        assert_eq!(
            metadata.cwd.as_deref(),
            Some(if cfg!(windows) {
                "C:/cursor-test-workspace"
            } else {
                "/tmp/cursor-test-workspace"
            })
        );
        assert!(content.contains("Explain the architecture"));
        assert!(content.contains("Here is the architecture."));
    }

    #[test]
    fn test_cursor_dedupe_preserves_bubble_order() {
        let mut ids = vec![
            "bubble-2".to_string(),
            "bubble-10".to_string(),
            "bubble-2".to_string(),
            "bubble-1".to_string(),
        ];

        dedupe_preserving_order(&mut ids);

        assert_eq!(ids, vec!["bubble-2", "bubble-10", "bubble-1"]);
    }

    #[tokio::test]
    async fn test_cursor_discovers_store_db_sessions() {
        let home = TempDir::new().unwrap();
        let store_dir = home
            .path()
            .join(".cursor")
            .join("chats")
            .join("a")
            .join("b");
        tokio::fs::create_dir_all(&store_dir).await.unwrap();
        seed_cursor_store_db(&store_dir.join("store.db"), "store-session-1");

        let logs =
            discover_store_db_sessions(home.path(), current_unix_epoch_for_tests(), 3600).await;
        assert_eq!(logs.len(), 1);
        let content = match &logs[0].log.source {
            SessionSource::Inline { content, .. } => content,
            SessionSource::File(_) => panic!("expected inline store db session"),
        };
        let metadata = scanner::parse_session_metadata_str(content);
        assert_eq!(metadata.session_id.as_deref(), Some("store-session-1"));
        assert_eq!(metadata.cwd.as_deref(), Some("/Users/zack/dev/cadence-cli"));
        assert!(content.contains("Investigate the outage"));
        assert!(content.contains("Here is the outage analysis."));
    }

    #[tokio::test]
    async fn test_cursor_dedupes_duplicate_transcript_and_desktop_session_ids() {
        let home = TempDir::new().unwrap();
        let repo_root = PathBuf::from("/Users/zack/dev/cadence-cli");

        let global_dir = app_config_dir_in("Cursor", home.path())
            .join("User")
            .join("globalStorage");
        tokio::fs::create_dir_all(&global_dir).await.unwrap();
        seed_global_cursor_session(&global_dir.join("state.vscdb"), "shared-session");

        let workspace_dir = app_config_dir_in("Cursor", home.path())
            .join("User")
            .join("workspaceStorage")
            .join("workspace-1");
        write_workspace(
            &workspace_dir,
            &format!("file://{}", repo_root.display()),
            "shared-session",
            1_775_083_382_256i64,
        )
        .await;

        let encoded = encode_cursor_project_workspace_key(&repo_root);
        let transcript = home
            .path()
            .join(".cursor")
            .join("projects")
            .join(encoded)
            .join("agent-transcripts")
            .join("shared-session")
            .join("shared-session.jsonl");
        tokio::fs::create_dir_all(transcript.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(
            &transcript,
            "{\"role\":\"user\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"short transcript\"}]}}\n",
        )
        .await
        .unwrap();

        let logs = discover_recent_in(home.path(), 1_775_083_400, 3600).await;
        assert_eq!(logs.len(), 1);
        let content = match &logs[0].source {
            SessionSource::Inline { content, .. } => content,
            SessionSource::File(_) => panic!("expected inline session"),
        };
        assert!(content.contains("Explain the architecture"));
        assert!(!content.contains("short transcript"));
    }

    fn current_unix_epoch_for_tests() -> i64 {
        std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn test_encode_cursor_project_workspace_key_windows_drive_format() {
        let encoded =
            encode_cursor_project_workspace_key(Path::new(r"C:\Users\zack\dev\cadence-cli"));

        if cfg!(windows) {
            assert_eq!(encoded, "C--Users-zack-dev-cadence-cli");
        }
    }
}
