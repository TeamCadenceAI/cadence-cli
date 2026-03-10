//! Warp AI session discovery (SQLite).
//!
//! Warp stores agent sessions in a local SQLite database (`warp.sqlite`) rather
//! than JSONL log files. This module extracts `ai_queries` and `agent_tasks`
//! rows and normalizes them into Cadence-compatible conversation events.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use protobuf::CodedInputStream;
use protobuf::rt::WireType;
use rusqlite::{Connection, OpenFlags};
use serde_json::{Map, Value, json};

use crate::scanner::AgentType;

use super::{AgentExplorer, SessionLog, SessionSource, home_dir};

pub struct WarpExplorer;

#[async_trait]
impl AgentExplorer for WarpExplorer {
    async fn discover_recent(&self, now: i64, since_secs: i64) -> Vec<SessionLog> {
        let paths = warp_db_paths();
        let mut out = Vec::new();

        for path in paths {
            if !path.exists() {
                continue;
            }
            let path_clone = path.clone();
            let result =
                tokio::task::spawn_blocking(move || query_warp_db(&path_clone, now, since_secs))
                    .await;
            match result {
                Ok(logs) => out.extend(logs),
                Err(_) => continue,
            }
        }

        out
    }
}

fn warp_db_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(path) = std::env::var("WARP_DB_PATH") {
        paths.push(PathBuf::from(path));
        return paths;
    }

    let home = match home_dir() {
        Some(h) => h,
        None => return paths,
    };

    if cfg!(target_os = "macos") {
        let base = home
            .join("Library")
            .join("Group Containers")
            .join("2BBY89MBSN.dev.warp")
            .join("Library")
            .join("Application Support");
        for name in [
            "dev.warp.Warp-Stable",
            "dev.warp.Warp",
            "dev.warp.Warp-Preview",
        ] {
            paths.push(base.join(name).join("warp.sqlite"));
        }
    } else if cfg!(target_os = "windows") {
        if let Ok(appdata) = std::env::var("APPDATA") {
            paths.push(PathBuf::from(appdata).join("Warp").join("warp.sqlite"));
        }
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            paths.push(PathBuf::from(local).join("Warp").join("warp.sqlite"));
        }
    } else {
        paths.push(
            home.join(".local")
                .join("share")
                .join("warp")
                .join("warp.sqlite"),
        );
        paths.push(home.join(".config").join("warp").join("warp.sqlite"));
    }

    paths
}

fn query_warp_db(path: &Path, now: i64, since_secs: i64) -> Vec<SessionLog> {
    let mut out = Vec::new();
    let conn = match Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(conn) => conn,
        Err(_) => return out,
    };
    let _ = conn.busy_timeout(Duration::from_millis(200));

    if !table_exists(&conn, "ai_queries") {
        return out;
    }

    let cutoff = now - since_secs;
    let rows = fetch_ai_query_rows(&conn, cutoff);
    let tasks_by_conversation = fetch_agent_tasks_by_conversation(&conn, cutoff);
    if rows.is_empty() && tasks_by_conversation.is_empty() {
        return out;
    }

    let mut by_conversation: BTreeMap<String, Vec<AiQueryRow>> = BTreeMap::new();
    let mut unknown_idx = 0usize;
    for row in rows {
        let key = row
            .conversation_id
            .clone()
            .or_else(|| row.exchange_id.clone())
            .unwrap_or_else(|| {
                let key = format!("unknown-{unknown_idx}");
                unknown_idx += 1;
                key
            });
        by_conversation.entry(key).or_default().push(row);
    }
    for conversation_id in tasks_by_conversation.keys() {
        by_conversation.entry(conversation_id.clone()).or_default();
    }

    for (conversation_id, rows) in by_conversation {
        let mut max_start = 0i64;
        let mut conversation_cwd: Option<String> = None;
        let mut events = Vec::new();
        let mut ord = 0usize;
        let task_rows = tasks_by_conversation.get(&conversation_id);

        for row in &rows {
            max_start = max_start.max(row.start_ts);
            if conversation_cwd.is_none()
                && let Some(cwd) = row.working_directory.as_deref().map(str::trim)
                && !cwd.is_empty()
            {
                conversation_cwd = Some(cwd.to_string());
            }

            let prompt = row
                .input
                .as_deref()
                .and_then(extract_prompt_from_ai_input)
                .and_then(|p| sanitize_text(&p));

            if let Some(prompt) = prompt {
                let mut obj = base_event("user", &conversation_id, row.start_ts, "ai_queries");
                obj.insert("role".to_string(), Value::String("user".to_string()));
                obj.insert("content".to_string(), Value::String(prompt));
                if let Some(exchange_id) = row.exchange_id.as_deref() {
                    obj.insert(
                        "exchange_id".to_string(),
                        Value::String(exchange_id.to_string()),
                    );
                }
                if let Some(cwd) = row.working_directory.as_deref().and_then(non_empty_str) {
                    obj.insert("cwd".to_string(), Value::String(cwd.to_string()));
                }
                if let Some(status) = row.output_status.as_deref().and_then(clean_status) {
                    obj.insert("status".to_string(), Value::String(status));
                }
                events.push(EmittedEvent {
                    ts: row.start_ts,
                    source_priority: 0,
                    ordinal: ord,
                    value: Value::Object(obj),
                });
                ord += 1;
            }
        }

        if let Some(task_rows) = task_rows {
            for task in task_rows {
                max_start = max_start.max(task.last_modified_ts);
                let decoded = decode_warp_task(&task.task_blob);
                let normalized = normalize_task_events(
                    &conversation_id,
                    task,
                    decoded.as_ref(),
                    conversation_cwd.as_deref(),
                );
                for value in normalized {
                    let ts = value
                        .get("timestamp")
                        .and_then(Value::as_i64)
                        .unwrap_or(task.last_modified_ts);
                    events.push(EmittedEvent {
                        ts,
                        source_priority: 1,
                        ordinal: ord,
                        value,
                    });
                    ord += 1;
                }
            }
        }

        events.sort_by(|a, b| {
            a.ts.cmp(&b.ts)
                .then(a.source_priority.cmp(&b.source_priority))
                .then(a.ordinal.cmp(&b.ordinal))
        });

        let mut lines = Vec::new();
        let mut deduped = dedupe_adjacent(events.into_iter().map(|e| e.value).collect());

        if deduped.is_empty() {
            if let Some(first) = rows.first() {
                let mut obj =
                    base_event("warp_meta", &conversation_id, first.start_ts, "ai_queries");
                if let Some(exchange_id) = first.exchange_id.as_deref() {
                    obj.insert(
                        "exchange_id".to_string(),
                        Value::String(exchange_id.to_string()),
                    );
                }
                if let Some(cwd) = conversation_cwd.as_deref() {
                    obj.insert("cwd".to_string(), Value::String(cwd.to_string()));
                }
                if let Some(status) = first.output_status.as_deref().and_then(clean_status) {
                    obj.insert("status".to_string(), Value::String(status));
                }
                if let Some(model) = first.model_id.as_deref().and_then(non_empty_str) {
                    obj.insert("model_id".to_string(), Value::String(model.to_string()));
                }
                if let Some(model) = first.planning_model_id.as_deref().and_then(non_empty_str) {
                    obj.insert(
                        "planning_model_id".to_string(),
                        Value::String(model.to_string()),
                    );
                }
                if let Some(model) = first.coding_model_id.as_deref().and_then(non_empty_str) {
                    obj.insert(
                        "coding_model_id".to_string(),
                        Value::String(model.to_string()),
                    );
                }
                deduped.push(Value::Object(obj));
            } else if let Some(first_task) = task_rows.and_then(|rows| rows.first()) {
                let mut obj = base_event(
                    "warp_meta",
                    &conversation_id,
                    first_task.last_modified_ts,
                    "agent_tasks",
                );
                obj.insert(
                    "task_id".to_string(),
                    Value::String(first_task.task_id.clone()),
                );
                if let Some(cwd) = conversation_cwd.as_deref() {
                    obj.insert("cwd".to_string(), Value::String(cwd.to_string()));
                }
                deduped.push(Value::Object(obj));
            }
        }

        if deduped.is_empty() {
            continue;
        }

        for value in deduped {
            if let Ok(line) = serde_json::to_string(&value) {
                lines.push(line);
            }
        }

        out.push(SessionLog {
            agent_type: AgentType::Warp,
            source: SessionSource::Inline {
                label: format!("warp:{conversation_id}"),
                content: lines.join("\n"),
            },
            updated_at: Some(max_start),
        });
    }

    out
}

fn base_event(
    event_type: &str,
    conversation_id: &str,
    timestamp: i64,
    source: &str,
) -> Map<String, Value> {
    let mut obj = Map::new();
    obj.insert("type".to_string(), Value::String(event_type.to_string()));
    obj.insert(
        "session_id".to_string(),
        Value::String(conversation_id.to_string()),
    );
    obj.insert(
        "conversation_id".to_string(),
        Value::String(conversation_id.to_string()),
    );
    obj.insert("timestamp".to_string(), Value::Number(timestamp.into()));
    obj.insert("source".to_string(), Value::String(source.to_string()));
    obj
}

fn normalize_task_events(
    conversation_id: &str,
    task: &AgentTaskRow,
    decoded: Option<&WarpDecodedTask>,
    cwd: Option<&str>,
) -> Vec<Value> {
    let Some(decoded) = decoded else {
        return Vec::new();
    };

    let mut by_envelope: BTreeMap<usize, EnvelopeAccumulator> = BTreeMap::new();

    for node in &decoded.flat_nodes {
        let Some(envelope_idx) = node.envelope_index else {
            continue;
        };

        let entry = by_envelope
            .entry(envelope_idx)
            .or_insert_with(|| EnvelopeAccumulator::new(envelope_idx));

        if entry.timestamp.is_none() && node.field_path == "5.14.1" {
            entry.timestamp = node.timestamp_candidate;
        }

        let Some(text_raw) = node.string_value.as_deref() else {
            continue;
        };
        let Some(text) = sanitize_text(text_raw) else {
            continue;
        };

        match WarpSchemaProfile::classify(&node.field_path) {
            WarpSemanticRole::UserText => entry.user_texts.push((text, node.field_path.clone())),
            WarpSemanticRole::AssistantText => {
                entry.assistant_texts.push((text, node.field_path.clone()))
            }
            WarpSemanticRole::ToolCallName => {
                entry.tool_call_name = Some((text, node.field_path.clone()))
            }
            WarpSemanticRole::ToolCallArgs => {
                entry.tool_call_args.push((text, node.field_path.clone()))
            }
            WarpSemanticRole::ToolResultName => {
                entry.tool_result_name = Some((text, node.field_path.clone()))
            }
            WarpSemanticRole::ToolResultOutput => entry
                .tool_result_outputs
                .push((text, node.field_path.clone())),
            WarpSemanticRole::ToolResultArgsEcho => {
                if entry.tool_call_args.is_empty() {
                    entry.tool_call_args.push((text, node.field_path.clone()));
                }
            }
            WarpSemanticRole::Meta => {
                if is_high_signal_meta(&text) {
                    entry.meta.push((text, node.field_path.clone()));
                }
            }
            WarpSemanticRole::Ignore => {}
        }
    }

    let mut out = Vec::new();
    for (_, env) in by_envelope {
        let ts = env.timestamp.unwrap_or(task.last_modified_ts);
        let mut envelope_events = Vec::new();

        for (text, path) in dedupe_text_pairs(env.user_texts) {
            let mut obj = base_event("user", conversation_id, ts, "agent_tasks");
            obj.insert("role".to_string(), Value::String("user".to_string()));
            obj.insert("content".to_string(), Value::String(text));
            obj.insert("task_id".to_string(), Value::String(task.task_id.clone()));
            obj.insert("warp_raw_field_path".to_string(), Value::String(path));
            if let Some(cwd) = cwd {
                obj.insert("cwd".to_string(), Value::String(cwd.to_string()));
            }
            envelope_events.push(Value::Object(obj));
        }

        for (text, path) in dedupe_text_pairs(env.assistant_texts) {
            let mut obj = base_event("assistant", conversation_id, ts, "agent_tasks");
            obj.insert("role".to_string(), Value::String("assistant".to_string()));
            obj.insert("content".to_string(), Value::String(text));
            obj.insert("task_id".to_string(), Value::String(task.task_id.clone()));
            obj.insert("warp_raw_field_path".to_string(), Value::String(path));
            if let Some(cwd) = cwd {
                obj.insert("cwd".to_string(), Value::String(cwd.to_string()));
            }
            envelope_events.push(Value::Object(obj));
        }

        if env.tool_call_name.is_some() || !env.tool_call_args.is_empty() {
            let mut obj = base_event("tool_call", conversation_id, ts, "agent_tasks");
            let tool_call_name_path = env.tool_call_name.as_ref().map(|(_, p)| p.clone());
            let tool_call_args_path = env.tool_call_args.first().map(|(_, p)| p.clone());
            let tool_name = env
                .tool_call_name
                .as_ref()
                .map(|(s, _)| s.as_str())
                .or_else(|| env.tool_result_name.as_ref().map(|(s, _)| s.as_str()))
                .unwrap_or("warp_tool");
            obj.insert(
                "tool_name".to_string(),
                Value::String(tool_name.to_string()),
            );

            let args: Vec<String> = dedupe_text_pairs(env.tool_call_args)
                .into_iter()
                .map(|(s, _)| s)
                .collect();
            if let Some(arg) = args.first() {
                obj.insert("tool_args".to_string(), json!({ "command": arg }));
            }
            if args.len() > 1 {
                obj.insert(
                    "tool_args".to_string(),
                    Value::Array(args.into_iter().map(Value::String).collect()),
                );
            }

            if let Some(path) = tool_call_name_path {
                obj.insert("warp_raw_field_path".to_string(), Value::String(path));
            } else if let Some(path) = tool_call_args_path {
                obj.insert("warp_raw_field_path".to_string(), Value::String(path));
            }
            obj.insert("task_id".to_string(), Value::String(task.task_id.clone()));
            if let Some(cwd) = cwd {
                obj.insert("cwd".to_string(), Value::String(cwd.to_string()));
            }
            envelope_events.push(Value::Object(obj));
        }

        if !env.tool_result_outputs.is_empty() {
            let mut obj = base_event("tool_result", conversation_id, ts, "agent_tasks");
            let tool_result_name_path = env.tool_result_name.as_ref().map(|(_, p)| p.clone());
            let tool_name = env
                .tool_result_name
                .as_ref()
                .map(|(s, _)| s.as_str())
                .or_else(|| env.tool_call_name.as_ref().map(|(s, _)| s.as_str()))
                .unwrap_or("warp_tool");
            obj.insert(
                "tool_name".to_string(),
                Value::String(tool_name.to_string()),
            );

            let outputs: Vec<String> = dedupe_text_pairs(env.tool_result_outputs)
                .into_iter()
                .map(|(s, _)| s)
                .collect();
            let output_text = outputs.join("\n\n");
            if !output_text.trim().is_empty() {
                obj.insert("tool_output".to_string(), Value::String(output_text));
            }
            if let Some(path) = tool_result_name_path {
                obj.insert("warp_raw_field_path".to_string(), Value::String(path));
            }
            obj.insert("task_id".to_string(), Value::String(task.task_id.clone()));
            if let Some(cwd) = cwd {
                obj.insert("cwd".to_string(), Value::String(cwd.to_string()));
            }
            envelope_events.push(Value::Object(obj));
        }

        if envelope_events.is_empty() {
            for (text, path) in dedupe_text_pairs(env.meta) {
                let mut obj = base_event("warp_meta", conversation_id, ts, "agent_tasks");
                obj.insert("content".to_string(), Value::String(text));
                obj.insert("warp_raw_field_path".to_string(), Value::String(path));
                obj.insert("task_id".to_string(), Value::String(task.task_id.clone()));
                if let Some(cwd) = cwd {
                    obj.insert("cwd".to_string(), Value::String(cwd.to_string()));
                }
                envelope_events.push(Value::Object(obj));
            }
        }

        out.extend(envelope_events);
    }

    out
}

fn dedupe_text_pairs(items: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (text, path) in items {
        if out
            .last()
            .map(|(last, _): &(String, String)| last == &text)
            .unwrap_or(false)
        {
            continue;
        }
        out.push((text, path));
    }
    out
}

fn dedupe_adjacent(events: Vec<Value>) -> Vec<Value> {
    let mut out = Vec::new();
    for event in events {
        if let Some(prev) = out.last()
            && should_dedupe(prev, &event)
        {
            continue;
        }
        out.push(event);
    }
    out
}

fn should_dedupe(a: &Value, b: &Value) -> bool {
    let fingerprint = |value: &Value| {
        format!(
            "{}|{}|{}|{}|{}|{}",
            value
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            value
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            value
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            value
                .get("tool_name")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            value
                .get("tool_output")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            value
                .get("tool_args")
                .map(|v| v.to_string())
                .unwrap_or_default(),
        )
    };

    if fingerprint(a) != fingerprint(b) {
        return false;
    }

    let at = a
        .get("timestamp")
        .and_then(Value::as_i64)
        .unwrap_or(i64::MIN);
    let bt = b
        .get("timestamp")
        .and_then(Value::as_i64)
        .unwrap_or(i64::MAX);
    (at - bt).abs() <= 1
}

fn clean_status(status: &str) -> Option<String> {
    let normalized = status.trim().trim_matches('"').trim();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.to_string())
    }
}

fn non_empty_str(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn is_high_signal_meta(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    text.len() <= 280
        && (lower.contains("error")
            || lower.contains("failed")
            || lower.contains("succeeded")
            || lower.contains("completed"))
}

fn extract_prompt_from_ai_input(raw: &str) -> Option<String> {
    let value = serde_json::from_str::<Value>(raw).ok()?;

    if let Some(prompt) = extract_prompt_from_value(&value) {
        return Some(prompt);
    }

    if let Value::Array(items) = value {
        for item in items {
            if let Some(query) = item.get("Query")
                && let Some(text) = query.get("text").and_then(Value::as_str)
                && !text.trim().is_empty()
            {
                return Some(text.to_string());
            }
        }
    }

    None
}

fn extract_prompt_from_value(value: &Value) -> Option<String> {
    let obj = value.as_object()?;
    for key in [
        "prompt",
        "query",
        "user_query",
        "userQuery",
        "request",
        "text",
    ] {
        if let Some(s) = obj.get(key).and_then(Value::as_str)
            && !s.trim().is_empty()
        {
            return Some(s.to_string());
        }
    }
    None
}

fn sanitize_text(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if looks_like_uuid(trimmed) || looks_like_base64(trimmed) {
        return None;
    }

    let normalized = trimmed
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string();

    if normalized.is_empty() {
        return None;
    }
    if normalized.chars().count() < 3 {
        return None;
    }
    if !normalized.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }

    let mut clipped = normalized.chars().take(10_000).collect::<String>();
    if normalized.chars().count() > 10_000 {
        clipped.push_str("...");
    }
    Some(clipped)
}

fn looks_like_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    for (i, c) in s.chars().enumerate() {
        if [8, 13, 18, 23].contains(&i) {
            if c != '-' {
                return false;
            }
        } else if !c.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn looks_like_base64(s: &str) -> bool {
    if s.len() < 24 || s.contains(' ') || s.contains('\n') {
        return false;
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return false;
    }
    s.ends_with('=') || s.ends_with("==")
}

fn table_exists(conn: &Connection, table: &str) -> bool {
    conn.query_row(
        "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
        [table],
        |row| row.get::<_, String>(0),
    )
    .ok()
    .is_some()
}

fn fetch_ai_query_rows(conn: &Connection, cutoff: i64) -> Vec<AiQueryRow> {
    let start_ts_expr = normalized_start_ts_sql("start_ts");
    let query_full = format!(
        "SELECT exchange_id, conversation_id, {start_ts_expr} AS start_ts_epoch, input, working_directory, output_status, model_id, planning_model_id, coding_model_id
         FROM ai_queries
         WHERE {start_ts_expr} >= ?
         ORDER BY conversation_id, start_ts_epoch"
    );
    let query_fallback = format!(
        "SELECT exchange_id, conversation_id, {start_ts_expr} AS start_ts_epoch, input, working_directory, output_status
         FROM ai_queries
         WHERE {start_ts_expr} >= ?
         ORDER BY conversation_id, start_ts_epoch"
    );

    if let Ok(mut stmt) = conn.prepare(&query_full)
        && let Ok(rows) = stmt.query_map([cutoff], |row| {
            Ok(AiQueryRow {
                exchange_id: row.get(0)?,
                conversation_id: row.get(1)?,
                start_ts: row.get(2)?,
                input: row.get(3)?,
                working_directory: row.get(4)?,
                output_status: row.get(5)?,
                model_id: row.get(6)?,
                planning_model_id: row.get(7)?,
                coding_model_id: row.get(8)?,
            })
        })
    {
        return rows.flatten().collect();
    }

    let mut out = Vec::new();
    let Ok(mut stmt) = conn.prepare(&query_fallback) else {
        return out;
    };
    let rows = stmt.query_map([cutoff], |row| {
        Ok(AiQueryRow {
            exchange_id: row.get(0)?,
            conversation_id: row.get(1)?,
            start_ts: row.get(2)?,
            input: row.get(3)?,
            working_directory: row.get(4)?,
            output_status: row.get(5)?,
            model_id: None,
            planning_model_id: None,
            coding_model_id: None,
        })
    });
    let Ok(rows) = rows else {
        return out;
    };
    out.extend(rows.flatten());
    out
}

fn normalized_start_ts_sql(column: &str) -> String {
    format!(
        "CASE
            WHEN typeof({column}) IN ('integer', 'real') THEN
                CASE
                    WHEN CAST({column} AS INTEGER) > 100000000000 THEN CAST(CAST({column} AS INTEGER) / 1000 AS INTEGER)
                    ELSE CAST({column} AS INTEGER)
                END
            ELSE CAST(unixepoch({column}) AS INTEGER)
        END"
    )
}

fn fetch_agent_tasks_by_conversation(
    conn: &Connection,
    cutoff: i64,
) -> BTreeMap<String, Vec<AgentTaskRow>> {
    let mut out: BTreeMap<String, Vec<AgentTaskRow>> = BTreeMap::new();
    if !table_exists(conn, "agent_tasks") {
        return out;
    }

    let ts_expr = normalized_start_ts_sql("last_modified_at");
    let query = format!(
        "SELECT conversation_id, task_id, {ts_expr} AS ts_epoch, task
         FROM agent_tasks
         WHERE {ts_expr} >= ?
         ORDER BY conversation_id, ts_epoch"
    );
    let Ok(mut stmt) = conn.prepare(&query) else {
        return out;
    };
    let Ok(rows) = stmt.query_map([cutoff], |row| {
        Ok(AgentTaskRow {
            conversation_id: row.get(0)?,
            task_id: row.get(1)?,
            last_modified_ts: row.get(2)?,
            task_blob: row.get(3)?,
        })
    }) else {
        return out;
    };

    for row in rows.flatten() {
        out.entry(row.conversation_id.clone())
            .or_default()
            .push(row);
    }
    out
}

#[derive(Debug, Clone)]
struct EmittedEvent {
    ts: i64,
    source_priority: i32,
    ordinal: usize,
    value: Value,
}

#[derive(Debug, Clone)]
struct AiQueryRow {
    exchange_id: Option<String>,
    conversation_id: Option<String>,
    start_ts: i64,
    input: Option<String>,
    working_directory: Option<String>,
    output_status: Option<String>,
    model_id: Option<String>,
    planning_model_id: Option<String>,
    coding_model_id: Option<String>,
}

#[derive(Debug, Clone)]
struct AgentTaskRow {
    conversation_id: String,
    task_id: String,
    last_modified_ts: i64,
    task_blob: Vec<u8>,
}

#[derive(Debug, Clone)]
struct WarpDecodedTask {
    flat_nodes: Vec<WarpFlatNode>,
}

#[derive(Debug, Clone)]
struct WarpDecodedNode {
    field_path: String,
    field_path_indexed: String,
    wire_type: u8,
    timestamp_candidate: Option<i64>,
    string_value: Option<String>,
    bytes_value: Option<Vec<u8>>,
    nested_children: Vec<WarpDecodedNode>,
}

#[derive(Debug, Clone)]
struct WarpFlatNode {
    field_path: String,
    timestamp_candidate: Option<i64>,
    string_value: Option<String>,
    envelope_index: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WarpSemanticRole {
    UserText,
    AssistantText,
    ToolCallName,
    ToolCallArgs,
    ToolResultName,
    ToolResultOutput,
    ToolResultArgsEcho,
    Meta,
    Ignore,
}

struct WarpSchemaProfile;

impl WarpSchemaProfile {
    fn classify(field_path: &str) -> WarpSemanticRole {
        match field_path {
            "5.2.1" => WarpSemanticRole::UserText,
            "5.3.1" | "5.15.1" => WarpSemanticRole::AssistantText,
            "5.4.1" => WarpSemanticRole::ToolCallName,
            "5.4.2.1" => WarpSemanticRole::ToolCallArgs,
            "5.5.1" => WarpSemanticRole::ToolResultName,
            "5.5.2.3" => WarpSemanticRole::ToolResultArgsEcho,
            "5.5.2.5.1" => WarpSemanticRole::ToolResultOutput,
            "5.2.2.1.1" | "5.5.11.1.1" => WarpSemanticRole::Ignore,
            "5.2.2.10.2.2" => WarpSemanticRole::Ignore,
            _ => {
                if field_path.starts_with("5.14.") {
                    WarpSemanticRole::Ignore
                } else {
                    WarpSemanticRole::Meta
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct EnvelopeAccumulator {
    timestamp: Option<i64>,
    user_texts: Vec<(String, String)>,
    assistant_texts: Vec<(String, String)>,
    tool_call_name: Option<(String, String)>,
    tool_call_args: Vec<(String, String)>,
    tool_result_name: Option<(String, String)>,
    tool_result_outputs: Vec<(String, String)>,
    meta: Vec<(String, String)>,
}

impl EnvelopeAccumulator {
    fn new(_envelope_index: usize) -> Self {
        Self {
            timestamp: None,
            user_texts: Vec::new(),
            assistant_texts: Vec::new(),
            tool_call_name: None,
            tool_call_args: Vec::new(),
            tool_result_name: None,
            tool_result_outputs: Vec::new(),
            meta: Vec::new(),
        }
    }
}

fn decode_warp_task(blob: &[u8]) -> Option<WarpDecodedTask> {
    let mut node_count = 0usize;
    let nodes = decode_message_protobuf(blob, "", "", 0, &mut node_count)
        .or_else(|_| decode_message_manual(blob, "", "", 0, &mut node_count))
        .ok()?;
    if nodes.is_empty() {
        return None;
    }

    let mut flat_nodes = Vec::new();
    flatten_nodes(&nodes, &mut flat_nodes);
    Some(WarpDecodedTask { flat_nodes })
}

fn decode_message_protobuf(
    bytes: &[u8],
    parent_path: &str,
    parent_path_indexed: &str,
    depth: usize,
    node_count: &mut usize,
) -> Result<Vec<WarpDecodedNode>, ()> {
    const MAX_DEPTH: usize = 20;
    const MAX_NODES: usize = 50_000;

    if depth > MAX_DEPTH {
        return Err(());
    }

    let mut out = Vec::new();
    let mut field_seen: HashMap<u64, usize> = HashMap::new();
    let mut cis = CodedInputStream::from_bytes(bytes);

    while !cis.eof().map_err(|_| ())? {
        if *node_count >= MAX_NODES {
            return Err(());
        }

        let tag = cis.read_raw_tag_or_eof().map_err(|_| ())?;
        let Some(tag) = tag else {
            break;
        };
        let field_num = (tag >> 3) as u64;
        let wire_type = WireType::new(tag & 0x07).ok_or(())?;

        let seen_count = field_seen.entry(field_num).or_insert(0usize);
        let current_index = *seen_count;
        *seen_count += 1;

        let field_path = if parent_path.is_empty() {
            field_num.to_string()
        } else {
            format!("{parent_path}.{field_num}")
        };
        let field_path_indexed = if parent_path_indexed.is_empty() {
            format!("{field_num}#{current_index}")
        } else {
            format!("{parent_path_indexed}.{field_num}#{current_index}")
        };

        let mut timestamp_candidate = None;
        let mut string_value = None;
        let mut bytes_value = None;
        let mut nested_children = Vec::new();

        match wire_type {
            WireType::Varint => {
                let value = cis.read_raw_varint64().map_err(|_| ())?;
                timestamp_candidate = normalize_epoch_candidate(value);
            }
            WireType::Fixed64 => {
                let value = cis.read_fixed64().map_err(|_| ())?;
                bytes_value = Some(value.to_le_bytes().to_vec());
            }
            WireType::LengthDelimited => {
                let payload = cis.read_bytes().map_err(|_| ())?;
                if let Ok(s) = std::str::from_utf8(&payload) {
                    if !s.trim().is_empty() {
                        string_value = Some(s.to_string());
                    }
                } else if payload.len() <= 4096 {
                    bytes_value = Some(payload.to_vec());
                }
                if let Ok(children) = decode_message_protobuf(
                    &payload,
                    &field_path,
                    &field_path_indexed,
                    depth + 1,
                    node_count,
                ) && !children.is_empty()
                {
                    nested_children = children;
                }
            }
            WireType::Fixed32 => {
                let value = cis.read_fixed32().map_err(|_| ())?;
                bytes_value = Some(value.to_le_bytes().to_vec());
            }
            _ => {
                cis.skip_field(wire_type).map_err(|_| ())?;
            }
        }

        out.push(WarpDecodedNode {
            field_path,
            field_path_indexed,
            wire_type: wire_type as u8,
            timestamp_candidate,
            string_value,
            bytes_value,
            nested_children,
        });
        *node_count += 1;
    }

    Ok(out)
}

fn decode_message_manual(
    bytes: &[u8],
    parent_path: &str,
    parent_path_indexed: &str,
    depth: usize,
    node_count: &mut usize,
) -> Result<Vec<WarpDecodedNode>, ()> {
    const MAX_DEPTH: usize = 20;
    const MAX_NODES: usize = 50_000;

    if depth > MAX_DEPTH {
        return Err(());
    }

    let mut out = Vec::new();
    let mut offset = 0usize;
    let mut field_seen: HashMap<u64, usize> = HashMap::new();

    while offset < bytes.len() {
        if *node_count >= MAX_NODES {
            return Err(());
        }

        let (key, key_len) = decode_varint(&bytes[offset..]).ok_or(())?;
        offset += key_len;

        let field_num = key >> 3;
        let wire_type = (key & 0x07) as u8;

        let seen_count = field_seen.entry(field_num).or_insert(0usize);
        let current_index = *seen_count;
        *seen_count += 1;

        let field_path = if parent_path.is_empty() {
            field_num.to_string()
        } else {
            format!("{parent_path}.{field_num}")
        };
        let field_path_indexed = if parent_path_indexed.is_empty() {
            format!("{field_num}#{current_index}")
        } else {
            format!("{parent_path_indexed}.{field_num}#{current_index}")
        };

        let mut timestamp_candidate = None;
        let mut string_value = None;
        let mut bytes_value = None;
        let mut nested_children = Vec::new();

        match wire_type {
            0 => {
                let (value, consumed) = decode_varint(&bytes[offset..]).ok_or(())?;
                offset += consumed;
                timestamp_candidate = normalize_epoch_candidate(value);
            }
            1 => {
                if offset + 8 > bytes.len() {
                    return Err(());
                }
                bytes_value = Some(bytes[offset..offset + 8].to_vec());
                offset += 8;
            }
            2 => {
                let (len, consumed_len) = decode_varint(&bytes[offset..]).ok_or(())?;
                offset += consumed_len;
                let len = len as usize;
                if offset + len > bytes.len() {
                    return Err(());
                }
                let payload = &bytes[offset..offset + len];
                offset += len;

                if let Ok(s) = std::str::from_utf8(payload) {
                    let s = s.to_string();
                    if !s.trim().is_empty() {
                        string_value = Some(s);
                    }
                } else if payload.len() <= 4096 {
                    bytes_value = Some(payload.to_vec());
                }

                if let Ok(children) = decode_message_manual(
                    payload,
                    &field_path,
                    &field_path_indexed,
                    depth + 1,
                    node_count,
                ) && !children.is_empty()
                {
                    nested_children = children;
                }
            }
            5 => {
                if offset + 4 > bytes.len() {
                    return Err(());
                }
                bytes_value = Some(bytes[offset..offset + 4].to_vec());
                offset += 4;
            }
            _ => return Err(()),
        }

        out.push(WarpDecodedNode {
            field_path,
            field_path_indexed,
            wire_type,
            timestamp_candidate,
            string_value,
            bytes_value,
            nested_children,
        });
        *node_count += 1;
    }

    Ok(out)
}

fn normalize_epoch_candidate(value: u64) -> Option<i64> {
    let v = value as i64;
    if (1_000_000_000..=5_000_000_000).contains(&v) {
        return Some(v);
    }
    if (1_000_000_000_000..=5_000_000_000_000).contains(&v) {
        return Some(v / 1000);
    }
    None
}

fn flatten_nodes(nodes: &[WarpDecodedNode], out: &mut Vec<WarpFlatNode>) {
    for node in nodes {
        let _ = node.wire_type;
        let _ = node.bytes_value.as_ref().map(|b| b.len());
        out.push(WarpFlatNode {
            field_path: node.field_path.clone(),
            timestamp_candidate: node.timestamp_candidate,
            string_value: node.string_value.clone(),
            envelope_index: parse_envelope_index(&node.field_path_indexed),
        });
        if !node.nested_children.is_empty() {
            flatten_nodes(&node.nested_children, out);
        }
    }
}

fn parse_envelope_index(path_indexed: &str) -> Option<usize> {
    let (first, _) = path_indexed.split_once('.').unwrap_or((path_indexed, ""));
    if !first.starts_with("5#") {
        return None;
    }
    first[2..].parse::<usize>().ok()
}

fn decode_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (i, &b) in bytes.iter().enumerate() {
        let part = (b & 0x7f) as u64;
        value |= part << shift;
        if b & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner;
    use serial_test::serial;
    use tempfile::TempDir;

    fn create_db(path: &Path) -> Connection {
        let conn = Connection::open(path).expect("open");
        conn.execute_batch(
            "CREATE TABLE ai_queries (
                exchange_id TEXT,
                conversation_id TEXT,
                start_ts INTEGER,
                input TEXT,
                working_directory TEXT,
                output_status TEXT,
                model_id TEXT,
                planning_model_id TEXT,
                coding_model_id TEXT
            );
            CREATE TABLE agent_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                task BLOB NOT NULL,
                last_modified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );",
        )
        .expect("create");
        conn
    }

    fn pb_varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    fn pb_key(field: u64, wire: u8) -> Vec<u8> {
        pb_varint((field << 3) | wire as u64)
    }

    fn pb_len(field: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = pb_key(field, 2);
        out.extend(pb_varint(payload.len() as u64));
        out.extend(payload);
        out
    }

    fn pb_str(field: u64, text: &str) -> Vec<u8> {
        pb_len(field, text.as_bytes())
    }

    fn pb_u64(field: u64, value: u64) -> Vec<u8> {
        let mut out = pb_key(field, 0);
        out.extend(pb_varint(value));
        out
    }

    fn build_task_with_user_assistant_and_tool() -> Vec<u8> {
        let event_user = {
            let mut m = Vec::new();
            m.extend(pb_len(2, &pb_str(1, "Review current changes")));
            m.extend(pb_len(14, &pb_u64(1, 1_772_582_530)));
            m
        };
        let event_assistant = {
            let mut m = Vec::new();
            m.extend(pb_len(15, &pb_str(1, "I'll inspect diffs and summarize.")));
            m.extend(pb_len(14, &pb_u64(1, 1_772_582_535)));
            m
        };
        let event_call = {
            let mut call = Vec::new();
            call.extend(pb_str(1, "Bash"));
            call.extend(pb_len(2, &pb_str(1, "git --no-pager diff --stat HEAD")));

            let mut m = Vec::new();
            m.extend(pb_len(4, &call));
            m.extend(pb_len(14, &pb_u64(1, 1_772_582_540)));
            m
        };
        let event_result = {
            let mut result_payload = Vec::new();
            result_payload.extend(pb_len(5, &pb_str(1, "[main abcdef0] fix\n 1 file changed")));

            let mut result_msg = Vec::new();
            result_msg.extend(pb_str(1, "Bash"));
            result_msg.extend(pb_len(2, &result_payload));

            let mut m = Vec::new();
            m.extend(pb_len(5, &result_msg));
            m.extend(pb_len(14, &pb_u64(1, 1_772_582_545)));
            m
        };

        let mut root = Vec::new();
        root.extend(pb_str(1, "task-root"));
        root.extend(pb_len(5, &event_user));
        root.extend(pb_len(5, &event_assistant));
        root.extend(pb_len(5, &event_call));
        root.extend(pb_len(5, &event_result));
        root
    }

    #[tokio::test]
    #[serial]
    async fn warp_groups_by_conversation_id() {
        let tmp = TempDir::new().expect("tmp");
        let db_path = tmp.path().join("warp.sqlite");
        let conn = create_db(&db_path);
        conn.execute(
            "INSERT INTO ai_queries (exchange_id, conversation_id, start_ts, input, working_directory, output_status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                "ex1",
                "conv-1",
                1_700_000_000i64,
                r#"{"prompt":"hi"}"#,
                "/tmp/repo",
                "Succeeded",
            ),
        )
        .expect("insert");
        conn.execute(
            "INSERT INTO ai_queries (exchange_id, conversation_id, start_ts, input, working_directory, output_status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                "ex2",
                "conv-1",
                1_700_000_100i64,
                r#"{"prompt":"there"}"#,
                "/tmp/repo",
                "Succeeded",
            ),
        )
        .expect("insert");

        unsafe {
            std::env::set_var("WARP_DB_PATH", &db_path);
        }
        let logs = WarpExplorer.discover_recent(1_700_000_200, 1_000).await;
        unsafe {
            std::env::remove_var("WARP_DB_PATH");
        }

        assert_eq!(logs.len(), 1);
        let content = match &logs[0].source {
            SessionSource::Inline { content, .. } => content,
            _ => panic!("expected inline"),
        };
        assert!(content.contains("\"type\":\"user\""));
    }

    #[tokio::test]
    #[serial]
    async fn warp_missing_working_directory_has_no_cwd() {
        let tmp = TempDir::new().expect("tmp");
        let db_path = tmp.path().join("warp.sqlite");
        let conn = create_db(&db_path);
        conn.execute(
            "INSERT INTO ai_queries (exchange_id, conversation_id, start_ts, input, output_status)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                "ex1",
                "conv-2",
                1_700_000_000i64,
                r#"{"prompt":"hi"}"#,
                "Succeeded",
            ),
        )
        .expect("insert");

        unsafe {
            std::env::set_var("WARP_DB_PATH", &db_path);
        }
        let logs = WarpExplorer.discover_recent(1_700_000_200, 1_000).await;
        unsafe {
            std::env::remove_var("WARP_DB_PATH");
        }

        let log = logs.first().expect("log");
        let content = match &log.source {
            SessionSource::Inline { content, .. } => content,
            _ => panic!("expected inline"),
        };
        let metadata = scanner::parse_session_metadata_str(content);
        assert!(metadata.cwd.is_none());
    }

    #[tokio::test]
    #[serial]
    async fn warp_ms_timestamps_respected() {
        let tmp = TempDir::new().expect("tmp");
        let db_path = tmp.path().join("warp.sqlite");
        let conn = create_db(&db_path);
        conn.execute(
            "INSERT INTO ai_queries (exchange_id, conversation_id, start_ts, input, output_status)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                "ex1",
                "conv-3",
                1_700_000_000_000i64,
                r#"{"prompt":"hi"}"#,
                "Succeeded",
            ),
        )
        .expect("insert");

        unsafe {
            std::env::set_var("WARP_DB_PATH", &db_path);
        }
        let logs = WarpExplorer.discover_recent(1_700_000_200, 1_000).await;
        unsafe {
            std::env::remove_var("WARP_DB_PATH");
        }

        let log = logs.first().expect("log");
        assert_eq!(log.updated_at, Some(1_700_000_000));
    }

    #[tokio::test]
    #[serial]
    async fn warp_text_datetime_timestamps_respected() {
        let tmp = TempDir::new().expect("tmp");
        let db_path = tmp.path().join("warp.sqlite");
        let conn = create_db(&db_path);
        conn.execute(
            "INSERT INTO ai_queries (exchange_id, conversation_id, start_ts, input, output_status)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                "ex1",
                "conv-text",
                "2026-03-04 00:04:41.054251",
                r#"{"prompt":"hi"}"#,
                "Succeeded",
            ),
        )
        .expect("insert");

        unsafe {
            std::env::set_var("WARP_DB_PATH", &db_path);
        }
        let logs = WarpExplorer.discover_recent(1_772_583_000, 1_000).await;
        unsafe {
            std::env::remove_var("WARP_DB_PATH");
        }

        let log = logs.first().expect("log");
        assert_eq!(log.updated_at, Some(1_772_582_681));
    }

    #[tokio::test]
    #[serial]
    async fn warp_missing_table_returns_empty() {
        let tmp = TempDir::new().expect("tmp");
        let db_path = tmp.path().join("warp.sqlite");
        let _conn = Connection::open(&db_path).expect("open");

        unsafe {
            std::env::set_var("WARP_DB_PATH", &db_path);
        }
        let logs = WarpExplorer.discover_recent(1_700_000_200, 1_000).await;
        unsafe {
            std::env::remove_var("WARP_DB_PATH");
        }

        assert!(logs.is_empty());
    }

    #[tokio::test]
    #[serial]
    async fn warp_discovers_task_only_conversation() {
        let tmp = TempDir::new().expect("tmp");
        let db_path = tmp.path().join("warp.sqlite");
        let conn = create_db(&db_path);

        let blob = build_task_with_user_assistant_and_tool();
        conn.execute(
            "INSERT INTO agent_tasks (conversation_id, task_id, task, last_modified_at)
             VALUES (?1, ?2, ?3, ?4)",
            ("conv-task-only", "task-1", blob, "2026-03-04 00:04:50"),
        )
        .expect("insert task");

        unsafe {
            std::env::set_var("WARP_DB_PATH", &db_path);
        }
        let logs = WarpExplorer.discover_recent(1_772_583_000, 10_000).await;
        unsafe {
            std::env::remove_var("WARP_DB_PATH");
        }

        assert_eq!(logs.len(), 1);
        let log = logs.first().expect("log");
        assert_eq!(log.updated_at, Some(1_772_582_690));
        let content = match &log.source {
            SessionSource::Inline { content, .. } => content,
            _ => panic!("expected inline"),
        };
        assert!(content.contains("\"conversation_id\":\"conv-task-only\""));
        assert!(content.contains("\"type\":\"assistant\""));
    }

    #[tokio::test]
    #[serial]
    async fn warp_normalizes_agent_tasks_to_turns_and_tools() {
        let tmp = TempDir::new().expect("tmp");
        let db_path = tmp.path().join("warp.sqlite");
        let conn = create_db(&db_path);
        conn.execute(
            "INSERT INTO ai_queries (exchange_id, conversation_id, start_ts, input, working_directory, output_status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                "ex-task",
                "conv-task",
                1_772_582_520i64,
                r#"[]"#,
                "/tmp/repo",
                "Completed",
            ),
        )
        .expect("insert query");

        let blob = build_task_with_user_assistant_and_tool();
        conn.execute(
            "INSERT INTO agent_tasks (conversation_id, task_id, task, last_modified_at)
             VALUES (?1, ?2, ?3, ?4)",
            ("conv-task", "task-1", blob, "2026-03-04 00:04:50"),
        )
        .expect("insert task");

        unsafe {
            std::env::set_var("WARP_DB_PATH", &db_path);
        }
        let logs = WarpExplorer.discover_recent(1_772_583_000, 10_000).await;
        unsafe {
            std::env::remove_var("WARP_DB_PATH");
        }

        let log = logs.first().expect("log");
        let content = match &log.source {
            SessionSource::Inline { content, .. } => content,
            _ => panic!("expected inline"),
        };

        assert!(content.contains("\"type\":\"user\""));
        assert!(content.contains("\"type\":\"assistant\""));
        assert!(content.contains("\"type\":\"tool_call\""));
        assert!(content.contains("\"type\":\"tool_result\""));
        assert!(content.contains("\"tool_args\""));
        assert!(content.contains("\"tool_output\""));
        assert!(!content.contains("\"input\":[]"));
    }

    #[test]
    fn protobuf_decoder_extracts_field_paths_and_nested_strings() {
        let blob = build_task_with_user_assistant_and_tool();
        let decoded = decode_warp_task(&blob).expect("decoded");

        assert!(decoded.flat_nodes.iter().any(|n| n.field_path == "5.2.1"
            && n.string_value.as_deref() == Some("Review current changes")));
        assert!(decoded.flat_nodes.iter().any(|n| {
            n.field_path == "5.5.2.5.1"
                && n.string_value
                    .as_deref()
                    .unwrap_or_default()
                    .contains("file changed")
        }));
    }

    #[test]
    fn protobuf_decoder_handles_truncated_blob_without_panic() {
        let blob = vec![0x0a, 0x10, 0x41, 0x42];
        assert!(decode_warp_task(&blob).is_none());
    }

    #[test]
    fn dedupe_adjacent_removes_identical_neighbor_events() {
        let events = vec![
            json!({"type":"assistant","timestamp":1,"content":"same"}),
            json!({"type":"assistant","timestamp":1,"content":"same"}),
            json!({"type":"assistant","timestamp":2,"content":"same"}),
            json!({"type":"assistant","timestamp":4,"content":"same"}),
        ];
        let deduped = dedupe_adjacent(events);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn warp_profile_maps_expected_paths() {
        assert_eq!(
            WarpSchemaProfile::classify("5.2.1"),
            WarpSemanticRole::UserText
        );
        assert_eq!(
            WarpSchemaProfile::classify("5.3.1"),
            WarpSemanticRole::AssistantText
        );
        assert_eq!(
            WarpSchemaProfile::classify("5.4.2.1"),
            WarpSemanticRole::ToolCallArgs
        );
        assert_eq!(
            WarpSchemaProfile::classify("5.5.2.5.1"),
            WarpSemanticRole::ToolResultOutput
        );
    }

    #[test]
    fn normalize_task_events_keeps_meta_for_later_envelope() {
        let task = AgentTaskRow {
            conversation_id: "conv-1".to_string(),
            task_id: "task-1".to_string(),
            last_modified_ts: 1_700_000_000,
            task_blob: Vec::new(),
        };
        let decoded = WarpDecodedTask {
            flat_nodes: vec![
                WarpFlatNode {
                    field_path: "5.2.1".to_string(),
                    timestamp_candidate: Some(1_700_000_001),
                    string_value: Some("first user prompt".to_string()),
                    envelope_index: Some(0),
                },
                WarpFlatNode {
                    field_path: "9.1.1".to_string(),
                    timestamp_candidate: Some(1_700_000_002),
                    string_value: Some("Task failed after timeout".to_string()),
                    envelope_index: Some(1),
                },
            ],
        };

        let events = normalize_task_events("conv-1", &task, Some(&decoded), Some("/tmp/repo"));
        assert!(
            events
                .iter()
                .any(|event| event.get("type").and_then(Value::as_str) == Some("user"))
        );
        assert!(events.iter().any(|event| {
            event.get("type").and_then(Value::as_str) == Some("warp_meta")
                && event
                    .get("content")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .contains("failed")
        }));
    }
}
