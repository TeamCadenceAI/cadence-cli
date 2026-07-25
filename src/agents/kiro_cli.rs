//! Kiro CLI (v2) log discovery and Claude-Code-shaped transcript translation.
//!
//! Kiro CLI v2 stores per-session files flat inside `$KIRO_HOME/sessions/cli/`,
//! defaulting to `$HOME/.kiro/sessions/cli/` when `KIRO_HOME` is unset or empty:
//!
//! - `<session_id>.json`  — session metadata: `session_id`, `cwd`,
//!   `created_at`, `updated_at`, `title`, `model_id`, `personality_id`,
//!   `parent_session_id`, `session_created_reason`, plus per-turn telemetry
//!   (`input_token_count`, `output_token_count`, `metering_usage`, …) under
//!   `session_state.conversation_metadata.user_turn_metadatas`. Older
//!   versions also include a top-level `messages` array.
//! - `<session_id>.jsonl` — append-only event log. Each line is one of:
//!     - `{"version":"v1","kind":"Prompt","data":{...}}`
//!     - `{"version":"v1","kind":"AssistantMessage","data":{...}}`
//!     - `{"version":"v1","kind":"ToolResults","data":{...}}`
//!     - `{"version":"v1","kind":"Compaction","data":{"summary":"..."}}`
//! - `<session_id>.lock`  — only present while the session is active.
//!
//! v1 stored everything in a SQLite database under
//! `~/Library/Application Support/kiro-cli/data.sqlite3`. This module is
//! intentionally v2-only: it discovers v2 file pairs and ignores v1.
//!
//! Each session is published as a single `SessionSource::Inline` carrying a
//! synthetic Claude-Code-shaped JSONL transcript. The Cadence backend's
//! canonical-transcript recognizer is keyed on Claude Code's schema
//! (`type: "user"|"assistant"`, `message:{role, content[]}`, etc.), so we
//! translate kiro-cli's native event shape into that schema while
//! preserving kiro-cli telemetry under namespaced keys.
//!
//! Layout of the published JSONL (line-delimited JSON):
//!
//! 1. A leading `session_meta` header carrying enriched session metadata
//!    (model id, personality id, parent session id, agent name, etc.).
//!    The header uses both `type` and `kind` field names so existing
//!    unit tests and the canonical parser both handle it gracefully.
//! 2. One Claude-Code-shaped event per kiro-cli transcript event.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

use super::{AgentExplorer, SessionLog, SessionSource, home_dir};
use crate::scanner::AgentType;
use async_trait::async_trait;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Environment variable consulted by kiro-cli v2 to relocate `$HOME/.kiro`.
const KIRO_HOME_ENV: &str = "KIRO_HOME";

/// Synthetic version stamp embedded in every translated event so the
/// backend can tell a kiro-cli-translated transcript apart from a native
/// Claude Code one.
const SYNTHETIC_VERSION: &str = "kiro-cli/v2";

/// Schema version advertised by the leading `session_meta` line.
/// Bumped whenever the translation layout changes in a backwards
/// incompatible way.
const SCHEMA_VERSION: &str = "v3";

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Return the kiro-cli v2 sessions root, honoring `KIRO_HOME`.
///
/// Returns an empty `Vec` if neither `KIRO_HOME` nor `$HOME` resolves to a
/// usable directory.
pub async fn all_log_dirs() -> Vec<PathBuf> {
    match resolve_sessions_root() {
        Some(root) => vec![root],
        None => Vec::new(),
    }
}

pub struct KiroCliExplorer;

#[async_trait]
impl AgentExplorer for KiroCliExplorer {
    async fn discover_recent(&self, now: i64, since_secs: i64) -> Vec<SessionLog> {
        let roots = all_log_dirs().await;
        discover_recent_in(&roots, now, since_secs).await
    }
}

/// Resolve `$KIRO_HOME/sessions/cli` if `KIRO_HOME` is set and non-empty,
/// otherwise `$HOME/.kiro/sessions/cli`. Returns `None` only when no home
/// directory could be resolved.
fn resolve_sessions_root() -> Option<PathBuf> {
    if let Ok(value) = std::env::var(KIRO_HOME_ENV)
        && !value.is_empty()
    {
        return Some(PathBuf::from(value).join("sessions").join("cli"));
    }
    Some(home_dir()?.join(".kiro").join("sessions").join("cli"))
}

/// Test-friendly helper: build the v2 sessions root rooted at an arbitrary
/// home directory, ignoring `KIRO_HOME`.
#[cfg(test)]
fn sessions_root_in(home: &std::path::Path) -> PathBuf {
    home.join(".kiro").join("sessions").join("cli")
}

#[derive(Debug, Default)]
struct SessionFiles {
    metadata: Option<PathBuf>,
    transcript: Option<PathBuf>,
    metadata_mtime: Option<i64>,
    transcript_mtime: Option<i64>,
}

impl SessionFiles {
    fn latest_mtime(&self) -> Option<i64> {
        match (self.metadata_mtime, self.transcript_mtime) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum FileKind {
    Metadata,
    Transcript,
}

async fn discover_recent_in(roots: &[PathBuf], now: i64, since_secs: i64) -> Vec<SessionLog> {
    let cutoff = now - since_secs;
    let mut sessions: HashMap<String, SessionFiles> = HashMap::new();

    for root in roots {
        let mut entries = match tokio::fs::read_dir(root).await {
            Ok(e) => e,
            Err(_) => continue,
        };

        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let Ok(file_type) = entry.file_type().await else {
                continue;
            };
            if !file_type.is_file() {
                continue;
            }

            let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };

            // Ignore lock files (active session sentinels) and any
            // unrelated extensions kiro-cli might drop in this directory.
            let kind = if file_name.ends_with(".json") {
                FileKind::Metadata
            } else if file_name.ends_with(".jsonl") {
                FileKind::Transcript
            } else {
                continue;
            };

            let mtime = match tokio::fs::metadata(&path)
                .await
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|m| m.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
            {
                Some(t) => t,
                None => continue,
            };

            let entry = sessions.entry(stem.to_string()).or_default();
            match kind {
                FileKind::Metadata => {
                    entry.metadata = Some(path);
                    entry.metadata_mtime = Some(mtime);
                }
                FileKind::Transcript => {
                    entry.transcript = Some(path);
                    entry.transcript_mtime = Some(mtime);
                }
            }
        }
    }

    let mut session_ids: Vec<_> = sessions.keys().cloned().collect();
    session_ids.sort();

    let mut out = Vec::with_capacity(session_ids.len());
    for session_id in session_ids {
        let files = match sessions.remove(&session_id) {
            Some(f) => f,
            None => continue,
        };
        let Some(mtime) = files.latest_mtime() else {
            continue;
        };
        if mtime < cutoff {
            continue;
        }

        let content = build_synthetic_content(&session_id, &files).await;
        out.push(SessionLog {
            agent_type: AgentType::KiroCli,
            source: SessionSource::Inline {
                label: format!("kiro-cli:{session_id}"),
                content,
            },
            updated_at: Some(mtime),
        });
    }

    out
}

// ---------------------------------------------------------------------------
// Synthetic transcript construction
// ---------------------------------------------------------------------------

/// Build the inline transcript published for a kiro-cli session.
///
/// Layout (one JSON value per line, JSONL):
///
/// 1. A synthetic `session_meta` header derived from `<session_id>.json`.
/// 2. Claude-Code-shaped events translated from `<session_id>.jsonl`.
///    If the `.jsonl` is missing or empty, falls back to the legacy
///    top-level `messages` array on `<session_id>.json` when present.
async fn build_synthetic_content(session_id: &str, files: &SessionFiles) -> String {
    let metadata = read_metadata(files).await;
    let header = build_header_line(session_id, &metadata);

    let raw_jsonl = match &files.transcript {
        Some(path) => tokio::fs::read_to_string(path).await.unwrap_or_default(),
        None => String::new(),
    };

    // Fallback timestamp anchor: prefer transcript mtime, then metadata mtime.
    let fallback_ts_secs = files.transcript_mtime.or(files.metadata_mtime).unwrap_or(0);

    let body = if raw_jsonl.trim().is_empty() {
        translate_legacy_messages(&metadata, fallback_ts_secs)
    } else {
        translate_jsonl(&raw_jsonl, &metadata, fallback_ts_secs)
    };

    if body.is_empty() {
        return header;
    }
    format!("{header}\n{}", body.trim_end_matches('\n'))
}

// ---------------------------------------------------------------------------
// Metadata model
// ---------------------------------------------------------------------------

/// Per-session metadata harvested from `<session_id>.json`.
#[derive(Debug, Default, Clone)]
struct Metadata {
    /// Session id from the metadata file (overrides filename if disagreed).
    session_id: Option<String>,
    cwd: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
    title: Option<String>,
    /// Top-level `model_id` (newer schema) or `model_info.model_id` if only
    /// the nested copy is present.
    model_id: Option<String>,
    personality_id: Option<String>,
    parent_session_id: Option<String>,
    session_created_reason: Option<String>,
    agent_name: Option<String>,
    /// Full `session_state.rts_model_state.model_info` blob, when present.
    model_info: Option<Value>,
    /// Per-message-id telemetry derived from `user_turn_metadatas`.
    turns: HashMap<String, TurnInfo>,
    /// Raw legacy top-level `messages` array, when present.
    legacy_messages: Option<Vec<Value>>,
}

/// Telemetry attached to a particular message_id by walking the `.json`
/// `user_turn_metadatas` list.
#[derive(Debug, Default, Clone)]
struct TurnInfo {
    /// True when this message_id is the final AssistantMessage of a turn
    /// (i.e. matches `user_turn_metadatas[i].result.Ok.id`).
    is_final: bool,
    end_timestamp_rfc3339: Option<String>,
    end_timestamp_secs: Option<i64>,
    end_reason: Option<String>,
    input_token_count: u64,
    output_token_count: u64,
    metering_usage: Option<Value>,
    turn_duration_secs: Option<u64>,
    context_usage_percentage: Option<f64>,
    number_of_cycles: Option<u64>,
    total_request_count: Option<u64>,
    builtin_tool_uses: Option<u64>,
}

async fn read_metadata(files: &SessionFiles) -> Metadata {
    let Some(path) = files.metadata.as_ref() else {
        return Metadata::default();
    };
    let Ok(text) = tokio::fs::read_to_string(path).await else {
        return Metadata::default();
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return Metadata::default();
    };

    let mut meta = Metadata::default();

    // Top-level scalar fields.
    if let Some(s) = value.get("session_id").and_then(|v| v.as_str()) {
        meta.session_id = Some(s.to_string());
    }
    if let Some(s) = value.get("cwd").and_then(|v| v.as_str()) {
        meta.cwd = Some(s.to_string());
    }
    if let Some(s) = value.get("created_at").and_then(|v| v.as_str()) {
        meta.created_at = Some(s.to_string());
    }
    if let Some(s) = value.get("updated_at").and_then(|v| v.as_str()) {
        meta.updated_at = Some(s.to_string());
    }
    if let Some(s) = value.get("title").and_then(|v| v.as_str()) {
        meta.title = Some(s.to_string());
    }
    if let Some(s) = value.get("model_id").and_then(|v| v.as_str()) {
        meta.model_id = Some(s.to_string());
    }
    if let Some(s) = value.get("personality_id").and_then(|v| v.as_str()) {
        meta.personality_id = Some(s.to_string());
    }
    if let Some(s) = value.get("parent_session_id").and_then(|v| v.as_str()) {
        meta.parent_session_id = Some(s.to_string());
    }
    if let Some(s) = value.get("session_created_reason").and_then(|v| v.as_str()) {
        meta.session_created_reason = Some(s.to_string());
    }

    // session_state.* nested fields.
    if let Some(state) = value.get("session_state") {
        if let Some(s) = state.get("agent_name").and_then(|v| v.as_str()) {
            meta.agent_name = Some(s.to_string());
        }

        if let Some(model_info) = state.pointer("/rts_model_state/model_info")
            && model_info.is_object()
        {
            // If top-level model_id wasn't set, surface the nested one.
            if meta.model_id.is_none()
                && let Some(s) = model_info.get("model_id").and_then(|v| v.as_str())
            {
                meta.model_id = Some(s.to_string());
            }
            meta.model_info = Some(model_info.clone());
        }

        if let Some(turns) = state.pointer("/conversation_metadata/user_turn_metadatas")
            && let Some(arr) = turns.as_array()
        {
            for (idx, turn) in arr.iter().enumerate() {
                index_turn(turn, idx, &mut meta.turns);
            }
        }
    }

    // Legacy top-level `messages` array (pre-v3 sessions).
    if let Some(arr) = value.get("messages").and_then(|v| v.as_array())
        && !arr.is_empty()
    {
        meta.legacy_messages = Some(arr.clone());
    }

    meta
}

fn index_turn(turn: &Value, _turn_idx: usize, into: &mut HashMap<String, TurnInfo>) {
    let mut base = TurnInfo {
        input_token_count: turn
            .get("input_token_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        output_token_count: turn
            .get("output_token_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        metering_usage: turn.get("metering_usage").cloned(),
        turn_duration_secs: turn.pointer("/turn_duration/secs").and_then(|v| v.as_u64()),
        context_usage_percentage: turn
            .get("context_usage_percentage")
            .and_then(|v| v.as_f64()),
        number_of_cycles: turn.get("number_of_cycles").and_then(|v| v.as_u64()),
        total_request_count: turn.get("total_request_count").and_then(|v| v.as_u64()),
        builtin_tool_uses: turn.get("builtin_tool_uses").and_then(|v| v.as_u64()),
        ..Default::default()
    };

    if let Some(s) = turn.get("end_reason").and_then(|v| v.as_str()) {
        base.end_reason = Some(s.to_string());
    }
    if let Some(s) = turn.get("end_timestamp").and_then(|v| v.as_str()) {
        base.end_timestamp_rfc3339 = Some(s.to_string());
        base.end_timestamp_secs = OffsetDateTime::parse(s, &Rfc3339)
            .ok()
            .map(|dt| dt.unix_timestamp());
    }

    // Identify the final AssistantMessage of the turn.
    let final_id = turn
        .pointer("/result/Ok/id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Attribute base info to every message_id in the turn.
    if let Some(ids) = turn.get("message_ids").and_then(|v| v.as_array()) {
        for id in ids {
            let Some(id) = id.as_str() else {
                continue;
            };
            let mut info = base.clone();
            info.is_final = final_id.as_deref() == Some(id);
            into.insert(id.to_string(), info);
        }
    }

    // Make sure the final id is indexed even if missing from message_ids.
    if let Some(id) = final_id {
        let mut info = base.clone();
        info.is_final = true;
        into.entry(id).or_insert(info);
    }
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

/// Construct the single-line synthetic header. Always starts with the
/// fields Cadence's scanner needs to identify the session, then layers in
/// any matching fields harvested from the metadata file.
fn build_header_line(session_id: &str, meta: &Metadata) -> String {
    // Resolve effective session id: metadata wins if it disagrees with the
    // filename — this mirrors kiro-cli's own behavior for renamed sessions.
    let effective_id = meta
        .session_id
        .clone()
        .unwrap_or_else(|| session_id.to_string());

    let mut header = json!({
        "type": "session_meta",
        "kind": "session_meta",
        "source": "kiro-cli",
        "schema": SCHEMA_VERSION,
        "version": SYNTHETIC_VERSION,
        "session_id": effective_id,
        "sessionId": effective_id,
    });
    let out = header
        .as_object_mut()
        .expect("header initializer is always an object");

    if let Some(s) = &meta.cwd {
        out.insert("cwd".into(), Value::String(s.clone()));
    }
    if let Some(s) = &meta.created_at {
        out.insert("created_at".into(), Value::String(s.clone()));
    }
    if let Some(s) = &meta.updated_at {
        out.insert("updated_at".into(), Value::String(s.clone()));
    }
    if let Some(s) = &meta.title {
        out.insert("title".into(), Value::String(s.clone()));
    }
    if let Some(s) = &meta.model_id {
        // Use `model` (Claude Code's convention on assistant messages) plus
        // `model_id` for kiro-cli-native consumers.
        out.insert("model".into(), Value::String(s.clone()));
        out.insert("model_id".into(), Value::String(s.clone()));
    }
    if let Some(s) = &meta.personality_id {
        out.insert("personality_id".into(), Value::String(s.clone()));
    }
    if let Some(s) = &meta.parent_session_id {
        out.insert("parent_session_id".into(), Value::String(s.clone()));
    }
    if let Some(s) = &meta.session_created_reason {
        out.insert("session_created_reason".into(), Value::String(s.clone()));
    }
    if let Some(s) = &meta.agent_name {
        out.insert("agent_name".into(), Value::String(s.clone()));
    }
    if let Some(model_info) = &meta.model_info {
        out.insert("model_info".into(), model_info.clone());
    }

    header.to_string()
}

// ---------------------------------------------------------------------------
// .jsonl translation
// ---------------------------------------------------------------------------

/// Translate the kiro-cli `.jsonl` event stream into Claude-Code-shaped
/// JSONL. Returns an empty string if no events translated cleanly.
fn translate_jsonl(raw: &str, meta: &Metadata, fallback_ts_secs: i64) -> String {
    let mut ctx = TranslateCtx::new(meta, fallback_ts_secs);
    let mut out = Vec::new();

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(kind) = value.get("kind").and_then(|v| v.as_str()) else {
            continue;
        };
        let data = value.get("data").cloned().unwrap_or(Value::Null);
        match kind {
            "Prompt" => {
                if let Some(line) = ctx.translate_prompt(&data) {
                    out.push(line);
                }
            }
            "AssistantMessage" => {
                if let Some(line) = ctx.translate_assistant(&data) {
                    out.push(line);
                }
            }
            "ToolResults" => {
                if let Some(line) = ctx.translate_tool_results(&data) {
                    out.push(line);
                }
            }
            "Compaction" => {
                if let Some(line) = ctx.translate_compaction(&data) {
                    out.push(line);
                }
            }
            _ => {
                // Unknown kinds are dropped to keep the canonical parser
                // happy. Add namespaced passthrough later if needed.
            }
        }
    }

    out.join("\n")
}

/// Translate the legacy top-level `messages` array (pre-v3 sessions) into
/// canonical events. Synthesizes deterministic message_ids so parent
/// chaining and tool_use → tool_result correlation remain stable.
fn translate_legacy_messages(meta: &Metadata, fallback_ts_secs: i64) -> String {
    let Some(messages) = meta.legacy_messages.as_ref() else {
        return String::new();
    };

    let mut ctx = TranslateCtx::new(meta, fallback_ts_secs);
    let mut out = Vec::new();

    for (idx, msg) in messages.iter().enumerate() {
        let role = msg.get("role").and_then(|v| v.as_str()).unwrap_or("");
        let synthetic_id = format!("legacy-{idx}");

        // Build a Prompt-like or AssistantMessage-like `data` value from
        // the legacy content array, then route through the same translator
        // path we use for `.jsonl` events.
        let translated_content = legacy_content_to_kiro(msg.get("content"));

        match role {
            "user" => {
                // If the legacy content is purely tool_result blocks, route
                // it through the ToolResults path so parent chaining and
                // sourceToolAssistantUUID are populated correctly.
                if legacy_is_tool_result_only(msg.get("content")) {
                    let data = json!({
                        "message_id": synthetic_id,
                        "content": translated_content,
                    });
                    if let Some(line) = ctx.translate_tool_results(&data) {
                        out.push(line);
                    }
                } else {
                    let data = json!({
                        "message_id": synthetic_id,
                        "content": translated_content,
                    });
                    if let Some(line) = ctx.translate_prompt(&data) {
                        out.push(line);
                    }
                }
            }
            "assistant" => {
                let data = json!({
                    "message_id": synthetic_id,
                    "content": translated_content,
                });
                if let Some(line) = ctx.translate_assistant(&data) {
                    out.push(line);
                }
            }
            _ => continue,
        }
    }

    out.join("\n")
}

/// Convert a legacy `messages[*].content` element (which uses one of the
/// keys `text` / `toolUse` / `toolResult` / `reasoning` to discriminate
/// kind) into the kiro-cli-native `{kind, data}` shape used by the
/// translator. Unknown shapes round-trip as best-effort text.
fn legacy_content_to_kiro(content: Option<&Value>) -> Vec<Value> {
    let Some(Value::Array(items)) = content else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Value::Object(obj) = item else { continue };
        if let Some(text) = obj.get("text").and_then(|v| v.as_str()) {
            out.push(json!({"kind": "text", "data": text}));
        } else if let Some(reasoning) = obj.get("reasoning")
            && reasoning.is_object()
        {
            out.push(json!({
                "kind": "thinking",
                "data": {
                    "text": reasoning.get("text").and_then(|v| v.as_str()).unwrap_or(""),
                    "signature": reasoning.get("signature").and_then(|v| v.as_str()).unwrap_or(""),
                }
            }));
        } else if let Some(tool_use) = obj.get("toolUse")
            && tool_use.is_object()
        {
            out.push(json!({
                "kind": "toolUse",
                "data": tool_use,
            }));
        } else if let Some(tool_result) = obj.get("toolResult")
            && tool_result.is_object()
        {
            out.push(json!({
                "kind": "toolResult",
                "data": tool_result,
            }));
        } else {
            // Unknown shape: stringify so the content isn't lost.
            out.push(
                json!({"kind": "text", "data": serde_json::to_string(item).unwrap_or_default()}),
            );
        }
    }
    out
}

fn legacy_is_tool_result_only(content: Option<&Value>) -> bool {
    let Some(Value::Array(items)) = content else {
        return false;
    };
    !items.is_empty()
        && items.iter().all(|item| {
            item.as_object()
                .map(|o| o.contains_key("toolResult"))
                .unwrap_or(false)
        })
}

/// State carried across a single session's translation walk.
struct TranslateCtx<'a> {
    meta: &'a Metadata,
    fallback_ts_secs: i64,
    /// Most recently emitted event uuid; threaded into the next event's
    /// `parentUuid`.
    last_uuid: Option<String>,
    /// `tool_use_id → assistant_message_id` for tool_result attribution.
    tool_use_owners: HashMap<String, String>,
    /// Effective session id (metadata-overridden when applicable).
    session_id: String,
    cwd: Option<String>,
}

impl<'a> TranslateCtx<'a> {
    fn new(meta: &'a Metadata, fallback_ts_secs: i64) -> Self {
        let session_id = meta.session_id.clone().unwrap_or_default();
        let cwd = meta.cwd.clone();
        Self {
            meta,
            fallback_ts_secs,
            last_uuid: None,
            tool_use_owners: HashMap::new(),
            session_id,
            cwd,
        }
    }

    fn parent(&self) -> Value {
        match &self.last_uuid {
            Some(s) => Value::String(s.clone()),
            None => Value::Null,
        }
    }

    fn stamp_session_fields(&self, obj: &mut Map<String, Value>) {
        obj.insert("sessionId".into(), Value::String(self.session_id.clone()));
        if let Some(cwd) = &self.cwd {
            obj.insert("cwd".into(), Value::String(cwd.clone()));
        }
        obj.insert(
            "version".into(),
            Value::String(SYNTHETIC_VERSION.to_string()),
        );
        obj.insert("userType".into(), Value::String("external".into()));
        obj.insert("entrypoint".into(), Value::String("cli".into()));
        obj.insert("isSidechain".into(), Value::Bool(false));
    }

    fn translate_prompt(&mut self, data: &Value) -> Option<String> {
        let message_id = data
            .get("message_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(new_uuid);

        let timestamp = self
            .timestamp_for_message(&message_id, data)
            .unwrap_or_else(|| epoch_to_rfc3339(self.fallback_ts_secs));

        // Pure-text prompts become a string-form message.content (matches
        // Claude Code for simple user inputs). Mixed-content prompts emit
        // an array of canonical content blocks.
        let raw_content = data.get("content").cloned().unwrap_or(Value::Null);
        let message_content = build_user_message_content(&raw_content);

        let mut obj = Map::new();
        obj.insert("type".into(), Value::String("user".into()));
        obj.insert("uuid".into(), Value::String(message_id.clone()));
        obj.insert("parentUuid".into(), self.parent());
        obj.insert("promptId".into(), Value::String(message_id.clone()));
        obj.insert("timestamp".into(), Value::String(timestamp));
        obj.insert(
            "message".into(),
            json!({
                "role": "user",
                "content": message_content,
            }),
        );
        self.stamp_session_fields(&mut obj);

        self.last_uuid = Some(message_id);
        Some(Value::Object(obj).to_string())
    }

    fn translate_assistant(&mut self, data: &Value) -> Option<String> {
        let message_id = data
            .get("message_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(new_uuid);

        let timestamp = self
            .timestamp_for_message(&message_id, data)
            .unwrap_or_else(|| epoch_to_rfc3339(self.fallback_ts_secs));

        // Translate kiro content blocks; record any tool_use ownerships so
        // following ToolResults events can backreference the assistant.
        let raw_content = data
            .get("content")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut content_blocks = Vec::with_capacity(raw_content.len());
        for block in &raw_content {
            if let Some(b) = self.translate_assistant_block(block, &message_id) {
                content_blocks.push(b);
            }
        }

        // Per-turn telemetry, when this message is the final of its turn.
        let turn = self.meta.turns.get(&message_id);
        let is_final_of_turn = turn.map(|t| t.is_final).unwrap_or(false);

        let usage = build_usage_value(turn, is_final_of_turn);
        let stop_reason = if is_final_of_turn {
            turn.and_then(|t| t.end_reason.clone())
                .map(Value::String)
                .unwrap_or(Value::Null)
        } else {
            Value::Null
        };

        let model = self
            .meta
            .model_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        let message = json!({
            "model": model,
            "id": message_id.clone(),
            "type": "message",
            "role": "assistant",
            "content": content_blocks,
            "stop_reason": stop_reason,
            "stop_sequence": Value::Null,
            "stop_details": Value::Null,
            "usage": usage,
        });

        let mut obj = Map::new();
        obj.insert("type".into(), Value::String("assistant".into()));
        obj.insert("uuid".into(), Value::String(message_id.clone()));
        obj.insert("parentUuid".into(), self.parent());
        obj.insert("timestamp".into(), Value::String(timestamp));
        obj.insert("message".into(), message);
        self.stamp_session_fields(&mut obj);

        self.last_uuid = Some(message_id);
        Some(Value::Object(obj).to_string())
    }

    fn translate_assistant_block(&mut self, block: &Value, owner_msg_id: &str) -> Option<Value> {
        let kind = block.get("kind").and_then(|v| v.as_str())?;
        let data = block.get("data");
        match kind {
            "text" => {
                let text = data
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                Some(json!({"type": "text", "text": text}))
            }
            "thinking" => {
                let text = data
                    .and_then(|v| v.get("text"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let signature = data
                    .and_then(|v| v.get("signature"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Some(json!({
                    "type": "thinking",
                    "thinking": text,
                    "signature": signature,
                }))
            }
            "toolUse" => {
                let tool_use_id = data
                    .and_then(|v| v.get("toolUseId"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = data
                    .and_then(|v| v.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let input = data
                    .and_then(|v| v.get("input"))
                    .cloned()
                    .unwrap_or(Value::Null);
                if !tool_use_id.is_empty() {
                    self.tool_use_owners
                        .insert(tool_use_id.clone(), owner_msg_id.to_string());
                }
                Some(json!({
                    "type": "tool_use",
                    "id": tool_use_id,
                    "name": name,
                    "input": input,
                }))
            }
            // Unknown content kinds round-trip as text so nothing is lost.
            _ => Some(json!({
                "type": "text",
                "text": serde_json::to_string(block).unwrap_or_default(),
            })),
        }
    }

    fn translate_tool_results(&mut self, data: &Value) -> Option<String> {
        let message_id = data
            .get("message_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(new_uuid);

        let raw_blocks = data
            .get("content")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut canonical_blocks = Vec::with_capacity(raw_blocks.len());
        let mut owner_uuids: Vec<String> = Vec::new();
        let mut tool_use_ids: Vec<String> = Vec::new();

        for block in &raw_blocks {
            if block.get("kind").and_then(|v| v.as_str()) != Some("toolResult") {
                continue;
            }
            let bdata = match block.get("data") {
                Some(d) => d,
                None => continue,
            };
            let tool_use_id = bdata
                .get("toolUseId")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let status = bdata
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("success")
                .to_string();
            let inner = bdata
                .get("content")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let canonical_inner = inner
                .iter()
                .map(stringify_tool_result_inner_block)
                .collect::<Vec<_>>();

            let canonical = json!({
                "type": "tool_result",
                "tool_use_id": tool_use_id.clone(),
                "content": canonical_inner,
                "is_error": status != "success",
            });

            if !tool_use_id.is_empty() {
                if let Some(owner) = self.tool_use_owners.get(&tool_use_id) {
                    owner_uuids.push(owner.clone());
                }
                tool_use_ids.push(tool_use_id);
            }
            canonical_blocks.push(canonical);
        }

        if canonical_blocks.is_empty() {
            return None;
        }

        let timestamp = self
            .timestamp_for_message(&message_id, data)
            .unwrap_or_else(|| epoch_to_rfc3339(self.fallback_ts_secs));

        let mut obj = Map::new();
        obj.insert("type".into(), Value::String("user".into()));
        obj.insert("uuid".into(), Value::String(message_id.clone()));
        obj.insert("parentUuid".into(), self.parent());
        obj.insert("timestamp".into(), Value::String(timestamp));
        obj.insert(
            "message".into(),
            json!({
                "role": "user",
                "content": canonical_blocks,
            }),
        );

        // Mirror Claude Code's tool-result attribution fields.
        if let Some(first) = tool_use_ids.first() {
            obj.insert("sourceToolUseID".into(), Value::String(first.clone()));
        }
        if let Some(first) = owner_uuids.first() {
            obj.insert(
                "sourceToolAssistantUUID".into(),
                Value::String(first.clone()),
            );
        }

        // Preserve the raw kiro-cli `results` payload for full fidelity.
        if let Some(results) = data.get("results") {
            obj.insert("toolUseResult".into(), results.clone());
        }

        self.stamp_session_fields(&mut obj);

        self.last_uuid = Some(message_id);
        Some(Value::Object(obj).to_string())
    }

    fn translate_compaction(&mut self, data: &Value) -> Option<String> {
        let summary = data
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let uuid = new_uuid();
        let timestamp = epoch_to_rfc3339(self.fallback_ts_secs);

        let mut obj = Map::new();
        obj.insert("type".into(), Value::String("summary".into()));
        obj.insert("uuid".into(), Value::String(uuid.clone()));
        obj.insert("parentUuid".into(), self.parent());
        obj.insert("timestamp".into(), Value::String(timestamp));
        obj.insert("summary".into(), Value::String(summary));
        // Keep the raw kiro payload alongside under a namespaced key so
        // future tooling can recover the full compaction state.
        obj.insert("kiro_compaction".into(), data.clone());
        self.stamp_session_fields(&mut obj);

        self.last_uuid = Some(uuid);
        Some(Value::Object(obj).to_string())
    }

    /// Resolve a Claude-Code-shape RFC3339 timestamp for a message, in
    /// preference order:
    ///   1. `data.meta.timestamp` (epoch seconds, present on Prompt and
    ///      legacy AssistantMessage events)
    ///   2. The owning turn's `end_timestamp` (RFC3339)
    ///   3. None — caller falls back to the file mtime.
    fn timestamp_for_message(&self, message_id: &str, data: &Value) -> Option<String> {
        if let Some(secs) = data.pointer("/meta/timestamp").and_then(|v| v.as_i64()) {
            return Some(epoch_to_rfc3339(secs));
        }
        if let Some(turn) = self.meta.turns.get(message_id)
            && let Some(s) = &turn.end_timestamp_rfc3339
        {
            return Some(s.clone());
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Content helpers
// ---------------------------------------------------------------------------

/// Build the `message.content` value for a Claude-Code-shape user event.
///
/// kiro-cli prompts always carry a `content: [{kind, data}, ...]` array.
/// When every block is plain text we collapse to a single string (matching
/// Claude Code's most common shape for human-typed prompts). Anything else
/// becomes an array of canonical content blocks so binary / image / mixed
/// inputs aren't dropped.
fn build_user_message_content(raw: &Value) -> Value {
    let Some(arr) = raw.as_array() else {
        // Non-array `content` (rare): pass through as-is via stringification.
        return Value::String(stringify_for_text(raw));
    };

    let all_text = arr.iter().all(|b| {
        b.get("kind").and_then(|v| v.as_str()) == Some("text")
            && b.get("data").and_then(|v| v.as_str()).is_some()
    });

    if all_text {
        let text = arr
            .iter()
            .map(|b| b.get("data").and_then(|v| v.as_str()).unwrap_or(""))
            .collect::<Vec<_>>()
            .join("");
        return Value::String(text);
    }

    let mut blocks: Vec<Value> = Vec::with_capacity(arr.len());
    for b in arr {
        let kind = b.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let data = b.get("data");
        match kind {
            "text" => blocks.push(json!({
                "type": "text",
                "text": data.and_then(|v| v.as_str()).unwrap_or("").to_string(),
            })),
            // image and other binary blocks: encode as a text fallback that
            // preserves the original JSON for debugging.
            _ => blocks.push(json!({
                "type": "text",
                "text": stringify_for_text(b),
            })),
        }
    }
    Value::Array(blocks)
}

/// Convert an inner tool-result content block (`{kind:"json"|"text"|...,
/// data:...}`) into a Claude-Code-style `{type:"text", text: ...}` block.
/// JSON / structured payloads are stringified verbatim so the backend can
/// re-parse them if it wants.
fn stringify_tool_result_inner_block(block: &Value) -> Value {
    let kind = block.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    let data = block.get("data");
    match kind {
        "text" => json!({
            "type": "text",
            "text": data.and_then(|v| v.as_str()).unwrap_or("").to_string(),
        }),
        _ => json!({
            "type": "text",
            "text": data
                .map(|v| serde_json::to_string(v).unwrap_or_default())
                .unwrap_or_default(),
        }),
    }
}

fn stringify_for_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        _ => serde_json::to_string(value).unwrap_or_default(),
    }
}

/// Build a Claude-Code-style `usage` object. When the message is the final
/// of its turn, populate the input / output token totals from kiro-cli's
/// per-turn telemetry. Otherwise emit zeros so the schema slot is still
/// present (Claude Code populates this on every assistant message).
fn build_usage_value(turn: Option<&TurnInfo>, is_final: bool) -> Value {
    let mut usage = json!({
        "input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "output_tokens": 0,
        "service_tier": "standard",
    });

    let obj = usage
        .as_object_mut()
        .expect("usage initializer is always an object");

    if let (true, Some(t)) = (is_final, turn) {
        obj.insert("input_tokens".into(), Value::from(t.input_token_count));
        obj.insert("output_tokens".into(), Value::from(t.output_token_count));
        if let Some(metering) = &t.metering_usage {
            obj.insert("kiro_metering_usage".into(), metering.clone());
        }
        if let Some(p) = t.context_usage_percentage {
            obj.insert("kiro_context_usage_percentage".into(), Value::from(p));
        }
        if let Some(secs) = t.turn_duration_secs {
            obj.insert("kiro_turn_duration_secs".into(), Value::from(secs));
        }
        if let Some(s) = &t.end_reason {
            obj.insert("kiro_end_reason".into(), Value::String(s.clone()));
        }
        if let Some(n) = t.number_of_cycles {
            obj.insert("kiro_number_of_cycles".into(), Value::from(n));
        }
        if let Some(n) = t.total_request_count {
            obj.insert("kiro_total_request_count".into(), Value::from(n));
        }
        if let Some(n) = t.builtin_tool_uses {
            obj.insert("kiro_builtin_tool_uses".into(), Value::from(n));
        }
    }

    usage
}

fn epoch_to_rfc3339(secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        // Last-resort fallback: a fixed epoch string so events always parse.
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

fn new_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use crate::agents::set_file_mtime;
    use std::path::Path;
    use tempfile::TempDir;

    /// Helper: write a paired `<id>.json` + `<id>.jsonl` pair under `root`.
    async fn write_session(root: &Path, id: &str, metadata_json: &str, transcript_jsonl: &str) {
        tokio::fs::create_dir_all(root).await.unwrap();
        tokio::fs::write(root.join(format!("{id}.json")), metadata_json)
            .await
            .unwrap();
        tokio::fs::write(root.join(format!("{id}.jsonl")), transcript_jsonl)
            .await
            .unwrap();
    }

    fn lines(content: &str) -> Vec<&str> {
        content.split('\n').filter(|l| !l.is_empty()).collect()
    }

    fn header_line(content: &str) -> &str {
        content.split('\n').next().unwrap_or("")
    }

    fn parse(line: &str) -> Value {
        serde_json::from_str(line).unwrap_or_else(|e| panic!("invalid JSON '{line}': {e}"))
    }

    async fn discover_one(root: &Path, now: i64) -> SessionLog {
        let logs = discover_recent_in(&[root.to_path_buf()], now, 3600).await;
        assert_eq!(
            logs.len(),
            1,
            "expected exactly one discovered session, got {}",
            logs.len()
        );
        logs.into_iter().next().unwrap()
    }

    fn inline_content(log: &SessionLog) -> &str {
        match &log.source {
            SessionSource::Inline { content, .. } => content.as_str(),
            SessionSource::File(_) => panic!("expected inline session"),
        }
    }

    // -- discovery --------------------------------------------------------

    #[tokio::test]
    async fn test_discovers_session_pair_within_window() {
        let home = TempDir::new().unwrap();
        let root = sessions_root_in(home.path());

        let id = "fdde89ef-92ca-445a-b601-d25a1bbbef4f";
        let meta = r#"{"session_id":"fdde89ef-92ca-445a-b601-d25a1bbbef4f","cwd":"/tmp/repo","created_at":"2026-05-19T10:00:00Z","updated_at":"2026-05-19T10:05:00Z","title":"hello"}"#;
        let transcript = r#"{"version":"v1","kind":"Prompt","data":{"message_id":"m1","content":[{"kind":"text","data":"hi"}],"meta":{"timestamp":1747641600}}}
"#;
        write_session(&root, id, meta, transcript).await;

        let now: i64 = 1_747_700_000;
        set_file_mtime(&root.join(format!("{id}.json")), now - 30);
        set_file_mtime(&root.join(format!("{id}.jsonl")), now - 10);

        let log = discover_one(&root, now).await;
        assert_eq!(log.agent_type, AgentType::KiroCli);
        assert_eq!(log.updated_at, Some(now - 10));

        let content = inline_content(&log);
        let head = parse(header_line(content));
        assert_eq!(head["type"], "session_meta");
        assert_eq!(head["kind"], "session_meta");
        assert_eq!(head["source"], "kiro-cli");
        assert_eq!(head["schema"], SCHEMA_VERSION);
        assert_eq!(head["session_id"], id);
        assert_eq!(head["sessionId"], id);
        assert_eq!(head["cwd"], "/tmp/repo");
        assert_eq!(head["title"], "hello");

        // Body event should be a Claude-Code-shape `user` event.
        let body_lines = lines(content);
        assert!(body_lines.len() >= 2);
        let user_evt = parse(body_lines[1]);
        assert_eq!(user_evt["type"], "user");
        assert_eq!(user_evt["uuid"], "m1");
        assert_eq!(user_evt["parentUuid"], Value::Null);
        assert_eq!(user_evt["sessionId"], id);
        assert_eq!(user_evt["cwd"], "/tmp/repo");
        assert_eq!(user_evt["version"], SYNTHETIC_VERSION);
        assert_eq!(user_evt["userType"], "external");
        assert_eq!(user_evt["entrypoint"], "cli");
        assert_eq!(user_evt["isSidechain"], false);
        assert_eq!(user_evt["message"]["role"], "user");
        assert_eq!(user_evt["message"]["content"], "hi");
    }

    #[tokio::test]
    async fn test_skips_sessions_outside_window() {
        let home = TempDir::new().unwrap();
        let root = sessions_root_in(home.path());

        let id = "stale-1";
        write_session(
            &root,
            id,
            r#"{"session_id":"stale-1","cwd":"/tmp/old"}"#,
            "{}\n",
        )
        .await;

        let now: i64 = 1_700_000_000;
        // Both files are well outside the 1-hour window.
        set_file_mtime(&root.join(format!("{id}.json")), now - 10 * 86_400);
        set_file_mtime(&root.join(format!("{id}.jsonl")), now - 10 * 86_400);

        let logs = discover_recent_in(&[root], now, 3600).await;
        assert!(
            logs.is_empty(),
            "expected stale session to be skipped, got {} logs",
            logs.len()
        );
    }

    #[tokio::test]
    async fn test_includes_metadata_only_session() {
        let home = TempDir::new().unwrap();
        let root = sessions_root_in(home.path());
        tokio::fs::create_dir_all(&root).await.unwrap();

        // A freshly created session may not yet have a `.jsonl`. We should
        // still discover it so cwd is available for repo resolution; the
        // synthetic content is just the header line.
        let id = "metadata-only";
        let meta_path = root.join(format!("{id}.json"));
        tokio::fs::write(
            &meta_path,
            r#"{"session_id":"metadata-only","cwd":"/tmp/empty"}"#,
        )
        .await
        .unwrap();

        let now: i64 = 1_700_000_000;
        set_file_mtime(&meta_path, now - 5);

        let log = discover_one(&root, now).await;
        let content = inline_content(&log);
        let head = parse(header_line(content));
        assert_eq!(head["session_id"], id);
        assert_eq!(head["cwd"], "/tmp/empty");
        assert!(
            !content.contains('\n'),
            "no transcript means no extra lines"
        );
    }

    #[tokio::test]
    async fn test_uses_filename_session_id_when_metadata_missing() {
        let home = TempDir::new().unwrap();
        let root = sessions_root_in(home.path());
        tokio::fs::create_dir_all(&root).await.unwrap();

        // Only the `.jsonl` is present (rare, but possible during a race).
        // Header still gets a session_id from the filename so downstream
        // identifies the session, even though cwd is missing.
        let id = "transcript-only";
        let transcript_path = root.join(format!("{id}.jsonl"));
        tokio::fs::write(
            &transcript_path,
            r#"{"version":"v1","kind":"Prompt","data":{"content":[{"kind":"text","data":"hi"}]}}"#,
        )
        .await
        .unwrap();

        let now: i64 = 1_700_000_000;
        set_file_mtime(&transcript_path, now - 5);

        let log = discover_one(&root, now).await;
        let content = inline_content(&log);
        let head = parse(header_line(content));
        assert_eq!(head["session_id"], id);
        assert_eq!(head["sessionId"], id);
        assert!(head.get("cwd").is_none());
    }

    #[tokio::test]
    async fn test_lock_and_unrelated_files_are_ignored() {
        let home = TempDir::new().unwrap();
        let root = sessions_root_in(home.path());
        tokio::fs::create_dir_all(&root).await.unwrap();

        let lock_path = root.join("orphan.lock");
        tokio::fs::write(&lock_path, "1234\n").await.unwrap();

        let ds_path = root.join(".DS_Store");
        tokio::fs::write(&ds_path, "junk").await.unwrap();

        let now: i64 = 1_700_000_000;
        set_file_mtime(&lock_path, now - 5);
        set_file_mtime(&ds_path, now - 5);

        let logs = discover_recent_in(&[root], now, 3600).await;
        assert!(
            logs.is_empty(),
            "lock/foreign files should not be discovered, got {} logs",
            logs.len()
        );
    }

    #[tokio::test]
    async fn test_metadata_session_id_overrides_filename() {
        let home = TempDir::new().unwrap();
        let root = sessions_root_in(home.path());
        let stem = "filename-id";
        write_session(
            &root,
            stem,
            r#"{"session_id":"metadata-id","cwd":"/tmp/x"}"#,
            "",
        )
        .await;

        let now: i64 = 1_700_000_000;
        set_file_mtime(&root.join(format!("{stem}.json")), now - 5);
        set_file_mtime(&root.join(format!("{stem}.jsonl")), now - 5);

        let log = discover_one(&root, now).await;
        // Label still uses the filename stem (it identifies the file pair).
        let label = match &log.source {
            SessionSource::Inline { label, .. } => label.clone(),
            SessionSource::File(_) => panic!("expected inline session"),
        };
        assert_eq!(label, format!("kiro-cli:{stem}"));
        let content = inline_content(&log);
        let head = parse(header_line(content));
        assert_eq!(head["session_id"], "metadata-id");
        assert_eq!(head["sessionId"], "metadata-id");
    }

    #[tokio::test]
    async fn test_synthetic_content_parses_as_session_metadata() {
        let home = TempDir::new().unwrap();
        let root = sessions_root_in(home.path());

        let id = "round-trip";
        write_session(
            &root,
            id,
            r#"{"session_id":"round-trip","cwd":"/Users/foo/dev/cadence-cli","title":"unused"}"#,
            r#"{"version":"v1","kind":"Prompt","data":{"content":[{"kind":"text","data":"hi"}]}}"#,
        )
        .await;

        let now: i64 = 1_700_000_000;
        set_file_mtime(&root.join(format!("{id}.json")), now - 5);
        set_file_mtime(&root.join(format!("{id}.jsonl")), now - 5);

        let log = discover_one(&root, now).await;
        let content = inline_content(&log);

        let metadata = crate::scanner::parse_session_metadata_str(content);
        assert_eq!(metadata.session_id.as_deref(), Some("round-trip"));
        assert_eq!(metadata.cwd.as_deref(), Some("/Users/foo/dev/cadence-cli"));
    }

    #[tokio::test]
    async fn test_resolve_sessions_root_honors_kiro_home() {
        unsafe {
            std::env::remove_var(KIRO_HOME_ENV);
        }
        let resolved = resolve_sessions_root();
        let home = home_dir().expect("home should resolve in tests");
        assert_eq!(
            resolved,
            Some(home.join(".kiro").join("sessions").join("cli"))
        );
    }

    // -- translation ------------------------------------------------------

    #[tokio::test]
    async fn test_translates_prompt_assistant_tool_round_trip() {
        let home = TempDir::new().unwrap();
        let root = sessions_root_in(home.path());

        let id = "round";
        let meta = r#"{
            "session_id":"round",
            "cwd":"/tmp/wd",
            "model_id":"claude-opus-4-7",
            "personality_id":"default",
            "session_state":{
                "agent_name":"kiro_default",
                "rts_model_state":{
                    "model_info":{"model_id":"claude-opus-4-7","model_name":"Claude Opus 4.7","context_window_tokens":1000000,"rate_multiplier":1.0,"rate_unit":"requests"}
                },
                "conversation_metadata":{
                    "user_turn_metadatas":[
                        {
                            "message_ids":["m_user","m_asst1","m_tool","m_asst2"],
                            "result":{"Ok":{"id":"m_asst2","role":"assistant","content":[],"timestamp":1747641900}},
                            "input_token_count":123,
                            "output_token_count":456,
                            "end_reason":"UserTurnEnd",
                            "end_timestamp":"2026-05-19T10:05:00Z",
                            "metering_usage":[{"value":1.5,"unit":"REQUEST","unitPlural":"REQUESTS"}],
                            "context_usage_percentage":12.5,
                            "turn_duration":{"secs":42,"nanos":0},
                            "number_of_cycles":3,
                            "total_request_count":4,
                            "builtin_tool_uses":2
                        }
                    ]
                }
            }
        }"#;
        let transcript = concat!(
            r#"{"version":"v1","kind":"Prompt","data":{"message_id":"m_user","content":[{"kind":"text","data":"do work"}],"meta":{"timestamp":1747641800}}}"#,
            "\n",
            r#"{"version":"v1","kind":"AssistantMessage","data":{"message_id":"m_asst1","content":[{"kind":"text","data":"on it"},{"kind":"toolUse","data":{"toolUseId":"tu_1","name":"shell","input":{"command":"ls"}}}]}}"#,
            "\n",
            r#"{"version":"v1","kind":"ToolResults","data":{"message_id":"m_tool","content":[{"kind":"toolResult","data":{"toolUseId":"tu_1","content":[{"kind":"text","data":"ok output"}],"status":"success"}}]}}"#,
            "\n",
            r#"{"version":"v1","kind":"AssistantMessage","data":{"message_id":"m_asst2","content":[{"kind":"thinking","data":{"text":"reasoning","signature":"sig"}},{"kind":"text","data":"done"}]}}"#,
            "\n",
        );
        write_session(&root, id, meta, transcript).await;

        let now: i64 = 1_747_700_000;
        set_file_mtime(&root.join(format!("{id}.json")), now - 5);
        set_file_mtime(&root.join(format!("{id}.jsonl")), now - 5);

        let log = discover_one(&root, now).await;
        let content = inline_content(&log);
        let body = lines(content);
        assert_eq!(body.len(), 5, "header + 4 events");

        let head = parse(body[0]);
        assert_eq!(head["model"], "claude-opus-4-7");
        assert_eq!(head["model_id"], "claude-opus-4-7");
        assert_eq!(head["personality_id"], "default");
        assert_eq!(head["agent_name"], "kiro_default");
        assert_eq!(head["model_info"]["context_window_tokens"], 1_000_000);

        // user prompt
        let user = parse(body[1]);
        assert_eq!(user["type"], "user");
        assert_eq!(user["uuid"], "m_user");
        assert_eq!(user["parentUuid"], Value::Null);
        assert_eq!(user["promptId"], "m_user");
        assert_eq!(user["timestamp"], "2025-05-19T08:03:20Z");
        assert_eq!(user["message"]["content"], "do work");

        // first assistant (intermediate, with tool_use)
        let a1 = parse(body[2]);
        assert_eq!(a1["type"], "assistant");
        assert_eq!(a1["uuid"], "m_asst1");
        assert_eq!(a1["parentUuid"], "m_user");
        assert_eq!(a1["message"]["model"], "claude-opus-4-7");
        let blocks = a1["message"]["content"].as_array().unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0]["type"], "text");
        assert_eq!(blocks[0]["text"], "on it");
        assert_eq!(blocks[1]["type"], "tool_use");
        assert_eq!(blocks[1]["id"], "tu_1");
        assert_eq!(blocks[1]["name"], "shell");
        assert_eq!(blocks[1]["input"]["command"], "ls");
        // intermediate => zeroed usage, no kiro extras, null stop_reason
        assert_eq!(a1["message"]["stop_reason"], Value::Null);
        let usage = &a1["message"]["usage"];
        assert_eq!(usage["input_tokens"], 0);
        assert_eq!(usage["output_tokens"], 0);
        assert!(usage.get("kiro_metering_usage").is_none());

        // tool result
        let tr = parse(body[3]);
        assert_eq!(tr["type"], "user");
        assert_eq!(tr["uuid"], "m_tool");
        assert_eq!(tr["parentUuid"], "m_asst1");
        assert_eq!(tr["sourceToolUseID"], "tu_1");
        assert_eq!(tr["sourceToolAssistantUUID"], "m_asst1");
        let tr_block = &tr["message"]["content"][0];
        assert_eq!(tr_block["type"], "tool_result");
        assert_eq!(tr_block["tool_use_id"], "tu_1");
        assert_eq!(tr_block["is_error"], false);
        assert_eq!(tr_block["content"][0]["type"], "text");
        assert_eq!(tr_block["content"][0]["text"], "ok output");

        // final assistant (final-of-turn, carries usage)
        let a2 = parse(body[4]);
        assert_eq!(a2["uuid"], "m_asst2");
        assert_eq!(a2["parentUuid"], "m_tool");
        let blocks2 = a2["message"]["content"].as_array().unwrap();
        assert_eq!(blocks2.len(), 2);
        assert_eq!(blocks2[0]["type"], "thinking");
        assert_eq!(blocks2[0]["thinking"], "reasoning");
        assert_eq!(blocks2[0]["signature"], "sig");
        assert_eq!(blocks2[1]["type"], "text");
        assert_eq!(blocks2[1]["text"], "done");
        assert_eq!(a2["message"]["stop_reason"], "UserTurnEnd");
        let u2 = &a2["message"]["usage"];
        assert_eq!(u2["input_tokens"], 123);
        assert_eq!(u2["output_tokens"], 456);
        assert_eq!(u2["service_tier"], "standard");
        assert_eq!(u2["kiro_metering_usage"][0]["unit"], "REQUEST");
        assert_eq!(u2["kiro_context_usage_percentage"], 12.5);
        assert_eq!(u2["kiro_turn_duration_secs"], 42);
        assert_eq!(u2["kiro_end_reason"], "UserTurnEnd");
        assert_eq!(u2["kiro_number_of_cycles"], 3);
        assert_eq!(u2["kiro_total_request_count"], 4);
        assert_eq!(u2["kiro_builtin_tool_uses"], 2);
    }

    #[tokio::test]
    async fn test_tool_result_error_status_maps_to_is_error_true() {
        let home = TempDir::new().unwrap();
        let root = sessions_root_in(home.path());
        let id = "tool-err";

        let meta = r#"{"session_id":"tool-err","cwd":"/tmp"}"#;
        let transcript = concat!(
            r#"{"version":"v1","kind":"AssistantMessage","data":{"message_id":"a","content":[{"kind":"toolUse","data":{"toolUseId":"tu","name":"shell","input":{"command":"false"}}}]}}"#,
            "\n",
            r#"{"version":"v1","kind":"ToolResults","data":{"message_id":"r","content":[{"kind":"toolResult","data":{"toolUseId":"tu","content":[{"kind":"text","data":"boom"}],"status":"error"}}]}}"#,
            "\n",
        );
        write_session(&root, id, meta, transcript).await;

        let now: i64 = 1_700_000_000;
        set_file_mtime(&root.join(format!("{id}.json")), now - 5);
        set_file_mtime(&root.join(format!("{id}.jsonl")), now - 5);

        let log = discover_one(&root, now).await;
        let content = inline_content(&log);
        let body = lines(content);
        let tr = parse(body[2]);
        assert_eq!(tr["message"]["content"][0]["is_error"], true);
        assert_eq!(tr["message"]["content"][0]["tool_use_id"], "tu");
    }

    #[tokio::test]
    async fn test_compaction_emitted_as_summary_event() {
        let home = TempDir::new().unwrap();
        let root = sessions_root_in(home.path());
        let id = "comp";

        let meta = r#"{"session_id":"comp","cwd":"/tmp"}"#;
        let transcript = concat!(
            r#"{"version":"v1","kind":"Prompt","data":{"message_id":"u","content":[{"kind":"text","data":"hi"}]}}"#,
            "\n",
            r#"{"version":"v1","kind":"Compaction","data":{"summary":"OBJECTIVE\nthings\n"}}"#,
            "\n",
        );
        write_session(&root, id, meta, transcript).await;

        let now: i64 = 1_700_000_000;
        set_file_mtime(&root.join(format!("{id}.json")), now - 5);
        set_file_mtime(&root.join(format!("{id}.jsonl")), now - 5);

        let log = discover_one(&root, now).await;
        let content = inline_content(&log);
        let body = lines(content);
        assert_eq!(body.len(), 3);
        let summary = parse(body[2]);
        assert_eq!(summary["type"], "summary");
        assert_eq!(summary["summary"], "OBJECTIVE\nthings\n");
        assert_eq!(summary["parentUuid"], "u");
        assert!(summary.get("uuid").is_some());
        assert_eq!(summary["sessionId"], "comp");
    }

    #[tokio::test]
    async fn test_legacy_messages_used_when_jsonl_empty() {
        let home = TempDir::new().unwrap();
        let root = sessions_root_in(home.path());
        let id = "legacy";

        let meta = r#"{
            "session_id":"legacy","cwd":"/tmp",
            "model_id":"claude-opus-4-7",
            "messages":[
                {"role":"user","content":[{"text":"do work"}]},
                {"role":"assistant","content":[
                    {"reasoning":{"text":"think","signature":"sig"}},
                    {"text":"on it"},
                    {"toolUse":{"toolUseId":"tu","name":"shell","input":{"command":"ls"}}}
                ]},
                {"role":"user","content":[
                    {"toolResult":{"toolUseId":"tu","content":[{"text":"ok"}],"status":"success"}}
                ]},
                {"role":"assistant","content":[{"text":"done"}]}
            ]
        }"#;
        // .jsonl is intentionally empty.
        write_session(&root, id, meta, "").await;

        let now: i64 = 1_700_000_000;
        set_file_mtime(&root.join(format!("{id}.json")), now - 5);
        set_file_mtime(&root.join(format!("{id}.jsonl")), now - 5);

        let log = discover_one(&root, now).await;
        let content = inline_content(&log);
        let body = lines(content);
        assert_eq!(body.len(), 5, "header + 4 events");

        let user = parse(body[1]);
        assert_eq!(user["type"], "user");
        assert_eq!(user["message"]["content"], "do work");

        let asst = parse(body[2]);
        assert_eq!(asst["type"], "assistant");
        let blocks = asst["message"]["content"].as_array().unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0]["type"], "thinking");
        assert_eq!(blocks[0]["thinking"], "think");
        assert_eq!(blocks[1]["type"], "text");
        assert_eq!(blocks[1]["text"], "on it");
        assert_eq!(blocks[2]["type"], "tool_use");
        assert_eq!(blocks[2]["id"], "tu");

        let tr = parse(body[3]);
        assert_eq!(tr["type"], "user");
        assert_eq!(tr["sourceToolUseID"], "tu");
        assert_eq!(tr["sourceToolAssistantUUID"], asst["uuid"]);
        assert_eq!(tr["message"]["content"][0]["type"], "tool_result");
        assert_eq!(tr["message"]["content"][0]["is_error"], false);

        let final_asst = parse(body[4]);
        assert_eq!(final_asst["type"], "assistant");
        assert_eq!(final_asst["message"]["content"][0]["text"], "done");
    }

    #[tokio::test]
    async fn test_malformed_jsonl_lines_are_skipped() {
        let home = TempDir::new().unwrap();
        let root = sessions_root_in(home.path());
        let id = "junk";

        let meta = r#"{"session_id":"junk","cwd":"/tmp"}"#;
        // First line is invalid JSON, second is valid Prompt.
        let transcript = concat!(
            "this is not json\n",
            r#"{"version":"v1","kind":"Prompt","data":{"message_id":"u","content":[{"kind":"text","data":"hi"}]}}"#,
            "\n",
        );
        write_session(&root, id, meta, transcript).await;

        let now: i64 = 1_700_000_000;
        set_file_mtime(&root.join(format!("{id}.json")), now - 5);
        set_file_mtime(&root.join(format!("{id}.jsonl")), now - 5);

        let log = discover_one(&root, now).await;
        let content = inline_content(&log);
        let body = lines(content);
        assert_eq!(body.len(), 2, "junk line dropped; header + Prompt remain");
        let user = parse(body[1]);
        assert_eq!(user["type"], "user");
    }

    #[tokio::test]
    async fn test_meta_timestamp_used_when_present_else_turn_end_else_mtime() {
        let home = TempDir::new().unwrap();
        let root = sessions_root_in(home.path());
        let id = "ts";

        // Two turns: turn 0 has end_timestamp, turn 1 omits it. Prompt of
        // turn 0 carries data.meta.timestamp (preferred over turn end).
        let meta = r#"{
            "session_id":"ts","cwd":"/tmp","model_id":"m",
            "session_state":{"conversation_metadata":{
                "user_turn_metadatas":[
                    {"message_ids":["u1","a1"],"result":{"Ok":{"id":"a1","role":"assistant","content":[]}},
                     "input_token_count":1,"output_token_count":2,
                     "end_reason":"UserTurnEnd","end_timestamp":"2026-01-02T03:04:05Z"},
                    {"message_ids":["u2","a2"],"result":{"Ok":{"id":"a2","role":"assistant","content":[]}},
                     "input_token_count":3,"output_token_count":4,"end_reason":"UserTurnEnd"}
                ]
            }}
        }"#;
        let transcript = concat!(
            r#"{"version":"v1","kind":"Prompt","data":{"message_id":"u1","content":[{"kind":"text","data":"a"}],"meta":{"timestamp":1700000000}}}"#,
            "\n",
            r#"{"version":"v1","kind":"AssistantMessage","data":{"message_id":"a1","content":[{"kind":"text","data":"x"}]}}"#,
            "\n",
            r#"{"version":"v1","kind":"Prompt","data":{"message_id":"u2","content":[{"kind":"text","data":"b"}]}}"#,
            "\n",
            r#"{"version":"v1","kind":"AssistantMessage","data":{"message_id":"a2","content":[{"kind":"text","data":"y"}]}}"#,
            "\n",
        );
        write_session(&root, id, meta, transcript).await;

        let now: i64 = 1_750_000_000;
        let file_mtime = now - 5;
        set_file_mtime(&root.join(format!("{id}.json")), file_mtime);
        set_file_mtime(&root.join(format!("{id}.jsonl")), file_mtime);

        let log = discover_one(&root, now).await;
        let body = lines(inline_content(&log));
        let u1 = parse(body[1]);
        let a1 = parse(body[2]);
        let u2 = parse(body[3]);
        let a2 = parse(body[4]);

        // u1: data.meta.timestamp (1700000000)
        assert_eq!(u1["timestamp"], "2023-11-14T22:13:20Z");
        // a1: turn 0 end_timestamp
        assert_eq!(a1["timestamp"], "2026-01-02T03:04:05Z");
        // u2: no meta.timestamp, no turn end_timestamp -> file mtime
        assert_eq!(u2["timestamp"], epoch_to_rfc3339(file_mtime));
        // a2: same fallback (turn 1 has no end_timestamp)
        assert_eq!(a2["timestamp"], epoch_to_rfc3339(file_mtime));
    }
}
