//! Session scanning and metadata extraction.
//!
//! Parses session logs to extract lightweight metadata and timestamps
//! without loading unnecessary structure into the ingest pipeline.

use std::io::{BufRead, BufReader, Cursor};
use std::path::{MAIN_SEPARATOR, Path, PathBuf};
#[cfg(test)]
use time::OffsetDateTime;
#[cfg(test)]
use time::format_description::well_known::Rfc3339;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The type of AI agent that produced a session log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentType {
    Claude,
    Codex,
    Cursor,
    Copilot,
    Cline,
    RooCode,
    OpenCode,
    Kiro,
    AmpCode,
    Antigravity,
    Windsurf,
    Warp,
}

impl std::fmt::Display for AgentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentType::Claude => write!(f, "claude-code"),
            AgentType::Codex => write!(f, "codex"),
            AgentType::Cursor => write!(f, "cursor"),
            AgentType::Copilot => write!(f, "copilot"),
            AgentType::Cline => write!(f, "cline"),
            AgentType::RooCode => write!(f, "roo-code"),
            AgentType::OpenCode => write!(f, "opencode"),
            AgentType::Kiro => write!(f, "kiro"),
            AgentType::AmpCode => write!(f, "amp-code"),
            AgentType::Antigravity => write!(f, "antigravity"),
            AgentType::Windsurf => write!(f, "windsurf"),
            AgentType::Warp => write!(f, "warp"),
        }
    }
}

/// Minimal metadata parsed from a session log file.
///
/// Not every field is guaranteed to be present -- session logs vary
/// in structure. Fields are `Option` to handle missing data gracefully.
#[derive(Debug, Clone, Default)]
pub struct SessionMetadata {
    /// The session ID (UUID or similar identifier).
    pub session_id: Option<String>,
    /// The working directory where the agent was running.
    pub cwd: Option<String>,
    /// The agent type, if determinable from the log content.
    pub agent_type: Option<AgentType>,
}

const CLAUDE_PATH_DECODE_MAX_CANDIDATES: usize = 65_536;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse minimal metadata from a session log file.
///
/// Reads the file line-by-line, attempting to parse each line as JSON
/// and extracting known fields:
/// - `session_id` (or `sessionId`)
/// - `cwd` (or `workdir`, `working_directory`)
/// - `type` field that may indicate the agent
///
/// This is best-effort: not every line will be valid JSON, and not
/// every JSON line will contain the fields we need. The function
/// accumulates fields across all lines. `session_id` is first-value-wins,
/// while `cwd` prefers the most recent direct cwd/workdir field so later
/// worktree handoff records can override stale earlier values.
pub async fn parse_session_metadata(file: &Path) -> SessionMetadata {
    let content = match tokio::fs::read_to_string(file).await {
        Ok(c) => c,
        Err(_) => return SessionMetadata::default(),
    };
    parse_session_metadata_with_content(file, &content).await
}

pub async fn parse_session_metadata_with_content(file: &Path, content: &str) -> SessionMetadata {
    let mut metadata = parse_session_metadata_str(content);
    let agent_type = infer_agent_type(file);

    apply_metadata_from_path(&mut metadata, file, &agent_type).await;
    metadata.agent_type = Some(agent_type);

    metadata
}

/// Parse minimal metadata from a session log string.
pub fn parse_session_metadata_str(content: &str) -> SessionMetadata {
    let metadata = SessionMetadata::default();
    let metadata = parse_session_metadata_reader(BufReader::new(Cursor::new(content)), metadata);
    let mut metadata = metadata;

    if (metadata.session_id.is_none() || metadata.cwd.is_none())
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(content)
    {
        apply_metadata_from_value(&mut metadata, &value);
    }

    metadata
}

#[cfg(test)]
/// Extract the session time range (start, end) from a session log file.
///
/// Scans each line as JSON and looks for known timestamp keys:
/// - Top-level: `timestamp`, `time`, `created_at`, `createdAt`
/// - Nested under `payload`: `timestamp`, `created_at`, `createdAt`
///
/// Parses RFC3339/ISO8601 timestamps and returns the min/max epoch seconds.
/// Returns `None` if no parseable timestamps are found.
pub async fn session_time_range(file: &Path) -> Option<(i64, i64)> {
    let content = tokio::fs::read_to_string(file).await.ok()?;
    let reader = BufReader::new(Cursor::new(content.as_bytes()));
    let range = session_time_range_reader(reader);

    if range.is_none()
        && let Some(value) = read_json_value(file).await
    {
        return session_time_range_from_value(&value);
    }

    range
}

#[cfg(test)]
/// Extract the session time range (start, end) from a session log string.
pub fn session_time_range_str(content: &str) -> Option<(i64, i64)> {
    let reader = BufReader::new(Cursor::new(content));
    let range = session_time_range_reader(reader);

    if range.is_none()
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(content)
    {
        return session_time_range_from_value(&value);
    }

    range
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Infer the agent type from a file path using ordered substring matches.
///
/// Match precedence is significant for overlapping paths:
/// 1. Codex (`.codex`)
/// 2. OpenCode data roots
/// 3. Cline extension/storage paths
/// 4. Roo Code extension/storage paths
/// 5. Kiro storage paths
/// 6. Amp Code paths
/// 7. Cursor paths
/// 8. Antigravity paths
/// 9. Windsurf paths
/// 10. Warp paths
/// 11. VS Code / Copilot workspace storage
/// 12. Fallback to Claude
fn infer_agent_type(path: &Path) -> AgentType {
    let path_str = path.to_string_lossy().replace('\\', "/");
    let path_lower = path_str.to_ascii_lowercase();
    if path_lower.contains(".codex") {
        AgentType::Codex
    } else if path_lower.contains("/.local/share/opencode/")
        || path_lower.contains("/opencode/storage/")
        || path_lower.contains("/opencode/log/")
        || path_lower.ends_with("/opencode/opencode.db")
        || path_lower.contains("/library/application support/opencode/")
        || path_lower.contains("/appdata/roaming/opencode/")
    {
        AgentType::OpenCode
    } else if path_lower.contains("/.cline/")
        || path_lower.contains("/saoudrizwan.claude-dev/")
        || path_lower.contains("/cline.cline/")
    {
        AgentType::Cline
    } else if path_lower.contains("/.roo/")
        || path_lower.contains("/rooveterinaryinc.roo-cline/")
        || path_lower.contains("/roocode.roo-code/")
    {
        AgentType::RooCode
    } else if path_lower
        .contains("/library/application support/kiro/user/globalstorage/kiro.kiroagent/")
        || path_lower.contains("/.config/kiro/user/globalstorage/kiro.kiroagent/")
        || path_lower.contains("/appdata/roaming/kiro/user/globalstorage/kiro.kiroagent/")
    {
        AgentType::Kiro
    } else if path_lower.contains("/.local/share/amp/threads/")
        || path_lower.contains("/.amp/file-changes/")
        || path_lower.contains("/appdata/roaming/amp/threads/")
    {
        AgentType::AmpCode
    } else if path_lower.contains(".cursor") || path_lower.contains("/cursor/") {
        AgentType::Cursor
    } else if path_lower.contains("/antigravity/")
        || path_lower.contains("/antigravity-api/")
        || path_lower.contains("/.cadence/cli/antigravity-api/")
    {
        AgentType::Antigravity
    } else if path_lower.contains("/.codeium/windsurf/")
        || path_lower.contains("/windsurf-api/")
        || path_lower.contains("/library/application support/windsurf/")
        || path_lower.contains("/.config/windsurf/")
        || path_lower.contains("/appdata/roaming/windsurf/")
        || path_lower.contains("/windsurf/user/workspacestorage/")
    {
        AgentType::Windsurf
    } else if path_lower.contains("warp.sqlite") || path_lower.contains("/warp/") {
        AgentType::Warp
    } else if path_lower.contains("/code/") {
        AgentType::Copilot
    } else {
        // Default to Claude -- `.claude` paths and unknown paths
        AgentType::Claude
    }
}

#[cfg(test)]
/// Parse a timestamp value into epoch seconds.
fn parse_timestamp(value: &serde_json::Value) -> Option<i64> {
    let s = value.as_str()?;
    let dt = OffsetDateTime::parse(s, &Rfc3339).ok()?;
    Some(dt.unix_timestamp())
}

#[cfg(test)]
fn parse_numeric_timestamp(value: &serde_json::Value) -> Option<i64> {
    let num = value.as_i64()?;
    if num <= 0 {
        return None;
    }
    if num > 1_000_000_000_000 {
        Some(num / 1000)
    } else {
        Some(num)
    }
}

#[cfg(test)]
async fn read_json_value(file: &Path) -> Option<serde_json::Value> {
    let content = tokio::fs::read_to_string(file).await.ok()?;
    serde_json::from_str(&content).ok()
}

async fn apply_metadata_from_path(
    metadata: &mut SessionMetadata,
    file: &Path,
    agent_type: &AgentType,
) {
    let Some(project_dir) = claude_project_dir(file, agent_type) else {
        return;
    };

    let recovered_session_id = file
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|id| !id.is_empty());
    if metadata.session_id.is_some() {
        // Keep the first parsed ID when the log already provided one.
    } else if let Some(id) = recovered_session_id {
        ::tracing::trace!(
            recovered_session_id = %id,
            path = %file.display(),
            "inferred session_id from Claude project path"
        );
        metadata.session_id = Some(id.to_string());
    }

    let recovered_cwd = if metadata.cwd.is_none() {
        infer_claude_project_cwd(project_dir).await
    } else {
        None
    };
    if let Some(cwd) = recovered_cwd {
        ::tracing::trace!(
            recovered_cwd = %cwd,
            path = %file.display(),
            "inferred cwd from Claude project directory name"
        );
        metadata.cwd = Some(cwd);
    }
}

fn claude_project_dir<'a>(file: &'a Path, agent_type: &AgentType) -> Option<&'a Path> {
    if *agent_type != AgentType::Claude {
        return None;
    }

    let project_dir = file.parent()?;
    let projects_dir = project_dir.parent()?;
    let claude_dir = projects_dir.parent()?;
    let encoded = project_dir.file_name()?.to_str()?;

    if projects_dir.file_name().and_then(|name| name.to_str()) != Some("projects")
        || claude_dir.file_name().and_then(|name| name.to_str()) != Some(".claude")
        || !encoded.starts_with('-')
        || encoded.len() <= 1
        || encoded.contains('/')
        || encoded.contains('\\')
    {
        return None;
    }

    Some(project_dir)
}

async fn infer_claude_project_cwd(project_dir: &Path) -> Option<String> {
    let encoded = project_dir.file_name()?.to_str()?;
    let decoded = decode_hyphenated_absolute_path(encoded).await?;
    Some(decoded.to_string_lossy().to_string())
}

fn initial_hyphenated_path_state(trimmed: &str) -> (PathBuf, usize) {
    if MAIN_SEPARATOR == '\\' {
        let bytes = trimmed.as_bytes();
        if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() {
            let drive = char::from(bytes[0]);
            if bytes[1] == b':' && bytes[2] == b'-' {
                return (PathBuf::from(format!("{drive}:{MAIN_SEPARATOR}")), 3);
            }
            if bytes[1] == b'-' && bytes[2] == b'-' {
                return (PathBuf::from(format!("{drive}:{MAIN_SEPARATOR}")), 3);
            }
        }
    }

    (PathBuf::from(MAIN_SEPARATOR.to_string()), 0)
}

async fn decode_hyphenated_absolute_path(encoded: &str) -> Option<PathBuf> {
    let trimmed = encoded.strip_prefix('-')?;
    if trimmed.is_empty() {
        return None;
    }

    let mut stack = vec![initial_hyphenated_path_state(trimmed)];
    let mut checked_candidates = 0usize;
    while let Some((prefix, start_idx)) = stack.pop() {
        if start_idx >= trimmed.len() {
            return Some(prefix);
        }

        let mut next = Vec::new();
        let bytes = trimmed.as_bytes();
        for end_idx in (start_idx + 1..=trimmed.len()).rev() {
            if end_idx != trimmed.len() && bytes[end_idx] != b'-' {
                continue;
            }

            checked_candidates += 1;
            if checked_candidates > CLAUDE_PATH_DECODE_MAX_CANDIDATES {
                return None;
            }

            let segment = &trimmed[start_idx..end_idx];
            if segment.is_empty() {
                continue;
            }

            let candidate = prefix.join(segment);
            if tokio::fs::try_exists(&candidate).await.unwrap_or(false) {
                let next_idx = if end_idx == trimmed.len() {
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

fn parse_session_metadata_reader<R: BufRead>(
    reader: R,
    mut metadata: SessionMetadata,
) -> SessionMetadata {
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        // Attempt to parse as JSON
        let value: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        apply_metadata_from_value(&mut metadata, &value);
    }

    metadata
}

fn apply_metadata_from_value(metadata: &mut SessionMetadata, value: &serde_json::Value) {
    // Extract session_id (top-level or nested under payload for Codex)
    if metadata.session_id.is_none()
        && let Some(id) = value
            .get("session_id")
            .or_else(|| value.get("sessionId"))
            .or_else(|| value.get("sessionID"))
            .or_else(|| value.get("taskId"))
            .or_else(|| value.pointer("/payload/id"))
            .and_then(|v| v.as_str())
    {
        metadata.session_id = Some(id.to_string());
    }

    // Extract cwd / workdir (top-level or nested under payload for Codex)
    let mut saw_direct_cwd = false;
    if let Some(cwd) = value
        .get("cwd")
        .or_else(|| value.get("workdir"))
        .or_else(|| value.get("working_directory"))
        .or_else(|| value.get("directory"))
        .or_else(|| value.get("workspaceDirectory"))
        .or_else(|| value.get("workspacePath"))
        .or_else(|| value.pointer("/payload/cwd"))
        .and_then(|v| v.as_str())
    {
        metadata.cwd = Some(cwd.to_string());
        saw_direct_cwd = true;
    }

    if metadata.session_id.is_none()
        && let Some(id) = value.get("sessionId").and_then(|v| v.as_str())
    {
        metadata.session_id = Some(id.to_string());
    }
    if metadata.session_id.is_none()
        && let Some(id) = value.get("id").and_then(|v| v.as_str())
        && (id.starts_with("ses_")
            || (id.starts_with("T-") && value.get("messages").and_then(|v| v.as_array()).is_some()))
    {
        metadata.session_id = Some(id.to_string());
    }

    if !saw_direct_cwd && let Some(path) = extract_cwd_from_value(value) {
        metadata.cwd = Some(path);
    }
}

#[cfg(test)]
fn session_time_range_reader<R: BufRead>(reader: R) -> Option<(i64, i64)> {
    let mut min_ts: Option<i64> = None;
    let mut max_ts: Option<i64> = None;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        let value: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let candidates = [
            value.get("timestamp"),
            value.get("time"),
            value.get("created_at"),
            value.get("createdAt"),
            value.get("creationDate"),
            value.get("lastMessageDate"),
            value.pointer("/payload/timestamp"),
            value.pointer("/payload/created_at"),
            value.pointer("/payload/createdAt"),
        ];

        for candidate in candidates.iter().flatten() {
            if let Some(ts) =
                parse_timestamp(candidate).or_else(|| parse_numeric_timestamp(candidate))
            {
                min_ts = Some(min_ts.map_or(ts, |min| min.min(ts)));
                max_ts = Some(max_ts.map_or(ts, |max| max.max(ts)));
            }
        }
    }

    match (min_ts, max_ts) {
        (Some(min), Some(max)) => Some((min, max)),
        _ => None,
    }
}

#[cfg(test)]
fn session_time_range_from_value(value: &serde_json::Value) -> Option<(i64, i64)> {
    let mut all = Vec::new();
    collect_timestamp_candidates(value, &mut all);
    let mut min_ts: Option<i64> = None;
    let mut max_ts: Option<i64> = None;
    for candidate in all {
        if let Some(ts) =
            parse_timestamp(&candidate).or_else(|| parse_numeric_timestamp(&candidate))
        {
            min_ts = Some(min_ts.map_or(ts, |min| min.min(ts)));
            max_ts = Some(max_ts.map_or(ts, |max| max.max(ts)));
        }
    }
    match (min_ts, max_ts) {
        (Some(min), Some(max)) => Some((min, max)),
        _ => None,
    }
}

fn extract_cwd_from_value(value: &serde_json::Value) -> Option<String> {
    if let Some(path) = value.pointer("/baseUri/fsPath").and_then(|v| v.as_str()) {
        return Some(normalize_cwd_path(path));
    }
    if let Some(path) = value.pointer("/baseUri/path").and_then(|v| v.as_str()) {
        return Some(normalize_cwd_path(path));
    }

    if let Some(requests) = value.get("requests").and_then(|v| v.as_array()) {
        for request in requests {
            if let Some(path) = request
                .pointer("/variableData/variables")
                .and_then(|v| v.as_array())
                .and_then(|vars| {
                    vars.iter().find_map(|var| {
                        var.pointer("/value/uri/fsPath")
                            .or_else(|| var.pointer("/value/uri/path"))
                            .and_then(|v| v.as_str())
                    })
                })
            {
                return Some(normalize_cwd_path(path));
            }

            if let Some(path) = request
                .pointer("/response")
                .and_then(|v| v.as_array())
                .and_then(|responses| {
                    responses.iter().find_map(|resp| {
                        resp.pointer("/baseUri/fsPath")
                            .or_else(|| resp.pointer("/baseUri/path"))
                            .and_then(|v| v.as_str())
                    })
                })
            {
                return Some(normalize_cwd_path(path));
            }
        }
    }

    if let Some(trees) = value
        .pointer("/env/initial/trees")
        .and_then(|v| v.as_array())
    {
        for tree in trees {
            if let Some(uri) = tree.get("uri").and_then(|v| v.as_str()) {
                return Some(normalize_cwd_path(uri));
            }
        }
    }

    None
}

fn normalize_cwd_path(path: &str) -> String {
    let trimmed = strip_file_uri_prefix(path);
    let candidate = Path::new(trimmed);
    if looks_like_file(candidate) {
        candidate
            .parent()
            .unwrap_or(candidate)
            .to_string_lossy()
            .to_string()
    } else {
        candidate.to_string_lossy().to_string()
    }
}

fn strip_file_uri_prefix(path: &str) -> &str {
    let Some(mut trimmed) = path.strip_prefix("file://") else {
        return path;
    };

    if let Some(local_path) = trimmed.strip_prefix("localhost/") {
        trimmed = local_path;
    }

    if let Some(without_leading_slash) = trimmed.strip_prefix('/')
        && is_windows_drive_path(without_leading_slash)
    {
        return without_leading_slash;
    }

    trimmed
}

fn is_windows_drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\')
}

fn looks_like_file(path: &Path) -> bool {
    if path.extension().is_some() {
        return true;
    }
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        return name.contains('.');
    }
    false
}

#[cfg(test)]
fn collect_timestamp_candidates(value: &serde_json::Value, out: &mut Vec<serde_json::Value>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                match key.as_str() {
                    "timestamp" | "time" | "created_at" | "createdAt" | "creationDate"
                    | "lastMessageDate" => out.push(val.clone()),
                    _ => {}
                }
                collect_timestamp_candidates(val, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_timestamp_candidates(item, out);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::MAIN_SEPARATOR;
    use tempfile::TempDir;
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    // -----------------------------------------------------------------------
    // Helper: create a temp file with given content
    // -----------------------------------------------------------------------

    async fn write_temp_file(dir: &Path, name: &str, content: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        tokio::fs::write(&path, content)
            .await
            .expect("failed to write temp file");
        path
    }

    fn encode_claude_project_path(path: &Path) -> String {
        let raw = path.to_string_lossy();
        let normalized = raw.replace('\\', "/");
        let encoded = if let Some(without_drive_root) = normalized
            .strip_prefix(|c: char| c.is_ascii_alphabetic())
            .and_then(|rest| rest.strip_prefix(":/"))
        {
            format!(
                "{}--{}",
                normalized.chars().next().unwrap_or_default(),
                without_drive_root.replace('/', "-")
            )
        } else {
            normalized.replace('/', "-")
        };
        if encoded.starts_with('-') {
            encoded
        } else {
            format!("-{encoded}")
        }
    }

    // -----------------------------------------------------------------------
    // infer_agent_type
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_infer_agent_type_claude() {
        let path = Path::new("/Users/foo/.claude/projects/-Users-foo-bar/session.jsonl");
        assert_eq!(infer_agent_type(path), AgentType::Claude);
    }

    #[tokio::test]
    async fn test_infer_agent_type_codex() {
        let path = Path::new("/Users/foo/.codex/sessions/abc123/session.jsonl");
        assert_eq!(infer_agent_type(path), AgentType::Codex);
    }

    #[tokio::test]
    async fn test_infer_agent_type_cline() {
        let path = Path::new(
            "/Users/foo/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/tasks/x/task.json",
        );
        assert_eq!(infer_agent_type(path), AgentType::Cline);
    }

    #[tokio::test]
    async fn test_infer_agent_type_roo_code() {
        let path = Path::new(
            "/Users/foo/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/tasks/x/task.json",
        );
        assert_eq!(infer_agent_type(path), AgentType::RooCode);
    }

    #[tokio::test]
    async fn test_infer_agent_type_opencode() {
        let path =
            Path::new("/Users/foo/.local/share/opencode/storage/session/global/ses_abc.json");
        assert_eq!(infer_agent_type(path), AgentType::OpenCode);
    }

    #[tokio::test]
    async fn test_infer_agent_type_kiro() {
        let path = Path::new(
            "/Users/foo/Library/Application Support/Kiro/User/globalStorage/kiro.kiroagent/workspace-sessions/x/session.json",
        );
        assert_eq!(infer_agent_type(path), AgentType::Kiro);
    }

    #[tokio::test]
    async fn test_infer_agent_type_amp_code() {
        let path = Path::new("/Users/foo/.local/share/amp/threads/T-abc.json");
        assert_eq!(infer_agent_type(path), AgentType::AmpCode);
    }

    #[tokio::test]
    async fn test_infer_agent_type_cursor() {
        let path = Path::new(
            "/Users/foo/Library/Application Support/Cursor/User/workspaceStorage/x/chatSessions/session.json",
        );
        assert_eq!(infer_agent_type(path), AgentType::Cursor);
    }

    #[tokio::test]
    async fn test_infer_agent_type_cline_wins_over_cursor_for_ambiguous_path() {
        let path = Path::new(
            "/Users/foo/Library/Application Support/Cursor/User/globalStorage/saoudrizwan.claude-dev/tasks/x/task.json",
        );
        assert_eq!(infer_agent_type(path), AgentType::Cline);
    }

    #[tokio::test]
    async fn test_infer_agent_type_copilot() {
        let path = Path::new(
            "/Users/foo/Library/Application Support/Code/User/workspaceStorage/x/chatSessions/session.json",
        );
        assert_eq!(infer_agent_type(path), AgentType::Copilot);
    }

    #[tokio::test]
    async fn test_infer_agent_type_antigravity() {
        let path = Path::new(
            "/Users/foo/Library/Application Support/Antigravity/User/workspaceStorage/x/chatSessions/session.json",
        );
        assert_eq!(infer_agent_type(path), AgentType::Antigravity);
    }

    #[tokio::test]
    async fn test_infer_agent_type_antigravity_api_cache() {
        let path = Path::new("/Users/foo/.cadence/cli/antigravity-api/abc.json");
        assert_eq!(infer_agent_type(path), AgentType::Antigravity);
    }

    #[tokio::test]
    async fn test_infer_agent_type_windsurf() {
        let path = Path::new("/Users/foo/.codeium/windsurf/cascade/abc.pb");
        assert_eq!(infer_agent_type(path), AgentType::Windsurf);
    }

    #[tokio::test]
    async fn test_infer_agent_type_windsurf_api_cache() {
        let path = Path::new("/Users/foo/.cadence/cli/windsurf-api/abc.json");
        assert_eq!(infer_agent_type(path), AgentType::Windsurf);
    }

    #[tokio::test]
    async fn test_infer_agent_type_windsurf_linux_workspace_storage() {
        let path = Path::new(
            "/home/foo/.config/Windsurf/User/workspaceStorage/x/chatSessions/session.json",
        );
        assert_eq!(infer_agent_type(path), AgentType::Windsurf);
    }

    #[tokio::test]
    async fn test_infer_agent_type_windsurf_windows_workspace_storage() {
        let path = Path::new(
            "C:\\Users\\foo\\AppData\\Roaming\\Windsurf\\User\\workspaceStorage\\x\\chatSessions\\session.json",
        );
        assert_eq!(infer_agent_type(path), AgentType::Windsurf);
    }

    #[test]
    fn test_infer_agent_type_warp() {
        let path = Path::new(
            "/Users/foo/Library/Group Containers/2BBY89MBSN.dev.warp/Library/Application Support/dev.warp.Warp-Stable/warp.sqlite",
        );
        assert_eq!(infer_agent_type(path), AgentType::Warp);
    }

    #[tokio::test]
    async fn test_infer_agent_type_unknown_defaults_to_claude() {
        let path = Path::new("/tmp/some/random/session.jsonl");
        assert_eq!(infer_agent_type(path), AgentType::Claude);
    }

    // -----------------------------------------------------------------------
    // AgentType display
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_agent_type_display_claude() {
        assert_eq!(AgentType::Claude.to_string(), "claude-code");
    }

    #[tokio::test]
    async fn test_agent_type_display_codex() {
        assert_eq!(AgentType::Codex.to_string(), "codex");
    }

    #[tokio::test]
    async fn test_agent_type_display_cursor() {
        assert_eq!(AgentType::Cursor.to_string(), "cursor");
    }

    #[tokio::test]
    async fn test_agent_type_display_copilot() {
        assert_eq!(AgentType::Copilot.to_string(), "copilot");
    }

    #[tokio::test]
    async fn test_agent_type_display_cline() {
        assert_eq!(AgentType::Cline.to_string(), "cline");
    }

    #[tokio::test]
    async fn test_agent_type_display_roo_code() {
        assert_eq!(AgentType::RooCode.to_string(), "roo-code");
    }

    #[tokio::test]
    async fn test_agent_type_display_opencode() {
        assert_eq!(AgentType::OpenCode.to_string(), "opencode");
    }

    #[tokio::test]
    async fn test_agent_type_display_kiro() {
        assert_eq!(AgentType::Kiro.to_string(), "kiro");
    }

    #[tokio::test]
    async fn test_agent_type_display_amp_code() {
        assert_eq!(AgentType::AmpCode.to_string(), "amp-code");
    }

    #[tokio::test]
    async fn test_agent_type_display_antigravity() {
        assert_eq!(AgentType::Antigravity.to_string(), "antigravity");
    }

    #[tokio::test]
    async fn test_agent_type_display_windsurf() {
        assert_eq!(AgentType::Windsurf.to_string(), "windsurf");
    }

    #[test]
    fn test_agent_type_display_warp() {
        assert_eq!(AgentType::Warp.to_string(), "warp");
    }

    // -----------------------------------------------------------------------
    // parse_session_metadata
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_parse_metadata_session_id_and_cwd() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"session_id":"abc-123","cwd":"/Users/foo/bar"}
{"type":"message","content":"hello"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("abc-123".to_string()));
        assert_eq!(metadata.cwd, Some("/Users/foo/bar".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_camel_case_session_id() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"sessionId":"def-456","cwd":"/Users/baz"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("def-456".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_workdir_field() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"workdir":"/home/user/project"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.cwd, Some("/home/user/project".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_working_directory_field() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"working_directory":"/opt/app"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.cwd, Some("/opt/app".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_opencode_fields() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"id":"ses_123","sessionID":"ses_123","directory":"/Users/foo/dev/repo"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("ses_123".to_string()));
        assert_eq!(metadata.cwd, Some("/Users/foo/dev/repo".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_kiro_fields() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"sessionId":"kiro-1","workspaceDirectory":"/Users/foo/dev/kiro-repo"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("kiro-1".to_string()));
        assert_eq!(metadata.cwd, Some("/Users/foo/dev/kiro-repo".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_amp_fields() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"id":"T-123","messages":[],"env":{"initial":{"trees":[{"uri":"file:///Users/foo/dev/cadence-cli"}]}}}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("T-123".to_string()));
        assert_eq!(metadata.cwd, Some("/Users/foo/dev/cadence-cli".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_amp_fields_windows_file_uri() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"id":"T-456","messages":[],"env":{"initial":{"trees":[{"uri":"file:///C:/Users/foo/dev/cadence-cli"}]}}}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("T-456".to_string()));
        assert_eq!(
            metadata.cwd,
            Some("C:/Users/foo/dev/cadence-cli".to_string())
        );
    }

    #[tokio::test]
    async fn test_parse_metadata_cline_task_id() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"taskId":"task-123","workspacePath":"/Users/foo/dev/repo"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("task-123".to_string()));
        assert_eq!(metadata.cwd, Some("/Users/foo/dev/repo".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_chat_session_json() {
        let dir = TempDir::new().unwrap();
        let content = r#"{
  "sessionId": "chat-123",
  "requests": [
    {
      "variableData": {
        "variables": [
          {
            "value": {
              "uri": {
                "fsPath": "/Users/foo/dev/my-repo/src/main.rs"
              }
            }
          }
        ]
      }
    }
  ]
}"#;
        let file = write_temp_file(dir.path(), "session.json", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("chat-123".to_string()));
        assert_eq!(metadata.cwd, Some("/Users/foo/dev/my-repo/src".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_fields_across_multiple_lines() {
        let dir = TempDir::new().unwrap();
        // session_id on one line, cwd on another
        let content = r#"{"session_id":"multi-line-id"}
{"type":"other"}
{"cwd":"/Users/foo/repo"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("multi-line-id".to_string()));
        assert_eq!(metadata.cwd, Some("/Users/foo/repo".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_no_fields() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"type":"message","content":"no metadata here"}
{"type":"tool_result","content":"more stuff"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, None);
        assert_eq!(metadata.cwd, None);
    }

    #[tokio::test]
    async fn test_parse_metadata_invalid_json_lines_skipped() {
        let dir = TempDir::new().unwrap();
        let content = r#"this is not json
{"session_id":"valid-id"}
also not json {{{{
{"cwd":"/valid/path"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("valid-id".to_string()));
        assert_eq!(metadata.cwd, Some("/valid/path".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_empty_file() {
        let dir = TempDir::new().unwrap();
        let file = write_temp_file(dir.path(), "empty.jsonl", "").await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, None);
        assert_eq!(metadata.cwd, None);
    }

    #[tokio::test]
    async fn test_parse_metadata_nonexistent_file() {
        let path = Path::new("/nonexistent/file.jsonl");
        let metadata = parse_session_metadata(path).await;

        assert_eq!(metadata.session_id, None);
        assert_eq!(metadata.cwd, None);
    }

    #[tokio::test]
    async fn test_parse_metadata_agent_type_from_claude_path() {
        let dir = TempDir::new().unwrap();
        let claude_dir = dir.path().join(".claude").join("projects");
        tokio::fs::create_dir_all(&claude_dir).await.unwrap();
        let file = write_temp_file(&claude_dir, "session.jsonl", "{}").await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.agent_type, Some(AgentType::Claude));
    }

    #[tokio::test]
    async fn test_parse_metadata_agent_type_from_codex_path() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex").join("sessions");
        tokio::fs::create_dir_all(&codex_dir).await.unwrap();
        let file = write_temp_file(&codex_dir, "session.jsonl", "{}").await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.agent_type, Some(AgentType::Codex));
    }

    #[tokio::test]
    async fn test_parse_metadata_agent_type_from_opencode_path() {
        let dir = TempDir::new().unwrap();
        let opencode_dir = dir.path().join(".local").join("share").join("opencode");
        tokio::fs::create_dir_all(&opencode_dir).await.unwrap();
        let file = write_temp_file(&opencode_dir, "session.json", "{}").await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.agent_type, Some(AgentType::OpenCode));
    }

    #[tokio::test]
    async fn test_parse_metadata_agent_type_from_opencode_custom_xdg_path() {
        let dir = TempDir::new().unwrap();
        let opencode_dir = dir
            .path()
            .join("custom-data")
            .join("opencode")
            .join("storage")
            .join("session");
        tokio::fs::create_dir_all(&opencode_dir).await.unwrap();
        let file = write_temp_file(&opencode_dir, "session.json", "{}").await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.agent_type, Some(AgentType::OpenCode));
    }

    #[tokio::test]
    async fn test_parse_metadata_infers_claude_session_id_and_cwd_from_path() {
        let dir = TempDir::new().unwrap();
        let repo_root = dir.path().join("work").join("git-context-explorer");
        tokio::fs::create_dir_all(&repo_root).await.unwrap();

        let encoded = encode_claude_project_path(&repo_root);
        let claude_dir = dir.path().join(".claude").join("projects").join(encoded);
        tokio::fs::create_dir_all(&claude_dir).await.unwrap();

        let file = write_temp_file(
            &claude_dir,
            "042afd87-a800-4248-8234-5e9222dd6f22.jsonl",
            "{}",
        )
        .await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(
            metadata.session_id,
            Some("042afd87-a800-4248-8234-5e9222dd6f22".to_string())
        );
        assert_eq!(metadata.cwd, Some(repo_root.to_string_lossy().to_string()));
    }

    #[tokio::test]
    async fn test_decode_hyphenated_absolute_path_handles_hyphenated_segments() {
        let dir = TempDir::new().unwrap();
        let repo_root = dir.path().join("work").join("git--context-explorer");
        tokio::fs::create_dir_all(&repo_root).await.unwrap();

        let decoded =
            decode_hyphenated_absolute_path(&encode_claude_project_path(&repo_root)).await;

        assert_eq!(decoded, Some(repo_root));
    }

    #[test]
    fn test_initial_hyphenated_path_state_handles_windows_drive_prefix() {
        let (root, start_idx) = initial_hyphenated_path_state("C:-Users-zack");
        if MAIN_SEPARATOR == '\\' {
            assert_eq!(root, PathBuf::from(r"C:\"));
            assert_eq!(start_idx, 3);
        } else {
            assert_eq!(root, PathBuf::from("/"));
            assert_eq!(start_idx, 0);
        }
    }

    #[test]
    fn test_initial_hyphenated_path_state_handles_windows_safe_drive_prefix() {
        let (root, start_idx) = initial_hyphenated_path_state("C--Users-zack");
        if MAIN_SEPARATOR == '\\' {
            assert_eq!(root, PathBuf::from(r"C:\"));
            assert_eq!(start_idx, 3);
        } else {
            assert_eq!(root, PathBuf::from("/"));
            assert_eq!(start_idx, 0);
        }
    }

    #[tokio::test]
    async fn test_parse_metadata_first_value_wins() {
        let dir = TempDir::new().unwrap();
        // Two lines with session_id -- first should win
        let content = r#"{"session_id":"first-id"}
{"session_id":"second-id"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("first-id".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_last_cwd_wins() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"session_id":"session-1","cwd":"/tmp/first"}
{"cwd":"/tmp/second"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("session-1".to_string()));
        assert_eq!(metadata.cwd, Some("/tmp/second".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_direct_cwd_beats_nested_payload_path_in_same_event() {
        let dir = TempDir::new().unwrap();
        let content =
            r#"{"sessionId":"session-1","cwd":"/top/level","payload":{"cwd":"/payload/path"}}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("session-1".to_string()));
        assert_eq!(metadata.cwd, Some("/top/level".to_string()));
    }

    // -----------------------------------------------------------------------
    // parse_session_metadata_str
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_metadata_str_extracts_fields() {
        let content = r#"{"session_id":"str-1","cwd":"/tmp/repo"}"#;
        let metadata = parse_session_metadata_str(content);
        assert_eq!(metadata.session_id, Some("str-1".to_string()));
        assert_eq!(metadata.cwd, Some("/tmp/repo".to_string()));
    }

    #[test]
    fn test_parse_metadata_str_falls_back_to_full_json() {
        let content = r#"{"sessionId":"chat-999","requests":[{"response":[{"baseUri":{"path":"file:///Users/foo/dev/repo"}}]}]}"#;
        let metadata = parse_session_metadata_str(content);
        assert_eq!(metadata.session_id, Some("chat-999".to_string()));
        assert_eq!(metadata.cwd, Some("/Users/foo/dev/repo".to_string()));
    }

    #[test]
    fn test_normalize_cwd_path_handles_localhost_windows_file_uri() {
        let normalized = normalize_cwd_path("file://localhost/C:/Users/foo/dev/repo");
        assert_eq!(normalized, "C:/Users/foo/dev/repo".to_string());
    }

    // -----------------------------------------------------------------------
    // parse_session_metadata — Codex format (nested under payload)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_parse_metadata_codex_session_meta() {
        let dir = TempDir::new().unwrap();
        // Real Codex session_meta format: id and cwd nested under payload
        let content = r#"{"timestamp":"2026-02-10T01:52:21.832Z","type":"session_meta","payload":{"id":"019c453f-e731-7bd1-9d05-c571ec59ca6b","cwd":"/Users/foo/dev/my-project","originator":"codex_cli_rs","cli_version":"0.98.0"}}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(
            metadata.session_id,
            Some("019c453f-e731-7bd1-9d05-c571ec59ca6b".to_string())
        );
        assert_eq!(metadata.cwd, Some("/Users/foo/dev/my-project".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_codex_payload_id_only() {
        let dir = TempDir::new().unwrap();
        // Only payload.id present, no cwd
        let content = r#"{"type":"session_meta","payload":{"id":"abc-123"}}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("abc-123".to_string()));
        assert_eq!(metadata.cwd, None);
    }

    #[tokio::test]
    async fn test_parse_metadata_codex_payload_cwd_only() {
        let dir = TempDir::new().unwrap();
        // Only payload.cwd present, no id
        let content = r#"{"type":"session_meta","payload":{"cwd":"/Users/foo/bar"}}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, None);
        assert_eq!(metadata.cwd, Some("/Users/foo/bar".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_last_cwd_across_lines_wins_over_earlier_top_level() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"session_id":"top-level-id","cwd":"/top/level"}
{"type":"session_meta","payload":{"id":"payload-id","cwd":"/payload/path"}}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("top-level-id".to_string()));
        assert_eq!(metadata.cwd, Some("/payload/path".to_string()));
    }

    // -----------------------------------------------------------------------
    // session_time_range
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_session_time_range_parses_rfc3339() {
        let dir = TempDir::new().unwrap();
        let t1 = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let t2 = OffsetDateTime::from_unix_timestamp(1_700_000_120).unwrap();
        let s1 = t1.format(&Rfc3339).unwrap();
        let s2 = t2.format(&Rfc3339).unwrap();

        let content = format!(
            r#"{{"timestamp":"{s1}"}}
{{"payload":{{"createdAt":"{s2}"}}}}"#,
        );
        let file = write_temp_file(dir.path(), "session.jsonl", &content).await;

        let range = session_time_range(&file).await.unwrap();
        assert_eq!(range.0, t1.unix_timestamp());
        assert_eq!(range.1, t2.unix_timestamp());
    }

    #[tokio::test]
    async fn test_session_time_range_numeric_ms() {
        let dir = TempDir::new().unwrap();
        let content = r#"{
  "creationDate": 1749509938455,
  "lastMessageDate": 1749509971642
}"#;
        let file = write_temp_file(dir.path(), "session.json", content).await;

        let range = session_time_range(&file).await.unwrap();
        assert_eq!(range.0, 1_749_509_938);
        assert_eq!(range.1, 1_749_509_971);
    }

    #[test]
    fn test_session_time_range_str_parses() {
        let content = r#"{"timestamp":"2026-02-10T01:52:21Z"}"#;
        let range = session_time_range_str(content).unwrap();
        assert_eq!(range.0, range.1);
    }

    #[tokio::test]
    async fn test_session_time_range_none_when_missing() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"type":"message","content":"no timestamps"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let range = session_time_range(&file).await;
        assert!(range.is_none());
    }
}
