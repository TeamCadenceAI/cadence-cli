//! Antigravity log discovery (VS Code style workspace storage + local API).
//!
//! Antigravity stores chat sessions under:
//! - macOS: ~/Library/Application Support/Antigravity/User/workspaceStorage/*/chatSessions/*.json
//! - Linux: ~/.config/Antigravity/User/workspaceStorage/*/chatSessions/*.json
//! - Windows: %APPDATA%\\Antigravity\\User\\workspaceStorage\\*\\chatSessions\\*.json
//!
//! If local API discovery succeeds, this module also writes API-fetched
//! conversations into `~/.cadence/cli/antigravity-api/*.json`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{
    AgentExplorer, SessionLog, SessionSource, app_config_dir_in, find_chat_session_dirs, home_dir,
    recent_files_with_exts,
};
use crate::scanner::AgentType;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Return all Antigravity log directories for use by the post-commit hook.
pub async fn log_dirs() -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    log_dirs_in(&home).await
}

/// Return all Antigravity log directories for backfill (not repo-scoped).
pub async fn all_log_dirs() -> Vec<PathBuf> {
    log_dirs().await
}

pub struct AntigravityExplorer;

#[async_trait]
impl AgentExplorer for AntigravityExplorer {
    async fn discover_recent(&self, now: i64, since_secs: i64) -> Vec<SessionLog> {
        let dirs = all_log_dirs().await;
        recent_files_with_exts(&dirs, now, since_secs, &["json"])
            .await
            .into_iter()
            .map(|file| SessionLog {
                agent_type: AgentType::Antigravity,
                source: SessionSource::File(file.path),
                updated_at: Some(file.mtime_epoch),
            })
            .collect()
    }
}

async fn log_dirs_in(home: &Path) -> Vec<PathBuf> {
    let ws_root = app_config_dir_in("Antigravity", home)
        .join("User")
        .join("workspaceStorage");
    let user_root = app_config_dir_in("Antigravity", home).join("User");

    let mut dirs = BTreeSet::new();
    for dir in find_chat_session_dirs(&ws_root).await {
        dirs.insert(dir);
    }
    // Some forks store chatSessions outside workspaceStorage; scan User root too.
    for dir in find_chat_session_dirs(&user_root).await {
        dirs.insert(dir);
    }

    if let Some(dir) = api_log_dir(home).await {
        dirs.insert(dir);
    }

    dirs.into_iter().collect()
}

// ---------------------------------------------------------------------------
// Local API discovery (best-effort)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct LspProcess {
    pid: u32,
    csrf_token: String,
    extension_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ProbeCache {
    last_checked_epoch: i64,
    last_success_epoch: Option<i64>,
    cached_log_dir: Option<String>,
}

async fn api_log_dir(home: &Path) -> Option<PathBuf> {
    if std::env::var("CADENCE_DISABLE_ANTIGRAVITY_API").is_ok() {
        return None;
    }
    let debug = std::env::var("CADENCE_ANTIGRAVITY_DEBUG").is_ok();
    let now = now_epoch();
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(2))
        .connect_timeout(Duration::from_millis(500))
        .build()
        .ok()?;

    let cache_dir = api_cache_dir(home);
    if ensure_dir(&cache_dir).await.is_err() {
        if debug {
            eprintln!("[cadence] antigravity: failed to create cache dir");
        }
        return None;
    }
    let probe_ttl_secs = std::env::var("CADENCE_ANTIGRAVITY_PROBE_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(90);
    let cache_path = probe_cache_path(home);
    let mut probe_cache = load_probe_cache(&cache_path).await.unwrap_or_default();
    if now.saturating_sub(probe_cache.last_checked_epoch) < probe_ttl_secs {
        if let Some(cached_dir) = probe_cache.cached_log_dir.as_deref() {
            let candidate = PathBuf::from(cached_dir);
            if tokio::fs::try_exists(&candidate).await.unwrap_or(false) {
                return Some(candidate);
            }
        }
        return fallback_cached_dir(&cache_dir).await;
    }

    probe_cache.last_checked_epoch = now;
    let _ = save_probe_cache(&cache_path, &probe_cache).await;

    let process = match discover_lsp_process().await {
        Some(v) => v,
        None => {
            if let Some(dir) = fallback_cached_dir(&cache_dir).await {
                return Some(dir);
            }
            return None;
        }
    };
    if debug {
        eprintln!(
            "[cadence] antigravity: pid={}, extension_port={:?}",
            process.pid, process.extension_port
        );
    }
    let ports = discover_listening_ports(process.pid).await;
    let preferred_connect = override_connect_port();
    let probed_connect = probe_connect_port(&client, &ports, &process.csrf_token).await;
    let (scheme, port) = match preferred_connect.or(probed_connect) {
        Some(p) => p,
        None => {
            if let Some(ext_port) = process.extension_port {
                if debug {
                    eprintln!(
                        "[cadence] antigravity: probe failed, using extension port {}",
                        ext_port
                    );
                }
                ("http", ext_port)
            } else {
                if debug {
                    eprintln!("[cadence] antigravity: no connect port found");
                }
                probe_cache.cached_log_dir = None;
                let _ = save_probe_cache(&cache_path, &probe_cache).await;
                return None;
            }
        }
    };

    if debug {
        eprintln!(
            "[cadence] antigravity: connect {}://127.0.0.1:{}",
            scheme, port
        );
    }

    let cascade_ids = match fetch_cascade_ids(&client, scheme, port, &process.csrf_token).await {
        Ok(ids) => ids,
        Err(e) => {
            if debug {
                eprintln!("[cadence] antigravity: list failed: {e}");
            }
            return fallback_cached_dir(&cache_dir).await;
        }
    };

    if cascade_ids.is_empty() {
        if debug {
            eprintln!("[cadence] antigravity: no cascade ids found");
        }
        return fallback_cached_dir(&cache_dir).await;
    }

    let mut payloads: Vec<(String, String)> = Vec::new();
    for (idx, cascade_id) in cascade_ids.iter().enumerate() {
        match fetch_cascade_steps(&client, scheme, port, &process.csrf_token, cascade_id).await {
            Ok(steps) => {
                let workspace_uri = extract_workspace_uri(&steps);
                let payload = serde_json::json!({
                    "sessionId": cascade_id,
                    "cascadeId": cascade_id,
                    "source": "antigravity_api",
                    "baseUri": workspace_uri.as_ref().map(|uri| serde_json::json!({ "path": uri })),
                    "fetchedAt": time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).ok(),
                    "steps": steps,
                });
                let filename = format!("{}.json", sanitize_filename(cascade_id, idx));
                payloads.push((filename, payload.to_string()));
            }
            Err(e) => {
                if debug {
                    eprintln!(
                        "[cadence] antigravity: steps failed for {}: {}",
                        cascade_id, e
                    );
                }
                continue;
            }
        }
    }

    if payloads.is_empty() {
        return fallback_cached_dir(&cache_dir).await;
    }

    let _ = clear_json_files(&cache_dir).await;
    let mut wrote_any = false;
    for (filename, payload) in payloads {
        let path = cache_dir.join(filename);
        if tokio::fs::write(&path, payload).await.is_ok() {
            wrote_any = true;
        } else if debug {
            eprintln!("[cadence] antigravity: failed to write {}", path.display());
        }
    }

    if wrote_any {
        probe_cache.last_success_epoch = Some(now);
        probe_cache.cached_log_dir = Some(cache_dir.to_string_lossy().to_string());
        let _ = save_probe_cache(&cache_path, &probe_cache).await;
        Some(cache_dir)
    } else {
        fallback_cached_dir(&cache_dir).await
    }
}

fn api_cache_dir(home: &Path) -> PathBuf {
    home.join(".cadence/cli").join("antigravity-api")
}

fn probe_cache_path(home: &Path) -> PathBuf {
    home.join(".cadence/cli").join("antigravity-probe.json")
}

async fn load_probe_cache(path: &Path) -> Option<ProbeCache> {
    let content = tokio::fs::read_to_string(path).await.ok()?;
    serde_json::from_str(&content).ok()
}

async fn save_probe_cache(path: &Path, cache: &ProbeCache) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let data = serde_json::to_vec_pretty(cache)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing parent for {}", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("probe-cache");
    let pid = std::process::id();

    for attempt in 0..8u32 {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp = parent.join(format!(".{file_name}.{pid}.{nonce}.{attempt}.tmp"));
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        match opts.open(&tmp).await {
            Ok(mut file) => {
                tokio::io::AsyncWriteExt::write_all(&mut file, &data).await?;
                drop(file);
                tokio::fs::rename(&tmp, path).await?;
                return Ok(());
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "create temp file for {}: {}",
                    path.display(),
                    err
                ));
            }
        }
    }

    Err(anyhow::anyhow!(
        "failed to create unique temp file for {}",
        path.display()
    ))
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

async fn ensure_dir(dir: &Path) -> anyhow::Result<()> {
    if !tokio::fs::try_exists(dir).await.unwrap_or(false) {
        tokio::fs::create_dir_all(dir).await?;
    }
    Ok(())
}

async fn clear_json_files(dir: &Path) -> anyhow::Result<()> {
    let mut entries = tokio::fs::read_dir(dir).await?;
    loop {
        let Some(entry) = entries.next_entry().await? else {
            break;
        };
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            let _ = tokio::fs::remove_file(&path).await;
        }
    }
    Ok(())
}

async fn fallback_cached_dir(cache_dir: &Path) -> Option<PathBuf> {
    if has_json_files(cache_dir).await {
        Some(cache_dir.to_path_buf())
    } else {
        None
    }
}

async fn has_json_files(dir: &Path) -> bool {
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(_) => return false,
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            return true;
        }
    }
    false
}

#[cfg(unix)]
async fn discover_lsp_process() -> Option<LspProcess> {
    let output = tokio::process::Command::new("ps")
        .args(["-ax", "-o", "pid=,command="])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let mut parts = line.split_whitespace();
        let pid_str = parts.next()?;
        let pid: u32 = pid_str.parse().ok()?;
        let cmd = line[pid_str.len()..].trim();
        let cmd_lower = cmd.to_lowercase();
        if !cmd_lower.contains("language_server_") {
            continue;
        }
        if !(cmd_lower.contains("--app_data_dir antigravity")
            || cmd_lower.contains("/antigravity/"))
        {
            continue;
        }

        let csrf_token = extract_flag_value(cmd, "--csrf_token")?;
        let extension_port =
            extract_flag_value(cmd, "--extension_server_port").and_then(|v| v.parse::<u16>().ok());
        return Some(LspProcess {
            pid,
            csrf_token,
            extension_port,
        });
    }

    None
}

#[cfg(windows)]
async fn discover_lsp_process() -> Option<LspProcess> {
    let output = tokio::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-CimInstance Win32_Process | Select-Object ProcessId, CommandLine | ConvertTo-Json -Compress",
        ])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let value: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let rows = match value {
        serde_json::Value::Array(rows) => rows,
        row @ serde_json::Value::Object(_) => vec![row],
        _ => return None,
    };

    for row in rows {
        let map = match row.as_object() {
            Some(map) => map,
            None => continue,
        };
        let pid = match map.get("ProcessId").and_then(|v| v.as_u64()) {
            Some(pid) => pid as u32,
            None => continue,
        };
        let cmd = map
            .get("CommandLine")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if cmd.is_empty() {
            continue;
        }
        let cmd_lower = cmd.to_lowercase();
        if !cmd_lower.contains("language_server_") {
            continue;
        }
        if !(cmd_lower.contains("--app_data_dir antigravity")
            || cmd_lower.contains("/antigravity/")
            || cmd_lower.contains("\\antigravity\\"))
        {
            continue;
        }

        let csrf_token = extract_flag_value(cmd, "--csrf_token")?;
        let extension_port =
            extract_flag_value(cmd, "--extension_server_port").and_then(|v| v.parse::<u16>().ok());
        return Some(LspProcess {
            pid,
            csrf_token,
            extension_port,
        });
    }

    None
}

#[cfg(all(not(unix), not(windows)))]
async fn discover_lsp_process() -> Option<LspProcess> {
    // Local LSP probing currently supports Unix (`ps`/`lsof`) and Windows
    // (`powershell`/`netstat`) only.
    None
}

fn extract_flag_value(command: &str, flag: &str) -> Option<String> {
    let mut iter = command.split_whitespace();
    while let Some(part) = iter.next() {
        if part == flag {
            return iter.next().map(|v| v.to_string());
        }
    }
    None
}

#[cfg(unix)]
async fn discover_listening_ports(pid: u32) -> Vec<u16> {
    let output = tokio::process::Command::new("lsof")
        .args(["-nP", "-iTCP", "-sTCP:LISTEN", "-p"])
        .arg(pid.to_string())
        .output()
        .await;
    let output = match output {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    if !output.status.success() {
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ports = BTreeSet::new();
    for line in stdout.lines() {
        if let Some(port) = parse_port_from_lsof_line(line) {
            ports.insert(port);
        }
    }

    ports.into_iter().collect()
}

#[cfg(windows)]
async fn discover_listening_ports(pid: u32) -> Vec<u16> {
    let output = tokio::process::Command::new("netstat")
        .args(["-ano", "-p", "tcp"])
        .output()
        .await;
    let output = match output {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    if !output.status.success() {
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ports = BTreeSet::new();
    for line in stdout.lines() {
        if let Some(port) = parse_port_from_netstat_line(line, pid) {
            ports.insert(port);
        }
    }
    ports.into_iter().collect()
}

#[cfg(all(not(unix), not(windows)))]
async fn discover_listening_ports(_pid: u32) -> Vec<u16> {
    Vec::new()
}

#[cfg(any(unix, test))]
fn parse_port_from_lsof_line(line: &str) -> Option<u16> {
    for token in line.split_whitespace().rev() {
        if let Some(port) = parse_port_from_lsof_field(token) {
            return Some(port);
        }
    }
    None
}

#[cfg(any(unix, test))]
fn parse_port_from_lsof_field(field: &str) -> Option<u16> {
    let port_str = match field.rfind(':') {
        Some(idx) => &field[idx + 1..],
        None => return None,
    };
    let port_str = port_str.trim_matches(|c: char| c == ')' || c == ']');
    port_str.parse::<u16>().ok()
}

#[cfg(any(windows, test))]
fn parse_port_from_netstat_line(line: &str, pid: u32) -> Option<u16> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    if !parts[0].eq_ignore_ascii_case("tcp") {
        return None;
    }
    if !parts[3].eq_ignore_ascii_case("listening") {
        return None;
    }
    let line_pid = parts[4].parse::<u32>().ok()?;
    if line_pid != pid {
        return None;
    }
    let local_addr = parts[1].trim_matches(|c| c == '[' || c == ']');
    let port_str = local_addr.rsplit(':').next()?;
    port_str.parse::<u16>().ok()
}

async fn probe_connect_port(
    client: &reqwest::Client,
    ports: &[u16],
    csrf: &str,
) -> Option<(&'static str, u16)> {
    for port in ports {
        if post_json(
            client,
            "https",
            *port,
            "GetUnleashData",
            csrf,
            &serde_json::json!({}),
        )
        .await
        .is_ok()
        {
            return Some(("https", *port));
        }
    }
    for port in ports {
        if post_json(
            client,
            "http",
            *port,
            "GetUnleashData",
            csrf,
            &serde_json::json!({}),
        )
        .await
        .is_ok()
        {
            return Some(("http", *port));
        }
    }
    None
}

fn override_connect_port() -> Option<(&'static str, u16)> {
    let port = std::env::var("ANTIGRAVITY_LSP_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())?;
    let scheme = std::env::var("ANTIGRAVITY_LSP_SCHEME")
        .ok()
        .unwrap_or_else(|| "https".to_string());
    let scheme = if scheme.eq_ignore_ascii_case("http") {
        "http"
    } else {
        "https"
    };
    Some((scheme, port))
}

async fn fetch_cascade_ids(
    client: &reqwest::Client,
    scheme: &str,
    port: u16,
    csrf: &str,
) -> anyhow::Result<Vec<String>> {
    let method = std::env::var("ANTIGRAVITY_LSP_LIST_METHOD")
        .unwrap_or_else(|_| "GetAllCascadeTrajectories".to_string());
    let response = post_json(client, scheme, port, &method, csrf, &serde_json::json!({})).await?;
    Ok(extract_cascade_ids_from_value(&response))
}

async fn fetch_cascade_steps(
    client: &reqwest::Client,
    scheme: &str,
    port: u16,
    csrf: &str,
    cascade_id: &str,
) -> anyhow::Result<serde_json::Value> {
    let method = std::env::var("ANTIGRAVITY_LSP_STEPS_METHOD")
        .unwrap_or_else(|_| "GetCascadeTrajectorySteps".to_string());
    let end_index = std::env::var("ANTIGRAVITY_LSP_STEPS_END")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(10_000);

    let body = serde_json::json!({
        "cascadeId": cascade_id,
        "startIndex": 0,
        "endIndex": end_index
    });
    post_json(client, scheme, port, &method, csrf, &body).await
}

async fn post_json(
    client: &reqwest::Client,
    scheme: &str,
    port: u16,
    method: &str,
    csrf: &str,
    body: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let url = format!(
        "{}://127.0.0.1:{}/exa.language_server_pb.LanguageServerService/{}",
        scheme, port, method
    );
    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("Connect-Protocol-Version", "1")
        .header("X-Codeium-Csrf-Token", csrf)
        .json(body)
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "antigravity API returned status {}",
            response.status()
        ));
    }
    Ok(response.json().await?)
}

fn extract_cascade_ids_from_value(value: &serde_json::Value) -> Vec<String> {
    let mut ids = Vec::new();
    extract_trajectory_summary_keys(value, &mut ids);
    extract_cascade_ids_inner(value, &mut ids);
    ids.sort();
    ids.dedup();
    ids
}

fn extract_trajectory_summary_keys(value: &serde_json::Value, ids: &mut Vec<String>) {
    let Some(map) = value.as_object() else { return };
    if let Some(summary_map) = map.get("trajectorySummaries").and_then(|v| v.as_object()) {
        for key in summary_map.keys() {
            ids.push(key.to_string());
        }
    }
}

fn extract_cascade_ids_inner(value: &serde_json::Value, ids: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if (k.eq_ignore_ascii_case("cascadeId") || k.eq_ignore_ascii_case("cascade_id"))
                    && let Some(id) = v.as_str()
                {
                    ids.push(id.to_string());
                }
                extract_cascade_ids_inner(v, ids);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                extract_cascade_ids_inner(item, ids);
            }
        }
        _ => {}
    }
}

fn sanitize_filename(input: &str, fallback_index: usize) -> String {
    let mut out = String::new();
    for c in input.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        format!("cascade-{}", fallback_index)
    } else if out.len() > 96 {
        out.truncate(96);
        out
    } else {
        out
    }
}

fn extract_workspace_uri(value: &serde_json::Value) -> Option<String> {
    if let Some(uri) = value
        .pointer("/steps/0/userInput/activeUserState/activeDocument/workspaceUri")
        .and_then(|v| v.as_str())
    {
        return Some(uri.to_string());
    }
    if let Some(uri) = value
        .pointer("/steps/0/userInput/activeUserState/workspaceUri")
        .and_then(|v| v.as_str())
    {
        return Some(uri.to_string());
    }
    if let Some(uri) = value
        .pointer("/steps/0/userInput/activeUserState/openDocuments/0/workspaceUri")
        .and_then(|v| v.as_str())
    {
        return Some(uri.to_string());
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::app_config_dir_in;
    use serde_json::json;

    use tempfile::TempDir;

    #[tokio::test]
    async fn test_antigravity_log_dirs_collects_chat_sessions() {
        let home = TempDir::new().unwrap();
        let ws_root = app_config_dir_in("Antigravity", home.path())
            .join("User")
            .join("workspaceStorage")
            .join("abc")
            .join("chatSessions");
        tokio::fs::create_dir_all(&ws_root).await.unwrap();
        let other_root = app_config_dir_in("Antigravity", home.path())
            .join("User")
            .join("other")
            .join("chatSessions");
        tokio::fs::create_dir_all(&other_root).await.unwrap();

        let dirs = log_dirs_in(home.path()).await;
        assert!(dirs.contains(&ws_root));
        assert!(dirs.contains(&other_root));
    }

    #[tokio::test]
    async fn test_extract_cascade_ids_from_trajectory_summaries_keys() {
        let value = json!({
            "trajectorySummaries": {
                "abc-123": { "summary": "one" },
                "def-456": { "summary": "two" }
            }
        });
        let ids = extract_cascade_ids_from_value(&value);
        assert!(ids.contains(&"abc-123".to_string()));
        assert!(ids.contains(&"def-456".to_string()));
    }

    #[tokio::test]
    async fn test_extract_cascade_ids_from_nested_fields() {
        let value = json!({
            "items": [
                { "cascadeId": "foo" },
                { "cascade_id": "bar" }
            ]
        });
        let ids = extract_cascade_ids_from_value(&value);
        assert!(ids.contains(&"foo".to_string()));
        assert!(ids.contains(&"bar".to_string()));
    }

    #[test]
    fn test_parse_port_from_lsof_line_handles_listen_suffix() {
        let line = "language_ 20815 zack 6u IPv4 0x0 0t0 TCP 127.0.0.1:60482 (LISTEN)";
        assert_eq!(parse_port_from_lsof_line(line), Some(60482));
    }

    #[test]
    fn test_parse_port_from_netstat_line_filters_pid_and_extracts_port() {
        let line = "  TCP    127.0.0.1:60482    0.0.0.0:0    LISTENING    20815";
        assert_eq!(parse_port_from_netstat_line(line, 20815), Some(60482));
        assert_eq!(parse_port_from_netstat_line(line, 99999), None);
    }

    #[tokio::test]
    async fn test_extract_workspace_uri_prefers_active_document() {
        let value = json!({
            "steps": [{
                "userInput": {
                    "activeUserState": {
                        "activeDocument": { "workspaceUri": "file:///Users/zack/dev/cadence" },
                        "openDocuments": [{ "workspaceUri": "file:///Users/zack/dev/other" }]
                    }
                }
            }]
        });
        let uri = extract_workspace_uri(&value);
        assert_eq!(uri.as_deref(), Some("file:///Users/zack/dev/cadence"));
    }

    #[tokio::test]
    async fn test_extract_workspace_uri_falls_back_to_open_documents() {
        let value = json!({
            "steps": [{
                "userInput": {
                    "activeUserState": {
                        "openDocuments": [{ "workspaceUri": "file:///Users/zack/dev/fallback" }]
                    }
                }
            }]
        });
        let uri = extract_workspace_uri(&value);
        assert_eq!(uri.as_deref(), Some("file:///Users/zack/dev/fallback"));
    }
}
