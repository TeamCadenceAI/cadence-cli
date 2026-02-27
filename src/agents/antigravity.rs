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
use std::process::Command;

use super::{app_config_dir_in, find_chat_session_dirs, home_dir};

/// Return all Antigravity log directories for use by the post-commit hook.
pub fn log_dirs() -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    log_dirs_in(&home)
}

/// Return all Antigravity log directories for backfill (not repo-scoped).
pub fn all_log_dirs() -> Vec<PathBuf> {
    log_dirs()
}

fn log_dirs_in(home: &Path) -> Vec<PathBuf> {
    let ws_root = app_config_dir_in("Antigravity", home)
        .join("User")
        .join("workspaceStorage");
    let user_root = app_config_dir_in("Antigravity", home).join("User");

    let mut dirs = BTreeSet::new();
    for dir in find_chat_session_dirs(&ws_root) {
        dirs.insert(dir);
    }
    // Some forks store chatSessions outside workspaceStorage; scan User root too.
    for dir in find_chat_session_dirs(&user_root) {
        dirs.insert(dir);
    }

    if let Some(dir) = api_log_dir(home) {
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

fn api_log_dir(home: &Path) -> Option<PathBuf> {
    if std::env::var("CADENCE_DISABLE_ANTIGRAVITY_API").is_ok() {
        return None;
    }
    let debug = std::env::var("CADENCE_ANTIGRAVITY_DEBUG").is_ok();

    let cache_dir = api_cache_dir(home);
    if ensure_dir(&cache_dir).is_err() {
        if debug {
            eprintln!("[cadence] antigravity: failed to create cache dir");
        }
        return None;
    }
    let _ = clear_json_files(&cache_dir);

    let process = discover_lsp_process()?;
    if debug {
        eprintln!(
            "[cadence] antigravity: pid={}, extension_port={:?}",
            process.pid, process.extension_port
        );
    }
    let ports = discover_listening_ports(process.pid);
    let (scheme, port) =
        match override_connect_port().or_else(|| probe_connect_port(&ports, &process.csrf_token)) {
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

    let cascade_ids = match fetch_cascade_ids(scheme, port, &process.csrf_token) {
        Ok(ids) => ids,
        Err(e) => {
            if debug {
                eprintln!("[cadence] antigravity: list failed: {e}");
            }
            return None;
        }
    };

    if cascade_ids.is_empty() {
        if debug {
            eprintln!("[cadence] antigravity: no cascade ids found");
        }
        return None;
    }

    let mut wrote_any = false;
    for (idx, cascade_id) in cascade_ids.iter().enumerate() {
        match fetch_cascade_steps(scheme, port, &process.csrf_token, cascade_id) {
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
                let path = cache_dir.join(filename);
                if std::fs::write(&path, payload.to_string()).is_ok() {
                    wrote_any = true;
                } else if debug {
                    eprintln!("[cadence] antigravity: failed to write {}", path.display());
                }
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

    if wrote_any { Some(cache_dir) } else { None }
}

fn api_cache_dir(home: &Path) -> PathBuf {
    home.join(".cadence/cli").join("antigravity-api")
}

fn ensure_dir(dir: &Path) -> anyhow::Result<()> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

fn clear_json_files(dir: &Path) -> anyhow::Result<()> {
    let entries = std::fs::read_dir(dir)?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            let _ = std::fs::remove_file(&path);
        }
    }
    Ok(())
}

fn discover_lsp_process() -> Option<LspProcess> {
    let output = Command::new("ps")
        .args(["-ax", "-o", "pid=,command="])
        .output()
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
        if !cmd_lower.contains("language_server_macos") {
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

fn extract_flag_value(command: &str, flag: &str) -> Option<String> {
    let mut iter = command.split_whitespace();
    while let Some(part) = iter.next() {
        if part == flag {
            return iter.next().map(|v| v.to_string());
        }
    }
    None
}

fn discover_listening_ports(pid: u32) -> Vec<u16> {
    let output = Command::new("lsof")
        .args(["-nP", "-iTCP", "-sTCP:LISTEN", "-p"])
        .arg(pid.to_string())
        .output();
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
        let last = match line.split_whitespace().last() {
            Some(v) => v,
            None => continue,
        };
        if let Some(port) = parse_port_from_lsof_field(last) {
            ports.insert(port);
        }
    }

    ports.into_iter().collect()
}

fn parse_port_from_lsof_field(field: &str) -> Option<u16> {
    let port_str = match field.rfind(':') {
        Some(idx) => &field[idx + 1..],
        None => return None,
    };
    let port_str = port_str.trim_matches(|c: char| c == ')' || c == ']');
    port_str.parse::<u16>().ok()
}

fn probe_connect_port(ports: &[u16], csrf: &str) -> Option<(&'static str, u16)> {
    for port in ports {
        if post_json(
            "https",
            *port,
            "GetUnleashData",
            csrf,
            &serde_json::json!({}),
        )
        .is_ok()
        {
            return Some(("https", *port));
        }
    }
    for port in ports {
        if post_json(
            "http",
            *port,
            "GetUnleashData",
            csrf,
            &serde_json::json!({}),
        )
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

fn fetch_cascade_ids(scheme: &str, port: u16, csrf: &str) -> anyhow::Result<Vec<String>> {
    let method = std::env::var("ANTIGRAVITY_LSP_LIST_METHOD")
        .unwrap_or_else(|_| "GetAllCascadeTrajectories".to_string());
    let response = post_json(scheme, port, &method, csrf, &serde_json::json!({}))?;
    Ok(extract_cascade_ids_from_value(&response))
}

fn fetch_cascade_steps(
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
    post_json(scheme, port, &method, csrf, &body)
}

fn post_json(
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
    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("Connect-Protocol-Version", "1")
        .header("X-Codeium-Csrf-Token", csrf)
        .json(body)
        .send()?;
    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "antigravity API returned status {}",
            response.status()
        ));
    }
    Ok(response.json()?)
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
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_antigravity_log_dirs_collects_chat_sessions() {
        let home = TempDir::new().unwrap();
        let ws_root = app_config_dir_in("Antigravity", home.path())
            .join("User")
            .join("workspaceStorage")
            .join("abc")
            .join("chatSessions");
        fs::create_dir_all(&ws_root).unwrap();
        let other_root = app_config_dir_in("Antigravity", home.path())
            .join("User")
            .join("other")
            .join("chatSessions");
        fs::create_dir_all(&other_root).unwrap();

        let dirs = log_dirs_in(home.path());
        assert!(dirs.contains(&ws_root));
        assert!(dirs.contains(&other_root));
    }

    #[test]
    fn test_extract_cascade_ids_from_trajectory_summaries_keys() {
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

    #[test]
    fn test_extract_cascade_ids_from_nested_fields() {
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
    fn test_extract_workspace_uri_prefers_active_document() {
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

    #[test]
    fn test_extract_workspace_uri_falls_back_to_open_documents() {
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
