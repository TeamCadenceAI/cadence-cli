//! Canonical session storage models and serialization helpers.
//!
//! Session objects are the source of truth and contain both structured
//! frontmatter metadata and raw session content.

use crate::scanner::AgentType;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Confidence level of the match between session and commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::enum_variant_names)]
pub enum Confidence {
    ExactHashMatch,
    TimeWindowMatch,
    ScoredMatch,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::ExactHashMatch => write!(f, "exact_hash_match"),
            Confidence::TimeWindowMatch => write!(f, "time_window_match"),
            Confidence::ScoredMatch => write!(f, "scored_match"),
        }
    }
}

/// Encryption/compression encoding for stored canonical session objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentEncoding {
    Plain,
    Zstd,
    Pgp,
    ZstdPgp,
}

impl std::fmt::Display for ContentEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentEncoding::Plain => write!(f, "plain"),
            ContentEncoding::Zstd => write!(f, "zstd"),
            ContentEncoding::Pgp => write!(f, "pgp"),
            ContentEncoding::ZstdPgp => write!(f, "zstd+pgp"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub start: i64,
    pub end: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchSignals {
    pub confidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_uid: String,
    pub agent: String,
    pub session_id: String,
    pub repo_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_remote_url: Option<String>,
    pub branch_key: String,
    pub committer_key_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_start: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_end: Option<i64>,
    pub content_sha256: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_commits: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub touched_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_signals: Option<MatchSignals>,
    pub ingested_at: String,
    pub cli_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEnvelope {
    pub record: SessionRecord,
    pub session_content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub session_uid: String,
    pub session_blob_sha: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_start: Option<i64>,
    pub agent: String,
    pub ingested_at: String,
}

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn content_sha256(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

pub fn hash_key(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

pub fn compute_session_uid(
    agent: &AgentType,
    session_id: &str,
    repo_root: &str,
    session_start: Option<i64>,
    content_sha: &str,
) -> String {
    let key = format!(
        "{}|{}|{}|{}|{}",
        agent,
        session_id,
        repo_root,
        session_start.unwrap_or_default(),
        content_sha
    );
    hash_key(&key)
}

pub fn serialize_session_object(record: SessionRecord, session_content: String) -> Result<Vec<u8>> {
    let envelope = SessionEnvelope {
        record,
        session_content,
    };
    Ok(serde_json::to_vec(&envelope)?)
}

pub fn serialize_index_entry_line(entry: &IndexEntry) -> Result<String> {
    Ok(serde_json::to_string(entry)?)
}

pub fn compress_bytes(data: &[u8]) -> Result<Vec<u8>> {
    Ok(zstd::encode_all(std::io::Cursor::new(data), 3)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> SessionRecord {
        SessionRecord {
            session_uid: "uid-1".to_string(),
            agent: "codex".to_string(),
            session_id: "session-abc".to_string(),
            repo_root: "/tmp/repo".to_string(),
            repo_remote_url: None,
            branch_key: "main".to_string(),
            committer_key_hash: "committer-hash".to_string(),
            session_start: Some(1_700_000_000),
            session_end: Some(1_700_000_100),
            content_sha256: "content-sha".to_string(),
            observed_commits: vec!["abc123".to_string()],
            time_window: Some(TimeWindow {
                start: 1_700_000_000,
                end: 1_700_000_100,
            }),
            cwd: Some("/tmp/repo".to_string()),
            touched_paths: vec!["src/main.rs".to_string()],
            match_signals: Some(MatchSignals {
                confidence: "scored_match".to_string(),
                score: Some(0.9),
                reasons: vec!["contains_commit_hash".to_string()],
            }),
            ingested_at: "2026-03-02T00:00:00Z".to_string(),
            cli_version: "1.0.0".to_string(),
        }
    }

    #[test]
    fn compute_session_uid_is_deterministic() {
        let content_sha = content_sha256("session content");
        let uid1 = compute_session_uid(
            &AgentType::Codex,
            "session-abc",
            "/tmp/repo",
            Some(1_700_000_000),
            &content_sha,
        );
        let uid2 = compute_session_uid(
            &AgentType::Codex,
            "session-abc",
            "/tmp/repo",
            Some(1_700_000_000),
            &content_sha,
        );
        assert_eq!(uid1, uid2);

        let uid_with_different_start = compute_session_uid(
            &AgentType::Codex,
            "session-abc",
            "/tmp/repo",
            Some(1_700_000_001),
            &content_sha,
        );
        assert_ne!(uid1, uid_with_different_start);
    }

    #[test]
    fn serialize_session_object_round_trips() {
        let record = sample_record();
        let bytes = serialize_session_object(record.clone(), "line1\nline2".to_string())
            .expect("serialize session object");
        let envelope: SessionEnvelope =
            serde_json::from_slice(&bytes).expect("deserialize session envelope");

        assert_eq!(envelope.record.session_uid, record.session_uid);
        assert_eq!(envelope.record.agent, record.agent);
        assert_eq!(envelope.record.session_id, record.session_id);
        assert_eq!(envelope.record.repo_root, record.repo_root);
        assert_eq!(envelope.record.content_sha256, record.content_sha256);
        assert_eq!(envelope.session_content, "line1\nline2");
    }

    #[test]
    fn serialize_index_entry_line_is_stable_and_omits_none() {
        let entry = IndexEntry {
            session_uid: "uid-1".to_string(),
            session_blob_sha: "blob-sha".to_string(),
            session_start: None,
            agent: "codex".to_string(),
            ingested_at: "2026-03-02T00:00:00Z".to_string(),
        };

        let line = serialize_index_entry_line(&entry).expect("serialize index entry");
        assert_eq!(
            line,
            r#"{"session_uid":"uid-1","session_blob_sha":"blob-sha","agent":"codex","ingested_at":"2026-03-02T00:00:00Z"}"#
        );

        let parsed: serde_json::Value = serde_json::from_str(&line).expect("parse line");
        assert!(parsed.get("session_start").is_none());
    }
}
