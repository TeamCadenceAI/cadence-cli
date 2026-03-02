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
