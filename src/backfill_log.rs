use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Clone, Default)]
pub struct BackfillLogger {
    inner: Option<Arc<BackfillLoggerInner>>,
}

struct BackfillLoggerInner {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
}

impl BackfillLogger {
    pub fn new() -> Result<Self> {
        let dir = crate::config::CliConfig::config_dir()
            .ok_or_else(|| anyhow!("cannot determine config directory: $HOME is not set"))?;
        Self::new_with_now(&dir, OffsetDateTime::now_utc())
    }

    pub fn disabled() -> Self {
        Self { inner: None }
    }

    #[cfg(test)]
    pub(crate) fn new_with_now(dir: &Path, now: OffsetDateTime) -> Result<Self> {
        Self::create_in_dir(dir, now)
    }

    #[cfg(not(test))]
    fn new_with_now(dir: &Path, now: OffsetDateTime) -> Result<Self> {
        Self::create_in_dir(dir, now)
    }

    fn create_in_dir(dir: &Path, now: OffsetDateTime) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create config directory at {}", dir.display()))?;

        let file_name = format!("backfill.{}.log", filename_timestamp(now));
        let path = dir.join(file_name);
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("failed to create backfill log file at {}", path.display()))?;

        Ok(Self {
            inner: Some(Arc::new(BackfillLoggerInner {
                path,
                writer: Mutex::new(BufWriter::new(file)),
            })),
        })
    }

    pub fn path(&self) -> Option<PathBuf> {
        self.inner.as_ref().map(|inner| inner.path.clone())
    }

    pub fn event(&self, event: &str, payload: Value) {
        let Some(inner) = &self.inner else {
            return;
        };

        let row = json!({
            "timestamp": now_rfc3339(),
            "event": event,
            "payload": payload,
        });

        let Ok(line) = serde_json::to_string(&row) else {
            return;
        };

        let Ok(mut writer) = inner.writer.lock() else {
            return;
        };

        let _ = writeln!(writer, "{line}");
        let _ = writer.flush();
    }
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

fn filename_timestamp(now: OffsetDateTime) -> String {
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}{:09}Z",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.nanosecond()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn new_with_now_creates_timestamped_log_file() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let now = OffsetDateTime::from_unix_timestamp(1_706_795_445).expect("ts");

        let logger = BackfillLogger::new_with_now(tmp.path(), now).expect("create logger");
        let path = logger.path().expect("path");

        assert_eq!(path.parent(), Some(tmp.path()));
        let file_name = path.file_name().and_then(|v| v.to_str()).unwrap_or("");
        let expected_prefix = format!("backfill.{}", filename_timestamp(now));
        assert!(file_name.starts_with("backfill."));
        assert!(file_name.ends_with(".log"));
        assert!(file_name.starts_with(&expected_prefix));
    }

    #[tokio::test]
    async fn event_writes_jsonl_row() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let logger = BackfillLogger::new_with_now(
            tmp.path(),
            OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("ts"),
        )
        .expect("create logger");

        logger.event(
            "session_skipped",
            json!({
                "file": "/tmp/session.jsonl",
                "reason": "missing_cwd",
            }),
        );

        let path = logger.path().expect("path");
        let content = std::fs::read_to_string(path).expect("read");
        let row: Value = serde_json::from_str(content.trim()).expect("json row");
        assert_eq!(
            row.get("event").and_then(Value::as_str),
            Some("session_skipped")
        );
        assert_eq!(
            row.get("payload")
                .and_then(|p| p.get("reason"))
                .and_then(Value::as_str),
            Some("missing_cwd")
        );
        assert!(row.get("timestamp").is_some());
    }
}
