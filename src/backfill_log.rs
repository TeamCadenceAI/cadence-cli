use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
#[cfg(test)]
use tokio::sync::oneshot;

#[derive(Clone, Default)]
pub struct BackfillLogger {
    inner: Option<Arc<BackfillLoggerInner>>,
}

struct BackfillLoggerInner {
    path: PathBuf,
    sender: UnboundedSender<LogMessage>,
}

enum LogMessage {
    Line(String),
    #[cfg(test)]
    Flush(oneshot::Sender<()>),
}

impl BackfillLogger {
    pub async fn new() -> Result<Self> {
        let dir = crate::config::CliConfig::config_dir()
            .ok_or_else(|| anyhow!("cannot determine config directory: $HOME is not set"))?;
        Self::new_with_now(&dir, OffsetDateTime::now_utc()).await
    }

    pub fn disabled() -> Self {
        Self { inner: None }
    }

    #[cfg(test)]
    pub(crate) async fn new_with_now(dir: &Path, now: OffsetDateTime) -> Result<Self> {
        Self::create_in_dir(dir, now).await
    }

    #[cfg(not(test))]
    async fn new_with_now(dir: &Path, now: OffsetDateTime) -> Result<Self> {
        Self::create_in_dir(dir, now).await
    }

    async fn create_in_dir(dir: &Path, now: OffsetDateTime) -> Result<Self> {
        tokio::fs::create_dir_all(dir)
            .await
            .with_context(|| format!("failed to create config directory at {}", dir.display()))?;

        let file_name = format!("backfill.{}.log", filename_timestamp(now));
        let path = dir.join(file_name);
        let file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .await
            .with_context(|| format!("failed to create backfill log file at {}", path.display()))?;
        let mut writer = BufWriter::new(file);
        let (sender, mut receiver) = unbounded_channel::<LogMessage>();
        tokio::spawn(async move {
            while let Some(message) = receiver.recv().await {
                match message {
                    LogMessage::Line(line) => {
                        if writer.write_all(line.as_bytes()).await.is_err() {
                            break;
                        }
                        if writer.write_all(b"\n").await.is_err() {
                            break;
                        }
                        if writer.flush().await.is_err() {
                            break;
                        }
                    }
                    #[cfg(test)]
                    LogMessage::Flush(ack) => {
                        let _ = writer.flush().await;
                        let _ = ack.send(());
                    }
                }
            }
            let _ = writer.flush().await;
        });

        Ok(Self {
            inner: Some(Arc::new(BackfillLoggerInner { path, sender })),
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

        let _ = inner.sender.send(LogMessage::Line(line));
    }

    #[cfg(test)]
    pub async fn flush(&self) {
        let Some(inner) = &self.inner else {
            return;
        };
        let (tx, rx) = oneshot::channel();
        if inner.sender.send(LogMessage::Flush(tx)).is_ok() {
            let _ = rx.await;
        }
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

        let logger = BackfillLogger::new_with_now(tmp.path(), now)
            .await
            .expect("create logger");
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
        .await
        .expect("create logger");

        logger.event(
            "session_skipped",
            json!({
                "file": "/tmp/session.jsonl",
                "reason": "missing_cwd",
            }),
        );
        logger.flush().await;

        let path = logger.path().expect("path");
        let content = tokio::fs::read_to_string(path).await.expect("read");
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
