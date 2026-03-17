use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
#[cfg(test)]
use tokio::sync::oneshot;

#[derive(Clone, Default)]
pub struct DiagnosticsLogger {
    inner: Option<Arc<DiagnosticsLoggerInner>>,
}

struct DiagnosticsLoggerInner {
    path: PathBuf,
    sender: UnboundedSender<LogMessage>,
}

enum LogMessage {
    Line(String),
    #[cfg(test)]
    Flush(oneshot::Sender<()>),
}

#[derive(Default)]
pub struct DiagnosticsSessionGuard {
    previous: Option<DiagnosticsLogger>,
}

impl Drop for DiagnosticsSessionGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = global_slot().lock() {
            *slot = self.previous.clone();
        }
    }
}

impl DiagnosticsLogger {
    pub async fn new(prefix: &str) -> Result<Self> {
        let dir = crate::config::CliConfig::config_dir()
            .ok_or_else(|| anyhow!("cannot determine config directory: $HOME is not set"))?;
        Self::new_in_dir(&dir, prefix, OffsetDateTime::now_utc()).await
    }

    pub(crate) async fn new_in_dir(dir: &Path, prefix: &str, now: OffsetDateTime) -> Result<Self> {
        tokio::fs::create_dir_all(dir)
            .await
            .with_context(|| format!("failed to create config directory at {}", dir.display()))?;

        let file_name = format!("{prefix}.{}.log", filename_timestamp(now));
        let path = dir.join(file_name);
        let file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .await
            .with_context(|| {
                format!(
                    "failed to create diagnostics log file at {}",
                    path.display()
                )
            })?;
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
            inner: Some(Arc::new(DiagnosticsLoggerInner { path, sender })),
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

pub fn install_global(logger: DiagnosticsLogger) -> DiagnosticsSessionGuard {
    let previous = global_slot()
        .lock()
        .ok()
        .and_then(|mut slot| slot.replace(logger));
    DiagnosticsSessionGuard { previous }
}

pub fn event(event: &str, payload: Value) {
    let current = global_slot().lock().ok().and_then(|slot| slot.clone());
    if let Some(logger) = current {
        logger.event(event, payload);
    }
}

fn global_slot() -> &'static Mutex<Option<DiagnosticsLogger>> {
    static SLOT: OnceLock<Mutex<Option<DiagnosticsLogger>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
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
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn event_writes_jsonl_row() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let logger = DiagnosticsLogger::new_in_dir(
            tmp.path(),
            "trace",
            OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("ts"),
        )
        .await
        .expect("create logger");

        logger.event("upload_attempt_started", json!({ "session_uid": "abc" }));
        logger.flush().await;

        let path = logger.path().expect("path");
        let content = tokio::fs::read_to_string(path).await.expect("read");
        let row: Value = serde_json::from_str(content.trim()).expect("json");
        assert_eq!(
            row.get("event").and_then(Value::as_str),
            Some("upload_attempt_started")
        );
        assert_eq!(
            row.get("payload")
                .and_then(|payload| payload.get("session_uid"))
                .and_then(Value::as_str),
            Some("abc")
        );
        assert!(row.get("timestamp").is_some());
    }

    #[tokio::test]
    #[serial]
    async fn install_global_restores_previous_logger() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let first = DiagnosticsLogger::new_in_dir(
            tmp.path(),
            "trace-first",
            OffsetDateTime::from_unix_timestamp(1_700_000_001).expect("ts"),
        )
        .await
        .expect("create first logger");
        let second = DiagnosticsLogger::new_in_dir(
            tmp.path(),
            "trace-second",
            OffsetDateTime::from_unix_timestamp(1_700_000_002).expect("ts"),
        )
        .await
        .expect("create second logger");

        let first_path = first.path().expect("first path");
        let second_path = second.path().expect("second path");

        let outer = install_global(first.clone());
        event("outer", json!({ "index": 1 }));
        {
            let inner = install_global(second.clone());
            event("inner", json!({ "index": 2 }));
            drop(inner);
        }
        event("outer-again", json!({ "index": 3 }));
        drop(outer);
        first.flush().await;
        second.flush().await;

        let first_content = tokio::fs::read_to_string(first_path)
            .await
            .expect("read first");
        let second_content = tokio::fs::read_to_string(second_path)
            .await
            .expect("read second");

        assert!(first_content.contains("\"event\":\"outer\""));
        assert!(first_content.contains("\"event\":\"outer-again\""));
        assert!(!first_content.contains("\"event\":\"inner\""));
        assert!(second_content.contains("\"event\":\"inner\""));
    }
}
