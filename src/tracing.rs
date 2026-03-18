use anyhow::{Context, Result, anyhow};
use std::fs::File;
use std::io::{self, LineWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use time::OffsetDateTime;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::{LevelFilter, filter_fn};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

#[derive(Clone, Default)]
pub struct DiagnosticsLogger {
    inner: Option<Arc<TraceSink>>,
}

struct TraceSink {
    path: PathBuf,
    writer: Mutex<LineWriter<File>>,
}

#[derive(Default)]
pub struct DiagnosticsSessionGuard {
    previous: Option<DiagnosticsLogger>,
}

#[derive(Clone, Default)]
struct SessionWriterFactory;

struct SessionWriter {
    buffer: Vec<u8>,
}

const MAX_TEXT_FIELD_CHARS: usize = 4096;

impl Drop for DiagnosticsSessionGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = current_session_slot().lock() {
            if let Some(current) = slot.clone() {
                let _ = current.flush_sync();
            }
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
        ensure_tracing_initialized()?;

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
            })?
            .into_std()
            .await;

        Ok(Self {
            inner: Some(Arc::new(TraceSink {
                path,
                writer: Mutex::new(LineWriter::new(file)),
            })),
        })
    }

    pub fn path(&self) -> Option<PathBuf> {
        self.inner.as_ref().map(|inner| inner.path.clone())
    }

    fn flush_sync(&self) -> io::Result<()> {
        if let Some(inner) = &self.inner {
            inner.flush()?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub async fn flush(&self) {
        let _ = self.flush_sync();
    }
}

impl TraceSink {
    fn flush(&self) -> io::Result<()> {
        self.writer
            .lock()
            .map_err(|err| io::Error::other(err.to_string()))?
            .flush()
    }
}

impl<'a> MakeWriter<'a> for SessionWriterFactory {
    type Writer = SessionWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SessionWriter { buffer: Vec::new() }
    }
}

impl Write for SessionWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        flush_buffer(&mut self.buffer)
    }
}

impl Drop for SessionWriter {
    fn drop(&mut self) {
        let _ = flush_buffer(&mut self.buffer);
    }
}

pub fn install_global(logger: DiagnosticsLogger) -> DiagnosticsSessionGuard {
    let previous = current_session_slot()
        .lock()
        .ok()
        .and_then(|mut slot| slot.replace(logger));
    DiagnosticsSessionGuard { previous }
}

pub(crate) fn sanitize_path(path: &Path) -> String {
    let home = crate::agents::home_dir();
    if let Some(home) = home
        && let Ok(stripped) = path.strip_prefix(home)
    {
        let stripped = stripped.display().to_string();
        if stripped.is_empty() {
            return "~".to_string();
        }
        return truncate_text(format!("~/{}", stripped), MAX_TEXT_FIELD_CHARS);
    }

    truncate_text(path.display().to_string(), MAX_TEXT_FIELD_CHARS)
}

pub(crate) fn redact_remote_url(url: &str) -> String {
    if let Ok(parsed) = reqwest::Url::parse(url)
        && matches!(parsed.scheme(), "http" | "https")
    {
        let mut sanitized = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or(""));
        if let Some(port) = parsed.port() {
            sanitized.push(':');
            sanitized.push_str(&port.to_string());
        }
        sanitized.push_str(parsed.path());
        if let Some(query) = parsed.query() {
            sanitized.push('?');
            sanitized.push_str(query);
        }
        return truncate_text(sanitized, MAX_TEXT_FIELD_CHARS);
    }

    truncate_text(url, MAX_TEXT_FIELD_CHARS)
}

pub(crate) fn truncate_text(value: impl AsRef<str>, max_chars: usize) -> String {
    let value = value.as_ref();
    if value.chars().count() <= max_chars {
        return value.to_string();
    }

    let mut truncated = value.chars().take(max_chars).collect::<String>();
    truncated.push_str("...[truncated]");
    truncated
}

fn ensure_tracing_initialized() -> Result<()> {
    static INIT: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    let result = INIT.get_or_init(|| {
        let file_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_ansi(false)
            .with_writer(SessionWriterFactory)
            .with_filter(LevelFilter::TRACE);
        let pretty_stderr = tracing_subscriber::fmt::layer()
            .pretty()
            .with_writer(std::io::stderr)
            .with_ansi(crate::output::is_stderr_tty())
            .with_filter(filter_fn(|_| {
                crate::output::is_verbose() && current_session_installed()
            }));
        let subscriber = tracing_subscriber::registry()
            .with(file_layer)
            .with(pretty_stderr);

        tracing::subscriber::set_global_default(subscriber).map_err(|err| err.to_string())
    });

    result
        .as_ref()
        .map(|_| ())
        .map_err(|err| anyhow!(err.clone()))
}

fn current_session_slot() -> &'static Mutex<Option<DiagnosticsLogger>> {
    static SLOT: OnceLock<Mutex<Option<DiagnosticsLogger>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

fn current_session_installed() -> bool {
    current_session_slot()
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
        .is_some()
}

fn flush_buffer(buffer: &mut Vec<u8>) -> io::Result<()> {
    if buffer.is_empty() {
        return Ok(());
    }

    let current = current_session_slot()
        .lock()
        .map_err(|err| io::Error::other(err.to_string()))?
        .clone();
    if let Some(current) = current.and_then(|logger| logger.inner.clone()) {
        current
            .writer
            .lock()
            .map_err(|err| io::Error::other(err.to_string()))?
            .write_all(buffer)?;
    }
    buffer.clear();
    Ok(())
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
    use serde_json::Value;
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn trace_event_writes_jsonl_row() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let logger = DiagnosticsLogger::new_in_dir(
            tmp.path(),
            "trace",
            OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("ts"),
        )
        .await
        .expect("create logger");
        let _session = install_global(logger.clone());

        ::tracing::info!(event = "upload_attempt_started", session_uid = "abc");
        logger.flush().await;

        let path = logger.path().expect("path");
        let content = tokio::fs::read_to_string(path).await.expect("read");
        let row: Value = serde_json::from_str(content.trim()).expect("json");
        assert_eq!(
            row.pointer("/fields/event").and_then(Value::as_str),
            Some("upload_attempt_started")
        );
        assert_eq!(
            row.pointer("/fields/session_uid").and_then(Value::as_str),
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
        ::tracing::info!(event = "outer", index = 1);
        {
            let inner = install_global(second.clone());
            ::tracing::info!(event = "inner", index = 2);
            drop(inner);
        }
        ::tracing::info!(event = "outer_again", index = 3);
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
        assert!(first_content.contains("\"event\":\"outer_again\""));
        assert!(!first_content.contains("\"event\":\"inner\""));
        assert!(second_content.contains("\"event\":\"inner\""));
    }

    #[test]
    fn redact_remote_url_removes_http_userinfo() {
        assert_eq!(
            redact_remote_url("https://user:secret@example.com/team/repo.git"),
            "https://example.com/team/repo.git"
        );
    }
}
