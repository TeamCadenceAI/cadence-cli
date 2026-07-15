//! Hard-coded final-release lifecycle for the retired standalone CLI.

use crate::state_files;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use time::OffsetDateTime;

pub const BENEFITS_URL: &str = "https://teamcadence.ai/cli-eol";
pub const GOODBYE_URL: &str = "https://teamcadence.ai/cli-eol?phase=goodbye";
pub const CLEANUP_ONLY_AT: i64 = 1_784_815_200; // 2026-07-24T00:00:00+10:00
pub const SELF_DISABLE_AT: i64 = 1_785_420_000; // 2026-07-31T00:00:00+10:00
const NUDGE_INTERVAL_SECS: i64 = 48 * 60 * 60;
const STATE_FILE: &str = "eol-state.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Active,
    CleanupOnly,
    SelfDisabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct EolState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_nudge_attempt_at: Option<i64>,
    #[serde(default)]
    goodbye_attempted: bool,
    #[serde(default)]
    scheduler_cleanup_complete: bool,
}

fn state_path() -> Result<PathBuf> {
    Ok(state_files::cadence_dir()?.join(STATE_FILE))
}

async fn load_state() -> Result<EolState> {
    let path = state_path()?;
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => serde_json::from_str(&content)
            .with_context(|| format!("failed to parse EOL state {}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(EolState::default()),
        Err(err) => {
            Err(err).with_context(|| format!("failed to read EOL state {}", path.display()))
        }
    }
}

async fn save_state(state: &EolState) -> Result<()> {
    state_files::write_json_atomic(&state_path()?, state).await
}

pub fn phase_at(epoch: i64) -> Phase {
    if epoch >= SELF_DISABLE_AT {
        Phase::SelfDisabled
    } else if epoch >= CLEANUP_ONLY_AT {
        Phase::CleanupOnly
    } else {
        Phase::Active
    }
}

pub fn phase() -> Phase {
    phase_at(OffsetDateTime::now_utc().unix_timestamp())
}

pub fn notice() -> &'static str {
    "Cadence has moved to the Cadence App. Learn more: https://teamcadence.ai/cli-eol"
}

pub fn retired_notice() -> &'static str {
    "This Cadence CLI is retired. Only cleanup commands are available. Move to the Cadence App: https://teamcadence.ai/cli-eol"
}

pub fn should_open_nudge_at(last_attempt: Option<i64>, now: i64) -> bool {
    last_attempt.is_none_or(|last| now.saturating_sub(last) >= NUDGE_INTERVAL_SECS)
}

pub async fn maybe_open_nudge() -> Result<bool> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut state = load_state().await?;
    if !should_open_nudge_at(state.last_nudge_attempt_at, now) {
        return Ok(false);
    }
    state.last_nudge_attempt_at = Some(now);
    save_state(&state).await?;
    if let Err(err) = open::that(BENEFITS_URL) {
        ::tracing::warn!(event = "eol_nudge_browser_open_failed", error = %err);
    }
    Ok(true)
}

pub async fn maybe_open_goodbye() -> Result<bool> {
    let mut state = load_state().await?;
    if state.goodbye_attempted {
        return Ok(false);
    }
    state.goodbye_attempted = true;
    save_state(&state).await?;
    if let Err(err) = open::that(GOODBYE_URL) {
        ::tracing::warn!(event = "eol_goodbye_browser_open_failed", error = %err);
    }
    Ok(true)
}

pub async fn scheduler_cleanup_complete() -> Result<bool> {
    Ok(load_state().await?.scheduler_cleanup_complete)
}

pub async fn mark_scheduler_cleanup_complete() -> Result<()> {
    let mut state = load_state().await?;
    state.scheduler_cleanup_complete = true;
    save_state(&state).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_boundaries_are_aest_midnight() {
        assert_eq!(phase_at(CLEANUP_ONLY_AT - 1), Phase::Active);
        assert_eq!(phase_at(CLEANUP_ONLY_AT), Phase::CleanupOnly);
        assert_eq!(phase_at(SELF_DISABLE_AT - 1), Phase::CleanupOnly);
        assert_eq!(phase_at(SELF_DISABLE_AT), Phase::SelfDisabled);
    }

    #[test]
    fn nudge_is_due_immediately_then_every_48_hours() {
        assert!(should_open_nudge_at(None, 100));
        assert!(!should_open_nudge_at(
            Some(100),
            100 + NUDGE_INTERVAL_SECS - 1
        ));
        assert!(should_open_nudge_at(Some(100), 100 + NUDGE_INTERVAL_SECS));
    }
}
