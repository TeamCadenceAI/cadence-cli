//! Permission gating for macOS TCC-protected folders (Documents, Desktop).
//!
//! On macOS, the first filesystem access under `~/Documents` or `~/Desktop`
//! triggers a Transparency, Consent, and Control (TCC) permission prompt.
//! Triggering those prompts as an incidental side effect of backfill leaves
//! the user without context on why Cadence wants access. This module surfaces
//! the prompts with an on-screen rationale instead, and persists a marker so
//! that existing users are not unexpectedly re-prompted on upgrade.
//!
//! Linux and Windows have no equivalent TCC gate for these folders, so the
//! rationale text, probes, and marker are all elided there — Desktop is simply
//! scanned unconditionally on those platforms.

use anyhow::Result;

#[cfg(target_os = "macos")]
use crate::output;

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use anyhow::Context;
    use std::path::PathBuf;

    pub(super) const DESKTOP_ACCESS_MARKER_FILE: &str = "desktop-access-requested";

    pub(super) fn desktop_access_marker_path() -> Option<PathBuf> {
        Some(crate::config::CliConfig::config_dir()?.join(DESKTOP_ACCESS_MARKER_FILE))
    }

    pub(super) async fn mark_desktop_access_requested() -> Result<()> {
        let Some(path) = desktop_access_marker_path() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
        tokio::fs::write(&path, b"")
            .await
            .with_context(|| format!("failed to write desktop access marker {}", path.display()))?;
        Ok(())
    }
}

/// Returns true once the user has been prompted for Desktop access.
///
/// On non-macOS platforms this always returns true: no TCC-equivalent gate
/// exists, so Desktop is freely readable and scanning it needs no opt-in.
pub(crate) async fn desktop_access_requested() -> bool {
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
    #[cfg(target_os = "macos")]
    {
        let Some(path) = macos::desktop_access_marker_path() else {
            return false;
        };
        tokio::fs::try_exists(&path).await.unwrap_or(false)
    }
}

/// First-install permission flow. On macOS, prints a short rationale and
/// probes `~/Documents` and `~/Desktop` to surface both TCC prompts while the
/// explanation is on screen, then records the marker.
///
/// The marker records "the user has been asked" (not "granted"). If the user
/// denies, subsequent probes simply fail silently; if they later enable access
/// in System Settings we'll start picking up matches without needing to
/// re-prompt.
///
/// On non-macOS this is a no-op — there is nothing to prompt for and Desktop
/// is already scanned by default.
pub(crate) async fn prompt_first_install_folder_access() -> Result<()> {
    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let Some(home) = crate::agents::home_dir() else {
            return Ok(());
        };

        println!();
        output::action("Folder access", "Documents and Desktop");
        output::detail("Cadence reads agent session logs and locates their Git repositories.");
        output::detail("macOS may now ask for access to Documents and Desktop — these are common");
        output::detail(
            "locations for Git repositories. Deny either and Cadence will skip that folder.",
        );

        let _ = tokio::fs::read_dir(home.join("Documents")).await;
        let _ = tokio::fs::read_dir(home.join("Desktop")).await;

        macos::mark_desktop_access_requested().await
    }
}

/// Explicit opt-in for existing users, wired as `cadence permissions request-desktop`.
///
/// On macOS, surfaces the TCC prompt for `~/Desktop` and persists the marker
/// so future backfills scan that folder. On non-macOS, reports that Desktop
/// access is unrestricted and exits successfully without side effects.
pub(crate) async fn request_desktop_access() -> Result<()> {
    #[cfg(not(target_os = "macos"))]
    {
        crate::output::detail(
            "Desktop folder access is not gated on this platform; no action required.",
        );
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let home = crate::agents::home_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine home directory"))?;

        println!();
        output::action("Folder access", "Desktop");
        output::detail(
            "Cadence will check ~/Desktop for Git repositories when matching agent sessions.",
        );
        output::detail(
            "macOS may prompt you now. Deny to keep Desktop inaccessible; Cadence will skip it.",
        );

        let _ = tokio::fs::read_dir(home.join("Desktop")).await;

        macos::mark_desktop_access_requested().await?;
        output::success("Recorded", "Desktop access preference");
        Ok(())
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use crate::test_support::EnvGuard;
    use serial_test::serial;
    use tempfile::TempDir;

    #[tokio::test]
    #[serial]
    async fn desktop_access_requested_is_false_before_marker_written() {
        let home = TempDir::new().expect("home tempdir");
        let guard = EnvGuard::new("HOME");
        guard.set_path(home.path());
        assert!(!desktop_access_requested().await);
    }

    #[tokio::test]
    #[serial]
    async fn mark_desktop_access_requested_creates_marker() {
        let home = TempDir::new().expect("home tempdir");
        let guard = EnvGuard::new("HOME");
        guard.set_path(home.path());

        macos::mark_desktop_access_requested()
            .await
            .expect("write desktop marker");

        assert!(desktop_access_requested().await);
        let marker = macos::desktop_access_marker_path().expect("marker path");
        assert!(marker.exists(), "marker file should exist at {marker:?}");
    }

    #[tokio::test]
    #[serial]
    async fn prompt_first_install_folder_access_records_marker() {
        let home = TempDir::new().expect("home tempdir");
        let guard = EnvGuard::new("HOME");
        guard.set_path(home.path());

        prompt_first_install_folder_access()
            .await
            .expect("first install folder access probe");

        assert!(desktop_access_requested().await);
    }
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn desktop_access_requested_is_always_true_off_macos() {
        assert!(desktop_access_requested().await);
    }

    #[tokio::test]
    async fn prompt_first_install_folder_access_is_noop_off_macos() {
        prompt_first_install_folder_access()
            .await
            .expect("first install folder access should succeed as a no-op");
    }

    #[tokio::test]
    async fn request_desktop_access_is_noop_off_macos() {
        request_desktop_access()
            .await
            .expect("request_desktop_access should succeed as a no-op");
    }
}
