//! Push decision logic for AI session notes.
//!
//! Orchestrates the decision of whether to push notes to the remote after
//! attaching them locally. The decision depends on several factors:
//!
//! 1. **Has upstream**: repo must have at least one configured remote.
//! 2. **Org filter**: if `git config --global ai.barometer.org` is set,
//!    at least one remote must belong to that org. Otherwise, notes are
//!    attached locally only (no push).
//! 3. **Autopush consent**: `git config ai.barometer.autopush` -- on first
//!    push for a repo, print a warning and record consent. After that,
//!    push silently.
//!
//! Note: The per-repo enabled check (`git config ai.barometer.enabled`) is
//! handled by [`git::check_enabled()`] in the git module, since it gates
//! ALL processing (not just push).
//!
//! Push failures are always non-fatal: logged to stderr, never block the
//! commit, never retry automatically in the hook.

use std::path::Path;

use crate::git;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Determine whether notes should be pushed for this repository.
///
/// Orchestrates all checks: enabled (already checked by caller), has upstream,
/// org filter, and autopush consent.
///
/// Returns `true` if all conditions are met and notes should be pushed.
/// Returns `false` if any condition prevents pushing.
///
/// The `repo_root` parameter is used for logging context only.
pub fn should_push(_repo_root: &Path) -> bool {
    // Check 1: Does the repo have a remote?
    match git::has_upstream() {
        Ok(true) => {}
        _ => return false,
    }

    // Check 2: Org filter
    if !check_org_filter() {
        return false;
    }

    // Check 3: Autopush consent
    if !check_or_request_consent() {
        return false;
    }

    true
}

/// Attempt to push notes to the remote. Handles failure gracefully.
///
/// On success: silent (no output).
/// On failure: logs a warning to stderr. Never blocks, never retries.
pub fn attempt_push() {
    if let Err(e) = git::push_notes() {
        eprintln!("[ai-barometer] warning: failed to push notes: {}", e);
    }
}

/// Check the org filter: if a global org is configured, verify that at least
/// one remote belongs to that org.
///
/// Reads `git config --global ai.barometer.org`. If not set, the filter
/// passes (no org restriction). If set, extracts orgs from ALL remotes
/// and checks for a match via [`org_matches`].
///
/// Returns `true` if push is allowed (no filter, or filter matches).
/// Returns `false` if the org filter is set and no remote matches.
pub fn check_org_filter() -> bool {
    let configured_org = match git::config_get_global("ai.barometer.org") {
        Ok(Some(org)) => org,
        // No org filter configured: allow push
        _ => return true,
    };

    // Get orgs from ALL remotes
    let remote_orgs = match git::remote_orgs() {
        Ok(orgs) => orgs,
        // If we can't read remotes, don't push
        Err(_) => return false,
    };

    org_matches(&configured_org, &remote_orgs)
}

/// Pure-logic helper: check whether any of the `remote_orgs` matches the
/// `configured_org` using case-insensitive comparison.
///
/// This is extracted from [`check_org_filter`] for testability — the
/// orchestration function reads from global git config which is hard to
/// isolate in tests, but this pure function can be tested directly.
pub fn org_matches(configured_org: &str, remote_orgs: &[String]) -> bool {
    remote_orgs
        .iter()
        .any(|org| org.eq_ignore_ascii_case(configured_org))
}

/// Check autopush consent. On first push for a repo, print a warning to
/// stderr and record consent by setting `git config ai.barometer.autopush true`.
///
/// Returns `true` if consent is granted (either already recorded or just granted).
/// Returns `false` if consent cannot be recorded (config write failure).
pub fn check_or_request_consent() -> bool {
    match git::config_get("ai.barometer.autopush") {
        Ok(Some(val)) if val == "true" => {
            // Consent already recorded, push silently
            return true;
        }
        Ok(Some(val)) if val == "false" => {
            // Explicitly opted out of push
            return false;
        }
        _ => {
            // Not set or error reading: this is the first push for this repo.
            // Print a consent warning and record it.
        }
    }

    // First push for this repo: print informational warning
    eprintln!(
        "[ai-barometer] This is the first time AI Barometer will push notes for this repository."
    );
    eprintln!("[ai-barometer] AI session notes will be pushed to the remote via:");
    eprintln!("[ai-barometer]   git push origin refs/notes/ai-sessions");
    eprintln!("[ai-barometer] To disable, run: git config ai.barometer.autopush false");

    // Record consent
    if let Err(e) = git::config_set("ai.barometer.autopush", "true") {
        eprintln!(
            "[ai-barometer] warning: failed to record autopush consent: {}",
            e
        );
        // Still allow this push attempt even if we couldn't save the config
        return true;
    }

    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::path::PathBuf;
    use std::process::Command;
    use tempfile::TempDir;

    /// Helper: create a temporary git repo with one commit.
    fn init_temp_repo() -> TempDir {
        let dir = TempDir::new().expect("failed to create temp dir");
        let path = dir.path();

        run_git(path, &["init"]);
        run_git(path, &["config", "user.email", "test@test.com"]);
        run_git(path, &["config", "user.name", "Test User"]);
        std::fs::write(path.join("README.md"), "hello").unwrap();
        run_git(path, &["add", "README.md"]);
        run_git(path, &["commit", "-m", "initial commit"]);

        dir
    }

    /// Run a git command inside the given directory, panicking on failure.
    fn run_git(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(["-C", dir.to_str().unwrap()])
            .args(args)
            .output()
            .expect("failed to run git");
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("git {:?} failed: {}", args, stderr);
        }
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    /// Helper: get a stable directory to use as a fallback CWD.
    fn safe_cwd() -> PathBuf {
        match std::env::current_dir() {
            Ok(cwd) if cwd.exists() => cwd,
            _ => {
                let fallback = std::env::temp_dir();
                std::env::set_current_dir(&fallback).ok();
                fallback
            }
        }
    }

    // -----------------------------------------------------------------------
    // check_or_request_consent
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_consent_first_time_grants_and_records() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // No autopush config set -- first time
        assert!(check_or_request_consent());

        // Should now have autopush=true recorded
        let val = run_git(dir.path(), &["config", "--get", "ai.barometer.autopush"]);
        assert_eq!(val, "true");

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_consent_already_true() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        run_git(dir.path(), &["config", "ai.barometer.autopush", "true"]);
        assert!(check_or_request_consent());

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_consent_explicitly_false_denies() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        run_git(dir.path(), &["config", "ai.barometer.autopush", "false"]);
        assert!(!check_or_request_consent());

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_consent_second_call_is_silent() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // First call: grants consent and records it
        assert!(check_or_request_consent());
        // Second call: should still return true (already recorded)
        assert!(check_or_request_consent());

        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // check_org_filter
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_org_filter_no_config_allows_push() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Use an empty global config so we don't depend on the developer's
        // real global git config (which might have ai.barometer.org set).
        let global_config = dir.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // No global org config -- filter should pass
        assert!(check_org_filter());

        // Restore
        unsafe {
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_org_filter_matching_org_allows_push() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Add a remote with a known org
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:my-org/my-repo.git",
            ],
        );

        // Create a global config with matching org filter
        let global_config = dir.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "[ai \"barometer\"]\n    org = my-org\n").unwrap();

        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // check_org_filter should pass because the remote org matches
        assert!(check_org_filter());

        // Restore
        unsafe {
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_org_filter_no_remote_denies_push() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Create a global config with an org filter set
        let global_config = dir.path().join("fake-global-gitconfig");
        std::fs::write(
            &global_config,
            "[ai \"barometer\"]\n    org = required-org\n",
        )
        .unwrap();

        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // No remotes configured -- org filter should deny (no remote matches)
        assert!(!check_org_filter());

        // Restore
        unsafe {
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // should_push
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_should_push_no_remote_returns_false() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // No remote -- should_push should return false
        assert!(!should_push(dir.path()));

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_should_push_with_remote_and_consent() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Add a remote
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:test-org/test-repo.git",
            ],
        );

        // Pre-set consent so should_push doesn't need to print the warning
        run_git(dir.path(), &["config", "ai.barometer.autopush", "true"]);

        // should_push should return true (remote exists, no org filter, consent given)
        assert!(should_push(dir.path()));

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_should_push_consent_denied_returns_false() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Add a remote
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:test-org/test-repo.git",
            ],
        );

        // Explicitly deny consent
        run_git(dir.path(), &["config", "ai.barometer.autopush", "false"]);

        assert!(!should_push(dir.path()));

        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // remote_orgs with multiple remotes
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_remote_orgs_multiple_remotes() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Add multiple remotes with different orgs
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:org-one/repo1.git",
            ],
        );
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "upstream",
                "https://github.com/org-two/repo2.git",
            ],
        );

        let orgs = git::remote_orgs().unwrap();
        assert_eq!(orgs.len(), 2);
        assert!(orgs.contains(&"org-one".to_string()));
        assert!(orgs.contains(&"org-two".to_string()));

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_remote_orgs_deduplicates() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Add two remotes with the same org
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:same-org/repo1.git",
            ],
        );
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "fork",
                "https://github.com/same-org/repo2.git",
            ],
        );

        let orgs = git::remote_orgs().unwrap();
        assert_eq!(orgs.len(), 1);
        assert_eq!(orgs[0], "same-org");

        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // org_matches (pure-logic unit tests)
    // -----------------------------------------------------------------------

    #[test]
    fn test_org_matches_exact() {
        let orgs = vec!["my-org".to_string()];
        assert!(org_matches("my-org", &orgs));
    }

    #[test]
    fn test_org_matches_case_insensitive() {
        let orgs = vec!["my-org".to_string()];
        assert!(org_matches("My-Org", &orgs));
        assert!(org_matches("MY-ORG", &orgs));
    }

    #[test]
    fn test_org_matches_reverse_case() {
        // Configured is lowercase, remote is mixed case
        let orgs = vec!["My-Org".to_string()];
        assert!(org_matches("my-org", &orgs));
    }

    #[test]
    fn test_org_matches_no_match() {
        let orgs = vec!["other-org".to_string()];
        assert!(!org_matches("my-org", &orgs));
    }

    #[test]
    fn test_org_matches_empty_remotes() {
        let orgs: Vec<String> = vec![];
        assert!(!org_matches("my-org", &orgs));
    }

    #[test]
    fn test_org_matches_multiple_remotes_one_matches() {
        let orgs = vec!["unrelated".to_string(), "my-org".to_string()];
        assert!(org_matches("my-org", &orgs));
    }

    #[test]
    fn test_org_matches_multiple_remotes_none_match() {
        let orgs = vec!["org-a".to_string(), "org-b".to_string()];
        assert!(!org_matches("my-org", &orgs));
    }

    // -----------------------------------------------------------------------
    // should_push with org filter
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_should_push_org_filter_denies_returns_false() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Add a remote with org "actual-org"
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:actual-org/repo.git",
            ],
        );

        // Pre-set consent so we isolate the org filter behavior
        run_git(dir.path(), &["config", "ai.barometer.autopush", "true"]);

        // Create a temp global config file with a different org filter
        let global_config = dir.path().join("fake-global-gitconfig");
        std::fs::write(
            &global_config,
            "[ai \"barometer\"]\n    org = required-org\n",
        )
        .unwrap();

        // Point GIT_CONFIG_GLOBAL to our fake global config
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // should_push should return false because "actual-org" != "required-org"
        assert!(!should_push(dir.path()));

        // Restore GIT_CONFIG_GLOBAL
        unsafe {
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_should_push_org_filter_allows_matching_org() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Add a remote with org "my-org"
        run_git(
            dir.path(),
            &["remote", "add", "origin", "git@github.com:my-org/repo.git"],
        );

        // Pre-set consent
        run_git(dir.path(), &["config", "ai.barometer.autopush", "true"]);

        // Create a global config file with matching org filter
        let global_config = dir.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "[ai \"barometer\"]\n    org = my-org\n").unwrap();

        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // should_push should return true because "my-org" matches
        assert!(should_push(dir.path()));

        // Restore
        unsafe {
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_check_org_filter_end_to_end_with_global_config() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Add a remote with org "test-org"
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:test-org/repo.git",
            ],
        );

        // Create a global config with matching org
        let global_config = dir.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "[ai \"barometer\"]\n    org = Test-Org\n").unwrap();

        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // Case-insensitive match: "Test-Org" should match "test-org"
        assert!(check_org_filter());

        // Now test with non-matching org
        std::fs::write(&global_config, "[ai \"barometer\"]\n    org = other-org\n").unwrap();

        assert!(!check_org_filter());

        // Restore
        unsafe {
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // attempt_push — always succeeds (never panics)
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_attempt_push_failure_does_not_panic() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // No remote configured -- push will fail, but should not panic
        attempt_push();

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_attempt_push_with_unreachable_remote_does_not_panic() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Add a remote that doesn't actually exist
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:nonexistent/repo.git",
            ],
        );

        // This will fail (can't connect) but should not panic or block
        attempt_push();

        std::env::set_current_dir(original_cwd).unwrap();
    }
}
