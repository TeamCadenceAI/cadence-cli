# Phase 11 Code Review: `status` Subcommand

**Reviewer:** Claude Opus 4.6 (automated review)
**Date:** 2026-02-09
**Files reviewed:** `src/main.rs` (run_status + 7 tests), `src/git.rs`, `src/pending.rs`, `NOTES.md`, `TODO.md`
**Build status:** 238 tests passing, clippy clean (2 expected dead-code warnings), formatting clean.

---

## Summary

Phase 11 implements the `status` subcommand as specified in TODO.md. The implementation is clean, compact (90 lines), and reuses existing module APIs without introducing any new modules or public functions. All six TODO.md checklist items are fulfilled. Seven tests cover the feature. The function never returns `Err`, handling all failures gracefully.

Overall assessment: **Good implementation with minor issues.** No critical or commit-blocking bugs found.

---

## Findings

### 1. `run_status_returns_ok_outside_repo` does not actually test the outside-repo path (Medium)

**File:** `src/main.rs`, line 1034-1040

The test is named `run_status_returns_ok_outside_repo` and its comment says "it gracefully handles the case where git::repo_root() fails." However, the test is NOT marked `#[serial]` and does not change the working directory. Since `cargo test` runs with its CWD inside the project's git repository, `git::repo_root()` succeeds, meaning the test exercises the *inside-a-repo* path, not the outside-repo path.

The test passes, but it provides false confidence about the outside-repo code path. To actually test the outside-repo behavior, the test would need to `chdir` to a non-repo directory (e.g., `/tmp`) before calling `run_status()`.

Additionally, because this test is not `#[serial]`, it can run in parallel with other serial tests that manipulate CWD or `$HOME`. In practice this is low-risk because the test only asserts `is_ok()` and `run_status()` never returns `Err`, but it could read the developer's real `$HOME` and real global git config, making the test environment-dependent.

**Severity:** Medium. The key outside-repo code path (lines 767-770, 802-804, 831-833, 843-845) has zero test coverage.

---

### 2. `hooks_path` variable assigned and then immediately suppressed (Low)

**File:** `src/main.rs`, line 793

```rust
let _ = hooks_path; // suppress unused warning
```

The `hooks_path` value returned from the match block is stored in a `Some(path)` variable, but is never used again. The `let _ = hooks_path` line exists solely to suppress the compiler warning. This is a code smell: either the variable should be useful for something (e.g., included in a structured return type for programmatic consumers) or the match should not bind it.

A cleaner approach would be to avoid binding the variable at all -- the match block already prints the output as a side effect:

```rust
match git::config_get_global("core.hooksPath") {
    Ok(Some(path)) => { /* print */ }
    _ => { /* print */ }
}
```

**Severity:** Low. Cosmetic / tidiness issue.

---

### 3. Tests only assert `result.is_ok()` without verifying output content (Medium)

**File:** `src/main.rs`, tests at lines 2203-2442

All six status integration tests (`test_status_in_repo_shows_repo_root`, `test_status_shows_hooks_path_when_configured`, `test_status_shows_pending_count`, `test_status_shows_org_filter`, `test_status_shows_autopush_status`, `test_status_shows_repo_disabled`) follow the same pattern:

1. Set up state (repo, config, pending records, etc.)
2. Call `run_status()`
3. Assert `result.is_ok()`

Since `run_status()` *always* returns `Ok(())` regardless of what state it finds, `assert!(result.is_ok())` is a tautology. The tests do not verify that the correct output was actually printed.

For example, `test_status_shows_pending_count` creates 3 pending records but only verifies the count by calling `pending::list_for_repo` separately -- it never confirms that `run_status()` actually printed "Pending retries: 3". Similarly, `test_status_shows_repo_disabled` verifies `check_enabled()` returns `false` separately but does not confirm that `run_status()` printed "Repo enabled: no".

This means regressions in the output formatting (wrong field names, missing fields, wrong values) would not be caught by the test suite.

**Severity:** Medium. The tests verify that status does not crash but not that it produces correct output.

**Suggestion:** Either capture stderr and assert on specific output strings, or refactor `run_status()` to return a structured `StatusInfo` struct that tests can inspect. The stderr capture approach is simpler:
```rust
// Conceptual approach -- capture stderr
// Or refactor to return StatusInfo { repo: Option<PathBuf>, pending_count: usize, ... }
```

---

### 4. No test for the autopush "disabled (opted out)" and "not yet configured" paths (Low)

**File:** `src/main.rs`, lines 2381-2409

`test_status_shows_autopush_status` only tests the `autopush = true` case. The `autopush = false` (opted out) case and the unset/default case are not tested. Since `run_status()` has three distinct match arms for autopush (lines 819-829), two of the three arms have no dedicated test.

**Severity:** Low. The match arms are simple string prints and unlikely to regress, but completeness would be nice.

---

### 5. `pending::list_for_repo` reads from real `$HOME` in `test_status_shows_pending_count` side-verification (Low)

**File:** `src/main.rs`, lines 2323-2327

After calling `run_status()`, the test calls `pending::list_for_repo(&git_repo_root)` to verify the count is 3. This works because `$HOME` was redirected to `fake_home` (line 2294). However, the call to `pending::list_for_repo` is a side-verification of the pending module, not of `run_status()` itself. This is acceptable but slightly confusing -- it gives the impression that the test is verifying `run_status()` output, when it is really just verifying the test setup.

**Severity:** Low (informational). No bug, just a clarity concern.

---

### 6. Status reads developer's real global git config during `run_status_returns_ok_outside_repo` (Low)

**File:** `src/main.rs`, line 1038

As noted in finding #1, this non-serial test calls `run_status()` without isolating `$HOME` or `GIT_CONFIG_GLOBAL`. This means:
- `config_get_global("core.hooksPath")` reads the developer's actual global git config.
- `config_get_global("ai.barometer.org")` reads the developer's actual global git config.
- `pending::list_for_repo()` reads the developer's actual `~/.ai-barometer/pending/` directory.
- `config_get("ai.barometer.autopush")` reads from the repo where `cargo test` runs (this project).

If the developer has `core.hooksPath` or `ai.barometer.org` configured globally, the test output will include their real values. The test still passes (since `is_ok()` is always true), but it introduces a dependency on the developer's environment.

**Severity:** Low. Not a bug, but non-hermetic.

---

### 7. All output goes to stderr -- no stdout (Informational, by design)

**File:** `src/main.rs`, lines 758-848

All output uses `eprintln!` (stderr), consistent with every other subcommand in the project. The NOTES.md Phase 11 section documents this as intentional: "All output uses `[ai-barometer]` prefix on stderr, consistent with every other subcommand."

This is correct for the hook path (where stdout could interfere with git), but for an explicitly user-invoked diagnostic command like `status`, writing to stdout would be more conventional and would allow piping/capturing. This is a design question, not a bug.

**Severity:** Informational. Consistent with project-wide convention.

---

### 8. Completeness per TODO.md spec (Positive)

All six TODO.md Phase 11 items are implemented:

| TODO.md item | Implementation | Status |
|---|---|---|
| Show: current repo root | Lines 762-771 | Complete |
| Show: hooks path and whether shim is installed | Lines 774-792 | Complete |
| Show: number of pending retries for current repo | Lines 796-804 | Complete |
| Show: org filter config (if any) | Lines 807-814 | Complete |
| Show: autopush consent status | Lines 817-833 | Complete |
| Show: per-repo enabled/disabled status | Lines 836-845 | Complete |

**Severity:** Positive.

---

### 9. Graceful handling outside git repo (Positive, with caveat)

The implementation correctly handles the outside-repo case for all repo-dependent fields:
- Repo line shows "(not in a git repository)"
- Pending retries shows "(n/a - not in a repo)"
- Auto-push shows "(n/a - not in a repo)"
- Repo enabled shows "(n/a - not in a repo)"

Global config (hooks path, org filter) is correctly shown regardless of repo context.

The function always returns `Ok(())`.

**Caveat:** As noted in finding #1, this path is not actually tested.

**Severity:** Positive (implementation), but see finding #1 for testing gap.

---

### 10. No doc comment on `run_status` (Low)

**File:** `src/main.rs`, line 758

Unlike other subcommand handlers (`run_install`, `run_hook_post_commit`, `run_hydrate`, `run_retry`), `run_status` has no doc comment. The other handlers have detailed doc comments explaining their steps and behavior. Adding one for `run_status` would maintain consistency.

**Severity:** Low. Documentation gap.

---

### 11. `test_status_shows_hooks_path_when_configured` does not set `GIT_CONFIG_GLOBAL` before redirecting `$HOME` (Low)

**File:** `src/main.rs`, lines 2230-2282

The test sets `$HOME` and `GIT_CONFIG_GLOBAL` to isolated fake values, but the `$HOME` is set before `GIT_CONFIG_GLOBAL` (line 2262-2263). In the brief window between the two `set_var` calls, any concurrent test (unlikely because this is `#[serial]`, but worth noting) could read the wrong config. More importantly, if the `set_var("GIT_CONFIG_GLOBAL", ...)` line were to panic, `$HOME` would be left redirected without cleanup.

This is a pre-existing pattern used throughout the test suite and is not unique to Phase 11.

**Severity:** Low. Theoretical concern, mitigated by `#[serial]`.

---

## Recommendations Summary

| # | Finding | Severity | Recommendation |
|---|---|---|---|
| 1 | Outside-repo path not tested | Medium | Add a serial test that chdirs to a non-repo dir |
| 2 | Unused `hooks_path` binding | Low | Remove the variable binding |
| 3 | Tests don't verify output content | Medium | Capture stderr or return structured data |
| 4 | Missing autopush opt-out/default tests | Low | Add tests for false and unset cases |
| 5 | Side-verification in pending test | Low | Informational, no action needed |
| 6 | Non-hermetic outside-repo test | Low | Add `#[serial]` and env isolation |
| 7 | All output to stderr | Info | By design, no action needed |
| 8 | Completeness per TODO.md | Positive | All items implemented |
| 9 | Graceful outside-repo handling | Positive | Correct, but untested |
| 10 | Missing doc comment | Low | Add doc comment for consistency |
| 11 | Env var ordering in test setup | Low | Pre-existing pattern, no action needed |
