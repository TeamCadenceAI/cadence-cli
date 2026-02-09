# Phase 6 Code Review: `hook post-commit` Subcommand

**Reviewer:** Claude Opus 4.6
**Date:** 2026-02-09
**Scope:** Phase 6 implementation (the critical hot path)
**Status:** 142 tests passing, clippy clean (expected dead-code warnings only), fmt clean

---

## Executive Summary

Phase 6 is well-implemented. The catch-all error/panic handling is sound and will never block a commit. The algorithm faithfully follows PLAN.md's Post-Commit Resolution Strategy. Module integration is clean, the pending stub is sufficient for Phase 6's needs, and the test suite covers the important integration scenarios. I found no commit-blocking bugs.

I identified 16 findings: 0 critical, 3 medium, 6 low, 7 informational.

---

## 1. Catch-All Error/Panic Handling

### 1.1 Verdict: Sound

The two-layer guard in `run_hook_post_commit()` (lines 81-97 of `src/main.rs`) is correctly structured:

1. **Panic guard:** `std::panic::catch_unwind` wraps the inner handler.
2. **Error guard:** `hook_post_commit_inner()` returns `anyhow::Result<()>`, and any `Err` is caught.
3. **Both cases:** Log a warning to stderr and return `Ok(())`.

This guarantees the function **never** returns `Err` and **never** panics, satisfying the PLAN.md requirement: "Commits are never blocked. Crashes in hooks must be caught."

### 1.2 [Info] `catch_unwind` does not catch all panics

`std::panic::catch_unwind` only catches panics that use the standard panic machinery. A panic configured with `panic = abort` in the Cargo profile, or a signal like SIGSEGV, will bypass it. This is fine for the default profile (which uses `unwind`), but worth noting if a future Cargo.toml change sets `panic = "abort"` for release builds. No action required now.

### 1.3 [Info] Missing chain context on logged errors

When the inner handler fails (line 88), the error is logged as `"hook failed: {}"`. The `anyhow::Error` Display impl only shows the outermost context. Using `{:#}` (alternate Display) would show the full chain, which is more useful for debugging. However, since this runs in the hook hot path and verbosity should be minimal, this is a stylistic choice, not a bug.

---

## 2. Algorithm vs PLAN.md Post-Commit Resolution Strategy

The implementation in `hook_post_commit_inner()` (lines 103-179) follows the PLAN.md algorithm step-by-step:

| PLAN.md Step | Implementation | Status |
|---|---|---|
| 1. Resolve repo root | `git::repo_root()` | Correct |
| 2. Resolve commit hash + timestamp | `git::head_hash()`, `git::head_timestamp()` | Correct |
| 3. Narrow candidate session dirs | `agents::claude::log_dirs()`, `agents::codex::log_dirs()` | Correct |
| 4. Narrow candidate files by time | `agents::candidate_files(&dirs, ts, 600)` | Correct (600 = 10 min) |
| 5. Stream files, substring match | `scanner::find_session_for_commit()` | Correct |
| 6. Parse minimal JSON fields | `scanner::parse_session_metadata()` | Correct |
| 7. Verify cwd + commit existence | `scanner::verify_match()` | Correct |
| If matched: attach note | `note::format()` + `git::add_note()` | Correct |
| If not matched: defer | `pending::write_pending()` | Correct |
| After resolving: retry pending | `retry_pending_for_repo()` | Correct (stub) |

### 2.1 [Medium] Deduplication check position

The deduplication check (line 111) runs **before** collecting candidate dirs. This matches PLAN.md's "before attaching anything" rule and is correctly placed. However, I note that `note_exists()` calls `git notes --ref=... show -- <commit>` which will write to stderr (suppressed) on miss. This is fine functionally but generates a brief git subprocess on every commit even when there is no AI session. This is the expected behavior per the plan.

### 2.2 [Low] Retry uses same 600-second window for pending commits

In `retry_pending_for_repo()` (line 211), the candidate file window is hardcoded to `600` seconds (same as the initial attempt). For retried pending commits, the time gap between the commit and the log file's mtime will only grow over time. Eventually, no candidate files will pass the window filter, and the pending record will never be resolved via this retry path.

Phase 7 should either widen the window for retries (e.g., `600 * (attempts + 1)`) or scan all files in the candidate directories without a time filter. The current stub behavior is acceptable for Phase 6 but will need to change.

### 2.3 [Info] PLAN.md says "Increment attempt counter" on retry failure

The current stub retry logic does not increment the attempt counter or update `last_attempt` when resolution fails. This is explicitly documented as a Phase 7 responsibility in NOTES.md and the code comments. Acceptable for Phase 6.

---

## 3. Integration Between Modules

### 3.1 Module call graph

```
main.rs (hook_post_commit_inner)
  -> git::repo_root()
  -> git::head_hash()
  -> git::head_timestamp()
  -> git::note_exists()
  -> agents::claude::log_dirs()
  -> agents::codex::log_dirs()
  -> agents::candidate_files()
  -> scanner::find_session_for_commit()
  -> scanner::parse_session_metadata()
  -> scanner::verify_match()
       -> git::repo_root_at()
       -> git::commit_exists_at()
  -> note::format()
       -> git::validate_commit_hash()
  -> git::add_note()
       -> git::validate_commit_hash()
  -> pending::write_pending()
  -> pending::list_for_repo()
  -> pending::remove()
```

The integration is clean. Each module has a well-defined responsibility and the call graph is acyclic except for the cross-module validation calls (scanner and note both call into git for `validate_commit_hash`, which is appropriate).

### 3.2 [Medium] `read_to_string` loads entire session log into memory

At line 132, after finding a match, the entire session log is loaded into memory with `std::fs::read_to_string(&matched.file_path)`. The PLAN.md notes "Session logs can be very large (tens of MB)" and the scanner module specifically uses `BufReader` for streaming. However, since the note format requires the full verbatim session log as payload, loading it into memory is currently unavoidable -- the note must be passed as a single string to `git notes add -m`.

This is not a bug, but for very large session logs (100+ MB), this could cause memory pressure. Phase 12 (Hardening) lists "Handle very large session logs (streaming, not loading into memory)" as a future task. A possible mitigation would be to use `git notes add -F <file>` instead of `-m <content>`, writing the formatted note to a temp file first. This would avoid the `arg_max` limit on command-line arguments as well.

### 3.3 [Medium] `unwrap_or_default()` on `read_to_string` silently produces empty note

At line 132:
```rust
let session_log = std::fs::read_to_string(&matched.file_path).unwrap_or_default();
```

If the file read fails (permissions, file deleted between match and read, etc.), the session log silently becomes an empty string. The note is still attached with valid headers and an empty payload. This is misleading -- the note would have `payload_sha256` matching the SHA of an empty string, but the original session data is lost.

A better approach would be to propagate the error (using `?`) so it falls through to the pending path. If reading the file fails, treating it as "no match" and writing a pending record would be more correct -- the file might become readable on a future retry. Same issue exists in the retry path at line 219.

### 3.4 [Low] Redundant hash validation

The commit hash passes through `validate_commit_hash` multiple times:
- `note_exists()` validates it (line 111)
- `verify_match()` validates it (scanner.rs line 201)
- `note::format()` validates it (note.rs line 51)
- `add_note()` validates it (git.rs line 139)

This is defensive-in-depth and not a bug. The overhead is negligible (a few string length checks). If anything, it is a positive pattern for a security-conscious codebase. Noted as informational only.

### 3.5 [Info] `repo_root_str` computed from `to_string_lossy`

Line 108: `let repo_root_str = repo_root.to_string_lossy().to_string();`

If the repo root somehow contains non-UTF-8 bytes, `to_string_lossy` will replace them with the Unicode replacement character. This could cause the pending record's `repo` field to not match the actual path on disk, preventing retries from finding the record. In practice, git repo paths are always UTF-8 (git itself requires this), so this is not a real risk.

---

## 4. Test Quality and Coverage

### 4.1 Integration tests (5 new tests in Phase 6)

| Test | What it covers | Quality |
|---|---|---|
| `test_hook_post_commit_attaches_note_to_commit` | Full happy path: temp repo, fake Claude session log, mtime set, chdir, run hook, verify note attached with correct fields | Excellent |
| `test_hook_post_commit_deduplication_skips_if_note_exists` | Pre-existing note is not overwritten | Good |
| `test_hook_post_commit_no_match_writes_pending` | No session log -> pending record written | Good |
| `test_hook_post_commit_never_fails_outside_git_repo` | Catch-all wrapper returns Ok even outside a repo | Good |
| `test_pending_record_struct` | Basic struct construction | Minimal (but sufficient for a stub) |

### 4.2 [Low] Missing test: verification failure path

There is no test that exercises the path where `scanner::find_session_for_commit` returns a match but `scanner::verify_match` returns `false` (lines 156-164). This is the path where a session file contains the commit hash but the cwd points to a different repo. A test for this would require creating a fake session log with the commit hash but a mismatched `cwd` field.

### 4.3 [Low] Missing test: retry resolves a pending commit

The `retry_pending_for_repo` function is tested only indirectly (via `test_hook_post_commit_no_match_writes_pending`, which does not verify retry behavior). There is no test that:
1. Creates a pending record
2. Creates a matching session log
3. Runs the hook (or calls retry directly) and verifies the pending record is resolved

This is acceptable for Phase 6 since retry is explicitly a Phase 7 concern, but it means the retry stub has no test coverage beyond "it doesn't crash."

### 4.4 [Info] `safe_cwd()` helper is a smart defensive pattern

The `safe_cwd()` helper (lines 454-465) handles the case where a previous serial test panicked and left the process CWD in a deleted temp directory. This is a well-thought-out defensive measure for test reliability.

### 4.5 [Low] Integration test cleanup is best-effort

The `test_hook_post_commit_attaches_note_to_commit` test creates a directory under the real `~/.claude/projects/` (line 491). Cleanup on line 534 uses `let _ = std::fs::remove_dir_all(...)` which silently ignores errors. If the test panics between creation and cleanup, the fake directory remains on disk. This could theoretically interfere with real AI Barometer usage if the encoded path matches a real repo.

A more robust approach would be to use a `Drop` guard or `defer!` pattern for cleanup, but this is low priority since:
- Tests rarely panic after the critical section
- The directory name is an encoded temp path (unlikely to collide with real repos)
- The `TempDir` drop will clean up the temp repo itself

---

## 5. Pending Module Stub Assessment

### 5.1 Verdict: Sufficient for Phase 6

The `src/pending.rs` stub provides the four functions needed by the hook handler:
- `write_pending()` -- writes real JSON files to `~/.ai-barometer/pending/`
- `list_for_repo()` -- reads and filters pending records by repo path
- `remove()` -- deletes resolved pending records
- `pending_dir()` -- returns/creates the pending directory

These are not empty stubs -- they write and read real files, which means the pending system works end-to-end even before Phase 7.

### 5.2 [Low] No `serde::Deserialize` on `PendingRecord`

The `PendingRecord` struct has `#[derive(Debug, Clone)]` but does not derive `serde::Deserialize`. Instead, `list_for_repo` manually extracts fields from `serde_json::Value`. Phase 7 should add `#[derive(Serialize, Deserialize)]` and use `serde_json::from_str::<PendingRecord>()` for cleaner deserialization. The current approach works but is fragile -- field names must be kept in sync between `write_pending` (which uses `json!()` macro) and `list_for_repo` (which uses `.get("field_name")`).

### 5.3 [Info] Missing `increment` function

PLAN.md and TODO.md list `pending::increment(record)` as a Phase 7 deliverable. The Phase 6 stub does not include it, which is correct -- the hook handler does not call it. Phase 7 will need to add it.

### 5.4 [Info] `pending_dir()` races on directory creation

If two concurrent post-commit hooks run simultaneously (e.g., two repos committing at the same time), both might check `!dir.exists()` and then both call `create_dir_all`. This is safe because `create_dir_all` is idempotent (it succeeds even if the directory already exists). No issue here.

### 5.5 [Info] Pending filename uses full commit hash

`write_pending` writes to `<commit-hash>.json` using the full 40-character hash. This matches the PLAN.md format and avoids collision risks from short hashes. Good.

---

## 6. Commit-Blocking Bug Analysis

**The hook must never block a commit.** I examined every code path for potential blocking scenarios:

| Scenario | Risk | Mitigation |
|---|---|---|
| Panic in inner handler | Caught by `catch_unwind` | Returns `Ok(())` |
| Error in inner handler | Caught by `match result` | Returns `Ok(())` |
| `git notes add` fails | Propagated as `Err`, caught by outer handler | Returns `Ok(())` |
| `note::format` fails | Propagated as `Err`, caught by outer handler | Returns `Ok(())` |
| `pending::write_pending` fails | Explicitly caught with `if let Err(e)` | Logs warning, continues |
| `retry_pending_for_repo` fails | All errors swallowed internally | Continues |
| Session log file unreadable | `unwrap_or_default()` returns empty string | Continues (see 3.3) |
| Home directory missing | `agents::home_dir()` returns `None`, empty dirs | Empty candidate list, pending write fails, caught |
| `~/.claude/projects/` missing | `read_dir` returns `Err`, ignored | Empty candidate list |

**Verdict: No commit-blocking bugs found.** All error paths eventually reach the outer catch-all and return `Ok(())`.

---

## 7. Additional Observations

### 7.1 [Info] `head_hash[..7]` slice in log message could panic

Line 152: `&head_hash[..7]`
Line 238: `&record.commit[..std::cmp::min(7, record.commit.len())]`

The main path on line 152 slices without bounds checking. If `head_hash` were ever fewer than 7 characters, this would panic. However, by this point in the code, `head_hash` has already passed through `note_exists()` which calls `validate_commit_hash()` requiring 7-40 characters. So the panic is unreachable. The retry path on line 238 correctly uses `min(7, len)` as a defensive measure since the commit comes from a pending record file. Good asymmetry -- the main path can trust the validated hash; the retry path defensively handles potentially corrupt data.

### 7.2 [Info] No logging/tracing beyond stderr

The hook uses `eprintln!` with the `[ai-barometer]` prefix for all output. There is no structured logging or verbosity control. This is appropriate for the hook path (which should be quiet) but Phase 12 or a future phase may want to add a `--verbose` flag or `RUST_LOG`-based tracing for debugging.

---

## Summary of Findings

| # | Severity | Description | Action |
|---|---|---|---|
| 1.2 | Info | `catch_unwind` doesn't catch `abort` panics | Note for Cargo.toml |
| 1.3 | Info | Error log could use `{:#}` for full chain | Optional improvement |
| 2.2 | Low | Retry uses same 600s window (will fail for old commits) | Phase 7 fix |
| 2.3 | Info | Retry doesn't increment attempt counter | Phase 7 responsibility |
| 3.2 | Medium | `read_to_string` loads full log into memory | Phase 12 concern |
| 3.3 | Medium | `unwrap_or_default` silently produces empty note on read failure | Fix: propagate error |
| 3.4 | Low | Redundant hash validation (not a bug, defense-in-depth) | No action |
| 3.5 | Info | `to_string_lossy` could mangle non-UTF-8 paths | Theoretical only |
| 4.2 | Low | No test for verification-failure -> pending path | Add test |
| 4.3 | Low | No test for retry resolving a pending commit | Phase 7 |
| 4.5 | Low | Integration test creates dirs under real ~/.claude | Low risk |
| 5.2 | Low | PendingRecord lacks serde derives | Phase 7 cleanup |
| 5.3 | Info | Missing `increment` function | Phase 7 |
| 5.4 | Info | Concurrent `create_dir_all` is safe | No issue |
| 5.5 | Info | Pending filename uses full hash | Good |
| 7.1 | Info | `head_hash[..7]` safe due to prior validation | No issue |

### Recommended Priority Fixes (before moving to Phase 7)

1. **[3.3 - Medium]** Change `unwrap_or_default()` on `read_to_string` to propagate the error so that unreadable files fall through to the pending path rather than creating empty notes.
2. **[4.2 - Low]** Add a test for the verify_match failure -> pending path.

### Deferred to Later Phases

- **[3.2]** Streaming note attachment via `git notes add -F` (Phase 12)
- **[2.2]** Widened retry window or full directory scan (Phase 7)
- **[5.2]** Serde derives on PendingRecord (Phase 7)
