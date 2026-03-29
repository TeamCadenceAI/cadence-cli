# Fix Global Discovery Cursor Stall

## Problem

The monitor's `upload_incremental_sessions_globally` function uses a single
global discovery cursor to track progress across all repos and agent types. When
any session produces a `Retryable` upload outcome, the function sets a
`cursor_blocked` flag that prevents cursor advancement for **every subsequent
session in that tick**, even ones that upload successfully. The next tick
rediscovers the same sessions from the stalled position. If the error persists
(e.g., a repo whose `git remote` is temporarily unreachable), the entire
discovery pipeline stalls indefinitely.

A second stall site exists in the org-filter check: if
`git::repo_matches_org_filter` returns an error, the same `cursor_blocked = true`
fires and the loop continues without advancing.

The codebase already has a durable retry system (publication-state with
exponential backoff) that handles retries for queued sessions. The cursor
blocking mechanism is a parallel retry system that duplicates this, but worse —
it blocks all sessions, not just the failing one.

## Approach

**Always advance the cursor. Use publication-state for retries.**

After this change:
- Cursor = "what have I discovered" (always moves forward)
- Publication-state = "what needs retry" (handles failures with backoff)

The `cursor_blocked` flag, the `maybe_advance_monitor_cursor` gatekeeper, and
all code that conditions cursor advancement on prior outcomes are removed.

## Desired Behavior

- A single failing session never blocks discovery of other sessions.
- Sessions that fail with retryable errors are persisted into publication-state
  before the cursor advances past them, so they are retried by the existing
  pending drain on subsequent ticks.
- Sessions that fail before preparation (e.g., `git remote` fails) are
  queued into publication-state in a retriable status so the pending drain
  can reattempt them later.
- The org-filter error path no longer blocks the cursor; it skips the session
  and advances, logging the issue.
- All existing non-error behavior (Uploaded, AlreadyExists, Queued) is unchanged.

## Required Code Changes

### 1. Remove cursor blocking from `apply_monitor_incremental_upload_outcome`

**File:** `src/main.rs`, lines 478–507

Remove the `cursor_blocked` parameter. The `Retryable` match arm should advance
the cursor instead of blocking it. The function signature becomes:

```rust
fn apply_monitor_incremental_upload_outcome(
    stats: &mut MonitorTickSummary,
    cursor_advance: &mut IncrementalCursor,
    log_mtime: Option<i64>,
    log_source_label: &str,
    outcome: UploadFromLogOutcome,
)
```

All match arms advance the cursor unconditionally via
`advance_cursor_for_disposition`. The `Retryable` arm increments
`stats.issues` and advances.

### 2. Remove `maybe_advance_monitor_cursor`

**File:** `src/main.rs`, lines 509–519

This function exists solely to gate advancement on `cursor_blocked`. Delete it.
All call sites that previously called `maybe_advance_monitor_cursor` should call
`advance_cursor_for_disposition` directly (there is no reason to conditionally
skip advancement anymore).

### 3. Remove `cursor_blocked` from `upload_incremental_sessions_globally`

**File:** `src/main.rs`, line 1574 and all references in lines 1574–1666

Delete the `let mut cursor_blocked = false;` declaration and remove
`cursor_blocked` from all `maybe_advance_monitor_cursor` call sites (which will
now be direct `advance_cursor_for_disposition` calls). This includes:

- Line 1580–1585: no-cwd skip → advance cursor directly
- Line 1599–1604: no-repo skip → advance cursor directly
- Line 1616–1621: repo-disabled skip → advance cursor directly
- Line 1640–1645: org-mismatch skip → advance cursor directly

### 4. Fix the org-filter error path

**File:** `src/main.rs`, lines 1630–1634

Currently:
```rust
Err(_) => {
    stats.issues += 1;
    cursor_blocked = true;
    continue;
}
```

Change to: increment `stats.issues`, advance the cursor past this session, and
continue. The session is skipped for this tick. Because the org-filter result is
cached per repo, the same repo will hit the same error on subsequent sessions in
this tick (which is fine — each one advances the cursor). On the next tick, the
cursor has moved past these sessions and the org check is retried fresh.

### 5. Ensure Retryable outcomes persist to publication-state before returning

**File:** `src/main.rs`, `upload_session_from_log` function (lines 604–720)

There are five `Retryable` return sites. Two of them return **before** the
session has been prepared or persisted:

- **Line 632:** `git::remote_urls_at` fails → returns Retryable with no state
  persisted. The session data (parsed log, repo root, metadata) is available but
  `prepare_session_upload` was never called.

- **Line 711:** `prepare_session_upload` fails → returns Retryable with no state
  persisted. The observations were constructed but preparation itself failed.

The other three (lines 673, 683, 718) return Retryable after
`upload_or_queue_prepared_session` has already been called, which means
publication-state has already been written by `persist_state`.

For the two early-return sites, the session must be persisted into
publication-state before returning so that the pending drain can reattempt later.
The approach for each:

**Line 632 (remote_urls_at failure):** Construct observations with empty
`remote_urls` and `canonical_remote_url`, call `prepare_session_upload`, and
persist with `RetryableFailure` status. If preparation itself fails, return
`Retryable` — this is a degenerate case (session data is malformed) and the
cursor should still advance past it. The session will be rediscovered only if
its mtime changes.

**Line 711 (prepare_session_upload failure):** Preparation failed, so there is
no `PreparedSessionUpload` to persist. This indicates malformed session content.
Advance the cursor past it. Do not persist — there is nothing usable to retry.
Change this outcome from `Retryable` to a new skip disposition or keep as
`Retryable` with the understanding that the cursor advances anyway (since all
outcomes now advance the cursor, this is safe).

### 6. Update tests

**File:** `src/main.rs`, tests section

**Delete or rewrite:**
- `monitor_retryable_incremental_outcome_blocks_future_cursor_advances`
  (lines 3527–3561): This test asserts that Retryable blocks the cursor and
  that subsequent Uploaded outcomes don't advance. After the fix, both should
  advance. Rewrite to verify that Retryable advances the cursor and does not
  affect subsequent outcomes.

- `monitor_retryable_block_prevents_non_applicable_cursor_advances`
  (lines 3564–3574): Tests `maybe_advance_monitor_cursor` with `blocked=true`.
  Delete — the function no longer exists.

**Add:**
- A test verifying that a Retryable outcome followed by an Uploaded outcome
  results in the cursor at the Uploaded session's position (not stuck at the
  pre-Retryable position).
- A test verifying that the org-filter error path advances the cursor past the
  failing session.

## What Does NOT Change

- `UploadFromLogOutcome` enum stays the same (Uploaded, AlreadyExists, Queued,
  Retryable). Retryable is still a meaningful signal for stats tracking.
- `IncrementalCursor` struct and `advance_cursor_for_disposition` are unchanged.
- `select_incremental_candidates` and cursor filtering logic are unchanged.
- Pending drain (`process_pending_uploads`) is unchanged.
- `MonitorTickSummary` and `stats.issues` counting are unchanged.
- Publication-state persistence and exponential backoff are unchanged.
- All non-Retryable upload paths are unchanged.

## Verification

Before committing, run:

- `cargo fmt -- --check`
- `cargo clippy --all-targets --all-features`
- `cargo test --no-fail-fast`
