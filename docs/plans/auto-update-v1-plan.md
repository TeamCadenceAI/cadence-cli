# Cadence Unattended Auto-Update v1 (Hook-Safe, Reliability-First)

## Summary

Build true unattended auto-updating that works even when users never open a terminal again after initial install.

Product constraints:

- Overlap between hooks and updater is expected to be rare.
- Hook flows always win.
- Reliability is prioritized over update speed.
- Stable releases only.
- Silent auto-install (no prompt/UI dependency).
- Minimal controls and local status visibility.

## Implementation Plan

1. Add a hidden internal updater entrypoint
- Add internal command path (for example `cadence hook auto-update`) for scheduler-triggered unattended updates.
- Reuse existing update install pipeline (`check -> download -> checksum -> extract -> self-replace`).
- Disable interactive prompts in this path.

2. Add a global activity lock to avoid mid-hook updates
- Add one shared cross-process lock under `~/.cadence/cli/locks/`.
- Use this lock in:
  - `hook post-commit`
  - `hook pre-push`
  - deferred-sync worker
  - auto-updater path
- Lock policy:
  - hooks/deferred-sync acquire and run immediately
  - updater attempts non-blocking acquire and exits fast if unavailable
- Outcome: updater never interferes with commit/push workflows.

3. Provision OS-native background scheduling via `cadence install`
- Add idempotent scheduler setup:
  - macOS: LaunchAgent
  - Linux: `systemd --user` timer/service (fallback only if user-systemd unavailable)
  - Windows: Task Scheduler task
- Schedule every 8 hours with random delay/jitter.
- Always point scheduler to current installed `cadence` executable path.

4. Persist updater state + retries
- Add updater state file in `~/.cadence/cli/` written atomically.
- Track:
  - `last_check_at`, `last_attempt_at`, `last_success_at`
  - `last_seen_version`, `last_installed_version`
  - `consecutive_failures`, `next_retry_after`
  - `last_error`
- Retry policy: capped exponential backoff + jitter.
- Reset failure counters on successful install.

5. Update config semantics and status surfaces
- Keep `auto_update` key, but redefine semantics:
  - `true`: unattended background updates enabled
  - `false`: scheduled updater no-ops
- Extend `cadence status` and `cadence doctor` to report updater health:
  - enabled/disabled
  - last result
  - next retry
  - last error
- No desktop notifications in v1.

## Testing Plan

1. Updater core logic
- update available -> unattended install succeeds
- up-to-date -> no install
- stable-only behavior
- retry/backoff state transitions

2. Concurrency and lock safety
- hook holds lock -> updater skips and reschedules
- deferred-sync holds lock -> updater skips
- concurrent updater invocations -> single runner
- hook performance remains non-blocking

3. Failure safety
- network/discovery/checksum/extraction/self-replace failures
- current binary remains usable
- failures recorded and retried

4. Scheduler provisioning
- idempotent install/repair across macOS/Linux/Windows paths
- scheduler points to current executable after reinstall/path changes
- `auto_update=false` causes scheduled run to exit cleanly

5. Status/doctor output
- never-run, healthy, retrying, disabled, and failing states render correctly

## Acceptance Criteria

- Cadence updates itself in background without terminal interaction when `auto_update=true`.
- Updater never interrupts or slows hook-driven commit/push paths.
- Failures are non-destructive and self-healing via retries.
- Users can inspect updater health from Cadence CLI status/doctor commands.
