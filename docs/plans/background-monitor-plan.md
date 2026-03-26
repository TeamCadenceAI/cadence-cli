# Cadence Background Monitor Plan

## Summary

This document is the current plan for moving Cadence from hook-owned live
ingestion to background monitoring.

It was revised against the codebase on 2026-03-26.

The previous version of this document was no longer accurate because it assumed
the CLI was still on a pre-v2 publication path. That is no longer true:

- the CLI already publishes through `/api/v2/session-publications`
- the codebase already has `LogicalSessionKey`, `publish_uid`, and durable
  `publication_state`
- backfill already uses the same publication pipeline as live ingestion

This plan is therefore a runtime/install/status/doctor migration plan on top of
the current publication stack. It is not a plan for changing publication
contracts.

## Current Codebase Snapshot

As of 2026-03-26, the relevant runtime shape is:

- `cadence install` sets global `core.hooksPath`, writes `~/.git-hooks/post-commit`,
  removes a Cadence-managed `pre-push` hook, persists `ai.cadence.org`, and
  reconciles the auto-update scheduler
- live ingestion is triggered by `cadence hook post-commit`
- `hook post-commit` drains pending publications, incrementally scans recent
  session logs for the current repo, and uploads through `src/upload.rs`
- the publication stack already uses:
  - `src/publication.rs`
  - `src/publication_state.rs`
  - `src/upload.rs`
  - `/api/v2/session-publications`
- current live incremental discovery is driven by repo-scoped upload cursors in
  `src/upload_cursor.rs`
- `cadence backfill` already performs global session discovery, repo
  resolution, repo grouping, and publication through the same upload pipeline
- OS-native scheduler support already exists, but it is owned by `src/update.rs`
  and currently targets `cadence hook auto-update`
- `status` and `doctor` are still hook-centric and treat hook presence as a
  primary source of install truth

## Goal

After `cadence install`, Cadence should behave like a background capability
without taking ownership of the user's Git hook setup.

Desired outcomes:

- `cadence install` enables background monitoring
- Cadence no longer requires `post-commit` hooks for correctness
- existing user hooks continue to work untouched
- repo-local or global `core.hooksPath` no longer determines whether Cadence
  works
- live discovery and retry move off commit-time execution
- the current publication semantics remain intact

## Non-Goals

- redesigning the current publication contract
- rolling the CLI back to any v1 upload model
- redesigning `LogicalSessionKey`, `publish_uid`, or durable publication-state
  semantics
- changing org-selection rules
- changing material metadata hash semantics
- reconstructing historical branch/HEAD truth for old sessions
- changing repo/org ignore behavior
- building a long-lived daemon
- adding burst mode or sub-30-second fast paths

## Locked Decisions

- This is a runtime migration, not a publication migration.
- The current v2 publication stack is fixed input for this plan.
- The monitor continues to publish through the current `upload` /
  `publication_state` pipeline.
- A new publication is still created when content or material metadata changes.
- `git_ref` and `head_commit_sha` remain current publish-time hints only; by
  themselves they do not force new publication.
- Remote observations and a single target org remain publication prerequisites.
- Retryable or ineligible work remains in durable local state and is retried
  later.
- Background monitoring runs on an OS-native scheduler:
  - macOS/Linux: 30-second ticks
  - Windows: 60-second ticks
- Auto-update due checks fold into the monitor tick; the monitor becomes the
  periodic runtime substrate.
- Existing repo/org opt-out behavior stays unchanged.
- Hidden hook entrypoints stay around temporarily as migration compatibility
  paths, but they stop being the primary runtime.

## Resolved Planning Questions

These were the main stale or ambiguous parts of the old document.

### 1. Publication Boundary

Resolved decision:

- the monitor should reuse the current v2 publication stack exactly as it
  exists today
- this plan should not use v1 terminology or pretend that `publish_uid` /
  `publication_state` work is still pending

### 2. Incremental Discovery State

Resolved decision:

- the current repo-scoped upload cursor is hook-shaped and does not fit a
  scheduler that scans all supported session sources globally
- the monitor should adopt a global discovery cursor keyed by:
  - last scanned mtime
  - source label tiebreaker
- repo-scoped cursors may remain only as migration baggage or for temporary
  compatibility, not as the long-term monitor model

Reason:

- a periodic monitor tick has no single "current repo"
- reusing the current repo-scoped cursor model would either rescan too much or
  couple the monitor to repo-by-repo scheduling that the codebase does not
  currently have

### 3. Scheduler Ownership

Resolved decision:

- the monitor should own the periodic scheduler
- `auto-update` becomes policy and health inside the monitor runtime rather than
  a separate scheduler owner

Implication:

- `cadence monitor enable|disable|uninstall` own scheduler lifecycle
- `cadence auto-update status|enable|disable` remain as update-policy commands
- `cadence auto-update uninstall` should be deprecated or turned into a
  compatibility message that points users to `cadence monitor uninstall`

### 4. Hook Compatibility

Resolved decision:

- hidden hook entrypoints should not become blind no-ops immediately
- for at least one migration release, `hook post-commit` should remain a
  best-effort compatibility shim that exits successfully and attempts monitor
  work indirectly

Reason:

- users may upgrade binaries before rerunning `cadence install`
- a pure no-op risks silently dropping live ingestion during the transition

## Current Constraints

### Publication Stack

The monitor should treat these as existing platform facts:

- `src/publication.rs` already defines logical session identity and metadata
  hashing
- `src/publication_state.rs` already persists durable per-session/per-org state
- `src/upload.rs` already performs create/upload/confirm, target-org selection,
  retry scheduling, and pending-state draining
- backfill already publishes through this stack

This plan should not try to replace those pieces unless runtime extraction
requires small refactors.

### Discovery And Repo Resolution

Current live ingestion is split across two useful but differently shaped paths:

- `hook post-commit`:
  - efficient current-repo incremental scan
  - repo-scoped cursor
  - commit-triggered execution
- `backfill`:
  - global discovery
  - repo resolution from session metadata
  - repo grouping and filter checks

The monitor should reuse the backfill-style global discovery shape more than the
current hook path, while still preserving the efficient incremental cursor
behavior.

### Scheduler Infrastructure

Current scheduler provisioning and health checks live in `src/update.rs` and
assume:

- an hourly updater cadence
- scheduler artifacts target `cadence hook auto-update`
- `status` and `doctor` surface scheduler health as "auto-update scheduler"

That code is useful, but it is not yet the correct ownership boundary for a
30-second or 60-second monitor runtime.

### Install / Update Coupling

Current self-update behavior still refreshes hooks after replacing the binary.

Once hook ownership is removed:

- post-update follow-up should reconcile monitor scheduler/runtime state instead
  of refreshing hooks
- hidden hook refresh entrypoints can remain only as compatibility shims

### Hook Cleanup Safety

The install migration cannot assume every `core.hooksPath` or every file under
`~/.git-hooks` is safely disposable.

Cleanup rules should be:

- remove Cadence-managed hook files
- restore `post-commit.pre-cadence` when present
- leave non-Cadence hooks untouched
- only unset global `core.hooksPath` when Cadence can prove it still owns that
  configuration path and cleanup will not break preserved user hooks

## Target Runtime Architecture

Cadence runs as a scheduled one-shot monitor tick, not a Git hook and not a
persistent daemon.

Recommended hidden entrypoint:

- `cadence monitor tick`

Each tick should:

1. Acquire a nonblocking global activity lock.
2. Exit immediately if another Cadence activity is already running.
3. Load monitor config/state and confirm monitoring is enabled.
4. Scan supported session sources incrementally using a global discovery
   cursor.
5. Parse session metadata and resolve repo roots from `cwd`.
6. Apply existing repo/org filters.
7. Group eligible sessions by repo.
8. Publish newly discovered work through the existing live publication path.
9. Drain due pending publication records.
10. Run cheap auto-update due checks and invoke update work only when due.
11. Persist monitor health:
    - last run
    - last success
    - last error
    - counts / summary

The monitor should be conservative:

- unchanged sessions should not be republished every tick
- retryable failures should remain durable and retry later
- monitor lock contention should be an expected fast-exit condition

## Command And UX Model

Recommended command surface:

- `cadence monitor status`
- `cadence monitor enable`
- `cadence monitor disable`
- `cadence monitor uninstall`

Updated semantics:

- `cadence install` means "enable background monitoring"
- `cadence auto-update enable|disable` control whether update work runs inside
  the monitor
- `cadence auto-update status` remains an update-health view
- `cadence auto-update uninstall` should stop being the primary scheduler-removal
  command once the monitor owns scheduler lifecycle

Compatibility behavior:

- `cadence hook post-commit` remains hidden and exits success
- it should trigger best-effort compatibility behavior rather than remaining the
  primary runtime
- `cadence hook refresh-hooks` becomes a compatibility shim or explicit no-op
- remediation should point users to rerun `cadence install`

## Status / Doctor Model

`status` and `doctor` should stop treating hook presence as install truth.

### Status should report

- monitor enabled/disabled
- monitor scheduler health
- actual cadence on this platform
- last monitor run / last success / last error
- pending publication count
- auto-update policy and health
- current repo enabled/disabled state from existing repo/org rules

### Doctor should validate

- monitor scheduler artifacts are present and correct
- monitor command target is valid
- monitor state and discovery cursor files are readable/writable
- publication-state and payload directories are coherent
- old Cadence hook ownership was cleaned up where Cadence can prove ownership
- auto-update due-check state is healthy

### Doctor should stop failing on

- repo-local `core.hooksPath`
- missing Cadence hook files
- non-Cadence hook setups

## Recommended Code Shape

Recommended additions:

- `src/monitor.rs`
  - tick orchestration
  - monitor state persistence
  - compatibility hook delegation
- `src/monitor_scheduler.rs`
  - monitor scheduler provisioning
  - monitor scheduler health probes
- `src/discovery_cursor.rs`
  - global monitor cursor persistence

Recommended extractions:

- extract reusable global discovery / repo-grouping helpers out of `main.rs`
  so `backfill` and `monitor` can share them cleanly
- extract or generalize scheduler primitives from `src/update.rs` where that
  reduces duplication

Recommended avoidance:

- do not reintroduce v1 upload terminology into the code shape
- do not couple monitor correctness to `core.hooksPath`
- do not preserve hook-refresh abstractions longer than needed for migration

## Phased Implementation Plan

### Phase 1: Monitor Primitives And Scheduler

Goal:

- add a real monitor runtime substrate without changing publication semantics

Work:

- add hidden `cadence monitor tick`
- add monitor state persistence
- add a global discovery cursor
- add monitor scheduler provisioning and health probes
- expose cadence / health in monitor-aware status surfaces

Acceptance criteria:

- `cadence monitor tick` exists
- scheduler artifacts invoke the monitor tick
- platform cadence is visible and correct
- monitor state records last run / success / error

### Phase 2: Global Live Ingestion

Goal:

- move live discovery and retry off `post-commit` onto the monitor tick

Work:

- extract global discovery / repo-grouping helpers from current backfill logic
- scan all supported session sources incrementally from the monitor tick
- apply current repo/org filters
- publish through the existing live upload path
- drain pending publication records from the monitor tick

Acceptance criteria:

- new eligible sessions upload without requiring a commit
- retryable pending work is drained by the monitor
- unchanged sessions are not continuously reprocessed
- disabled repos and org-filtered repos stay skipped under the monitor

### Phase 3: Install / Update / Uninstall Migration Off Hooks

Goal:

- remove Cadence hook ownership from the primary product model

Work:

- rewrite `cadence install` to:
  - enable monitor scheduling
  - stop writing or refreshing Git hooks
  - clean up old Cadence-managed hook ownership where safe
- update self-update follow-up to reconcile monitor runtime state instead of
  refreshing hooks
- update uninstall to remove monitor scheduler artifacts and legacy Cadence hook
  remnants safely
- keep hook entrypoints as temporary compatibility paths

Acceptance criteria:

- fresh install enables monitoring without touching user hooks
- upgraded install cleans up Cadence-owned hook artifacts where safe
- update no longer depends on hook refresh for correctness
- hook ownership is no longer required for live ingestion

### Phase 4: Status / Doctor / Command Surface

Goal:

- make the CLI describe monitor reality accurately

Work:

- add visible `monitor` lifecycle commands
- reframe `status` around monitor health rather than hooks
- reframe `doctor` around monitor runtime, state, and safe migration cleanup
- narrow `auto-update` commands to policy / health
- deprecate or compatibility-wrap `cadence auto-update uninstall`

Acceptance criteria:

- status and doctor speak about monitor health, not hook presence
- users have explicit monitor lifecycle controls
- auto-update remains visible without pretending it owns the scheduler

### Phase 5: Compatibility Cleanup And Docs

Goal:

- finish the migration cleanly and remove stale user-model language

Work:

- update README and install/uninstall guidance
- update docs that still describe hook-owned ingestion
- update cross-doc references that still describe background monitoring as a
  pre-v2 publication phase
- add clear compatibility messaging for old hidden hook entrypoints

Acceptance criteria:

- docs describe Cadence as background monitoring rather than post-commit-owned
  ingestion
- docs stop describing the publication stack as pre-v2
- migration guidance is explicit for upgraded users

## Related Docs That Need Reconciliation

This plan is now ahead of a few other documents that still describe older
states:

- `README.md`
- `docs/plans/install-process.md`
- `docs/plans/cli-v2-session-publication-plan.md`

Those docs do not need to be rewritten as part of this plan refresh, but they
should be updated alongside implementation or immediately after it lands.

## Review Checklist

- Does this doc match the codebase as of 2026-03-26?
- Does it clearly treat the current v2 publication stack as fixed input?
- Is the global discovery cursor decision explicit enough?
- Is scheduler ownership between `monitor` and `auto-update` explicit enough?
- Is hook cleanup safety specific enough to avoid breaking preserved user hooks?
- Are the runtime/install/status/doctor/doc changes scoped clearly enough for an
  implementation agent to execute?
