# Cadence Background Monitor Plan (V1 API)

## Summary

This document is the phase-1 plan for moving Cadence from hook-owned triggering
to background monitoring while keeping the existing v1 session-upload API.

It is intentionally scoped to:

- monitor/runtime/install/status/doctor changes
- how the CLI should behave while still publishing through the current v1 API

It is intentionally not the plan for the new v2 publication contract.

For the v2 publication cutover, see
`docs/cli-v2-session-publication-plan.md`.

Phase 1 should optimize for shipping the correct v1 runtime behavior. It does
not need to preserve internal publication abstractions for later reuse by v2.

## Boundary

This plan assumes the current v1 API and transport model remain in place:

- current direct-upload create/upload/confirm flow
- current request model and required fields
- current `session_uid`-based publication identity
- current semantic envelope / blob shape
- current retry queue model

This plan does not redesign:

- stable logical session identity
- `publish_uid`
- raw tool-session blob publication
- org-target selection as an explicit client responsibility
- server-side unresolved publication semantics

Those are phase-2 concerns and belong only to the v2 plan.

## Goal

After `cadence install`, Cadence should behave like a background capability
without taking ownership of the user's Git hook setup.

Phase-1 outcomes:

- `cadence install` enables background monitoring
- Cadence no longer installs or manages Git hooks
- existing user hooks continue to work untouched
- repo-local `core.hooksPath` no longer disables Cadence
- session discovery and retry move off `post-commit`
- uploads still go through the existing v1 API contract

## Non-Goals

- Redesigning the session-publication contract
- Introducing stable logical session identity in the server contract
- Metadata-only republishes under the v1 API
- Replacing the current v1 semantic envelope
- Reconstructing historical branch/HEAD truth for backfill
- Changing repo/org ignore logic
- Building a true long-lived daemon
- Adding burst mode or sub-30-second fast paths

## Locked Decisions

- This is a real deployable phase that ships before v2.
- `cadence install` means "enable background monitoring", not "install hooks".
- Hook installation is removed entirely.
- Install performs aggressive cleanup of existing Cadence-managed hook
  ownership.
- Background monitoring runs on an OS-native scheduler:
  - macOS/Linux: 30-second ticks
  - Windows: 60-second ticks
- Auto-update work folds into the monitor tick.
- Watch all supported session locations by default.
- Existing repo/org ignore behavior stays unchanged.
- This phase keeps the current v1 upload contract.
- Remote remains an upload gate.
- Branch and HEAD continue to follow the existing v1 upload contract rather
  than the future v2 hint model.
- The v1 plan should not try to emulate v2 publication semantics on top of the
  old API.

## Existing V1 Constraints

The current CLI and API shape impose real limits on what phase 1 can do.

### Publication Identity

The current upload path is built around the existing v1 identity and envelope
shape.

Implications for phase 1:

- the monitor can switch the trigger substrate from hooks to background ticks
- it cannot make v1 behave like v2 stable logical-session publication
- changed content snapshots still follow the current v1 semantics

### Metadata Model

Under the current v1 path, the CLI still derives and sends:

- repo remote URL
- repo root
- branch / ref
- HEAD SHA
- user identity

Phase 1 should continue to operate within those constraints rather than
pretending the v1 API has v2-style observation semantics.

### Retry Model

The existing durable queue and repo-scoped upload cursor are already in the
codebase.

Phase 1 should reuse and adapt those mechanisms where possible instead of
building the v2 publication-state machine early.

## Runtime Architecture

Cadence runs as a scheduled monitor tick, not a Git hook and not a persistent
daemon.

Recommended hidden entrypoint:

- `cadence monitor tick`

Each tick should:

- acquire a nonblocking global activity lock
- exit immediately if another Cadence activity is already running
- scan supported session sources incrementally
- derive current local Git metadata using the existing v1 rules
- publish any newly discovered upload-eligible sessions through the v1 API
- drain retry work
- perform cheap auto-update due checks and only run update work when due

## Upload Behavior In Phase 1

Phase 1 keeps the current v1 publication model.

That means:

- keep the existing v1 create/upload/confirm contract
- keep the current envelope/blob semantics
- keep the current retry queue concept
- keep the current repo-local upload cursor concept where it still fits

Phase-1 publish triggers should stay conservative:

- new content should publish
- existing pending/retry work should be retried
- metadata-only republish is not a goal for phase 1

The reason is simple:

- v1 is not the final publication model
- trying to force v2-style republish semantics into v1 would create churn and
  confusion

## Eligibility Rules In Phase 1

Phase 1 should preserve the current v1 eligibility rules unless they are proven
safe to relax without changing the v1 server contract.

Specifically:

- a remote is still required
- branch/ref and HEAD continue to be derived the current v1 way
- sessions that fail current v1 upload eligibility should remain in durable
  local state and be retried later

This is one of the deliberate differences between phase 1 and phase 2:

- v1 remains constrained by the current API
- v2 will revisit publication eligibility and metadata semantics explicitly

## Backfill In Phase 1

Backfill remains supported in phase 1, but it should remain a v1 backfill path.

This phase should:

- move backfill triggering onto the monitor-aligned runtime where helpful
- keep the existing v1 publication semantics
- avoid introducing v2-only concepts into backfill

Backfill's publication-model cleanup belongs to the v2 plan, not here.

## Install / Migration

`cadence install` should:

- aggressively remove Cadence-managed hook ownership
- enable the background monitor scheduler
- preserve existing user hooks untouched
- stop writing or refreshing Git hooks

Because this phase is still shipping before v2:

- hidden hook entrypoints should remain temporarily for upgrade compatibility
- they should become harmless compatibility paths or explicit no-ops
- remediation should point users to rerun `cadence install`

## Status / Doctor Model

`status` and `doctor` should stop treating hook presence as the install truth.

### Status should report

- monitor enabled/disabled
- monitor scheduler health
- actual cadence on this platform
- last monitor run / last success / last error
- pending v1 upload count
- auto-update policy and health
- current repo enabled/disabled state from existing repo/org rules

### Doctor should validate

- monitor scheduler artifacts are present and correct
- monitor command target is valid
- old Cadence hook ownership was removed successfully
- existing local state directories are readable/writable
- existing pending-upload state is coherent
- auto-update due-check state is healthy

### Doctor should stop failing on

- repo-local `core.hooksPath`
- missing Cadence hook files
- non-Cadence hook setups

## Recommended Code Shape

Phase 1 should add monitor/runtime structure without prematurely adopting v2
publication abstractions.

Recommended additions:

- `src/monitor.rs`
  - monitor tick orchestration
  - scheduler-facing commands
- optional `src/monitor_scheduler.rs`
  - if separating scheduler ownership from `update.rs` improves clarity

Recommended phase-1 reuse:

- reuse the existing upload transport layer where it is still truly v1
- reuse the existing queue/cursor patterns where they fit

Recommended phase-1 avoidance:

- do not introduce `publish_uid`
- do not rename v1 structures as if they were already v2
- do not build the v2 local publication-state machine early

## Phased Implementation Plan

### Phase 1: Monitor Entry Point And Scheduler

Goal:

- create the background execution substrate without changing the v1 upload
  contract

Work:

- add hidden monitor tick command
- provision scheduler artifacts for the monitor tick
- set cadence to:
  - 30 seconds on macOS/Linux
  - 60 seconds on Windows
- fold auto-update due checks into the monitor tick

Acceptance criteria:

- monitor tick exists
- scheduler artifacts invoke the monitor tick
- the platform cadence is visible and correct

### Phase 2: Rewire V1 Upload Triggering

Goal:

- move live ingestion from `post-commit` to the monitor while keeping the v1
  upload path

Work:

- move incremental discovery into the monitor tick
- publish through the existing v1 upload flow
- drain the existing pending-upload queue from the monitor tick
- keep v1 eligibility and retry behavior coherent

Acceptance criteria:

- new sessions upload without a commit
- existing v1 retry behavior still works
- unchanged sessions are not continuously re-uploaded by the monitor

### Phase 3: Install Migration Off Hooks

Goal:

- remove Cadence hook ownership from install

Work:

- rewrite `cadence install` to:
  - aggressively clean up old Cadence-managed hook ownership
  - remove Cadence-managed hook files/directories
  - unset Cadence-owned global `core.hooksPath` where applicable
  - enable monitor scheduling
- stop writing hooks during install
- remove hook-refresh behavior from update/install paths where possible
- keep hidden hook commands as temporary compatibility no-ops

Acceptance criteria:

- fresh install enables monitoring without touching user hooks
- upgraded install removes old Cadence hook ownership
- hook ownership is no longer required for correctness

### Phase 4: Status / Doctor / Commands

Goal:

- make the CLI describe phase-1 reality accurately

Work:

- add `monitor` subcommands:
  - `cadence monitor status`
  - `cadence monitor enable`
  - `cadence monitor disable`
  - `cadence monitor uninstall`
- update `status`
- update `doctor`
- keep `auto-update` commands, but narrow them to update policy/visibility

Acceptance criteria:

- status/doctor speak about monitor health, not hooks
- users have explicit monitor lifecycle controls
- auto-update remains visible but no longer owns scheduler semantics

### Phase 5: Backfill / Compatibility / Docs

Goal:

- finish the v1 runtime migration cleanly

Work:

- align backfill with the phase-1 monitor/runtime where appropriate
- document the v1 limitations explicitly
- add compatibility messaging for old hook entrypoints
- update README/install/uninstall guidance

Acceptance criteria:

- docs clearly describe phase 1 as "background monitor over v1 API"
- docs point to the separate v2 publication plan for the next phase

## Explicit Phase-1 Limitations

These are intentional and should remain explicit in the document:

- phase 1 does not introduce stable logical session identity
- phase 1 does not add `publish_uid`
- phase 1 does not add metadata-only republish semantics
- phase 1 does not redefine branch/HEAD as v2-style hints
- phase 1 does not change the current semantic envelope / blob model
- phase 1 is not the final publication model

## Review Checklist

- Does this doc stay strictly within the current v1 API boundary?
- Is the runtime/install/status/doctor scope clear enough to implement as a
  real shipped phase?
- Are the intentional limitations of phase 1 explicit enough that an
  implementation agent will not accidentally build v2 semantics into it?
- Are the boundaries with `docs/cli-v2-session-publication-plan.md` clear?
