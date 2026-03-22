# Cadence Background Monitor Plan

## Summary

Replace Cadence's hook-owned session ingestion model with an OS-scheduled background monitor that scans supported agent session sources, republishes changed session snapshots, and treats Git as mutable observation/enrichment data rather than the trigger substrate.

This is a planning document only. It is intended for implementation handoff and review, not partial execution.

## Goal

After `cadence install`, Cadence should behave like a background capability:

- Cadence watches for supported AI sessions automatically.
- Existing user Git hooks continue to work untouched.
- Repo-local `core.hooksPath` does not disable Cadence.
- Sessions can upload without waiting for a commit.
- Git metadata is attached when available, but it is not required except for remote association.

## Non-Goals

- Changing repo/org ignore logic.
- Building a true resident daemon in this change.
- Adding burst mode or sub-30-second fast paths.
- Reconstructing historical branch or HEAD state for backfill.
- Preserving hook ownership as a supported primary architecture.
- Introducing server-side snapshot history as a product feature.

## Locked Decisions

- `cadence install` now means "enable background monitoring", not "install hooks".
- Hook installation is removed entirely.
- Install performs aggressive cleanup of existing Cadence-managed hook ownership.
- Background monitoring runs on an OS-native scheduler:
  - macOS/Linux: 30-second ticks
  - Windows: 60-second ticks
- Auto-update work folds into the monitor tick.
- Watch all supported session locations by default.
- Existing repo/org filter behavior stays unchanged.
- Logical session identity is stable and based on the agent-native session UUID plus agent type.
- The server stores the latest published session content/state for a logical session rather than treating every content change as a new session object.
- The client republishes on content changes or material metadata changes.
- The client does not upload sessions that do not currently resolve to a remote.
- For live monitoring, branch and HEAD are best-effort local-checkout hints.
- For backfill, branch and HEAD are omitted.
- The client sends a canonical remote observation plus all remote observations.
- The client sends a canonical repo-root observation plus all linked worktree-root observations.
- The client sends everything it knows on every publish as current local observations at publish time; the server is responsible for reconciling accumulated signals over time.
- No burst mode in v1. Cadence relies on the fixed scheduler cadence only.

## Why The Current Design Must Change

The current CLI still encodes hook ownership as product correctness:

- `install` sets global `core.hooksPath` and writes a `post-commit` shim in `src/main.rs`.
- `post-commit` is the only reliable trigger for incremental upload and pending retry.
- `status` and `doctor` judge install health primarily by active hooksPath state.
- `session_uid` is content-sensitive in `src/note.rs`, which conflicts with "same logical session, updated snapshot".
- The live upload path currently queues when branch, HEAD, or remote are missing, even though those fields have different semantics.

The background-monitor design removes those couplings.

## Existing Modules That Matter

- `src/main.rs`
  - install flow
  - hidden hook entrypoints
  - live upload path
  - backfill flow
  - status/doctor surfaces
- `src/update.rs`
  - scheduler provisioning
  - global activity lock
  - unattended auto-update
- `src/upload.rs`
  - direct upload pipeline
  - retry queue
- `src/note.rs`
  - session identity helpers
  - serialized session envelope
- `src/git.rs`
  - branch/HEAD derivation
  - canonical remote selection
  - org filtering
  - worktree enumeration and repo-root fallbacks
- `src/scanner.rs`
  - tool-native session ID parsing
- `src/agents/*`
  - source-specific discovery
- `src/upload_cursor.rs`
  - repo-scoped incremental cursor pattern that can inform monitor state design

## Target Architecture

### 1. Runtime Model

Cadence runs as a scheduled monitor tick, not a Git hook and not a persistent daemon.

- A hidden command such as `cadence monitor tick` becomes the background entrypoint.
- Each tick:
  - acquires a nonblocking global activity lock
  - skips immediately if another Cadence activity is already running
  - scans supported session sources incrementally
  - derives current local Git metadata for affected sessions
  - republishes changed sessions when upload-eligible
  - drains retry work
  - performs cheap auto-update due checks and only runs update work when due

### 2. Session Identity

Cadence stops using content-derived identity for the primary server key.

- Current problem:
  - `session_uid` includes `content_sha256`, so every changed snapshot becomes a new identity.
- New model:
  - define a stable logical session identity from:
    - `agent_type`
    - tool-native session UUID / session ID parsed from the session source
- Content hash remains important, but only as change detection and upload-state metadata.

The implementation should assume that the API contract and server storage model also change to accept repeated uploads for the same logical session.

### 3. Metadata Semantics

The client can only publish current local observations at publish time. It cannot claim canonical historical truth for repo attribution, branch attribution, or HEAD attribution.

These fields must no longer be treated as one monolithic "Git metadata blob":

- Remote:
  - hard upload gate
  - no upload until at least one remote is present
  - send:
    - selected canonical remote URL as an observation
    - all observed remote URLs
- Repo roots:
  - send:
    - selected canonical repo root as an observation
    - all linked worktree roots for that repo as observations
- Branch / ref:
  - best-effort hint from current local checkout state at publish time
  - live monitor only
- HEAD SHA:
  - best-effort hint from current local checkout state at publish time
  - live monitor only
- Backfill:
  - omits branch and HEAD entirely

This is intentionally asymmetric:

- remote determines whether the repo is upload-eligible
- branch and HEAD are hints only
- repo roots and worktree roots are attribution evidence, not a complete attribution solution
- server-side derivation is expected to accumulate and reconcile multiple attribution signals over time

### 4. Local Durable Monitor State

The monitor needs its own durable state store under `~/.cadence/cli/`.

This state should be keyed by logical session identity, not by repo only.

Each record should be able to answer:

- Have we seen this logical session before?
- What was the last observed content hash?
- What was the last uploaded content hash?
- What was the last uploaded material metadata hash?
- When was it last scanned?
- Is it currently:
  - awaiting remote
  - uploaded
  - pending retry
  - filtered out by existing ignore logic
- What local repo metadata was last observed?

The client should republish when either of these changes:

- session content hash
- material metadata fingerprint

Material metadata should include at least:

- canonical remote observation
- all remote observations
- canonical repo-root observation
- all worktree-root observations
- branch/ref
- HEAD SHA

Incidental metadata such as CLI version should not trigger republishes by itself.

### 5. Worktree-Aware Repo Context

Current repo-root derivation is too narrow for sessions that move across worktrees.

The monitor should:

- continue resolving the canonical repo via local Git state
- enumerate all linked worktree roots for that repo
- upload the full set of repo/worktree-root observations with the session snapshot

This gives the server additional attribution evidence for sessions that begin in one checkout but later interact with another worktree for the same repository. It is not, by itself, a complete worktree-attribution solution.

### 6. Backfill Semantics

Backfill remains useful, but it cannot claim historical local Git truth it does not have.

Backfill should:

- use the same stable logical session identity as live monitoring
- use the same stable logical-session publish contract
- still require a remote before upload
- send a canonical remote observation plus all remote observations
- send a canonical repo-root observation plus all worktree-root observations when derivable
- omit branch/ref and HEAD SHA

Backfill should not derive current local branch/HEAD and pretend those are historical session facts.

## API / Contract Changes Required

This CLI plan depends on coordinated contract work.

Required server-side changes:

- Accept repeated publishes for the same logical session identity.
- Treat repeated publishes as updates to the latest session content/state for that logical session.
- Accept partial metadata and incremental enrichment over time.
- Interpret git_ref, head_sha, repo roots, remotes, and similar fields as current local observations at publish time.
- Reconcile attribution signals over time rather than assuming last-write-wins for repo/ref/head fields.
- Accept a canonical remote observation plus all remote observations.
- Accept a canonical repo-root observation plus all worktree-root observations.
- Tolerate live publishes with missing branch/HEAD.
- Tolerate backfill publishes that omit branch/HEAD.

Strong recommendation:

- keep a server-visible distinction between:
  - logical session identity
  - latest content hash
  - latest metadata hash
  - accumulated attribution observations / derived attribution state when those are modeled separately

The current `upload-url -> presigned PUT -> confirm` shape can remain if it is adapted to stable logical identity rather than content-derived `session_uid`.

## CLI Surface Changes

### Install

`cadence install` should:

- aggressively remove Cadence-managed hook ownership
- enable the background monitor scheduler
- preserve existing auto-update consent behavior, but route scheduler ownership through the monitor architecture
- stop writing or refreshing Git hooks

### New Monitor Controls

Add a dedicated `monitor` command family:

- `cadence monitor status`
- `cadence monitor enable`
- `cadence monitor disable`
- `cadence monitor uninstall`

Rationale:

- install should enable monitoring by default
- users still need explicit controls for the background monitor lifecycle
- auto-update and monitor are now different concerns:
  - monitor owns scheduler artifacts
  - auto-update remains a policy/features concern inside monitor ticks

### Auto-Update Controls

Keep `cadence auto-update ...`, but narrow it to update policy and visibility:

- enabled/disabled preference
- last result
- last error
- next retry / next due information

Do not let auto-update own background scheduler artifacts anymore once monitor scheduling exists.

### Hidden Hook Commands

Do not immediately delete hidden hook entrypoints in the same release that stops installing hooks.

Recommended transition behavior:

- keep hidden hook commands temporarily
- make them harmless compatibility paths or explicit no-ops
- print remediation telling users to run `cadence install`

This avoids breakage for upgraded users who still have old Cadence hooks on disk before they rerun install.

## Status / Doctor Model

`status` and `doctor` must stop treating hook presence as the install truth.

### Status should report

- monitor enabled/disabled
- monitor scheduler health
- actual tick cadence on this platform
- last monitor run / last success / last error
- pending retry count
- sessions awaiting remote count
- auto-update policy and health
- current repo enabled/disabled state from existing repo/org rules

### Doctor should validate

- monitor scheduler artifacts are present and correct
- monitor command target is valid
- old Cadence hook ownership was removed successfully
- local monitor state directory is readable/writable
- pending retry / awaiting-remote stores are coherent
- auto-update due-check state is healthy

### Doctor should stop failing on

- repo-local `core.hooksPath`
- missing Cadence hook files
- non-Cadence hook setups

## Recommended New Internal Modules

The implementation will be simpler if the code stops overloading existing hook concepts.

Recommended additions:

- `src/monitor.rs`
  - monitor tick orchestration
  - scheduler-facing commands
  - monitor state transitions
- `src/monitor_state.rs`
  - durable per-session monitor cache
  - metadata fingerprinting
  - awaiting-remote state
- optional `src/monitor_scheduler.rs`
  - if separating scheduler ownership from auto-update makes `update.rs` cleaner

Reusing `update.rs` directly is acceptable if the code is aggressively renamed and split so the monitor does not read as an auto-update side effect.

## Phased Implementation Plan

Each phase is intended to fit in a single implementation session.

### Phase 1: Contract And Data Model Cutover

Goal:

- make the session primitive stable across content changes

Work:

- replace content-derived logical identity in the CLI model
- add a stable logical session ID helper built from:
  - agent type
  - native session UUID / session ID
- keep content hash as change detection data, not logical identity
- update request/response models in `src/api_client.rs`
- update upload preparation code in `src/upload.rs`
- document the new CLI/server contract in `docs/`

Implementation notes:

- the serialized session object can continue to carry the full payload and content hash
- queue and retry records must key off logical identity plus current payload state
- the implementation agent should not preserve old assumptions that `409` means "identical content already exists" unless the server contract still defines it that way under the new model

Acceptance criteria:

- one logical session can be republished after content changes without generating a new logical identity
- client upload requests carry stable session identity and current content hash separately

### Phase 2: Durable Monitor State And Metadata Fingerprinting

Goal:

- teach Cadence when to republish and when to suppress

Work:

- introduce durable per-session monitor state under `~/.cadence/cli/`
- track:
  - last observed content hash
  - last uploaded content hash
  - last uploaded material metadata hash
  - last seen timestamp
  - eligibility state (`awaiting_remote`, `uploaded`, `pending_retry`, `filtered_out`)
- implement material metadata fingerprinting
- add helper(s) in `src/git.rs` for:
  - canonical remote
  - all remotes
  - canonical repo root
  - all worktree roots

Implementation notes:

- do not reuse the repo-scoped upload cursor as the primary monitor state; it is too coarse
- keep records atomically written like the existing queue/cursor patterns

Acceptance criteria:

- unchanged sessions do not republish
- content changes do republish
- material metadata changes do republish even if content is unchanged
- sessions with no remote remain durable and reevaluable

### Phase 3: Background Monitor Tick

Goal:

- move live ingestion out of hooks and into a scheduler-driven monitor path

Work:

- add hidden monitor tick command
- build a monitor loop that:
  - acquires the nonblocking global activity lock
  - discovers recent session candidates
  - maps them to logical session identity
  - derives current local Git metadata
  - checks monitor state
  - uploads or suppresses accordingly
  - drains retry queue
  - reevaluates `awaiting_remote` sessions
  - performs cheap auto-update due checks
- fold auto-update checks into the monitor tick

Implementation notes:

- keep the tick bounded and idempotent
- do not add burst mode
- do not add any hook-triggered fast path
- do not make monitor correctness depend on branch/HEAD presence

Acceptance criteria:

- a changed live session uploads without a commit
- the same unchanged session is not repeatedly uploaded every tick
- a session that previously lacked a remote uploads later once a remote appears
- auto-update due checks still occur, but do not dominate tick cost

### Phase 4: Scheduler Provisioning And Platform Cadence

Goal:

- provision the monitor on supported platforms using OS-native scheduler facilities

Work:

- adapt scheduler provisioning to target `cadence monitor tick`
- set cadence to:
  - 30 seconds on macOS/Linux
  - 60 seconds on Windows
- expose monitor scheduler health APIs for status/doctor
- stop treating auto-update as the owner of scheduler artifacts

Implementation notes:

- macOS can use `launchd`
- Linux can use `systemd --user`
- Windows should explicitly degrade to 60-second cadence
- status must surface the actual cadence per platform

Acceptance criteria:

- installable scheduler artifacts point to the monitor tick command
- health checks distinguish installed/missing/broken states for the monitor
- Windows clearly reports the 60-second cadence

### Phase 5: Install And Migration Off Hooks

Goal:

- change install semantics from hook ownership to background monitoring

Work:

- rewrite `cadence install` to:
  - aggressively clean up old Cadence-managed hook ownership
  - remove Cadence hook files/directories
  - unset Cadence-owned global hooksPath when applicable
  - enable monitor scheduling
- stop writing hooks during install
- remove hook refresh logic from update/install paths
- keep hidden hook commands only as temporary compatibility no-ops

Implementation notes:

- aggressive cleanup is acceptable in this rollout because user count is still low
- do not preserve current logic that backs up and rewrites hook contents

Acceptance criteria:

- a fresh install enables monitoring without touching user hooks
- an upgraded install removes old Cadence hook ownership
- hook health is no longer part of install success

### Phase 6: Status, Doctor, Config, And Command Surface

Goal:

- make the CLI describe the new architecture accurately

Work:

- add monitor subcommands
- add config needed for monitor enablement if required
- update `status`
- update `doctor`
- keep `auto-update` commands, but move them to policy-only semantics
- update help text and uninstall guidance

Implementation notes:

- if monitor enablement is persisted in config, use a dedicated key such as `monitor_enabled`
- keep `cadence config` coherent with the new command surface

Acceptance criteria:

- status/doctor speak about monitor health, not hook ownership
- users have explicit commands to enable/disable/uninstall the monitor
- auto-update state remains visible

### Phase 7: Backfill Alignment

Goal:

- keep backfill useful without inventing fake historical Git truth

Work:

- move backfill to the stable logical-session upload path
- backfill should:
  - require a remote
  - send a canonical remote observation plus all remote observations
  - send a canonical repo-root observation plus all worktree-root observations
  - omit branch/ref and HEAD
- align retry/error handling with the new monitor contract

Acceptance criteria:

- backfill uploads old sessions using stable logical identity
- backfill does not send current branch/HEAD as historical facts

### Phase 8: Tests, Docs, And Rollout Hardening

Goal:

- lock in behavior and remove the old mental model from user-facing surfaces

Work:

- add tests for:
  - stable logical session identity
  - content-vs-metadata republish behavior
  - awaiting-remote later upload
  - worktree-root metadata collection
  - branch/HEAD omission in backfill
  - install aggressive hook cleanup
  - monitor scheduler provisioning
  - Windows cadence downgrade
  - hook compatibility no-op behavior during transition
- update README and install/uninstall docs
- update any stale plan/docs that still describe hook-owned correctness

Acceptance criteria:

- docs describe install as enabling background monitoring
- docs no longer frame hooks as the primary architecture
- tests cover the new suppression and republish rules

## Review Checklist For Zack

- Is stable logical session identity defined correctly, or should the exact key shape differ?
- Is "remote required, branch/HEAD optional hints" the right semantic split?
- Is sending canonical-plus-all remotes the right contract, or should the client send remote names too?
- Is sending canonical-plus-all repo/worktree roots sufficient, or does the server need a stronger notion of "active checkout root"?
- Is folding auto-update into monitor ticks still worth it once scheduler ownership moves away from `auto-update`?
- Should hidden hook commands remain for one release or longer?
- Is a dedicated `monitor` command family the right CLI surface, or should monitor control be folded into existing commands?

## Implementation Risks

- The biggest risk is trying to preserve old content-derived identity assumptions in the new pipeline.
- The second biggest risk is mixing scheduler ownership, auto-update, and monitor state in one poorly named module.
- The third biggest risk is accidental overpublishing if metadata fingerprinting is too broad or unstable.
- The fourth biggest risk is migration breakage for users who upgrade before rerunning `cadence install`.

## Recommended Execution Order

1. Phase 1
2. Phase 2
3. Phase 3
4. Phase 4
5. Phase 5
6. Phase 6
7. Phase 7
8. Phase 8

This order keeps the contract and state model stable before any install/runtime migration work starts.
