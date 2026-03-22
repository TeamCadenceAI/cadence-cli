# CLI V2 Session Publication Plan

## Summary

This document is the phase-2 CLI plan for cutting Cadence over from the
existing v1 session-upload contract to the new v2 session-publication API.

It is a CLI-only plan. The server endpoints and server behavior described by
`../ai-barometer/docs/plans/cli-v2-session-publication-spec-2026-03-22.md` are
treated as already available and fixed input.

This document is the canonical publication-contract plan.

For the shipped phase-1 background-monitor work on the existing API, see
`docs/background-monitor-plan.md`.

## Relationship To Phase 1

The two documents represent two real delivery phases:

1. phase 1: background monitor over the existing v1 API
2. phase 2: hard cutover to the v2 publication contract

Phase 2 is not constrained to preserve all implementation details from phase 1.
It may revisit significant monitor/runtime internals where the v1 publication
model would otherwise fight the v2 contract.

What is fixed:

- v1 ships first
- v2 is a hard cutover
- the CLI does not need to keep a long-lived dual-path publication layer
- phase 2 may significantly refactor phase-1 internals if that produces a
  cleaner v2 publication architecture

## Goals

- cut the CLI to the v2 session-publication contract cleanly
- stop using content-derived session identity for publication
- separate logical session identity from publication identity
- publish raw tool session content rather than the v1 semantic envelope
- track publication state durably per logical session and org
- preserve the background-monitor product model while moving publication
  semantics to v2

## Non-Goals

- redesigning the server contract described in the ai-barometer spec
- inventing a fallback from v2 back to v1
- preserving v1 publication abstractions for compatibility
- designing server-side repo inference internals
- adding client-side semantic extraction for session timing, commit extraction,
  or touched-file extraction

## Locked Decisions

- v2 is a hard cutover.
- The publication layer is a full rewrite, not an incremental adaptation of the
  v1 upload/envelope code.
- `agent + agent_session_id` is the stable logical-session key.
- `publish_uid` is separate publication identity.
- Retries of the same publication reuse the same `publish_uid`.
- New publications get a new `publish_uid`.
- The CLI creates a new publication when:
  - content hash changes
  - material metadata hash changes
- The CLI sends current local publish-time observations, not canonical
  historical truth.
- The CLI must choose exactly one target org before publishing.
- If org selection is ambiguous, publication is blocked and kept in local
  durable state.
- The CLI does not publish without:
  - at least one remote observation
  - one target Cadence org
- The CLI does not send `session_uid` in v2.
- The CLI does not send the v1 semantic envelope in v2.
- Backfill omits `git_ref` and `head_commit_sha`.

## Fixed Server Inputs

The CLI plan must treat these as fixed:

- logical session identity:
  - `agent`
  - `agent_session_id`
- publication identity:
  - `publish_uid`
- create/upload/confirm flow:
  - `POST /api/v2/session-publications`
  - upload to presigned URL
  - `POST /api/v2/session-publications/{publication_id}/confirm`
- create carries publish-time observations
- confirm is minimal
- the blob is raw tool session content
- server-side repo inference is responsible for resolving repo meaning inside
  the chosen org
- unresolved repo attribution is allowed
- branch and HEAD are hints only
- backfill omits branch and HEAD

## Current CLI Gaps Relative To V2

The current CLI is materially incompatible with v2 in several ways:

- it uses `session_uid` as a publication-facing identity
- it ties identity to content-derived state
- it uploads a semantic Cadence envelope instead of raw tool session content
- it does not model `publish_uid`
- it does not model publication retries separately from logical-session identity
- it does not treat org selection as an explicit client-side prerequisite
- it does not have a publication-state machine keyed by logical session and org

Phase 2 should fix these directly rather than trying to preserve the old shape.

## Target CLI Model

### 1. Logical Session Identity

The CLI should model a logical session key as:

- `agent`
- `agent_session_id`

`agent_session_id` must come from the tool-native session ID parsed from the
source.

The CLI must not derive a Cadence-specific logical-session key from content.

### 2. Publication Identity

Each publication attempt for a logical session has:

- `publish_uid`

Rules:

- new publication => new `publish_uid`
- retry of same publication => same `publish_uid`
- `publish_uid` uniqueness only needs to hold within the logical session

### 3. Blob Identity

Each publication also has:

- `upload_sha256`

This is the hash of the blob actually uploaded for that publication.

### 4. Material Metadata Hash

The CLI should compute `metadata_sha256` from at least:

- canonical remote observation
- all remote observations
- canonical repo-root observation
- all linked worktree-root observations
- `git_ref`
- `head_commit_sha`

`cli_version` must not trigger a new publication by itself.

For backfill:

- `git_ref` is omitted
- `head_commit_sha` is omitted
- the metadata hash should reflect the fields actually present for that
  backfill publication

### 5. Observation Model

The CLI should explicitly treat these fields as current local observations at
publish time:

- canonical remote URL
- all remote URLs
- canonical repo root
- all worktree roots
- cwd
- git ref
- head commit SHA
- git user email/name

The CLI should not claim these are historical truths about when the session was
created or what checkout the session "really belonged to."

### 6. Publication Creation Rule

The CLI should create a new publication when either changes:

- content hash
- material metadata hash

The CLI should retry the same publication when a failure occurs after that
publication has already been created.

## Org Selection And Eligibility

V2 introduces an explicit client-side org-selection responsibility.

The CLI should:

- derive remote observations
- resolve the target org from those observations using the normal CLI org
  selection mechanism
- block publication when org selection is ambiguous

Recommended durable states:

- `awaiting_remote`
- `awaiting_org`
- `ready_to_publish`
- `publishing`
- `awaiting_confirm`
- `retryable_failure`
- `published`

Important:

- the CLI does not need to resolve the exact repo before publishing
- it does need enough remote/org context to choose the org

## No Client-Side Semantic Extraction

The CLI must not try to derive server-owned semantics such as:

- `session_start`
- `session_end`
- observed commits from content parsing
- touched files from content parsing
- server-facing file or commit extraction results

The only client-side publication responsibilities are:

- raw session content
- publish-time observations
- stable logical-session identity
- publication state and retry handling

## Blob / Transport Model

The v2 blob should be:

- raw tool session content
- optionally compressed for transport if the final server implementation
  supports it

The v2 blob should not be a semantic Cadence envelope.

Phase 2 should remove these from publication semantics:

- `SessionEnvelope`
- `SessionRecord`
- `session_uid`
- derived semantic fields packed into the blob for server consumption

## Durable Local State

Phase 2 needs a new durable publication-state model.

It should be keyed by:

- logical session key (`agent + agent_session_id`)
- target org

Each record should track at least:

- last observed content hash
- last observed material metadata hash
- last published content hash
- last published material metadata hash
- current or most recent `publish_uid`
- publication status
- publication retry state
- last known remote observations
- last known repo/worktree observations
- last known branch/HEAD observations when applicable

Why this is new:

- v1 queue/cursor state is not the right abstraction for `publish_uid`
  lifecycle or per-org publication tracking
- phase 2 should not try to preserve those semantics

## API Client Shape

Recommended new v2 client responsibilities:

- create publication
- upload blob
- confirm publication

### Create request must carry

- `agent`
- `agent_session_id`
- `publish_uid`
- `upload_sha256`
- `metadata_sha256`
- canonical remote observation
- all remote observations
- canonical repo-root observation
- all worktree-root observations
- optional `cwd`
- optional live `git_ref`
- optional live `head_commit_sha`
- optional `git_user_email`
- optional `git_user_name`
- optional `cli_version`

### Create response handling

The CLI should treat create as:

- idempotent for the same logical session plus `publish_uid`
- exact retries of the same publication are allowed
- conflicting reuse of the same `publish_uid` is an error
- publication-stub creation only
- not synchronous session processing

### Confirm handling

The CLI should treat confirm as:

- minimal
- publication-oriented, not metadata-patching
- an async-processing enqueue step

The CLI must not plan around synchronous session finalization on confirm.

## Monitor Integration

Phase 2 will cut the background monitor over to v2 publication semantics.

The monitor should:

- discover session sources
- derive logical session key
- derive current publish-time observations
- derive target org
- compute content hash
- compute material metadata hash
- compare against durable publication state
- create a new publication when required
- retry the same publication with the same `publish_uid` when appropriate

Because phase 2 is allowed to revisit significant details, the implementation
agent may refactor phase-1 monitor internals if the v1 publication model is too
entangled with scheduling/runtime code.

## Backfill Integration

Backfill in v2 should:

- use the same logical session identity
- choose a target org
- require remote observations
- send canonical remote observation plus all remote observations
- send canonical repo-root observation plus all worktree-root observations
- omit `git_ref`
- omit `head_commit_sha`

Backfill must not derive current branch/HEAD and pretend those are historical
session facts.

## Recommended Code Shape

Because this is a full rewrite, phase 2 should introduce publication-specific
modules instead of adapting the v1 upload shape in place.

Recommended additions:

- `src/publication_v2.rs`
  - v2 create/upload/confirm flow
  - request/response types
- `src/publication_state.rs`
  - durable logical-session/publication state
  - `publish_uid` lifecycle
  - per-org tracking
- `src/org_selection.rs`
  - org-resolution helpers for publication eligibility

Recommended removals from publication semantics:

- v1 identity helpers that exist only for `session_uid`
- v1 semantic envelope publication code
- v1 retry semantics that cannot express `publish_uid` reuse

## Phased Implementation Plan

### Phase 1: V2 Primitives And Boundaries

Goal:

- define the new publication primitives cleanly before touching transport

Work:

- add v2 request/response models
- add logical-session key helpers
- add `publish_uid` generation helpers
- add material metadata hashing helpers
- remove v1 publication concepts from the planning surface

Acceptance criteria:

- the codebase has explicit v2 concepts for logical session, publication, and
  blob hash
- no new work depends on `session_uid`

### Phase 2: Org Selection And Observation Collection

Goal:

- make the CLI able to determine whether a session is publishable under v2

Work:

- collect:
  - canonical remote observation
  - all remote observations
  - canonical repo-root observation
  - all worktree-root observations
  - live branch/HEAD observations where available
- implement target-org selection
- block ambiguous org cases into durable local state

Acceptance criteria:

- a session is only publishable when remote + org are known
- ambiguous org cases do not silently publish

### Phase 3: Durable Publication State Machine

Goal:

- replace v1 retry/cursor semantics with v2 publication tracking

Work:

- add durable state keyed by logical session and org
- track last content hash, last metadata hash, last `publish_uid`, and current
  publication status
- implement:
  - new publication on content change
  - new publication on material metadata change
  - retry with same `publish_uid`

Acceptance criteria:

- same publication retries reuse `publish_uid`
- content-only or metadata-only changes create new publications
- unchanged sessions do not republish

### Phase 4: V2 API Client And Raw Blob Transport

Goal:

- replace the v1 semantic upload path with the v2 create/upload/confirm flow

Work:

- implement `POST /api/v2/session-publications`
- upload raw tool blob to presigned URL
- implement minimal confirm
- ensure retry behavior matches the fixed server semantics

Acceptance criteria:

- the CLI publishes raw tool content, not a v1 semantic envelope
- confirm is minimal and publication-oriented

### Phase 5: Monitor And Backfill Cutover

Goal:

- route all publication behavior through v2

Work:

- cut the monitor over to the v2 publication state machine
- cut backfill over to v2 publication semantics
- remove any remaining v1 publication behavior from active paths

Acceptance criteria:

- live monitoring publishes through v2 only
- backfill publishes through v2 only
- branch/HEAD omission rules for backfill are enforced

### Phase 6: V1 Publication Removal, Docs, And Tests

Goal:

- complete the hard cutover cleanly

Work:

- remove v1 publication-only code
- update docs and command help
- add tests for:
  - logical-session identity
  - `publish_uid` reuse on retry
  - new publication on metadata-only changes
  - org ambiguity blocking
  - raw blob publication
  - backfill omission of branch/HEAD

Acceptance criteria:

- there is no fallback to v1 publication
- docs clearly describe v2 as the active publication model

## Review Checklist

- Does the plan stay within the fixed ai-barometer v2 spec?
- Is the hard-cutover boundary explicit enough?
- Is the full-rewrite expectation clear enough that an implementation agent will
  not try to preserve v1 publication abstractions?
- Is the org-selection responsibility explicit enough?
- Does the plan consistently treat Git/ref/head/worktree fields as current
  publish-time observations rather than canonical historical attribution?
- Are the relationships between:
  - logical session identity
  - publication identity
  - blob identity
  clear enough?
