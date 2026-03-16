# Cadence CLI Direct Upload Migration Plan

## Summary

Replace the CLI's git-ref based session storage and sync pipeline with direct HTTP upload to the app-backed ingest flow.

The new model uploads discovered sessions immediately from `post-commit` and retries transient failures from a local pending queue on later hook runs.

This plan assumes the app contract described by the consumer/api/app work:

1. `POST /api/sessions/upload-url`
2. `PUT <presigned_url>`
3. `POST /api/sessions/{uid}/confirm`

## Decisions

These were the explicit rollout decisions for this migration:

- Do a hard cutover to the direct-upload path.
- Do not keep a `404` fallback to the legacy git-ref sync flow.
- Move `cadence backfill` onto the direct-upload pipeline in the same change.
- Remove `pre-push` entirely. Uploads should happen from `post-commit` only.
- Remove `keys`, `sessions`, and `gc`; they are not part of the supported surface after the migration.

## Goals

- Preserve the existing session discovery and metadata extraction pipeline.
- Preserve the existing `SessionEnvelope` shape and `session_uid` computation.
- Preserve zstd compression of the session payload.
- Reuse existing CLI auth and token storage.
- Make upload happen immediately on discovery rather than batching until push.
- Keep hook execution resilient to transient network and auth failures by queuing retryable uploads locally.

## Non-Goals

- Keep compatibility with legacy git-ref session storage.
- Keep PGP encryption, key management, or keychain storage.
- Keep pre-push sync, deferred sync workers, or ref-merge logic.
- Recreate session listing or garbage-collection commands on top of the new transport.

## Implementation Plan

1. Add a direct-upload transport layer

- Extend the authenticated API client with:
  - upload URL request/response types
  - confirm response type
  - precise handling for `401`, `409`, and `422`
- Add a direct HTTPS `PUT` for presigned S3 upload with `application/zstd`.
- Keep the upload payload exactly as today's `SessionEnvelope` JSON compressed with zstd.

2. Introduce upload preparation and retry primitives

- Add a dedicated upload module that:
  - resolves API/auth context once per run
  - builds the upload request payload from discovered sessions
  - computes the uncompressed content SHA-256 required by the app contract
  - performs request-upload-url -> PUT -> confirm
- Add a local pending-upload queue under the Cadence state directory.
- Store enough information in each queued item to retry the exact upload later without rescanning raw agent logs.
- Add simple backoff metadata so repeated failures do not thrash hooks.

3. Rework `post-commit` around upload instead of ref writes

- Remove the git-ref storage/write path from the hook flow.
- On each `post-commit`:
  - retry pending uploads first
  - scan for newly discovered sessions
  - upload each prepared session immediately
  - queue retryable failures
- Treat auth failures as non-fatal for hook execution, but print a clear login/remediation hint.

4. Add incremental upload state

- Introduce a repo-scoped upload cursor so `post-commit` only reprocesses new session logs.
- Keep cursor storage separate from pending uploads.
- Ensure cursor updates happen only after the session has either uploaded successfully or been safely queued.

5. Move `backfill` to the same ingestion pipeline

- Replace ref creation/push behavior in `cadence backfill` with direct upload.
- Share the same preparation, upload, and queuing code as `post-commit`.
- Report uploaded, queued, skipped, and errored counts in backfill output.

6. Remove obsolete surfaces

- Remove CLI commands:
  - `cadence keys`
  - `cadence sessions`
  - `cadence gc`
- Remove hook commands:
  - `cadence hook pre-push`
  - deferred-sync entrypoints tied to ref sync
- Update `cadence install` to:
  - install only `post-commit`
  - remove an existing Cadence-managed `pre-push` hook if present
  - stop provisioning encryption/key material

7. Update status, doctor, and docs

- Reframe `status` and `doctor` around:
  - `post-commit` hook presence
  - upload readiness
  - pending upload count
- Remove references to git refs, session ref sync, and encryption setup from user-facing docs.

## Error Handling Model

1. `POST /api/sessions/upload-url`

- `200`: continue upload
- `401`: treat as auth failure, queue for retry, prompt user to re-authenticate
- `409`: treat as already ingested and skip without error
- `422`: treat as unsupported repo/org association and skip with warning

2. S3 `PUT`

- Any transport or non-success response should be treated as retryable unless clearly permanent.
- Upload expiry is handled by requesting a fresh upload URL during retry, not by reusing stale presigned URLs.

3. `POST /api/sessions/{uid}/confirm`

- `200`: accepted
- `409`: treat as success
- `404` or `422`: treat as failed upload/confirm mismatch and retry from a fresh request cycle

## Risks and Mitigations

1. Hook latency regression

- Keep the network flow small and per-session.
- Retry only pending items that are eligible by backoff.
- Avoid any git push or ref merge work in hooks.

2. Data loss from transient failures

- Queue failures before advancing upload cursors.
- Retry from durable local state on later hook runs.

3. Duplicate ingestion

- Preserve the deterministic `session_uid`.
- Treat `409` as a successful no-op in both request and confirm phases.

4. Surface-area mismatch after removal of legacy commands

- Update install, status, doctor, and README together so the user model changes in the same release.

## Testing Plan

1. API client behavior

- upload-url success path
- `401`, `409`, and `422` handling
- confirm `200` and `409` handling

2. Upload pipeline

- session preparation produces stable `session_uid`, content hash, and compressed payload
- queued upload can be retried successfully later
- retry backoff suppresses repeated immediate retries

3. Hook behavior

- `post-commit` uploads newly discovered sessions
- transient failures are queued
- pending uploads are retried on later runs
- auth failures do not hard-fail the hook

4. Backfill behavior

- uploads through the same direct path
- reports uploaded/queued/skipped/errors correctly

5. CLI surface changes

- removed commands no longer parse
- install/status/doctor reflect post-commit plus upload queue semantics only

## Acceptance Criteria

- No new session data is written to Cadence git refs.
- `post-commit` uploads sessions directly through the app and S3 contract.
- Failed uploads are retried from a local durable queue on later hook runs.
- `backfill` uses the same direct-upload path.
- `pre-push`, encryption setup, and key-management flows are no longer required.
- Status and docs describe direct upload rather than ref sync.

## Follow-Up Cleanup

After the cutover is stable in production, remove remaining dead internal code tied only to the legacy git-ref and encryption flow.
