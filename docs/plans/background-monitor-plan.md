# Cadence Background Monitor Plan

## Summary

This document now records the background-monitor design that is implemented in
the CLI as of 2026-03-26.

Cadence no longer relies on Git hooks for live ingestion. The product model is:

- `cadence install` is the idempotent bootstrap command
- the monitor owns the scheduler lifecycle
- live discovery, retry, and unattended update checks run from the monitor tick
- old hook entrypoints remain only as temporary compatibility shims

The publication stack is unchanged. Cadence still publishes through the current
v2 `/api/v2/session-publications` flow and the existing
`publication`/`publication_state`/`upload` pipeline.

## Current Runtime Shape

### Bootstrap And Install

`cadence install` is the canonical runtime bootstrap operation.

It:

- cleans up legacy Cadence-managed hook ownership where safe
- persists `ai.cadence.org` when `--org` is provided
- enables monitoring by default
- preserves an explicitly disabled monitor state when internal bootstrap runs
  with `--preserve-disable-state`
- reconciles monitor-owned scheduler artifacts
- runs a best-effort `backfill --since 7d` when monitoring is enabled
- records the current version in `~/.cadence/cli/last-version-bootstrap`

The shell installer still calls `cadence install`, so the public install flow
and the internal bootstrap flow converge on the same command.

### First-Run Version Bootstrap

Cadence also performs automatic once-per-version bootstrap.

The intended update path is:

1. `cadence update` or background update replaces the binary.
2. The updater launches the new binary.
3. The new binary runs `cadence install --preserve-disable-state`.

If that immediate handoff does not happen, the next normal CLI invocation runs
the same once-per-version bootstrap automatically.

This means runtime migration is owned by the new version, not by old-process
post-update follow-up code.

### Monitor Runtime

The monitor is the real live runtime.

- hidden entrypoint: `cadence monitor tick`
- cadence:
  - macOS and Linux: every 30 seconds
  - Windows: every 60 seconds
- responsibilities:
  - acquire the Cadence activity lock
  - exit early when monitoring is disabled
  - drain due pending uploads
  - incrementally scan supported session stores with a global discovery cursor
  - resolve repo roots from metadata
  - apply repo-disable and org-filter rules
  - publish through the existing v2 upload pipeline
  - record monitor health
  - run unattended stable-channel update checks

The current upload/publication semantics remain unchanged:

- unchanged content is not republished every tick
- retryable work remains durable and is retried later
- remote observations and a single target org remain prerequisites for upload

### Scheduler Ownership

The monitor owns scheduler lifecycle.

- `cadence monitor enable|disable|uninstall` are the real lifecycle commands
- `cadence status` and `cadence doctor` report monitor scheduler health
- `cadence auto-update status` remains diagnostic only
- there is no separate user-controlled `auto_update` policy
- if monitoring is enabled, unattended updates are enabled
- if monitoring is disabled, unattended updates are also disabled

### Compatibility Hooks

Legacy hidden hook commands still exist for migration safety, but they are no
longer part of normal ingestion behavior.

- `cadence hook post-commit` is a silent success no-op
- `cadence hook refresh-hooks` prints compatibility guidance only
- `cadence hook auto-update` delegates to the monitor tick

The steady-state goal is no hook ownership and no hook-dependent correctness.

## Locked Product Decisions

- Cadence should be active after install by default.
- `cadence install` should remain safe and idempotent.
- Existing non-Cadence hooks must be left alone.
- Legacy Cadence hook cleanup must happen automatically as part of bootstrap.
- Update/bootstrap migration belongs to the new version.
- The monitor is the periodic substrate for both publication and unattended
  updates.
- Scheduler health must remain visible in status and doctor output.

## Safe Hook Cleanup Rules

Cadence can clean up only the hook artifacts it can prove it owns.

Bootstrap and uninstall may:

- remove Cadence-managed `post-commit`
- remove legacy Cadence-managed `pre-push`
- restore `post-commit.pre-cadence` when present
- unset global `core.hooksPath` only when it still points at the Cadence-owned
  hooks directory and doing so will not strand preserved user hooks

Cadence must not:

- modify repo-local hook configuration
- remove non-Cadence hook files
- assume `~/.git-hooks` is disposable just because it exists

## Status And Doctor Model

`status` and `doctor` should reflect the monitor, not hook presence.

They should surface:

- monitor enabled or disabled state
- scheduler installed, missing, broken, or unsupported state
- cadence on the current platform
- last run, last success, and last error
- pending upload count
- updater health as a monitor-driven subsystem
- current repo eligibility based on existing repo/org rules

## Remaining Cleanup

The main runtime migration is now implemented. Remaining follow-up is smaller
in scope:

- remove temporary hidden compatibility commands after migration runway is no
  longer needed
- prune dead hook-era code paths that are no longer reachable
- continue reconciling older historical plan docs so they do not describe hook
  ownership as the current model

## Review Checklist

- Does this document match the codebase as of 2026-03-26?
- Does it clearly describe `cadence install` as bootstrap rather than hook
  setup?
- Is the update handoff to the new version explicit enough?
- Is scheduler ownership under `monitor` explicit enough?
- Are the hook-cleanup safety constraints specific enough?
