# Cadence Background Monitor Bootstrap Follow-Up Plan

## Summary

This document captures the follow-up work discovered after landing the initial
background-monitor runtime branch.

The current branch successfully moves Cadence off hook-owned live ingestion, but
it still carries a few transitional behaviors that do not match the intended
product model:

- upgrade cleanup still depends too much on `cadence install`
- update-time follow-up still runs in the old process
- `hook post-commit` still does compatibility work instead of being inert
- unattended updates still look like a user-controlled preference

This follow-up plan tightens those edges so install, update, and recovery all
converge on a single bootstrap model.

## Product Decisions

These decisions are treated as fixed input for this work:

- If Cadence is installed, it should be active by default.
- If Cadence is installed, unattended updates are also on by default.
- There should be no user-controlled `auto_update` opt-out.
- `cadence install` should remain for now because `install.sh` depends on it.
- `cadence install` should become the generic, idempotent bootstrap primitive.
- After `cadence update` or auto-update, the new version should immediately run
  `cadence install`.
- First-run-per-version migration should remain as a fallback if that immediate
  handoff does not happen.
- Legacy `hook post-commit` should remain temporarily only as a silent success
  no-op while old hook installs are being cleaned up automatically.
- Scheduler health should remain visible in Cadence status/health output.

## Desired End State

After this work lands, Cadence should behave like this:

- `install.sh` installs the binary, then runs `cadence install`
- `cadence install` safely bootstraps the current machine into the desired
  runtime state
- `cadence update` replaces the binary, launches the new binary, and the new
  version runs the same bootstrap logic immediately
- if that immediate handoff fails, the next ordinary invocation of the new
  binary still performs the same bootstrap work once for that version
- legacy Cadence-owned hooks are cleaned up automatically
- stray executions of `cadence hook post-commit` succeed without doing work
- Cadence health output continues to surface scheduler/runtime health

## Bootstrap Responsibilities

The shared bootstrap path should own all machine-level Cadence setup that is
safe and idempotent:

- enable or reconcile the monitor scheduler/runtime
- enable or reconcile unattended-update scheduler/runtime
- remove or restore only proven Cadence-owned legacy hook artifacts
- perform any once-per-version recovery work
- write whatever markers are needed so the fallback first-run path does not
  repeat one-time migration unnecessarily

This work should be owned by code that both `cadence install` and first-run
version migration can call directly.

## Required Code Changes

### 1. Extract A Shared Bootstrap Primitive

The current install migration logic lives mostly in `src/main.rs`, while update
follow-up and version recovery live in `src/update.rs`.

This branch should extract the shared install/bootstrap logic into a module that
both sides can call safely. The extracted operation should:

- be idempotent
- avoid touching non-Cadence-owned hooks or scheduler artifacts
- accept the org configuration that `cadence install --org` currently supports
- be suitable for both interactive install flows and internal recovery flows

### 2. Make `cadence install` The Canonical Bootstrap Command

`cadence install` should stop being a special-case migration path and instead
become the canonical bootstrap command for the current version.

Its responsibilities should include:

- persisting the requested org scope
- running the shared bootstrap/reconciliation logic
- surfacing clear machine-readable or human-readable status when setup fails

Repeated `cadence install` runs should be safe and should converge the machine
back to the expected Cadence runtime state.

### 3. Move Upgrade Migration To New-Version Bootstrap

The current update flow performs follow-up work immediately after
`self_replace_binary(...)`, but that code still runs in the old process image.

That follow-up should be reworked so that:

- the old binary replaces itself
- the old binary launches the new binary
- the new binary runs `cadence install`
- if the launched bootstrap fails or never happens, the next ordinary command
  still executes fallback first-run migration for that version

Scheduler reconciliation, hook cleanup, and any once-per-version recovery should
be moved out of the current old-process follow-up path and into the shared
bootstrap / first-run migration path.

### 4. Simplify Auto-Update Policy

Unattended updates are part of the installed Cadence runtime, not an optional
preference. This follow-up should align the command surface and config model
with that policy.

Target behavior:

- installed Cadence implies unattended updates are enabled
- user-facing `auto-update enable|disable` no longer exists
- status/health output may still report updater scheduler state and last-run
  health

Implementation can keep minimal internal state if needed, but the product should
no longer present this as a supported user choice.

### 5. Reduce Legacy Hook Compatibility To A No-Op

`cadence hook post-commit` should remain temporarily so old hook installs do not
fail before automatic cleanup runs, but it should no longer do compatibility
scans or any real runtime work.

Required behavior:

- exit successfully
- perform no monitoring, discovery, upload, pending-drain, or update work

This command becomes temporary migration padding only.

## Testing And Verification

This work should add or update tests covering at least:

- idempotent bootstrap/install behavior
- safe cleanup of Cadence-owned hook artifacts
- no-op `hook post-commit` compatibility behavior
- first-run fallback migration for a new version
- update handoff to the new binary bootstrap path where feasible
- command-surface changes for auto-update policy

Before each logical checkpoint commit, run:

- `cargo fmt -- --check`
- `cargo clippy`
- `cargo test --no-fail-fast`

## Commit Plan

Expected logical checkpoints:

1. plan document only
2. extract shared bootstrap logic and redefine `cadence install`
3. move update/bootstrap handoff to the new version and unify first-run
   migration
4. reduce `hook post-commit` to a no-op and simplify auto-update command policy
5. documentation/help text/test cleanup as needed

The exact split can change if the codebase suggests a cleaner boundary, but each
commit should leave the branch passing format, lint, and tests.
