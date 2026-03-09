# Cadence CLI Update / Auto-Update Investigation

## Scope

This document captures:

1. **Phase 1**: How Cadence currently detects updates and how updates are installed.
2. **Phase 2**: Happy-path and unhappy-path flows, including conditions that delay, suppress, or cancel updates.

Codebase analyzed from `main` branch at investigation time: **2026-03-09**.

---

## Phase 1: How Updates Work Today

## 1) Entry points

- Manual update command: `cadence update` (install flow) and `cadence update --check` (check-only flow).
- Passive check path: runs after successful non-`update` commands in `main` (`src/main.rs`), via `update::passive_version_check()`.
- Install-time preference capture: `cadence install` may prompt for `auto_update` preference if TTY and not already configured.

## 2) Release discovery

`src/update.rs` does **not** call GitHub API JSON endpoints for release metadata.  
It requests:

- `https://github.com/TeamCadenceAI/cadence-cli/releases/latest`

Then expects an HTTP redirect and extracts tag from redirect `Location` header.

From that tag it synthesizes artifact URLs for supported targets plus:

- `checksums-sha256.txt`

## 3) Version comparison and availability detection

- Local version: compile-time `CARGO_PKG_VERSION`.
- Remote version: discovered tag (normalized to remove optional `v`).
- Comparison: `semver` ordering.

Outcomes:

- `cadence update --check`
  - Prints update available message if remote newer.
  - Prints up-to-date message otherwise.
  - On network/parse errors: warns and exits successfully.
- Passive check
  - If remote newer: prints stderr notification:  
    `A new version of cadence is available... Run 'cadence update' to upgrade.`
  - Never auto-installs in passive mode.

## 4) Install flow (`cadence update`)

When update is available:

1. Load config (`~/.cadence/cli/config.toml`) as a hard requirement.
2. Resolve platform artifact by compile-time target triple.
3. Resolve checksums asset.
4. Confirmation precedence:
   - `--yes` => accept
   - else `auto_update = true` => accept
   - else interactive confirm prompt (`[y/N]`)
5. Download checksums and archive to temp dir.
6. Verify SHA-256 hash.
7. Extract `cadence`/`cadence.exe`.
8. Set Unix executable permissions (on Unix).
9. Self-replace running binary via `self_replace`.

## 5) What `auto_update` actually means

`auto_update` currently means:

- **Skip confirmation prompt when user runs `cadence update`.**

It does **not** currently mean:

- background unattended update installation
- hook-triggered self-update
- periodic auto-install of new versions

## 6) Passive-check gating and throttling

Passive checks are suppressed unless all conditions allow:

- Not an `update` command
- Prior command succeeded
- `CADENCE_NO_UPDATE_CHECK` is not `"1"`
- stdout is a TTY
- check interval elapsed (default 8h, configurable via `update_check_interval`)

Timing behavior:

- Passive network timeout is 3 seconds.
- Timestamp is updated after attempt (success or failure), preventing retry storms.
- Failed passive checks are silent.

---

## Phase 2: Happy / Unhappy Flows and Risks

## Happy flows

1. **Manual check path**
   - User runs `cadence update --check`.
   - Redirect resolves, semver compare succeeds, clear availability result printed.

2. **Manual install path with prompt**
   - User runs `cadence update`.
   - Update found, prompt shown, user confirms, checksum passes, binary replaces successfully.

3. **Manual install path without prompt**
   - User runs `cadence update -y` OR has `auto_update=true`.
   - Same install flow, non-interactive confirmation stage.

4. **Passive detection with visible terminal**
   - User runs successful non-update command in TTY.
   - If interval elapsed and update exists, user sees reminder to run `cadence update`.

## Unhappy flows / failure modes

## A) Detection can be missed or delayed

1. **Non-TTY contexts suppress passive checks**
   - Hooks or GUI-driven flows often run without TTY.
   - No passive check => no update notification.

2. **No successful commands run**
   - Passive checks run only after successful command completion.
   - If users do not run Cadence commands directly, no passive detection occurs.

3. **Throttle interval delays visibility**
   - Default `8h` means users can be behind until next eligible check window.

4. **Failure backoff behavior can delay retries**
   - Timestamp is updated even on failed check attempts.
   - Persistent network outage can postpone re-attempt until next interval.

## B) Install can be blocked or canceled

1. **User cancellation**
   - Interactive prompt default is No.
   - Ctrl-C / interrupted input treated as decline (`Update cancelled.`).

2. **Config parse/load failure**
   - `cadence update` hard-fails if config is malformed.

3. **Release discovery failure**
   - Non-redirect response, missing `Location`, invalid tag parse, or network failure.

4. **Artifact/target mismatch**
   - Missing expected asset name for current target triple.

5. **Missing or malformed checksums**
   - No `checksums-sha256.txt`, malformed file, missing artifact entry, hash mismatch.

6. **Archive extraction problems**
   - Corrupt archive or missing `cadence` binary in archive structure.

7. **Permissions / in-use binary replacement issues**
   - `self_replace` failure if permissions disallow replace or OS/process locking interferes.

## C) Hook-related behavior (specific question)

If update detection is triggered from a hook path:

- Passive check may run after hook command returns success in `main`, because hooks are non-`update` commands.
- But passive check still requires TTY. In many hook invocations that condition is false, so it is skipped.
- Even if passive check runs and detects a new release, it only prints a reminder; it does **not** install.
- `cadence update` remains manually runnable later (or auto-confirmed if configured), independent of whether a hook-triggered passive check happened.

## D) GUI/embedded-agent users (e.g., Claude app users not seeing terminal)

This is a real visibility gap:

- If the user never sees Cadence stderr/stdout and never runs explicit `cadence update`/`cadence update --check`, they may not notice updates.
- Current passive notification is terminal text only.
- There is no background updater daemon, desktop notification integration, or forced upgrade flow in this CLI.

## E) Terminology gap (important)

Current naming can be interpreted as stronger automation than implemented:

- `auto_update=true` suggests unattended updates.
- Actual behavior is "auto-confirm update command".

This can cause expectation mismatch for users and for docs/support.

---

## Practical conclusions

1. Update **detection** is best-effort and visibility-biased toward interactive terminal users.
2. Update **installation** is explicit/manual (`cadence update`), with optional prompt bypass.
3. Hook paths do not provide reliable update visibility and do not auto-install.
4. Users operating through non-terminal tools can remain outdated indefinitely unless another mechanism prompts them.

---

## Referenced code paths

- `src/main.rs`
  - command dispatch (`Update`)
  - passive check trigger after successful non-update commands
  - install-time auto-update preference prompt
- `src/update.rs`
  - release tag discovery via redirect
  - version comparison
  - install orchestration (download, checksum, extract, self-replace)
  - passive-check gating (`TTY`, env var, interval)
- `src/config.rs`
  - `auto_update` and `update_check_interval`
  - latest-version cache write helpers
