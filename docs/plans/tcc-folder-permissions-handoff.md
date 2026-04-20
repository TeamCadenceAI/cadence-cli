# Handoff: Documents/Desktop TCC Permission Prompts

**Branch**: `claude/awesome-jang-6b704a`
**PR**: to be opened (see `gh pr view` once pushed)
**Worktree**: `/Users/keithlang/Documents/GitHub/cadence-cli/.claude/worktrees/awesome-jang-6b704a`
**Status**: code complete, tests green — awaiting manual testing on macOS (and spot-check on Linux/Windows)
**Date**: 2026-04-20

## What Was Done

- New module `/Users/keithlang/Documents/GitHub/cadence-cli/.claude/worktrees/awesome-jang-6b704a/src/permissions.rs`
  - `prompt_first_install_folder_access()` — macOS only: prints rationale, probes `~/Documents` and `~/Desktop` to trigger TCC prompts with context, persists a marker.
  - `request_desktop_access()` — opt-in entrypoint for existing users; macOS-only behavior, Linux/Windows print a neutral "no action required" note.
  - `desktop_access_requested()` — returns `true` unconditionally on Linux/Windows; on macOS reads the marker file.
  - Full `#[cfg(target_os = "macos")]` gating so non-macOS builds stay silent and side-effect-free.
- `run_install` in `/Users/keithlang/Documents/GitHub/cadence-cli/.claude/worktrees/awesome-jang-6b704a/src/bootstrap.rs` detects first install via absence of `last-version-bootstrap` marker, then calls `prompt_first_install_folder_access()` before recovery backfill.
- `candidate_owner_repo_roots` in `/Users/keithlang/Documents/GitHub/cadence-cli/.claude/worktrees/awesome-jang-6b704a/src/git.rs` now adds `~/Desktop` and `~/Desktop/GitHub` to its search list, gated on `desktop_access_requested()`. On Linux/Windows this is unconditional; on macOS it waits for the marker.
- New CLI subcommand: `cadence permissions request-desktop` wired in `/Users/keithlang/Documents/GitHub/cadence-cli/.claude/worktrees/awesome-jang-6b704a/src/main.rs`.
- 8 new tests (marker round-trip, `is_first_install` detection, Desktop gating, clap parsing). Full suite (360 unit tests + 36 integration tests) passes; `cargo fmt` and `cargo clippy --all-targets -- -D warnings` clean.

## What's Left — Local Test Plan

Build the binary once:

```bash
cd /Users/keithlang/Documents/GitHub/cadence-cli/.claude/worktrees/awesome-jang-6b704a
cargo build --release
```

Then, on **macOS**, test each scenario by simulating a fresh or existing user via `HOME` overrides so you don't touch your real state:

### 1. First install — both prompts with rationale
```bash
FRESH_HOME=$(mktemp -d)
HOME=$FRESH_HOME ./target/release/cadence install
```
Expect: "Folder access Documents and Desktop" banner + 3 rationale lines, then macOS dialogs for **Documents** and **Desktop** (in that order). Install should complete regardless of grant/deny.

### 2. Re-run install after first install — no new prompts
```bash
HOME=$FRESH_HOME ./target/release/cadence install   # same HOME as step 1
```
Expect: No rationale banner. No new prompts. Just the normal install output.

### 3. Existing user upgrade path — no Desktop prompt
```bash
EXISTING_HOME=$(mktemp -d)
mkdir -p $EXISTING_HOME/.cadence/cli
echo "2.6.0" > $EXISTING_HOME/.cadence/cli/last-version-bootstrap   # simulate prior install
HOME=$EXISTING_HOME ./target/release/cadence install
```
Expect: Install runs normally; **no** folder-access banner; no Desktop prompt. (Documents may or may not prompt depending on prior state — macOS remembers across processes.)

### 4. Opt-in command — Desktop prompt only
```bash
HOME=$EXISTING_HOME ./target/release/cadence permissions request-desktop
```
Expect: "Folder access Desktop" banner + 2 rationale lines, then a Desktop TCC dialog. "Recorded Desktop access preference" on exit.

### 5. Deny path — no crashes
Re-run step 1 with a fresh `HOME` and click **Don't Allow** on both dialogs. Install should still complete cleanly; `cadence backfill --since 7d` afterward should not error. (It just won't find repos under those folders.)

### 6. Linux / Windows spot-check (optional)
- `cadence install` on a fresh HOME: no rationale banner, no prompts, completes normally.
- `cadence permissions request-desktop`: prints `"Desktop folder access is not gated on this platform; no action required."` and exits 0.
- Put a git repo at `~/Desktop/myrepo` and confirm `cadence backfill` finds it.

### 7. Help text sanity
```bash
./target/release/cadence --help | grep permissions
./target/release/cadence permissions --help
./target/release/cadence permissions request-desktop --help
```
All three should read cleanly on any platform.

## Known Issues

- **Silent failure on full-deny**: if a macOS user denies both prompts *and* keeps all repos under `~/Documents/GitHub`, backfill silently finds nothing. No warning surfaced today. Possible follow-up: add a `cadence doctor` check that detects a TCC-denied path with recent agent sessions.
- **Pre-marker legacy users**: a user on a very old Cadence version that predates `last-version-bootstrap` would be treated as first-install on their next `cadence install` — they'd see the rationale once. Small population; acceptable IMO, but worth noting.
- **Rationale line wraps**: the "macOS may now ask..." sentence is split across two `output::detail()` calls at `src/permissions.rs:87-89` with a manual line break. Deterministic across terminal widths but looks odd if someone copy-pastes a single line.

## Key Decisions

- **Marker file, not config value**: used a zero-byte sentinel file `~/.cadence/cli/desktop-access-requested` because writing "user has been asked" is orthogonal to the existing TOML config surface, and absence-of-file is a clean existing-user signal.
- **Asked-not-granted semantics**: the marker records "the user has seen the prompt," not "the user granted." If they deny now and later enable in System Settings, Cadence picks it up automatically on the next backfill — no re-prompt needed.
- **First-install detection reuses the `last-version-bootstrap` marker** rather than adding a new one. Absence of that file is already the de-facto "never installed successfully" signal.
- **Linux/Windows get Desktop scanning for free**: on non-macOS, `desktop_access_requested()` returns `true` unconditionally, so `~/Desktop` is always in the scan list. This is additive — no existing scan paths were removed.
- **No `--refresh-permissions` flag on install**: kept opt-in on its own subcommand (`cadence permissions request-desktop`) to keep `install`'s flag surface minimal and make the opt-in discoverable via `cadence permissions --help`.

## Context Docs

- `/Users/keithlang/Documents/GitHub/cadence-cli/.claude/worktrees/awesome-jang-6b704a/src/permissions.rs` — new module, fully commented.
- `/Users/keithlang/Documents/GitHub/cadence-cli/.claude/worktrees/awesome-jang-6b704a/src/bootstrap.rs` — see `is_first_install()` and the first-install prompt call in `run_install`.
- `/Users/keithlang/Documents/GitHub/cadence-cli/.claude/worktrees/awesome-jang-6b704a/src/git.rs` — see `candidate_owner_repo_roots()` for the Desktop gating logic.
- `git diff main` — full diff of changes.

## Handoff Prompt

Copy-paste this into a new Claude session if picking up mid-testing:

---

Check out worktree at `/Users/keithlang/Documents/GitHub/cadence-cli/.claude/worktrees/awesome-jang-6b704a` (branch `claude/awesome-jang-6b704a`) and read `/Users/keithlang/Documents/GitHub/cadence-cli/.claude/worktrees/awesome-jang-6b704a/docs/plans/tcc-folder-permissions-handoff.md`.

Work is code-complete on a TCC permission flow (Documents/Desktop) for `cadence install` with a `cadence permissions request-desktop` opt-in for existing users. All automated tests pass. Keith is manually testing the 7 scenarios in the "What's Left" section. If a scenario fails, the fix likely lives in `src/permissions.rs`, `src/bootstrap.rs::run_install`, or `src/git.rs::candidate_owner_repo_roots`.

---
