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

### Two kinds of testing

**A. Code-path tests** — cheap, fast, use a throwaway `HOME` to isolate from your real state.
`HOME=$(mktemp -d)` redirects `home_dir()` ([src/agents/mod.rs:156](src/agents/mod.rs:156)) to the tempdir. This exercises the rationale banner, marker write/read, install ordering, and `is_first_install()` — but **does not trigger real macOS TCC dialogs**, because `/tmp/.../Documents` and `/tmp/.../Desktop` aren't TCC-protected. Use these to verify the code flows.

**B. Real TCC dialog tests** — must run against your actual `HOME` on a macOS session where the relevant TCC grant is either missing or has been reset. The terminal you run `cadence` from is what macOS attaches the grant to (e.g. `com.apple.Terminal`, `com.googlecode.iterm2`). Use these to verify the prompts themselves fire.

---

### Code-path tests (throwaway HOME)

#### 1. First install — rationale fires, marker written
```bash
FRESH_HOME=$(mktemp -d)
HOME=$FRESH_HOME ./target/release/cadence install
ls $FRESH_HOME/.cadence/cli/
```
Expect:
- "Folder access Documents and Desktop" banner + 3 rationale lines printed.
- No actual TCC dialog (tempdir path is not protected).
- `$FRESH_HOME/.cadence/cli/desktop-access-requested` exists after the run.
- `$FRESH_HOME/.cadence/cli/last-version-bootstrap` exists after the run.

#### 2. Re-run install — no rationale the second time
```bash
HOME=$FRESH_HOME ./target/release/cadence install   # same HOME as step 1
```
Expect: no folder-access banner; install proceeds normally.

#### 3. Simulated existing user — no Desktop gating surprise
```bash
EXISTING_HOME=$(mktemp -d)
mkdir -p $EXISTING_HOME/.cadence/cli
echo "2.6.0" > $EXISTING_HOME/.cadence/cli/last-version-bootstrap
HOME=$EXISTING_HOME ./target/release/cadence install
```
Expect: no banner, no Desktop-related output.

#### 4. Opt-in command — runs the request path
```bash
HOME=$EXISTING_HOME ./target/release/cadence permissions request-desktop
ls $EXISTING_HOME/.cadence/cli/desktop-access-requested
```
Expect: "Folder access Desktop" banner + 2 rationale lines, "Recorded Desktop access preference". Marker now exists.

---

### Real TCC dialog tests (real HOME)

Run these **once** from the terminal app you normally use. macOS caches the TCC decision per-terminal, so after the first round you'll need a reset or a different terminal to see the prompt again.

#### 5. Reset TCC for your terminal, then first-install
```bash
# Reset TCC grants for the terminal bundle — pick whichever matches your terminal.
# Terminal.app:
tccutil reset SystemPolicyDocumentsFolder com.apple.Terminal
tccutil reset SystemPolicyDesktopFolder com.apple.Terminal
# iTerm2 (replace as needed):
#   tccutil reset SystemPolicyDocumentsFolder com.googlecode.iterm2
#   tccutil reset SystemPolicyDesktopFolder com.googlecode.iterm2

# Make Cadence treat this as first install — remove (or back up) the bootstrap marker
# under your REAL HOME. WARNING: this touches your live Cadence state.
mv ~/.cadence/cli/last-version-bootstrap ~/.cadence/cli/last-version-bootstrap.bak 2>/dev/null
rm -f ~/.cadence/cli/desktop-access-requested

./target/release/cadence install
```
Expect: rationale banner, then **two real macOS TCC dialogs** (Documents then Desktop). Install completes regardless of grant/deny.

After: `mv ~/.cadence/cli/last-version-bootstrap.bak ~/.cadence/cli/last-version-bootstrap` (or just re-run `cadence install`, which writes it).

#### 6. Deny path — no crashes
Repeat step 5 but click **Don't Allow** on both dialogs. Expect: install completes cleanly. Follow with `./target/release/cadence backfill --since 7d` and confirm it doesn't error — it'll just skip the denied folders.

#### 7. Opt-in command fires the real Desktop prompt
With the terminal's Desktop grant reset and the opt-in marker absent:
```bash
tccutil reset SystemPolicyDesktopFolder com.apple.Terminal
rm -f ~/.cadence/cli/desktop-access-requested
./target/release/cadence permissions request-desktop
```
Expect: rationale banner, then a real Desktop TCC dialog.

---

### Cross-platform

#### 8. Linux / Windows spot-check (optional)
- `cadence install` on a fresh HOME: no rationale banner, no prompts, completes normally.
- `cadence permissions request-desktop`: prints `"Desktop folder access is not gated on this platform; no action required."` and exits 0.
- Put a git repo at `~/Desktop/myrepo` and confirm `cadence backfill` finds it.

#### 9. Help text sanity (any platform)
```bash
./target/release/cadence --help | grep permissions
./target/release/cadence permissions --help
./target/release/cadence permissions request-desktop --help
```
All three should read cleanly.

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
