# Cadence CLI

Cadence CLI uploads AI coding agent session logs to Cadence from a scheduled
background monitor. It adds provenance for AI-assisted development without
taking ownership of your normal Git workflow.

## Install

Prerequisites:
- Git

macOS and Linux:
```sh
curl -sSf https://raw.githubusercontent.com/TeamCadenceAI/cadence-cli/main/install.sh | sh
```

Windows (PowerShell):
```powershell
iwr -useb https://raw.githubusercontent.com/TeamCadenceAI/cadence-cli/main/install.ps1 | iex
```

If `~/.local/bin` is not on your PATH, add it:
```sh
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
```

Build from source:
```sh
cargo build --release
```

The release binary is written to `target/release/cadence` on macOS/Linux and
`target\\release\\cadence.exe` on Windows.

## Quick Start

1. Install Cadence.

The shell and PowerShell installers already run `cadence install` for you. If
you built from source, copied the binary manually, or need to repair runtime
bootstrap, run the installed binary directly. For example:

```sh
cadence install                   # if cadence is on your PATH
./target/release/cadence install  # if you are running the source-built binary directly
```

2. Code normally. Cadence scans supported agent session stores in the
background.

3. Check runtime and upload status:
```sh
cadence status
cadence monitor status
```

4. Diagnose or repair install issues:
```sh
cadence doctor
cadence doctor --repair
```

## Monitor Lifecycle

```sh
cadence monitor status
cadence monitor enable
cadence monitor disable
cadence monitor uninstall
```

- `cadence install` is the idempotent bootstrap command used by installer
  flows, first-run version reconciliation, and manual runtime repair.
- `cadence install` enables the monitor by default, reconciles scheduler
  artifacts, and runs a best-effort 7-day recovery backfill when monitoring is
  enabled.
- `cadence monitor enable` re-enables background monitoring and recreates the
  scheduler if needed.
- `cadence monitor disable` keeps state but makes scheduled ticks and
  unattended updates exit early.
- `cadence monitor uninstall` removes the shared scheduler artifacts and leaves
  monitoring disabled.

`cadence install` does not install or refresh Git hooks. If Cadence previously
owned `~/.git-hooks`, install cleans up Cadence-managed hook artifacts where it
can prove ownership and leaves non-Cadence hooks untouched.

## Updates and Background Updates

Cadence has two update paths:

1. Manual update commands:
```sh
cadence update --check
cadence update
cadence update -y
```

2. Background updates:
- Update checks run inside monitor ticks whenever monitoring is enabled.
- Stable releases only; prereleases are ignored.
- A shared activity lock prevents overlap with other Cadence work.
- Retry and backoff state is persisted locally.
- After replacing the binary, Cadence immediately launches the new version and
  reruns bootstrap.
- Automatic post-update bootstrap preserves an explicitly disabled monitor
  state.
- If that handoff does not happen, the next normal CLI invocation performs the
  same once-per-version bootstrap automatically.

Diagnostic command:
```sh
cadence auto-update status
```

- `status` reports updater health and policy.
- There is no separate user-facing auto-update toggle. Monitoring state
  controls unattended updates.
- Use `cadence monitor disable` or `cadence monitor uninstall` if you need to
  stop all background Cadence activity.

## How It Works

Cadence installs an OS-native scheduled one-shot monitor tick:

- macOS and Linux: every 30 seconds
- Windows: every 60 seconds

Each tick:

- acquires the shared Cadence activity lock
- exits immediately if monitoring is disabled or another Cadence task is active
- drains due pending uploads
- scans supported agent session sources globally
- resolves repo roots from session metadata
- applies existing repo and org filters
- publishes through the current v2 session-publication pipeline
- records monitor health and summary counts
- runs unattended stable-channel update checks while monitoring is enabled

Legacy hidden hook entrypoints still exist only as upgrade-compatibility shims.
`cadence hook post-commit` is now a silent success no-op while old installs are
being cleaned up.

## Visibility and Repair

```sh
cadence status
cadence doctor
cadence doctor --repair
```

- `status` shows monitor health, cadence, pending uploads, and updater health.
- `status` also shows the current org filter and whether the current repo is
  locally enabled for Cadence uploads.
- `doctor` validates monitor state, discovery cursor readability, scheduler
  artifacts, pending upload state, and safe migration cleanup.
- `doctor --repair` rewrites scheduler artifacts based on current monitor
  intent.

## Supported Agents

- Claude Code
- Codex
- Cline
- Roo Code
- OpenCode
- Kiro
- Amp Code
- Cursor
- GitHub Copilot
- Antigravity
- Warp

Note: Warp stores sessions in a local SQLite database. In some local-only
cases the assistant output may be missing, so Cadence stores prompts/context
without responses. OpenCode sessions are normalized from fragmented storage
(`session`, `message`, `part`) into one synthetic session log per session ID
before ingestion.

## Uninstall

Stop background monitoring but keep the CLI installed:
```sh
cadence monitor uninstall
```

Remove Cadence state, scheduler artifacts, org filter config, legacy hook
ownership, and the running binary when possible:
```sh
cadence uninstall -y
```

On Windows, Cadence will ask you to delete the executable manually after
uninstall because self-delete is not reliable there.

## License

See `LICENSE.md`.
