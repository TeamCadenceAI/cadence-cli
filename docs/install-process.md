# `cadence install` — Installation Process

## Synopsis

```
cadence install [--org <GITHUB_ORG>]
```

| Flag    | Description                                          |
| ------- | ---------------------------------------------------- |
| `--org` | Optional GitHub org filter; only track repos in this org |

## `install.sh` — Shell wrapper

The `install.sh` script downloads the latest release binary and runs `cadence install`. It accepts an optional org argument:

```sh
# Without org
curl -sSf https://raw.githubusercontent.com/TeamCadenceAI/cadence-cli/main/install.sh | sh

# With org
curl -sSf https://raw.githubusercontent.com/TeamCadenceAI/cadence-cli/main/install.sh | sh -s -- MyOrg
```

When an org is provided, the script prints a confirmation before running setup:

```
Installing for org: MyOrg
```

The org argument is forwarded to `cadence install --org <ORG>`.

**Source:** [`install.sh:76-85`](../install.sh#L76-L85)

## Step-by-step walkthrough

### Step 1 — Set global `core.hooksPath`

```
git config --global core.hooksPath ~/.git-hooks
```

Configures Git to look for hooks in `~/.git-hooks/` instead of each repository's `.git/hooks/` directory. This is the mechanism that lets a single hook installation cover every repository on the machine.

**Source:** [`main.rs:332-344`](../src/main.rs#L332-L344)

---

### Step 2 — Create `~/.git-hooks/` directory

If `~/.git-hooks/` does not already exist, it is created (including any missing parent directories).

**Source:** [`main.rs:346-365`](../src/main.rs#L346-L365)

---

### Step 3 — Write post-commit hook shim

A lightweight shell script is written to `~/.git-hooks/post-commit`:

```sh
#!/bin/sh
exec cadence hook post-commit
```

The shim delegates all work to `cadence hook post-commit`, which scans for AI agent session logs and attaches them to the commit via git notes.

**Existing hook handling:**

| Scenario | Action |
| --- | --- |
| No existing hook | Write new shim |
| Existing hook is a Cadence hook | Overwrite (update in place) |
| Existing hook is **not** a Cadence hook | Back up to `~/.git-hooks/post-commit.pre-cadence`, then overwrite |
| Existing hook is unreadable | Overwrite with a warning |

**Source:** [`main.rs:367-457`](../src/main.rs#L367-L457), [`main.rs:226-228`](../src/main.rs#L226-L228)

---

### Step 4 — Make hook executable

On Unix systems (macOS / Linux), the shim is set to mode `0755` so Git can execute it.

**Source:** [`main.rs:425-445`](../src/main.rs#L425-L445)

---

### Step 5 — Clean up legacy pre-push hook

Cadence previously used a `pre-push` hook. If `~/.git-hooks/pre-push` exists and contains Cadence content, it is removed. Non-Cadence pre-push hooks are left untouched.

**Source:** [`main.rs:459-501`](../src/main.rs#L459-L501)

---

### Step 6 — Persist org filter (conditional)

Only runs if `--org <ORG>` was passed:

```
git config --global ai.cadence.org <ORG>
```

The post-commit hook later reads this value to decide whether to process a repository (only repos whose remote matches the configured org are tracked).

**Source:** [`main.rs:268-279`](../src/main.rs#L268-L279)

---

### Step 7 — Auto-update preference (first-time experience)

Only runs in interactive terminals (both stdout and stderr are TTYs). Skipped silently in CI or piped contexts.

| User state | Behavior |
| --- | --- |
| First-time user (`auto_update` not set) | Enables auto-update by default; shows disclosure; saves `auto_update = true` to `~/.cadence/cli/config.toml` |
| `auto_update = true` already set | Shows disclosure message only |
| `auto_update = false` | Skipped entirely |

Disclosure message:

> Cadence enables unattended background updates by default (stable channel only, no prompts).
> Disable anytime: `cadence auto-update disable`
> Remove scheduler artifacts: `cadence auto-update uninstall`

**Source:** [`main.rs:2567-2664`](../src/main.rs#L2567-L2664)

---

### Step 8 — Reconcile auto-update scheduler

Provisions a platform-specific scheduler so Cadence can self-update in the background (every 8 hours with a 30-minute random delay).

#### macOS — LaunchAgent

Creates `~/Library/LaunchAgents/ai.teamcadence.cadence.autoupdate.plist` and loads it:

```
launchctl bootout gui/<uid>/ai.teamcadence.cadence.autoupdate   # unload if present
launchctl bootstrap gui/<uid> ~/Library/LaunchAgents/…plist      # load
launchctl enable gui/<uid>/ai.teamcadence.cadence.autoupdate     # enable
```

Key plist settings:
- `RunAtLoad: true`
- `StartInterval: 28800` (8 hours)
- `RandomDelay: 1800` (30 minutes)

#### Linux — systemd user timer

Creates two files:
- `~/.config/systemd/user/cadence-autoupdate.service` (oneshot, runs `cadence hook auto-update`)
- `~/.config/systemd/user/cadence-autoupdate.timer` (`OnBootSec=5m`, `OnUnitActiveSec=8h`, `RandomizedDelaySec=30m`)

Then runs:
```
systemctl --user daemon-reload
systemctl --user enable --now cadence-autoupdate.timer
```

#### Windows — Task Scheduler

```
schtasks /Create /F /SC HOURLY /MO 8 /TN "Cadence CLI Auto Update" /TR "cadence.exe hook auto-update"
```

If auto-update is **disabled**, the scheduler artifacts are removed instead.

**Source:** `src/update.rs` (scheduler provisioning functions)

---

## Files created or modified

| Path | Purpose |
| --- | --- |
| `~/.gitconfig` | Sets `core.hooksPath` and optionally `ai.cadence.org` |
| `~/.git-hooks/` | Hooks directory |
| `~/.git-hooks/post-commit` | Post-commit hook shim (mode `0755`) |
| `~/.git-hooks/post-commit.pre-cadence` | Backup of pre-existing non-Cadence hook (if any) |
| `~/.cadence/cli/config.toml` | Stores `auto_update` preference |
| `~/Library/LaunchAgents/ai.teamcadence.cadence.autoupdate.plist` | macOS scheduler (if auto-update enabled) |
| `~/.config/systemd/user/cadence-autoupdate.{service,timer}` | Linux scheduler (if auto-update enabled) |

## Error handling

Each step reports errors but **does not abort** — subsequent steps are always attempted. A `had_errors` flag tracks whether any step failed. At the end:

- All steps succeeded → `Install complete`
- One or more steps failed → `Install completed with issues`

Total elapsed time is printed in milliseconds.

## Repo-level control

`cadence install` does **not** offer per-repo selection — the hook applies globally to every repository on the machine. Repos are controlled after install via two opt-out mechanisms:

### Org filter (install-time)

Pass `--org <GITHUB_ORG>` during install to restrict tracking to repositories whose remote matches the given org. The hook checks this at commit time and silently skips non-matching repos.

```
cadence install --org my-company
```

Stored in: `git config --global ai.cadence.org`

### Per-repo disable (post-install)

Disable Cadence for a specific repository by setting a local git config:

```
cd /path/to/repo
git config ai.cadence.enabled false
```

Any value other than `"false"` (including unset) is treated as enabled. This check gates the entire hook lifecycle — when disabled, no session scanning, uploading, or note-writing occurs for that repo.

## What happens after install

Every `git commit` in any repository triggers the hook chain:

1. Git invokes `~/.git-hooks/post-commit`
2. The shim runs `cadence hook post-commit`
3. The hook checks `ai.cadence.enabled` git config (default: `true`) and the org filter
4. If enabled, it scans for AI agent session logs (Claude Code, Codex, etc.)
5. Discovered sessions are attached to the commit as git notes under `refs/cadence/sessions/data`
6. Notes are pushed to the remote on the next `git push`
