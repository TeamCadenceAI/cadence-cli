# `cadence install` — Installation Process

## Synopsis

```sh
cadence install [--org <GITHUB_ORG>]
```

| Flag | Description |
| --- | --- |
| `--org` | Optional GitHub org filter; only upload sessions for repos in this org |

## Current Behavior

`cadence install` enables Cadence as a background monitor. It does not install
or refresh Git hooks.

High-level responsibilities:

1. clean up legacy Cadence-managed hook ownership where safe
2. persist the optional org filter
3. enable monitor state
4. reconcile the OS-native scheduler that runs `cadence monitor tick`
5. enable auto-update policy so update checks can run inside monitor ticks

## `install.sh` Wrapper

The shell installer downloads the latest release and runs `cadence install`.
An optional org argument is forwarded to `cadence install --org <ORG>`.

```sh
curl -sSf https://raw.githubusercontent.com/TeamCadenceAI/cadence-cli/main/install.sh | sh
curl -sSf https://raw.githubusercontent.com/TeamCadenceAI/cadence-cli/main/install.sh | sh -s -- MyOrg
```

## Step-by-step Walkthrough

### Step 1 — Clean Up Legacy Cadence Hook Ownership

Cadence checks `~/.git-hooks` and the global `core.hooksPath` only to clean up
old Cadence-managed installs. It does not claim hook ownership for new
installs.

Cleanup rules:

- remove Cadence-managed `post-commit` and legacy `pre-push` hooks
- restore `post-commit.pre-cadence` when it exists
- leave non-Cadence hook files untouched
- unset global `core.hooksPath` only if it still points to the Cadence-owned
  hooks directory and no preserved user hooks remain there

Repo-local `core.hooksPath` and non-Cadence hook layouts are left alone.

### Step 2 — Persist Org Filter

If `--org <ORG>` is provided, install writes:

```sh
git config --global ai.cadence.org <ORG>
```

The monitor later uses this global org filter during session eligibility checks.

### Step 3 — Show Monitor / Auto-Update Disclosure

In interactive terminals, install prints the current product model:

- background monitoring runs without owning Git hooks
- monitor lifecycle lives under `cadence monitor ...`
- auto-update runs inside the monitor runtime

This is informational only; non-interactive installs skip the disclosure.

### Step 4 — Enable Monitor State And Reconcile Scheduler

Install marks monitoring enabled and provisions an OS-native scheduler for
`cadence monitor tick`.

Cadence:

- runs every 30 seconds on macOS and Linux
- runs every 60 seconds on Windows

Platform artifacts:

- macOS: `~/Library/LaunchAgents/ai.teamcadence.cadence.monitor.plist`
- Linux: `~/.config/systemd/user/cadence-monitor.service` and
  `~/.config/systemd/user/cadence-monitor.timer`
- Windows: Task Scheduler task `Cadence CLI Monitor`

The scheduler is monitor-owned. Auto-update no longer provisions a separate
scheduler.

### Step 5 — Enable Auto-Update Policy

Install enables `auto_update = true` in `~/.cadence/cli/config.toml` so update
checks can run during monitor ticks.

This is policy only. Scheduler lifecycle remains under `cadence monitor ...`.

## Files Created Or Modified

| Path | Purpose |
| --- | --- |
| `~/.gitconfig` | May set `ai.cadence.org`; may remove Cadence-owned `core.hooksPath` during cleanup |
| `~/.git-hooks/post-commit` | Removed only if Cadence can prove it owns the hook |
| `~/.git-hooks/post-commit.pre-cadence` | Restored when a pre-Cadence hook backup exists |
| `~/.git-hooks/pre-push` | Removed only if it is a legacy Cadence hook |
| `~/.cadence/cli/monitor-state.json` | Stores monitor enablement and last-run health |
| `~/.cadence/cli/config.toml` | Stores auto-update policy and other CLI config |
| `~/Library/LaunchAgents/ai.teamcadence.cadence.monitor.plist` | macOS monitor scheduler |
| `~/.config/systemd/user/cadence-monitor.{service,timer}` | Linux monitor scheduler |

The global discovery cursor file
`~/.cadence/cli/monitor-discovery-cursor.json` is typically created on the
first successful monitor tick, not during install itself.

## Error Handling

Install keeps going after individual step failures and reports a final summary:

- `Install complete`
- `Install completed with issues`

The command prints total elapsed time in milliseconds.

## Repo-level Control

`cadence install` is machine-wide monitor enablement, not a per-repo opt-in.
Repo selection still uses the existing filters:

### Org Filter

```sh
cadence install --org my-company
```

Stored in global git config as `ai.cadence.org`.

### Per-repo Disable

```sh
cd /path/to/repo
git config ai.cadence.enabled false
```

Any value other than `false` is treated as enabled.

## What Happens After Install

The scheduler periodically runs `cadence monitor tick`.

Each tick:

1. acquires the shared Cadence activity lock
2. loads monitor state and exits early if monitoring is disabled
3. drains due pending uploads
4. incrementally scans supported agent session sources globally
5. resolves repo roots from session metadata
6. applies repo-disable and org-filter rules
7. publishes eligible sessions through the v2 publication pipeline
8. records monitor health and summary counts
9. runs unattended update checks if auto-update policy is enabled
