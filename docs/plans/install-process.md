# `cadence install` — Installation Process

## Synopsis

```sh
cadence install [--org <GITHUB_ORG>]
```

| Flag | Description |
| --- | --- |
| `--org` | Optional GitHub org filter; only upload sessions for repos in this org |

## Current Behavior

`cadence install` is Cadence's idempotent bootstrap command. It enables or
repairs the background runtime, and it does not install or refresh Git hooks.

High-level responsibilities:

1. clean up legacy Cadence-managed hook ownership where safe
2. persist the optional org filter
3. determine the desired monitor state
4. reconcile the OS-native scheduler that runs `cadence monitor tick`
5. run a recovery backfill when monitoring is enabled
6. record that the current Cadence version completed bootstrap

Monitor-state rules:

- normal `cadence install` enables monitoring by default
- internal post-update bootstrap uses the hidden
  `--preserve-disable-state` flag so an explicit `cadence monitor disable`
  choice survives updates
- unattended updates follow monitor state; there is no separate
  `auto_update` policy toggle

## `install.sh` Wrapper

The shell installer downloads the latest release and runs `cadence install`.
An optional org argument is forwarded to `cadence install --org <ORG>`.

Self-update follows the same bootstrap model:

- `cadence update` replaces the binary
- the updater immediately launches the new version and runs
  `cadence install --preserve-disable-state`
- if that handoff does not happen, the next normal CLI invocation performs the
  same once-per-version bootstrap automatically

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

### Step 3 — Show Monitor / Update Disclosure

In interactive terminals, install prints the current product model:

- background monitoring runs without owning Git hooks
- monitor lifecycle lives under `cadence monitor ...`
- unattended stable-channel updates run inside the monitor runtime whenever
  monitoring is enabled

This is informational only; non-interactive installs skip the disclosure.

### Step 4 — Determine Monitor State And Reconcile Scheduler

Install determines whether monitoring should be enabled, then provisions or
removes OS-native scheduler artifacts for `cadence monitor tick`.

State rules:

- a user-invoked `cadence install` enables monitoring
- an internal `cadence install --preserve-disable-state` keeps an explicitly
  disabled monitor disabled
- if no prior monitor state exists, bootstrap enables monitoring

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

### Step 5 — Run Recovery Backfill And Mark Version Bootstrap

When monitoring is enabled, install runs a best-effort:

```sh
cadence backfill --since 7d
```

This recovers recent local sessions after fresh install or version migration.

Install then records the current CLI version in the bootstrap marker so later
invocations know this version's runtime migration is complete.

## Files Created Or Modified

| Path | Purpose |
| --- | --- |
| `~/.gitconfig` | May set `ai.cadence.org`; may remove Cadence-owned `core.hooksPath` during cleanup |
| `~/.git-hooks/post-commit` | Removed only if Cadence can prove it owns the hook |
| `~/.git-hooks/post-commit.pre-cadence` | Restored when a pre-Cadence hook backup exists |
| `~/.git-hooks/pre-push` | Removed only if it is a legacy Cadence hook |
| `~/.cadence/cli/monitor-state.json` | Stores monitor enablement and last-run health |
| `~/.cadence/cli/last-version-bootstrap` | Records the last Cadence version that completed runtime bootstrap |
| `~/Library/LaunchAgents/ai.teamcadence.cadence.monitor.plist` | macOS monitor scheduler |
| `~/.config/systemd/user/cadence-monitor.{service,timer}` | Linux monitor scheduler |

The global discovery cursor file
`~/.cadence/cli/monitor-discovery-cursor.json` is typically created on the
first successful monitor tick, not during install itself. Updater retry state
is also created lazily when background updates first run.

## Error Handling

Install keeps going after individual step failures so it can perform as much
bootstrap work as possible, but it still exits non-zero if any runtime step
failed.

On success it prints `Install complete` and the elapsed time in milliseconds.
On failure it surfaces the accumulated bootstrap error so the user can rerun
`cadence install` after fixing the underlying issue.

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
9. runs unattended stable-channel update checks while monitoring is enabled
