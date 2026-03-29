# Pre-Deploy TODO

This branch needs the following fixes before deployment.

- [x] Fix background auto-update success accounting so a failed `cadence install --preserve-disable-state` handoff is not recorded as a successful install/update.
- [x] Fix background update fallback behavior so a background-only upgrade cannot remain permanently unbootstrapped when the new binary never finishes bootstrap.
- [x] Fix `cadence doctor --repair` so an unreadable `monitor-state.json` does not get treated as `enabled = false` and reconciled as disabled.
- [x] Fix once-per-version bootstrap marker semantics so one-time recovery work is not retried indefinitely after partial bootstrap failures.
- [x] Tighten legacy hook ownership detection so cleanup only removes or restores hook files Cadence can actually prove it owns.
- [x] Add targeted tests for bootstrap/update control flow:
- [x] Cover `maybe_run_current_version_bootstrap`.
- [x] Cover failed update handoff followed by first-run fallback bootstrap.
- [x] Cover the "one-time recovery backfill does not rerun forever after partial bootstrap failure" case.
- [x] Add targeted tests for the monitor runtime core paths:
- [x] Cover `run_monitor_tick_internal` or equivalent end-to-end monitor tick behavior.
- [x] Cover `upload_incremental_sessions_globally` cursor advance, retryable blocking, disabled-monitor early exit, and pending-drain behavior.
- [ ] Clean up the dead-code warnings on this branch, including old hook-era paths, upload-cursor leftovers, and dead constants.
- [x] Stop silently swallowing legacy auto-update scheduler teardown failures in monitor scheduler reconciliation; log them clearly.
- [x] Move monitor logging out of `/tmp/cadence-monitor.log` and into `~/.cadence/cli`.
- [x] Use daily append logs for monitor runtime diagnostics, for example `~/.cadence/cli/monitor.YYYY-MM-DD.log`.
- [x] Retain only 14 days of monitor log history; do not add a size cap for this branch.
- [x] Ensure monitor log parent directories are created automatically and cleanup paths are updated for the new durable log location.
- [x] Remove any active monitor log dependence on `/tmp`; do not leave the scheduler writing the primary monitor log there.
- [ ] Fix the stale `run_status_inner` docstring/help text that still describes removed hook-era status checks.
- [ ] Investigate and resolve the observed `cargo test --no-fail-fast` instability before deploy, including the intermittent `activity_lock_blocking_times_out_when_held` failure.

Before deployment, rerun:

- [ ] `cargo fmt -- --check`
- [ ] `cargo clippy --all-targets --all-features`
- [ ] `cargo test --no-fail-fast`
