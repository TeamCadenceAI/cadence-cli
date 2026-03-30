# Cadence Detached Updater And macOS Signing Plan

## Summary

Cadence fixed the immediate monitor self-update outage in `2.2.6`, but the
current updater design still has two structural problems:

- the running `cadence` binary replaces itself in place and immediately starts
  follow-up work from the same on-disk path
- macOS release artifacts are not Developer ID signed or notarized

This plan hardens the updater so the active CLI process never swaps its own
binary under itself, and it adds proper macOS release signing/notarization so
the shipped binaries have a stable trust story.

## Why This Exists

Recent investigation on a real machine showed:

- broken monitor-owned self-update could disable its own LaunchAgent during the
  `2.2.5 -> 2.2.6` handoff
- that specific scheduler bug is now fixed, but macOS still logs `cdhash
  mismatch` during successful updates
- the installed macOS binary is currently only ad-hoc signed
- the release workflow builds raw binaries and archives them without any
  Developer ID signing or notarization

The `cdhash mismatch` is a strong signal that Cadence is still doing something
macOS considers suspicious: the old process is alive while the file at the same
path has already been replaced by a different code object.

## Product Decisions

These are the recommended fixed inputs for the implementation:

- Cadence should stop self-replacing the running `cadence` executable in place.
- Update installation should be performed by a separate updater helper process.
- The updater helper should not depend on the active monitor LaunchAgent staying
  alive while installation runs.
- The updater helper should be treated as the cross-platform primitive, not a
  macOS-only escape hatch.
- macOS release artifacts should be Developer ID signed and notarized before
  they are published.
- Already-stranded machines may still require one manual scheduler repair
  before they can take the new updater path.

## Desired End State

After this work lands:

- `cadence` downloads and verifies a release payload but does not replace its
  own executable while still running
- `cadence` launches a separate updater helper and exits
- the helper waits for the original `cadence` PID to die before swapping files
- the helper installs the staged binary and runs the post-update bootstrap path
- monitor-owned unattended updates no longer perform risky in-place mutation of
  the live `cadence` path
- macOS release artifacts are signed, notarized, and pass `spctl`
- Linux and Windows use the same high-level helper model, with only the final
  file-replacement mechanism varying by platform

## Standard Update Model

The standard safe updater model across desktop platforms is:

1. the running app/tool downloads and verifies the new payload
2. a separate updater process is launched
3. the original app/tool exits
4. the updater waits for the original PID to die
5. the updater swaps files on disk
6. the updater runs any bootstrap/install reconciliation
7. the updater optionally relaunches the updated app/tool

This is the model Cadence should follow. The current `self_replace(...)`
approach is the outlier that creates unnecessary overlap between the old
process image and the new file on disk.

## Architecture Plan

### 1. Add A Separate Updater Helper

Introduce a separate executable, referred to here as `cadence-updater`.

Properties:

- lives at a different path than `cadence`
- accepts a small, explicit install manifest
- can wait for a target PID to exit
- performs the final on-disk replacement
- runs follow-up bootstrap using the updated `cadence`

Recommended scope:

- keep the helper intentionally small and stable
- make it responsible only for staging validation, process waiting, file swap,
  and bootstrap handoff
- avoid letting the helper own normal Cadence monitor or publication logic

### 2. Stage Before Swap

The main `cadence` process should change from:

- download archive
- extract binary
- `self_replace`
- immediately run `cadence install`

to:

- download archive
- verify checksum
- extract staged payload into a versioned temp/staging directory
- write an install manifest describing:
  - target version
  - staged binary path
  - final install path
  - parent PID to wait on
  - whether bootstrap should preserve monitor disable state
  - whether the caller was interactive or silent unattended
- launch `cadence-updater`
- exit cleanly

### 3. Update From The Helper, Not The Main Binary

The helper should:

1. read the install manifest
2. wait for the target Cadence PID to exit
3. swap the staged `cadence` binary into the final install location
4. run the updated `cadence install --preserve-disable-state`
5. record update success/failure in updater state

The helper must not require the old monitor process to remain alive after it
starts.

### 4. Keep Scheduler Ownership Separate

The helper should not directly unload/reload the monitor scheduler unless that
is strictly required.

Recommended rule:

- normal version updates should replace the binary and then let the updated
  `cadence install` reconcile scheduler state
- if the helper is running under monitor-owned unattended update flow, it must
  still avoid the old "disable your own LaunchAgent" failure mode

This keeps scheduler logic in one place instead of teaching both `cadence` and
`cadence-updater` how to manage every OS scheduler edge.

## Cross-Platform Design

The cross-platform invariant should be:

- never replace the target binary until the old target process has exited

Platform-specific replacement details can differ.

### macOS

- helper waits for old Cadence PID to exit
- helper swaps the staged binary into the final path
- helper runs the updated bootstrap path
- no in-place replacement of a still-running executable

This is the main path that should remove the current `cdhash mismatch` pattern.

### Linux

- use the same helper flow as macOS
- final swap can continue using normal rename/copy semantics once the old PID is
  gone

Linux is already permissive, but using the same helper model reduces divergence
and gives confidence that the platform behavior matches the stricter platforms.

### Windows

- use the same helper flow
- helper waits for the old process to exit before touching the installed binary
- final replacement should use the Windows-safe replace/move path already
  validated in tests or be updated to a stricter wait-and-replace mechanism if
  needed

Windows is the platform that most strongly benefits from this model, because
replacing an executable that is still in use is far less forgiving there.

## macOS Signing And Notarization Plan

### 1. Release Artifact Changes

The current release workflow in `.github/workflows/release.yml`:

- builds the macOS binary
- archives it
- uploads it

It does not sign or notarize it.

The macOS release path should change to:

- sign the binary with `Developer ID Application`
- package it in a notarizable format
- notarize the artifact with `notarytool`
- staple if the chosen format supports stapling
- publish only after verification succeeds

### 2. Certificate And CI Secrets

Set up the following at minimum:

- Apple Developer account with Developer ID capability
- `Developer ID Application` certificate
- CI secret material for importing that certificate on GitHub-hosted macOS
  runners
- notarization credentials for `notarytool`

Recommended CI inputs:

- base64-encoded `.p12`
- certificate password
- Apple ID / app-specific password or App Store Connect API key credentials

### 3. Packaging Choice

For macOS, choose one of these and standardize it:

- signed ZIP containing the CLI binary
- signed PKG installer

Recommendation:

- use a signed ZIP first because it is a smaller change from the current
  archive-based updater model
- keep PKG as a later product/distribution improvement if needed

If the archive format changes for macOS, the updater’s artifact selection logic
must be updated accordingly.

### 4. Verification In CI

Before publishing the macOS artifact, CI should run:

- `codesign --verify --strict --verbose=2`
- `codesign -dv --verbose=4`
- `spctl -a -vv`

The release should fail if those checks fail.

## Logging And Diagnostics

The recent updater handoff logging should stay.

Required retained traces:

- self-update start/finish around the handoff boundary
- updater helper launch and PID information
- manifest path/version/install target
- scheduler reconcile decisions during post-update bootstrap
- explicit success/failure result for helper-driven install

This should remain in place even after the helper lands so future updater bugs
have better evidence than the current `cdhash mismatch` investigation did.

## Testing Plan

### Unit / Integration

Add tests for:

- manifest generation and parsing
- helper wait-for-parent behavior
- helper replacement behavior in a temp install directory
- helper bootstrap handoff on success/failure
- updater state persistence for helper-driven installs

### End-To-End Local Repro Harness

Add a dedicated local integration harness for the real update path:

- fake release feed with version N+1 artifacts
- installed binary at a realistic path
- monitor-owned unattended update invocation
- helper-driven swap into the real install path

This is the key regression test missing from the previous self-update work.

### Platform Coverage

Require end-to-end update-path coverage on:

- macOS
- Linux
- Windows

The harness does not need to assert identical OS logging, but it must assert:

- the updater detects the new version
- the old PID exits before swap
- the new binary is installed
- post-update bootstrap completes
- the scheduler remains healthy on platforms that use one

## Migration / Rollout

### Phase 1

- keep the `2.2.6` scheduler fix in place
- add the helper architecture without removing current diagnostics
- ship helper-driven update flow behind the existing update entry points

### Phase 2

- switch macOS release artifacts to signed/notarized output
- update updater asset-selection logic if artifact naming or format changes

### Phase 3

- consider a one-time recovery path for already-stranded clients whose monitor
  scheduler is missing and therefore cannot notice future releases

## Risks

- helper design adds complexity and another binary to distribute
- helper protocol must remain stable enough that an older Cadence can launch a
  newer install helper successfully
- macOS signing/notarization introduces certificate management and CI secret
  handling
- changing macOS artifact format can break updater asset selection if not rolled
  out carefully

## Recommended Commit Plan

1. plan document only
2. introduce updater manifest and helper executable skeleton
3. move manual `cadence update` to helper-driven install flow
4. move monitor-owned unattended update to the same helper flow
5. add macOS signing in CI
6. add macOS notarization and verification in CI
7. add end-to-end updater-path regression coverage and docs cleanup

Each checkpoint should leave the branch passing format, lint, and tests.
