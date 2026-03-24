# Enterprise TLS Transport Plan

## Summary

This plan hardens Cadence CLI for enterprise networks that intercept TLS
traffic with a corporate root CA, such as Netskope or Zscaler.

The current CLI uses `reqwest` with Rustls web PKI roots. That works on normal
public networks, but it does not automatically trust corporate interception
certificates installed in the operating system trust store. As a result,
`cadence login` can succeed in the browser and still fail when the CLI itself
tries to call the Cadence API.

This plan changes the CLI transport layer so enterprise trust configuration
works consistently across login, upload, and update flows.

## Goals

- trust the native OS certificate store by default for CLI HTTPS traffic
- support an explicit PEM bundle override via `CADENCE_CA_BUNDLE`
- apply the same trust configuration to all Cadence-managed HTTP clients
- improve CLI guidance when TLS verification fails because of an untrusted
  issuer
- print the browser auth URL during login so users can copy it manually

## Non-Goals

- adding an insecure TLS bypass flag
- redesigning the login protocol or upload protocol
- adding full `doctor` TLS diagnostics in this change
- changing the local-only debug clients that intentionally disable TLS checks

## Scope

The change should cover:

- Cadence API calls used by login, logout, onboarding sync, org lookup, and
  session publication
- raw HTTPS calls made by the updater and release downloader
- login UX around the browser auth URL and targeted TLS failure guidance

## Implementation Plan

### 1. Switch To Native Rustls Roots

- change the `reqwest` feature set from `rustls-tls` to
  `rustls-tls-native-roots`
- keep `default-features = false`
- rely on native OS trust plus `SSL_CERT_FILE` support provided by
  `rustls-native-certs`

### 2. Centralize HTTP Client Construction

- add a shared transport helper module for production `reqwest::Client`
  construction
- move common trust configuration into that module
- route both the Cadence API client and updater/download clients through the
  same helper
- ensure the raw presigned-upload client receives the same trust settings

### 3. Add `CADENCE_CA_BUNDLE`

- support a Cadence-specific env var pointing to a PEM certificate bundle
- parse one-or-more certs from the PEM bundle and add them as extra root certs
- surface clear errors when the file is missing or cannot be parsed
- make the override apply consistently anywhere the CLI builds a production
  HTTPS client

### 4. Improve TLS-Aware Error Guidance

- detect trust failures such as `UnknownIssuer` in the top-level error chain
- print a targeted note describing the likely enterprise TLS interception case
- point users at native trust plus `CADENCE_CA_BUNDLE` and `SSL_CERT_FILE`

### 5. Print The Login Auth URL

- print the browser auth URL before attempting to launch the browser
- phrase it as a manual fallback rather than as the primary path

## Validation

- add unit coverage for CA bundle loading success and failure cases
- add unit coverage for TLS guidance detection
- preserve the existing login callback tests
- run:
  - `cargo fmt`
  - `cargo clippy`
  - `cargo test --no-fail-fast`

## Expected Outcome

After this change:

- enterprise users with a corporate CA trusted by macOS or Linux should be
  able to use the CLI without extra Cadence-specific setup
- users who have a PEM bundle but not system trust can point the CLI at
  `CADENCE_CA_BUNDLE`
- when trust is still wrong, the CLI should explain the likely reason instead
  of only surfacing a generic connect error
