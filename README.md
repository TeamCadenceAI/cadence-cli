# Cadence CLI

Cadence CLI ingests AI coding agent sessions into Git-native refs for provenance and backend analysis.

## Storage Model

Cadence uses three refs:

- `refs/cadence/sessions/data`
  - Canonical encrypted session objects (`frontmatter + session content`) stored as blobs.
- `refs/cadence/sessions/index/branch`
  - Branch-scoped NDJSON index entries pointing to canonical session blobs.
- `refs/cadence/sessions/index/committer`
  - Committer-scoped NDJSON index entries pointing to canonical session blobs.

This is a hard cutover architecture. Legacy git-notes storage is no longer used by active workflows.

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

## Quick Start

1. Install hooks:
```sh
cadence install
```

2. Commit normally. Cadence will ingest matched AI session data into session refs.

3. Push as usual. Pre-push syncs session refs with the selected remote.

4. Diagnose install issues:
```sh
cadence doctor
```

## Supported Agents

- Claude Code
- Codex
- Cursor
- GitHub Copilot
- Antigravity

## Encryption

To encrypt session objects for local + API recipients:
```sh
cadence keys setup
```

Cadence uses built-in OpenPGP (Rust). Canonical session objects are stored as `zstd + pgp` binary when encryption is enabled.

## Uninstall

- Remove hooks:
```sh
git config --global --unset core.hooksPath
rm -rf ~/.git-hooks
```

- Remove the binary from your PATH (for example `~/.local/bin/cadence`).

## License

See `LICENSE.md`.
