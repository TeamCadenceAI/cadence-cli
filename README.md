# Cadence CLI

Cadence CLI stores AI coding agent session logs in dedicated Git refs:
- `refs/cadence/sessions/data`
- `refs/cadence/sessions/index/branch`
- `refs/cadence/sessions/index/committer`
It adds provenance for AI-assisted development without altering your commit history.

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

## Quick Start

1. Install hooks:
```sh
cadence install
```

2. Make commits as usual.

3. Inspect session refs:
```sh
git show-ref refs/cadence/sessions/data
```

4. Diagnose install issues (hooks, rewrite safety):
```sh
cadence doctor
```

## How It Works

Cadence installs global Git hooks that scan for recent AI session logs, then stores canonical session objects and indexes after each commit.
It also configures Git note rewrite settings so notes follow rewritten commits during rebase/amend.
Notes can be synced alongside commits without modifying commit history.

If a repository still has the legacy ref `refs/notes/ai-sessions`, Cadence will migrate it to
`refs/cadence/sessions/data` when new session data is ingested.

## Supported Agents

- Claude Code
- Codex
- Cursor
- GitHub Copilot
- Antigravity
- Warp

Note: Warp stores sessions in a local SQLite database. In some local-only cases the
assistant output may be missing, so Cadence stores prompts/context without responses.

## Optional: Encryption

To encrypt session logs before attaching (local + API recipients):
```sh
cadence keys setup
```

Cadence uses built-in OpenPGP (Rust) and stores an encrypted private key in `~/.cadence/cli/`.
The passphrase is stored in your OS keychain.

## Uninstall

- Remove hooks:
```sh
git config --global --unset core.hooksPath
rm -rf ~/.git-hooks
```

- Remove the binary from your PATH (for example `~/.local/bin/cadence`).

## License

See `LICENSE.md`.
