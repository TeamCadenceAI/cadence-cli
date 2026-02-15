# Cadence CLI

Cadence CLI attaches AI coding agent session logs to Git commits using git notes (ref: `refs/notes/ai-sessions`).
It adds provenance for AI-assisted development without altering your commit history.

## Install

Prerequisites:
- Git
- GPG is optional for encryption

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

3. View the attached session note:
```sh
git notes --ref refs/notes/ai-sessions show HEAD
```

## How It Works

Cadence installs global Git hooks that scan for recent AI session logs, then attaches matching logs as Git notes after each commit.
Notes can be synced alongside commits without modifying commit history.

## Supported Agents

- Claude Code
- Codex
- Cursor
- GitHub Copilot
- Antigravity

## Optional: GPG Encryption

To encrypt session logs before attaching:
```sh
cadence gpg setup
```

GPG install hints:
- macOS: `brew install gnupg`
- Linux: use your distro's package manager
- Windows: `winget install GnuPG.GnuPG`

## Uninstall

- Remove hooks:
```sh
git config --global --unset core.hooksPath
rm -rf ~/.git-hooks
```

- Remove the binary from your PATH (for example `~/.local/bin/cadence`).

## License

See `LICENSE.md`.
