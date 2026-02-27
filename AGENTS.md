## Project Overview

**Cadence CLI** is a single Rust CLI binary that attaches AI coding agent session logs (Claude Code, Codex) to Git commits using **git notes** (ref: `refs/notes/ai-sessions`).
It provides provenance and measurement of AI-assisted development without polluting commit history.

## Build & Development Commands

```bash
cargo build                    # Debug build
cargo build --release          # Release build
cargo test --no-fail-fast     # Run all tests (do not stop after first failure)
cargo nextest run              # Faster test runs (if installed)
cargo test <test_name>         # Run a single test
cargo clippy                   # Lint
cargo fmt -- --check           # Check formatting
cargo fmt                      # Auto-format
```

## Dev Workflow

- Add tests to cover core functionality and to avoid regressions.
- Run `cargo fmt` and `cargo clippy` before committing.
- Always run tests after changes.
- Always commit once tests are passing.
- Use Conventional Commits for every commit message (e.g., `feat(push): ...`, `fix(git): ...`, `docs(workflow): ...`).
- Commit messages should be detailed so future readers can understand the full intent.

## Rust CLI Best Practices

- Keep CLI UX explicit: use clear subcommands, flags, and help text.
- Prefer `anyhow` for top-level errors and add context to failures.
- Use deterministic, machine-readable output where possible.
- Be cross-platform: avoid hard-coded paths and use OS-aware defaults.
- Make destructive actions opt-in and clearly warn users.
- Keep startup fast; avoid heavy I/O unless required.
- Make configuration discoverable (env vars and `--help`).
- Keep hooks non-blocking unless a hard failure is intentional.
- Prefer small, focused modules with thorough tests.
- Use Tokio for production I/O (filesystem, network, subprocess, timers).
- Do not block the Tokio runtime; run CPU-bound or sync-only work with `tokio::task::spawn_blocking`.
