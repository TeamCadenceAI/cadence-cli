## Project Overview

**AI Barometer** is a single Rust CLI binary that attaches AI coding agent session logs (Claude Code, Codex) to Git commits using **git notes** (ref: `refs/notes/ai-sessions`).
It provides provenance and measurement of AI-assisted development without polluting commit history.

## Build & Development Commands

```bash
cargo build                    # Debug build
cargo build --release          # Release build
cargo test                     # Run all tests
cargo test <test_name>         # Run a single test
cargo clippy                   # Lint
cargo fmt -- --check           # Check formatting
cargo fmt                      # Auto-format
```

## Dev Workflow

- Add tests to cover core functionality and to avoid regressions.
- Always run tests after changes.
- Always commit once tests are passing.
- Commit messages should be detailed so future readers can understand the full intent.
