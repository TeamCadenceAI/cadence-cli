# Implementation Notes

Notes for future subagents working on subsequent phases.

---

## Phase 1 Decisions

### Rust Edition
- The project uses Rust edition 2024 (set by `cargo init` on Rust 1.91.1). This is the latest edition and requires a recent toolchain.

### CLI Structure
- The CLI uses `clap` derive API with a top-level `Cli` struct containing a `Command` enum.
- The `hook` subcommand uses nested subcommands via a separate `HookCommand` enum. This means invocation is `ai-barometer hook post-commit` which matches the plan's hook shim: `exec ai-barometer hook post-commit`.
- Each subcommand dispatches to a standalone `run_*` function that returns `anyhow::Result<()>`. This keeps the dispatch in `main()` clean and allows each handler to use `?` freely.
- `main()` catches all errors and prints them to stderr with the `[ai-barometer]` prefix, then exits with code 1. This ensures the binary never panics on user-facing errors.

### Error Handling
- Using `anyhow::Result` for all fallible functions. Switched from `Box<dyn std::error::Error>` during the Phase 1 review triage because it was early enough to make the change cheaply. `anyhow` provides better error context (via `.context()`) and is the idiomatic choice for application-level error handling in Rust. If we later need structured error types for specific modules, we can introduce `thiserror` enums that work with `anyhow`.

### Dependencies Included But Not Yet Used
- `serde`, `serde_json`, `sha2`, and `chrono` are declared in Cargo.toml but not imported in main.rs yet. This is intentional -- they are needed starting in Phase 2+. Clippy does not warn about unused crate dependencies.

### Test Strategy
- Tests use `Cli::parse_from()` to verify CLI parsing without spawning a subprocess. This is fast and avoids PATH issues.
- Each `run_*` function has a basic "returns Ok" smoke test. These will evolve into real integration tests as logic is added.

### File Layout
- All code is currently in `src/main.rs`. As Phase 2+ adds modules (git utilities, agent discovery, scanner, etc.), these should be extracted into separate files under `src/` (e.g., `src/git.rs`, `src/agents.rs`, `src/scanner.rs`, `src/note.rs`, `src/pending.rs`).

---

## Phase 1 Review Triage

A code review was conducted after Phase 1. The review found no bugs and confirmed all TODO items were complete. The following issues were triaged and addressed:

### Fixed
1. **Removed redundant `default_value_t = false`** on the `push` bool flag in the `Hydrate` variant. Clap already defaults bool flags to `false`.
2. **Switched to `anyhow` for error handling.** Replaced `Box<dyn std::error::Error>` with `anyhow::Result` throughout. This was cheap to do now with minimal code, and `anyhow` is the standard choice for Rust application error handling.
3. **Added negative CLI parsing tests.** Four new tests using `Cli::try_parse_from()` verify that clap correctly rejects: unknown subcommands, `hook` with no sub-subcommand, `--since` with a missing value, and no subcommand at all.

### Deferred
- **`assert_cmd` integration test:** Deferred to a later phase. Not needed while all logic is in stubs.
- **Edition 2024 downgrade:** Not needed. The edition is fine for this project.
- **`chrono` serde feature review:** Will revisit when timestamps are actually used (Phase 4+).

---

## Phase 2 Decisions

### Module Layout
- The git utilities module is in `src/git.rs`, wired into the crate via `mod git;` in `main.rs`.
- All functions are `pub` so they can be called from other modules (e.g. the hook handler in Phase 6, the push logic in Phase 8).

### Git Command Execution Pattern
- Two internal helpers encapsulate all git subprocess calls:
  - `git_output(args)` — runs git, returns trimmed stdout on success, returns `Err` on non-zero exit. Used for commands where we need the output (rev-parse, config --get, etc.).
  - `git_succeeds(args)` — runs git, returns `bool` for exit code. Suppresses stdout/stderr. Used for existence checks (note_exists) where a non-zero exit is an expected "no" answer, not an error.
- All commands use `std::process::Command` with `.output()` or `.status()`. No shell invocation.

### Error Handling
- All public functions return `anyhow::Result<T>`, consistent with Phase 1.
- `config_get` returns `Ok(None)` for missing keys (exit code 1 from `git config --get` is expected, not an error).
- `note_exists` returns `Ok(false)` when the note doesn't exist, using `git_succeeds` to treat non-zero exit as a boolean false rather than an error.

### URL Parsing (remote_org)
- `parse_org_from_url` is extracted as a pure function for easy unit testing without needing a git repo.
- Supports SSH (`git@host:org/repo.git`) and HTTPS/HTTP (`https://host/org/repo.git`) URL formats.
- Returns `None` for unrecognized formats rather than erroring. This is intentional — callers should handle the "no org found" case gracefully.
- `remote_org()` reads the first configured remote's URL. If a repo has multiple remotes, only the first is inspected. This is sufficient for the org filter use case.

### Notes Ref
- The notes ref `refs/notes/ai-sessions` is defined as a module-level constant `NOTES_REF` to avoid string duplication and ensure consistency.

### Test Strategy
- Integration tests create real temp git repos using the `tempfile` crate (added as a dev-dependency).
- Because test threads run in parallel and `std::env::set_current_dir` is process-global, tests do NOT change the working directory. Instead, they shell out to git with `git -C <path>` to run commands in the temp repo.
- The public functions (`repo_root`, `head_hash`, etc.) rely on the process cwd, so tests validate the underlying git operations via direct `git -C` commands rather than calling the public API directly. This is intentional — it avoids test interference while still validating the git operations work correctly. When these functions are used in production, the process cwd will be inside the target repo (set by the hook entry point).
- The `parse_org_from_url` function is tested as a pure function since it has no git dependency.

### Dead Code Warnings
- Clippy and the compiler emit "never used" warnings for all `pub fn` items in `git.rs` because nothing in `main.rs` calls them yet. This is expected and will resolve once Phase 6+ wires up the hook handler. No `#[allow(dead_code)]` annotations were added — the warnings serve as a reminder of incomplete integration.

### Dev-Dependencies
- Added `tempfile = "3"` as a dev-dependency for test temp directories. It is only compiled for `cargo test`.
