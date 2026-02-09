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

---

## Phase 2 Review Triage

A code review was conducted after Phase 2 (21 findings). The following issues were triaged and addressed:

### Fixed

1. **Commit hash input validation (Review #4, Medium).** Added `validate_commit_hash()` that rejects anything not matching 7-40 hex characters. Called from `note_exists` and `add_note`. Also added `--` separator before positional commit args in git commands to prevent flag injection (e.g., `--help` being interpreted as a git flag). Even though `std::process::Command` prevents shell injection, flag injection was still a risk.

2. **`add_note` precondition documented (Review #1, Medium).** Added a doc comment to `add_note` warning that callers must check `note_exists` first. The PLAN.md deduplication rules require checking before attaching. Did not add `--force` since the caller contract is sufficient and matches the plan's "check then skip" pattern.

3. **`config_get` now distinguishes exit code 1 vs other errors (Review #2, Low).** Previously, all non-zero exits from `git config --get` were treated as "key not set" (`Ok(None)`). Now only exit code 1 returns `Ok(None)`; any other non-zero exit (e.g., code 2 for corrupt config) returns `Err` with the stderr message.

4. **`has_upstream` returns `Ok(false)` on failure (Review #3, Low).** Changed from propagating `git remote` errors to returning `Ok(false)` when the command fails. This matches the `git_succeeds` defensive pattern and makes the function safe to call outside a git repository.

5. **Public API tests via `set_current_dir` (Review #13-14, Medium).** Added 11 serial tests that call the actual Rust wrapper functions (`repo_root`, `head_hash`, `head_timestamp`, `note_exists`, `add_note`, `has_upstream`, `remote_org`, `config_get`, `config_set`) against temp repos using `std::env::set_current_dir`. These use the `serial_test` crate to avoid CWD race conditions. This directly validates the wrapper logic (argument order, `.trim()`, error mapping), not just the underlying git commands.

6. **Edge case tests for `parse_org_from_url` (Review #17, Low).** Added 6 new test cases: trailing slash, host-only URL, host without trailing slash, SSH with nested paths, HTTPS with port, and HTTPS with embedded auth credentials.

7. **`validate_commit_hash` unit tests.** Added 7 tests covering valid short/full hashes and rejection of: flag injection (`--help`), too-short, non-hex, empty, and too-long strings.

8. **`remote_org` Phase 8 note (Review #9/20).** Added a doc comment on `remote_org` noting that it only inspects the first remote and that Phase 8 will need to check all remotes per the PLAN.md requirement.

### Deferred

- **SSH URL parsing edge cases (Review #6-7):** `ssh://` protocol, non-`git@` users, and ports in SSH URLs. Will address in Phase 8 when org filtering is implemented.
- **`push_notes` testing (Review #15):** Requires a remote, complex setup. Not worth the test infrastructure cost right now.
- **`remote_org` checking all remotes (Review #9/20):** Phase 8 responsibility.
- **`config_set` legacy git invocation (Review #12):** The `git config key value` form works and is widely supported. Not urgent.
- **`add_note`/`push_notes` using `git_output` pattern (Review #11):** Minor refactoring opportunity, low value.
- **`git_output_in` test helper duplication (Review #18):** Acknowledged but not worth the refactor since the helper is small and test-only.
- **Config key validation (Review #5):** Low risk since callers are internal and use well-known key names.

### Dev-Dependencies Added
- `serial_test = "3"` for serializing tests that use `set_current_dir`.

---

## Phase 3 Decisions

### Module Layout
- The agents module uses a directory structure: `src/agents/mod.rs`, `src/agents/claude.rs`, `src/agents/codex.rs`. This keeps the agent-specific logic isolated and allows each agent to be extended independently in future phases.
- Wired into the crate via `mod agents;` in `main.rs`.

### Testability Pattern: Internal Functions with Home Parameter
- The `claude::log_dirs` and `codex::log_dirs` public functions resolve the home directory via `home_dir()` (which reads `$HOME`), then delegate to internal `log_dirs_in` functions that accept a `home: &Path` parameter.
- Tests call the `_in` variants directly with a temp directory, avoiding the need to modify environment variables. This is important because Rust 2024 edition makes `std::env::set_var` and `std::env::remove_var` **unsafe** (they can cause data races in multi-threaded programs). Rather than wrapping env var mutations in `unsafe` blocks, the testability-via-parameter approach is cleaner and avoids the issue entirely.
- This pattern could be generalized to a `Config` or `Context` struct in a later phase if needed, but for now the simple function parameter is sufficient.

### File Mtime in Tests
- Initially used `touch -t` with `chrono` to format timestamps, but this produced incorrect results because `chrono::DateTime::from_timestamp` creates UTC datetimes while macOS `touch -t` interprets timestamps in local time. The timezone offset caused mtime to be set to the wrong epoch value.
- Switched to the `filetime` crate (added as dev-dependency `filetime = "0.2"`) which correctly sets file mtimes using the Unix epoch directly via `utimensat`/equivalent syscalls. This is cross-platform and timezone-safe.

### encode_repo_path
- Simple string replacement: every `/` becomes `-`. The leading `/` in an absolute path becomes a leading `-`.
- This matches the Claude Code convention observed in `~/.claude/projects/` directory names.
- No special handling for relative paths, trailing slashes, or non-UTF-8 paths. These are not expected in practice (repo paths from `git rev-parse --show-toplevel` are always absolute and UTF-8).

### candidate_files
- Filters by file extension (`.jsonl`), file type (regular file, not directory), and modification time window.
- Uses `abs(file_mtime - commit_time) <= window_secs` as specified.
- Silently skips files with unreadable metadata or mtimes before the Unix epoch. This matches the design principle that errors in the hook path should be non-fatal.

### Codex log_dirs API
- The `codex::log_dirs` function accepts a `_repo_path` parameter for API symmetry with `claude::log_dirs`, but does not use it for filtering. Codex sessions are not scoped to a repo path in the filesystem. The caller (Phase 6's post-commit handler) will filter by time window and content.

### Dead Code Warnings
- As with Phase 2, all new `pub fn` items generate "never used" warnings because they are not called from `main.rs` yet. These will resolve when Phase 6 wires up the hook handler.

### Dev-Dependencies Added
- `filetime = "0.2"` for setting file modification times in tests.
