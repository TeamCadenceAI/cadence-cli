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

---

## Phase 3 Review Triage

A code review was conducted after Phase 3 (16 findings). The following issues were triaged and addressed:

### Fixed

1. **Substring match false positives in `claude::log_dirs_in` (Review #1, Medium).** Changed from `name.contains(&encoded)` to `name == encoded` (exact match). The previous substring check would cause `/Users/foo/bar` (encoded as `-Users-foo-bar`) to false-positive match directories for `/Users/foo/bar-extra` (encoded as `-Users-foo-bar-extra`). Updated tests: renamed `test_log_dirs_finds_multiple_matching_directories` to `test_log_dirs_does_not_match_longer_paths` which verifies that longer encoded paths are not matched. Updated doc comments to reflect exact-match semantics.

2. **`DirEntry::metadata()` does not follow symlinks (Review #6, Medium).** Replaced `entry.metadata()` with `std::fs::metadata(entry.path())` in `candidate_files`. The `DirEntry::metadata()` method uses `lstat` on Unix which does not follow symlinks, causing symlinked `.jsonl` files to be skipped. The `std::fs::metadata()` function follows symlinks.

3. **Added hardcoded roundtrip test for Claude directory matching (Review #9, Medium).** Added `test_log_dirs_hardcoded_roundtrip` which uses a known hardcoded directory name (`-Users-dave-dev-my-project`) rather than computing it via `encode_repo_path`. This breaks the circularity where all other tests use `encode_repo_path` for both creating and searching for directories, meaning an encoding bug could go undetected.

### Deferred

- **Trailing slash handling (Review #2, Low):** Edge case, not blocking. `git rev-parse --show-toplevel` never returns trailing slashes.
- **`to_string_lossy` for non-UTF-8 paths (Review #3, Low):** Acceptable for v1. Repo paths from git are always UTF-8.
- **Sorting results by mtime (Review #10, Info):** Not required by design. Phase 4 scans for commit hash matches regardless of order.
- **Unix-only `home_dir` (Review #7, Low):** Project targets macOS/Linux only.
- **Codex `_repo_path` unused parameter (Review #8, Low):** Documented, kept for API symmetry.
- **`window_secs` negative value / `window_secs = 0` tests (Review #14, Low):** Harmless behavior (returns empty Vec). Can add edge case tests opportunistically.

### Test Count
- Total: 84 tests (was 83 before triage). Added 1 new test, renamed 1 test.

---

## Phase 4 Decisions

### Module Layout
- The scanner module is in `src/scanner.rs`, wired into the crate via `mod scanner;` in `main.rs`.
- Contains three main public functions (`find_session_for_commit`, `parse_session_metadata`, `verify_match`) and two public types (`SessionMatch`, `SessionMetadata`).

### Agent Type Inference
- Agent type is inferred from the file path rather than from log content. If the path contains `.codex`, it is classified as Codex; otherwise it defaults to Claude. This is simple, reliable, and avoids parsing overhead.
- The `AgentType` enum is defined in the scanner module (not in the agents module) because it is used primarily by scanner types. If other modules need it in the future, it can be moved to a shared location.
- `AgentType` implements `Display` to produce the note-format strings: `"claude-code"` and `"codex"`.

### Streaming Line-by-Line
- `find_session_for_commit` uses `BufReader` to stream files line-by-line. This is critical because session logs can be very large (tens of MB) and loading them entirely into memory would be wasteful, especially in the hot post-commit hook path.
- Lines that fail to read (I/O errors) are silently skipped, matching the defensive pattern used throughout the project.

### Substring Matching Strategy
- Both the full 40-character hash and the 7-character short hash are checked on every line.
- The full hash is checked first (more specific, less likely to false-positive), then the short hash.
- Stop-on-first-match: as soon as any line in any file matches, the function returns. This avoids scanning the rest of potentially large files.

### Metadata Parsing
- `parse_session_metadata` reads the file line-by-line, attempting to parse each line as JSON via `serde_json::Value`.
- Looks for multiple field name variants: `session_id`/`sessionId` for the session ID, and `cwd`/`workdir`/`working_directory` for the working directory.
- Fields are accumulated across lines (first value wins for each field). Once both `session_id` and `cwd` are found, parsing stops early.
- Invalid JSON lines are silently skipped. This is intentional since JSONL files may contain non-JSON lines or malformed entries.

### Verification
- `verify_match` performs two checks: (1) the metadata's cwd resolves to the same git repo root as the target repo, and (2) the commit exists in that repo.
- Uses `git -C <dir> rev-parse --show-toplevel` to resolve the repo root from the session's cwd. This handles the case where the cwd is a subdirectory of the repo.
- Uses `git -C <repo> cat-file -t <commit>` to verify commit existence. This is a lightweight check that doesn't require checking out the commit.
- Both paths are canonicalized before comparison to handle symlinks (e.g., on macOS where `/var` is a symlink to `/private/var`).
- The git helper functions (`repo_root_at`, `commit_exists_at`) are defined in `git.rs` as `pub(crate)` functions that accept a directory parameter. The scanner module calls these directly. This was refactored during the Phase 4 review triage (originally they were private duplicates in scanner.rs).

### Test Strategy
- 35 new tests added (total: 119).
- Tests cover:
  - Full hash matching, short hash matching, no match, stop-on-first-match, match in second file, empty candidates, nonexistent files.
  - Agent type inference from Claude and Codex paths, and unknown paths.
  - Metadata parsing: session_id, camelCase sessionId, cwd, workdir, working_directory, fields across multiple lines, invalid JSON lines, empty files, nonexistent files, first-value-wins semantics.
  - Verification: same repo, different repo, missing cwd, nonexistent cwd, nonexistent commit, cwd in subdirectory.
  - End-to-end: find + parse + verify workflow.
- Tests that need real git repos use the same `init_temp_repo` + `run_git` helper pattern established in Phase 2.
- The "partial hash no false positive" test verifies that a 6-character substring does not match a 7-character short hash, confirming the boundary behavior.

### Dead Code Warnings
- As with Phases 2 and 3, all new `pub` items generate "never used" warnings because they are not called from production code yet. These will resolve when Phase 6 wires up the hook handler.

---

## Phase 4 Review Triage

A code review was conducted after Phase 4 (21 findings across 8 sections). The review confirmed 121 tests passing, clippy clean (only expected dead-code warnings), and formatting clean.

### Fixed

1. **Doc comment on `parse_session_metadata` said "later values overwriting" but code uses first-value-wins (Review 2.1, Low).** Fixed the doc comment to say "first-value-wins semantics (once a field is found, later occurrences are ignored)." The code was correct; only the comment was wrong.

2. **Empty/short commit hash causes universal match in `find_session_for_commit` (Review 4.2, Medium).** Added input validation via `crate::git::validate_commit_hash` at the top of `find_session_for_commit`. If the hash fails validation (not 7-40 hex characters), returns `None` immediately. This prevents `line.contains("")` from returning `true` for every line. Added 2 new tests: `test_find_session_empty_hash_returns_none` and `test_find_session_short_hash_returns_none`.

3. **No input validation on commit hash in scanner entry points (Review 3.1, Medium).** Made `validate_commit_hash` in `git.rs` `pub(crate)` and called it from both `find_session_for_commit` and `verify_match`. This reuses the existing validation logic (7-40 hex characters) rather than duplicating it.

4. **Duplicated git helpers between scanner.rs and git.rs (Review 3.4, Medium).** Moved `git_repo_root_at` and `git_commit_exists_at` from `scanner.rs` to `git.rs` as `pub(crate)` functions named `repo_root_at` and `commit_exists_at`. The scanner module now calls `crate::git::repo_root_at` and `crate::git::commit_exists_at`. Removed unused imports (`anyhow`, `std::process::Command`) from scanner.rs production code; added `std::process::Command` to the test module where it is still needed.

### Deferred

- **Short hash false positive risk on hex-heavy log lines (Review 1.1):** Known limitation, mitigated by the verify step. The 7-character hex space (268M values) makes random collisions unlikely, and the verify step rejects most false positives.
- **Two-pass file I/O for match + metadata (Review 5.4):** Premature optimization; OS page cache makes the second pass fast.
- **Line limit for metadata parsing (Review 5.3):** Not critical for v1; metadata fields appear near the top of session logs in practice.
- **Move `AgentType` to shared location (Review 6.5):** Will address when Phase 5/6 need it.
- **No logging/tracing in scanner (Review 7.3):** Phase 6 hook handler should add logging around scanner calls.

### Test Count
- Total: 121 tests (was 119 before triage). Added 2 new tests for commit hash validation edge cases.

---

## Phase 5 Decisions

### Module Layout
- The note formatting module is in `src/note.rs`, wired into the crate via `mod note;` in `main.rs`.
- Contains two public functions (`format`, `payload_sha256`) and no public types.

### Note Format
- The note format follows the PLAN.md specification exactly: YAML-style header delimited by `---` on their own lines, with the verbatim session log appended after the closing delimiter.
- Header fields appear in a fixed order: `agent`, `session_id`, `repo`, `commit`, `confidence`, `payload_sha256`. This order matches the spec and ensures consistent, predictable output.
- The `confidence` field is hardcoded to `exact_hash_match` for now. The PLAN.md notes `commit_in_session: <optional>` as a potential header field, but it is not included in this phase since the format function's parameters do not yet carry that information. It can be added in a future phase if needed.

### SHA-256 Implementation
- Uses the `sha2` crate (already declared as a dependency in Phase 1's Cargo.toml) via `sha2::Sha256`.
- The hash is computed over the raw bytes of the session log payload (`content.as_bytes()`), producing a lowercase hex string (64 characters).
- The `payload_sha256` function is a separate public function (not just an internal helper) because it may be useful for verification in future phases (e.g., validating note integrity).

### Payload Handling
- The session log is appended verbatim after the closing `---\n` delimiter. No transformation, escaping, or truncation is applied. This ensures the payload in the note is bit-for-bit identical to the original session log file content that was passed in.
- Empty payloads are handled correctly: the note still has a valid header with the SHA-256 of the empty string, and the note ends with the closing `---\n`.

### Test Strategy
- 12 new tests added (total: 133).
- SHA-256 tests use well-known hash values (SHA-256 of "hello" and SHA-256 of empty string) to verify correctness against independent references.
- Format tests verify: exact structure via `splitn` parsing, header field order, empty payload, multiline payload, verbatim payload preservation, round-trip extraction (split note back into header + payload and verify SHA matches), and agent type variation (codex vs claude-code).

### Dead Code Warnings
- As with Phases 2-4, all new `pub` items generate "never used" warnings because they are not called from production code yet. These will resolve when Phase 6 wires up the hook handler.

---

## Phase 5 Review Triage

A code review was conducted after Phase 5 (12 findings). The review confirmed 133 tests passing, clippy clean (only expected dead-code warnings), and formatting clean.

### Fixed

1. **`agent` parameter now uses `AgentType` enum (Review #5, Medium).** Changed `note::format()` signature from `agent: &str` to `agent: &AgentType`, importing `crate::scanner::AgentType`. This provides type safety and eliminates the possibility of passing misspelled or unknown agent strings. The `Display` impl on `AgentType` is used automatically when formatting the header. All tests updated to pass `&AgentType::Claude` or `&AgentType::Codex` instead of string literals.

2. **Added test for payload containing `---` delimiter (Review #6, Medium).** New test `test_format_payload_containing_delimiter` uses a payload with `"line one\n---\nline two\n"` and verifies that `splitn(3, "---\n")` correctly extracts the payload and the SHA matches. This documents the expected parsing strategy and guards against regressions.

3. **Added doc comment noting `---` injection risk (Review #1, Medium).** Added a "Parsing caveat" section to the `format` function's doc comment explaining that payloads containing `---` on their own line will confuse naive parsers, and recommending `splitn(3, "---\n")` plus `payload_sha256` verification.

4. **Added commit hash validation in `format()` (Review #3, Medium).** The `format` function now calls `crate::git::validate_commit_hash(commit)?` at the top, rejecting invalid hashes early. The return type changed from `String` to `anyhow::Result<String>`. Added 3 new tests: `test_format_rejects_invalid_commit_hash`, `test_format_rejects_empty_commit_hash`, `test_format_rejects_short_commit_hash`.

### Deferred

- **Input validation on all parameters (Review #3, Medium):** Over-engineering for now. The `commit` parameter is the most important and is now validated. Other parameters (session_id, repo) come from trusted internal sources.
- **Renaming `format` function (Review #2, Low):** Works fine with module qualification (`note::format`). Not worth the churn.
- **Performance of string building (Review #4, Low):** Negligible for typical use. The header is ~200 bytes.
- **Special characters in header values (Review #7, Low):** Not a real concern for our use case. Session IDs and repo paths do not contain colons in practice.

### Test Count
- Total: 137 tests (was 133 before triage). Added 4 new tests (1 for `---` delimiter edge case, 3 for commit hash validation).

---

## Phase 6 Decisions

### Hook Handler Architecture
- The `run_hook_post_commit()` function uses a two-layer catch-all:
  1. **Panic guard:** `std::panic::catch_unwind` wraps the inner handler. Any panic is caught and logged to stderr.
  2. **Error guard:** The inner function `hook_post_commit_inner()` returns `anyhow::Result<()>`. Any error is caught by the outer function and logged to stderr.
- In both cases, the function returns `Ok(())` — the hook **never** fails the commit.
- All output uses the `[ai-barometer]` prefix on stderr.

### Inner Handler Flow
The `hook_post_commit_inner()` function follows the algorithm specified in PLAN.md:
1. Get `repo_root`, `head_hash`, `head_timestamp` from the git module.
2. **Deduplication check:** If a note already exists for HEAD (`git::note_exists`), exit early. This prevents duplicate work, rebase loops, and hydration collisions.
3. Collect candidate log directories from both `agents::claude::log_dirs` and `agents::codex::log_dirs`.
4. Filter candidate files by the ±600 second (10 minute) time window using `agents::candidate_files`.
5. Run `scanner::find_session_for_commit` to find a session match.
6. If matched: parse metadata, verify match against repo root, read the full session log, format the note, and attach it via `git::add_note`.
7. If not matched (or verification fails): write a pending record via `pending::write_pending`.
8. After resolving the current commit: run `retry_pending_for_repo` to attempt resolution of all pending commits for this repo.

### Pending Module (Stub)
- Created `src/pending.rs` with the minimal functions needed by the hook handler: `write_pending`, `list_for_repo`, `remove`, `pending_dir`.
- The stub writes real JSON files to `~/.ai-barometer/pending/<commit-hash>.json`, so the pending system works end-to-end even before Phase 7 fleshes out the full retry logic.
- `PendingRecord` struct holds: commit, repo, commit_time, attempts, last_attempt.

### Retry Logic (Stub)
- `retry_pending_for_repo` iterates over all pending records for the repo, attempts resolution for each, and removes records on success.
- This is a best-effort operation — errors during retry are silently ignored.
- Phase 7 will implement the full retry system with proper increment/backoff.

### Push Logic
- Push is stubbed out. Phase 8 will implement the consent check, org filter, and actual push.

### macOS Path Symlink Handling
- On macOS, `TempDir::new()` returns paths under `/var/folders/...` but the actual filesystem path is `/private/var/folders/...`. `git rev-parse --show-toplevel` returns the `/private` variant. This caused mismatches in integration tests between the path used to create the session log directory (via `encode_repo_path(dir.path())`) and the path the hook computes (via `encode_repo_path(repo_root())`).
- The fix in tests: use `git rev-parse --show-toplevel` to get the canonical repo root, then use that for both creating the fake session log directory and for the session metadata's `cwd` field.

### CWD Safety in Serial Tests
- Serial tests that call `set_current_dir` can leave the process CWD in a deleted temp directory if an assertion panics before CWD is restored. Subsequent serial tests then fail on `current_dir()`.
- Added a `safe_cwd()` helper that falls back to `std::env::temp_dir()` if the current directory is invalid. All serial tests use `safe_cwd()` instead of `current_dir().expect(...)`.

### Dead Code Warnings
- Most dead code warnings from Phases 2-5 are now resolved since `run_hook_post_commit` calls into `git`, `agents`, `scanner`, and `note` modules.
- Remaining dead code warnings: `push_notes`, `has_upstream`, `remote_org`, `parse_org_from_url`, `config_get`, `config_set` (all Phase 8 concerns), `matched_line` on `SessionMatch` (may be used in future phases), and some `PendingRecord` fields.

### Test Count
- Total: 142 tests (was 137 before Phase 6). Added 5 new tests:
  - `test_hook_post_commit_attaches_note_to_commit`: full integration test with a temp repo and fake Claude session log.
  - `test_hook_post_commit_deduplication_skips_if_note_exists`: verifies existing notes are not overwritten.
  - `test_hook_post_commit_no_match_writes_pending`: verifies pending records are written when no session match is found.
  - `test_hook_post_commit_never_fails_outside_git_repo`: verifies the catch-all wrapper.
  - `test_pending_record_struct`: basic struct construction test for `PendingRecord`.

---

## Phase 6 Review Triage

A code review was conducted after Phase 6 (16 findings: 0 critical, 3 medium, 6 low, 7 informational). The review confirmed 142 tests passing, clippy clean (expected dead-code warnings only), and formatting clean. No commit-blocking bugs were found.

### Fixed

1. **`unwrap_or_default()` on `read_to_string` silently produces empty note (Review 3.3, Medium).** Changed both occurrences of `std::fs::read_to_string(&matched.file_path).unwrap_or_default()` in `src/main.rs` (main path and retry path). The main path now uses a `match` that logs a warning, writes a pending record, and returns early on read failure -- so the file can be retried later instead of attaching a note with an empty payload. The retry path uses `match` with `continue` on failure, so it skips to the next pending record.

2. **Integration tests pollute real `~/.claude` and `~/.ai-barometer` (Review 4.5, Low).** The `test_hook_post_commit_attaches_note_to_commit` and `test_hook_post_commit_no_match_writes_pending` tests now create a separate `TempDir` as a fake HOME, redirect `$HOME` to it via `unsafe { std::env::set_var("HOME", ...) }` (safe because tests are `#[serial]`), and restore `$HOME` afterward. All fake `.claude/projects/` directories and `.ai-barometer/pending/` files are now fully contained in temp directories that auto-clean on drop.

3. **`PendingRecord` lacks serde derives (Review 5.2, Low).** Added `#[derive(Serialize, Deserialize)]` to `PendingRecord` in `src/pending.rs`, with `use serde::{Deserialize, Serialize};`. This enables direct `serde_json::from_str::<PendingRecord>()` deserialization in Phase 7 instead of manual `serde_json::Value` field extraction.

### Deferred

- **`read_to_string` loads full session log into memory (Review 3.2, Medium):** Phase 12 hardening concern. Future mitigation: use `git notes add -F <file>` with a temp file to avoid both memory pressure and `arg_max` limits.
- **Retry uses same 600-second window for pending commits (Review 2.2, Low):** Phase 7 will implement proper retry logic with widened windows or full directory scans.
- **Retry does not increment attempt counter (Review 2.3, Info):** Phase 7 responsibility.
- **Redundant hash validation (Review 3.4, Low):** Defense-in-depth, intentional. No action needed.
- **Missing test for verify_match failure -> pending path (Review 4.2, Low):** Nice to have but not blocking.
- **Missing test for retry resolving a pending commit (Review 4.3, Low):** Phase 7 responsibility.

### Test Count
- Total: 142 tests (unchanged). No new tests added; existing tests were improved for isolation.

---

## Phase 7 Decisions

### Pending Module: Full Implementation
- The `src/pending.rs` stub from Phase 6 was fully fleshed out with production-quality implementations of all five public functions: `pending_dir`, `write_pending`, `list_for_repo`, `increment`, and `remove`.
- The `PendingRecord` struct and its `Serialize`/`Deserialize` derives were preserved from the Phase 6 stub.

### Testability Pattern: Internal `_in` Functions
- Each public function has a corresponding internal `_in` variant that accepts a directory parameter: `pending_dir_in(home)`, `write_pending_in(dir, ...)`, `list_for_repo_in(dir, ...)`, `increment_in(dir, ...)`, `remove_in(dir, ...)`.
- Tests call the `_in` variants directly with `TempDir` paths, avoiding manipulation of the `$HOME` environment variable and enabling parallel execution without `#[serial]`.
- This mirrors the testability pattern established in Phase 3 (agents module) where `log_dirs_in` accepts a home directory parameter.

### Atomic Writes
- All file writes (both `write_pending` and `increment`) use the write-to-temp-then-rename pattern: data is first written to `<commit-hash>.json.tmp`, then `std::fs::rename` atomically replaces the final `<commit-hash>.json`. This prevents concurrent post-commit hooks from reading a half-written file.
- `std::fs::rename` is atomic on POSIX filesystems when source and destination are on the same filesystem, which is guaranteed since both files are in the same pending directory.

### Deserialization: Direct `serde_json::from_str::<PendingRecord>`
- The Phase 6 stub used `serde_json::Value` with manual field extraction. The full implementation deserializes directly to `PendingRecord` via `serde_json::from_str::<PendingRecord>()`. This is cleaner, type-safe, and validates the JSON structure automatically. Files that don't match the expected structure are silently skipped.

### Retry Time Window: 24 Hours
- The Phase 6 retry used the same 600-second (10-minute) window as the initial hook, which was too narrow for pending commits that could be hours or days old.
- Phase 7 widened the retry window to 86,400 seconds (24 hours). This gives session log files much more time to land on disk after the commit was created. The tradeoff is scanning more candidate files, but this is acceptable since retry is best-effort and runs in the background of each hook invocation.

### Retry: Increment on Failure
- The Phase 6 retry stub did not increment the attempt counter on failure. Phase 7 adds `pending::increment(record)` calls in all failure paths: no session match found, verification failed, file unreadable, note format error, and note add error.
- This ensures the attempt counter accurately reflects how many times resolution was attempted, which is useful for debugging and for potential future backoff policies.

### `run_retry` Subcommand
- The `run_retry` stub was upgraded to a working implementation that calls `git::repo_root()` to determine the current repository, counts pending records, runs `retry_pending_for_repo`, and prints a summary of how many records were resolved vs still pending.

### Dead Code Warnings
- The same dead code warnings from previous phases remain: `push_notes`, `has_upstream`, `remote_org`, `parse_org_from_url`, `config_get`, `config_set` (Phase 8 functions), and `matched_line` on `SessionMatch`.

### Deferred Phase 6 Review Items Resolved
- **Retry uses same 600-second window (Review 2.2):** Resolved. Now uses 86,400-second window.
- **Retry does not increment attempt counter (Review 2.3):** Resolved. All failure paths call `pending::increment`.
- **Missing test for retry resolving a pending commit (Review 4.3):** Resolved. Added `test_retry_resolves_pending_commit` integration test.

### Test Count
- Total: 166 tests (was 142 before Phase 7). Added 24 new tests:
  - **Pending module (19 tests):** `test_pending_record_serialize_deserialize`, `test_pending_dir_in_creates_directory`, `test_pending_dir_in_idempotent`, `test_write_pending_creates_json_file`, `test_write_pending_no_temp_file_left`, `test_write_pending_overwrites_existing`, `test_list_for_repo_empty_dir`, `test_list_for_repo_filters_by_repo`, `test_list_for_repo_no_matching_repo`, `test_list_for_repo_skips_non_json_files`, `test_list_for_repo_skips_invalid_json`, `test_list_for_repo_nonexistent_dir`, `test_increment_bumps_attempts`, `test_increment_multiple_times`, `test_increment_preserves_other_fields`, `test_remove_deletes_file`, `test_remove_idempotent`, `test_remove_only_removes_target`, `test_write_list_remove_roundtrip`, `test_write_increment_list_roundtrip`, `test_current_unix_timestamp_is_reasonable`.
  - **Integration tests (3 tests):** `test_retry_resolves_pending_commit`, `test_retry_increments_attempt_on_failure`, `test_run_retry_in_repo`.

---

## Phase 7 Review Triage

A code review was conducted after Phase 7 (28 findings: 0 critical, 2 medium, 10 low, 16 informational). The review confirmed 166 tests passing, clippy clean (expected dead-code warnings only), and formatting clean. No critical or commit-blocking bugs were found.

### Fixed

1. **Test for `increment` on nonexistent file (Review 6.3, Low).** Added `test_increment_on_nonexistent_file_creates_it` which calls `increment_in` with a `PendingRecord` whose file was never written to disk. Verifies that `increment` handles this gracefully (creates the file rather than panicking) and that the in-memory record and on-disk file both reflect the incremented state.

2. **Orphaned `.json.tmp` cleanup in `list_for_repo_in` (Review 1.2, Low).** Added cleanup logic in `list_for_repo_in` that deletes any `.json.tmp` files encountered during directory iteration. These files indicate crashed writes (the process died between `std::fs::write` to the temp file and `std::fs::rename` to the final path). The cleanup uses `let _ = std::fs::remove_file(...)` so a failed cleanup (e.g., permissions) does not affect the listing operation. Added `test_list_for_repo_cleans_up_orphaned_tmp_files` and updated the existing `test_list_for_repo_skips_non_json_files` to verify cleanup behavior.

3. **Doc comment on `list_for_repo` noting canonical path requirement (Review 3.1, Medium).** Added documentation that the `repo` parameter must be a canonical absolute path as returned by `git rev-parse --show-toplevel`, and that filtering uses exact string equality. This documents the known limitation where symlinked or non-canonical paths would fail to match.

### Deferred to Phase 12

- **Maximum retry count (Review 4.7, Low):** A pending record for an unresolvable commit will be retried forever. Phase 12 should add a max attempt count (e.g., remove after 100 attempts or 30 days).
- **Schema versioning on `PendingRecord` (Review 2.2, Low):** No version field on the struct. Future phases that add fields should use `#[serde(default)]` to maintain backward compatibility.
- **fsync before rename (Review 1.3, Low):** Acceptable tradeoff for a best-effort pending system. Power failure could theoretically lose a pending record.
- **Concurrent write testing (Review 6.2, Low):** No test for truly concurrent `write_pending` calls. Atomic rename ensures safety, so this is low risk.

### Test Count
- Total: 168 tests (was 166 before triage). Added 2 new tests: `test_increment_on_nonexistent_file_creates_it`, `test_list_for_repo_cleans_up_orphaned_tmp_files`.
