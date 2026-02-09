# TODO — AI Barometer Implementation Plan

Ordered by dependency. Complete each phase before starting the next.

---

## Phase 1: Project Scaffolding

- [x] `cargo init` with binary target, set package name to `ai-barometer`
- [x] Add dependencies: `clap` (CLI parsing), `serde` + `serde_json` (JSON), `sha2` (SHA-256), `chrono` (timestamps)
- [x] Set up CLI skeleton with `clap` derive API — subcommands: `install`, `hook` (with sub `post-commit`), `hydrate`, `retry`, `status`
- [x] Add top-level error handling: all subcommands return `Result`, main catches and prints errors without panicking
- [x] Add `#[cfg(test)]` test module scaffolding

---

## Phase 2: Git Utilities Module

Shared helpers that multiple subcommands depend on.

- [x] `git::repo_root()` — run `git rev-parse --show-toplevel`, return `PathBuf`
- [x] `git::head_hash()` — run `git rev-parse HEAD`, return full 40-char hash
- [x] `git::head_timestamp()` — run `git show -s --format=%ct HEAD`, return `i64` unix timestamp
- [x] `git::note_exists(commit: &str)` — run `git notes --ref=refs/notes/ai-sessions show <commit>`, return `bool`
- [x] `git::add_note(commit: &str, content: &str)` — run `git notes --ref=refs/notes/ai-sessions add -m <content> <commit>`
- [x] `git::push_notes()` — run `git push origin refs/notes/ai-sessions`
- [x] `git::has_upstream()` — check if repo has a configured remote
- [x] `git::remote_org()` — extract owner/org from remote URLs
- [x] `git::config_get(key: &str)` — read a git config value
- [x] `git::config_set(key: &str, value: &str)` — write a git config value
- [x] Unit tests: mock or integration-test each helper against a temp git repo

---

## Phase 3: Agent Log Discovery Module

- [x] `agents::encode_repo_path(path: &Path) -> String` — encode `/Users/foo/bar` → `-Users-foo-bar`
- [x] `agents::claude::log_dirs(repo_path: &Path) -> Vec<PathBuf>` — glob `~/.claude/projects/*<encoded-repo>*`
- [x] `agents::codex::log_dirs(repo_path: &Path) -> Vec<PathBuf>` — glob `~/.codex/sessions/*`
- [x] `agents::candidate_files(dirs: &[PathBuf], commit_time: i64, window_secs: i64) -> Vec<PathBuf>` — filter `.jsonl` files with mtime within ±window of commit time
- [x] Unit tests: create temp dirs with fake JSONL files, verify filtering by mtime and path encoding

---

## Phase 4: Session Scanning & Correlation

- [x] `scanner::find_session_for_commit(commit_hash: &str, candidate_files: &[PathBuf]) -> Option<SessionMatch>` — stream each file line-by-line, substring match for full hash and short hash (first 7 chars), stop on first match
- [x] `scanner::SessionMatch` struct — fields: `file_path`, `matched_line`, `agent_type`
- [x] `scanner::parse_session_metadata(file: &Path) -> SessionMetadata` — parse minimal JSON fields: `session_id`, `cwd`/`workdir`, `agent_type`
- [x] `scanner::verify_match(metadata: &SessionMetadata, repo_root: &Path, commit: &str) -> bool` — confirm cwd resolves to same git repo, commit exists in repo
- [x] Unit tests: fake JSONL files with embedded commit hashes, verify match/no-match

---

## Phase 5: Note Formatting

- [x] `note::format(agent: &str, session_id: &str, repo: &str, commit: &str, session_log: &str) -> String` — produce the full note with YAML-style header + verbatim JSONL payload
- [x] `note::payload_sha256(content: &str) -> String` — SHA-256 of the session log payload
- [x] Unit tests: verify note format matches spec, verify SHA-256 is correct

---

## Phase 6: `hook post-commit` Subcommand

This is the critical hot path. Must be fast and never fail the commit.

- [x] Wrap entire handler in catch-all: any error → log warning to stderr, exit 0
- [x] Get repo root, HEAD hash, HEAD timestamp
- [x] Check deduplication: if note already exists for HEAD, exit early
- [x] Get candidate log dirs (Claude + Codex) for this repo
- [x] Get candidate files filtered by ±10 min window
- [x] Run scanner to find session match
- [x] If matched: format note, attach via `git notes add`, attempt push (with consent check)
- [x] If not matched: write pending record (see Phase 7)
- [x] After resolving current commit: run retry for all pending commits in this repo
- [x] Integration test: set up temp repo, create fake session log, run commit, verify note attached

---

## Phase 7: Pending Retry System

- [x] `pending::pending_dir() -> PathBuf` — return `~/.ai-barometer/pending/`, create if missing
- [x] `pending::write(commit: &str, repo: &str, commit_time: i64)` — write `<commit-hash>.json` with fields: commit, repo, commit_time, attempts (1), last_attempt (now)
- [x] `pending::list_for_repo(repo: &str) -> Vec<PendingRecord>` — read all pending JSON files, filter by repo path
- [x] `pending::increment(record: &mut PendingRecord)` — bump attempts + last_attempt, rewrite file
- [x] `pending::remove(commit: &str)` — delete the pending file
- [x] `pending::PendingRecord` struct — fields: commit, repo, commit_time, attempts, last_attempt
- [x] `retry::run(repo: &str)` — load all pending for repo, attempt resolution for each, remove on success, increment on failure
- [x] Unit tests: write/read/delete pending records, verify retry logic

---

## Phase 8: Push Logic

- [x] Check `git config ai.barometer.autopush` — if unset, this is first push for repo
- [x] On first push: print warning to stderr, set `ai.barometer.autopush true`
- [x] After consent: push silently
- [x] On push failure: log warning to stderr, never block, never retry in hook
- [x] Check org filter: extract org from remotes, compare to configured `--org` value
- [x] If org doesn't match: attach locally only, skip push
- [x] Check per-repo override: `git config ai.barometer.enabled` — if `false`, skip entirely
- [x] Unit tests: verify consent flow, org filtering logic

---

## Phase 9: `hydrate` Subcommand

- [x] Accept `--since` flag (e.g. `7d`, `30d`) — parse duration string
- [x] Scan all Claude + Codex log root directories (not scoped to one repo)
- [x] Filter log files by mtime within `--since` window
- [x] For each log file: stream lines, extract all commit hashes found
- [x] For each commit hash: resolve repo from session cwd/workdir
- [x] Check dedup: skip if note already exists
- [x] Attach note if missing
- [x] Print verbose progress throughout: `[ai-barometer] → session <id> (repo: <name>)`
- [x] Print final summary: `Done. N attached, N skipped, N errors.`
- [x] All errors are non-fatal — log and continue
- [x] Do NOT auto-push by default (add `--push` flag to opt in)
- [x] Integration test: fake log directory with multiple sessions, verify hydration attaches correct notes

---

## Phase 10: `install` Subcommand

- [ ] Accept `--org <github-org>` optional flag
- [ ] Set `git config --global core.hooksPath ~/.git-hooks`
- [ ] Create `~/.git-hooks/` directory if missing
- [ ] Write `~/.git-hooks/post-commit` shim: `#!/bin/sh\nexec ai-barometer hook post-commit`
- [ ] Make shim executable (`chmod +x`)
- [ ] Persist org filter to config if provided
- [ ] Run `hydrate --since 7d` as final step
- [ ] Print clear confirmation output at each step

---

## Phase 11: `status` Subcommand

- [ ] Show: current repo root
- [ ] Show: hooks path and whether shim is installed
- [ ] Show: number of pending retries for current repo
- [ ] Show: org filter config (if any)
- [ ] Show: autopush consent status
- [ ] Show: per-repo enabled/disabled status

---

## Phase 12: Hardening & Edge Cases

- [ ] Ensure hook never panics — catch_unwind or equivalent top-level guard
- [ ] Handle missing `~/.claude/` or `~/.codex/` dirs gracefully (not errors)
- [ ] Handle repos with no remotes (local-only)
- [ ] Handle detached HEAD state
- [ ] Handle concurrent commits (pending file write atomicity)
- [ ] Handle very large session logs (streaming, not loading into memory)
- [ ] Verify short hash matching uses first 7 chars of full hash
- [ ] Test on repos with existing notes from other sources
