# Plan: Add git identity fields and remove touched_paths

## Context

ai-barometer needs to attribute AI sessions to PR authors. The current `SessionRecord`
stores `committer_key_hash` (a SHA256 of `user.email`) which is used as an index key
but cannot be reversed by the server. The server needs plaintext identity to match
sessions to GitHub PR authors.

Additionally, `touched_paths` exists in the schema but is never populated (hardcoded
to `Vec::new()`). File interaction extraction will be done server-side from the raw
session content, so this field should be removed.

## Changes

### 1. Add `git_user_email` and `git_user_name` to `SessionRecord` (note.rs)

Add two new optional fields:

```rust
#[serde(skip_serializing_if = "Option::is_none")]
pub git_user_email: Option<String>,
#[serde(skip_serializing_if = "Option::is_none")]
pub git_user_name: Option<String>,
```

These are populated from `git config user.email` and `git config user.name` at
ingestion time. The existing `committer_key_hash` field and committer index remain
unchanged.

### 2. Remove `touched_paths` from `SessionRecord` (note.rs)

Remove the `touched_paths: Vec<String>` field entirely. Remove any code that
sets it (currently just `let touched_paths = Vec::new()` in `ingest_session_from_log`
in main.rs).

### 3. Populate new fields at ingestion time (main.rs)

In `ingest_session_from_log`, read `git config user.email` and `git config user.name`
(the email read already exists for `committer_key_hash_for_repo`) and pass them into
the `SessionRecord`.

### 4. Update tests

- Update `sample_record()` in note.rs tests to include the new fields and remove
  `touched_paths`
- Update any test assertions that reference `touched_paths`
- Add a test verifying `git_user_email` and `git_user_name` are populated in
  ingested sessions

## What does NOT change

- Git notes refs structure
- Index entry format
- Compression/encryption
- Upload mechanism (git push of session refs)
- `committer_key_hash` field or committer index

## What ai-barometer should expect

After this change, each `SessionEnvelope` blob contains:

```json
{
  "record": {
    "session_uid": "...",
    "agent": "claude-code",
    "session_id": "...",
    "repo_root": "/local/path",
    "repo_remote_url": "https://github.com/org/repo.git",
    "branch_key": "origin/main",
    "committer_key_hash": "<sha256 of email>",
    "git_user_email": "dev@example.com",
    "git_user_name": "Dev Name",
    "session_start": 1700000000,
    "session_end": 1700000100,
    "content_sha256": "...",
    "observed_commits": ["abc123..."],
    "time_window": { "start": 1700000000, "end": 1700000100 },
    "cwd": "/local/path",
    "match_signals": { "confidence": "exact_hash_match", "score": 0.95, "reasons": ["..."] },
    "ingested_at": "2026-03-07T...",
    "cli_version": "1.2.0"
  },
  "session_content": "<full raw JSONL session log>"
}
```

Note: `touched_paths` is removed. `git_user_email` and `git_user_name` are new.
Older sessions ingested before this change will not have these fields (they are
`Option` / `skip_serializing_if`), so the server should handle their absence.
