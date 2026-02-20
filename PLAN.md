# Notes Storage Overhaul

## Problem

Git notes are hitting GitHub's 2 GiB push limit. Root causes:

1. **Per-commit duplication**: A session that produces N commits stores the full session log N times (e.g., one 41 MB session x 37 commits = 1.5 GB).
2. **Encryption defeats git delta compression**: PGP uses a random session key each time, so two encrypted copies of the same payload share zero bytes — git can't delta-compress them.
3. **PGP ASCII armor overhead**: Base64 encoding adds ~33%, which cancels out any compression savings.
4. **No payload compression**: JSONL is stored verbatim (compresses ~25% with zstd).
5. **Notes ref accumulates merge history**: Each fetch-merge-push cycle adds commits that serve no purpose.
6. **Push attempted when no local notes ref exists**: Causes a spurious error on repos with 0 attached sessions.

Data from `ai-barometer` (204 notes, 3.3 GB total):
- Top session: 41 MB x 37 copies = 1.5 GB
- Second session: 25 MB x 34 copies = 860 MB
- Third session: 10 MB x 17 copies = 173 MB
- These three sessions alone = 2.5 GB of the 3.3 GB total

---

## Phase 1: New note format (deduplicate + compress) ✅ DONE

**Goal**: Store the session payload once as a standalone git blob; attach a lightweight pointer note to each commit.

### New format: pointer note

```
---
cadence_version: 2
agent: claude-code
session_id: <uuid>
repo: <path>
commit: <full 40-char hash>
confidence: exact_hash_match | time_window_match
session_start: 2025-01-15T10:30:00Z
payload_blob: <40-char SHA-1 of the git blob holding the payload>
payload_sha256: <hex SHA-256 of the uncompressed plaintext payload>
payload_encoding: zstd+pgp | zstd | pgp | plain
---
```

No inline payload. The `payload_blob` field references a git blob object that holds the (optionally compressed, optionally encrypted) session log.

### Storage flow

1. Compress the raw JSONL payload with zstd (level 3 — fast, ~25% savings on plaintext, and critically enables git to store the binary blob efficiently).
2. Optionally encrypt the compressed bytes with PGP (binary, NOT armored — avoids the 33% base64 overhead).
3. Store the result as a git blob: `git hash-object -w --stdin < payload_file` → get blob SHA.
4. Build the pointer note (YAML header above, no inline payload).
5. Optionally encrypt the pointer note itself with PGP (armored is fine here — it's tiny).
6. Attach the pointer note to the commit via `git notes add`.

When a session produces multiple commits, step 3 happens **once** and steps 4-6 reuse the same `payload_blob` SHA.

### `payload_encoding` values

| Value | Meaning |
|-------|---------|
| `plain` | Raw JSONL, no compression, no encryption |
| `zstd` | Zstd-compressed, not encrypted |
| `pgp` | PGP-encrypted (binary), not compressed |
| `zstd+pgp` | Zstd-compressed then PGP-encrypted (binary) |

### Backward compatibility

Add `cadence_version: 2` to the header. Consumers check this field:
- Missing or `1` → legacy format (inline payload after closing `---`)
- `2` → pointer format (read `payload_blob` and `payload_encoding`)

The CLI `cadence show` command should handle both formats transparently.

### Files to change

- `src/note.rs` — new `format_v2()` that produces the pointer header; keep `format()` for reading legacy notes
- `src/git.rs` — new `store_blob_at()` fn wrapping `git hash-object -w`; new `read_blob_at()` fn wrapping `git cat-file -p`
- `src/main.rs` — update `attach_note_from_log()` to use the new format; deduplicate blob storage when a session has multiple commits
- `src/main.rs` (hydrate) — same dedup logic in the hydrate loop
- `src/main.rs` (`cadence show`) — detect format version and read accordingly

### Compression dependency

Add `zstd` crate to `Cargo.toml` (pure Rust, no C dependency needed — use the `zstd` crate which wraps `zstd-safe`).

---

## Phase 2: Squash notes ref on push ✅ DONE

**Goal**: Always push a single orphan commit instead of the full merge history.

### Approach

After the existing fetch-merge step, before pushing:

```
tree=$(git rev-parse refs/notes/ai-sessions^{tree})
orphan_commit=$(git commit-tree $tree -m "cadence notes")
git update-ref refs/notes/ai-sessions $orphan_commit
git push --force --no-verify $remote refs/notes/ai-sessions
```

This replaces the linear/merge history with a single commit pointing at the current tree. The force-push is safe because we just merged the remote's state.

### Handling the payload blobs

With Phase 1's pointer notes, the notes tree references pointer notes, but the payload blobs are standalone objects NOT referenced by the notes tree. They're referenced only indirectly (by SHA in the header text). Git would garbage-collect them.

**Solution**: Store payload blobs under a second ref, e.g. `refs/cadence/blobs`, using a tree that maps `<blob-sha>` → blob. This ref is also squash-pushed alongside the notes ref. Alternatively, the simpler approach: append payload blobs to the notes tree itself under a `_blobs/` prefix path, so they're part of the same ref and survive GC.

Chosen approach: **`_blobs/` prefix in the notes tree**. Use `git update-index` / `git mktree` to add entries like `_blobs/<sha>` pointing at the payload blob. This keeps everything on a single ref and the squash-push naturally includes them.

Actually, simpler: since `git notes` manages the tree, we can store blobs by attaching them as a note on a synthetic "commit" hash (e.g., a well-known sentinel). But this is hacky.

**Simplest approach**: Use `git hash-object -w` to create the blob. Reference it from the pointer note. Before pushing, ensure the pack includes these blobs by adding them to the notes tree via `git update-index`. Concretely:

1. After merge, read the current notes tree.
2. For every pointer note in the tree, parse out `payload_blob` SHAs.
3. Add each as a tree entry: `100644 blob <sha>\t_payload/<sha>`
4. Write the new tree, create orphan commit, update ref, force-push.

This is done once at push time, not at attach time. Payload blobs live as loose objects locally (GC-safe because they're recently created) and get included in the push pack via the tree.

### Files to change

- `src/push.rs` — `sync_notes_for_remote_inner()`: after merge, before push, squash the ref. New helper `squash_notes_ref()` that: reads tree, collects payload blob refs from pointer notes, builds augmented tree, creates orphan commit, updates ref.
- `src/push.rs` — `attempt_push_remote_at()`: same squash step.
- `src/git.rs` — helpers: `commit_tree()`, `update_ref()`, `read_tree()`, `write_tree_with_entries()`.

### Force-push safety

The current non-fast-forward retry logic handles the race condition (someone pushes between our fetch and our push). With force-push, the same race can silently overwrite their changes. Mitigation: use `--force-with-lease=refs/notes/ai-sessions:<expected-hash>` where `<expected-hash>` is the remote hash we fetched. This fails if the remote changed since our fetch, and we retry.

---

## Phase 3: Skip push when no local notes ref ✅ DONE

**Goal**: Don't attempt `git push refs/notes/ai-sessions` when the ref doesn't exist locally.

### Approach

In `attempt_push_remote_at()` (push.rs line 58), after `fetch_merge_notes_for_remote_at()`, check if `refs/notes/ai-sessions` exists locally:

```rust
let has_local_notes = git::run_git_output_at(
    Some(repo),
    &["show-ref", "--verify", "--quiet", NOTES_REF],
    &[],
)?.status.success();

if !has_local_notes {
    return; // nothing to push
}
```

Similarly in `sync_notes_for_remote_inner()`, the existing `(None, None)` check at line 172-178 already handles this for the pre-push hook path. But for the `attempt_push_remote_at` path (used by hydrate), the fetch-merge may succeed but leave no local ref. Add the guard.

### Files to change

- `src/push.rs` — `attempt_push_remote_at()`: add local ref check after fetch-merge, before push.

---

## Phase 4: Clear and re-push existing repos

**Goal**: After deploying the new CLI, clear bloated notes refs on affected remotes and re-hydrate.

### Steps (manual, per-repo)

1. Delete remote notes ref: `git push origin --delete refs/notes/ai-sessions`
2. Delete local notes ref: `git update-ref -d refs/notes/ai-sessions`
3. Run `cadence hydrate --since 30d` (or appropriate window) — regenerates notes in v2 format
4. Notes are pushed automatically during hydrate

### Optional: `cadence gc` command

Add a subcommand that automates the above for the current repo:
- Warns the user about what will happen
- Requires `--confirm` flag
- Deletes remote + local notes ref
- Runs hydrate

This is nice-to-have and can come later.

---

## Implementation Order

1. **Phase 3** (skip push when no ref) — ✅ DONE (commit 0adab24)
2. **Phase 1** (new note format) — ✅ DONE (commit 2a44a37)
3. **Phase 2** (squash on push) — ✅ DONE
4. **Phase 4** (clear and re-push) — operational, after Phases 1-3 are shipped

---

## API Consumer Spec

See below — after the plan is approved, a separate consumer spec document will be provided.
