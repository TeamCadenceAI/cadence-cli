# AI Barometer – Implementation Plan

## Overview

**AI Barometer** captures and attaches **AI coding agent session logs** (Claude Code, Codex) to Git commits using **git notes**, providing durable provenance and measurement of AI-assisted development — without polluting commit history or changing developer workflows.

The goal is not surveillance, but **measurement and coaching**:
- to help developers reflect on how AI tools are used
- to help teams improve practice over time
- to give engineering leaders and execs visibility into AI adoption quality and trends

Key properties:

- No extra commits
- No modification of Git history
- Deterministic session → commit correlation
- Best-effort at commit time, **guaranteed eventual attachment**
- Implemented as a **single Rust CLI binary**
- Git hooks are thin shims that call into the binary
- Installer runs **one-time hydration for the last week** by default

This document captures **all design decisions and constraints**. Do not deviate without strong reason.

---

## Core Design Decisions

### Why git notes
- Git notes allow attaching arbitrary data to commits by hash
- No history pollution
- No circular dependency (hash exists before note)
- Notes are stored in a separate ref
- Git blobs are content-addressed and deduplicated

We **always** use a dedicated ref:

refs/notes/ai-sessions

Never use default notes.

---

### Why Rust
- Single static binary
- No runtime dependencies
- Predictable performance for hooks
- Clean distribution
- We explicitly do **not** care about Rust iteration cost

All logic lives in Rust. Shell is only used as a shim.

---

## High-Level Architecture

ai-barometer (Rust binary)
├── install
│   └── sets up hooks + runs hydration
├── hook post-commit
│   └── hot path, must be fast and never fail commit
├── hydrate
│   └── one-time (and optional manual) backfill
├── retry
│   └── implicit: runs on every commit
└── status
└── optional debugging output

Git hook file contents:
```sh
#!/bin/sh
exec ai-barometer hook post-commit

No logic in shell.

⸻

Supported Agents (v1)
	•	Claude Code
	•	Logs under ~/.claude/projects/**
	•	JSONL files
	•	Commit hashes appear in tool output lines
	•	Codex
	•	Logs under ~/.codex/sessions/**
	•	JSONL files
	•	Commit hashes appear in command output

Other agents are explicitly out of scope for now.

⸻

Session → Commit Correlation (Critical)

Invariant

If an AI agent created a commit, the commit hash appears verbatim in the session log.

AI Barometer relies on this invariant. No heuristics based on diffs, prompts, or timestamps alone.

⸻

Post-Commit Resolution Strategy (Fast Path)

The post-commit hook must not scan all logs (log directories can be very large).

Algorithm:
	1.	Resolve repo root:

git rev-parse --show-toplevel


	2.	Resolve commit hash and timestamp:

git rev-parse HEAD
git show -s --format=%ct HEAD


	3.	Narrow candidate session directories:
	•	Encode repo path into Claude-style project name:

/Users/foo/bar → -Users-foo-bar


	•	Only search matching directories:

~/.claude/projects/*<encoded-repo>*


	4.	Narrow candidate files by time:
	•	Only .jsonl files
	•	Modified within ±10 minutes of commit time
	5.	Stream candidate files line-by-line:
	•	Simple substring match for:
	•	short hash
	•	full hash
	•	Stop on first match
	6.	Parse only minimal JSON fields:
	•	session ID
	•	cwd / workdir
	•	agent type
	7.	Verify:
	•	cwd resolves to same Git repo
	•	commit exists in that repo

If matched → success
If not matched → defer (see Pending Retries)

⸻

Pending Retry Mechanism (No Misses Allowed)

AI Barometer does not allow permanent misses.

If a commit cannot be resolved at hook time:
	•	Write a pending record:

~/.ai-barometer/pending/<commit-hash>.json



Example:

{
  "commit": "655dd38",
  "repo": "/Users/foo/dev/my-repo",
  "commit_time": 1707445523,
  "attempts": 1,
  "last_attempt": 1707445601
}

Retry Policy
	•	On every post-commit in the repo:
	•	Attempt resolution for:
	•	current commit
	•	all pending commits for that repo
	•	Increment attempt counter
	•	Delete pending record only on success

No background daemon. No cron. No global scans.

This guarantees eventual attachment once logs land on disk.

⸻

Deduplication Rules

Before attaching anything:

git notes --ref=refs/notes/ai-sessions show <commit>

If a note already exists:
	•	Treat as success
	•	Do nothing
	•	Do not push

This prevents:
	•	duplicate work
	•	rebase loops
	•	hydration collisions

⸻

Multiple Commits per Session

This is expected and correct.
	•	A single session log may contain multiple commits
	•	The same session log may be attached to multiple commits

This does not meaningfully increase repo size:
	•	Git blobs are content-addressed
	•	Identical payloads are stored once
	•	Differences are delta-compressed

AI Barometer prioritises correctness and simplicity over minimising logical duplication.

⸻

Note Format

Notes are self-contained and human-readable.

Structure:

---
agent: claude-code | codex
session_id: <uuid>
repo: <path>
commit: <full hash>
commit_in_session: <optional>
confidence: exact_hash_match
payload_sha256: <hash>
---
<verbatim session log (JSONL)>

Rules:
	•	Session payload is immutable
	•	Header is small
	•	No cross-note references
	•	No Git-internal blob linking (intentionally avoided)

⸻

Pushing Notes

Default Behaviour
	•	Notes are pushed automatically if:
	•	repo has an upstream
	•	org filter (if configured) allows it

Command:

git push origin refs/notes/ai-sessions

Safety
	•	First push per repo:
	•	emit warning
	•	record consent:

git config ai.barometer.autopush true


	•	After consent, push silently

Push failures:
	•	log warning
	•	never block commit
	•	never retry automatically in the hook

⸻

Installer Behaviour

Installer responsibilities:
	1.	Download correct ai-barometer binary
	2.	Set:

git config --global core.hooksPath ~/.git-hooks


	3.	Install hook shim
	4.	Persist configuration (org filter, defaults)
	5.	Run hydration for the last 7 days by default

Hydration runs once at install unless manually re-invoked.

⸻

Hydration Command

ai-barometer hydrate --since 7d

Properties:
	•	Can take minutes
	•	Must be very verbose
	•	Must not auto-push by default

Algorithm:
	1.	Scan Claude + Codex log roots
	2.	Filter logs by mtime
	3.	Stream logs
	4.	Extract commit hashes
	5.	Resolve repos via cwd/workdir
	6.	Attach notes if missing
	7.	Print progress continuously
	8.	Print final summary

Example output:

[ai-barometer] Scanning Claude logs (last 7 days)…
[ai-barometer] Found 143 session logs
[ai-barometer] → session 923bf742 (repo: session_summariser)
[ai-barometer]   ↳ commit 655dd38 attached
[ai-barometer] → session 71ac…
[ai-barometer]   ↳ repo missing, skipped
[ai-barometer] Done. 38 attached, 12 skipped, 4 errors.

Hydration errors must be non-fatal.

⸻

Org Filtering

Installer may accept:

--org <github-org>

Rules:
	•	Extract owner from all Git remotes
	•	If any remote matches org → allowed
	•	If not:
	•	notes may still be attached locally
	•	notes must NOT be pushed

Per-repo override:

git config ai.barometer.enabled false


⸻

Non-Goals (Explicit)

Do NOT implement:
	•	SQLite or indexing
	•	Background daemons
	•	UI
	•	GitHub API integration
	•	Secret redaction (future concern)
	•	Session merging or summarisation
	•	Cross-machine syncing

This tool is intentionally narrow.

⸻

Failure Guarantees
	•	Commits are never blocked
	•	Crashes in hooks must be caught
	•	Missing logs are retried until found
	•	Storage grows with unique sessions, not commits

⸻

Summary

AI Barometer is designed to be:
	•	Calm and non-invasive
	•	Invisible when working
	•	Verbose when doing heavy work
	•	Deterministic and Git-native
	•	Focused on measurement, reflection, and improvement — not surveillance

Do not optimise prematurely. Correctness and robustness matter more than cleverness.
