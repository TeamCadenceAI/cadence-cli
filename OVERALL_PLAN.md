# Cadence Architecture Plan

This document defines the architecture for:

* **cadence-cli** — developer-side ingestion and instrumentation
* **ai-barometer** — server-side ingestion, attribution, analysis, and UI

The primary goal is to reliably connect:

```
AI sessions
↓
code generated during those sessions
↓
pull requests containing that code
```

so Cadence can perform **LLM-assisted PR review with session context**.

---

# System Goals

Cadence must support:

* multiple AI coding tools
* inconsistent session log schemas
* git workflows including:

  * rebases
  * squash merges
  * force pushes
  * delayed PR creation
* large session logs (10–100MB)
* multi-developer repos
* multi-repo sessions
* sessions paused/resumed across days

The system must also be:

* tool-agnostic
* resilient to partial data
* cheap to run
* incrementally deployable

---

# Core Principle

The **only durable link between AI sessions and PRs is the code itself**.

Git history, commit hashes, and timestamps are helpful but unreliable.

Therefore Cadence uses:

```
code fingerprinting
+
developer identity
+
file overlap
```

to attribute session segments to PRs.

---

# High Level Architecture

```
Developer machine
   ↓
cadence-cli
   ↓
session ingestion + code extraction
   ↓
server (ai-barometer)
   ↓
session normalization
   ↓
code fingerprint index
   ↓
PR ingestion
   ↓
code similarity matching
   ↓
session attribution
   ↓
LLM PR review
```

---

# Part 1 — cadence-cli

---

# Intention

cadence-cli is responsible for:

1. capturing AI session logs from multiple tools
2. attaching developer + git context
3. uploading sessions reliably
4. providing minimal preprocessing to reduce server load

It must work without requiring modifications to AI tools.

---

# What We Considered

### Option A — Fully server-side processing

Developer machines upload raw logs only.

**Advantages**

* simplest CLI
* no local processing

**Disadvantages**

* higher server cost
* delayed attribution signals
* larger uploads

---

### Option B — Heavy client preprocessing

CLI extracts code fingerprints locally.

**Advantages**

* smaller uploads
* faster attribution

**Disadvantages**

* complex CLI
* harder to evolve algorithms

---

### Option C — Lightweight client preprocessing (Chosen)

CLI extracts **minimal metadata and code signals**, but leaves attribution logic server-side.

**Advantages**

* low complexity
* scalable
* flexible

---

# Proposed Solution

cadence-cli should perform:

### Session ingestion

Capture session logs from supported tools:

Examples:

```
Claude Code
Codex
Warp
Cursor
others
```

CLI should treat logs as opaque blobs.

---

### Metadata extraction

CLI extracts minimal metadata:

```
session_id
user
repo
branch
timestamp_start
timestamp_end
tool
cwd
```

---

### File interaction extraction

Detect files touched during the session:

Sources:

* tool calls
* shell commands
* file edit operations
* patch outputs

Store:

```
files_touched[]
```

Paths normalized to repo-relative.

---

### Code block extraction

Extract code from:

* assistant code blocks
* diff outputs
* edit tool calls

These are stored for fingerprinting.

---

### Upload session bundle

Upload a bundle containing:

```
raw_session_log
metadata
files_touched
extracted_code_blocks
```

---

### Git context capture

cadence-cli runs via global git hooks.

Hooks provide reliable:

```
repo
branch
commit
timestamp
```

CLI should attach this metadata to sessions when available.

---

# Why This Solution Was Chosen

This architecture:

* supports all AI tools
* keeps CLI simple
* keeps server logic flexible
* tolerates incomplete metadata
* avoids dependency on commit hashes

---

# Suggested Implementation Plan (Non-binding)

### 1. Session ingestion layer

Create tool-specific parsers:

```
parser_claude_code
parser_codex
parser_warp
parser_generic
```

Each produces a normalized event stream.

---

### 2. Metadata extractor

Implement simple detectors for:

```
repo detection
branch detection
cwd
timestamps
user
```

---

### 3. Code block extractor

Extract:

```
markdown code blocks
patch blocks
edit tool outputs
```

---

### 4. Session packaging

Bundle data into a compressed payload:

```
session.json
code_blocks.json
metadata.json
```

Upload via API.

---

### 5. Retry and buffering

CLI should maintain a small local queue so sessions upload even if network is unavailable.

---

# Additional Notes

cadence-cli should remain **stateless and lightweight**.

All attribution logic must live server-side.

---

# Part 2 — ai-barometer

---

# Intention

ai-barometer is responsible for:

* ingesting session data
* extracting code fingerprints
* indexing fingerprints
* ingesting PR events
* matching PR code to sessions
* generating PR review context
* powering developer and team analytics

---

# What We Considered

### Option A — Commit-based attribution

Match sessions to commits.

**Rejected**

Git history is unstable under rebases and squashes.

---

### Option B — Branch timeline model

Track development activity per branch.

**Viable but complex**

Requires extensive git modeling.

---

### Option C — Code fingerprint attribution (Chosen)

Match PR diffs directly to AI-generated code.

**Advantages**

* robust to git rewrites
* tool-agnostic
* cheap to compute
* proven technique (plagiarism detection)

---

# Proposed Solution

ai-barometer should maintain:

### Session storage

Raw session logs stored in object storage.

Database stores:

```
session_id
user
repo
timestamps
tool
files_touched
blob_location
```

---

### Code fingerprint index

Extract code fingerprints from sessions.

Process:

```
normalize code
chunk code
hash chunks
```

Store:

```
chunk_hash
session_id
file_path
timestamp
```

---

### PR ingestion

From GitHub webhooks:

```
pull_request
push
synchronize
```

Extract:

```
repo
PR author
commit authors
files changed
diff
timestamps
```

---

### PR code fingerprinting

Process PR diffs using same fingerprint algorithm.

---

### Session candidate selection

Initial filter:

```
session.user ∈ PR author set
AND
session.repo == PR.repo
AND
session.timestamp <= PR evaluation time
```

Optional:

```
file overlap
branch match
```

---

### Code similarity matching

For each PR chunk hash:

```
lookup matching session hashes
```

Aggregate matches per session segment.

---

### Attribution scoring

Score candidate segments using:

```
code overlap
file overlap
author match
branch match
time proximity
```

Produce ranked results.

---

### PR review context generation

Construct review prompt including:

```
PR diff
session segments
confidence scores
session messages
tool interactions
```

This context is sent to the LLM reviewer.

---

# Why This Solution Was Chosen

Code fingerprinting provides:

* resilience to git workflow variations
* tool independence
* cheap similarity matching
* scalable indexing

It also unlocks future product capabilities such as:

```
bug origin tracing
AI suggestion reuse metrics
developer AI usage insights
```

---

# Suggested Implementation Plan (Non-binding)

### Phase 1 — Session ingestion

Create ingestion pipeline:

```
API endpoint
session normalization
object storage upload
metadata persistence
```

---

### Phase 2 — Code extraction

Extract code blocks from sessions.

Normalize:

```
remove comments
collapse whitespace
remove blank lines
```

---

### Phase 3 — Fingerprint generation

Chunk code into sliding windows (5–10 lines).

Hash each chunk.

Store in index.

---

### Phase 4 — PR ingestion

Process GitHub webhook events.

Extract PR diffs.

Generate fingerprints.

---

### Phase 5 — Matching engine

Lookup session fingerprints.

Compute similarity scores.

Return ranked session segments.

---

### Phase 6 — PR review integration

Construct LLM input using:

```
PR diff
matched session segments
confidence signals
```

---

### Phase 7 — Analytics layer

Aggregate attribution data to power UI:

Developer insights:

```
AI session usage
code reuse
efficiency metrics
```

Manager insights:

```
team AI productivity
code quality trends
tool comparison
```

---

# Storage Strategy

Sessions:

```
object storage (S3/R2/etc)
```

Metadata and fingerprints:

```
Postgres
```

Optional:

```
Redis for hot index cache
```

---

# Scalability

Fingerprint index is small.

Example:

```
2000 lines of code
≈400 fingerprints
≈3KB index data
```

Millions of sessions remain manageable.

---

# Observability

ai-barometer should log:

```
session ingestion success
fingerprint generation stats
PR attribution confidence
review latency
```

These metrics allow continuous improvement.

---

# Future Enhancements

Possible later improvements:

```
AST-aware fingerprinting
function signature indexing
AI suggestion lineage tracking
semantic embeddings
```

These are **not required for initial release**.

---

# Final Notes

The key design decision is:

```
PR attribution via code similarity
not git history
```

This ensures Cadence remains robust across:

* tools
* repos
* git workflows
* session formats

while keeping implementation complexity manageable.
