# Phase 5 Review: Note Formatting (`src/note.rs`)

Review date: 2026-02-09
Reviewed by: Claude Opus 4.6 (super-review)
Files reviewed: `src/note.rs`, `src/main.rs` (module wiring), `Cargo.toml`
Test status: 133 tests passing, clippy clean (expected dead-code warnings only), `cargo fmt` clean

---

## Summary

Phase 5 implements the note formatting module (`src/note.rs`) which produces self-contained git notes with a YAML-style header and verbatim session log payload. The implementation is clean, small (62 lines of production code), and well-tested (12 tests). The SHA-256 computation uses the `sha2` crate correctly.

Overall assessment: **solid implementation with a few issues worth addressing**.

---

## Findings

### 1. `---` Delimiter Injection in Payload (Medium)

**Issue:** If the session log payload itself contains a line that is exactly `---\n`, the note becomes ambiguous to any parser that tries to split it back into header + payload by searching for `---\n` delimiters. The `test_format_roundtrip_payload_extraction` test uses `splitn(3, "---\n")` which works because it only splits on the first 3 occurrences, but any future consumer (or external tool) that naively scans for `---` will misparse.

**Impact:** Not a bug today since the `payload_sha256` field provides an integrity check and the spec says payloads are immutable/verbatim. However, it is a latent parsing fragility that could cause issues when Phase 9 (hydrate) or Phase 11 (status) need to read notes back. PLAN.md does not address this.

**Recommendation:** Document this limitation explicitly (either in a doc comment on `format` or in NOTES.md). When a note parser is eventually written, it should use the `payload_sha256` for verification and/or count exactly two `---` delimiters at the header boundary rather than scanning the full note. Alternatively, consider encoding the payload length in the header so parsers know exactly where the payload starts.

### 2. Function Name Shadows `std::fmt::format` (Low)

**Issue:** The public function is named `note::format()`. While this is unambiguous when called as `note::format(...)` from other modules, within `note.rs` itself the name `format` shadows the `format!` macro's underlying function `std::fmt::format`. This does not cause a compilation error because `format!` is a macro (not a function call), but it is a subtle naming collision that could confuse readers or cause issues if someone tries to import `note::format` with `use note::format;` in a module that also needs `std::fmt::format`.

**Recommendation:** Consider renaming to `note::format_note()` or `note::build()` to avoid the shadow. This is low severity since Rust's module system prevents actual collisions, but it would improve clarity. If the name is kept, add a brief doc note explaining the choice.

### 3. No Input Validation on Parameters (Medium)

**Issue:** The `format` function accepts arbitrary strings for `agent`, `session_id`, `repo`, and `commit` with no validation. The caller could pass values containing newlines, which would break the YAML-style header structure. For example, `agent = "claude-code\nmalicious_field: value"` would inject an extra header field.

The `commit` parameter is particularly notable: it is not validated via `git::validate_commit_hash()` like it is in `scanner::find_session_for_commit` and `scanner::verify_match`. The `format` function blindly embeds whatever string is provided.

**Impact:** In the current architecture, the `format` function will only be called from Phase 6's hook handler, which gets the commit hash from `git::head_hash()`. So the practical risk is low. But as a public API, it has no defensive guards.

**Recommendation:** At minimum, add a debug assertion or doc comment warning that parameters must not contain newlines. For the `commit` parameter specifically, consider calling `validate_commit_hash()` or at least documenting the precondition. The `agent` parameter should ideally be constrained to the `AgentType` enum from `scanner.rs` rather than accepting a raw `&str` (see finding #5).

### 4. String Building Uses Repeated `format!` Allocations (Low)

**Issue:** The `format` function builds the note string by calling `format!()` six times inside `push_str()`. Each `format!()` call allocates a temporary `String` that is immediately discarded after being appended. For example:

```rust
note.push_str(&format!("agent: {}\n", agent));
note.push_str(&format!("session_id: {}\n", session_id));
```

**Impact:** Negligible for typical use. Session logs are the dominant allocation, not the header. The header is ~200 bytes and the six temporary allocations are cheap.

**Recommendation:** Could use `write!()` or `writeln!()` with the `std::fmt::Write` trait to avoid temporaries, or use a single `format!()` for the entire header. Not urgent -- this is a style/minor-efficiency observation. Defer unless someone is optimizing the hot path.

### 5. `agent` Parameter Should Use `AgentType` Enum (Medium)

**Issue:** The `format` function takes `agent: &str` as a raw string. Phase 4 already defines `scanner::AgentType` with a `Display` impl that produces `"claude-code"` and `"codex"`. Passing a raw string means the `format` function has no type-safety guarantee that the agent value is one of the known variants. A caller could pass `"unknown-agent"` or a misspelled value.

**Impact:** When Phase 6 wires everything together, it will need to call `agent_type.to_string()` before passing to `note::format`. This is an unnecessary conversion step and a missed opportunity for type safety.

**Recommendation:** Change the signature to accept `&scanner::AgentType` (or move `AgentType` to a shared location as noted in Phase 4 review finding 6.5). This would make the API more robust and eliminate possible misuse. The NOTES.md Phase 4 section already flagged this: "Move `AgentType` to shared location -- will address when Phase 5/6 need it." Phase 5 was the right time to address it.

### 6. Missing Test: Payload Containing `---` Delimiter (Medium)

**Issue:** There is no test verifying that the round-trip extraction works when the payload itself contains `---` on its own line. The existing round-trip test (`test_format_roundtrip_payload_extraction`) uses a payload that does not contain `---`. Given finding #1, this is an important edge case to verify.

**Recommendation:** Add a test with a payload like `"line one\n---\nline two\n"` and verify that `splitn(3, "---\n")` still correctly extracts the payload. This would document the expected behavior and catch regressions.

### 7. Missing Test: Header Values Containing Special Characters (Low)

**Issue:** Tests only use "clean" values for `session_id`, `repo`, and `commit`. There are no tests with values containing colons (`:` -- relevant since the header format is `key: value`), Unicode characters, or very long strings. While JSONL session IDs and repo paths are unlikely to contain colons in practice, the format function does not restrict them.

**Recommendation:** Add one or two tests with edge-case values (e.g., a repo path containing a colon like `/Users/foo/bar:baz`, or a session_id with spaces). These would document the behavior and serve as regression guards.

### 8. Confidence Field is Hardcoded (Info)

**Issue:** The `confidence` field is hardcoded to `"exact_hash_match"`. NOTES.md documents this decision and says it can be added as a parameter later. This is fine for Phase 5.

**Recommendation:** No action needed now. When Phase 6 wires things up, revisit whether other confidence levels are needed. The PLAN.md spec mentions this as the only value.

### 9. `payload_sha256` Hashes `&str` Not `&[u8]` (Info)

**Issue:** `payload_sha256` takes `&str` and calls `.as_bytes()`. This means it can only hash valid UTF-8 content. Session logs (JSONL) are always UTF-8 in practice, so this is correct for the current use case.

**Recommendation:** If binary payloads ever need to be supported, the signature would need to change to `&[u8]`. Not a concern for v1 given the JSONL-only scope.

### 10. No `parse` / Deserialization Counterpart (Info)

**Issue:** Phase 5 only implements the `format` direction (serialization). There is no `parse` function to extract the header and payload from a note string. Phase 6 and Phase 9 may need to read existing notes (e.g., for deduplication verification or status display).

**Recommendation:** Not required by Phase 5's scope, but note that a future phase will need a parser. The `splitn(3, "---\n")` pattern used in tests is the implicit parsing strategy. Consider adding a `note::parse()` function in Phase 6 or 9 when it becomes needed.

### 11. TODO.md Checklist Completeness (Info)

All three Phase 5 TODO items are checked off:
- [x] `note::format(...)` -- implemented correctly
- [x] `note::payload_sha256(...)` -- implemented correctly
- [x] Unit tests -- 12 tests covering SHA-256 correctness, format structure, field order, empty/multiline payloads, verbatim preservation, round-trip extraction, and agent variation

The implementation fully satisfies the TODO.md requirements.

### 12. NOTES.md Phase 5 Decisions Section (Info)

The NOTES.md Phase 5 section is well-written and documents all key decisions: module layout, note format adherence to spec, SHA-256 implementation, payload handling, test strategy, and dead code warnings. The documentation quality is consistent with previous phases.

---

## Test Coverage Assessment

**Strengths:**
- SHA-256 tested against well-known hash values (not just "does it return 64 hex chars")
- Round-trip test verifies that the payload can be extracted and its SHA matches the header
- Field order is explicitly tested (not just field presence)
- Empty payload edge case is covered
- Both agent types (claude-code, codex) are tested

**Gaps:**
- No test for payload containing `---` delimiter (finding #6)
- No test for header values containing special characters (finding #7)
- No test for very large payloads (relevant for Phase 12 hardening)
- No test that the note is valid for `git notes add -m` (i.e., no null bytes or other git-unfriendly content)

---

## Severity Summary

| # | Finding | Severity |
|---|---------|----------|
| 1 | `---` delimiter injection in payload | Medium |
| 2 | Function name shadows `std::fmt::format` | Low |
| 3 | No input validation on parameters | Medium |
| 4 | Repeated `format!` allocations | Low |
| 5 | `agent` should use `AgentType` enum | Medium |
| 6 | Missing test: payload with `---` | Medium |
| 7 | Missing test: special characters in values | Low |
| 8 | Hardcoded confidence field | Info |
| 9 | Hashes `&str` not `&[u8]` | Info |
| 10 | No parse counterpart | Info |
| 11 | TODO completeness | Info |
| 12 | NOTES.md quality | Info |
