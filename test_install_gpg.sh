#!/bin/sh
# Test script for install.sh GPG setup functionality.
# Uses command stubs in a temp PATH to make tests deterministic
# regardless of host tool availability (gpg, brew, curl).
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_SCRIPT="$SCRIPT_DIR/install.sh"

# Config key constants (matching install.sh)
GPG_RECIPIENT_KEY="ai.cadence.gpg.recipient"
GPG_KEY_SOURCE_KEY="ai.cadence.gpg.publicKeySource"

# --- Test harness ---

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo "  PASS: $1"
}

fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo "  FAIL: $1"
    if [ -n "${2:-}" ]; then
        echo "    Detail: $2"
    fi
}

assert_contains() {
    _haystack="$1"
    _needle="$2"
    _msg="$3"
    if echo "$_haystack" | grep -qF "$_needle"; then
        pass "$_msg"
    else
        fail "$_msg" "Expected to find '$_needle' in output"
    fi
}

assert_not_contains() {
    _haystack="$1"
    _needle="$2"
    _msg="$3"
    if echo "$_haystack" | grep -qF "$_needle"; then
        fail "$_msg" "Expected NOT to find '$_needle' in output"
    else
        pass "$_msg"
    fi
}

# --- Stub infrastructure ---

# Create a stub directory with configurable command stubs.
# Usage: create_stubs "$stub_dir" [gpg_available] [brew_available] [brew_install_succeeds]
#                                  [curl_succeeds] [gpg_import_succeeds] [git_config_succeeds]
# Each flag is "true" or "false". Defaults: all false/unavailable.
create_stubs() {
    _stub_dir="$1"
    _gpg_avail="${2:-false}"
    _brew_avail="${3:-false}"
    _brew_install_ok="${4:-false}"
    _curl_ok="${5:-false}"
    _gpg_import_ok="${6:-false}"
    _git_config_ok="${7:-true}"

    mkdir -p "$_stub_dir"

    # Stub log file for recording which commands were called
    _log="$_stub_dir/stub.log"
    : > "$_log"

    # gpg stub
    if [ "$_gpg_avail" = "true" ]; then
        cat > "$_stub_dir/gpg" <<STUBEOF
#!/bin/sh
echo "gpg \$*" >> "$_log"
case "\$1" in
    --import)
        if [ "$_gpg_import_ok" = "true" ]; then
            echo "gpg: key imported"
            exit 0
        else
            echo "gpg: import failed" >&2
            exit 1
        fi
        ;;
    *)
        exit 0
        ;;
esac
STUBEOF
        chmod +x "$_stub_dir/gpg"
    fi
    # If gpg not available, don't create the stub — command -v will fail

    # brew stub
    if [ "$_brew_avail" = "true" ]; then
        cat > "$_stub_dir/brew" <<STUBEOF
#!/bin/sh
echo "brew \$*" >> "$_log"
case "\$1" in
    install)
        if [ "$_brew_install_ok" = "true" ]; then
            echo "brew: installed \$2"
            exit 0
        else
            echo "brew: install failed" >&2
            exit 1
        fi
        ;;
    *)
        exit 0
        ;;
esac
STUBEOF
        chmod +x "$_stub_dir/brew"
    fi

    # curl stub
    cat > "$_stub_dir/curl" <<STUBEOF
#!/bin/sh
echo "curl \$*" >> "$_log"
if [ "$_curl_ok" = "true" ]; then
    # Find the -o argument and write dummy content to that file
    _outfile=""
    while [ \$# -gt 0 ]; do
        case "\$1" in
            -o) _outfile="\$2"; shift ;;
        esac
        shift
    done
    if [ -n "\$_outfile" ]; then
        echo "FAKE_KEY_DATA" > "\$_outfile"
    fi
    exit 0
else
    exit 1
fi
STUBEOF
    chmod +x "$_stub_dir/curl"

    # git stub — wraps real git but can simulate config write failures
    _real_git=$(command -v git)
    if [ "$_git_config_ok" = "true" ]; then
        cat > "$_stub_dir/git" <<STUBEOF
#!/bin/sh
echo "git \$*" >> "$_log"
exec "$_real_git" "\$@"
STUBEOF
    else
        cat > "$_stub_dir/git" <<STUBEOF
#!/bin/sh
echo "git \$*" >> "$_log"
case "\$1" in
    config)
        echo "error: could not lock config file" >&2
        exit 1
        ;;
    *)
        exec "$_real_git" "\$@"
        ;;
esac
STUBEOF
    fi
    chmod +x "$_stub_dir/git"

    # Also need basic utilities: sed, printf, echo, mktemp, rm, chmod, uname
    # These come from system PATH, so we append system dirs after our stub dir
}

# Save original PATH once at script start
ORIG_PATH="$PATH"

# Shared test environment state (set by setup_test_env, read by tests)
TEST_TMPDIR=""

# Set up isolated test environment with stubs.
# Sets TEST_TMPDIR, GIT_CONFIG_GLOBAL, PATH.
# Must be called directly (not in a subshell) so env changes persist.
# Usage: setup_test_env [gpg_avail] [brew_avail] [brew_install_ok] [curl_ok] [gpg_import_ok] [git_config_ok]
setup_test_env() {
    TEST_TMPDIR=$(mktemp -d)
    _stub_dir="$TEST_TMPDIR/stubs"

    # Create a minimal git config for testing
    GIT_CONFIG_GLOBAL="$TEST_TMPDIR/gitconfig"
    export GIT_CONFIG_GLOBAL
    : > "$GIT_CONFIG_GLOBAL"

    create_stubs "$_stub_dir" "${1:-false}" "${2:-false}" "${3:-false}" "${4:-false}" "${5:-false}" "${6:-true}"

    # Set stub-first PATH; include /usr/bin, /bin for sed, mktemp, rm, etc.
    PATH="$_stub_dir:/usr/bin:/bin"
    export PATH
}

cleanup_test_env() {
    PATH="$ORIG_PATH"
    export PATH
    rm -rf "$TEST_TMPDIR"
    TEST_TMPDIR=""
}

# Source helpers from install.sh (everything before main())
eval_helpers() {
    eval "$(sed '/^main()/,$d' "$INSTALL_SCRIPT")"
}

# Read stub log
stub_log() {
    cat "$1/stubs/stub.log"
}

# --- Tests: prompt_yn ---

echo "=== Testing prompt_yn helper ==="

test_prompt_yn_yes() {
    TESTS_RUN=$((TESTS_RUN + 1))
    setup_test_env
    _output=$(echo "y" | (eval_helpers; prompt_yn "Test?"; echo "RESULT=$PROMPT_RESULT") 2>&1)
    if echo "$_output" | grep -qF "RESULT=yes"; then
        pass "prompt_yn accepts 'y'"
    else
        fail "prompt_yn accepts 'y'" "Got: $_output"
    fi
    cleanup_test_env
}

test_prompt_yn_no() {
    TESTS_RUN=$((TESTS_RUN + 1))
    setup_test_env
    _output=$(echo "n" | (eval_helpers; prompt_yn "Test?"; echo "RESULT=$PROMPT_RESULT") 2>&1)
    if echo "$_output" | grep -qF "RESULT=no"; then
        pass "prompt_yn accepts 'n'"
    else
        fail "prompt_yn accepts 'n'" "Got: $_output"
    fi
    cleanup_test_env
}

test_prompt_yn_empty_defaults_no() {
    TESTS_RUN=$((TESTS_RUN + 1))
    setup_test_env
    _output=$(echo "" | (eval_helpers; prompt_yn "Test?"; echo "RESULT=$PROMPT_RESULT") 2>&1)
    if echo "$_output" | grep -qF "RESULT=no"; then
        pass "prompt_yn empty input defaults to 'no'"
    else
        fail "prompt_yn empty input defaults to 'no'" "Got: $_output"
    fi
    cleanup_test_env
}

test_prompt_yn_quit() {
    TESTS_RUN=$((TESTS_RUN + 1))
    setup_test_env
    _output=$(echo "q" | (eval_helpers; prompt_yn "Test?" || true; echo "RESULT=$PROMPT_RESULT") 2>&1)
    if echo "$_output" | grep -qF "RESULT=quit"; then
        pass "prompt_yn detects quit"
    else
        fail "prompt_yn detects quit" "Got: $_output"
    fi
    cleanup_test_env
}

test_prompt_yn_eof() {
    TESTS_RUN=$((TESTS_RUN + 1))
    setup_test_env
    _output=$(printf "" | (eval_helpers; prompt_yn "Test?" || true; echo "RESULT=$PROMPT_RESULT") 2>&1)
    if echo "$_output" | grep -qF "RESULT=quit"; then
        pass "prompt_yn handles EOF as quit"
    else
        fail "prompt_yn handles EOF as quit" "Got: $_output"
    fi
    cleanup_test_env
}

test_prompt_yn_yes_uppercase() {
    TESTS_RUN=$((TESTS_RUN + 1))
    setup_test_env
    _output=$(echo "Y" | (eval_helpers; prompt_yn "Test?"; echo "RESULT=$PROMPT_RESULT") 2>&1)
    if echo "$_output" | grep -qF "RESULT=yes"; then
        pass "prompt_yn accepts uppercase 'Y'"
    else
        fail "prompt_yn accepts uppercase 'Y'" "Got: $_output"
    fi
    cleanup_test_env
}

# --- Tests: prompt_line ---

echo ""
echo "=== Testing prompt_line helper ==="

test_prompt_line_normal() {
    TESTS_RUN=$((TESTS_RUN + 1))
    setup_test_env
    _output=$(echo "test@example.com" | (eval_helpers; prompt_line "Input:"; echo "RESULT=$PROMPT_RESULT") 2>&1)
    if echo "$_output" | grep -qF "RESULT=test@example.com"; then
        pass "prompt_line returns normal input"
    else
        fail "prompt_line returns normal input" "Got: $_output"
    fi
    cleanup_test_env
}

test_prompt_line_blank() {
    TESTS_RUN=$((TESTS_RUN + 1))
    setup_test_env
    _output=$(echo "" | (eval_helpers; prompt_line "Input:"; echo "RESULT=[$PROMPT_RESULT]") 2>&1)
    if echo "$_output" | grep -qF "RESULT=[]"; then
        pass "prompt_line returns blank on empty input"
    else
        fail "prompt_line returns blank on empty input" "Got: $_output"
    fi
    cleanup_test_env
}

test_prompt_line_quit() {
    TESTS_RUN=$((TESTS_RUN + 1))
    setup_test_env
    _output=$(echo "quit" | (eval_helpers; prompt_line "Input:" || true; echo "RESULT=$PROMPT_RESULT") 2>&1)
    if echo "$_output" | grep -qF "RESULT=quit"; then
        pass "prompt_line detects quit"
    else
        fail "prompt_line detects quit" "Got: $_output"
    fi
    cleanup_test_env
}

test_prompt_line_eof() {
    TESTS_RUN=$((TESTS_RUN + 1))
    setup_test_env
    _output=$(printf "" | (eval_helpers; prompt_line "Input:" || true; echo "RESULT=$PROMPT_RESULT") 2>&1)
    if echo "$_output" | grep -qF "RESULT=quit"; then
        pass "prompt_line handles EOF as quit"
    else
        fail "prompt_line handles EOF as quit" "Got: $_output"
    fi
    cleanup_test_env
}

# --- Tests: print_gpg_manual_steps ---

echo ""
echo "=== Testing print_gpg_manual_steps ==="

test_manual_steps_none_done() {
    TESTS_RUN=$((TESTS_RUN + 1))
    setup_test_env
    _output=$( (eval_helpers; print_gpg_manual_steps "") 2>&1)
    assert_contains "$_output" "Install GPG" "Shows GPG install step when nothing done"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "Import your public key" "Shows import step when nothing done"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "cadence gpg setup" "Shows setup command when nothing done"
    cleanup_test_env
}

test_manual_steps_gpg_installed() {
    TESTS_RUN=$((TESTS_RUN + 1))
    setup_test_env
    _output=$( (eval_helpers; print_gpg_manual_steps "gpg_installed") 2>&1)
    assert_not_contains "$_output" "Install GPG" "Hides GPG install step when gpg installed"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "Import your public key" "Shows import step when gpg installed"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "cadence gpg setup" "Shows setup command when gpg installed"
    cleanup_test_env
}

test_manual_steps_key_imported() {
    TESTS_RUN=$((TESTS_RUN + 1))
    setup_test_env
    _output=$( (eval_helpers; print_gpg_manual_steps "gpg_installed key_imported") 2>&1)
    assert_not_contains "$_output" "Install GPG" "Hides install step when key imported"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_not_contains "$_output" "Import your public key" "Hides import step when key imported"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "cadence gpg setup" "Shows setup command when key imported but no recipient"
    cleanup_test_env
}

test_manual_steps_all_done() {
    TESTS_RUN=$((TESTS_RUN + 1))
    setup_test_env
    _output=$( (eval_helpers; print_gpg_manual_steps "gpg_installed key_imported recipient_set") 2>&1)
    assert_not_contains "$_output" "Install GPG" "Hides install step when all done"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_not_contains "$_output" "Import your public key" "Hides import step when all done"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "GPG encryption is configured" "Shows configured message when all done"
    cleanup_test_env
}

# --- Tests: ensure_gpg_available ---

echo ""
echo "=== Testing ensure_gpg_available ==="

test_ensure_gpg_already_available() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=true on PATH
    setup_test_env true
    _rc=0
    (eval_helpers; ensure_gpg_available) >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -eq 0 ]; then
        pass "ensure_gpg_available returns 0 when gpg on PATH"
    else
        fail "ensure_gpg_available returns 0 when gpg on PATH" "Got rc=$_rc"
    fi
    cleanup_test_env
}

test_ensure_gpg_missing_brew_missing() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=false, brew=false
    setup_test_env false false
    _output=""
    _rc=0
    _output=$( (eval_helpers; ensure_gpg_available) 2>&1) || _rc=$?
    if [ "$_rc" -eq 1 ]; then
        pass "ensure_gpg_available returns 1 when gpg and brew missing"
    else
        fail "ensure_gpg_available returns 1 when gpg and brew missing" "Got rc=$_rc"
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "gpg not found" "Shows 'gpg not found' message"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "Homebrew is not installed" "Shows Homebrew not installed message"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "Install GPG manually" "Shows manual install guidance"
    cleanup_test_env
}

test_ensure_gpg_missing_brew_decline() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=false, brew=true
    setup_test_env false true
    _rc=0
    _output=$(echo "n" | (eval_helpers; ensure_gpg_available) 2>&1) || _rc=$?
    if [ "$_rc" -eq 1 ]; then
        pass "ensure_gpg_available returns 1 when user declines brew install"
    else
        fail "ensure_gpg_available returns 1 when user declines brew install" "Got rc=$_rc"
    fi
    cleanup_test_env
}

test_ensure_gpg_missing_brew_install_fails() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=false, brew=true, brew_install=false
    setup_test_env false true false
    _rc=0
    _output=$(echo "y" | (eval_helpers; ensure_gpg_available) 2>&1) || _rc=$?
    if [ "$_rc" -eq 1 ]; then
        pass "ensure_gpg_available returns 1 when brew install fails"
    else
        fail "ensure_gpg_available returns 1 when brew install fails" "Got rc=$_rc"
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "brew install gnupg failed" "Shows brew install failure message"
    cleanup_test_env
}

test_ensure_gpg_quit_at_brew_prompt() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=false, brew=true
    setup_test_env false true
    _rc=0
    _output=$(echo "q" | (eval_helpers; ensure_gpg_available) 2>&1) || _rc=$?
    if [ "$_rc" -eq 2 ]; then
        pass "ensure_gpg_available returns 2 on quit at brew prompt"
    else
        fail "ensure_gpg_available returns 2 on quit at brew prompt" "Got rc=$_rc"
    fi
    cleanup_test_env
}

test_ensure_gpg_eof_at_brew_prompt() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=false, brew=true
    setup_test_env false true
    _rc=0
    _output=$(printf "" | (eval_helpers; ensure_gpg_available) 2>&1) || _rc=$?
    if [ "$_rc" -eq 2 ]; then
        pass "ensure_gpg_available returns 2 on EOF at brew prompt"
    else
        fail "ensure_gpg_available returns 2 on EOF at brew prompt" "Got rc=$_rc"
    fi
    cleanup_test_env
}

# --- Tests: import_gpg_key ---

echo ""
echo "=== Testing import_gpg_key ==="

test_import_key_invalid_path() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=true (needed for import), import succeeds doesn't matter since file check fails first
    setup_test_env true
    _output=$( (eval_helpers; import_gpg_key "/nonexistent/path/key.asc") 2>&1) || true
    assert_contains "$_output" "File not found" "Invalid path shows file not found"
    cleanup_test_env
}

test_import_key_local_file_success() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=true, gpg_import=true
    setup_test_env true false false false true
    _keyfile="$TEST_TMPDIR/test.key"
    echo "FAKE_KEY" > "$_keyfile"
    _rc=0
    _output=$( (eval_helpers; import_gpg_key "$_keyfile") 2>&1) || _rc=$?
    if [ "$_rc" -eq 0 ]; then
        pass "import_gpg_key succeeds for valid local file"
    else
        fail "import_gpg_key succeeds for valid local file" "Got rc=$_rc, output: $_output"
    fi
    cleanup_test_env
}

test_import_key_local_file_fails() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=true, gpg_import=false (import fails)
    setup_test_env true false false false false
    _keyfile="$TEST_TMPDIR/bad.key"
    echo "BAD_KEY" > "$_keyfile"
    _rc=0
    _output=$( (eval_helpers; import_gpg_key "$_keyfile") 2>&1) || _rc=$?
    if [ "$_rc" -eq 1 ]; then
        pass "import_gpg_key returns 1 for failed import"
    else
        fail "import_gpg_key returns 1 for failed import" "Got rc=$_rc"
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "Key import failed" "Shows import failure message"
    cleanup_test_env
}

test_import_key_url_success() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=true, curl=true, gpg_import=true
    setup_test_env true false false true true
    _rc=0
    _output=$( (eval_helpers; import_gpg_key "https://example.com/key.asc") 2>&1) || _rc=$?
    if [ "$_rc" -eq 0 ]; then
        pass "import_gpg_key succeeds for URL source"
    else
        fail "import_gpg_key succeeds for URL source" "Got rc=$_rc, output: $_output"
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "Fetching key from URL" "Shows URL fetch message"
    TESTS_RUN=$((TESTS_RUN + 1))
    _log=$(stub_log "$TEST_TMPDIR")
    if echo "$_log" | grep -q "curl"; then
        pass "curl was called for URL import"
    else
        fail "curl was called for URL import" "Stub log: $_log"
    fi
    cleanup_test_env
}

test_import_key_url_fetch_fails() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=true, curl=false (fetch fails)
    setup_test_env true false false false
    _rc=0
    _output=$( (eval_helpers; import_gpg_key "https://example.com/key.asc") 2>&1) || _rc=$?
    if [ "$_rc" -eq 1 ]; then
        pass "import_gpg_key returns 1 when URL fetch fails"
    else
        fail "import_gpg_key returns 1 when URL fetch fails" "Got rc=$_rc"
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "Could not fetch key from URL" "Shows URL fetch failure message"
    cleanup_test_env
}

test_import_key_url_import_fails() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=true, curl=true, gpg_import=false (fetch ok, import fails)
    setup_test_env true false false true false
    _rc=0
    _output=$( (eval_helpers; import_gpg_key "https://example.com/bad.asc") 2>&1) || _rc=$?
    if [ "$_rc" -eq 1 ]; then
        pass "import_gpg_key returns 1 when URL import fails"
    else
        fail "import_gpg_key returns 1 when URL import fails" "Got rc=$_rc"
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "Key import failed" "Shows import failure after URL fetch"
    cleanup_test_env
}

# --- Tests: setup_gpg_encryption flows ---

echo ""
echo "=== Testing setup_gpg_encryption flows ==="

test_gpg_setup_skip() {
    TESTS_RUN=$((TESTS_RUN + 1))
    setup_test_env true
    _output=$(echo "n" | (eval_helpers; setup_gpg_encryption) 2>&1)
    assert_contains "$_output" "WARNING: Session logs will be stored as plaintext" "Skip shows plaintext warning"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "cadence gpg setup" "Skip references gpg setup command"
    # Verify no config written
    TESTS_RUN=$((TESTS_RUN + 1))
    if git config --global --get "$GPG_RECIPIENT_KEY" >/dev/null 2>&1; then
        fail "No recipient config on skip" "Recipient was unexpectedly set"
    else
        pass "No recipient config on skip"
    fi
    cleanup_test_env
}

test_gpg_setup_quit_at_initial_prompt() {
    TESTS_RUN=$((TESTS_RUN + 1))
    setup_test_env true
    _output=$(echo "q" | (eval_helpers; setup_gpg_encryption) 2>&1)
    assert_contains "$_output" "To complete GPG setup manually" "Quit at initial shows manual steps"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "Install GPG" "Quit at initial shows all steps"
    cleanup_test_env
}

test_gpg_setup_eof_at_initial_prompt() {
    TESTS_RUN=$((TESTS_RUN + 1))
    setup_test_env true
    _output=$(printf "" | (eval_helpers; setup_gpg_encryption) 2>&1)
    assert_contains "$_output" "To complete GPG setup manually" "EOF at initial shows manual steps"
    cleanup_test_env
}

test_gpg_setup_full_flow_with_recipient() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=true, all defaults
    setup_test_env true
    # yes to GPG, blank key import (skip), provide recipient
    _output=$(printf "y\n\ntest@example.com\n" | (eval_helpers; setup_gpg_encryption) 2>&1)
    assert_contains "$_output" "GPG encryption configured for recipient: test@example.com" "Full flow sets recipient"
    TESTS_RUN=$((TESTS_RUN + 1))
    _saved_recipient=$(git config --global --get "$GPG_RECIPIENT_KEY" 2>/dev/null || echo "")
    if [ "$_saved_recipient" = "test@example.com" ]; then
        pass "Recipient persisted in git config"
    else
        fail "Recipient persisted in git config" "Got: $_saved_recipient"
    fi
    cleanup_test_env
}

test_gpg_setup_quit_at_key_source() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=true
    setup_test_env true
    _output=$(printf "y\nq\n" | (eval_helpers; setup_gpg_encryption) 2>&1)
    assert_contains "$_output" "To complete GPG setup manually" "Quit at key source shows manual steps"
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg_installed should be done, so should NOT show "Install GPG"
    assert_not_contains "$_output" "Install GPG" "Quit at key source omits gpg install step"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "Import your public key" "Quit at key source shows import step"
    cleanup_test_env
}

test_gpg_setup_quit_at_recipient() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=true
    setup_test_env true
    # yes to GPG, skip key import, quit at recipient
    _output=$(printf "y\n\nq\n" | (eval_helpers; setup_gpg_encryption) 2>&1)
    assert_contains "$_output" "To complete GPG setup manually" "Quit at recipient shows manual steps"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "cadence gpg setup" "Quit at recipient references setup command"
    cleanup_test_env
}

test_gpg_setup_blank_recipient() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=true
    setup_test_env true
    # yes to GPG, skip key import, blank recipient
    _output=$(printf "y\n\n\n" | (eval_helpers; setup_gpg_encryption) 2>&1)
    assert_contains "$_output" "No recipient set" "Blank recipient shows plaintext message"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "cadence gpg setup" "Blank recipient references setup command"
    TESTS_RUN=$((TESTS_RUN + 1))
    if git config --global --get "$GPG_RECIPIENT_KEY" >/dev/null 2>&1; then
        fail "No config written on blank recipient" "Recipient was unexpectedly set"
    else
        pass "No config written on blank recipient"
    fi
    cleanup_test_env
}

test_gpg_setup_idempotent_rerun() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=true
    setup_test_env true
    # First run: set recipient
    printf "y\n\nfirst@example.com\n" | (eval_helpers; setup_gpg_encryption) >/dev/null 2>&1
    # Second run: set different recipient
    _output=$(printf "y\n\nsecond@example.com\n" | (eval_helpers; setup_gpg_encryption) 2>&1)
    _saved=$(git config --global --get "$GPG_RECIPIENT_KEY" 2>/dev/null || echo "")
    if [ "$_saved" = "second@example.com" ]; then
        pass "Rerun overwrites recipient correctly"
    else
        fail "Rerun overwrites recipient correctly" "Got: $_saved"
    fi
    cleanup_test_env
}

# --- Tests: GPG missing flows (stubbed, deterministic) ---

echo ""
echo "=== Testing GPG-missing installer flows ==="

test_gpg_missing_plaintext_continuation() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=false, brew=false — user says yes to GPG setup but gpg unavailable
    setup_test_env false false
    _output=$(printf "y\n" | (eval_helpers; setup_gpg_encryption) 2>&1)
    assert_contains "$_output" "gpg not found" "GPG missing: shows not found message"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "WARNING: Session logs will be stored as plaintext" "GPG missing: plaintext warning"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "cadence gpg setup" "GPG missing: references gpg setup command"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "To complete GPG setup manually" "GPG missing: shows manual steps"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "Install GPG" "GPG missing: manual steps include GPG install"
    cleanup_test_env
}

test_gpg_missing_brew_available_decline() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=false, brew=true — user says yes to GPG, no to brew install
    setup_test_env false true
    _output=$(printf "y\nn\n" | (eval_helpers; setup_gpg_encryption) 2>&1)
    assert_contains "$_output" "gpg not found" "GPG missing + decline brew: shows not found"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "Skipping GPG setup" "GPG missing + decline brew: shows skip message"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "WARNING: Session logs will be stored as plaintext" "GPG missing + decline brew: plaintext warning"
    cleanup_test_env
}

test_gpg_missing_brew_install_fails_flow() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=false, brew=true, brew_install=false
    setup_test_env false true false
    _output=$(printf "y\ny\n" | (eval_helpers; setup_gpg_encryption) 2>&1)
    assert_contains "$_output" "brew install gnupg failed" "Brew install fail: shows failure message"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "Skipping GPG setup" "Brew install fail: shows skip message"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "WARNING: Session logs will be stored as plaintext" "Brew install fail: plaintext warning"
    cleanup_test_env
}

test_gpg_setup_quit_at_brew_prompt_flow() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=false, brew=true — user says yes to GPG, quits at brew prompt
    setup_test_env false true
    _output=$(printf "y\nq\n" | (eval_helpers; setup_gpg_encryption) 2>&1)
    assert_contains "$_output" "To complete GPG setup manually" "Quit at brew: shows manual steps"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "Install GPG" "Quit at brew: manual steps include GPG install (not yet installed)"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "Import your public key" "Quit at brew: manual steps include import"
    cleanup_test_env
}

# --- Tests: Key import with config persistence ---

echo ""
echo "=== Testing key import config persistence ==="

test_gpg_setup_local_key_import_success() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=true, gpg_import=true
    setup_test_env true false false false true
    _keyfile="$TEST_TMPDIR/test.pub"
    echo "FAKE_KEY" > "$_keyfile"
    # yes to GPG, provide key path, provide recipient
    _output=$(printf "y\n%s\ntest@example.com\n" "$_keyfile" | (eval_helpers; setup_gpg_encryption) 2>&1)
    assert_contains "$_output" "Key imported successfully" "Local key import: shows success"
    TESTS_RUN=$((TESTS_RUN + 1))
    _saved_source=$(git config --global --get "$GPG_KEY_SOURCE_KEY" 2>/dev/null || echo "")
    if [ "$_saved_source" = "$_keyfile" ]; then
        pass "publicKeySource persisted on import success"
    else
        fail "publicKeySource persisted on import success" "Got: $_saved_source"
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
    _saved_recipient=$(git config --global --get "$GPG_RECIPIENT_KEY" 2>/dev/null || echo "")
    if [ "$_saved_recipient" = "test@example.com" ]; then
        pass "Recipient persisted after key import"
    else
        fail "Recipient persisted after key import" "Got: $_saved_recipient"
    fi
    cleanup_test_env
}

test_gpg_setup_url_key_import_success() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=true, curl=true, gpg_import=true
    setup_test_env true false false true true
    # yes to GPG, URL key source, provide recipient
    _output=$(printf "y\nhttps://example.com/key.asc\ntest@example.com\n" | (eval_helpers; setup_gpg_encryption) 2>&1)
    assert_contains "$_output" "Fetching key from URL" "URL import: shows fetch message"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "Key imported successfully" "URL import: shows success"
    TESTS_RUN=$((TESTS_RUN + 1))
    _saved_source=$(git config --global --get "$GPG_KEY_SOURCE_KEY" 2>/dev/null || echo "")
    if [ "$_saved_source" = "https://example.com/key.asc" ]; then
        pass "publicKeySource persisted for URL source"
    else
        fail "publicKeySource persisted for URL source" "Got: $_saved_source"
    fi
    cleanup_test_env
}

test_gpg_setup_url_fetch_failure_no_config() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=true, curl=false (fetch fails)
    setup_test_env true false false false
    # yes to GPG, URL key source (fetch will fail), provide recipient
    _output=$(printf "y\nhttps://example.com/key.asc\ntest@example.com\n" | (eval_helpers; setup_gpg_encryption) 2>&1)
    assert_contains "$_output" "Could not fetch key from URL" "URL fetch fail: shows warning"
    TESTS_RUN=$((TESTS_RUN + 1))
    # publicKeySource should NOT be persisted
    if git config --global --get "$GPG_KEY_SOURCE_KEY" >/dev/null 2>&1; then
        fail "No publicKeySource on fetch failure" "Key source was unexpectedly set"
    else
        pass "No publicKeySource on fetch failure"
    fi
    TESTS_RUN=$((TESTS_RUN + 1))
    # But recipient should still be set (flow continues)
    _saved_recipient=$(git config --global --get "$GPG_RECIPIENT_KEY" 2>/dev/null || echo "")
    if [ "$_saved_recipient" = "test@example.com" ]; then
        pass "Recipient still persisted after URL fetch failure"
    else
        fail "Recipient still persisted after URL fetch failure" "Got: $_saved_recipient"
    fi
    cleanup_test_env
}

# --- Tests: git config write failure ---

echo ""
echo "=== Testing git config write failures ==="

test_git_config_failure_key_source() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=true, gpg_import=true, git_config=false (config writes fail)
    setup_test_env true false false false true false
    _keyfile="$TEST_TMPDIR/test.pub"
    echo "FAKE_KEY" > "$_keyfile"
    # yes to GPG, provide key path, provide recipient
    _output=$(printf "y\n%s\ntest@example.com\n" "$_keyfile" | (eval_helpers; setup_gpg_encryption) 2>&1)
    assert_contains "$_output" "Could not save key source to git config" "Git config fail: key source warning"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "git config --global" "Git config fail: shows manual command"
    cleanup_test_env
}

test_git_config_failure_recipient() {
    TESTS_RUN=$((TESTS_RUN + 1))
    # gpg=true, git_config=false
    setup_test_env true false false false false false
    # yes to GPG, skip key, provide recipient
    _output=$(printf "y\n\ntest@example.com\n" | (eval_helpers; setup_gpg_encryption) 2>&1)
    assert_contains "$_output" "Could not save recipient to git config" "Git config fail: recipient warning"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "git config --global" "Git config fail: shows manual recipient command"
    TESTS_RUN=$((TESTS_RUN + 1))
    assert_contains "$_output" "To complete GPG setup manually" "Git config fail: shows remaining steps"
    cleanup_test_env
}

# --- Run all tests ---

echo ""
test_prompt_yn_yes
test_prompt_yn_no
test_prompt_yn_empty_defaults_no
test_prompt_yn_quit
test_prompt_yn_eof
test_prompt_yn_yes_uppercase

echo ""
test_prompt_line_normal
test_prompt_line_blank
test_prompt_line_quit
test_prompt_line_eof

echo ""
test_manual_steps_none_done
test_manual_steps_gpg_installed
test_manual_steps_key_imported
test_manual_steps_all_done

echo ""
test_ensure_gpg_already_available
test_ensure_gpg_missing_brew_missing
test_ensure_gpg_missing_brew_decline
test_ensure_gpg_missing_brew_install_fails
test_ensure_gpg_quit_at_brew_prompt
test_ensure_gpg_eof_at_brew_prompt

echo ""
test_import_key_invalid_path
test_import_key_local_file_success
test_import_key_local_file_fails
test_import_key_url_success
test_import_key_url_fetch_fails
test_import_key_url_import_fails

echo ""
test_gpg_setup_skip
test_gpg_setup_quit_at_initial_prompt
test_gpg_setup_eof_at_initial_prompt
test_gpg_setup_full_flow_with_recipient
test_gpg_setup_quit_at_key_source
test_gpg_setup_quit_at_recipient
test_gpg_setup_blank_recipient
test_gpg_setup_idempotent_rerun

echo ""
test_gpg_missing_plaintext_continuation
test_gpg_missing_brew_available_decline
test_gpg_missing_brew_install_fails_flow
test_gpg_setup_quit_at_brew_prompt_flow

echo ""
test_gpg_setup_local_key_import_success
test_gpg_setup_url_key_import_success
test_gpg_setup_url_fetch_failure_no_config

echo ""
test_git_config_failure_key_source
test_git_config_failure_recipient

# --- Summary ---

echo ""
echo "==============================="
echo "Tests run: $TESTS_RUN"
echo "Passed:    $TESTS_PASSED"
echo "Failed:    $TESTS_FAILED"
echo "==============================="

if [ "$TESTS_FAILED" -gt 0 ]; then
    exit 1
fi
