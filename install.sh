#!/bin/sh
set -eu

REPO="TeamCadenceAI/ai-session-commit-linker"
INSTALL_DIR="${HOME}/.local/bin"

# Git config key constants for GPG encryption
GPG_RECIPIENT_KEY="ai.session-commit-linker.gpg.recipient"
GPG_KEY_SOURCE_KEY="ai.session-commit-linker.gpg.publicKeySource"

# --- Helper functions ---

# Shared result variable for prompt helpers.
# Callers read this after calling prompt_yn or prompt_line.
PROMPT_RESULT=""

# Prompt user for yes/no with quit support.
# Usage: prompt_yn "Question text"
# Sets PROMPT_RESULT to "yes", "no", or "quit".
# Returns 0 on yes/no, 1 on quit/EOF.
prompt_yn() {
    _prompt_text="$1"
    printf "%s (y/N/q) " "$_prompt_text"
    if ! IFS= read -r _answer; then
        # EOF (Ctrl+D)
        echo ""
        PROMPT_RESULT="quit"
        return 1
    fi
    # Trim leading/trailing whitespace
    _answer=$(echo "$_answer" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    case "$_answer" in
        y|Y|yes|YES|Yes)
            PROMPT_RESULT="yes"
            return 0
            ;;
        q|Q|quit|QUIT|Quit)
            PROMPT_RESULT="quit"
            return 1
            ;;
        *)
            PROMPT_RESULT="no"
            return 0
            ;;
    esac
}

# Prompt user for free-text input with quit support.
# Usage: prompt_line "Prompt text"
# Sets PROMPT_RESULT to the input string, or "quit" on abort.
# Returns 0 on input (even blank), 1 on quit/EOF.
prompt_line() {
    _prompt_text="$1"
    printf "%s " "$_prompt_text"
    if ! IFS= read -r _line_answer; then
        # EOF (Ctrl+D)
        echo ""
        PROMPT_RESULT="quit"
        return 1
    fi
    # Trim leading/trailing whitespace
    _line_answer=$(echo "$_line_answer" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    case "$_line_answer" in
        q|Q|quit|QUIT|Quit)
            PROMPT_RESULT="quit"
            return 1
            ;;
        *)
            PROMPT_RESULT="$_line_answer"
            return 0
            ;;
    esac
}

# Print remaining GPG manual setup steps based on progress phase.
# Usage: print_gpg_manual_steps "phase1 phase2 ..."
# Phase markers: gpg_installed, key_imported, recipient_set
print_gpg_manual_steps() {
    _completed_phases="${1:-}"
    _gpg_done=false
    _import_done=false
    _recipient_done=false

    # Parse space-separated phase markers
    for _phase in $_completed_phases; do
        case "$_phase" in
            gpg_installed) _gpg_done=true ;;
            key_imported) _import_done=true ;;
            recipient_set) _recipient_done=true ;;
        esac
    done

    echo ""
    echo "To complete GPG setup manually:"

    if [ "$_gpg_done" = false ]; then
        echo "  1. Install GPG: brew install gnupg"
    fi
    if [ "$_import_done" = false ]; then
        echo "  2. Import your public key: gpg --import <key-file>"
    fi
    if [ "$_recipient_done" = false ]; then
        echo "  3. Run: ai-session-commit-linker gpg setup"
    else
        echo "  GPG encryption is configured."
    fi
}

# Attempt to ensure gpg is available. Offers Homebrew install on macOS.
# Returns 0 if gpg is available, 1 if not available (user declined or install failed),
# 2 if user quit (quit token or EOF at brew prompt).
ensure_gpg_available() {
    if command -v gpg >/dev/null 2>&1; then
        return 0
    fi

    echo "gpg not found."

    # macOS-specific: offer Homebrew install
    if ! command -v brew >/dev/null 2>&1; then
        echo "Homebrew is not installed. Cannot auto-install GPG."
        echo "Install GPG manually: https://gnupg.org/download/"
        return 1
    fi

    if ! prompt_yn "Install GPG via Homebrew?"; then
        return 2  # quit signal
    fi

    if [ "$PROMPT_RESULT" = "yes" ]; then
        echo "Installing GPG via Homebrew..."
        if brew install gnupg; then
            if command -v gpg >/dev/null 2>&1; then
                echo "GPG installed successfully."
                return 0
            else
                echo "Warning: brew install succeeded but gpg is still not on PATH."
                return 1
            fi
        else
            echo "Warning: brew install gnupg failed."
            return 1
        fi
    else
        # User declined install
        return 1
    fi
}

# Import a GPG key from a file path or URL.
# Usage: import_gpg_key "$source"
# Returns 0 on success, 1 on failure.
import_gpg_key() {
    _key_source="$1"

    case "$_key_source" in
        http://*|https://*)
            echo "Fetching key from URL..."
            _key_tmpfile=$(mktemp)
            if curl -fsSL -o "$_key_tmpfile" "$_key_source"; then
                if gpg --import "$_key_tmpfile" 2>&1; then
                    rm -f "$_key_tmpfile"
                    return 0
                else
                    echo "Warning: Key import failed. The file may not contain a valid GPG key."
                    rm -f "$_key_tmpfile"
                    return 1
                fi
            else
                echo "Warning: Could not fetch key from URL."
                rm -f "$_key_tmpfile"
                return 1
            fi
            ;;
        *)
            # Treat as local file path
            if [ ! -f "$_key_source" ]; then
                echo "Warning: File not found: $_key_source"
                return 1
            fi
            if gpg --import "$_key_source" 2>&1; then
                return 0
            else
                echo "Warning: Key import failed. The file may not contain a valid GPG key."
                return 1
            fi
            ;;
    esac
}

# Run the optional GPG encryption setup flow.
# This function is safe to call under set -eu; all fallible commands are guarded.
setup_gpg_encryption() {
    echo ""
    echo "=== Optional: GPG Encryption ==="
    echo "You can encrypt session logs before they are attached as git notes."
    echo "This requires GPG and a public key."
    echo ""

    # Track progress for manual-step renderer
    _phases=""

    # Step 1: Ask if user wants GPG setup
    if ! prompt_yn "Would you like to set up GPG encryption?"; then
        # quit/EOF
        print_gpg_manual_steps "$_phases"
        return 0
    fi

    if [ "$PROMPT_RESULT" != "yes" ]; then
        echo ""
        echo "WARNING: Session logs will be stored as plaintext in git notes."
        echo "Run 'ai-session-commit-linker gpg setup' to enable encryption later."
        return 0
    fi

    # Step 2: Ensure GPG is available
    _ensure_result=0
    ensure_gpg_available || _ensure_result=$?

    if [ "$_ensure_result" -eq 2 ]; then
        # User quit during brew prompt
        print_gpg_manual_steps "$_phases"
        return 0
    fi

    if [ "$_ensure_result" -ne 0 ]; then
        # GPG not available and user declined or install failed
        echo ""
        echo "Skipping GPG setup. GPG is required for encryption."
        print_gpg_manual_steps "$_phases"
        echo ""
        echo "WARNING: Session logs will be stored as plaintext in git notes."
        echo "Run 'ai-session-commit-linker gpg setup' to enable encryption later."
        return 0
    fi

    _phases="gpg_installed"

    # Step 3: Key import
    if ! prompt_line "Path or URL to GPG public key (Enter to skip):"; then
        # quit/EOF
        print_gpg_manual_steps "$_phases"
        return 0
    fi
    _key_source="$PROMPT_RESULT"

    if [ -n "$_key_source" ]; then
        if import_gpg_key "$_key_source"; then
            echo "Key imported successfully."
            if git config --global "$GPG_KEY_SOURCE_KEY" "$_key_source"; then
                _phases="gpg_installed key_imported"
            else
                echo "Warning: Could not save key source to git config."
                echo "  You can set it manually:"
                echo "  git config --global $GPG_KEY_SOURCE_KEY \"$_key_source\""
            fi
        else
            echo "You can import your key manually later:"
            echo "  gpg --import <key-file>"
        fi
    else
        echo "Skipping key import."
    fi

    # Step 4: Recipient
    if ! prompt_line "GPG recipient (fingerprint, email, or key ID):"; then
        # quit/EOF
        print_gpg_manual_steps "$_phases"
        return 0
    fi
    _recipient="$PROMPT_RESULT"

    if [ -n "$_recipient" ]; then
        if git config --global "$GPG_RECIPIENT_KEY" "$_recipient"; then
            _phases="$_phases recipient_set"
            echo "GPG encryption configured for recipient: $_recipient"
        else
            echo "Warning: Could not save recipient to git config."
            echo "  You can set it manually:"
            echo "  git config --global $GPG_RECIPIENT_KEY \"$_recipient\""
            print_gpg_manual_steps "$_phases"
        fi
    else
        echo ""
        echo "No recipient set. Session logs will be stored as plaintext."
        echo "Run 'ai-session-commit-linker gpg setup' to configure later."
    fi
}

# --- Main installer ---

main() {
    # Must be macOS
    if [ "$(uname -s)" != "Darwin" ]; then
        echo "Error: ai-session-commit-linker only supports macOS." >&2
        exit 1
    fi

    # Detect architecture
    arch=$(uname -m)
    case "$arch" in
        arm64)  target="aarch64-apple-darwin" ;;
        x86_64) target="x86_64-apple-darwin" ;;
        *)
            echo "Error: unsupported architecture: $arch" >&2
            exit 1
            ;;
    esac

    echo "Detected macOS $arch ($target)"

    # Get latest release tag
    echo "Fetching latest release..."
    release_url="https://api.github.com/repos/${REPO}/releases/latest"
    release_json=$(curl -sSf "$release_url") || {
        echo "Error: could not fetch latest release from GitHub." >&2
        echo "Check that ${REPO} has at least one published release." >&2
        exit 1
    }

    tag=$(echo "$release_json" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
    if [ -z "$tag" ]; then
        echo "Error: could not determine latest release tag." >&2
        exit 1
    fi
    echo "Latest release: $tag"

    # Download tarball
    tarball="ai-session-commit-linker-${target}.tar.gz"
    download_url="https://github.com/${REPO}/releases/download/${tag}/${tarball}"
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    echo "Downloading ${tarball}..."
    curl -sSfL -o "${tmpdir}/${tarball}" "$download_url" || {
        echo "Error: download failed." >&2
        echo "URL: $download_url" >&2
        exit 1
    }

    # Extract and install
    echo "Extracting..."
    tar xzf "${tmpdir}/${tarball}" -C "$tmpdir"

    mkdir -p "$INSTALL_DIR"
    echo "Installing to ${INSTALL_DIR}/ai-session-commit-linker..."
    cp "${tmpdir}/ai-session-commit-linker" "${INSTALL_DIR}/ai-session-commit-linker"
    chmod +x "${INSTALL_DIR}/ai-session-commit-linker"

    echo "Running initial setup..."
    "${INSTALL_DIR}/ai-session-commit-linker" install || {
        echo "Warning: 'ai-session-commit-linker install' failed. You can run it manually later." >&2
    }

    # Optional GPG encryption setup
    setup_gpg_encryption

    echo ""
    echo "ai-session-commit-linker installed successfully!"

    # Check if install dir is on PATH
    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            echo ""
            echo "WARNING: ${INSTALL_DIR} is not on your PATH."
            echo "Add it by running:"
            echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc"
            ;;
    esac
}

main
