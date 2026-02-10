#!/bin/sh
set -eu

REPO="TeamCadenceAI/ai-session-commit-linker"
INSTALL_DIR="${HOME}/.local/bin"

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
