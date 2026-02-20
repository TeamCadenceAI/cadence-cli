#!/bin/sh
set -eu

REPO="TeamCadenceAI/cadence-cli"
INSTALL_DIR="${HOME}/.local/bin"
OS_NAME="$(uname -s)"


# --- Main installer ---

main() {
    # Detect architecture and OS
    arch=$(uname -m)
    case "$OS_NAME" in
        Darwin)
            case "$arch" in
                arm64)  target="aarch64-apple-darwin" ;;
                x86_64) target="x86_64-apple-darwin" ;;
                *)
                    echo "Error: unsupported architecture: $arch" >&2
                    exit 1
                    ;;
            esac
            ;;
        Linux)
            case "$arch" in
                arm64|aarch64) target="aarch64-unknown-linux-gnu" ;;
                x86_64|amd64) target="x86_64-unknown-linux-gnu" ;;
                *)
                    echo "Error: unsupported architecture: $arch" >&2
                    exit 1
                    ;;
            esac
            ;;
        *)
            echo "Error: cadence-cli only supports macOS and Linux." >&2
            exit 1
            ;;
    esac

    echo "Detected $OS_NAME $arch ($target)"

    # Download tarball (uses /releases/latest/download/ redirect to avoid API rate limits)
    tarball="cadence-cli-${target}.tar.gz"
    download_url="https://github.com/${REPO}/releases/latest/download/${tarball}"
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    echo "Downloading ${tarball}..."
    curl -sSfL -o "${tmpdir}/${tarball}" "$download_url" || {
        echo "Error: download failed." >&2
        echo "Check that ${REPO} has at least one published release." >&2
        echo "URL: $download_url" >&2
        exit 1
    }

    # Extract and install
    echo "Extracting..."
    tar xzf "${tmpdir}/${tarball}" -C "$tmpdir"

    mkdir -p "$INSTALL_DIR"
    echo "Installing to ${INSTALL_DIR}/cadence..."
    cp "${tmpdir}/cadence" "${INSTALL_DIR}/cadence"
    chmod +x "${INSTALL_DIR}/cadence"

    echo "Running initial setup..."
    "${INSTALL_DIR}/cadence" install || {
        echo "Warning: 'cadence install' failed. You can run it manually later." >&2
    }

    echo ""
    echo "cadence installed successfully!"

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
