#!/usr/bin/env bash
# Run ssltui — installs uv and syncs dependencies if needed.
# Usage: ./ssltui.sh [args...]
#
# Make executable once: chmod +x run_ssltui.sh

set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

# Work from the directory containing this script so uv finds pyproject.toml
cd "$(dirname "$0")"

# ---------------------------------------------------------------------------
# 1. uv — install if missing
# ---------------------------------------------------------------------------
if ! command -v uv &>/dev/null; then
    echo "uv not found — installing via the official installer..."

    if command -v curl &>/dev/null; then
        curl -LsSf https://astral.sh/uv/install.sh | sh
    elif command -v wget &>/dev/null; then
        wget -qO- https://astral.sh/uv/install.sh | sh
    else
        echo "Error: neither curl nor wget found. Install one and try again." >&2
        exit 1
    fi

    if ! command -v uv &>/dev/null; then
        echo "Error: uv installation succeeded but uv is still not in PATH." >&2
        echo "Try opening a new shell then try again." >&2
        exit 1
    fi

    echo "uv installed successfully."
fi

# ---------------------------------------------------------------------------
# 2. Python + dependencies — uv handles the Python version too
# ---------------------------------------------------------------------------
uv sync --quiet

# ---------------------------------------------------------------------------
# 3. Run
# ---------------------------------------------------------------------------
exec uv run ssltui "$@"
