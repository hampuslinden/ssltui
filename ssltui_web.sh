#!/usr/bin/env bash
# Run the ssltui API server.
# Usage: ./ssltui_web.sh [--host 0.0.0.0] [--port 8080]
#
# The API token is read from $SSLTUI_API_TOKEN or from the api_token file
# in the CA root directory (created automatically when the CA is initialised).
#
# Make executable once: chmod +x ssltui_web.sh

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
        echo "Try opening a new shell and try again." >&2
        exit 1
    fi

    echo "uv installed successfully."
fi

# ---------------------------------------------------------------------------
# 2. Python + dependencies (includes the flask extra)
# ---------------------------------------------------------------------------
uv sync --quiet --extra api

# ---------------------------------------------------------------------------
# 3. Run
# ---------------------------------------------------------------------------
# If the first argument looks like a path (not a flag and not a known option
# value like --host / --port), treat it as the CA data directory and shift
# it into the --dir flag so the rest of the arguments go to `serve`.
DIR_ARG=()
PASS_ARGS=("$@")
if [[ ${#PASS_ARGS[@]} -gt 0 && "${PASS_ARGS[0]}" != --* ]]; then
    DIR_ARG=(--dir "${PASS_ARGS[0]}")
    PASS_ARGS=("${PASS_ARGS[@]:1}")
fi

exec uv run ssltui "${DIR_ARG[@]}" serve "${PASS_ARGS[@]}"
