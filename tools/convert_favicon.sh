#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
SRC="${REPO_ROOT}/ssltui/images/favicon.png"
DST="${REPO_ROOT}/ssltui/images/favicon.ico"

if ! command -v convert >/dev/null 2>&1; then
    echo "ImageMagick 'convert' command could not be found. Please install ImageMagick to proceed." >&2
    exit 1
fi

convert "$SRC" -define icon:auto-resize=64,48,32,16 "$DST"
