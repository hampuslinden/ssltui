"""Paths, defaults, and validated configuration."""

from __future__ import annotations

import os
import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_override_dir: Path | None = None


def set_data_dir(path: Path) -> None:
    """Override the active CA root directory at runtime (survives env changes)."""
    global _override_dir
    _override_dir = path.expanduser().resolve()


def data_dir() -> Path:
    if _override_dir is not None:
        return _override_dir
    base = os.environ.get("SSLTUI_DIR")
    if base:
        return Path(base)
    return Path.home() / ".local" / "share" / "ssltui"


def ca_key_path(root: Path) -> Path:
    return root / "ca.key"


def ca_cert_path(root: Path) -> Path:
    return root / "ca.crt"


def db_path(root: Path) -> Path:
    return root / "ca.db"


def cert_dir(root: Path, cn: str) -> Path:
    # Validate against the strict hostname allow-list first: this is the
    # primary sanitizer for any CN that reaches a filesystem path, so every
    # caller (issue/renew/revoke) is covered regardless of prior validation.
    cn = validate_cn(cn)
    base = (root / "certs").resolve()
    candidate = (base / _safe_cn(cn)).resolve()
    # Defense in depth: must be exactly one level under certs/ — blocks "..",
    # absolute paths, and any other traversal that survives _safe_cn.
    if candidate.parent != base:
        raise ValueError(f"Invalid certificate common name: {cn!r}")
    return candidate


def crl_path(root: Path) -> Path:
    return root / "ca.crl"


def api_token_path(root: Path) -> Path:
    return root / "api_token"


def renewal_log_path(root: Path) -> Path:
    return root / "renewal.log"


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

CA_SUBJECT = "/CN=ssltui Local CA/O=ssltui/C=UK"
CA_VALIDITY_DAYS = 1095  # 3 years
LEAF_VALIDITY_DAYS = 180  # default leaf cert lifetime
LEAF_VALIDITY_MAX = 825  # hard cap (Apple/browser limit)
RENEWAL_THRESHOLD_DAYS = 30  # renew if expiry within this window

# Key parameters
RSA_BITS = 4096
EC_CURVE = "secp384r1"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# CN is a DNS hostname or wildcard label — strict allow-list. No path
# separators, no traversal, no control characters.
_CN_RE = re.compile(r"^(\*\.)?([A-Za-z0-9_-]+\.)*[A-Za-z0-9_-]+$")


def validate_cn(cn: str) -> str:
    """Validate a certificate CN against a strict hostname allow-list.

    Returns the stripped CN. Raises ValueError on anything that isn't a plain
    DNS hostname or wildcard (rejecting path separators, ``..``, control chars).
    """
    cn = cn.strip()
    if not cn or len(cn) > 253 or not _CN_RE.match(cn):
        raise ValueError(f"Invalid certificate common name: {cn!r}")
    return cn


def _safe_cn(cn: str) -> str:
    """Map a CN to a safe filesystem name."""
    return cn.replace("*", "wildcard").replace("/", "_")
