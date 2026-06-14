"""Paths, defaults, and validated configuration."""

from __future__ import annotations

import os
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
    return root / "certs" / _safe_cn(cn)


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


def _safe_cn(cn: str) -> str:
    """Map a CN to a safe filesystem name."""
    return cn.replace("*", "wildcard").replace("/", "_")
