"""Expiry checks and renewal logic for headless --renew mode."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ssltui import config, store
from ssltui.ca import renew_cert, CAError


def _parse_expiry(expiry_str: str) -> datetime:
    """Parse the openssl 'notAfter' date string to a UTC datetime."""
    # Format: "Jun 13 12:00:00 2026 GMT"
    return datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def days_until_expiry(expiry_str: str) -> int:
    exp = _parse_expiry(expiry_str)
    delta = exp - datetime.now(timezone.utc)
    return delta.days


def certs_expiring_within(root: Path, threshold_days: int = config.RENEWAL_THRESHOLD_DAYS) -> list[dict]:
    return [
        c for c in store.list_certs(root)
        if days_until_expiry(c["expiry"]) <= threshold_days
    ]


def renew_all(root: Path, threshold_days: int = config.RENEWAL_THRESHOLD_DAYS) -> list[tuple[str, bool, str]]:
    """Renew all certs expiring within threshold.

    Returns list of (cn, success, message).
    """
    results = []
    for cert in certs_expiring_within(root, threshold_days):
        cn = cert["cn"]
        try:
            renew_cert(root, cn)
            results.append((cn, True, "renewed"))
        except CAError as exc:
            results.append((cn, False, str(exc)))
    return results


def refresh_crl(root: Path, threshold_days: int = 7) -> bool:
    """Append a fresh CRL block to ca.crl if it is missing or the last block
    expires within *threshold_days*. Returns True if a new block was appended.
    """
    from ssltui.ca import generate_crl, run_openssl

    crl_path = config.crl_path(root)
    if not crl_path.exists():
        generate_crl(root)
        return True

    last_pem = _last_crl_pem(crl_path)
    if last_pem is None:
        generate_crl(root)
        return True

    try:
        out = run_openssl(["crl", "-noout", "-nextupdate"], input=last_pem)
        next_update_str = out.decode().strip().split("=", 1)[-1]
        next_update = datetime.strptime(next_update_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        if (next_update - datetime.now(timezone.utc)).days <= threshold_days:
            generate_crl(root)
            return True
    except (CAError, ValueError):
        generate_crl(root)
        return True

    return False


def _last_crl_pem(crl_path: Path) -> bytes | None:
    """Return the last PEM CRL block from ca.crl, or None if the file is empty."""
    text = crl_path.read_text()
    begin = "-----BEGIN X509 CRL-----"
    end = "-----END X509 CRL-----"
    last_start = text.rfind(begin)
    if last_start == -1:
        return None
    last_end = text.find(end, last_start)
    if last_end == -1:
        return None
    return text[last_start: last_end + len(end)].encode()
