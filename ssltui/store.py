"""Cert/key storage and index (JSON)."""

from __future__ import annotations

import fcntl
import json
import threading
from contextlib import contextmanager
from pathlib import Path

from ssltui import config

_thread_lock = threading.Lock()


@contextmanager
def _locked(root: Path):
    """Exclusive lock for read-modify-write transactions on index.json.

    Combines a threading.Lock (in-process) with fcntl.flock (cross-process)
    so concurrent Flask threads and cron processes serialise correctly.
    """
    lock_path = config.index_path(root).with_suffix(".lock")
    with _thread_lock:
        with open(lock_path, "a") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            yield


def _load(root: Path) -> dict:
    p = config.index_path(root)
    if not p.exists():
        return {"certs": {}}
    return json.loads(p.read_text())


def _save(root: Path, data: dict) -> None:
    p = config.index_path(root)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.chmod(0o600)
    tmp.rename(p)  # atomic on POSIX — readers see old or new, never partial


def list_certs(root: Path) -> list[dict]:
    data = _load(root)
    return list(data.get("certs", {}).values())


def get_cert(root: Path, cn: str) -> dict | None:
    data = _load(root)
    return data.get("certs", {}).get(cn)


def add_cert(root: Path, metadata: dict) -> None:
    with _locked(root):
        data = _load(root)
        data.setdefault("certs", {})[metadata["cn"]] = metadata
        _save(root, data)


def remove_cert(root: Path, cn: str) -> None:
    with _locked(root):
        data = _load(root)
        data.get("certs", {}).pop(cn, None)
        _save(root, data)


def list_revoked(root: Path) -> list[dict]:
    data = _load(root)
    return list(data.get("revoked", []))


def add_revoked(root: Path, entry: dict) -> None:
    with _locked(root):
        data = _load(root)
        revoked = data.setdefault("revoked", [])
        if not any(r["serial"] == entry["serial"] for r in revoked):
            revoked.append(entry)
        _save(root, data)


def get_server_fqdn(root: Path) -> str | None:
    """Return the FQDN the dashboard/API server should present a cert for."""
    data = _load(root)
    return data.get("server_fqdn")


def set_server_fqdn(root: Path, fqdn: str | None) -> None:
    with _locked(root):
        data = _load(root)
        if fqdn:
            data["server_fqdn"] = fqdn
        else:
            data.pop("server_fqdn", None)
        _save(root, data)


def next_crl_number(root: Path) -> int:
    with _locked(root):
        data = _load(root)
        n = data.get("crl_number", 0) + 1
        data["crl_number"] = n
        _save(root, data)
    return n


def next_serial(root: Path) -> int:
    with _locked(root):
        data = _load(root)
        n = data.get("serial", 0) + 1
        data["serial"] = n
        _save(root, data)
    return n
