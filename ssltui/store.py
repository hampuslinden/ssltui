"""Cert/key metadata and event store (SQLite).

A single ``ca.db`` in the CA root holds the cert index, revocation list, an
append-only event log, and small counters (serial, CRL number, version). All
access goes through the module functions below; callers never touch the DB
directly. WAL mode plus a busy timeout let the TUI, the cron ``--renew``
process, and the multi-threaded Flask API read and write concurrently without
explicit file locking.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from ssltui import config


@contextmanager
def _connect(root: Path) -> Iterator[sqlite3.Connection]:
    """Open a connection to the CA database, creating the schema if needed.

    A fresh connection per call keeps the module functions stateless and
    sidesteps SQLite's cross-thread restrictions under Flask. The transaction
    is committed on clean exit (rolled back on error) and the connection is
    always closed.
    """
    conn = sqlite3.connect(config.db_path(root))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS certs (
            cn   TEXT PRIMARY KEY,
            data TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS revoked (
            serial TEXT PRIMARY KEY,
            data   TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS events (
            id     INTEGER PRIMARY KEY AUTOINCREMENT,
            ts     TEXT NOT NULL,
            type   TEXT NOT NULL,
            cn     TEXT,
            method TEXT,
            detail TEXT
        );
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        """
    )
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def _bump_version(conn: sqlite3.Connection) -> None:
    """Increment the change counter that watchers poll for refresh."""
    conn.execute(
        "INSERT INTO meta (key, value) VALUES ('version', '1') "
        "ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1"
    )


def _incr(conn: sqlite3.Connection, key: str) -> int:
    """Atomically increment an integer counter in ``meta`` and return it."""
    row = conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, '1') "
        "ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1 "
        "RETURNING value",
        (key,),
    ).fetchone()
    return int(row[0])


# ---------------------------------------------------------------------------
# Certs
# ---------------------------------------------------------------------------


def _exists(root: Path) -> bool:
    """True once the database has been created (i.e. after CA init / first write).

    Reads tolerate a missing DB so the TUI can render an empty list before the
    CA exists; writes always run after init_ca has created the root directory.
    """
    return config.db_path(root).exists()


def list_certs(root: Path) -> list[dict]:
    if not _exists(root):
        return []
    with _connect(root) as conn:
        rows = conn.execute("SELECT data FROM certs ORDER BY cn").fetchall()
    return [json.loads(r["data"]) for r in rows]


def get_cert(root: Path, cn: str) -> dict | None:
    if not _exists(root):
        return None
    with _connect(root) as conn:
        row = conn.execute("SELECT data FROM certs WHERE cn = ?", (cn,)).fetchone()
    return json.loads(row["data"]) if row else None


def add_cert(root: Path, metadata: dict) -> None:
    with _connect(root) as conn:
        conn.execute(
            "INSERT INTO certs (cn, data) VALUES (?, ?) "
            "ON CONFLICT(cn) DO UPDATE SET data = excluded.data",
            (metadata["cn"], json.dumps(metadata)),
        )
        _bump_version(conn)


def remove_cert(root: Path, cn: str) -> None:
    with _connect(root) as conn:
        conn.execute("DELETE FROM certs WHERE cn = ?", (cn,))
        _bump_version(conn)


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


def list_revoked(root: Path) -> list[dict]:
    if not _exists(root):
        return []
    with _connect(root) as conn:
        rows = conn.execute("SELECT data FROM revoked ORDER BY serial").fetchall()
    return [json.loads(r["data"]) for r in rows]


def add_revoked(root: Path, entry: dict) -> None:
    with _connect(root) as conn:
        # PRIMARY KEY on serial makes this idempotent — a repeated revoke is a no-op.
        conn.execute(
            "INSERT OR IGNORE INTO revoked (serial, data) VALUES (?, ?)",
            (str(entry["serial"]), json.dumps(entry)),
        )
        _bump_version(conn)


# ---------------------------------------------------------------------------
# Events (audit log + dashboard live feed)
# ---------------------------------------------------------------------------


def add_event(
    root: Path,
    type: str,
    *,
    cn: str | None = None,
    method: str | None = None,
    detail: str | None = None,
) -> None:
    """Append an event row. ``type`` is e.g. issue/revoke/renew/key_download."""
    ts = datetime.now(UTC).isoformat()
    with _connect(root) as conn:
        conn.execute(
            "INSERT INTO events (ts, type, cn, method, detail) VALUES (?, ?, ?, ?, ?)",
            (ts, type, cn, method, detail),
        )
        _bump_version(conn)


def list_events(root: Path, limit: int | None = 50) -> list[dict]:
    """Return the most recent events, oldest first. ``limit=None`` returns all."""
    if not _exists(root):
        return []
    with _connect(root) as conn:
        if limit is None:
            rows = conn.execute(
                "SELECT id, ts, type, cn, method, detail FROM events ORDER BY id DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, ts, type, cn, method, detail FROM events "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
    return [dict(r) for r in reversed(rows)]


# ---------------------------------------------------------------------------
# Server FQDN / counters / version
# ---------------------------------------------------------------------------


def get_server_fqdn(root: Path) -> str | None:
    """Return the FQDN the dashboard/API server should present a cert for."""
    if not _exists(root):
        return None
    with _connect(root) as conn:
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'server_fqdn'"
        ).fetchone()
    return row["value"] if row else None


def set_server_fqdn(root: Path, fqdn: str | None) -> None:
    with _connect(root) as conn:
        if fqdn:
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('server_fqdn', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (fqdn,),
            )
        else:
            conn.execute("DELETE FROM meta WHERE key = 'server_fqdn'")
        _bump_version(conn)


def get_name_suffix(root: Path) -> str | None:
    """Return the CA's required CN/SAN name suffix, or None if unrestricted."""
    if not _exists(root):
        return None
    with _connect(root) as conn:
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'name_suffix'"
        ).fetchone()
    return row["value"] if row else None


def set_name_suffix(root: Path, suffix: str | None) -> None:
    """Set (or clear, with a falsy value) the required CN/SAN name suffix."""
    with _connect(root) as conn:
        if suffix:
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('name_suffix', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (suffix,),
            )
        else:
            conn.execute("DELETE FROM meta WHERE key = 'name_suffix'")
        _bump_version(conn)


def next_crl_number(root: Path) -> int:
    with _connect(root) as conn:
        n = _incr(conn, "crl_number")
        _bump_version(conn)
    return n


def next_serial(root: Path) -> int:
    with _connect(root) as conn:
        n = _incr(conn, "serial")
        _bump_version(conn)
    return n


def get_version(root: Path) -> int:
    """Monotonic counter bumped on every write — watchers poll this to refresh."""
    if not _exists(root):
        return 0
    with _connect(root) as conn:
        row = conn.execute("SELECT value FROM meta WHERE key = 'version'").fetchone()
    return int(row["value"]) if row else 0
