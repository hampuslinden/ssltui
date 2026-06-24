"""Unit tests for the SQLite-backed metadata/event store.

These exercise ``ssltui.store`` directly against a temporary CA root — no tmux
and (mostly) no openssl required. A small lifecycle section uses the real CA
helpers and is skipped where openssl is unavailable.
"""

from __future__ import annotations

import importlib.util
import shutil
import threading
from pathlib import Path

import pytest

from ssltui import store

openssl_required = pytest.mark.skipif(
    shutil.which("openssl") is None, reason="requires openssl on PATH"
)
flask_required = pytest.mark.skipif(
    importlib.util.find_spec("flask") is None,
    reason="requires the optional 'api' extra (flask)",
)


def _meta(cn: str, serial: int = 1) -> dict:
    return {
        "cn": cn,
        "sans": [f"DNS:{cn}"],
        "key_type": "ec",
        "serial": serial,
        "issued": "2026-01-01T00:00:00+00:00",
        "expiry": "Jun 13 12:00:00 2026 GMT",
        "validity_days": 180,
        "cert": f"/tmp/{cn}/cert.crt",
        "key": f"/tmp/{cn}/cert.key",
        "chain": f"/tmp/{cn}/chain.crt",
    }


# ---------------------------------------------------------------------------
# Certs
# ---------------------------------------------------------------------------


def test_add_get_list_cert(tmp_path: Path) -> None:
    assert store.list_certs(tmp_path) == []
    assert store.get_cert(tmp_path, "a.local") is None

    store.add_cert(tmp_path, _meta("a.local"))
    store.add_cert(tmp_path, _meta("b.local", serial=2))

    cns = {c["cn"] for c in store.list_certs(tmp_path)}
    assert cns == {"a.local", "b.local"}
    got = store.get_cert(tmp_path, "a.local")
    assert got is not None and got["serial"] == 1


def test_add_cert_upsert(tmp_path: Path) -> None:
    store.add_cert(tmp_path, _meta("a.local", serial=1))
    store.add_cert(tmp_path, _meta("a.local", serial=9))  # same CN -> replace
    assert len(store.list_certs(tmp_path)) == 1
    assert store.get_cert(tmp_path, "a.local")["serial"] == 9


def test_remove_cert(tmp_path: Path) -> None:
    store.add_cert(tmp_path, _meta("a.local"))
    store.remove_cert(tmp_path, "a.local")
    assert store.get_cert(tmp_path, "a.local") is None
    store.remove_cert(tmp_path, "missing.local")  # no-op, must not raise


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


def test_revoked_dedupe(tmp_path: Path) -> None:
    entry = {"cn": "a.local", "serial": 5, "expiry": "x", "revoked_at": "t"}
    store.add_revoked(tmp_path, entry)
    store.add_revoked(tmp_path, entry)  # same serial -> idempotent
    revoked = store.list_revoked(tmp_path)
    assert len(revoked) == 1
    assert revoked[0]["serial"] == 5


# ---------------------------------------------------------------------------
# Counters / version / server fqdn
# ---------------------------------------------------------------------------


def test_counters_monotonic(tmp_path: Path) -> None:
    assert [store.next_serial(tmp_path) for _ in range(3)] == [1, 2, 3]
    assert [store.next_crl_number(tmp_path) for _ in range(2)] == [1, 2]


def test_version_increments_on_writes(tmp_path: Path) -> None:
    assert store.get_version(tmp_path) == 0
    store.add_cert(tmp_path, _meta("a.local"))
    v1 = store.get_version(tmp_path)
    assert v1 >= 1
    store.add_event(tmp_path, "issue", cn="a.local", method="tui")
    assert store.get_version(tmp_path) > v1


def test_server_fqdn_roundtrip(tmp_path: Path) -> None:
    assert store.get_server_fqdn(tmp_path) is None
    store.set_server_fqdn(tmp_path, "host.local")
    assert store.get_server_fqdn(tmp_path) == "host.local"
    store.set_server_fqdn(tmp_path, None)
    assert store.get_server_fqdn(tmp_path) is None


def test_name_suffix_roundtrip(tmp_path: Path) -> None:
    assert store.get_name_suffix(tmp_path) is None
    store.set_name_suffix(tmp_path, "local")
    assert store.get_name_suffix(tmp_path) == "local"
    store.set_name_suffix(tmp_path, None)
    assert store.get_name_suffix(tmp_path) is None


# ---------------------------------------------------------------------------
# Name-suffix policy helpers (config)
# ---------------------------------------------------------------------------


def test_normalize_name_suffix() -> None:
    from ssltui import config

    # Leading dot, surrounding whitespace and case are all normalised away.
    assert config.normalize_name_suffix(".local") == "local"
    assert config.normalize_name_suffix("  Dev.Corp  ") == "dev.corp"
    # Blank / bypass values yield the empty (unrestricted) policy.
    assert config.normalize_name_suffix("") == ""
    assert config.normalize_name_suffix("  .  ") == ""
    # Anything that isn't a plain dotted DNS label sequence is rejected.
    for bad in ("*.local", "a/b", "spa ce", "no_good!"):
        with pytest.raises(ValueError):
            config.normalize_name_suffix(bad)


def test_name_matches_suffix() -> None:
    from ssltui import config

    assert config.name_matches_suffix("app.local", "local")
    assert config.name_matches_suffix("LOCAL", "local")  # equals suffix
    assert config.name_matches_suffix("*.app.local", "local")  # wildcard host
    assert not config.name_matches_suffix("app.dev", "local")
    assert not config.name_matches_suffix("notlocal", "local")  # no dot boundary


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


def test_events_order_and_fields(tmp_path: Path) -> None:
    store.add_event(tmp_path, "issue", cn="a.local", method="cli")
    store.add_event(tmp_path, "key_download", cn="a.local", method="api")
    store.add_event(tmp_path, "revoke", cn="a.local", method="tui", detail="x")

    events = store.list_events(tmp_path)
    assert [e["type"] for e in events] == ["issue", "key_download", "revoke"]
    assert events[1]["method"] == "api"
    assert events[2]["detail"] == "x"
    # ids are strictly increasing in chronological order
    assert events[0]["id"] < events[1]["id"] < events[2]["id"]


def test_events_limit_returns_recent(tmp_path: Path) -> None:
    for i in range(10):
        store.add_event(tmp_path, "issue", cn=f"c{i}.local", method="cli")
    recent = store.list_events(tmp_path, limit=3)
    assert [e["cn"] for e in recent] == ["c7.local", "c8.local", "c9.local"]


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


def test_concurrent_next_serial_unique(tmp_path: Path) -> None:
    # WAL + busy_timeout must serialise writers so no two callers get the same
    # serial even under heavy contention from multiple threads.
    results: list[int] = []
    lock = threading.Lock()

    def worker() -> None:
        local = [store.next_serial(tmp_path) for _ in range(20)]
        with lock:
            results.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 160
    assert len(set(results)) == 160  # all unique
    assert sorted(results) == list(range(1, 161))  # contiguous, no gaps


# ---------------------------------------------------------------------------
# Lifecycle events via the real CA helpers
# ---------------------------------------------------------------------------


@openssl_required
def test_lifecycle_records_events(tmp_path: Path) -> None:
    from ssltui.ca import init_ca, issue_cert, revoke_cert

    init_ca(tmp_path)
    issue_cert(tmp_path, cn="app.local", method="api")
    revoke_cert(tmp_path, "app.local", method="tui")

    events = store.list_events(tmp_path)
    issued = [e for e in events if e["type"] == "issue" and e["cn"] == "app.local"]
    revoked = [e for e in events if e["type"] == "revoke" and e["cn"] == "app.local"]
    assert issued and issued[0]["method"] == "api"
    assert revoked and revoked[0]["method"] == "tui"


@openssl_required
def test_name_suffix_policy_enforced_on_issue(tmp_path: Path) -> None:
    from ssltui.ca import CAError, init_ca, issue_cert

    init_ca(tmp_path, name_suffix=".local")
    assert store.get_name_suffix(tmp_path) == "local"

    # A compliant CN issues fine, even with extra SANs under the suffix.
    meta = issue_cert(tmp_path, cn="app.local", sans=["www.app.local"])
    assert meta["cn"] == "app.local"

    # A CN outside the suffix is rejected.
    with pytest.raises(CAError, match="not permitted by CA policy"):
        issue_cert(tmp_path, cn="app.dev")

    # A compliant CN with a non-compliant DNS SAN is also rejected, and the
    # offending name is named.
    with pytest.raises(CAError, match="bad.example"):
        issue_cert(tmp_path, cn="ok.local", sans=["bad.example"])

    # IP SANs are exempt from the hostname suffix policy.
    meta = issue_cert(tmp_path, cn="api.local", sans=["10.0.0.1"])
    assert "IP:10.0.0.1" in meta["sans"]


@openssl_required
def test_no_name_suffix_allows_any_name(tmp_path: Path) -> None:
    from ssltui.ca import init_ca, issue_cert

    init_ca(tmp_path)  # no policy
    assert store.get_name_suffix(tmp_path) is None
    meta = issue_cert(tmp_path, cn="anything.example")
    assert meta["cn"] == "anything.example"


@openssl_required
def test_name_suffix_rejects_noncompliant_server_fqdn(tmp_path: Path) -> None:
    from ssltui.ca import CAError, init_ca

    # The default server cert must satisfy the policy too, so init fails clearly.
    with pytest.raises(CAError, match="not permitted by CA policy"):
        init_ca(tmp_path, name_suffix=".local", server_fqdn="ca.example")


@openssl_required
@flask_required
def test_api_key_download_records_event(tmp_path: Path) -> None:
    from ssltui.api import create_app
    from ssltui.ca import init_ca, issue_cert
    from ssltui.config import api_token_path

    init_ca(tmp_path)
    issue_cert(tmp_path, cn="app.local", method="api")
    token = api_token_path(tmp_path).read_text()

    app = create_app(tmp_path, token)
    client = app.test_client()
    resp = client.get(
        "/api/v1/certs/app.local/key.pem",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200

    downloads = [e for e in store.list_events(tmp_path) if e["type"] == "key_download"]
    assert downloads and downloads[-1]["cn"] == "app.local"
    assert downloads[-1]["method"] == "api"
