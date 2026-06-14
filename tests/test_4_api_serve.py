"""End-to-end coverage of the REST API exposed by ``ssltui serve``.

The server is started the way a user starts it -- ``ssltui serve`` running in a
tmux pane (the Textual "serve" UI) -- and shared across the tests in this module
via a module-scoped fixture. Each test drives the public REST API over HTTP with
the Bearer token written at CA init, and every download is compared byte-for-byte
against the corresponding file in the CA data directory.

Endpoints covered:
  GET   /api/v1/certs                 list cert metadata
  POST  /api/v1/certs                 issue a cert
  GET   /api/v1/certs/<cn>            cert metadata
  POST  /api/v1/certs/<cn>/renew      renew a cert
  GET   /api/v1/certs/<cn>/cert.pem   download leaf cert
  GET   /api/v1/certs/<cn>/key.pem    download private key
  GET   /api/v1/certs/<cn>/chain.pem  download chain (leaf + CA)
"""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import TmuxSession, launch_cmd, tmux_required
from ssltui import config, store
from ssltui.ca import init_ca, issue_cert

flask_required = pytest.mark.skipif(
    importlib.util.find_spec("flask") is None,
    reason="requires the optional 'api' extra (flask)",
)

pytestmark = [tmux_required, flask_required]

# Baseline cert issued by the fixture; read-only tests operate on this CN.
BASE_CN = "api.local"
BASE_SANS = ["www.api.local", "10.0.0.5"]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _http(
    method: str, url: str, token: str | None = None, body: dict | None = None
) -> tuple[int, bytes, dict[str, str]]:
    """Make a request; return (status, raw body, headers) without raising.

    A ``token`` of ``None`` omits the Authorization header entirely.
    """
    headers: dict[str, str] = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def _poll(predicate, timeout: float = 20.0, interval: float = 0.25) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _ca_files(data_dir: Path, cn: str) -> tuple[Path, Path, Path]:
    """The leaf cert, key, and chain files the CA wrote for *cn*."""
    d = config.cert_dir(data_dir, cn)
    return d / "cert.crt", d / "cert.key", d / "chain.crt"


@pytest.fixture(scope="module")
def server(tmp_path_factory: pytest.TempPathFactory):
    """Init a CA, issue a baseline cert, and run ``ssltui serve`` over HTTP."""
    data_dir = tmp_path_factory.mktemp("ca-data")
    init_ca(data_dir)
    issue_cert(data_dir, cn=BASE_CN, sans=BASE_SANS, key_type="ec")

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    token = config.api_token_path(data_dir).read_text().strip()

    session = TmuxSession(f"ssltui_api_{os.getpid()}", "api")
    session.start(
        launch_cmd(
            sys.executable,
            data_dir,
            extra=["serve", "--host", "127.0.0.1", "--port", str(port)],
        )
    )

    def _up() -> bool:
        try:
            urllib.request.urlopen(f"{base}/api/v1/certs", timeout=2)
            return True
        except urllib.error.HTTPError:
            return True  # 401 still proves the listener is accepting requests
        except OSError:
            # Covers URLError (connection refused while binding) and a bare
            # TimeoutError during the window after listen() but before the
            # accept loop starts serving. Keep polling.
            return False

    try:
        if not _poll(_up, timeout=30.0):
            pytest.fail(f"server never came up; pane:\n{session.capture()}")
        yield SimpleNamespace(base=base, token=token, data_dir=data_dir)
    finally:
        session.kill()


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #


def test_missing_token_rejected(server) -> None:
    status, _, _ = _http("GET", f"{server.base}/api/v1/certs", token=None)
    assert status == 401


def test_wrong_token_rejected(server) -> None:
    status, _, _ = _http("GET", f"{server.base}/api/v1/certs", token="not-the-token")
    assert status == 401


def test_key_download_requires_auth(server) -> None:
    # Private keys must never be served without a valid token (CLAUDE.md).
    status, _, _ = _http(
        "GET", f"{server.base}/api/v1/certs/{BASE_CN}/key.pem", token=None
    )
    assert status == 401


# --------------------------------------------------------------------------- #
# Listing & metadata
# --------------------------------------------------------------------------- #


def test_list_certs(server) -> None:
    status, body, _ = _http("GET", f"{server.base}/api/v1/certs", server.token)
    assert status == 200
    certs = json.loads(body)
    assert isinstance(certs, list)
    cns = {c["cn"] for c in certs}
    # The API listing matches what the store reports on disk.
    assert cns == {c["cn"] for c in store.list_certs(server.data_dir)}
    assert BASE_CN in cns


def test_cert_metadata(server) -> None:
    status, body, _ = _http(
        "GET", f"{server.base}/api/v1/certs/{BASE_CN}", server.token
    )
    assert status == 200
    meta = json.loads(body)
    on_disk = store.get_cert(server.data_dir, BASE_CN)
    assert on_disk is not None
    assert meta["cn"] == BASE_CN
    assert meta["serial"] == on_disk["serial"]


def test_cert_metadata_unknown_404(server) -> None:
    status, _, _ = _http("GET", f"{server.base}/api/v1/certs/nope.local", server.token)
    assert status == 404


# --------------------------------------------------------------------------- #
# Downloads — every body is compared to the file in the CA directory
# --------------------------------------------------------------------------- #


def test_download_cert_matches_disk(server) -> None:
    cert, _, _ = _ca_files(server.data_dir, BASE_CN)
    status, body, headers = _http(
        "GET", f"{server.base}/api/v1/certs/{BASE_CN}/cert.pem", server.token
    )
    assert status == 200
    assert body == cert.read_bytes()
    assert b"BEGIN CERTIFICATE" in body
    # Served as a download with the expected filename.
    assert "api.local.crt" in headers.get("Content-Disposition", "")


def test_download_key_matches_disk(server) -> None:
    _, key, _ = _ca_files(server.data_dir, BASE_CN)
    status, body, _ = _http(
        "GET", f"{server.base}/api/v1/certs/{BASE_CN}/key.pem", server.token
    )
    assert status == 200
    assert body == key.read_bytes()
    assert b"PRIVATE KEY" in body


def test_download_chain_matches_disk(server) -> None:
    _, _, chain = _ca_files(server.data_dir, BASE_CN)
    status, body, _ = _http(
        "GET", f"{server.base}/api/v1/certs/{BASE_CN}/chain.pem", server.token
    )
    assert status == 200
    assert body == chain.read_bytes()
    # The chain bundles the leaf followed by the CA cert.
    assert body.count(b"BEGIN CERTIFICATE") >= 2
    assert config.ca_cert_path(server.data_dir).read_bytes() in body


def test_download_unknown_404(server) -> None:
    for what in ("cert.pem", "key.pem", "chain.pem"):
        status, _, _ = _http(
            "GET", f"{server.base}/api/v1/certs/nope.local/{what}", server.token
        )
        assert status == 404, what


# --------------------------------------------------------------------------- #
# Issue
# --------------------------------------------------------------------------- #


def test_issue_creates_cert_on_disk(server) -> None:
    cn = "issued.local"
    status, body, _ = _http(
        "POST",
        f"{server.base}/api/v1/certs",
        server.token,
        body={"cn": cn, "sans": ["alt.issued.local"], "key_type": "rsa"},
    )
    assert status == 201, body
    meta = json.loads(body)
    assert meta["cn"] == cn
    assert meta["key_type"] == "rsa"

    cert, key, chain = _ca_files(server.data_dir, cn)
    assert _poll(lambda: cert.exists() and key.exists() and chain.exists())

    # Downloading the freshly issued cert returns exactly what is on disk.
    status, dl_cert, _ = _http(
        "GET", f"{server.base}/api/v1/certs/{cn}/cert.pem", server.token
    )
    assert status == 200
    assert dl_cert == cert.read_bytes()

    status, dl_key, _ = _http(
        "GET", f"{server.base}/api/v1/certs/{cn}/key.pem", server.token
    )
    assert status == 200
    assert dl_key == key.read_bytes()


def test_issue_without_cn_rejected(server) -> None:
    status, _, _ = _http(
        "POST", f"{server.base}/api/v1/certs", server.token, body={"sans": ["x.local"]}
    )
    assert status == 400


# --------------------------------------------------------------------------- #
# Renew
# --------------------------------------------------------------------------- #


def test_renew_reissues_cert(server) -> None:
    cn = "renew.local"
    issue_cert(server.data_dir, cn=cn, key_type="ec")
    before = store.get_cert(server.data_dir, cn)
    assert before is not None
    old_serial = before["serial"]

    status, body, _ = _http(
        "POST", f"{server.base}/api/v1/certs/{cn}/renew", server.token
    )
    assert status == 200, body
    meta = json.loads(body)
    assert meta["serial"] != old_serial

    # The renewed leaf on disk is what the API now serves.
    cert, _, _ = _ca_files(server.data_dir, cn)
    status, dl_cert, _ = _http(
        "GET", f"{server.base}/api/v1/certs/{cn}/cert.pem", server.token
    )
    assert status == 200
    assert dl_cert == cert.read_bytes()
    assert store.get_cert(server.data_dir, cn)["serial"] == meta["serial"]


def test_renew_unknown_404(server) -> None:
    status, _, _ = _http(
        "POST", f"{server.base}/api/v1/certs/nope.local/renew", server.token
    )
    assert status == 404


# --------------------------------------------------------------------------- #
# Sanity: a downloaded cert is a real X.509 cert openssl can parse
# --------------------------------------------------------------------------- #


def test_downloaded_cert_is_valid_x509(server, tmp_path: Path) -> None:
    status, body, _ = _http(
        "GET", f"{server.base}/api/v1/certs/{BASE_CN}/cert.pem", server.token
    )
    assert status == 200
    out_file = tmp_path / "downloaded.crt"
    out_file.write_bytes(body)
    out = subprocess.run(
        ["openssl", "x509", "-in", str(out_file), "-noout", "-subject"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    assert BASE_CN in out.stdout
