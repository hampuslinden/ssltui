"""End-to-end TUI test: drive `ssltui` under tmux to initialise a CA.

This launches the real Textual application inside a detached tmux session,
sends the keystrokes a user would press to create a root CA, and asserts the
expected files land on disk. It is slower and heavier than the smoke tests, so
it is skipped automatically when tmux/openssl are unavailable.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from conftest import launch_cmd, tmux_required

pytestmark = tmux_required


@tmux_required
def test_tui_init_ca_creates_files(tmux, wait_until, tmp_path: Path) -> None:
    data_dir = tmp_path / "ca-data"
    session = tmux()
    session.start(launch_cmd(sys.executable, data_dir))

    # Main screen renders the "not initialised" banner.
    session.wait_for("CA not initialised")

    # 'i' opens the Init CA modal.
    session.send_keys("i")
    session.wait_for("Initialise Certificate Authority")

    # Enter accepts the defaults (EC P-384, default subject) and creates it.
    session.send_keys("Enter")

    ca_key = data_dir / "ca.key"
    ca_crt = data_dir / "ca.crt"
    ca_crl = data_dir / "ca.crl"
    api_token = data_dir / "api_token"

    created = wait_until(
        lambda: all(p.exists() for p in (ca_key, ca_crt, ca_crl, api_token))
    )
    assert created, f"CA files not created; pane:\n{session.capture()}"

    # ca.crt must be a parseable X.509 cert carrying the default subject.
    out = subprocess.run(
        ["openssl", "x509", "-in", str(ca_crt), "-noout", "-subject"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    assert "ssltui Local CA" in out.stdout

    # Private material must be owner-only per CLAUDE.md (keys -> 0o600).
    assert (ca_key.stat().st_mode & 0o777) == 0o600
    assert (api_token.stat().st_mode & 0o777) == 0o600
