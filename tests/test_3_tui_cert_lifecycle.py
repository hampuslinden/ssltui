"""End-to-end TUI test: issue a cert, download (save) it, then revoke it.

The CA itself is created directly via ``init_ca`` (that path is exercised by
test_tui_init.py); this test focuses on driving the issue / view-and-save /
revoke flows through the real Textual UI under tmux.
"""

from __future__ import annotations

import sys
from pathlib import Path

from conftest import launch_cmd, tmux_required
from ssltui import config, store
from ssltui.ca import init_ca

pytestmark = tmux_required

CN = "app.local"


@tmux_required
def test_tui_issue_download_revoke(tmux, wait_until, tmp_path: Path) -> None:
    data_dir = tmp_path / "ca-data"
    init_ca(data_dir)  # CA must already exist before issuing.

    session = tmux()
    session.start(launch_cmd(sys.executable, data_dir))
    session.wait_for("CA ready")

    # --- Issue a certificate -------------------------------------------- #
    # 'n' opens the New Cert modal.
    session.send_keys("n")
    session.wait_for("Issue New Certificate")

    # Type the CN, then Enter walks focus CN -> SANs -> validity -> submit.
    # SANs left blank; validity keeps its 180-day default (< 200, no confirm).
    # Settle between Enters so each focus move is applied before the next key,
    # otherwise a queued Enter re-submits the same field and never advances.
    session.send_text(CN)
    session.send_keys("Enter", "Enter", "Enter", settle=0.4)

    cert_file = config.cert_dir(data_dir, CN) / "cert.crt"
    assert wait_until(cert_file.exists, timeout=30.0), (
        f"cert not issued; pane:\n{session.capture()}"
    )
    # Modal closes and we land back on the main table listing the new CN.
    session.wait_gone("Issue New Certificate")
    assert store.get_cert(data_dir, CN) is not None

    # --- Download (save) the cert via the viewer ------------------------ #
    # The new cert is the only/selected row; 'd' opens the PEM viewer.
    session.send_keys("d")
    session.wait_for("BEGIN CERTIFICATE")

    # 's' opens the save dialog; clear its default path and type our own.
    session.send_keys("s")
    session.wait_for("Save Certificate")
    download = tmp_path / "downloaded.crt"
    session.send_keys("C-e", "C-u", settle=0.3)  # end-of-line, then delete to start
    session.send_text(str(download))
    session.send_keys("Enter", settle=0.3)

    assert wait_until(download.exists), f"cert not saved; pane:\n{session.capture()}"
    pem = download.read_text()
    assert "BEGIN CERTIFICATE" in pem
    # Saved leaf must match what the CA wrote to the store.
    assert pem.strip() == cert_file.read_text().strip()

    # Back out of the viewer to the main screen.
    session.wait_gone("Save Certificate")
    session.send_keys("Escape")
    session.wait_gone("BEGIN CERTIFICATE")

    # --- Revoke the cert ------------------------------------------------ #
    session.send_keys("x")
    session.wait_for(f"Revoke {CN}")
    session.send_keys("y")  # confirm

    cert_dir = config.cert_dir(data_dir, CN)
    revoked = wait_until(
        lambda: not cert_dir.exists() and store.get_cert(data_dir, CN) is None
    )
    assert revoked, f"cert not revoked; pane:\n{session.capture()}"
    # The download we already saved is untouched by revocation.
    assert download.exists()
