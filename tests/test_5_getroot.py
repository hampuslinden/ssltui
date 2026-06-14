"""CLI `getroot` command: prints / saves the root CA certificate."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from ssltui import config
from ssltui.ca import init_ca


def _run(args: list[str], data_dir: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "SSLTUI_DIR": str(data_dir)}
    return subprocess.run(
        [sys.executable, "-m", "ssltui", *args],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )


def test_getroot_prints_ca_pem(tmp_path: Path) -> None:
    data_dir = tmp_path / "ca"
    init_ca(data_dir)

    result = _run(["getroot"], data_dir)
    assert result.returncode == 0, result.stderr
    # stdout is a clean PEM matching the CA cert on disk.
    expected = config.ca_cert_path(data_dir).read_text()
    assert result.stdout == expected
    assert result.stdout.startswith("-----BEGIN CERTIFICATE-----")


def test_getroot_out_writes_file(tmp_path: Path) -> None:
    data_dir = tmp_path / "ca"
    init_ca(data_dir)
    out = tmp_path / "exported.crt"

    result = _run(["getroot", "--out", str(out)], data_dir)
    assert result.returncode == 0, result.stderr
    assert out.exists()
    assert out.read_bytes() == config.ca_cert_path(data_dir).read_bytes()
    # Cert files are world-readable per the project's permission policy.
    assert (out.stat().st_mode & 0o777) == 0o644
    # Nothing is printed to stdout in --out mode (only a status line).
    assert "BEGIN CERTIFICATE" not in result.stdout


def test_getroot_uninitialised_errors(tmp_path: Path) -> None:
    # No CA created in this dir.
    result = _run(["getroot"], tmp_path / "empty")
    assert result.returncode == 1
    assert "not initialised" in result.stderr.lower()
    assert result.stdout == ""
