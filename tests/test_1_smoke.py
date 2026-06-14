"""Smoke tests: import the package and sanity-check config defaults."""

from __future__ import annotations

import subprocess
import sys

from ssltui import config


def test_package_imports() -> None:
    import ssltui

    assert ssltui is not None


def test_leaf_validity_within_cap() -> None:
    assert config.LEAF_VALIDITY_DAYS <= config.LEAF_VALIDITY_MAX


def test_key_parameters_meet_policy() -> None:
    # CLAUDE.md cipher policy: RSA 4096-bit minimum, EC P-384 preferred.
    assert config.RSA_BITS >= 4096
    assert config.EC_CURVE == "secp384r1"


def test_cli_help_runs() -> None:
    # `ssltui --help` must exit 0 and print usage without drawing the TUI.
    result = subprocess.run(
        [sys.executable, "-m", "ssltui", "--help"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout.lower()
    assert "ssltui" in result.stdout
