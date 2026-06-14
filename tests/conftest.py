"""Shared fixtures for driving the Textual TUI under tmux."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from collections.abc import Callable, Sequence

import pytest

# Reusable skip marker: these tests launch the real app inside tmux and shell
# out to openssl, so they only run where both are available.
tmux_required = pytest.mark.skipif(
    shutil.which("tmux") is None or shutil.which("openssl") is None,
    reason="requires tmux and openssl on PATH",
)


class TmuxSession:
    """A detached tmux session on a private socket, with screen-scraping helpers."""

    def __init__(self, socket: str, session: str = "app") -> None:
        self.socket = socket
        self.session = session
        self.target = f"{session}:0"

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        # Private socket (-L) so we never touch the user's own tmux server.
        return subprocess.run(
            ["tmux", "-L", self.socket, *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def start(self, command: str, width: int = 200, height: int = 50) -> None:
        """Create the session and run *command* (the app launch line)."""
        r = self._run(
            "new-session", "-d", "-s", self.session, "-x", str(width), "-y", str(height)
        )
        assert r.returncode == 0, r.stderr
        self.send_text(command)
        self.send_keys("Enter")

    def send_keys(self, *keys: str, settle: float = 0.0) -> None:
        """Send tmux key names (e.g. "Enter", "Escape", "C-u", "i").

        With *settle* > 0, pause between each key so Textual can apply the
        resulting state change (e.g. a focus move) before the next key lands —
        avoids races when walking a form with repeated Enter presses.
        """
        for key in keys:
            self._run("send-keys", "-t", self.target, key)
            if settle:
                time.sleep(settle)

    def send_text(self, text: str) -> None:
        """Type *text* literally (no key-name interpretation)."""
        self._run("send-keys", "-t", self.target, "-l", text)

    def capture(self) -> str:
        return self._run("capture-pane", "-p", "-t", self.target).stdout

    def wait_for(self, needle: str, timeout: float = 20.0) -> str:
        """Block until *needle* appears in the pane; return the pane contents."""
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            last = self.capture()
            if needle in last:
                return last
            time.sleep(0.25)
        raise AssertionError(f"timed out waiting for {needle!r}; pane:\n{last}")

    def wait_gone(self, needle: str, timeout: float = 20.0) -> None:
        """Block until *needle* is no longer in the pane (e.g. a modal closed)."""
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            last = self.capture()
            if needle not in last:
                return
            time.sleep(0.25)
        raise AssertionError(f"{needle!r} still on screen; pane:\n{last}")

    def kill(self) -> None:
        self._run("kill-server")


@pytest.fixture
def tmux() -> Callable[[], TmuxSession]:
    """Factory for TmuxSession objects, all torn down at test end."""
    sessions: list[TmuxSession] = []

    def _make(session: str = "app") -> TmuxSession:
        socket = f"ssltui_test_{os.getpid()}_{len(sessions)}"
        s = TmuxSession(socket, session)
        sessions.append(s)
        return s

    try:
        yield _make
    finally:
        for s in sessions:
            s.kill()


@pytest.fixture
def wait_until() -> Callable[..., bool]:
    """Poll *predicate* until it is truthy or the timeout elapses."""

    def _wait(predicate: Callable[[], bool], timeout: float = 20.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.25)
        return False

    return _wait


def launch_cmd(python: str, data_dir: object, extra: Sequence[str] = ()) -> str:
    """Build the shell line that starts the app against *data_dir*."""
    parts = [
        f"SSLTUI_DIR={data_dir}",
        "TEXTUAL_ANIMATIONS=none",
        python,
        "-m",
        "ssltui",
        *extra,
    ]
    return " ".join(str(p) for p in parts)
