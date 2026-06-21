"""Textual TUI for ssltui."""

from __future__ import annotations

import csv
import io
import logging
import queue as _queue
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.coordinate import Coordinate
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RadioButton,
    RadioSet,
    RichLog,
    Static,
)

from ssltui import config, store
from ssltui.ca import (
    CAError,
    ca_expiry,
    ca_fingerprint,
    ca_subject,
    init_ca,
    issue_cert,
    renew_cert,
    revoke_cert,
)
from ssltui.renewal import days_until_expiry

if TYPE_CHECKING:
    from ssltui.api import APIServer


class _WerkzeugCapture(logging.Handler):
    """Routes werkzeug request log lines into a queue for the TUI to consume."""

    def __init__(self, q: _queue.Queue) -> None:
        super().__init__()
        self._q = q

    def emit(self, record: logging.LogRecord) -> None:
        self._q.put(self.format(record))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _root() -> Path:
    return config.data_dir()


def _audit_csv(root: Path) -> str:
    """Render the full stored event log as CSV text (matches the API export)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "timestamp", "type", "cn", "method", "detail"])
    for ev in store.list_events(root, limit=None):
        writer.writerow(
            [
                ev.get("id", ""),
                ev.get("ts") or "",
                ev.get("type") or "",
                ev.get("cn") or "",
                ev.get("method") or "",
                ev.get("detail") or "",
            ]
        )
    return buf.getvalue()


def _expiry_style(days: int) -> str:
    if days < 0:
        return "bold red"
    if days <= 14:
        return "red"
    if days <= 30:
        return "yellow"
    return "green"


# Event type → (Rich style, human label) for the dashboard server log.
_EVENT_STYLE: dict[str, tuple[str, str]] = {
    "issue": ("green", "cert issued"),
    "renew": ("cyan", "cert renewed"),
    "revoke": ("yellow", "cert revoked"),
    "key_download": ("bold yellow", "key downloaded"),
    "ca_init": ("bold red", "CA re-initialised"),
}


def _format_tui_event(ev: dict) -> tuple[str, str]:
    """Map a stored event row to a (style, message) pair for the request log."""
    style, label = _EVENT_STYLE.get(ev["type"], ("dim", ev["type"]))
    method = ev.get("method")
    suffix = f" ({method})" if method else ""
    cn = ev.get("cn")
    msg = f"{label}{suffix}: {cn}" if cn else f"{label}{suffix}"
    return style, msg


# ---------------------------------------------------------------------------
# Confirm modal (used for destructive actions)
# ---------------------------------------------------------------------------


class ConfirmScreen(ModalScreen):
    """Ask for confirmation before a destructive action. Dismisses True/False."""

    BINDINGS = [
        Binding("y", "confirm", "Yes"),
        Binding("n", "cancel", "No"),
        Binding("escape", "cancel", "No"),
    ]

    DEFAULT_CSS = """
    ConfirmScreen { align: center middle; }
    ConfirmScreen > Vertical {
        width: 60; height: auto;
        background: $surface; border: thick $error; padding: 1 2;
    }
    ConfirmScreen .title { text-align: center; text-style: bold; color: $error; margin-bottom: 1; }
    ConfirmScreen .message { text-align: center; margin-bottom: 1; }
    ConfirmScreen .hint { text-align: center; color: $text-muted; }
    """

    def __init__(self, title: str, message: str) -> None:
        super().__init__()
        self._title = title
        self._message = message

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self._title, classes="title")
            yield Label(self._message, classes="message")
            yield Label(
                "[dim]y[/dim] confirm  [dim]n / Esc[/dim] cancel",
                markup=True,
                classes="hint",
            )
            with Horizontal():
                yield Button("Yes [y]", variant="error", id="yes")
                yield Button("No [n]", variant="primary", id="no")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class ErrorScreen(ModalScreen):
    """Show a blocking error message with a single dismiss action."""

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("enter", "close", "Close"),
    ]

    DEFAULT_CSS = """
    ErrorScreen { align: center middle; }
    ErrorScreen > Vertical {
        width: 60; height: auto;
        background: $surface; border: thick $error; padding: 1 2;
    }
    ErrorScreen .title { text-align: center; text-style: bold; color: $error; margin-bottom: 1; }
    ErrorScreen .message { text-align: center; margin-bottom: 1; }
    ErrorScreen .hint { text-align: center; color: $text-muted; }
    """

    def __init__(self, title: str, message: str) -> None:
        super().__init__()
        self._title = title
        self._message = message

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self._title, classes="title")
            yield Label(self._message, classes="message")
            yield Label("[dim]Enter / Esc[/dim] close", markup=True, classes="hint")
            yield Button("OK", variant="primary", id="ok")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------------------
# Init CA modal
# ---------------------------------------------------------------------------


class InitCAScreen(ModalScreen):
    """Modal to initialise the CA."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("enter", "create", "Create", priority=True, show=False),
    ]

    DEFAULT_CSS = """
    InitCAScreen { align: center middle; }
    InitCAScreen > Vertical {
        width: 90; height: auto;
        background: $surface; border: thick $primary; padding: 1 2;
    }
    InitCAScreen .title { text-align: center; text-style: bold; margin-bottom: 1; }
    InitCAScreen .hint { color: $text-muted; margin-bottom: 1; }
    InitCAScreen #error { color: red; height: auto; }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Initialise Certificate Authority", classes="title")
            yield Label("CA Subject (DN)")
            yield Input(value=config.CA_SUBJECT, id="subject")
            yield Label("Dashboard / API server FQDN (optional)")
            yield Label(
                "Issues a default HTTPS cert for this host so 'ssltui serve' "
                "can use it. Leave blank for HTTP only.",
                classes="hint",
            )
            yield Input(placeholder="e.g. ca.myhost.local", id="server_fqdn")
            yield Label("Key type")
            with RadioSet(id="key_type"):
                yield RadioButton("EC P-384 (recommended)", value=True, id="ec")
                yield RadioButton("RSA 4096", id="rsa")
            yield Static("", id="error")
            with Horizontal():
                yield Button("Create CA", variant="primary", id="create")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        inp = self.query_one("#subject", Input)
        inp.focus()
        inp.action_end()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._do_create()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.action_cancel()
        else:
            self._do_create()

    def action_create(self) -> None:
        self._do_create()

    def action_cancel(self) -> None:
        self.dismiss(False)

    def _do_create(self) -> None:
        subject = self.query_one("#subject", Input).value.strip()
        server_fqdn = self.query_one("#server_fqdn", Input).value.strip()
        rs = self.query_one("#key_type", RadioSet)
        key_type = (
            "rsa" if rs.pressed_button and rs.pressed_button.id == "rsa" else "ec"
        )
        try:
            init_ca(
                _root(),
                key_type=key_type,
                subject=subject or None,
                server_fqdn=server_fqdn or None,
            )
            self.dismiss(True)
        except CAError as exc:
            self.query_one("#error", Static).update(str(exc))


# ---------------------------------------------------------------------------
# Issue cert modal
# ---------------------------------------------------------------------------


class IssueCertScreen(ModalScreen):
    """Modal form for issuing a new certificate."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    DEFAULT_CSS = """
    IssueCertScreen { align: center middle; }
    IssueCertScreen > Vertical {
        width: 90; height: auto;
        background: $surface; border: thick $primary; padding: 1 2;
    }
    IssueCertScreen .title { text-align: center; text-style: bold; margin-bottom: 1; }
    IssueCertScreen .hint { color: $text-muted; margin-bottom: 1; }
    IssueCertScreen #error { color: red; height: auto; }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Issue New Certificate", classes="title")
            yield Label("Common Name (CN)")
            yield Input(placeholder="e.g. myapp.local or *.myapp.local", id="cn")
            yield Label("Subject Alternative Names (SANs)")
            yield Label(
                "Comma or space-separated DNS names and IPs. The CN is included automatically.",
                classes="hint",
            )
            yield Input(
                placeholder="e.g. www.myapp.local, api.myapp.local, 192.168.1.10",
                id="sans",
            )
            yield Label("Validity (days, max 825)")
            yield Input(value=str(config.LEAF_VALIDITY_DAYS), id="validity")
            yield Label("Key type")
            with RadioSet(id="key_type"):
                yield RadioButton("EC P-384 (recommended)", value=True, id="ec")
                yield RadioButton("RSA 4096", id="rsa")
            yield Static("", id="error")
            with Horizontal():
                yield Button("Issue", variant="primary", id="issue")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#cn", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "cn":
            self.query_one("#sans", Input).focus()
        elif event.input.id == "sans":
            self.query_one("#validity", Input).focus()
        elif event.input.id == "validity":
            self._do_issue()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.action_cancel()
        else:
            self._do_issue()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _do_issue(self) -> None:
        import re

        cn = self.query_one("#cn", Input).value.strip()
        sans_raw = self.query_one("#sans", Input).value.strip()
        validity_raw = self.query_one("#validity", Input).value.strip()
        rs = self.query_one("#key_type", RadioSet)
        key_type = (
            "rsa" if rs.pressed_button and rs.pressed_button.id == "rsa" else "ec"
        )

        error = self.query_one("#error", Static)

        if not cn:
            error.update("CN is required.")
            self.query_one("#cn", Input).focus()
            return

        if store.get_cert(_root(), cn) is not None:
            self.app.push_screen(
                ErrorScreen(
                    title="Certificate already exists",
                    message=(
                        f"A certificate for '{cn}' already exists.\n"
                        "Revoke it before issuing a new one."
                    ),
                )
            )
            return

        try:
            validity = int(validity_raw)
        except ValueError:
            error.update("Validity must be a number.")
            self.query_one("#validity", Input).focus()
            return

        if validity < 1 or validity > config.LEAF_VALIDITY_MAX:
            error.update(f"Validity must be between 1 and {config.LEAF_VALIDITY_MAX}.")
            self.query_one("#validity", Input).focus()
            return

        sans_list = [s.strip() for s in re.split(r"[,\s]+", sans_raw) if s.strip()]

        if validity >= 200:
            self._pending_issue = dict(
                cn=cn, sans=sans_list, key_type=key_type, validity=validity
            )
            self.app.push_screen(
                ConfirmScreen(
                    title=f"Validity: {validity} days",
                    message="Most browsers reject certs over 200 days. Issue anyway?",
                ),
                self._on_long_validity_confirmed,
            )
            return

        self._issue_cert(cn, sans_list, key_type, validity)

    def _on_long_validity_confirmed(self, confirmed: bool) -> None:
        if not confirmed:
            return
        p = self._pending_issue
        self._issue_cert(p["cn"], p["sans"], p["key_type"], p["validity"])

    def _issue_cert(
        self, cn: str, sans_list: list, key_type: str, validity: int
    ) -> None:
        try:
            meta = issue_cert(
                _root(),
                cn=cn,
                sans=sans_list,
                key_type=key_type,
                validity_days=validity,
            )
            self.dismiss(meta)
        except CAError as exc:
            self.query_one("#error", Static).update(str(exc))


# ---------------------------------------------------------------------------
# Cert detail modal
# ---------------------------------------------------------------------------


class CertDetailScreen(ModalScreen):
    """Show cert details with force-renew / revoke actions."""

    BINDINGS = [
        Binding("escape", "close_detail", "Close"),
        Binding("r", "renew", "Renew"),
        Binding("x", "revoke", "Revoke"),
    ]

    DEFAULT_CSS = """
    CertDetailScreen { align: center middle; }
    CertDetailScreen > Vertical {
        width: 90; height: auto;
        background: $surface; border: thick $primary; padding: 1 2;
    }
    CertDetailScreen .title { text-align: center; text-style: bold; margin-bottom: 1; }
    CertDetailScreen .kv { margin-bottom: 0; }
    CertDetailScreen #status { height: auto; margin-top: 1; }
    """

    def __init__(self, entry: dict) -> None:
        super().__init__()
        self._entry = entry

    def compose(self) -> ComposeResult:
        e = self._entry
        days = days_until_expiry(e["expiry"])
        style = _expiry_style(days)

        with Vertical():
            yield Label(f"Certificate: {e['cn']}", classes="title")
            yield Label(f"[b]CN:[/b]     {e['cn']}", markup=True, classes="kv")
            yield Label(
                f"[b]SANs:[/b]   {', '.join(e['sans'])}", markup=True, classes="kv"
            )
            yield Label(
                f"[b]Key:[/b]    {e.get('key_type', 'ec').upper()}",
                markup=True,
                classes="kv",
            )
            yield Label(f"[b]Serial:[/b] {e['serial']}", markup=True, classes="kv")
            yield Label(f"[b]Issued:[/b] {e['issued'][:10]}", markup=True, classes="kv")
            yield Label(f"[b]Expires:[/b]{e['expiry']}", markup=True, classes="kv")
            yield Label(
                f"[b]Days:[/b]   [{style}]{days}[/{style}]", markup=True, classes="kv"
            )
            yield Label(f"[b]Cert:[/b]   {e['cert']}", markup=True, classes="kv")
            yield Label(f"[b]Key:[/b]    {e['key']}", markup=True, classes="kv")
            yield Label(f"[b]Chain:[/b]  {e['chain']}", markup=True, classes="kv")
            yield Static("", id="status")
            with Horizontal():
                yield Button("Renew [r]", variant="primary", id="renew")
                yield Button("Revoke [x]", variant="error", id="revoke")
                yield Button("Close [Esc]", id="close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close":
            self.action_close_detail()
        elif event.button.id == "renew":
            self.action_renew()
        elif event.button.id == "revoke":
            self.action_revoke()

    def action_close_detail(self) -> None:
        self.dismiss("close")

    def action_renew(self) -> None:
        cn = self._entry["cn"]
        try:
            renew_cert(_root(), cn)
            self.query_one("#status", Static).update("[green]Renewed.[/green]")
            self.dismiss("renewed")
        except CAError as exc:
            self.query_one("#status", Static).update(f"[red]{exc}[/red]")

    def action_revoke(self) -> None:
        cn = self._entry["cn"]
        try:
            revoke_cert(_root(), cn)
            self.dismiss("revoked")
        except CAError as exc:
            self.query_one("#status", Static).update(f"[red]{exc}[/red]")


# ---------------------------------------------------------------------------
# Change CA root directory modal
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# API token modal
# ---------------------------------------------------------------------------


class TokenScreen(ModalScreen):
    """Display the API Bearer token with copy support."""

    BINDINGS = [
        Binding("y", "copy", "Copy"),
        Binding("escape", "close", "Close"),
    ]

    DEFAULT_CSS = """
    TokenScreen { align: center middle; }
    TokenScreen > Vertical {
        width: 84; height: auto;
        background: $surface; border: thick $primary; padding: 1 2;
    }
    TokenScreen .title  { text-align: center; text-style: bold; margin-bottom: 1; }
    TokenScreen .hint   { color: $text-muted; margin-bottom: 1; }
    TokenScreen .token  { color: $accent; text-style: bold; margin: 1 0; }
    """

    def __init__(self, token: str) -> None:
        super().__init__()
        self._token = token

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("API Bearer Token", classes="title")
            yield Label(
                "Pass this in the Authorization header:\n"
                "  Authorization: Bearer <token>",
                classes="hint",
            )
            yield Label(self._token, classes="token")
            yield Label(
                "[dim]y[/dim] copy  [dim]Esc[/dim] close", markup=True, classes="hint"
            )
            with Horizontal():
                yield Button("Copy [y]", variant="primary", id="copy")
                yield Button("Close [Esc]", id="close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "copy":
            self.action_copy()
        else:
            self.action_close()

    def action_copy(self) -> None:
        self.app.copy_to_clipboard(self._token)
        self.notify("Token copied to clipboard.")

    def action_close(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------------------
# curl issue-example modal
# ---------------------------------------------------------------------------


class IssueExampleScreen(ModalScreen):
    """Show a ready-to-run curl command for issuing a cert via the API.

    The Bearer token is masked on screen by default (so it is safe to share a
    screenshot) and can be revealed or copied in full.
    """

    MASK = "••••••••••••••••"

    BINDINGS = [
        Binding("y", "copy", "Copy"),
        Binding("r", "toggle_reveal", "Reveal token"),
        Binding("escape", "close", "Close"),
    ]

    DEFAULT_CSS = """
    IssueExampleScreen { align: center middle; }
    IssueExampleScreen > Vertical {
        width: 92; height: auto;
        background: $surface; border: thick $primary; padding: 1 2;
    }
    IssueExampleScreen .title { text-align: center; text-style: bold; margin-bottom: 1; }
    IssueExampleScreen .hint  { color: $text-muted; margin-bottom: 1; }
    IssueExampleScreen #cmd   { color: $accent; margin: 1 0; }
    """

    def __init__(self, base_url: str, token: str) -> None:
        super().__init__()
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._revealed = False

    def _curl(self, token: str) -> str:
        return (
            f"curl -X POST {self._base_url}/api/v1/certs \\\n"
            f'  -H "Authorization: Bearer {token}" \\\n'
            f'  -H "Content-Type: application/json" \\\n'
            '  -d \'{"cn": "app.local", "sans": ["www.app.local"], '
            '"key_type": "ec", "validity_days": 180}\''
        )

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Issue a Certificate — curl example", classes="title")
            yield Label(
                "POST /api/v1/certs  ·  body fields: cn (required), sans, "
                "key_type (ec|rsa), validity_days",
                classes="hint",
            )
            yield Static(self._curl(self.MASK), id="cmd", markup=False)
            yield Label(
                "[dim]y[/dim] copy (real token)  [dim]r[/dim] reveal token  [dim]Esc[/dim] close",
                markup=True,
                classes="hint",
            )
            with Horizontal():
                yield Button("Copy [y]", variant="primary", id="copy")
                yield Button("Reveal [r]", id="reveal")
                yield Button("Close [Esc]", id="close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "copy":
            self.action_copy()
        elif event.button.id == "reveal":
            self.action_toggle_reveal()
        else:
            self.action_close()

    def action_toggle_reveal(self) -> None:
        self._revealed = not self._revealed
        token = self._token if self._revealed else self.MASK
        self.query_one("#cmd", Static).update(self._curl(token))
        self.query_one("#reveal", Button).label = (
            "Hide [r]" if self._revealed else "Reveal [r]"
        )

    def action_copy(self) -> None:
        self.app.copy_to_clipboard(self._curl(self._token))
        self.notify("curl command (with token) copied to clipboard.")

    def action_close(self) -> None:
        self.dismiss(None)


# ---------------------------------------------------------------------------
# Save-to-path modal
# ---------------------------------------------------------------------------


class SaveCertScreen(ModalScreen):
    """Prompt for a filesystem path then write the PEM there."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    DEFAULT_CSS = """
    SaveCertScreen { align: center middle; }
    SaveCertScreen > Vertical {
        width: 90; height: auto;
        background: $surface; border: thick $primary; padding: 1 2;
    }
    SaveCertScreen .title { text-align: center; text-style: bold; margin-bottom: 1; }
    SaveCertScreen .hint  { color: $text-muted; margin-bottom: 1; }
    SaveCertScreen #error { color: red; height: auto; }
    """

    def __init__(
        self, pem: str, default_path: str, title: str = "Save Certificate"
    ) -> None:
        super().__init__()
        self._pem = pem
        self._default_path = default_path
        self._title = title

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self._title, classes="title")
            yield Label(
                "Edit the path below, then press Enter or Save.", classes="hint"
            )
            yield Input(value=self._default_path, id="path")
            yield Static("", id="error")
            with Horizontal():
                yield Button("Save", variant="primary", id="save")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        inp = self.query_one("#path", Input)
        inp.focus()
        inp.action_end()

    def on_input_submitted(self, _: Input.Submitted) -> None:
        self._do_save()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.action_cancel()
        else:
            self._do_save()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _do_save(self) -> None:
        path_str = self.query_one("#path", Input).value.strip()
        if not path_str:
            self.query_one("#error", Static).update("Path is required.")
            return
        path = Path(path_str).expanduser()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self._pem)
            self.dismiss(str(path))
        except OSError as exc:
            self.query_one("#error", Static).update(str(exc))


# ---------------------------------------------------------------------------
# Full-screen PEM viewer
# ---------------------------------------------------------------------------


class CertViewScreen(Screen):
    """Full-screen PEM certificate viewer.

    Uses the full terminal so the user can select and copy the text with
    their terminal's native selection (Shift+drag, tmux copy-mode, etc.).
    """

    BINDINGS = [
        Binding("y", "copy", "Copy"),
        Binding("k", "toggle_key", "Key"),
        Binding("s", "save", "Save"),
        Binding("escape", "back", "Back"),
        Binding("q", "back", "Back"),
    ]

    DEFAULT_CSS = """
    CertViewScreen { layout: vertical; }
    #pem-scroll { height: 1fr; }
    #pem-content { padding: 0 2; color: $text; }
    #cert-info {
        height: auto;
        background: $boost;
        padding: 0 2;
        border-bottom: solid $primary;
        color: $text-muted;
    }
    """

    def __init__(
        self,
        title: str,
        pem: str,
        filename: str,
        info: str = "",
        key_path: Path | None = None,
    ) -> None:
        super().__init__()
        self._title = title
        self._pem = pem
        self._filename = filename
        self._info = info
        self._key_path = key_path
        self._showing_key = False
        self._key_pem: str | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        if self._info:
            yield Static(self._info, id="cert-info")
        with ScrollableContainer(id="pem-scroll"):
            yield Static(self._pem, id="pem-content", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self.title = self._title
        self._refresh_subtitle()

    def _refresh_subtitle(self) -> None:
        hints = ["y copy"]
        if self._key_path:
            hints.append("k hide key" if self._showing_key else "k key")
        hints += ["s save", "q / Esc back"]
        self.sub_title = "  ".join(hints)

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        if action == "toggle_key":
            return True if self._key_path else False
        return True

    def _record_key_access(self, detail: str) -> None:
        """Audit a private-key exposure in the TUI (reveal/copy/save)."""
        cn = self._title.removeprefix("Certificate: ")
        try:
            store.add_event(_root(), "key_download", cn=cn, method="tui", detail=detail)
        except Exception:
            pass

    def action_copy(self) -> None:
        showing_key = self._showing_key and self._key_pem is not None
        pem = self._key_pem if showing_key else self._pem
        self.app.copy_to_clipboard(pem)
        if showing_key:
            self._record_key_access("copy")
        self.notify("Copied to clipboard.")

    def action_toggle_key(self) -> None:
        if not self._key_path or not self._key_path.exists():
            self.notify("Key file not found.", severity="error")
            return
        if self._key_pem is None:
            self._key_pem = self._key_path.read_text()
        self._showing_key = not self._showing_key
        if self._showing_key:
            self._record_key_access("reveal")
        pem_widget = self.query_one("#pem-content", Static)
        if self._showing_key:
            combined = self._pem.rstrip("\n") + "\n" + self._key_pem
            pem_widget.update(combined)
        else:
            pem_widget.update(self._pem)
        self._refresh_subtitle()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_save(self) -> None:
        if self._showing_key and self._key_pem is not None:
            cn = self._title.removeprefix("Certificate: ")
            safe_name = cn.replace("*", "wildcard").replace("/", "_")
            combined = self._pem.rstrip("\n") + "\n" + self._key_pem
            content = combined
            default = str(Path.home() / f"{safe_name}.pem")
            self._record_key_access("save")
        else:
            content = self._pem
            default = str(Path.home() / self._filename)
        self.app.push_screen(SaveCertScreen(content, default), self._on_saved)

    def _on_saved(self, path: str | None) -> None:
        if path:
            self.notify(f"Saved → {path}")


# ---------------------------------------------------------------------------
# Main screen
# ---------------------------------------------------------------------------


class MainScreen(Screen):
    BINDINGS = [
        Binding("i", "init_ca", "Init CA"),
        Binding("n", "issue_cert", "New cert"),
        Binding("c", "view_ca_cert", "Trusted CA root"),
        Binding("d", "view_cert", "View cert"),
        Binding("x", "revoke_selected", "Revoke"),
        Binding("t", "view_token", "API Token"),
        Binding("a", "export_audit", "Export audit"),
        Binding("q", "quit", "Quit"),
    ]

    DEFAULT_CSS = """
    MainScreen { layout: vertical; }
    #ca-status {
        height: auto; background: $boost; padding: 0 1;
        border-bottom: solid $primary;
    }
    #ca-status.uninit { color: $warning; }
    #toolbar {
        height: 3; align: left middle; padding: 0 1;
        background: $surface; border-bottom: solid $panel;
    }
    #cert-table { height: 1fr; }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("", id="ca-status")
        with Horizontal(id="toolbar"):
            yield Button("Init CA [i]", id="btn-init", variant="primary")
            yield Button("New Cert [n]", id="btn-new")
            yield Button("Trusted CA [c]", id="btn-ca-cert")
            yield Button("Export Audit [a]", id="btn-audit")
        yield DataTable(id="cert-table", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        self._build_table()
        self._update_ca_status()
        self.query_one("#cert-table", DataTable).focus()

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        ca_ready = config.ca_cert_path(_root()).exists()
        if action == "init_ca":
            return False if ca_ready else True
        if action in (
            "issue_cert",
            "revoke_selected",
            "view_ca_cert",
            "view_cert",
            "view_token",
        ):
            return True if ca_ready else False
        return True

    def _update_ca_status(self) -> None:
        root = _root()
        self.app.sub_title = str(root)

        status = self.query_one("#ca-status", Static)
        init_btn = self.query_one("#btn-init", Button)
        ca_cert_btn = self.query_one("#btn-ca-cert", Button)

        if not config.ca_cert_path(root).exists():
            status.update(
                "[bold yellow]CA not initialised[/bold yellow] — "
                "press [b]i[/b] or click [b]Init CA[/b] to create a root CA."
            )
            status.add_class("uninit")
            init_btn.display = True
            ca_cert_btn.display = False
        else:
            try:
                subj = ca_subject(root)
                expiry = ca_expiry(root)
                fp = ca_fingerprint(root)
                status.update(
                    f"[green]CA ready[/green]  [b]{subj}[/b]  "
                    f"expires [b]{expiry}[/b]  SHA256: {fp[:29]}…"
                )
                status.remove_class("uninit")
                init_btn.display = False
                ca_cert_btn.display = True
            except CAError as exc:
                status.update(f"[red]CA error: {exc}[/red]")

    def _build_table(self) -> None:
        table = self.query_one("#cert-table", DataTable)
        # Add the columns once; on later refreshes clear rows only. Re-adding
        # columns (clear(columns=True)) makes Textual recompute auto-widths from
        # the header labels alone when called outside a fresh mount, which
        # collapses the column widths.
        if not table.columns:
            table.add_columns("CN", "SANs", "Key", "Expires", "Days left")
        table.clear()

        for cert in store.list_certs(_root()):
            days = days_until_expiry(cert["expiry"])
            style = _expiry_style(days)
            sans_display = ", ".join(
                s.replace("DNS:", "").replace("IP:", "") for s in cert["sans"]
            )
            table.add_row(
                cert["cn"],
                sans_display,
                cert.get("key_type", "ec").upper(),
                cert["expiry"],
                f"[{style}]{days}[/{style}]",
                key=cert["cn"],
            )

    def _selected_cn(self) -> str | None:
        """Return the CN of the currently highlighted table row, or None."""
        table = self.query_one("#cert-table", DataTable)
        if not table.row_count:
            return None
        try:
            cell_key = table.coordinate_to_cell_key(Coordinate(table.cursor_row, 0))
            return cell_key.row_key.value
        except Exception:
            return None

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-init":
            self.action_init_ca()
        elif event.button.id == "btn-new":
            self.action_issue_cert()
        elif event.button.id == "btn-ca-cert":
            self.action_view_ca_cert()
        elif event.button.id == "btn-audit":
            self.action_export_audit()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        cn = event.row_key.value
        entry = store.get_cert(_root(), cn)
        if entry:
            self.app.push_screen(CertDetailScreen(entry), self._on_detail_done)

    def action_init_ca(self) -> None:
        if config.ca_cert_path(_root()).exists():
            return
        self.app.push_screen(InitCAScreen(), self._on_init_done)

    def action_issue_cert(self) -> None:
        if not config.ca_cert_path(_root()).exists():
            self.notify("Initialise the CA first.", severity="error")
            return
        self.app.push_screen(IssueCertScreen(), self._on_issue_done)

    def action_revoke_selected(self) -> None:
        cn = self._selected_cn()
        if not cn:
            self.notify("Select a cert to revoke.", severity="warning")
            return
        self.app.push_screen(
            ConfirmScreen(
                title=f"Revoke {cn}?",
                message="All cert files will be permanently deleted.",
            ),
            lambda confirmed: self._on_revoke_confirmed(cn, confirmed),
        )

    def _on_revoke_confirmed(self, cn: str, confirmed: bool) -> None:
        if not confirmed:
            self.query_one("#cert-table", DataTable).focus()
            return
        try:
            revoke_cert(_root(), cn)
            self.notify(f"Revoked and deleted: {cn}")
            self._build_table()
        except CAError as exc:
            self.notify(str(exc), severity="error")
        self.query_one("#cert-table", DataTable).focus()

    def action_view_ca_cert(self) -> None:
        root = _root()
        ca_path = config.ca_cert_path(root)
        if not ca_path.exists():
            self.notify("CA not initialised.", severity="error")
            return
        pem = ca_path.read_text()
        try:
            subj = ca_subject(root)
            expiry = ca_expiry(root)
            fp = ca_fingerprint(root)
            info = f"Subject: {subj}  |  Expires: {expiry}  |  SHA256: {fp}"
        except CAError:
            info = str(ca_path)
        self.app.push_screen(
            CertViewScreen(
                title="Root CA Certificate",
                pem=pem,
                filename="local-ca.crt",
                info=info,
            )
        )

    def action_view_cert(self) -> None:
        cn = self._selected_cn()
        if not cn:
            self.notify("Select a cert to view.", severity="warning")
            return
        entry = store.get_cert(_root(), cn)
        if not entry:
            return
        cert_path = Path(entry["cert"])
        if not cert_path.exists():
            self.notify("Cert file not found on disk.", severity="error")
            return
        pem = cert_path.read_text()
        days = days_until_expiry(entry["expiry"])
        sans = ", ".join(entry["sans"])
        info = f"CN: {cn}  |  SANs: {sans}  |  Expires: {entry['expiry']} ({days} days)"
        safe_name = cn.replace("*", "wildcard").replace("/", "_")
        self.app.push_screen(
            CertViewScreen(
                title=f"Certificate: {cn}",
                pem=pem,
                filename=f"{safe_name}.crt",
                info=info,
                key_path=Path(entry["key"]),
            )
        )

    def action_view_token(self) -> None:
        token_path = config.api_token_path(_root())
        if not token_path.exists():
            self.notify(
                "No API token found. Re-initialise the CA to generate one.",
                severity="warning",
            )
            return
        self.app.push_screen(
            TokenScreen(token_path.read_text().strip()),
            lambda _: self.query_one("#cert-table", DataTable).focus(),
        )

    def action_export_audit(self) -> None:
        root = _root()
        events = store.list_events(root, limit=None)
        if not events:
            self.notify("No audit events recorded yet.", severity="warning")
            return
        self.app.push_screen(
            SaveCertScreen(
                pem=_audit_csv(root),
                default_path=str(Path.home() / "ssltui-audit.csv"),
                title="Export Audit Log",
            ),
            self._on_audit_saved,
        )

    def _on_audit_saved(self, path: str | None) -> None:
        if path:
            self.notify(f"Audit log exported → {path}")
        self.query_one("#cert-table", DataTable).focus()

    def action_refresh(self) -> None:
        self._build_table()
        self._update_ca_status()
        self.query_one("#cert-table", DataTable).focus()
        self.notify("Refreshed.")

    def action_quit(self) -> None:
        self.app.exit()

    def _on_init_done(self, result: bool) -> None:
        self._update_ca_status()
        self._build_table()
        self.refresh_bindings()
        if result:
            token_path = config.api_token_path(_root())
            if token_path.exists():
                self.app.push_screen(
                    TokenScreen(token_path.read_text().strip()),
                    lambda _: self.query_one("#cert-table", DataTable).focus(),
                )
                return
        self.query_one("#cert-table", DataTable).focus()

    def _on_issue_done(self, meta: dict | None) -> None:
        if meta:
            self.notify(
                f"Issued: {meta['cn']} (expires in {meta['validity_days']} days)"
            )
            self._build_table()
        self.query_one("#cert-table", DataTable).focus()

    def _on_detail_done(self, result: str) -> None:
        self._build_table()
        self._update_ca_status()
        self.query_one("#cert-table", DataTable).focus()


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


class SSLTuiApp(App):
    TITLE = "ssltui — Local CA Manager"
    CSS = """
    Screen { background: $background; }
    """

    def on_mount(self) -> None:
        self.push_screen(MainScreen())


def run_tui() -> None:
    SSLTuiApp().run()


# ---------------------------------------------------------------------------
# API server TUI — ServeScreen / ServeApp (separate from the CA manager TUI)
# ---------------------------------------------------------------------------


class ServeScreen(Screen):
    """Full-screen view of a running API server: status bar + live request log."""

    TITLE = "ssltui — API Server"

    BINDINGS = [
        Binding("t", "view_token", "API Token"),
        Binding("i", "issue_example", "Show issue example"),
        Binding("c", "copy_url", "Copy dashboard URL"),
        Binding("q", "stop_server", "Stop server"),
    ]

    DEFAULT_CSS = """
    ServeScreen { layout: vertical; }
    #srv-status {
        height: 1; background: $boost; padding: 0 1;
        border-bottom: solid $primary; color: $text;
    }
    #request-log { height: 1fr; }
    """

    def __init__(self, server: APIServer, token: str) -> None:
        super().__init__()
        self._server = server
        self._token = token
        self._log_handler: _WerkzeugCapture | None = None
        self._fs_state: dict[str, float] = {}
        self._last_version: int = 0
        self._last_event_id: int = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        if self._server.secure:
            status = (
                f"[green]●[/green]  Listening on [bold]{self._server.address}[/bold] "
                f"[dim](HTTP fallback: {self._server.http_address})[/dim]"
            )
        else:
            status = (
                f"[yellow]●[/yellow]  Listening on [bold]{self._server.address}[/bold] "
                f"[dim](HTTP only — no server cert)[/dim]"
            )
        yield Static(status, id="srv-status")
        yield RichLog(id="request-log", highlight=False, markup=False, wrap=False)
        yield Footer()

    def on_mount(self) -> None:
        self.title = self.TITLE
        self.sub_title = self._server.address
        wlog = logging.getLogger("werkzeug")
        self._log_handler = _WerkzeugCapture(self._server.log_queue)
        self._log_handler.setFormatter(
            logging.Formatter("%(asctime)s  %(message)s", "%H:%M:%S")
        )
        wlog.addHandler(self._log_handler)
        wlog.propagate = False

        self._server.start()
        self._fs_state = self._fs_snapshot()
        self._last_version = self._safe_version()
        self._last_event_id = self._latest_event_id()
        self._write_history()
        self.set_interval(0.1, self._drain_log)
        self.set_interval(1.0, self._poll_fs)

    def on_unmount(self) -> None:
        self._server.stop()
        if self._log_handler:
            logging.getLogger("werkzeug").removeHandler(self._log_handler)

    def _drain_log(self) -> None:
        log = self.query_one("#request-log", RichLog)
        while True:
            try:
                line = self._server.log_queue.get_nowait()
            except _queue.Empty:
                break
            # Werkzeug colorizes the request line for non-2xx codes with raw
            # ANSI escapes. RichLog (markup=False) would render those as literal
            # text and corrupt the line, so decode them into a Rich Text.
            log.write(Text.from_ansi(line))

    def _safe_version(self) -> int:
        try:
            return store.get_version(self._server.root)
        except Exception:
            return self._last_version

    def _latest_event_id(self) -> int:
        try:
            evs = store.list_events(self._server.root, limit=1)
            return evs[-1]["id"] if evs else 0
        except Exception:
            return 0

    def _write_history(self) -> None:
        events = store.list_events(self._server.root, limit=5)
        if not events:
            return

        log = self.query_one("#request-log", RichLog)
        for ev in events:
            _, msg = _format_tui_event(ev)
            ts_iso = ev.get("ts") or ""
            try:
                dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
                ts = dt.strftime("%Y-%m-%d %H:%M")
            except ValueError:
                ts = ts_iso[:16]
            log.write(Text(f"{ts}  HISTORICAL  {msg}", style="dim italic"))
        log.write(Text("─" * 60 + "  live", style="dim"))

    def _fs_snapshot(self) -> dict[str, float]:
        root = self._server.root
        state: dict[str, float] = {}
        for name in ("ca.crt", "ca.crl", "api_token"):
            p = root / name
            if p.exists():
                state[name] = p.stat().st_mtime
        return state

    def _poll_fs(self) -> None:
        try:
            now = self._fs_snapshot()
        except OSError:
            return

        log = self.query_one("#request-log", RichLog)
        ts = datetime.now().strftime("%H:%M:%S")

        version = self._safe_version()
        version_changed = version != self._last_version
        if version_changed:
            self._last_version = version
            try:
                new_events = store.list_events(self._server.root, limit=100)
            except Exception:
                new_events = []
            for ev in new_events:
                if ev["id"] <= self._last_event_id:
                    continue
                style, msg = _format_tui_event(ev)
                log.write(Text(f"{ts}  {msg}", style=style))
                self._last_event_id = ev["id"]

        # CRL regeneration accompanies revokes (already logged above), so only
        # surface a standalone "CRL regenerated" when no event was recorded.
        if not version_changed and now.get("ca.crl") != self._fs_state.get("ca.crl"):
            log.write(Text(f"{ts}  CRL regenerated", style="dim"))

        if now.get("ca.crt") != self._fs_state.get("ca.crt"):
            log.write(Text(f"{ts}  CA re-initialised", style="bold red"))

        if now.get("api_token") != self._fs_state.get("api_token"):
            log.write(Text(f"{ts}  API token rotated", style="bold yellow"))

        self._fs_state = now

    def action_view_token(self) -> None:
        self.app.push_screen(TokenScreen(self._token))

    def action_issue_example(self) -> None:
        self.app.push_screen(IssueExampleScreen(self._server.address, self._token))

    def action_copy_url(self) -> None:
        url = f"{self._server.address}/dashboard"
        self.app.copy_to_clipboard(url)
        self.notify(f"Copied: {url}", title="Dashboard URL")

    def action_stop_server(self) -> None:
        self.app.exit()


class ServeApp(App):
    """Standalone Textual app for the API server — independent of SSLTuiApp."""

    CSS = "Screen { background: $background; }"

    def __init__(self, server: APIServer, token: str) -> None:
        super().__init__()
        self._server = server
        self._token = token

    def on_mount(self) -> None:
        self.push_screen(ServeScreen(self._server, self._token))
