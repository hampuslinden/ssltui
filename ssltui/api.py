"""Flask REST API for ssltui CA operations.

Start with:  ssltui serve [--host 127.0.0.1] [--port 8080]
Requires:    SSLTUI_API_TOKEN env var or api_token file in CA root.
             CA must already be initialised before starting.

Endpoints:
  GET   /api/v1/certs                 list all cert metadata (JSON)
  POST  /api/v1/certs                 issue new cert
  GET   /api/v1/certs/<cn>            cert metadata (JSON)
  POST  /api/v1/certs/<cn>/renew      renew cert
  GET   /api/v1/certs/<cn>/cert.pem   download leaf cert
  GET   /api/v1/certs/<cn>/key.pem    download private key
  GET   /api/v1/certs/<cn>/chain.pem  download chain (leaf + CA)

Wildcard CN example: GET /api/v1/certs/%2A.local/cert.pem
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import queue
import ssl
import threading
import time
from datetime import datetime
from functools import wraps
from pathlib import Path

try:
    from flask import (
        Flask,
        Response,
        abort,
        jsonify,
        redirect,
        render_template_string,
        request,
        send_file,
        session,
        stream_with_context,
    )
    from werkzeug.exceptions import HTTPException
    from werkzeug.serving import make_server
except ImportError as err:
    raise SystemExit(
        "Flask is required for the API server.\nInstall it with:  uv sync --extra api"
    ) from err

from ssltui import config, store
from ssltui.ca import (
    CAError,
    ca_expiry,
    ca_subject,
    issue_cert,
    renew_cert,
)
from ssltui.renewal import days_until_expiry


def _resolve_token(root: Path) -> str:
    """Return the API token from env var or api_token file. Raises SystemExit if missing."""
    token = os.environ.get("SSLTUI_API_TOKEN", "").strip()
    if not token:
        token_path = config.api_token_path(root)
        if token_path.exists():
            token = token_path.read_text().strip()
    if not token:
        raise SystemExit(
            "Error: No API token configured.\n"
            "Set SSLTUI_API_TOKEN or re-initialise the CA to generate one."
        )
    return token


# ---------------------------------------------------------------------------
# Event log (shared between API server and dashboard)
# ---------------------------------------------------------------------------


class EventLog:
    """Thread-safe in-memory ring buffer of dashboard events."""

    def __init__(self, maxlen: int = 500) -> None:
        self._events: list[dict] = []
        self._seq: int = 0
        self._lock = threading.Lock()
        self._maxlen = maxlen

    def add(self, level: str, msg: str) -> None:
        """Append an event. level: 'success' | 'info' | 'warning' | 'error' | 'dim'"""
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self._seq += 1
            self._events.append(
                {"ts": ts, "level": level, "msg": msg, "_seq": self._seq}
            )
            if len(self._events) > self._maxlen:
                del self._events[0]

    def since(self, after_seq: int) -> tuple[list[dict], int]:
        """Return (new_events, current_seq). Events with _seq > after_seq are returned."""
        with self._lock:
            result = [
                {"ts": e["ts"], "level": e["level"], "msg": e["msg"]}
                for e in self._events
                if e["_seq"] > after_seq
            ]
            return result, self._seq


# Event type \u2192 (dashboard level, human label) for rendering stored events.
_EVENT_RENDER: dict[str, tuple[str, str]] = {
    "issue": ("success", "issued"),
    "renew": ("info", "renewed"),
    "revoke": ("warning", "revoked"),
    "key_download": ("warning", "key downloaded"),
    "ca_init": ("error", "CA re-initialised"),
}


def _format_event(ev: dict) -> tuple[str, str]:
    """Map a stored event row to a (level, message) pair for the dashboard log."""
    level, label = _EVENT_RENDER.get(ev["type"], ("dim", ev["type"]))
    method = ev.get("method")
    suffix = f" ({method})" if method else ""
    cn = ev.get("cn")
    msg = f"{label}{suffix}: {cn}" if cn else f"{label}{suffix}"
    return level, msg


def _write_historical_events(root: Path, event_log: EventLog) -> None:
    """Seed the event log from the persisted events table so the dashboard has context."""
    try:
        events = store.list_events(root, limit=20)
        for ev in events:
            level, msg = _format_event(ev)
            day = (ev.get("ts") or "")[:10]
            event_log.add(level, f"[{day}] {msg}" if day else msg)
        if events:
            event_log.add("dim", "\u2500" * 24 + " live")
    except Exception:
        pass


def _start_fs_watcher(root: Path, event_log: EventLog) -> None:
    """Daemon thread that surfaces new events (and CA/CRL changes) on the dashboard.

    Cert lifecycle and key-download events come from the persisted events table,
    polled via the store version counter; CA re-init and CRL regeneration are
    still detected by file mtime since they don't always write an event row.
    """

    def _mtime(p: Path) -> float:
        try:
            return p.stat().st_mtime
        except OSError:
            return 0.0

    def _last_event_id() -> int:
        try:
            evs = store.list_events(root, limit=1)
            return evs[-1]["id"] if evs else 0
        except Exception:
            return 0

    state: dict = {
        "version": _safe_version(root),
        "last_id": _last_event_id(),
        "ca_mtime": _mtime(config.ca_cert_path(root)),
        "crl_mtime": _mtime(config.crl_path(root)),
    }

    def _poll() -> None:
        while True:
            time.sleep(5)
            try:
                version = _safe_version(root)
                if version != state["version"]:
                    state["version"] = version
                    for ev in store.list_events(root, limit=100):
                        if ev["id"] <= state["last_id"]:
                            continue
                        level, msg = _format_event(ev)
                        event_log.add(level, msg)
                        state["last_id"] = ev["id"]

                ca_mtime = _mtime(config.ca_cert_path(root))
                if ca_mtime and ca_mtime != state["ca_mtime"]:
                    event_log.add("error", "CA re-initialised")
                    state["ca_mtime"] = ca_mtime

                crl_mtime = _mtime(config.crl_path(root))
                if crl_mtime and crl_mtime != state["crl_mtime"]:
                    event_log.add("dim", "CRL regenerated")
                    state["crl_mtime"] = crl_mtime
            except Exception:
                pass

    threading.Thread(target=_poll, daemon=True, name="ssltui-fs-watcher").start()


def _safe_version(root: Path) -> int:
    try:
        return store.get_version(root)
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Dashboard HTML templates
# ---------------------------------------------------------------------------

_LOGIN_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ssltui &#8212; Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:Consolas,'Courier New',monospace;
  display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#161b22;border:1px solid #30363d;padding:32px 40px;width:360px}
.logo{color:#3fb950;font-weight:bold;font-size:15px;margin-bottom:4px}
.sub{color:#8b949e;font-size:12px;margin-bottom:24px}
label{color:#8b949e;font-size:12px;display:block;margin-bottom:4px}
input{width:100%;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;
  padding:8px 10px;font-family:inherit;font-size:13px;margin-bottom:16px}
input:focus{outline:none;border-color:#388bfd}
button{width:100%;background:#238636;color:#fff;border:none;
  padding:8px;font-family:inherit;font-size:13px;cursor:pointer}
button:hover{background:#2ea043}
.err{color:#f85149;font-size:12px;margin-bottom:12px}
</style>
</head>
<body>
<div class="card">
  <div class="logo">&#9670; ssltui Dashboard</div>
  <div class="sub">Enter your API token to continue</div>
  {%- if error %}<div class="err">{{ error }}</div>{% endif %}
  <form method="post" action="/dashboard/login">
    <label for="tok">API Token</label>
    <input type="password" id="tok" name="token"
           placeholder="Paste token here" autofocus autocomplete="off">
    <button type="submit">Sign in &#8594;</button>
  </form>
</div>
</body>
</html>
"""

_DASHBOARD_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ssltui &#8212; Dashboard</title>
<style>
:root{
  --bg:#0d1117;--surf:#161b22;--brd:#30363d;--txt:#c9d1d9;
  --mut:#8b949e;--grn:#3fb950;--ylw:#d29922;--red:#f85149;
  --cyn:#58a6ff;--acc:#388bfd;
  --fnt:Consolas,'Courier New',monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font-family:var(--fnt);
  font-size:14px;height:100vh;display:flex;flex-direction:column;overflow:hidden}
a{color:var(--cyn);text-decoration:none}
a:hover{text-decoration:underline}
/* header */
#hdr{background:var(--surf);border-bottom:1px solid var(--brd);
  padding:7px 14px;display:flex;align-items:center;
  justify-content:space-between;flex-shrink:0}
#hdr-l{display:flex;align-items:baseline;gap:14px}
#logo{color:var(--grn);font-weight:bold;font-size:15px}
#ca-nfo{color:var(--mut);font-size:12px}
#hdr-r{display:flex;align-items:center;gap:12px}
.btn{background:var(--surf);color:var(--txt);border:1px solid var(--brd);
  padding:3px 10px;cursor:pointer;font-family:var(--fnt);font-size:12px;
  text-decoration:none;display:inline-block}
.btn:hover{background:var(--brd);text-decoration:none}
.btn-d{border-color:var(--red);color:var(--red)}
/* status bar */
#sbar{background:var(--surf);border-bottom:1px solid var(--brd);
  padding:3px 14px;font-size:13px;color:var(--mut);flex-shrink:0}
#sdot{color:var(--grn)}
/* layout */
#main{display:grid;grid-template-columns:1fr 400px;flex:1;overflow:hidden}
/* cert panel */
#cpanel{overflow:auto;padding:10px 12px;border-right:1px solid var(--brd)}
#cp-hdr{color:var(--mut);font-size:12px;text-transform:uppercase;
  letter-spacing:1px;margin-bottom:8px;display:flex;align-items:center;gap:8px}
#ccnt{color:var(--acc);font-size:12px;text-transform:none;letter-spacing:0}
table{width:100%;border-collapse:collapse}
thead th{background:var(--surf);color:var(--mut);font-weight:normal;
  padding:5px 8px;text-align:left;border-bottom:1px solid var(--brd);
  font-size:12px;text-transform:uppercase;letter-spacing:.5px;
  position:sticky;top:0;z-index:1}
tbody tr{border-bottom:1px solid rgba(48,54,61,.6)}
tbody tr:hover{background:var(--surf)}
tbody tr:nth-child(even){background:rgba(255,255,255,.015)}
tbody tr:nth-child(even):hover{background:var(--surf)}
td{padding:4px 8px;vertical-align:middle}
.cn{font-weight:bold}
.sans{color:var(--mut);font-size:12px;max-width:190px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.kt{color:var(--mut);font-size:12px}
.exp{color:var(--mut);font-size:12px}
.ok{color:var(--grn)}.warn{color:var(--ylw)}
.crit,.expired{color:var(--red)}.expired{font-weight:bold}
.acts a,.acts button{color:var(--cyn);border:1px solid var(--brd);padding:2px 7px;
  font-size:12px;display:inline-block;margin-right:2px;text-decoration:none;
  background:none;cursor:pointer;font-family:var(--fnt)}
.acts a:hover,.acts button:hover{background:var(--surf);border-color:var(--cyn)}
.acts button.key-btn{color:var(--ylw);border-color:var(--brd)}
.acts button.key-btn:hover{border-color:var(--ylw)}
.acts button.cert-btn{color:var(--cyn);border-color:var(--brd)}
.acts button.cert-btn:hover{border-color:var(--cyn)}
.empty{color:var(--mut);padding:14px 8px;font-style:italic}
/* key modal + issue modal */
#kmodal-bg,#imodal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);
  z-index:100;align-items:center;justify-content:center}
#kmodal-bg.open,#imodal-bg.open{display:flex}
#kmodal,#imodal{background:var(--surf);border:1px solid var(--brd);
  padding:20px 24px;width:600px;max-width:96vw;position:relative}
#kmodal h3,#imodal h3{font-size:13px;font-weight:bold;margin-bottom:14px}
#kmodal-close,#imodal-close{position:absolute;top:10px;right:14px;background:none;border:none;
  color:var(--mut);cursor:pointer;font-size:18px;line-height:1;font-family:var(--fnt)}
#kmodal-close:hover,#imodal-close:hover{color:var(--txt)}
.curl-box{background:var(--bg);border:1px solid var(--brd);
  padding:10px 12px;font-size:12px;color:var(--txt);
  white-space:pre-wrap;word-break:break-all;margin-bottom:12px;
  font-family:var(--fnt);line-height:1.7;min-height:56px}
.curl-tok{color:var(--ylw)}
#kmodal-btns,#imodal-btns{display:flex;gap:8px;align-items:center}
.km-btn{background:var(--surf);color:var(--txt);border:1px solid var(--brd);
  padding:4px 12px;cursor:pointer;font-family:var(--fnt);font-size:12px}
.km-btn:hover{background:var(--brd)}
#km-copy-st,#im-copy-st{font-size:11px;color:var(--grn);margin-left:auto}
/* event panel */
#epanel{display:flex;flex-direction:column;overflow:hidden}
#ep-hdr{color:var(--mut);font-size:12px;text-transform:uppercase;
  letter-spacing:1px;padding:10px 12px 6px;flex-shrink:0;
  border-bottom:1px solid var(--brd);
  display:flex;justify-content:space-between;align-items:center}
#sse-st{font-size:10px;letter-spacing:0;text-transform:none;color:var(--grn)}
#elog{flex:1;overflow-y:auto;padding:4px 12px;font-size:13px;line-height:1.6}
.ev{display:flex;gap:8px;border-bottom:1px solid rgba(48,54,61,.3);padding:1px 0}
.ev-ts{color:var(--mut);flex-shrink:0;width:58px}
.success{color:var(--grn)}.warning{color:var(--ylw)}
.error{color:var(--red)}.info{color:var(--cyn)}
.dim{color:var(--mut);font-style:italic}
/* footer */
#foot{background:var(--surf);border-top:1px solid var(--brd);
  padding:3px 14px;font-size:12px;color:var(--mut);
  display:flex;justify-content:space-between;flex-shrink:0}
/* pem viewer modal */
#pem-modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);
  z-index:100;align-items:center;justify-content:center}
#pem-modal-bg.open{display:flex}
#pem-modal{background:var(--surf);border:1px solid var(--brd);
  padding:20px 24px;width:680px;max-width:96vw;position:relative;
  display:flex;flex-direction:column;max-height:90vh}
#pem-modal h3{font-size:13px;font-weight:bold;margin-bottom:14px;flex-shrink:0}
#pem-modal-close{position:absolute;top:10px;right:14px;background:none;border:none;
  color:var(--mut);cursor:pointer;font-size:18px;line-height:1;font-family:var(--fnt)}
#pem-modal-close:hover{color:var(--txt)}
#pem-content{background:var(--bg);border:1px solid var(--brd);
  padding:10px 12px;font-size:11px;color:var(--grn);
  white-space:pre;overflow:auto;flex:1;min-height:120px;max-height:60vh;
  font-family:var(--fnt);line-height:1.5;margin-bottom:12px}
#pem-modal-btns{display:flex;gap:8px;align-items:center;flex-shrink:0}
#pem-copy-st{font-size:11px;color:var(--grn);margin-left:auto}
/* auth-error modal */
#auth-modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.78);
  z-index:200;align-items:center;justify-content:center}
#auth-modal-bg.open{display:flex}
#auth-modal{background:var(--surf);border:1px solid var(--red);
  padding:22px 26px;width:400px;max-width:94vw}
#auth-modal h3{font-size:14px;font-weight:bold;color:var(--red)}
#auth-modal-btns{display:flex;gap:8px;align-items:center}
/* API designer modal */
#admodal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);
  z-index:100;align-items:center;justify-content:center}
#admodal-bg.open{display:flex}
#admodal{background:var(--surf);border:1px solid var(--brd);
  padding:20px 24px;width:840px;max-width:96vw;position:relative;
  display:flex;flex-direction:column;max-height:92vh}
#admodal h3{font-size:13px;font-weight:bold;margin-bottom:14px;flex-shrink:0}
#admodal-close{position:absolute;top:10px;right:14px;background:none;border:none;
  color:var(--mut);cursor:pointer;font-size:18px;line-height:1;font-family:var(--fnt)}
#admodal-close:hover{color:var(--txt)}
#ad-body{display:grid;grid-template-columns:290px 1fr;gap:18px;overflow:hidden}
#ad-form{overflow-y:auto;max-height:66vh;padding-right:6px}
#ad-out{display:flex;flex-direction:column;overflow:hidden}
.ad-lbl{color:var(--mut);font-size:11px;display:block;margin:10px 0 3px;
  text-transform:uppercase;letter-spacing:.5px}
.ad-req{color:var(--red)}
.ad-in,#ad-endpoint,#ad-format{width:100%;background:var(--bg);border:1px solid var(--brd);
  color:var(--txt);padding:6px 8px;font-family:var(--fnt);font-size:12px}
.ad-in:focus,#ad-endpoint:focus,#ad-format:focus{outline:none;border-color:var(--acc)}
.ad-method{display:inline-block;font-size:11px;font-weight:bold;padding:1px 7px;
  border:1px solid var(--brd);margin-left:8px;vertical-align:middle}
.ad-m-get{color:var(--grn);border-color:var(--grn)}
.ad-m-post{color:var(--ylw);border-color:var(--ylw)}
.ad-path{color:var(--cyn);font-size:12px;margin:8px 0 2px;word-break:break-all}
.ad-noparams{color:var(--mut);font-style:italic;font-size:12px;margin-top:10px}
#ad-preview{background:var(--bg);border:1px solid var(--brd);
  padding:10px 12px;font-size:12px;color:var(--txt);
  white-space:pre-wrap;word-break:break-all;flex:1;min-height:170px;max-height:58vh;
  overflow:auto;font-family:var(--fnt);line-height:1.7;margin-bottom:12px}
#admodal-btns{display:flex;gap:8px;align-items:center;flex-shrink:0}
#ad-copy-st{font-size:11px;color:var(--grn);margin-left:auto}
.ad-fmt-row{display:flex;gap:10px;align-items:center;margin-bottom:8px}
.ad-fmt-row label{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.5px}
</style>
</head>
<body>
<div id="hdr">
  <div id="hdr-l">
    <span id="logo">&#9670; ssltui</span>
    <span id="ca-nfo">{{ ca_info | e }}</span>
  </div>
  <div id="hdr-r">
    <button class="btn" onclick="openDesigner()">API Designer</button>
    <a href="/dashboard/logout" class="btn btn-d">Logout</a>
  </div>
</div>
<div id="sbar">
  <span id="sdot">&#9679;</span>
  API on <strong>{{ server_url | e }}</strong>
  &nbsp;&middot;&nbsp; CA root: {{ ca_root | e }}
  &nbsp;&middot;&nbsp; <a href="#" data-dl="/dashboard/ca/ca.crt" data-name="ca.crt" class="btn ca-dl" style="padding:1px 6px;font-size:11px">&#8595; Root CA cert</a>
  &nbsp;&middot;&nbsp; <a href="#" data-dl="/dashboard/ca/crl.pem" data-name="ca.crl" class="btn ca-dl" style="padding:1px 6px;font-size:11px">&#8595; CRL</a>
</div>
<div id="main">
  <div id="cpanel">
    <div id="cp-hdr">Certificates <span id="ccnt"></span></div>
    <table>
      <thead>
        <tr>
          <th>CN</th><th>SANs</th><th>Key</th>
          <th>Expires</th><th>Days</th><th>Download</th>
        </tr>
      </thead>
      <tbody id="ctbody">
        <tr><td colspan="6" class="empty">Loading&#8230;</td></tr>
      </tbody>
    </table>
  </div>
  <div id="epanel">
    <div id="ep-hdr">
      Events
      <span id="sse-st">connecting&#8230;</span>
    </div>
    <div id="elog"></div>
  </div>
</div>
<div id="foot">
  <span id="fst">Initialising&#8230;</span>
</div>

<div id="kmodal-bg">
  <div id="kmodal">
    <button id="kmodal-close" onclick="closeKeyModal()">&times;</button>
    <h3 id="kmodal-title">Download key &mdash; <span id="kmodal-cn"></span></h3>
    <div class="curl-box" id="curl-cmd"></div>
    <div id="kmodal-btns">
      <button class="km-btn" id="km-tok-btn" onclick="toggleTok()">Show token</button>
      <button class="km-btn" onclick="copyCurl()">Copy</button>
      <span id="km-copy-st"></span>
    </div>
  </div>
</div>

<div id="imodal-bg">
  <div id="imodal">
    <button id="imodal-close" onclick="closeIssueModal()">&times;</button>
    <h3>Issue a certificate &mdash; curl example</h3>
    <p style="font-size:11px;color:var(--mut);margin-bottom:12px">
      POST /api/v1/certs &middot; body fields: cn (required), sans, key_type (ec|rsa), validity_days
    </p>
    <div class="curl-box" id="issue-curl-cmd"></div>
    <div id="imodal-btns">
      <button class="km-btn" id="im-tok-btn" onclick="toggleIssueTok()">Show token</button>
      <button class="km-btn" onclick="copyIssueCurl()">Copy</button>
      <span id="im-copy-st"></span>
    </div>
  </div>
</div>

<div id="pem-modal-bg">
  <div id="pem-modal">
    <button id="pem-modal-close" onclick="closePemModal()">&times;</button>
    <h3 id="pem-modal-title"></h3>
    <div id="pem-content"></div>
    <div id="pem-modal-btns">
      <button class="km-btn" onclick="copyPem()">Copy</button>
      <a id="pem-dl-btn" class="km-btn" style="text-decoration:none" href="#" download="">Download</a>
      <span id="pem-copy-st"></span>
    </div>
  </div>
</div>

<div id="auth-modal-bg">
  <div id="auth-modal">
    <h3>&#9888; Session expired</h3>
    <p style="font-size:12px;color:var(--mut);margin:12px 0 18px;line-height:1.6">
      Your API token is no longer valid or your session has expired.
      Sign in again with a valid token to continue.
    </p>
    <div id="auth-modal-btns">
      <a href="/dashboard/login" class="km-btn" style="text-decoration:none;border-color:var(--acc);color:var(--cyn)">Go to login &#8594;</a>
    </div>
  </div>
</div>

<div id="admodal-bg">
  <div id="admodal">
    <button id="admodal-close" onclick="closeDesigner()">&times;</button>
    <h3>API Designer <span id="ad-method" class="ad-method ad-m-get">GET</span></h3>
    <div id="ad-body">
      <div id="ad-form">
        <label class="ad-lbl">Endpoint</label>
        <select id="ad-endpoint"></select>
        <div class="ad-path" id="ad-path"></div>
        <div id="ad-inputs"></div>
        <datalist id="ad-cn-list"></datalist>
      </div>
      <div id="ad-out">
        <div class="ad-fmt-row">
          <label for="ad-format">Output</label>
          <select id="ad-format" style="width:auto">
            <option value="curl" selected>curl</option>
            <option value="httpie">HTTPie</option>
            <option value="fetch">JavaScript (fetch)</option>
            <option value="http">Raw HTTP</option>
            <option value="powershell">PowerShell</option>
          </select>
        </div>
        <div id="ad-preview"></div>
        <div id="admodal-btns">
          <button class="km-btn" id="ad-tok-btn" onclick="toggleDesignerTok()">Show token</button>
          <button class="km-btn" onclick="copyDesigner()">Copy</button>
          <span id="ad-copy-st"></span>
        </div>
      </div>
    </div>
  </div>
</div>
<script>
const ESC = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const _tok = {{ server_token | tojson }};

// Event messages that change the cert list (see _format_event server-side):
// "issued (api): cn", "renewed (cron): cn", "revoked (tui): cn", and the
// historical "[2026-06-14] issued (api): cn" variant. "key downloaded" and
// "CA re-initialised" deliberately don't match — they don't alter the table.
const CERT_EVENTS = /(?:^|\\] )(?:issued|renewed|revoked)\\b/;

function dcls(d) {
  if (d < 0) return 'expired';
  if (d <= 14) return 'crit';
  if (d <= 30) return 'warn';
  return 'ok';
}

// Shown when the session/token is no longer valid (any dashboard request -> 401).
// Stops background polling and the SSE stream so we don't hammer the server.
let _authFailed = false;
function showAuthError() {
  if (_authFailed) return;
  _authFailed = true;
  if (evSrc) evSrc.close();
  document.getElementById('auth-modal-bg').classList.add('open');
}

async function loadCerts() {
  if (_authFailed) return;
  const tb = document.getElementById('ctbody');
  try {
    const r = await fetch('/dashboard/api/certs');
    if (r.status === 401) { showAuthError(); return; }
    if (!r.ok) {
      tb.innerHTML = '<tr><td colspan="6" class="empty" style="color:var(--red)">Error ' + r.status + ' loading certificates — check server logs.</td></tr>';
      return;
    }
    const certs = await r.json();
    if (!Array.isArray(certs)) {
      tb.innerHTML = '<tr><td colspan="6" class="empty" style="color:var(--red)">Unexpected server response: ' + ESC(JSON.stringify(certs).slice(0, 80)) + '</td></tr>';
      return;
    }
    document.getElementById('ccnt').textContent = '(' + certs.length + ')';
    _adCNs = certs.map(c => c.cn).filter(Boolean);
    _adFillCNs();
    if (!certs.length) {
      tb.innerHTML = '<tr><td colspan="6" class="empty">No certificates issued yet.</td></tr>';
      return;
    }
    tb.innerHTML = certs.map(c => {
      const sans = (c.sans || []).map(s => s.replace(/^DNS:|^IP:/, '')).join(', ');
      const dl = (c.days_left == null || c.days_left < 0) ? 'EXPIRED' : c.days_left;
      const dc = c.days_left == null ? 'crit' : dcls(c.days_left);
      const enc = encodeURIComponent(c.cn || '');
      const safe = (c.cn || '').replace(/\\*/g, 'wildcard').replace(/\\//g, '_');
      const expDisplay = c.expiry ? c.expiry.slice(0, 10) : '—';
      return '<tr>'
        + '<td class="cn">' + ESC(c.cn || '') + '</td>'
        + '<td class="sans" title="' + ESC(sans) + '">' + ESC(sans) + '</td>'
        + '<td class="kt">' + ESC((c.key_type || 'ec').toUpperCase()) + '</td>'
        + '<td class="exp">' + ESC(expDisplay) + '</td>'
        + '<td class="' + dc + '">' + dl + '</td>'
        + '<td class="acts">'
        + '<button class="cert-btn" data-cn="' + ESC(c.cn) + '" data-type="cert" data-safe="' + ESC(safe) + '">cert</button>'
        + '<button class="cert-btn" data-cn="' + ESC(c.cn) + '" data-type="chain" data-safe="' + ESC(safe) + '">chain</button>'
        + '<button class="key-btn" data-cn="' + ESC(c.cn) + '">key</button>'
        + '</td>'
        + '</tr>';
    }).join('');
    document.getElementById('fst').textContent = 'Certs updated ' + new Date().toLocaleTimeString();
  } catch (e) {
    tb.innerHTML = '<tr><td colspan="6" class="empty" style="color:var(--red)">Failed to load certificates: ' + ESC(e.message) + '</td></tr>';
    console.error('loadCerts', e);
  }
}

// Coalesce reloads: connecting to the SSE stream replays recent history, so a
// burst of cert events shouldn't fire one fetch each.
let _certReloadTimer = null;
function scheduleCertReload() {
  if (_certReloadTimer) return;
  _certReloadTimer = setTimeout(() => { _certReloadTimer = null; loadCerts(); }, 150);
}

const elog = document.getElementById('elog');

function appendEv(ev) {
  const d = document.createElement('div');
  d.className = 'ev';
  d.innerHTML = '<span class="ev-ts">' + ESC(ev.ts) + '</span>'
    + '<span class="' + ESC(ev.level) + '">' + ESC(ev.msg) + '</span>';
  elog.appendChild(d);
  elog.scrollTop = elog.scrollHeight;
  while (elog.children.length > 300) elog.removeChild(elog.firstChild);
}

let evSrc = null;
function connectSSE() {
  if (_authFailed) return;
  if (evSrc) evSrc.close();
  evSrc = new EventSource('/dashboard/api/events/stream');
  const st = document.getElementById('sse-st');
  evSrc.onopen = () => { st.textContent = 'live'; st.style.color = '#3fb950'; };
  evSrc.onmessage = e => {
    const ev = JSON.parse(e.data);
    appendEv(ev);
    if (CERT_EVENTS.test(ev.msg)) scheduleCertReload();
  };
  evSrc.onerror = () => {
    evSrc.close();
    if (_authFailed) return;
    // A 401 (expired session) surfaces here as a generic error; probe the
    // certs endpoint so we can tell "session expired" from "server restarting".
    fetch('/dashboard/api/certs', {method: 'HEAD'}).then(r => {
      if (r.status === 401) { showAuthError(); return; }
      st.textContent = 'reconnecting\u2026'; st.style.color = '#d29922';
      setTimeout(connectSSE, 4000);
    }).catch(() => {
      st.textContent = 'reconnecting\u2026'; st.style.color = '#d29922';
      setTimeout(connectSSE, 4000);
    });
  };
}

// --- Key modal ---
let _tokVis = false;
let _curCN = '';
const _masked = () => '\u25cf'.repeat(Math.min(_tok.length, 32));

function _curlCmd(vis) {
  const t = vis ? _tok : _masked();
  const enc = encodeURIComponent(_curCN);
  const safe = _curCN.replace(/\\*/g, 'wildcard').replace(/\\//g, '_');
  const url = location.origin + '/api/v1/certs/' + enc + '/key.pem';
  const NL = String.fromCharCode(10);
  const BS = String.fromCharCode(92);
  return 'TOKEN="' + t + '"' + NL
    + 'curl -s ' + BS + NL
    + '  -H "Authorization: Bearer $TOKEN" ' + BS + NL
    + '  ' + url + ' ' + BS + NL
    + '  -o ' + safe + '.key';
}

function openKeyModal(cn) {
  _curCN = cn;
  _tokVis = false;
  document.getElementById('kmodal-cn').textContent = cn;
  document.getElementById('curl-cmd').textContent = _curlCmd(false);
  document.getElementById('km-tok-btn').textContent = 'Show token';
  document.getElementById('km-copy-st').textContent = '';
  document.getElementById('kmodal-bg').classList.add('open');
}

function closeKeyModal() {
  _tokVis = false;
  document.getElementById('kmodal-bg').classList.remove('open');
}

function toggleTok() {
  _tokVis = !_tokVis;
  document.getElementById('curl-cmd').textContent = _curlCmd(_tokVis);
  document.getElementById('km-tok-btn').textContent = _tokVis ? 'Hide token' : 'Show token';
}

function copyCurl() {
  navigator.clipboard.writeText(_curlCmd(true)).then(() => {
    const st = document.getElementById('km-copy-st');
    st.textContent = 'Copied!';
    setTimeout(() => { st.textContent = ''; }, 2000);
  });
}

// --- Issue example modal ---
let _issueTokVis = false;

function _issueCurlCmd(vis) {
  const t = vis ? _tok : _masked();
  const url = location.origin + '/api/v1/certs';
  const NL = String.fromCharCode(10);
  const BS = String.fromCharCode(92);
  return 'TOKEN="' + t + '"' + NL
    + 'curl -s -X POST ' + BS + NL
    + '  -H "Authorization: Bearer $TOKEN" ' + BS + NL
    + '  -H "Content-Type: application/json" ' + BS + NL
    + '  -d \\'{"cn": "app.local", "sans": ["www.app.local"], "key_type": "ec", "validity_days": 180}\\' ' + BS + NL
    + '  ' + url;
}

function openIssueModal() {
  _issueTokVis = false;
  document.getElementById('issue-curl-cmd').textContent = _issueCurlCmd(false);
  document.getElementById('im-tok-btn').textContent = 'Show token';
  document.getElementById('im-copy-st').textContent = '';
  document.getElementById('imodal-bg').classList.add('open');
}

function closeIssueModal() {
  _issueTokVis = false;
  document.getElementById('imodal-bg').classList.remove('open');
}

function toggleIssueTok() {
  _issueTokVis = !_issueTokVis;
  document.getElementById('issue-curl-cmd').textContent = _issueCurlCmd(_issueTokVis);
  document.getElementById('im-tok-btn').textContent = _issueTokVis ? 'Hide token' : 'Show token';
}

function copyIssueCurl() {
  navigator.clipboard.writeText(_issueCurlCmd(true)).then(() => {
    const st = document.getElementById('im-copy-st');
    st.textContent = 'Copied!';
    setTimeout(() => { st.textContent = ''; }, 2000);
  });
}

// --- API Designer ---
// Builds a ready-to-run request to any endpoint, in the user's chosen output
// format (curl is the default). Read-only: it generates commands, never sends.
const AD_ENDPOINTS = [
  {id:'list',  label:'List certificates',          method:'GET',  path:'/api/v1/certs',                params:[],     body:null},
  {id:'issue', label:'Issue a certificate',        method:'POST', path:'/api/v1/certs',                params:[],     body:[
    {name:'cn',            type:'text',   required:true, placeholder:'app.local', cn:true},
    {name:'sans',          type:'list',                  placeholder:'www.app.local, 10.0.0.1'},
    {name:'key_type',      type:'select', options:['ec','rsa'], default:'ec'},
    {name:'validity_days', type:'number', default:180}
  ]},
  {id:'meta',  label:'Get certificate metadata',   method:'GET',  path:'/api/v1/certs/{cn}',           params:['cn'], body:null},
  {id:'renew', label:'Renew a certificate',        method:'POST', path:'/api/v1/certs/{cn}/renew',     params:['cn'], body:null},
  {id:'cert',  label:'Download certificate (PEM)', method:'GET',  path:'/api/v1/certs/{cn}/cert.pem',  params:['cn'], body:null, download:'{safe}.crt'},
  {id:'key',   label:'Download private key (PEM)', method:'GET',  path:'/api/v1/certs/{cn}/key.pem',   params:['cn'], body:null, download:'{safe}.key'},
  {id:'chain', label:'Download chain (PEM)',       method:'GET',  path:'/api/v1/certs/{cn}/chain.pem', params:['cn'], body:null, download:'{safe}-chain.pem'}
];
let _adTokVis = false;
let _adCNs = [];
let _adReady = false;

function _adEp() {
  const v = document.getElementById('ad-endpoint').value;
  return AD_ENDPOINTS.find(e => e.id === v) || AD_ENDPOINTS[0];
}

function _adFillCNs() {
  const dl = document.getElementById('ad-cn-list');
  if (dl) dl.innerHTML = _adCNs.map(cn => '<option value="' + ESC(cn) + '">').join('');
}

function _adRender() {
  const ep = _adEp();
  const mb = document.getElementById('ad-method');
  mb.textContent = ep.method;
  mb.className = 'ad-method ad-m-' + ep.method.toLowerCase();
  document.getElementById('ad-path').textContent = ep.path;
  const host = document.getElementById('ad-inputs');
  let html = '';
  ep.params.forEach(p => {
    html += '<label class="ad-lbl">' + ESC(p) + ' <span class="ad-req">*</span></label>';
    html += '<input class="ad-in" data-param="' + ESC(p) + '" list="ad-cn-list" placeholder="select or type a CN">';
  });
  if (ep.body) {
    ep.body.forEach(f => {
      html += '<label class="ad-lbl">' + ESC(f.name) + (f.required ? ' <span class="ad-req">*</span>' : '') + '</label>';
      if (f.type === 'select') {
        html += '<select class="ad-in" data-body="' + ESC(f.name) + '">'
          + f.options.map(o => '<option' + (o === f.default ? ' selected' : '') + '>' + ESC(o) + '</option>').join('')
          + '</select>';
      } else {
        const typ = f.type === 'number' ? 'number' : 'text';
        const val = (f.default != null) ? ' value="' + ESC(String(f.default)) + '"' : '';
        const ph  = f.placeholder ? ' placeholder="' + ESC(f.placeholder) + '"' : '';
        const lst = f.cn ? ' list="ad-cn-list"' : '';
        html += '<input class="ad-in" type="' + typ + '" data-body="' + ESC(f.name) + '"' + lst + val + ph + '>';
      }
    });
  }
  if (!html) html = '<div class="ad-noparams">No parameters &mdash; this endpoint takes no input.</div>';
  host.innerHTML = html;
  host.querySelectorAll('.ad-in').forEach(el => {
    el.addEventListener('input', _adUpdate);
    el.addEventListener('change', _adUpdate);
  });
  _adUpdate();
}

function _adCollect() {
  const ep = _adEp();
  const host = document.getElementById('ad-inputs');
  let path = ep.path, cn = '';
  ep.params.forEach(p => {
    const el = host.querySelector('[data-param="' + p + '"]');
    const v = el ? el.value.trim() : '';
    if (p === 'cn') cn = v;
    path = path.replace('{' + p + '}', v ? encodeURIComponent(v) : '{' + p + '}');
  });
  let body = null;
  if (ep.body) {
    body = {};
    ep.body.forEach(f => {
      const el = host.querySelector('[data-body="' + f.name + '"]');
      if (!el) return;
      const v = el.value.trim();
      if (f.cn) cn = v || cn;
      if (f.type === 'list') {
        body[f.name] = v ? v.split(',').map(s => s.trim()).filter(Boolean) : [];
      } else if (f.type === 'number') {
        body[f.name] = v !== '' ? parseInt(v, 10) : (f.default != null ? f.default : null);
      } else {
        body[f.name] = v;
      }
    });
  }
  const safe = (cn || 'cert').replace(/\\*/g, 'wildcard').replace(/\\//g, '_');
  const download = ep.download ? ep.download.replace('{safe}', safe) : null;
  return {ep, path, body, download};
}

function _adGen(vis) {
  const {ep, path, body, download} = _adCollect();
  const fmt = document.getElementById('ad-format').value;
  const t = vis ? _tok : _masked();
  const url = location.origin + path;
  const bodyJson = body ? JSON.stringify(body) : null;
  const NL = String.fromCharCode(10);
  const BS = String.fromCharCode(92);
  const Q  = String.fromCharCode(39);  // single quote

  if (fmt === 'curl') {
    const lines = ['curl -s' + (ep.method !== 'GET' ? ' -X ' + ep.method : '')];
    lines.push('-H "Authorization: Bearer $TOKEN"');
    if (bodyJson) {
      lines.push('-H "Content-Type: application/json"');
      lines.push('-d ' + Q + bodyJson + Q);
    }
    lines.push('"' + url + '"');
    if (download) lines.push('-o ' + download);
    return 'TOKEN="' + t + '"' + NL + lines.join(' ' + BS + NL + '  ');
  }

  if (fmt === 'httpie') {
    let cmd;
    if (bodyJson) {
      cmd = 'echo ' + Q + bodyJson + Q + ' | http ' + ep.method + ' "' + url + '" '
          + '"Authorization: Bearer $TOKEN"';
    } else {
      cmd = 'http ' + ep.method + ' "' + url + '" "Authorization: Bearer $TOKEN"';
      if (download) cmd += ' --download --output ' + download;
    }
    return 'TOKEN="' + t + '"' + NL + cmd;
  }

  if (fmt === 'fetch') {
    const headers = ['    "Authorization": "Bearer ' + t + '"'];
    if (bodyJson) headers.push('    "Content-Type": "application/json"');
    let s = 'const res = await fetch("' + url + '", {' + NL;
    s += '  method: "' + ep.method + '",' + NL;
    s += '  headers: {' + NL + headers.join(',' + NL) + NL + '  }';
    if (bodyJson) s += ',' + NL + '  body: JSON.stringify(' + bodyJson + ')';
    s += NL + '});' + NL;
    s += download ? 'const blob = await res.blob();  // save to ' + download
                  : 'console.log(await res.json());';
    return s;
  }

  if (fmt === 'http') {
    const lines = [ep.method + ' ' + path + ' HTTP/1.1', 'Host: ' + location.host,
                   'Authorization: Bearer ' + t];
    if (bodyJson) {
      lines.push('Content-Type: application/json');
      lines.push('Content-Length: ' + new Blob([bodyJson]).size);
      lines.push('');
      lines.push(bodyJson);
    }
    return lines.join(NL);
  }

  if (fmt === 'powershell') {
    let s = '$env:TOKEN = "' + t + '"' + NL;
    s += '$headers = @{ Authorization = "Bearer $env:TOKEN" }' + NL;
    s += 'Invoke-RestMethod -Method ' + ep.method + ' -Uri "' + url + '" -Headers $headers';
    if (bodyJson) s += ' -ContentType "application/json" -Body ' + Q + bodyJson + Q;
    if (download) s += ' -OutFile ' + download;
    return s;
  }
  return '';
}

function _adUpdate() {
  document.getElementById('ad-preview').textContent = _adGen(_adTokVis);
}

function openDesigner() {
  if (!_adReady) {
    const sel = document.getElementById('ad-endpoint');
    sel.innerHTML = AD_ENDPOINTS.map(e =>
      '<option value="' + e.id + '">' + ESC(e.method + ' — ' + e.label) + '</option>').join('');
    sel.addEventListener('change', _adRender);
    document.getElementById('ad-format').addEventListener('change', _adUpdate);
    _adReady = true;
  }
  _adTokVis = false;
  _adFillCNs();
  document.getElementById('ad-tok-btn').textContent = 'Show token';
  document.getElementById('ad-copy-st').textContent = '';
  _adRender();
  document.getElementById('admodal-bg').classList.add('open');
}

function closeDesigner() {
  _adTokVis = false;
  document.getElementById('admodal-bg').classList.remove('open');
}

function toggleDesignerTok() {
  _adTokVis = !_adTokVis;
  document.getElementById('ad-tok-btn').textContent = _adTokVis ? 'Hide token' : 'Show token';
  _adUpdate();
}

function copyDesigner() {
  navigator.clipboard.writeText(_adGen(true)).then(() => {
    const st = document.getElementById('ad-copy-st');
    st.textContent = 'Copied!';
    setTimeout(() => { st.textContent = ''; }, 2000);
  });
}

// --- PEM viewer modal ---
let _pemContent = '';

async function openPemModal(cn, type, safe) {
  const url = '/dashboard/certs/' + encodeURIComponent(cn) + '/' + (type === 'cert' ? 'cert.pem' : 'chain.pem');
  const filename = type === 'cert' ? safe + '.crt' : safe + '-chain.pem';
  const label = type === 'cert' ? 'Certificate' : 'Certificate chain';
  document.getElementById('pem-modal-title').textContent = label + ' \u2014 ' + cn;
  document.getElementById('pem-content').textContent = 'Loading\u2026';
  document.getElementById('pem-copy-st').textContent = '';
  const dlBtn = document.getElementById('pem-dl-btn');
  dlBtn.href = '#';
  dlBtn.download = filename;
  _pemContent = '';
  document.getElementById('pem-modal-bg').classList.add('open');
  try {
    const r = await fetch(url);
    if (r.status === 401) { closePemModal(); showAuthError(); return; }
    if (!r.ok) { document.getElementById('pem-content').textContent = 'Error: ' + r.status; return; }
    _pemContent = await r.text();
    document.getElementById('pem-content').textContent = _pemContent;
    const blob = new Blob([_pemContent], {type: 'application/x-pem-file'});
    dlBtn.href = URL.createObjectURL(blob);
  } catch (e) {
    document.getElementById('pem-content').textContent = 'Fetch error: ' + e.message;
  }
}

function closePemModal() {
  document.getElementById('pem-modal-bg').classList.remove('open');
}

function copyPem() {
  if (!_pemContent) return;
  navigator.clipboard.writeText(_pemContent).then(() => {
    const st = document.getElementById('pem-copy-st');
    st.textContent = 'Copied!';
    setTimeout(() => { st.textContent = ''; }, 2000);
  });
}

// Event delegation — avoids inline onclick attribute quoting issues
document.getElementById('ctbody').addEventListener('click', e => {
  const btn = e.target.closest('button.key-btn');
  if (btn) openKeyModal(btn.dataset.cn);
  const cb = e.target.closest('button.cert-btn');
  if (cb) openPemModal(cb.dataset.cn, cb.dataset.type, cb.dataset.safe);
});

document.getElementById('kmodal-bg').addEventListener('click', e => {
  if (e.target === document.getElementById('kmodal-bg')) closeKeyModal();
});
document.getElementById('pem-modal-bg').addEventListener('click', e => {
  if (e.target === document.getElementById('pem-modal-bg')) closePemModal();
});
document.getElementById('imodal-bg').addEventListener('click', e => {
  if (e.target === document.getElementById('imodal-bg')) closeIssueModal();
});
document.getElementById('admodal-bg').addEventListener('click', e => {
  if (e.target === document.getElementById('admodal-bg')) closeDesigner();
});
// Root CA cert / CRL: fetch into a blob and save it, rather than navigating
// the browser straight to the HTTPS URL. A direct download over a connection
// whose certificate the browser doesn't trust yet (the local CA being exactly
// what's downloaded here) is blocked by Chrome as a "network error"; a same-page
// blob save isn't subject to the origin connection's trust state.
async function caDownload(url, filename) {
  try {
    const r = await fetch(url);
    if (r.status === 401) { showAuthError(); return; }
    if (!r.ok) {
      let msg = 'Download failed (' + r.status + ')';
      try { const j = await r.json(); if (j && j.error) msg = j.error; } catch (e) {}
      alert(msg);
      return;
    }
    const blob = await r.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 0);
  } catch (e) {
    alert('Download error: ' + e.message);
  }
}
document.querySelectorAll('a.ca-dl').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    caDownload(a.dataset.dl, a.dataset.name);
  });
});

document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeKeyModal(); closePemModal(); closeIssueModal(); closeDesigner(); } });

loadCerts();
connectSSE();
document.getElementById('fst').textContent = 'Connected';
setInterval(loadCerts, 30000);
</script>
</body>
</html>
"""


# --- TLS cipher policy (see CLAUDE.md) -------------------------------------
# TLS 1.2 fallback suites; TLS 1.3 suites are governed by OpenSSL defaults,
# which already match the allowed set.
_TLS12_CIPHERS = ":".join(
    [
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-CHACHA20-POLY1305",
        "ECDHE-RSA-CHACHA20-POLY1305",
    ]
)


def server_ssl_context(root: Path) -> tuple[ssl.SSLContext | None, str | None]:
    """Build an SSL context from the configured server cert, if available.

    Returns ``(context, fqdn)``. If no server FQDN is configured, or its
    certificate/key is missing (e.g. the user deleted or revoked it), returns
    ``(None, fqdn)`` so the caller can fall back to plain HTTP.
    """
    fqdn = store.get_server_fqdn(root)
    if not fqdn:
        return None, None

    entry = store.get_cert(root, fqdn)
    if entry is None:
        return None, fqdn

    chain = Path(entry.get("chain", ""))
    key = Path(entry.get("key", ""))
    if not chain.exists() or not key.exists():
        return None, fqdn

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers(_TLS12_CIPHERS)
        ctx.load_cert_chain(certfile=str(chain), keyfile=str(key))
    except (ssl.SSLError, OSError):
        return None, fqdn
    return ctx, fqdn


class APIServer:
    """Stoppable WSGI server suitable for running inside a Textual TUI.

    Always binds an HTTP listener. When *ssl_context* is supplied it also binds
    an HTTPS listener on *https_port*, which becomes the advertised default.
    """

    def __init__(
        self,
        host: str,
        port: int,
        token: str,
        root: Path,
        threaded: bool = True,
        https_port: int | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.event_log = EventLog()
        flask_app = create_app(root, token, self.event_log)
        self.host = host
        self.port = port
        self.https_port = https_port
        self.root = root
        self.log_queue: queue.Queue[str] = queue.Queue()

        self._http = make_server(host, port, flask_app, threaded=threaded)
        self._https = None
        if ssl_context is not None and https_port is not None:
            self._https = make_server(
                host, https_port, flask_app, threaded=threaded, ssl_context=ssl_context
            )

    @property
    def secure(self) -> bool:
        return self._https is not None

    @property
    def address(self) -> str:
        """Primary URL — HTTPS when available, otherwise the HTTP fallback."""
        if self._https is not None:
            return f"https://{self.host}:{self.https_port}"
        return f"http://{self.host}:{self.port}"

    @property
    def http_address(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        _write_historical_events(self.root, self.event_log)
        _start_fs_watcher(self.root, self.event_log)
        threading.Thread(target=self._http.serve_forever, daemon=True).start()
        if self._https is not None:
            threading.Thread(target=self._https.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self._http.shutdown()
        if self._https is not None:
            self._https.shutdown()


def create_app(root: Path, token: str, event_log: EventLog | None = None) -> Flask:
    app = Flask(__name__)
    app.secret_key = hashlib.sha256(token.encode()).hexdigest()
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    _event_log = event_log if event_log is not None else EventLog()

    @app.before_request
    def _auth():
        if request.path.startswith("/dashboard"):
            return  # dashboard uses session-based auth
        auth = request.headers.get("Authorization", "")
        if not (auth.startswith("Bearer ") and hmac.compare_digest(auth[7:], token)):
            abort(401)

    @app.errorhandler(HTTPException)
    def _http_error(e: HTTPException):
        return jsonify(error=e.description), e.code

    @app.errorhandler(Exception)
    def _unexpected_error(e: Exception):
        return jsonify(error="Internal server error"), 500

    # --- Internal helpers ---

    def _entry_or_404(cn: str) -> dict:
        entry = store.get_cert(root, cn)
        if entry is None:
            abort(404, description=f"No cert found for CN={cn!r}")
        return entry  # type: ignore[return-value]

    def _pem_response(path: Path, download_name: str):
        if not path.exists():
            abort(404, description=f"File not found: {path.name}")
        return send_file(
            io.BytesIO(path.read_bytes()),
            mimetype="application/x-pem-file",
            as_attachment=True,
            download_name=download_name,
        )

    def _safe(cn: str) -> str:
        return cn.replace("*", "wildcard").replace("/", "_")

    # --- Routes ---

    @app.get("/api/v1/certs")
    def list_certs():
        return jsonify(store.list_certs(root))

    @app.post("/api/v1/certs")
    def issue():
        body = request.get_json(force=True, silent=True) or {}
        cn = (body.get("cn") or "").strip()
        if not cn:
            abort(400, description="cn is required")
        if store.get_cert(root, cn) is not None:
            abort(
                409,
                description=(
                    f"a certificate for {cn!r} already exists; "
                    "revoke it before issuing a new one"
                ),
            )
        try:
            meta = issue_cert(
                root,
                cn=cn,
                sans=body.get("sans") or [],
                key_type=body.get("key_type", "ec"),
                validity_days=int(body.get("validity_days", config.LEAF_VALIDITY_DAYS)),
                method="api",
            )
        except (CAError, ValueError) as exc:
            abort(400, description=str(exc))
        return jsonify(meta), 201  # type: ignore[return-value]

    @app.get("/api/v1/certs/<cn>")
    def cert_meta(cn: str):
        return jsonify(_entry_or_404(cn))

    @app.post("/api/v1/certs/<cn>/renew")
    def renew(cn: str):
        _entry_or_404(cn)
        try:
            meta = renew_cert(root, cn, method="api")
        except CAError as exc:
            abort(400, description=str(exc))
        return jsonify(meta)  # type: ignore[return-value]

    @app.get("/api/v1/certs/<cn>/cert.pem")
    def download_cert(cn: str):
        entry = _entry_or_404(cn)
        return _pem_response(Path(entry["cert"]), f"{_safe(cn)}.crt")

    @app.get("/api/v1/certs/<cn>/key.pem")
    def download_key(cn: str):
        entry = _entry_or_404(cn)
        store.add_event(root, "key_download", cn=cn, method="api")
        return _pem_response(Path(entry["key"]), f"{_safe(cn)}.key")

    @app.get("/api/v1/certs/<cn>/chain.pem")
    def download_chain(cn: str):
        entry = _entry_or_404(cn)
        return _pem_response(Path(entry["chain"]), f"{_safe(cn)}-chain.pem")

    # --- Dashboard auth helpers ---

    def _require_session(f):
        @wraps(f)
        def _w(*a, **kw):
            if not session.get("_auth"):
                return redirect("/dashboard/login")
            return f(*a, **kw)

        return _w

    def _require_session_api(f):
        @wraps(f)
        def _w(*a, **kw):
            if not session.get("_auth"):
                return jsonify(error="Unauthorized"), 401
            return f(*a, **kw)

        return _w

    # --- Dashboard routes ---

    @app.get("/")
    def root_redirect():
        return redirect("/dashboard")

    @app.route("/dashboard/login", methods=["GET", "POST"])
    def dashboard_login():
        if request.method == "POST":
            submitted = request.form.get("token", "")
            if hmac.compare_digest(submitted.strip(), token):
                session["_auth"] = True
                return redirect("/dashboard")
            return render_template_string(_LOGIN_HTML, error="Invalid token."), 401
        return render_template_string(_LOGIN_HTML, error="")

    @app.get("/dashboard/logout")
    def dashboard_logout():
        session.clear()
        return redirect("/dashboard/login")

    @app.get("/dashboard")
    @_require_session
    def dashboard():
        try:
            ca_nfo = f"{ca_subject(root)}  \u00b7  expires {ca_expiry(root)}"
        except Exception:
            ca_nfo = "CA info unavailable"
        return render_template_string(
            _DASHBOARD_HTML,
            ca_info=ca_nfo,
            server_url=f"{request.scheme}://{request.host}",
            ca_root=str(root),
            server_token=token,
        )

    @app.get("/dashboard/api/certs")
    @_require_session_api
    def dashboard_api_certs():
        certs = store.list_certs(root)
        result = []
        for c in certs:
            entry = dict(c)
            entry["days_left"] = days_until_expiry(c["expiry"])
            entry.pop("key", None)  # never expose key path via dashboard
            result.append(entry)
        return jsonify(result)

    @app.get("/dashboard/api/events/stream")
    @_require_session_api
    def dashboard_events_stream():
        _log = _event_log

        def _generate():
            seq = 0
            evs, seq = _log.since(0)
            for ev in evs:
                yield f"data: {json.dumps(ev)}\n\n"
            while True:
                time.sleep(0.5)
                new_evs, seq = _log.since(seq)
                for ev in new_evs:
                    yield f"data: {json.dumps(ev)}\n\n"

        return Response(
            stream_with_context(_generate()),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/dashboard/certs/<cn>/cert.pem")
    @_require_session_api
    def dashboard_cert_download(cn: str):
        entry = store.get_cert(root, cn)
        if not entry:
            abort(404)
        return _pem_response(Path(entry["cert"]), f"{_safe(cn)}.crt")

    @app.get("/dashboard/certs/<cn>/chain.pem")
    @_require_session_api
    def dashboard_chain_download(cn: str):
        entry = store.get_cert(root, cn)
        if not entry:
            abort(404)
        return _pem_response(Path(entry["chain"]), f"{_safe(cn)}-chain.pem")

    # The root CA cert and CRL are public material (the CA cert is sent in every
    # TLS handshake; the CRL is meant to be published). They are served without a
    # session so the download never redirects to an HTML login page — which the
    # browser would otherwise save as "ca.crt" — and so clients can bootstrap
    # trust of the HTTPS endpoint before they have a valid session.
    @app.get("/dashboard/ca/ca.crt")
    def dashboard_ca_download():
        ca_crt = config.ca_cert_path(root)
        if not ca_crt.exists():
            abort(404, description="CA certificate not found")
        return send_file(
            io.BytesIO(ca_crt.read_bytes()),
            mimetype="application/x-pem-file",
            as_attachment=True,
            download_name="ca.crt",
        )

    @app.get("/dashboard/ca/crl.pem")
    def dashboard_crl_download():
        crl = config.crl_path(root)
        if not crl.exists():
            abort(
                404, description="CRL not found — no certificates have been revoked yet"
            )
        return send_file(
            io.BytesIO(crl.read_bytes()),
            mimetype="application/x-pem-file",
            as_attachment=True,
            download_name="ca.crl",
        )

    return app


def run_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    https_port: int = 8443,
    debug: bool = False,
    threaded: bool = True,
) -> None:
    """Headless blocking server — used when stdout is not a TTY.

    Serves HTTP on *port* and, when a valid server certificate is configured,
    HTTPS on *https_port* as the default endpoint. Falls back to HTTP only when
    the server cert is missing (deleted or revoked).
    """
    root = config.data_dir()
    if not config.ca_cert_path(root).exists():
        raise SystemExit(
            f"Error: CA not initialised at {root}.\n"
            "Run 'ssltui' to initialise the CA first."
        )
    token = _resolve_token(root)
    ctx, fqdn = server_ssl_context(root)

    server = APIServer(
        host=host,
        port=port,
        token=token,
        root=root,
        threaded=threaded,
        https_port=https_port if ctx is not None else None,
        ssl_context=ctx,
    )

    if ctx is not None:
        base = f"https://{host}:{https_port}"
        print(f"ssltui API  →  {base}/api/v1/  (HTTPS, default)")
        print(f"Dashboard   →  {base}/dashboard")
        print(f"HTTP        →  http://{host}:{port}/  (also available)")
    else:
        base = f"http://{host}:{port}"
        if fqdn:
            print(f"WARN: server cert for {fqdn!r} is missing — serving HTTP only.")
        print(f"ssltui API  →  {base}/api/v1/")
        print(f"Dashboard   →  {base}/dashboard")
    print(f"CA root     →  {root}")

    server.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        server.stop()
