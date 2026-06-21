# ssltui — Local SSL Certificate Authority TUI

## Project Overview

### Three modes are available, TUI is key

A terminal UI application for managing a local SSL certificate authority (CA), written in Python. It leans on the standard library plus `textual` for the TUI and an optional `flask` extra for the API/dashboard mode; all key and certificate operations shell out to the `openssl` CLI rather than a third-party cryptography library. Intended for local development environments and private networks on Linux hosts.

A headless CLI mode is provided for cron-based renewal of certificates and integration with other tools. 

A simple Flask API and dashboard mode is also available for issuing and downloading certificates programmatically.

## Tech Stack

| Concern | Module |
|---|---|
| TUI | `textual` |
| Cryptography / cert generation | `ssl`, `subprocess` → `openssl` CLI |
| Scheduling / renewal | `cron` entry + headless CLI mode |
| Config persistence | `json` (stdlib) |
| Subprocess management | `subprocess` (stdlib) |
| Linting | `ruff` |


- Python's `ssl` module exposes verification and context objects but delegates key/cert generation to OpenSSL. The application shells out to `openssl` for all key and certificate operations — this is the standard pattern when avoiding a third-party cryptography library.

- Use strict type annotations.

- Ensure `ruff` passes with no errors or warnings.

- The token generated means everything, it can be used to download certs and keys, so it should be stored securely. 

## Cipher Policy

Use only post-2020 cipher suites. Minimum TLS 1.2, prefer TLS 1.3.

**Allowed cipher suites (TLS 1.3):**
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`

**Allowed cipher suites (TLS 1.2 fallback):**
- `ECDHE-ECDSA-AES256-GCM-SHA384`
- `ECDHE-RSA-AES256-GCM-SHA384`
- `ECDHE-ECDSA-CHACHA20-POLY1305`
- `ECDHE-RSA-CHACHA20-POLY1305`

**Forbidden:** RC4, 3DES, MD5, SHA-1 signatures, RSA key exchange (non-ECDHE), export ciphers, NULL ciphers.

**Key parameters:**
- RSA keys: 4096-bit minimum
- EC keys: P-384 (secp384r1) preferred, P-256 acceptable
- Signature hash: SHA-256 minimum, SHA-384 preferred
- CA cert validity: 10 years max
- Leaf cert validity: 825 days max (matches Apple/browser limits)

## Usage

- For public SSL recommend the user uses [Let's Encrypt](https://letsencrypt.org/) or a commercial CA. This tool is intended for local development and private networks only.

- Allow the user to create the root key with a passphrase but warn them they have to enter this every single time they use the CA. The CA is not intended for production use, and the user should be aware of the security implications of using a local CA. Default should be blank.

## Application Modes

### Interactive TUI mode (default)

```bash
ssltui
```

Full-screen textual UI. Entry point: `ssltui/tui.py`.

### Headless CLI mode

```bash
ssltui --renew          # renew all certs expiring within threshold
ssltui --renew --cert common_name   # renew a specific cert
ssltui --issue --cn foo.local [--san ...]  # non-interactive issue
ssltui --status         # print expiry table, exit 0 if all ok
```

Used by cron. Must produce machine-readable output (exit codes + stdout) and never draw curses.

### API mode

- Use flask to create an API, only issue new cert, renew cert and download cert + key should be available. It requires an already initialized CA. The API should be protected with a token or password.
- Using a file system structure for cert storage can cause concurrency issues if multiple processes are trying to read/write the same files.

## Dashboard mode

- In flask serve mode display a simple dashboard with a list of existing cert, no modifications allowed via the GUI. Allow the user to download certs, no keys via web UI, only API and TUI. It should reload and show new certs / deleted certs / revoked certs every 30 seconds.

## CA Data Directory

Default: `~/.local/share/ssltui/` (overridden via `SSLTUI_DIR` env var or `--dir` flag).

```text
$SSLTUI_DIR/
├── ca.key          # CA private key (chmod 600)
├── ca.crt          # CA certificate (self-signed)
├── ca.db           # SQLite store: cert index, revocations, event log, counters
├── certs/
│   ├── <cn>/
│   │   ├── cert.crt
│   │   ├── cert.key   (chmod 600)
│   │   └── chain.crt  # cert + CA bundled
│   └── ...
└── ca.crl          # certificate revocation list (PEM, regenerated on each revocation)
```

### Metadata store (`ca.db`)

All cert metadata, revocations, counters (serial / CRL number), and an
append-only **event log** live in a single SQLite database (`ssltui/store.py`),
replacing the earlier `index.json`. WAL mode plus a busy timeout let the TUI,
the cron `--renew` process, and the multi-threaded Flask API read and write
concurrently without explicit file locking. Cert/key material itself stays as
flat PEM files under `certs/<cn>/`.

Tables: `certs` (CN → metadata JSON), `revoked` (serial → JSON), `events`
(`id`, `ts`, `type`, `cn`, `method`, `detail`), and `meta` (serial, crl_number,
server_fqdn, and a `version` counter the dashboard/TUI watchers poll to refresh).

Events record lifecycle actions (`issue`, `renew`, `revoke`) and every private
**key access** (`key_download`), each tagged with the originating `method`
(`api` / `tui` / `cli` / `cron`). The events table is the system of record for
the dashboard and TUI live activity logs.

## Renewal

Cron entry (installed by the app):

```bash
0 3 * * * /usr/bin/python3 -m ssltui renew >> ~/.local/share/ssltui/renewal.log 2>&1
```

Renewal threshold: renew if cert expires within 30 days (configurable). The `--renew` path must be fully non-interactive and safe to run as a cron job with no TTY.


## Infrastructure Requirements

- Linux host with Python 3.11+ and OpenSSL installed.
- Use `uv` for environment isolation.
- Do not require sudo or root privileges — the CA is intended for local development use only

## Coding Conventions

- Python 3.11+ minimum (uses `tomllib`, `match` statements acceptable).
- Minimal dependencies: standard library, plus `textual` (TUI) and an optional `flask` extra (API/dashboard). No third-party cryptography library — all key/cert work goes through the `openssl` CLI.
- All `openssl` calls go through a single `ca.run_openssl(args, input=None)` helper that captures stderr and raises a typed `CAError` on non-zero exit.
- Textual layout uses a screen stack: each screen is a `Screen`/`ModalScreen` subclass that builds its widgets in `compose()`, declares `BINDINGS`, and responds via `on_*` event handlers and `action_*` methods. Navigation is `push_screen` / `pop_screen` (dismiss).
- Secrets (private keys) are never logged or printed to stdout in any mode.
- File permissions enforced immediately after write: keys → 0o600, certs → 0o644, directories → 0o700.

## TUI features

- Support subject alternative name (and encourage it for certs).
- Support wildcard certs
- Support both RSA and EC keys (configurable per cert).
- Support for custom validity periods (within limits) with a default of 180 days

## Documentation

- The root README.md should include the overview, installation instructions, and usage examples.

- The CLAUDE.md file should include the technical overview, architecture, and design decisions.

- The API.md file should include the API endpoints, request/response formats, and authentication details. Including examples.

