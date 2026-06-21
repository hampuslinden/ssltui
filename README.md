# ssltui

A terminal UI for managing a local SSL Certificate Authority. Create a root CA,
issue leaf certificates with SANs, renew, and revoke — all from the keyboard.
Runs headlessly for cron-driven renewal too.

## Development-only tool

`ssltui` is for local development, CI, and private test environments only.
It is not a production PKI, is not appropriate for public-trust TLS, and should
not be used as a replacement for Let's Encrypt or a commercial CA.

Use it when you need locally trusted certificates for things like:

- local hostnames such as `*.local` or internal test domains
- integration tests that need HTTPS end-to-end
- ephemeral Kubernetes or container-based test environments
- homelab environments where you control the trust store

Do not expose the CA private key, issued private keys, or the API server to
untrusted networks. If you need publicly trusted certificates, use a real CA.

## Requirements

- Linux host (WSL2 on Windows works)
- [uv](https://docs.astral.sh/uv/) — handles Python 3.11+ and dependencies
- OpenSSL (`openssl` in `$PATH`)

Check you have OpenSSL:

```
openssl version
```

Install `uv` if you don't have it:

```
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## Quick start

```bash
git clone https://github.com/hampuslinden/ssltui.git
cd ssltui
uv sync          # installs Python 3.11+ and textual into a local venv
uv run ssltui    # launch the TUI
```

On first launch the CA is uninitialised. Press **i** or click **Init CA** to
create a root CA, then **n** to issue your first certificate.

## Data directory

Certificates and keys are stored in `~/.local/share/ssltui/` by default.

Override with an environment variable:

```bash
SSLTUI_DIR=~/my-ca uv run ssltui
```

Or pass the path as the first argument (also works with subcommands):

```bash
uv run ssltui ~/my-ca
uv run ssltui ~/my-ca status
```

Each directory is an independent CA. You can maintain multiple CAs by pointing
at different directories or by using **p Root dir** in the TUI to switch at runtime.

### Directory layout

```
~/.local/share/ssltui/
├── ca.key          # CA private key (0600)
├── ca.crt          # CA certificate (self-signed)
├── ca.db           # SQLite store: cert index, revocations, event log, counters
├── ca.crl          # certificate revocation list (PEM)
├── api_token       # generated API/dashboard bearer token (0600)
├── certs/
│   └── <cn>/
│       ├── cert.crt    # signed leaf certificate
│       ├── cert.key    # leaf private key (0600)
│       └── chain.crt   # leaf + CA bundled
└── renewal.log
```

Cert and key material stays as flat PEM files under `certs/<cn>/`; all
metadata — the cert index, revocation list, an append-only event log, and the
serial / CRL-number counters — lives in the single SQLite database `ca.db`.
It runs in WAL mode so the TUI, the cron `renew` job, and the Flask API can
read and write concurrently without explicit file locking.

## Using the TUI

The interactive TUI is the default mode (`uv run ssltui`). Press **i** to
initialise the CA and **n** to issue a certificate. For the full keyboard
reference and the issue-form walkthrough, see [TUI.md](docs/TUI.md).

![ssltui TUI showing the certificate list](docs/artifacts/tui.png)

The certificate list shows each cert's CN, SANs, key type, expiry, and days
left, with footer key bindings for the common actions.

## Trusting the root CA

After creating your CA, get the root certificate one of two ways:

- **In the TUI** — press **c** to view the root certificate PEM, then **y** to
  copy it to the clipboard or **s** to save it to a file.
- **From the dashboard** — if the API server is running, click **↓ CA cert** in
  the status bar to download `ca.crt`. (Only the public CA certificate is served
  over the web — never private keys.)

### Linux (system trust)

```bash
sudo cp local-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

### Chrome / Chromium

Settings → Privacy → Manage certificates → Authorities → Import

### Firefox

Settings → Privacy → View Certificates → Authorities → Import

### Windows (for WSL users)

In PowerShell (as Administrator):

```powershell
Import-Certificate -FilePath "local-ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
```

## Headless / cron mode

### Print expiry status

```bash
uv run ssltui status          # exits 0 if all certs ok, 1 if any expired
uv run ssltui ~/my-ca status  # same for a specific CA dir
```

### Renew expiring certs

Renews all certs expiring within 30 days:

```bash
uv run ssltui renew
```

Renew a specific cert by CN:

```bash
uv run ssltui renew --cert myapp.local
```

### Issue non-interactively

```bash
uv run ssltui issue --cn api.local --san www.api.local --san 10.0.0.1 --days 365
```

### Get the root CA certificate

Print the root CA certificate (PEM) to stdout — handy for piping into a trust
store. A short summary is written to stderr when run interactively, so the
redirected output stays a clean PEM:

```bash
uv run ssltui getroot > local-ca.crt
# or write it directly
uv run ssltui getroot --out local-ca.crt
```

### Cron entry

Install via the TUI's **Cron Schedule** option, or add manually:

```
0 3 * * * /path/to/venv/bin/ssltui renew >> ~/.local/share/ssltui/renewal.log 2>&1
```

## API mode

API mode starts a small Flask server for programmatic certificate issuance,
renewal, and downloads. It is intended for local automation and test tooling,
not internet-facing deployment.

### Prerequisites

- the CA must already be initialised
- install the API extra: `uv sync --extra api`
- provide an API token with `SSLTUI_API_TOKEN`, or use the generated
  `api_token` file in the CA directory

### Start the API server / dashboard

Bind to localhost by default:

```bash
uv run ssltui serve
```

Listen on another address or port:

```bash
uv run ssltui serve --host 0.0.0.0 --port 8080 --https-port 8443
```

The helper script installs the Flask extra and starts the same command:

```bash
./ssltui_web.sh --host 0.0.0.0 --port 8080
```

#### Running in the background on a server

`ssltui serve` (like the TUI) runs in the foreground and stops when you log out.
To keep it running on a remote server after you disconnect, start it inside a
[tmux](https://github.com/tmux/tmux/wiki) session:

```bash
tmux new -s ssltui          # start a session
uv run ssltui serve --host 0.0.0.0 --port 8080
# detach with Ctrl-b then d — the server keeps running
```

Reattach later with `tmux attach -t ssltui`. (`screen` or a systemd user
service work equally well.)

While the server runs, the TUI shows a live access log alongside historical
issue events:

![ssltui API server screen with live access log](docs/artifacts/api.png)

#### HTTP and HTTPS

If you supplied a **dashboard / API server FQDN** when initialising the CA,
`ssltui` issues a default certificate for that host and `serve` listens on
**both HTTP (`--port`, default 8080) and HTTPS (`--https-port`, default 8443)**,
advertising HTTPS as the default endpoint. If that server certificate is later
deleted or revoked, `serve` automatically falls back to HTTP only.

Clients connecting over HTTPS should trust your `ca.crt` (see
[Trusting the root CA](#trusting-the-root-ca)).

### Authentication

Every request must include a bearer token:

```bash
Authorization: Bearer <token>
```

If you expose the server beyond localhost, treat that token like a secret. The
API can return private keys, so it should only be reachable from trusted test
infrastructure.

### Input validation

The `<cn>` path parameter is validated against a strict hostname allow-list
(DNS hostnames and wildcards only). Anything else — path separators, `..`, or
control characters — is rejected with `400 Bad Request` before any lookup.
Certificate, key, and chain downloads are confined to the CA's `certs/<cn>/`
directory, so a request can never read files outside it.

### Endpoints

- `GET /api/v1/certs` lists all certificates
- `POST /api/v1/certs` issues a new certificate
- `GET /api/v1/certs/<cn>` returns metadata for one certificate
- `POST /api/v1/certs/<cn>/renew` renews a certificate
- `GET /api/v1/certs/<cn>/cert.pem` downloads the leaf certificate
- `GET /api/v1/certs/<cn>/key.pem` downloads the private key
- `GET /api/v1/certs/<cn>/chain.pem` downloads the chain bundle
- `GET /api/v1/crl.pem` downloads the certificate revocation list

Example issue request:

```bash
curl -X POST http://127.0.0.1:8080/api/v1/certs \
  -H "Authorization: Bearer $SSLTUI_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cn": "api.test.local",
    "sans": ["api.test.local", "web.test.local", "10.0.0.15"],
    "key_type": "ec",
    "validity_days": 30
  }'
```

Example download request:

```bash
curl -H "Authorization: Bearer $SSLTUI_API_TOKEN" \
  -o tls.crt \
  http://127.0.0.1:8080/api/v1/certs/api.test.local/cert.pem
```

### Kubernetes test integration

API mode is useful when a Kubernetes-based test harness needs short-lived TLS
material for internal services. A common pattern is:

1. start `ssltui serve` on a trusted runner, sidecar, or cluster-internal
   utility pod
2. create a cert for the test hostname before the suite starts
3. download the cert, key, and CA cert into a Kubernetes `Secret` or mounted
   test workspace
4. mount that material into the application pod and the test client pod
5. trust the CA cert in the test container so HTTPS verification succeeds

This works well for ephemeral environments such as `kind`, `k3d`, Minikube, or
CI-created namespaces where you control both the server and client trust stores.

Operational guidance:

- keep the API service cluster-internal; do not publish it through an ingress
- store the bearer token as a Kubernetes `Secret`
- scope each test run to its own CA directory when isolation matters
- prefer short certificate validity for ephemeral environments
- clean up issued certs and secrets with the rest of the test namespace

If your framework already provisions Secrets, the API call can be a pre-test
step that writes `tls.crt`, `tls.key`, and the CA cert into a Secret manifest
before the workload is deployed.

## Dashboard

Starting the API server also serves a read-only web dashboard at
`/dashboard` on the same host and port:

```bash
uv run ssltui serve            # dashboard at http://127.0.0.1:8080/dashboard
```

![ssltui web dashboard with certificate list and live event log](docs/artifacts/webui.png)

Sign in with your API token. The dashboard:

- lists every issued certificate with its SANs, key type, and expiry, and
  refreshes automatically every 30 seconds
- streams a live event log (issued / renewed / revoked, CRL regeneration)
- lets you view and download the **certificate** and **chain** PEMs
- provides **root CA certificate**, **CRL**, and **audit log** (CSV) download
  links in the status bar (the audit log requires a signed-in session)

For safety, the dashboard never modifies the CA and never serves private keys —
key downloads are available only through the API and the TUI.

### API Designer

The **API Designer** button (top-right of the dashboard) builds a ready-to-run
request to any endpoint without leaving the browser:

![ssltui API Designer modal building a request](docs/artifacts/apidesigner.png)

1. pick an endpoint — the method badge and path update automatically
2. fill in the path parameter (`cn`, with autocomplete from your existing
   certificates) and any request-body fields (`sans`, `key_type`,
   `validity_days`)
3. choose an output format — **curl** (default), **HTTPie**,
   **JavaScript (fetch)**, **Raw HTTP**, or **PowerShell**
4. toggle **Show token** to reveal the bearer token, then **Copy**

The generated command is masked by default and copies with the real token. The
designer only *builds* commands — it never sends mutating requests from the
browser, keeping the dashboard read-only. For the full endpoint reference, see
[API.md](docs/API.md).

## Cipher policy

Only post-2020 suites are used. Keys default to EC P-384; RSA 4096 is also
available. Certificates are signed with SHA-384. The leaf cert validity cap is
825 days (matches Apple and browser requirements).

Forbidden: RC4, 3DES, MD5, SHA-1 signatures, RSA key exchange, export ciphers,
NULL ciphers.

## Development

Install the dev tooling (Ruff + pytest) into the venv:

```bash
uv sync --extra dev
```

Lint, autofix, and format with [Ruff](https://docs.astral.sh/ruff/):

```bash
uv run ruff check .          # lint
uv run ruff check --fix .    # lint and apply safe autofixes
uv run ruff format .         # format in place
uv run ruff format --check . # verify formatting (what CI runs)
```

Run the tests:

```bash
uv run pytest
```

CI runs the same `ruff check`, `ruff format --check`, and `pytest` on every push
and pull request (see [.github/workflows/ci.yml](.github/workflows/ci.yml)).
