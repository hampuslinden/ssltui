# ssltui API reference

The API mode exposes a small REST API for issuing, renewing, and downloading
certificates from a CA that has already been initialised. It is intended for
local automation and test tooling — not internet-facing deployment.

A read-only web dashboard is served alongside the API at `/dashboard`. It
includes an **API Designer** that builds ready-to-run requests (curl, HTTPie,
fetch, raw HTTP, or PowerShell) for every endpoint documented here. See the
[Dashboard section of the README](README.md#dashboard).

## Base URL

```
http://<host>:<port>/api/v1
```

Defaults to `http://127.0.0.1:8080`. Start the server with:

```bash
uv run ssltui serve --host 127.0.0.1 --port 8080
```

If a dashboard/API server FQDN was configured when the CA was initialised,
`serve` also exposes HTTPS on `--https-port` (default 8443) using that host's
certificate, and advertises `https://<host>:8443` as the default endpoint. The
examples below use HTTP; swap the scheme and port for HTTPS. If the server
certificate is missing (deleted or revoked), `serve` falls back to HTTP only.

The CA must already be initialised (run the TUI once), and the Flask extra must
be installed (`uv sync --extra api`).

## Authentication

Every `/api/v1` request must carry a bearer token:

```
Authorization: Bearer <token>
```

The token is read from the `SSLTUI_API_TOKEN` environment variable, or from the
`api_token` file generated in the CA directory. A missing or incorrect token
returns `401`:

```json
{ "error": "401 Unauthorized" }
```

The token can download private keys, so treat it as a secret and keep the
server reachable only from trusted infrastructure.

## Content types

- Request bodies for `POST` endpoints are JSON (`Content-Type: application/json`).
- Metadata responses are `application/json`.
- Certificate, key, and chain downloads are `application/x-pem-file`, served as
  attachments (`Content-Disposition: attachment`).

## Common path parameter: `<cn>`

`<cn>` is the certificate's Common Name. Wildcard CNs must be percent-encoded in
the URL — `*` becomes `%2A`:

```
GET /api/v1/certs/%2A.local/cert.pem
```

## Certificate metadata object

Metadata endpoints return objects of this shape:

```json
{
  "cn": "api.test.local",
  "sans": ["DNS:api.test.local", "DNS:web.test.local", "IP:10.0.0.15"],
  "key_type": "ec",
  "serial": "1A2B3C4D5E6F",
  "issued": "2026-06-14T09:30:00+00:00",
  "expiry": "Jul 14 09:30:00 2026 GMT",
  "validity_days": 30,
  "cert": "/home/you/.local/share/ssltui/certs/api.test.local/cert.crt",
  "key": "/home/you/.local/share/ssltui/certs/api.test.local/cert.key",
  "chain": "/home/you/.local/share/ssltui/certs/api.test.local/chain.crt"
}
```

| Field | Type | Notes |
|-------|------|-------|
| `cn` | string | Common Name (primary hostname) |
| `sans` | string[] | Subject Alternative Names, each prefixed `DNS:` or `IP:`. The CN is always included; wildcard CNs also include the base domain. |
| `key_type` | string | `ec` (P-384) or `rsa` (4096-bit) |
| `serial` | string | Certificate serial, uppercase hex |
| `issued` | string | ISO 8601 UTC timestamp |
| `expiry` | string | OpenSSL `notAfter` format (`%b %d %H:%M:%S %Y %Z`) |
| `validity_days` | int | Requested validity, capped at 825 days |
| `cert` / `key` / `chain` | string | Absolute server-side paths |

## Endpoints

### List certificates

```
GET /api/v1/certs
```

Returns a JSON array of [metadata objects](#certificate-metadata-object).

```bash
curl -s -H "Authorization: Bearer $SSLTUI_API_TOKEN" \
  http://127.0.0.1:8080/api/v1/certs
```

### Issue a certificate

```
POST /api/v1/certs
```

Request body:

| Field | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `cn` | string | yes | — | Common Name, e.g. `api.local` or `*.api.local` |
| `sans` | string[] | no | `[]` | Extra names. Bare values are auto-classified as `DNS:` or `IP:`; explicit `DNS:`/`IP:` prefixes are honoured. |
| `key_type` | string | no | `ec` | `ec` or `rsa` |
| `validity_days` | int | no | `180` | Capped at 825 days |

Returns `201 Created` with the new [metadata object](#certificate-metadata-object).

```bash
curl -s -X POST \
  -H "Authorization: Bearer $SSLTUI_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "cn": "api.test.local",
    "sans": ["web.test.local", "10.0.0.15"],
    "key_type": "ec",
    "validity_days": 30
  }' \
  http://127.0.0.1:8080/api/v1/certs
```

Invalid input (missing `cn`, bad `key_type`, etc.) returns `400`:

```json
{ "error": "cn is required" }
```

### Get certificate metadata

```
GET /api/v1/certs/<cn>
```

Returns the [metadata object](#certificate-metadata-object) for one
certificate, or `404` if the CN is unknown.

```bash
curl -s -H "Authorization: Bearer $SSLTUI_API_TOKEN" \
  http://127.0.0.1:8080/api/v1/certs/api.test.local
```

### Renew a certificate

```
POST /api/v1/certs/<cn>/renew
```

Re-issues the certificate, preserving its key type and SANs. Returns `200` with
the refreshed [metadata object](#certificate-metadata-object) (new serial and
expiry). Unknown CNs return `404`.

```bash
curl -s -X POST \
  -H "Authorization: Bearer $SSLTUI_API_TOKEN" \
  http://127.0.0.1:8080/api/v1/certs/api.test.local/renew
```

### Download the leaf certificate

```
GET /api/v1/certs/<cn>/cert.pem
```

```bash
curl -s -H "Authorization: Bearer $SSLTUI_API_TOKEN" \
  -o tls.crt \
  http://127.0.0.1:8080/api/v1/certs/api.test.local/cert.pem
```

### Download the private key

```
GET /api/v1/certs/<cn>/key.pem
```

Returns the leaf private key in PEM form. This is the only way to retrieve a key
over the network — the dashboard never serves keys.

```bash
curl -s -H "Authorization: Bearer $SSLTUI_API_TOKEN" \
  -o tls.key \
  http://127.0.0.1:8080/api/v1/certs/api.test.local/key.pem
```

### Download the chain bundle

```
GET /api/v1/certs/<cn>/chain.pem
```

Returns the leaf certificate concatenated with the CA certificate.

```bash
curl -s -H "Authorization: Bearer $SSLTUI_API_TOKEN" \
  -o chain.pem \
  http://127.0.0.1:8080/api/v1/certs/api.test.local/chain.pem
```

## Error responses

All errors return a JSON object with a single `error` field and an appropriate
HTTP status code:

| Status | Meaning |
|--------|---------|
| `400 Bad Request` | Invalid or missing request fields (e.g. no `cn`, bad `key_type`) |
| `401 Unauthorized` | Missing or incorrect bearer token |
| `404 Not Found` | No certificate exists for the given CN, or the file is missing |
| `500 Internal Server Error` | Unexpected server error (`{ "error": "Internal server error" }`) |

```json
{ "error": "No cert found for CN='unknown.local'" }
```
