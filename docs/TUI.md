# ssltui TUI guide

The interactive terminal UI is the default mode. Launch it with:

```bash
uv run ssltui
```

On first launch the CA is uninitialised. Press **i** or click **Init CA** to
create a root CA, then **n** to issue your first certificate.

## Initialising the CA

Press **i** to open the Init CA form:

- **CA Subject (DN)** — the root certificate's distinguished name.
- **Dashboard / API server FQDN** — optional; issues a default HTTPS cert for
  this host so `ssltui serve` advertises HTTPS.
- **Restrict CN / SAN suffix** — optional name-suffix policy. Enter a suffix
  such as `.local` to lock every certificate this CA issues to names under that
  suffix; the CN and all DNS SANs are validated against it at issue time
  (`app.local` and `*.app.local` pass, `app.dev` is rejected). IP SANs are
  exempt. **Leave it blank to bypass the restriction and allow any name.** The
  policy is fixed at init and applies to every mode (TUI, CLI, API, cron renew).
- **Key type** — EC P-384 (default) or RSA 4096.

If you also supply a server FQDN, it must satisfy the suffix too, otherwise init
fails with a clear error.

## Issuing a certificate

Press **n** to open the issue form:

- **CN** — the primary hostname, e.g. `myapp.local` or `*.myapp.local`
- **SANs** — additional names, space or comma-separated: DNS names and IP addresses.
  The CN is always included automatically.
- **Validity** — days, maximum 825 (Apple/browser limit)
- **Key type** — EC P-384 (default) or RSA 4096

Example SAN values:

```
www.myapp.local, api.myapp.local, 192.168.1.10
```

Wildcard certs (`*.myapp.local`) automatically include the base domain
(`myapp.local`) as a second SAN.

If the CA was initialised with a name-suffix restriction, the issue form shows
the active policy (e.g. *names must be under `.local`*) and rejects a CN or DNS
SAN that falls outside it.

## Keyboard reference

### Main screen

| Key | Action |
|-----|--------|
| `i` | Initialise CA (hidden once CA exists) |
| `n` | Issue a new certificate |
| `c` | View the trusted root CA certificate |
| `d` | View the selected certificate |
| `x` | Revoke and delete the selected certificate |
| `p` | Change CA root directory |
| `r` | Refresh table |
| `q` | Quit |
| `↑ ↓` | Navigate certificate list |
| `Enter` | Open certificate detail |

### Certificate detail

| Key | Action |
|-----|--------|
| `r` | Force-renew (re-issues the cert immediately) |
| `x` | Revoke and delete |
| `Esc` | Close |

### Certificate / CA cert viewer

| Key | Action |
|-----|--------|
| `y` | Copy PEM to clipboard (OSC 52 — works in Windows Terminal) |
| `s` | Save PEM to a file (prompts for path) |
| `q` / `Esc` | Back |

### Forms (issue cert, init CA, change dir)

| Key | Action |
|-----|--------|
| `Enter` | Advance to next field; submit on last field |
| `Esc` | Cancel |
