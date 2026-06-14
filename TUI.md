# ssltui TUI guide

The interactive terminal UI is the default mode. Launch it with:

```bash
uv run ssltui
```

On first launch the CA is uninitialised. Press **i** or click **Init CA** to
create a root CA, then **n** to issue your first certificate.

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
