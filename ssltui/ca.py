"""CA lifecycle: init, issue, revoke, renew.

All key/cert operations shell out to openssl. Private keys are never
logged or printed.
"""

from __future__ import annotations

import os
import secrets
import shutil
import socket
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from ssltui import config

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CAError(Exception):
    """Raised when an openssl command fails or the CA is in an invalid state."""


# ---------------------------------------------------------------------------
# Low-level openssl wrapper
# ---------------------------------------------------------------------------


def run_openssl(args: list[str], input: bytes | None = None) -> bytes:
    """Run openssl with *args*, return stdout bytes, raise CAError on failure."""
    cmd = ["openssl"] + args
    result = subprocess.run(
        cmd,
        input=input,
        capture_output=True,
    )
    if result.returncode != 0:
        raise CAError(result.stderr.decode(errors="replace").strip())
    return result.stdout


# ---------------------------------------------------------------------------
# CA initialisation
# ---------------------------------------------------------------------------


def init_ca(
    root: Path,
    key_type: str = "ec",
    subject: str | None = None,
    server_fqdn: str | None = None,
    name_suffix: str | None = None,
) -> None:
    """Create CA key and self-signed certificate in *root*.

    Args:
        root: Data directory (created if absent).
        key_type: ``"ec"`` (default, P-384) or ``"rsa"`` (4096-bit).
        subject: OpenSSL subject string; defaults to config.CA_SUBJECT.
        server_fqdn: Optional FQDN for the dashboard/API server. When given,
            a leaf certificate is issued for it and recorded as the server
            cert so ``ssltui serve`` can present HTTPS by default.
        name_suffix: Optional CN/SAN name-suffix policy (e.g. ``".local"``).
            When set, every later cert request must use names under this
            suffix. Blank/None leaves issuance unrestricted.
    """
    try:
        name_suffix = config.normalize_name_suffix(name_suffix or "")
    except ValueError as exc:
        raise CAError(str(exc)) from exc

    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    (root / "certs").mkdir(mode=0o700, exist_ok=True)

    key_path = config.ca_key_path(root)
    cert_path = config.ca_cert_path(root)

    if key_path.exists() and cert_path.exists():
        raise CAError(
            "CA already initialised. Delete ca.key and ca.crt to reinitialise."
        )

    if subject is None:
        subject = config.CA_SUBJECT

    # --- Generate key ---
    if key_type == "ec":
        run_openssl(
            [
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                f"ec_paramgen_curve:{config.EC_CURVE}",
                "-out",
                str(key_path),
            ]
        )
    elif key_type == "rsa":
        run_openssl(
            [
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                f"rsa_keygen_bits:{config.RSA_BITS}",
                "-out",
                str(key_path),
            ]
        )
    else:
        raise CAError(f"Unknown key type: {key_type!r}. Use 'ec' or 'rsa'.")

    key_path.chmod(0o600)

    # --- Self-sign CA certificate ---
    run_openssl(
        [
            "req",
            "-new",
            "-x509",
            "-key",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            str(config.CA_VALIDITY_DAYS),
            "-subj",
            subject,
            "-sha384",
            "-extensions",
            "v3_ca",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-addext",
            "subjectKeyIdentifier=hash",
        ]
    )
    cert_path.chmod(0o644)
    generate_crl(root)

    token_path = config.api_token_path(root)
    token_path.write_text(secrets.token_hex(32))
    token_path.chmod(0o600)

    # Persist the name-suffix policy before issuing anything so the default
    # server cert below is validated against it too.
    if name_suffix:
        from ssltui.store import set_name_suffix

        set_name_suffix(root, name_suffix)

    # --- Default dashboard/API server certificate ---
    if server_fqdn:
        server_fqdn = server_fqdn.strip()
    if server_fqdn:
        # Include the host's local IPs as SANs so the dashboard/API can be
        # reached over a raw IP (e.g. https://192.168.1.10:8443) and not just
        # the FQDN.
        issue_cert(root, cn=server_fqdn, sans=local_ip_sans(), key_type=key_type)
        from ssltui.store import set_server_fqdn

        set_server_fqdn(root, server_fqdn)


# ---------------------------------------------------------------------------
# Certificate issuance
# ---------------------------------------------------------------------------


def issue_cert(
    root: Path,
    cn: str,
    sans: list[str] | None = None,
    key_type: str = "ec",
    validity_days: int = config.LEAF_VALIDITY_DAYS,
    method: str = "tui",
    event_type: str = "issue",
) -> dict:
    """Issue a signed leaf certificate.

    Returns the metadata dict that was written to the store. ``method`` records
    which interface triggered the issue (api/tui/cli/cron); ``event_type`` lets
    renew_cert log a ``renew`` instead of a duplicate ``issue``.
    """
    if not config.ca_key_path(root).exists():
        raise CAError("CA not initialised. Run init_ca() first.")

    try:
        cn = config.validate_cn(cn)
    except ValueError as exc:
        raise CAError(str(exc)) from exc

    validity_days = min(validity_days, config.LEAF_VALIDITY_MAX)

    san_list = _build_san_list(cn, sans)
    _enforce_name_suffix(root, cn, san_list)
    san_ext = ",".join(san_list)

    cert_dir = config.cert_dir(root, cn)
    cert_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    key_path = cert_dir / "cert.key"
    csr_path = cert_dir / "cert.csr"
    cert_path = cert_dir / "cert.crt"
    chain_path = cert_dir / "chain.crt"

    # --- Generate key ---
    if key_type == "ec":
        run_openssl(
            [
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                f"ec_paramgen_curve:{config.EC_CURVE}",
                "-out",
                str(key_path),
            ]
        )
    elif key_type == "rsa":
        run_openssl(
            [
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                f"rsa_keygen_bits:{config.RSA_BITS}",
                "-out",
                str(key_path),
            ]
        )
    else:
        raise CAError(f"Unknown key type: {key_type!r}.")

    key_path.chmod(0o600)

    # --- Generate CSR ---
    run_openssl(
        [
            "req",
            "-new",
            "-key",
            str(key_path),
            "-out",
            str(csr_path),
            "-subj",
            f"/CN={cn}",
            "-sha384",
        ]
    )

    # --- Sign with CA using a temporary ext file ---
    ext_content = _build_ext_file(san_ext)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".ext", delete=False) as f:
        f.write(ext_content)
        ext_file = f.name

    from ssltui.store import next_serial

    serial_num = next_serial(root)

    try:
        run_openssl(
            [
                "x509",
                "-req",
                "-in",
                str(csr_path),
                "-CA",
                str(config.ca_cert_path(root)),
                "-CAkey",
                str(config.ca_key_path(root)),
                "-set_serial",
                str(serial_num),
                "-out",
                str(cert_path),
                "-days",
                str(validity_days),
                "-sha384",
                "-extfile",
                ext_file,
                "-extensions",
                "req_ext",
            ]
        )
    finally:
        os.unlink(ext_file)
        csr_path.unlink(missing_ok=True)

    cert_path.chmod(0o644)

    # --- Build chain (leaf + CA) ---
    ca_cert_data = config.ca_cert_path(root).read_bytes()
    chain_path.write_bytes(cert_path.read_bytes() + ca_cert_data)
    chain_path.chmod(0o644)

    # --- Read serial and expiry from the signed cert ---
    serial = _read_serial(cert_path)
    expiry = _read_expiry(cert_path)

    metadata = {
        "cn": cn,
        "sans": san_list,
        "key_type": key_type,
        "serial": serial,
        "issued": datetime.now(UTC).isoformat(),
        "expiry": expiry,
        "validity_days": validity_days,
        "cert": str(cert_path),
        "key": str(key_path),
        "chain": str(chain_path),
    }

    from ssltui.store import add_cert, add_event

    add_cert(root, metadata)
    add_event(root, event_type, cn=cn, method=method)

    return metadata


# ---------------------------------------------------------------------------
# Renewal
# ---------------------------------------------------------------------------


def renew_cert(root: Path, cn: str, method: str = "tui") -> dict:
    """Re-issue a cert for *cn*, preserving its key type and SANs."""
    from ssltui.store import get_cert

    entry = get_cert(root, cn)
    if entry is None:
        raise CAError(f"No cert found for CN={cn!r}.")

    # Remove old cert files so issue_cert can overwrite
    cert_dir = config.cert_dir(root, cn)
    for fname in ("cert.crt", "cert.key", "chain.crt"):
        p = cert_dir / fname
        if p.exists():
            p.unlink()

    from ssltui.store import remove_cert

    remove_cert(root, cn)

    return issue_cert(
        root,
        cn=entry["cn"],
        sans=[
            s
            for s in entry["sans"]
            if not s.startswith("DNS:" + cn) and s != f"IP:{cn}"
        ],
        key_type=entry.get("key_type", "ec"),
        validity_days=entry.get("validity_days", config.LEAF_VALIDITY_DAYS),
        method=method,
        event_type="renew",
    )


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


def revoke_cert(root: Path, cn: str, method: str = "tui") -> None:
    """Revoke a cert, update ca.crl, delete its files, and remove it from the store."""
    from ssltui.store import add_event, add_revoked, get_cert, remove_cert

    entry = get_cert(root, cn)
    if entry is None:
        raise CAError(f"No cert found for CN={cn!r}.")

    add_revoked(
        root,
        {
            "cn": cn,
            "serial": entry["serial"],
            "expiry": entry["expiry"],
            "revoked_at": datetime.now(UTC).isoformat(),
        },
    )
    generate_crl(root)

    cd = config.cert_dir(root, cn)
    if cd.exists():
        shutil.rmtree(cd)

    remove_cert(root, cn)
    add_event(root, "revoke", cn=cn, method=method)


def generate_crl(root: Path) -> Path:
    """Generate a signed CRL via openssl and append the PEM block to ca.crl.

    Each call appends one PEM CRL block so the file accumulates a full history.
    Returns the path to ca.crl.
    """
    from ssltui.store import list_revoked, next_crl_number

    revoked = list_revoked(root)
    crl_num = next_crl_number(root)

    with tempfile.TemporaryDirectory() as _tmp:
        tmpdir = Path(_tmp)
        (tmpdir / "newcerts").mkdir()

        seen: set[str] = set()
        lines = []
        for r in revoked:
            serial = r["serial"]
            if len(serial) % 2:
                serial = "0" + serial
            if serial in seen:
                continue
            seen.add(serial)
            expiry = _to_openssl_date(r["expiry"])
            revoked_at = _to_openssl_date(r["revoked_at"])
            lines.append(
                f"R\t{expiry}\t{revoked_at}\t{serial}\tunknown\t/CN={r['cn']}\n"
            )
        (tmpdir / "index.txt").write_text("".join(lines))
        (tmpdir / "index.txt.attr").write_text("unique_subject = no\n")
        (tmpdir / "crlnumber").write_text(f"{crl_num:04X}\n")
        (tmpdir / "openssl.cnf").write_text(_build_crl_config(tmpdir, root))

        crl_tmp = tmpdir / "crl.pem"
        run_openssl(
            [
                "ca",
                "-gencrl",
                "-config",
                str(tmpdir / "openssl.cnf"),
                "-out",
                str(crl_tmp),
            ]
        )

        dest = config.crl_path(root)
        with open(dest, "ab") as f:
            f.write(crl_tmp.read_bytes())
        dest.chmod(0o644)

    return dest


# ---------------------------------------------------------------------------
# CA info helpers
# ---------------------------------------------------------------------------


def ca_fingerprint(root: Path) -> str:
    out = run_openssl(
        [
            "x509",
            "-noout",
            "-fingerprint",
            "-sha256",
            "-in",
            str(config.ca_cert_path(root)),
        ]
    )
    return out.decode().strip().split("=", 1)[-1]


def ca_expiry(root: Path) -> str:
    out = run_openssl(
        ["x509", "-noout", "-enddate", "-in", str(config.ca_cert_path(root))]
    )
    return out.decode().strip().split("=", 1)[-1]


def ca_subject(root: Path) -> str:
    out = run_openssl(
        ["x509", "-noout", "-subject", "-in", str(config.ca_cert_path(root))]
    )
    return out.decode().strip().split("=", 1)[-1]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def local_ip_sans() -> list[str]:
    """Return ``IP:`` SAN entries for the loopback and primary local addresses.

    Used when issuing the default dashboard/API server cert so it is valid when
    reached over a raw IP, not just the FQDN. Best-effort: detection failures are
    silently skipped.
    """
    ips: list[str] = ["127.0.0.1", "::1"]

    # Primary outbound IPv4 — connecting a UDP socket sends no packets but lets
    # the OS pick the source address for the default route.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ips.append(s.getsockname()[0])
        finally:
            s.close()
    except OSError:
        pass

    # Whatever the hostname resolves to (covers extra interfaces).
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.append(info[4][0])
    except OSError:
        pass

    seen: set[str] = set()
    out: list[str] = []
    for ip in ips:
        ip = ip.split("%", 1)[0]  # strip IPv6 zone id (e.g. fe80::1%eth0)
        if ip and ip not in seen:
            seen.add(ip)
            out.append(f"IP:{ip}")
    return out


def _enforce_name_suffix(root: Path, cn: str, san_list: list[str]) -> None:
    """Reject the request if the CN or any DNS SAN escapes the CA's policy.

    IP SANs are exempt — a name-suffix policy only constrains DNS hostnames.
    No-op when the CA was initialised without a suffix restriction.
    """
    from ssltui.store import get_name_suffix

    suffix = get_name_suffix(root)
    if not suffix:
        return

    names = [cn] + [e[4:] for e in san_list if e.startswith("DNS:")]
    offenders = [n for n in names if not config.name_matches_suffix(n, suffix)]
    if offenders:
        uniq = ", ".join(dict.fromkeys(offenders))
        raise CAError(
            f"name(s) not permitted by CA policy (must be under .{suffix}): {uniq}"
        )


def _build_san_list(cn: str, extra_sans: list[str] | None) -> list[str]:
    """Build the full SAN list, always including the CN."""
    sans: list[str] = []

    # Always add CN as DNS SAN
    if cn.startswith("*."):
        sans.append(f"DNS:{cn}")
        # Also include the base domain
        base = cn[2:]
        sans.append(f"DNS:{base}")
    else:
        sans.append(f"DNS:{cn}")

    if extra_sans:
        for san in extra_sans:
            san = san.strip()
            if not san:
                continue
            if san.startswith("DNS:") or san.startswith("IP:"):
                entry = san
            elif _looks_like_ip(san):
                entry = f"IP:{san}"
            else:
                entry = f"DNS:{san}"
            if entry not in sans:
                sans.append(entry)

    return sans


def _looks_like_ip(s: str) -> bool:
    import re

    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))


def _build_ext_file(san_ext: str) -> str:
    return (
        "[req_ext]\n"
        "subjectAltName = " + san_ext + "\n"
        "basicConstraints = CA:FALSE\n"
        "keyUsage = critical, digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth, clientAuth\n"
        "subjectKeyIdentifier = hash\n"
        "authorityKeyIdentifier = keyid,issuer\n"
    )


def _read_serial(cert_path: Path) -> str:
    out = run_openssl(["x509", "-noout", "-serial", "-in", str(cert_path)])
    return out.decode().strip().split("=", 1)[-1]


def _read_expiry(cert_path: Path) -> str:
    out = run_openssl(["x509", "-noout", "-enddate", "-in", str(cert_path)])
    return out.decode().strip().split("=", 1)[-1]


def _to_openssl_date(date_str: str) -> str:
    """Convert ISO 8601 or OpenSSL notAfter strings to YYYYMMDDHHMMSSZ."""
    date_str = date_str.strip()
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    return dt.strftime("%y%m%d%H%M%SZ")


def _build_crl_config(tmpdir: Path, root: Path) -> str:
    return (
        "[ ca ]\n"
        "default_ca = CA_default\n\n"
        "[ CA_default ]\n"
        f"dir             = {tmpdir}\n"
        "database        = $dir/index.txt\n"
        "new_certs_dir   = $dir/newcerts\n"
        f"certificate     = {config.ca_cert_path(root)}\n"
        f"private_key     = {config.ca_key_path(root)}\n"
        "crlnumber       = $dir/crlnumber\n"
        "default_md      = sha384\n"
        "default_crl_days = 30\n"
        "policy          = policy_anything\n\n"
        "[ policy_anything ]\n"
        "countryName             = optional\n"
        "stateOrProvinceName     = optional\n"
        "localityName            = optional\n"
        "organizationName        = optional\n"
        "organizationalUnitName  = optional\n"
        "commonName              = supplied\n"
        "emailAddress            = optional\n"
    )
