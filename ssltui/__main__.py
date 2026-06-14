"""Entry point — dispatch to TUI or headless CLI modes."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ssltui",
        description="Local SSL CA manager",
    )
    p.add_argument("--dir", metavar="PATH", help="Override data directory")
    sub = p.add_subparsers(dest="cmd")

    # --renew
    renew = sub.add_parser("renew", help="Renew expiring certs (cron-safe)")
    renew.add_argument("--cert", metavar="CN", help="Renew a specific cert by CN")
    renew.add_argument(
        "--threshold",
        type=int,
        default=30,
        help="Renew certs expiring within N days (default 30)",
    )

    # --status
    sub.add_parser("status", help="Print expiry table and exit")

    # --issue
    issue = sub.add_parser("issue", help="Issue a cert non-interactively")
    issue.add_argument("--cn", required=True, help="Common name")
    issue.add_argument(
        "--san",
        action="append",
        default=[],
        metavar="SAN",
        help="Subject Alternative Name (repeatable)",
    )
    issue.add_argument("--key-type", choices=["ec", "rsa"], default="ec")
    issue.add_argument("--days", type=int, default=180)

    # serve
    serve = sub.add_parser("serve", help="Start the REST API server (requires Flask)")
    serve.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address; use 0.0.0.0 for all interfaces (default 127.0.0.1)",
    )
    serve.add_argument(
        "--port", type=int, default=8080, help="HTTP port (default 8080)"
    )
    serve.add_argument(
        "--https-port",
        dest="https_port",
        type=int,
        default=8443,
        help="HTTPS port (default 8443); used when a server cert is configured",
    )
    serve.add_argument(
        "--debug",
        action="store_true",
        help="Enable Flask debug mode. Do not use in production",
    )
    serve.add_argument(
        "--no-threaded",
        dest="threaded",
        action="store_false",
        help="Handle one request at a time instead of threading (threaded is the default)",
    )

    # get
    get = sub.add_parser(
        "get", help="Print or save a cert, key, chain, or full PEM bundle"
    )
    get.add_argument("--cn", default=None, help="Common name of the certificate")
    get.add_argument(
        "--what",
        choices=["cert", "key", "chain", "full"],
        default=None,
        help=(
            "What to retrieve: cert (leaf cert), key (private key), "
            "chain (leaf + CA bundle), full (cert + key + chain concatenated). "
            "Default: cert"
        ),
    )
    get.add_argument(
        "--out",
        metavar="FILE",
        help="Write to FILE instead of stdout (recommended for keys)",
    )

    return p


_SUBCMDS = frozenset({"renew", "status", "issue", "serve", "get"})


def main(argv: list[str] | None = None) -> None:
    raw: list[str] = list(argv) if argv is not None else sys.argv[1:]

    # Allow "ssltui <PATH>" as a shorthand for "ssltui --dir <PATH>".
    # Any first token that isn't a known subcommand or a flag is treated as a path.
    if raw and raw[0] not in _SUBCMDS and not raw[0].startswith("-"):
        raw = ["--dir", raw[0]] + raw[1:]

    parser = _build_parser()
    args = parser.parse_args(raw)

    from ssltui import config

    if args.dir:
        config.set_data_dir(Path(args.dir))

    if args.cmd == "renew":
        _cmd_renew(args)
    elif args.cmd == "status":
        _cmd_status()
    elif args.cmd == "issue":
        _cmd_issue(args)
    elif args.cmd == "serve":
        _cmd_serve(args)
    elif args.cmd == "get":
        _cmd_get(args)
    else:
        # Default: interactive TUI
        from ssltui.tui import run_tui

        run_tui()


def _cmd_renew(args) -> None:
    from ssltui import config
    from ssltui.ca import CAError, renew_cert
    from ssltui.renewal import refresh_crl, renew_all

    root = config.data_dir()
    exit_code = 0

    if args.cert:
        try:
            renew_cert(root, args.cert)
            print(f"OK renewed {args.cert}")
        except CAError as exc:
            print(f"ERROR {args.cert}: {exc}", file=sys.stderr)
            exit_code = 1
    else:
        results = renew_all(root, threshold_days=args.threshold)
        if not results:
            print("No certs due for renewal.")
        for cn, ok, msg in results:
            status = "OK" if ok else "ERROR"
            print(f"{status} {cn}: {msg}")
        if any(not ok for _, ok, _ in results):
            exit_code = 1

    try:
        if refresh_crl(root):
            print("CRL refreshed.")
    except CAError as exc:
        print(f"WARN CRL refresh failed: {exc}", file=sys.stderr)

    if exit_code:
        sys.exit(exit_code)


def _cmd_status() -> None:
    from ssltui import config, store
    from ssltui.renewal import days_until_expiry

    root = config.data_dir()
    certs = store.list_certs(root)

    if not certs:
        print("No certs issued.")
        return

    fmt = "{:<30} {:<8} {:<25}"
    print(fmt.format("CN", "DAYS", "EXPIRY"))
    print("-" * 65)
    any_bad = False
    for cert in sorted(certs, key=lambda c: c["expiry"]):
        days = days_until_expiry(cert["expiry"])
        flag = " [WARN]" if days <= 30 else ""
        if days < 0:
            flag = " [EXPIRED]"
            any_bad = True
        print(fmt.format(cert["cn"], days, cert["expiry"]) + flag)

    sys.exit(1 if any_bad else 0)


def _cmd_issue(args) -> None:
    from ssltui import config
    from ssltui.ca import CAError, issue_cert

    root = config.data_dir()
    try:
        meta = issue_cert(
            root,
            cn=args.cn,
            sans=args.san,
            key_type=args.key_type,
            validity_days=args.days,
        )
        print(f"OK issued {meta['cn']}")
        print(f"  cert:  {meta['cert']}")
        print(f"  key:   {meta['key']}")
        print(f"  chain: {meta['chain']}")
    except CAError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


def _cmd_serve(args) -> None:
    import sys

    from ssltui import config
    from ssltui.api import run_server

    if not sys.stdout.isatty():
        run_server(
            host=args.host,
            port=args.port,
            https_port=args.https_port,
            debug=args.debug,
            threaded=args.threaded,
        )
        return

    from ssltui.api import APIServer, _resolve_token, server_ssl_context

    root = config.data_dir()
    if not config.ca_cert_path(root).exists():
        print(f"Error: CA not initialised at {root}.", file=sys.stderr)
        sys.exit(1)

    token = _resolve_token(root)
    ctx, _fqdn = server_ssl_context(root)
    try:
        server = APIServer(
            host=args.host,
            port=args.port,
            token=token,
            root=root,
            threaded=args.threaded,
            https_port=args.https_port if ctx is not None else None,
            ssl_context=ctx,
        )
    except OSError as exc:
        print(f"Error starting API server: {exc}", file=sys.stderr)
        sys.exit(1)

    from ssltui.tui import ServeApp

    ServeApp(server, token).run()


def _cmd_get(args) -> None:
    from ssltui import config, store

    root = config.data_dir()

    # ------------------------------------------------------------------ #
    # Interactive prompts when flags are absent and stdin is a TTY         #
    # ------------------------------------------------------------------ #
    cn: str | None = args.cn
    what: str | None = args.what
    out_path: str | None = args.out

    if cn is None:
        if not sys.stdin.isatty():
            print("ERROR: --cn is required in non-interactive mode", file=sys.stderr)
            sys.exit(1)

        certs = store.list_certs(root)
        if not certs:
            print("No certificates issued yet.", file=sys.stderr)
            sys.exit(1)

        certs_sorted = sorted(certs, key=lambda c: c["cn"])
        print("Select a certificate:")
        for i, c in enumerate(certs_sorted, 1):
            print(f"  {i}) {c['cn']}")
        raw = input("Enter number or CN: ").strip()
        if raw.isdigit():
            idx = int(raw) - 1
            if not (0 <= idx < len(certs_sorted)):
                print("ERROR: invalid selection", file=sys.stderr)
                sys.exit(1)
            cn = certs_sorted[idx]["cn"]
        else:
            cn = raw

    if what is None:
        if not sys.stdin.isatty():
            what = "cert"
        else:
            _what_choices = ["cert", "key", "chain", "full"]
            _what_labels = [
                "cert  — leaf certificate only",
                "key   — private key",
                "chain — leaf + CA bundle",
                "full  — chain + key (PEM bundle)",
            ]
            print("What do you want?")
            for i, label in enumerate(_what_labels, 1):
                print(f"  {i}) {label}")
            raw = input("Enter number or name [1]: ").strip()
            if not raw:
                raw = "1"
            if raw.isdigit():
                idx = int(raw) - 1
                if not (0 <= idx < len(_what_choices)):
                    print("ERROR: invalid selection", file=sys.stderr)
                    sys.exit(1)
                what = _what_choices[idx]
            elif raw in _what_choices:
                what = raw
            else:
                print(f"ERROR: unknown option {raw!r}", file=sys.stderr)
                sys.exit(1)

    if out_path is None and sys.stdin.isatty():
        raw = input("Output file (Enter for stdout): ").strip()
        out_path = raw or None

    # ------------------------------------------------------------------ #
    # Resolve entry and assemble data                                      #
    # ------------------------------------------------------------------ #
    entry = store.get_cert(root, cn)
    if entry is None:
        print(f"ERROR: no cert found for CN={cn!r}", file=sys.stderr)
        sys.exit(1)

    if what == "cert":
        data = Path(entry["cert"]).read_bytes()
    elif what == "key":
        data = Path(entry["key"]).read_bytes()
    elif what == "chain":
        data = Path(entry["chain"]).read_bytes()
    else:  # full
        data = Path(entry["chain"]).read_bytes() + Path(entry["key"]).read_bytes()

    if out_path:
        out = Path(out_path)
        out.write_bytes(data)
        mode = 0o600 if what in ("key", "full") else 0o644
        out.chmod(mode)
        print(f"Written to {out}")
    else:
        if what in ("key", "full") and sys.stdout.isatty():
            print(
                "WARNING: printing private key material to a terminal. "
                "Use --out FILE to save to a file instead.",
                file=sys.stderr,
            )
        sys.stdout.buffer.write(data)


if __name__ == "__main__":
    main()
