"""Command-line entry point.

Subcommands:

* ``wizard``        — guided end-to-end run (discover -> pick -> capture -> crack)
* ``init``          — interactively create a config.toml
* ``discover``      — run stage 1 (offline via ``--input`` or live via ``--live``)
* ``capture``       — run stage 2 (offline replay via ``--input`` or live via ``--live``)
* ``crack``         — run stage 3 (dictionary attack on a captured handshake/PMKID)
* ``audit-verify``  — recompute and check the audit hash chain
* ``report``        — placeholder for the final stage

Everything the toolkit raises deliberately is a :class:`WifiAuditError`, so the
CLI catches that one base type and prints a clean message instead of a traceback.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from wifiaudit import __version__
from wifiaudit.capture.backends import AirodumpBackend, ReplayBackend
from wifiaudit.capture.capturer import Capturer
from wifiaudit.capture.models import CaptureResult, CaptureTarget
from wifiaudit.core.audit import verify_chain
from wifiaudit.core.config import load_config, normalize_bssid
from wifiaudit.core.errors import ConfigError, WifiAuditError
from wifiaudit.crack.cracker import Cracker
from wifiaudit.crack.models import CrackResult
from wifiaudit.wizard import Console, Wizard, run_init, run_menu
from wifiaudit.discovery.backends import FileBackend, IwScanBackend
from wifiaudit.discovery.models import ScanResult
from wifiaudit.discovery.scanner import Scanner


def _infer_format(path: str) -> str:
    return "airodump-csv" if path.lower().endswith(".csv") else "iw"


def _render_table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    sep = "  ".join("-" * widths[i] for i in range(len(headers)))
    body = [
        "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)) for row in rows
    ]
    return "\n".join([line, sep, *body])


def _print_scan(result: ScanResult) -> None:
    headers = ["SCOPE", "BSSID", "CH", "SIGNAL", "ENC", "AUTH", "ESSID"]
    rows: list[list[str]] = []
    for ap in result.access_points:
        rows.append(
            [
                "IN" if ap.in_scope else "--",
                ap.bssid,
                str(ap.channel) if ap.channel is not None else "?",
                f"{ap.signal_dbm:.0f}" if ap.signal_dbm is not None else "?",
                ap.encryption,
                ap.auth or "",
                ap.essid if ap.essid else "<hidden>",
            ]
        )
    if rows:
        print(_render_table(headers, rows))
    else:
        print("(no access points observed)")

    s = result.summary()
    print(
        f"\n{s['access_points']} APs "
        f"({s['in_scope']} in scope, {s['out_of_scope']} out of scope), "
        f"{s['clients']} clients."
    )
    if result.clients:
        print("\nClients:")
        crows = [
            [
                c.mac,
                c.bssid or "(unassociated)",
                f"{c.signal_dbm:.0f}" if c.signal_dbm is not None else "?",
                ", ".join(c.probes) if c.probes else "",
            ]
            for c in result.clients
        ]
        print(_render_table(["STATION", "ASSOCIATED", "SIGNAL", "PROBES"], crows))


def _cmd_discover(args: argparse.Namespace) -> int:
    config = load_config(args.config)

    if args.live:
        backend = IwScanBackend()
    elif args.input:
        fmt = args.format or _infer_format(args.input)
        backend = FileBackend(args.input, fmt)
    else:
        print("error: provide --input <file> for offline replay or --live for a live scan.", file=sys.stderr)
        return 2

    iface = args.iface or config.discovery.default_iface
    seconds = args.seconds or config.discovery.scan_seconds

    scanner = Scanner.from_config(config, backend)
    result = scanner.run(iface=iface if args.live else None, seconds=seconds)

    _print_scan(result)

    if config.audit.enabled:
        print(f"\nAudit log: {config.audit.path}")

    if args.json:
        Path(args.json).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        print(f"Wrote JSON results to {args.json}")
    return 0


def _print_capture(result: CaptureResult) -> None:
    t = result.target
    print(
        f"Target: {t.bssid}"
        + (f"  essid={t.essid}" if t.essid else "")
        + (f"  ch={t.channel}" if t.channel is not None else "")
    )
    if result.capture_path:
        print(f"Capture: {result.capture_path}")

    if not result.handshakes:
        print("\n(no EAPOL handshakes or PMKIDs observed for this target)")
    else:
        headers = ["AP BSSID", "CLIENT", "MESSAGES", "PMKID", "STATUS"]
        rows: list[list[str]] = []
        for h in result.handshakes:
            msgs = "".join(f"M{n}" for n in sorted(h.messages)) or "-"
            if h.is_complete:
                status = "handshake"
            elif h.pmkid:
                status = "pmkid"
            else:
                status = "partial"
            rows.append([h.ap_bssid, h.client_mac, msgs, "yes" if h.pmkid else "-", status])
        print()
        print(_render_table(headers, rows))

    s = result.summary()
    print(
        f"\n{s['complete_handshakes']} usable handshake(s), "
        f"{s['pmkids']} PMKID(s) across {s['pairs']} station pair(s)."
    )
    if result.got_crackable:
        print("Result: crackable material captured (ready for stage 3).")
    else:
        print("Result: nothing crackable yet — try longer, closer, or (if authorized) --deauth.")


def _cmd_capture(args: argparse.Namespace) -> int:
    config = load_config(args.config)

    try:
        bssid = normalize_bssid(args.bssid)
    except ValueError as exc:
        raise ConfigError(f"--bssid: {exc}") from exc
    target = CaptureTarget(bssid=bssid, essid=args.essid, channel=args.channel)

    if args.live:
        backend = AirodumpBackend(
            output_dir=config.capture.output_dir,
            airodump_path=None,
            aireplay_path=None,
        )
    elif args.input:
        backend = ReplayBackend(args.input)
    else:
        print(
            "error: provide --input <file> to replay a saved capture, or --live to capture.",
            file=sys.stderr,
        )
        return 2

    if args.deauth and not args.live:
        print("error: --deauth only applies to a --live capture.", file=sys.stderr)
        return 2

    iface = args.iface or config.capture.default_iface
    seconds = args.seconds or config.capture.capture_seconds

    capturer = Capturer.from_config(config, backend)
    result = capturer.run(
        target,
        iface=iface if args.live else None,
        seconds=seconds,
        deauth=args.deauth,
    )

    _print_capture(result)

    if config.audit.enabled:
        print(f"\nAudit log: {config.audit.path}")

    if args.json:
        Path(args.json).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        print(f"Wrote JSON results to {args.json}")
    return 0


def _print_crack(result: CrackResult) -> None:
    print(
        f"Target: {result.bssid}  ssid={result.ssid}\n"
        f"Material: {result.handshakes} handshake(s), {result.pmkids} PMKID(s)  "
        f"| wordlist: {result.candidates} candidate(s)"
    )
    if result.cracked:
        print(f"\n  *** PASSPHRASE FOUND (via {result.method}) ***")
        print(f"  passphrase : {result.passphrase}")
        print(f"  matched    : {result.matched}")
        print(f"  attempts   : {result.attempts}")
    else:
        print(
            f"\n  passphrase NOT found after {result.attempts} candidate(s). "
            "Try a larger or more targeted wordlist."
        )


def _cmd_crack(args: argparse.Namespace) -> int:
    config = load_config(args.config)

    try:
        bssid = normalize_bssid(args.bssid)
    except ValueError as exc:
        raise ConfigError(f"--bssid: {exc}") from exc

    wordlist_path = args.wordlist or config.crack.wordlist
    if not wordlist_path:
        print("error: provide --wordlist <file> (or set [crack] wordlist).", file=sys.stderr)
        return 2
    wl = Path(wordlist_path)
    if not wl.is_file():
        raise ConfigError(f"--wordlist: file not found: {wl}")
    cap = Path(args.input)
    if not cap.is_file():
        raise ConfigError(f"--input: capture file not found: {cap}")

    cracker = Cracker.from_config(config)
    result = cracker.run(
        capture=cap.read_bytes(),
        wordlist=wl.read_text(encoding="utf-8", errors="replace"),
        ssid=args.essid,
        bssid=bssid,
        channel=args.channel,
    )

    _print_crack(result)

    if config.audit.enabled:
        print(f"\nAudit log: {config.audit.path}")

    if args.json:
        Path(args.json).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        print(f"Wrote JSON results to {args.json}")
    return 0 if result.cracked else 1


def _cmd_menu(args: argparse.Namespace) -> int:
    return run_menu(Console(), config_path=Path(args.config))


def _cmd_wizard(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    wizard = Wizard(config, Console())
    outcome = wizard.run(
        live=args.live,
        iface=args.iface,
        discover_input=args.input,
        capture_input=args.capture_input,
        wordlist=args.wordlist,
        seconds=args.seconds,
        deauth=args.deauth,
    )
    if config.audit.enabled:
        print(f"\nAudit log: {config.audit.path}")
    if outcome is None or outcome.crack is None:
        return 1
    return 0 if outcome.crack.cracked else 1


def _cmd_init(args: argparse.Namespace) -> int:
    wrote = run_init(Console(), path=Path(args.path))
    return 0 if wrote else 1


def _cmd_audit_verify(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    result = verify_chain(config.audit.path)
    if result.ok:
        print(f"audit log OK: {result.count} record(s), chain intact ({config.audit.path}).")
        return 0
    print(
        f"AUDIT LOG FAILED verification at seq {result.at_seq}: {result.error} "
        f"({config.audit.path}).",
        file=sys.stderr,
    )
    return 1


def _cmd_not_implemented(args: argparse.Namespace) -> int:
    print(f"'{args.command}' is not implemented yet (planned stage).", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wifiaudit",
        description="Authorized-use WiFi security auditing toolkit.",
    )
    parser.add_argument("--version", action="version", version=f"wifiaudit {__version__}")
    # No subcommand -> the interactive menu, so a beta user can just run `wifiaudit`.
    sub = parser.add_subparsers(dest="command", required=False)

    m = sub.add_parser("menu", help="interactive menu — pick an option by number (default)")
    m.add_argument("--config", default="config.toml", help="path to config TOML (default: config.toml)")
    m.set_defaults(func=_cmd_menu)

    w = sub.add_parser("wizard", help="guided end-to-end run: discover -> pick -> capture -> crack")
    w.add_argument("--config", default="config.toml", help="path to config TOML (default: config.toml)")
    w.add_argument("--live", action="store_true", help="use real hardware (Linux); otherwise replay saved files")
    w.add_argument("--iface", help="wireless interface for --live (default from config)")
    w.add_argument("--input", help="offline: saved discovery scan file (.csv/iw)")
    w.add_argument("--capture-input", dest="capture_input", help="offline: saved capture file (.pcap/.cap)")
    w.add_argument("--wordlist", help="wordlist for cracking (default from [crack] wordlist)")
    w.add_argument("--seconds", type=int, help="scan/capture duration for --live")
    w.add_argument("--deauth", action="store_true", help="allow deauth during live capture (needs [capture] allow_deauth=true)")
    w.set_defaults(func=_cmd_wizard)

    ini = sub.add_parser("init", help="interactively create a config.toml")
    ini.add_argument("--path", default="config.toml", help="where to write the config (default: config.toml)")
    ini.set_defaults(func=_cmd_init)

    d = sub.add_parser("discover", help="enumerate access points and clients (stage 1)")
    d.add_argument("--config", default="config.toml", help="path to config TOML (default: config.toml)")
    src = d.add_argument_group("scan source")
    src.add_argument("--input", help="replay a saved scan file offline")
    src.add_argument("--format", choices=["iw", "airodump-csv"], help="format of --input (inferred from extension if omitted)")
    src.add_argument("--live", action="store_true", help="perform a live scan via 'iw' (Linux)")
    d.add_argument("--iface", help="wireless interface for --live (default from config)")
    d.add_argument("--seconds", type=int, help="scan duration/timeout (default from config)")
    d.add_argument("--json", help="also write full results as JSON to this path")
    d.set_defaults(func=_cmd_discover)

    c = sub.add_parser("capture", help="capture handshakes/PMKID for an in-scope target (stage 2)")
    c.add_argument("--config", default="config.toml", help="path to config TOML (default: config.toml)")
    c.add_argument("--bssid", required=True, help="target AP BSSID (must be in scope)")
    c.add_argument("--essid", help="target ESSID (used for scope matching)")
    c.add_argument("--channel", type=int, help="target channel")
    csrc = c.add_argument_group("capture source")
    csrc.add_argument("--input", help="replay/analyze a saved capture (.pcap/.cap) offline")
    csrc.add_argument("--live", action="store_true", help="capture live via airodump-ng (Linux, monitor mode)")
    c.add_argument("--iface", help="wireless interface for --live (default from config)")
    c.add_argument("--seconds", type=int, help="capture duration (default from config)")
    c.add_argument(
        "--deauth",
        action="store_true",
        help="send a bounded deauth to speed up capture (requires --live and [capture] allow_deauth=true)",
    )
    c.add_argument("--json", help="also write full results as JSON to this path")
    c.set_defaults(func=_cmd_capture)

    k = sub.add_parser("crack", help="recover a WPA/WPA2 passphrase from a capture (stage 3)")
    k.add_argument("--config", default="config.toml", help="path to config TOML (default: config.toml)")
    k.add_argument("--input", required=True, help="capture file (.pcap/.cap) with a handshake/PMKID")
    k.add_argument("--essid", required=True, help="target ESSID (the PBKDF2 salt; must be in scope)")
    k.add_argument("--bssid", required=True, help="target BSSID (must be in scope)")
    k.add_argument("--channel", type=int, help="target channel (for scope matching)")
    k.add_argument("--wordlist", help="dictionary file (default from [crack] wordlist)")
    k.add_argument("--json", help="also write full results as JSON to this path")
    k.set_defaults(func=_cmd_crack)

    av = sub.add_parser("audit-verify", help="verify the audit log hash chain")
    av.add_argument("--config", default="config.toml", help="path to config TOML (default: config.toml)")
    av.set_defaults(func=_cmd_audit_verify)

    for name, helptext in [
        ("report", "generate an engagement report (planned)"),
    ]:
        p = sub.add_parser(name, help=helptext)
        p.set_defaults(func=_cmd_not_implemented)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "func", None) is None:
        # Bare `wifiaudit` with no subcommand -> drop into the interactive menu.
        return run_menu(Console(), config_path=Path("config.toml"))
    try:
        return args.func(args)
    except WifiAuditError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
