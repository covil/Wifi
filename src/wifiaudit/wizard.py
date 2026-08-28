"""Guided, interactive flow — the friendly front door to the toolkit.

Instead of running ``discover`` → copy a BSSID → ``capture`` → copy a path →
``crack`` by hand, the :class:`Wizard` walks the operator through all three
stages in one go: it lists the in-scope networks it found, lets them pick one
from a menu, captures a handshake (managing monitor mode on Linux), and cracks
it with a wordlist — reusing the same authorization gate, scope checks, and
audit log as the individual commands.

All user interaction goes through :class:`Console`, which is injectable so the
whole flow can be driven by a script in tests with no real terminal.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from wifiaudit.capture.backends import ReplayBackend, capture_backend
from wifiaudit.capture.capturer import Capturer
from wifiaudit.capture.models import CaptureResult, CaptureTarget
from wifiaudit.core.config import Config, load_config
from wifiaudit.core.errors import ConfigError, WifiAuditError
from wifiaudit.core.iface import describe_interfaces, monitor_mode
from wifiaudit.core.wordlists import list_wordlists, read_wordlist
from wifiaudit.crack.cracker import Cracker
from wifiaudit.crack.models import CrackResult
from wifiaudit.discovery.backends import FileBackend, IwScanBackend
from wifiaudit.discovery.models import AccessPoint
from wifiaudit.discovery.scanner import Scanner


class Console:
    """Thin, injectable console I/O so the wizard is testable without a TTY."""

    def __init__(
        self,
        reader: Callable[[str], str] = input,
        writer: Callable[[str], None] = print,
    ) -> None:
        self._read = reader
        self._write = writer

    def say(self, msg: str = "") -> None:
        self._write(msg)

    def ask(self, prompt: str, default: str | None = None) -> str:
        suffix = f" [{default}]" if default else ""
        ans = self._read(f"{prompt}{suffix}: ").strip()
        return ans or (default or "")

    def confirm(self, prompt: str, default: bool = False) -> bool:
        hint = "Y/n" if default else "y/N"
        ans = self._read(f"{prompt} [{hint}]: ").strip().lower()
        if not ans:
            return default
        return ans in ("y", "yes")

    def choose(self, prompt: str, options: list[str]) -> int:
        self.say(prompt)
        for i, opt in enumerate(options, 1):
            self.say(f"  {i}. {opt}")
        while True:
            ans = self._read(f"Enter 1-{len(options)}: ").strip()
            if ans.isdigit() and 1 <= int(ans) <= len(options):
                return int(ans) - 1
            self.say("  (please enter a number from the list)")


@dataclass
class WizardOutcome:
    target: AccessPoint
    capture: CaptureResult
    crack: CrackResult | None = None


class Wizard:
    def __init__(self, config: Config, console: Console, *, now=None) -> None:
        self.config = config
        self.c = console
        self.now = now

    # -- individual stages ---------------------------------------------------

    def _discover(self, *, live: bool, discover_input: str | None, iface: str | None):
        if live:
            backend = IwScanBackend()
            scan_iface = iface or self.config.discovery.default_iface
        else:
            if not discover_input:
                raise ConfigError("wizard: offline mode needs a saved scan file.")
            fmt = "airodump-csv" if discover_input.lower().endswith(".csv") else "iw"
            backend = FileBackend(discover_input, fmt)
            scan_iface = None
        scanner = Scanner.from_config(self.config, backend, now=self.now)
        return scanner.run(iface=scan_iface, seconds=None)

    def _capture(self, target: CaptureTarget, *, live: bool, capture_input: str | None,
                 iface: str | None, seconds: int | None, deauth: bool,
                 tool: str | None = None) -> CaptureResult:
        capturer_backend_iface = iface or self.config.discovery.default_iface
        if live:
            backend = capture_backend(
                tool or self.config.capture.tool,
                output_dir=self.config.capture.output_dir,
                deauth_interval=self.config.capture.deauth_interval,
            )
            seconds_v = seconds or self.config.capture.capture_seconds
            capturer = Capturer.from_config(self.config, backend, now=self.now)
            if getattr(backend, "self_manages_monitor", False):
                # e.g. hcxdumptool sets up the interface itself; pre-setting
                # monitor mode makes it fail on a "shared interface".
                return capturer.run(
                    target, iface=capturer_backend_iface, seconds=seconds_v, deauth=deauth
                )
            with monitor_mode(capturer_backend_iface) as mon:
                return capturer.run(target, iface=mon, seconds=seconds_v, deauth=deauth)
        if not capture_input:
            raise ConfigError("wizard: offline mode needs a saved capture file.")
        backend = ReplayBackend(capture_input)
        capturer = Capturer.from_config(self.config, backend, now=self.now)
        return capturer.run(target)

    def _crack(self, ap: AccessPoint, capture: CaptureResult, wordlist: str) -> CrackResult:
        wl = Path(wordlist)
        if not wl.is_file():
            raise ConfigError(f"wizard: wordlist not found: {wl}")
        if not capture.capture_path:
            raise ConfigError("wizard: no capture file to crack.")
        data = Path(capture.capture_path).read_bytes()
        cracker = Cracker.from_config(self.config, now=self.now)
        return cracker.run(
            capture=data,
            wordlist=read_wordlist(wl),
            ssid=ap.essid or "",
            bssid=ap.bssid,
            channel=ap.channel,
        )

    # -- the guided flow -----------------------------------------------------

    def run(
        self,
        *,
        live: bool = False,
        iface: str | None = None,
        discover_input: str | None = None,
        capture_input: str | None = None,
        wordlist: str | None = None,
        seconds: int | None = None,
        deauth: bool = False,
        do_crack: bool = True,
        tool: str | None = None,
    ) -> WizardOutcome | None:
        c = self.c
        stages = "3" if do_crack else "2"
        c.say("=== wifiaudit guided run ===")
        c.say(f"Operator authorized via config; scope enforced throughout.\n")

        # Stage 1 — discovery
        c.say(f"[1/{stages}] Looking for in-scope networks...")
        scan = self._discover(live=live, discover_input=discover_input, iface=iface)
        targets = scan.in_scope_aps()
        if not targets:
            c.say(
                "\nNo in-scope access points were found.\n"
                "Nothing is in scope unless it matches [scope] in your config — "
                "check that your authorized target is listed there."
            )
            return None

        labels = [
            f"{(ap.essid or '<hidden>'):20}  {ap.bssid}  ch {ap.channel or '?':>3}  "
            f"{('%.0f dBm' % ap.signal_dbm) if ap.signal_dbm is not None else '?'}"
            for ap in targets
        ]
        idx = c.choose("\nSelect the target to attack:", labels)
        ap = targets[idx]

        essid = ap.essid
        if not essid:
            essid = c.ask(
                "This network hides its ESSID; enter it (needed to capture/crack)"
            )
            ap.essid = essid or None

        # Stage 2 — capture
        c.say(f"\n[2/{stages}] Capturing a handshake for {ap.essid} ({ap.bssid})...")
        if live:
            c.say("  (this needs root; the adapter is put into monitor mode)")
        target = CaptureTarget(bssid=ap.bssid, essid=ap.essid, channel=ap.channel)
        capture = self._capture(
            target, live=live, capture_input=capture_input,
            iface=iface, seconds=seconds, deauth=deauth, tool=tool,
        )
        s = capture.summary()
        c.say(
            f"  captured: {s['complete_handshakes']} handshake(s), "
            f"{s['pmkids']} PMKID(s)."
        )

        if not do_crack:
            saved = f" Saved to {capture.capture_path}." if capture.capture_path else ""
            c.say(f"\nCapture-only run: cracking skipped.{saved}")
            return WizardOutcome(target=ap, capture=capture)

        if not capture.got_crackable:
            c.say(
                "\nNo crackable handshake or PMKID was captured.\n"
                "Try again closer to the AP, for longer, or (if your engagement "
                "permits it) enable deauth."
            )
            return WizardOutcome(target=ap, capture=capture)

        # Stage 3 — crack
        c.say(f"\n[3/3] Cracking {ap.essid}...")
        wl = wordlist or self.config.crack.wordlist
        if not wl:
            wl = c.ask("Path to a wordlist file")
        crack = self._crack(ap, capture, wl)

        c.say("")
        if crack.cracked:
            c.say(f"  *** PASSPHRASE FOUND (via {crack.method}) ***")
            c.say(f"  {ap.essid} : {crack.passphrase}")
        else:
            c.say(
                f"  Passphrase not in the wordlist ({crack.attempts} tried). "
                "Try a larger dictionary."
            )
        return WizardOutcome(target=ap, capture=capture, crack=crack)


# --- config generator (`init`) ---------------------------------------------

def build_config_text(
    *,
    operator: str,
    organization: str,
    reference: str,
    expires: str,
    essids: list[str],
    wordlist: str,
    authorized: bool,
) -> str:
    """Render a config.toml body from answers. Kept pure for testing."""
    essid_list = ", ".join(f'"{e}"' for e in essids)
    return f"""# Generated by `wifiaudit init`. Review before use.
[authorization]
authorized   = {"true" if authorized else "false"}
operator     = "{operator}"
organization = "{organization}"
reference    = "{reference}"
expires      = "{expires}"

[scope]
bssids   = []
essids   = [{essid_list}]
channels = []

[capture]
default_iface   = "wlan0"
capture_seconds = 60
output_dir      = "captures"
tool            = "airodump-ng"
allow_deauth    = false

[crack]
wordlist = "{wordlist}"

[audit]
enabled = true
path    = "audit.log.jsonl"

[output]
dir = "output"
"""


def run_init(console: Console, *, path: Path) -> bool:
    """Interactively gather answers and write ``path``. Returns True if written."""
    c = console
    c.say("=== wifiaudit setup ===")
    c.say("This writes a config.toml. Answer a few questions.\n")

    if path.exists() and not c.confirm(f"{path} exists — overwrite it?", default=False):
        c.say("Left existing config unchanged.")
        return False

    operator = c.ask("Your name and email (operator)", "Operator <you@example.com>")
    organization = c.ask("Organization you are testing for", "")
    reference = c.ask("Authorization reference (SOW / permission ticket)", "")
    expires = c.ask("Authorization expiry date (YYYY-MM-DD)", "")
    essids_raw = c.ask("In-scope network name(s), comma-separated (wildcards ok)", "AuditLab-*")
    essids = [e.strip() for e in essids_raw.split(",") if e.strip()]
    wordlist = c.ask("Default wordlist path for cracking (optional)", "")

    c.say(
        "\nAuthorization attestation: only continue if you hold written "
        "permission to test the network(s) above."
    )
    authorized = c.confirm("I am authorized to test these targets", default=False)
    if not authorized:
        c.say(
            "\nNot attested — writing config with authorized=false. "
            "Nothing will run until you set it true yourself."
        )

    path.write_text(
        build_config_text(
            operator=operator, organization=organization, reference=reference,
            expires=expires, essids=essids, wordlist=wordlist, authorized=authorized,
        ),
        encoding="utf-8",
    )
    c.say(f"\nWrote {path}." + ("" if authorized else " (authorized=false)"))
    return True


# --- top-level menu (`menu`, and the default when run with no arguments) ------

def _demo_config(audit_path: Path) -> Config:
    """A self-contained authorized config for the offline demo (option 2)."""
    return Config.from_dict(
        {
            "authorization": {
                "authorized": True,
                "operator": "Demo <demo@example.com>",
                "reference": "OFFLINE-DEMO (bundled sample data only)",
                "expires": "2099-12-31",
            },
            "scope": {"essids": ["AuditLab-*"]},
            "audit": {"enabled": True, "path": str(audit_path)},
        }
    )


def _fixtures_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "tests" / "fixtures"


def _menu_setup(console: Console, config_path: Path) -> None:
    run_init(console, path=config_path)


def _menu_offline_demo(console: Console, config_path: Path, now, fixtures: Path) -> None:
    scan = fixtures / "airodump_sample.csv"
    cap = fixtures / "handshake_sample.pcap"
    wl = fixtures / "wordlist_sample.txt"
    if not (scan.is_file() and cap.is_file() and wl.is_file()):
        console.say(
            f"\nSample files not found under {fixtures}.\n"
            "The offline demo needs the project's tests/fixtures directory "
            "(run from the source checkout)."
        )
        return
    console.say("\nRunning the offline demo against bundled sample data...\n")
    cfg = _demo_config(config_path.parent / "audit.demo.jsonl")
    Wizard(cfg, console, now=now).run(
        discover_input=str(scan), capture_input=str(cap), wordlist=str(wl)
    )


def _default_wordlists() -> list[str]:
    sample = _fixtures_dir() / "wordlist_sample.txt"
    extra = (str(sample),) if sample.is_file() else ()
    return list_wordlists(extra=extra)


def _choose_wordlist(console: Console, config, lister) -> str:
    if config.crack.wordlist:
        return config.crack.wordlist
    found = lister()
    if not found:
        console.say(
            "\n(No wordlists found in the usual places. On Kali the classic one is "
            "/usr/share/wordlists/rockyou.txt.gz — gunzip it, or install with "
            "'sudo apt install wordlists'.)"
        )
        return console.ask("Path to a wordlist file")
    labels = []
    for p in found:
        tag = ""
        if p.endswith("wordlist_sample.txt"):
            tag = "  (tiny demo list)"
        elif p.endswith(".gz"):
            tag = "  (compressed; read directly)"
        labels.append(p + tag)
    labels.append("Enter a different path...")
    idx = console.choose("\nSelect a wordlist:", labels)
    if idx == len(found):
        return console.ask("Path to a wordlist file")
    return found[idx]


def _choose_interface(console: Console, config, lister) -> str:
    ifaces = lister()
    if ifaces:
        console.say(
            "\nTip: pick your external USB adapter that shows 'monitor=yes' "
            "(the built-in card, usually [PCI], often can't capture)."
        )
        idx = console.choose("Select the wireless interface:", [i.label() for i in ifaces])
        return ifaces[idx].name
    console.say("(could not auto-detect a wireless interface)")
    return console.ask("Wireless interface", config.discovery.default_iface)


def _ask_deauth(console: Console, config) -> bool:
    if config.capture.allow_deauth:
        return console.confirm("Send deauth to speed up capture?", default=False)
    return False


def _choose_capture_method(console: Console) -> str:
    """Ask handshake (airodump-ng) vs PMKID (hcxdumptool). Returns the tool name."""
    labels = [
        "Handshake via airodump-ng  (needs a connected client; can use deauth)",
        "PMKID via hcxdumptool       (clientless - no client or deauth needed)",
    ]
    idx = console.choose("\nHow do you want to capture?", labels)
    return "airodump-ng" if idx == 0 else "hcxdumptool"


def _menu_live(
    console: Console, config_path: Path, now,
    iface_lister=describe_interfaces, wordlist_lister=None,
) -> None:
    if not config_path.is_file():
        console.say("\nNo config yet — choose 'Set up' first (option 1).")
        return
    config = load_config(config_path)

    iface = _choose_interface(console, config, iface_lister)
    tool = _choose_capture_method(console)
    deauth = _ask_deauth(console, config) if tool == "airodump-ng" else False
    wl = _choose_wordlist(console, config, wordlist_lister or _default_wordlists)
    console.say(
        "\nThis will scan and capture on IN-SCOPE targets only. "
        "It needs root (run with sudo) and a monitor-capable adapter."
    )
    if not console.confirm("Continue?", default=False):
        console.say("Cancelled.")
        return
    Wizard(config, console, now=now).run(
        live=True, iface=iface, wordlist=wl, deauth=deauth, tool=tool
    )


def _menu_capture_only(
    console: Console, config_path: Path, now, iface_lister=describe_interfaces,
) -> None:
    if not config_path.is_file():
        console.say("\nNo config yet — choose 'Set up' first (option 1).")
        return
    config = load_config(config_path)

    iface = _choose_interface(console, config, iface_lister)
    tool = _choose_capture_method(console)
    deauth = _ask_deauth(console, config) if tool == "airodump-ng" else False
    console.say(
        "\nThis will capture a handshake/PMKID on IN-SCOPE targets only and then "
        "stop (no cracking). It needs root and a monitor-capable adapter."
    )
    if not console.confirm("Continue?", default=False):
        console.say("Cancelled.")
        return
    Wizard(config, console, now=now).run(
        live=True, iface=iface, deauth=deauth, do_crack=False, tool=tool
    )


def _menu_verify(console: Console, config_path: Path) -> None:
    if not config_path.is_file():
        console.say("\nNo config yet — choose 'Set up' first (option 1).")
        return
    from wifiaudit.core.audit import verify_chain

    config = load_config(config_path)
    result = verify_chain(config.audit.path)
    if result.ok:
        console.say(f"\nAudit log OK: {result.count} record(s), chain intact.")
    else:
        console.say(
            f"\nAUDIT LOG FAILED at seq {result.at_seq}: {result.error}"
        )


def run_menu(
    console: Console,
    *,
    config_path: Path,
    now=None,
    fixtures: Path | None = None,
    iface_lister=describe_interfaces,
    wordlist_lister=None,
) -> int:
    """Interactive top-level menu. Loops until the user chooses Quit."""
    fixtures = fixtures or _fixtures_dir()
    options = [
        "Set up (create your config)",
        "Try it offline (demo with sample data, no adapter needed)",
        "Run on real WiFi - full: capture + crack (Linux + adapter + sudo)",
        "Capture only - no cracking (Linux + adapter + sudo)",
        "Check the audit log",
        "Quit",
    ]
    console.say("=== wifiaudit ===")
    console.say("An authorized-use WiFi auditing toolkit. Pick an option.\n")
    while True:
        choice = console.choose("What would you like to do?", options)
        try:
            if choice == 0:
                _menu_setup(console, config_path)
            elif choice == 1:
                _menu_offline_demo(console, config_path, now, fixtures)
            elif choice == 2:
                _menu_live(
                    console, config_path, now,
                    iface_lister=iface_lister, wordlist_lister=wordlist_lister,
                )
            elif choice == 3:
                _menu_capture_only(console, config_path, now, iface_lister=iface_lister)
            elif choice == 4:
                _menu_verify(console, config_path)
            else:
                console.say("Bye.")
                return 0
        except WifiAuditError as exc:
            console.say(f"\nerror: {exc}")
        console.say("")  # spacer before the menu shows again


__all__ = [
    "Console",
    "Wizard",
    "WizardOutcome",
    "build_config_text",
    "run_init",
    "run_menu",
]
