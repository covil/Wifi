"""Tests for the guided wizard and the init config generator (offline)."""

from __future__ import annotations

import datetime as dt

import pytest

from wifiaudit.core.config import Config, load_config
from wifiaudit.wizard import Console, Wizard, build_config_text, run_init, run_menu


def _write_config(path, *, authorized=True, wordlist=""):
    path.write_text(
        build_config_text(
            operator="Op <op@example.com>", organization="Org", reference="SOW-1",
            expires="2099-12-31", essids=["AuditLab-*"], wordlist=wordlist,
            authorized=authorized,
        ),
        encoding="utf-8",
    )

NOW = dt.date(2026, 8, 28)


class ScriptedConsole(Console):
    """A Console that reads canned answers and captures everything printed."""

    def __init__(self, answers: list[str]) -> None:
        self.out: list[str] = []
        self._answers = list(answers)
        super().__init__(reader=self._scripted, writer=self.out.append)

    def _scripted(self, _prompt: str) -> str:
        return self._answers.pop(0)

    @property
    def text(self) -> str:
        return "\n".join(self.out)


def test_wizard_offline_end_to_end(config_data, fixtures_dir):
    cfg = Config.from_dict(config_data())  # scope essids = AuditLab-*
    console = ScriptedConsole(["1"])       # pick the strongest in-scope target
    wiz = Wizard(cfg, console, now=NOW)

    outcome = wiz.run(
        discover_input=str(fixtures_dir / "airodump_sample.csv"),
        capture_input=str(fixtures_dir / "handshake_sample.pcap"),
        wordlist=str(fixtures_dir / "wordlist_sample.txt"),
    )

    assert outcome is not None
    assert outcome.target.essid == "AuditLab-AP1"      # strongest, -42 dBm
    assert outcome.crack is not None
    assert outcome.crack.cracked
    assert outcome.crack.passphrase == "Summer2026!"
    assert "PASSPHRASE FOUND" in console.text


def test_wizard_reports_when_nothing_in_scope(config_data, fixtures_dir):
    # Scope that matches none of the sample APs.
    cfg = Config.from_dict(
        config_data(scope={"bssids": [], "essids": ["NoSuchNet-*"], "channels": []})
    )
    console = ScriptedConsole([])  # never gets to a prompt
    outcome = Wizard(cfg, console, now=NOW).run(
        discover_input=str(fixtures_dir / "airodump_sample.csv"),
        capture_input=str(fixtures_dir / "handshake_sample.pcap"),
        wordlist=str(fixtures_dir / "wordlist_sample.txt"),
    )
    assert outcome is None
    assert "No in-scope access points" in console.text


def test_wizard_prompts_for_wordlist_when_not_given(config_data, fixtures_dir):
    cfg = Config.from_dict(config_data())
    # answers: choose target #1, then supply the wordlist path when asked.
    console = ScriptedConsole(["1", str(fixtures_dir / "wordlist_sample.txt")])
    outcome = Wizard(cfg, console, now=NOW).run(
        discover_input=str(fixtures_dir / "airodump_sample.csv"),
        capture_input=str(fixtures_dir / "handshake_sample.pcap"),
    )
    assert outcome.crack.cracked


def test_init_writes_authorized_config(tmp_path):
    path = tmp_path / "config.toml"
    # operator, org, reference, expires, essids, wordlist, then confirm authorized = yes
    console = ScriptedConsole(
        [
            "Beta Tester <beta@example.com>",
            "Example Sec",
            "SOW-42",
            "2099-12-31",
            "AuditLab-*",
            "",
            "yes",
        ]
    )
    assert run_init(console, path=path) is True

    cfg = load_config(path)  # must be valid TOML and load cleanly
    assert cfg.authorization.authorized is True
    assert cfg.authorization.operator.startswith("Beta Tester")
    assert cfg.scope.essids == ("AuditLab-*",)


def test_init_declined_authorization_writes_false(tmp_path):
    path = tmp_path / "config.toml"
    console = ScriptedConsole(
        ["Op <op@example.com>", "", "ref", "2099-01-01", "Lab-*", "", "no"]
    )
    assert run_init(console, path=path) is True
    cfg = load_config(path)
    assert cfg.authorization.authorized is False


def test_menu_offline_demo_then_quit(tmp_path, fixtures_dir):
    # choose 2 (offline demo), pick target 1 in the wizard, then choose 6 (quit)
    console = ScriptedConsole(["2", "1", "6"])
    rc = run_menu(console, config_path=tmp_path / "config.toml", now=NOW, fixtures=fixtures_dir)
    assert rc == 0
    assert "Summer2026!" in console.text
    assert "Bye." in console.text


def test_menu_setup_then_quit(tmp_path, fixtures_dir):
    # choose 1 (set up), answer init prompts, then choose 5 (quit)
    answers = [
        "1",
        "Op <op@example.com>", "Org", "SOW-1", "2099-12-31", "AuditLab-*", "", "yes",
        "6",
    ]
    console = ScriptedConsole(answers)
    rc = run_menu(console, config_path=tmp_path / "config.toml", now=NOW, fixtures=fixtures_dir)
    assert rc == 0
    assert (tmp_path / "config.toml").is_file()


def test_menu_verify_without_config_prompts_setup(tmp_path, fixtures_dir):
    # choose 5 (check audit log) with no config, then quit
    console = ScriptedConsole(["5", "6"])
    rc = run_menu(console, config_path=tmp_path / "missing.toml", now=NOW, fixtures=fixtures_dir)
    assert rc == 0
    assert "Set up" in console.text


def test_menu_verify_with_config_loads_it(tmp_path, fixtures_dir):
    # choose 5 with a real config present, then quit — exercises load_config.
    cfg = tmp_path / "config.toml"
    _write_config(cfg)
    console = ScriptedConsole(["5", "6"])
    rc = run_menu(console, config_path=cfg, now=NOW, fixtures=fixtures_dir)
    assert rc == 0
    assert "Audit log" in console.text


def test_menu_live_cancel_typed_iface_when_none_detected(tmp_path, fixtures_dir):
    # No interfaces detected -> fall back to typing. choose 3, type iface +
    # wordlist, decline "Continue?". Exercises load_config (regression guard).
    cfg = tmp_path / "config.toml"
    _write_config(cfg)
    # 3 (live), type iface, method 1 (handshake), deauth? no, type wordlist, decline, quit
    console = ScriptedConsole(["3", "wlan0", "1", "no", "some-wordlist.txt", "no", "6"])
    rc = run_menu(
        console, config_path=cfg, now=NOW, fixtures=fixtures_dir,
        iface_lister=lambda: [], wordlist_lister=lambda: [],
    )
    assert rc == 0
    assert "could not auto-detect" in console.text
    assert "How do you want to capture" in console.text
    assert "ACTIVE transmission" in console.text   # deauth warning shown, no config edit
    assert "Cancelled" in console.text


def test_menu_live_picks_detected_interface(tmp_path, fixtures_dir):
    # Interfaces detected -> user picks from a menu (no typing the name).
    from wifiaudit.core.iface import InterfaceInfo

    cfg = tmp_path / "config.toml"
    _write_config(cfg)
    ifaces = [
        InterfaceInfo("wlan0", bus="pci", driver="iwlwifi", monitor=False),
        InterfaceInfo("wlan1", bus="usb", driver="rt2800usb", monitor=True),
    ]
    # 3 (live), 2 (pick USB monitor one), method 1, deauth? no, type wordlist, decline, quit
    console = ScriptedConsole(["3", "2", "1", "no", "some-wordlist.txt", "no", "6"])
    rc = run_menu(
        console, config_path=cfg, now=NOW, fixtures=fixtures_dir,
        iface_lister=lambda: ifaces, wordlist_lister=lambda: [],
    )
    assert rc == 0
    assert "monitor=yes" in console.text          # the helpful detail is shown
    assert "[USB]" in console.text
    assert "Cancelled" in console.text


def test_menu_live_picks_detected_wordlist(tmp_path, fixtures_dir):
    # Wordlists detected -> user picks one from the menu (no typing the path).
    cfg = tmp_path / "config.toml"
    _write_config(cfg)
    # 3 (live), iface typed, method 1, deauth? no, 1 (pick first wordlist), decline, quit
    console = ScriptedConsole(["3", "wlan0", "1", "no", "1", "no", "6"])
    rc = run_menu(
        console, config_path=cfg, now=NOW, fixtures=fixtures_dir,
        iface_lister=lambda: [],
        wordlist_lister=lambda: ["/usr/share/wordlists/fasttrack.txt", "/tmp/other.txt"],
    )
    assert rc == 0
    assert "Select a wordlist" in console.text
    assert "Cancelled" in console.text


def test_menu_capture_only_no_wordlist_prompt(tmp_path, fixtures_dir):
    # Option 4 (capture only): pick interface, decline continue. It must NOT ask
    # for a wordlist, since nothing is cracked.
    cfg = tmp_path / "config.toml"
    _write_config(cfg)
    # 4 (capture only), iface, method 1 (handshake), deauth? no, decline, quit
    console = ScriptedConsole(["4", "wlan0", "1", "no", "no", "6"])
    rc = run_menu(
        console, config_path=cfg, now=NOW, fixtures=fixtures_dir,
        iface_lister=lambda: [], wordlist_lister=lambda: ["/usr/share/wordlists/x.txt"],
    )
    assert rc == 0
    assert "no cracking" in console.text
    assert "Select a wordlist" not in console.text   # never prompted for one
    assert "Cancelled" in console.text


def test_menu_capture_only_pmkid_skips_deauth_prompt(tmp_path, fixtures_dir):
    # PMKID method (hcxdumptool) is clientless: even with allow_deauth on, no
    # deauth question should be asked.
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        build_config_text(
            operator="Op <op@example.com>", organization="Org", reference="SOW-1",
            expires="2099-12-31", essids=["AuditLab-*"], wordlist="", authorized=True,
        ).replace("allow_deauth    = false", "allow_deauth    = true"),
        encoding="utf-8",
    )
    # 4 (capture only), iface, method 2 (PMKID), decline, quit
    console = ScriptedConsole(["4", "wlan0", "2", "no", "6"])
    rc = run_menu(
        console, config_path=cfg, now=NOW, fixtures=fixtures_dir, iface_lister=lambda: [],
    )
    assert rc == 0
    assert "PMKID" in console.text
    assert "ACTIVE transmission" not in console.text   # clientless: never asks about deauth
    assert "Cancelled" in console.text


def test_wizard_capture_only_skips_crack(config_data, fixtures_dir):
    # Wizard.run(do_crack=False) must capture and stop, returning crack=None.
    cfg = Config.from_dict(config_data())
    console = ScriptedConsole(["1"])  # pick the first in-scope target
    outcome = Wizard(cfg, console, now=NOW).run(
        discover_input=str(fixtures_dir / "airodump_sample.csv"),
        capture_input=str(fixtures_dir / "handshake_sample.pcap"),
        do_crack=False,
    )
    assert outcome is not None
    assert outcome.capture.got_crackable
    assert outcome.crack is None
    assert "cracking skipped" in console.text.lower()


def test_parse_iw_dev():
    from wifiaudit.core.iface import _parse_iw_dev

    sample = (
        "phy#0\n"
        "\tInterface wlan0\n"
        "\t\tifindex 3\n"
        "\t\ttype managed\n"
        "phy#1\n"
        "\tInterface wlan1mon\n"
        "\t\ttype monitor\n"
    )
    assert _parse_iw_dev(sample) == ["wlan0", "wlan1mon"]


def test_parse_monitor_support():
    from wifiaudit.core.iface import _parse_monitor_support

    supports = (
        "Wiphy phy1\n"
        "\tSupported interface modes:\n"
        "\t\t * managed\n"
        "\t\t * AP\n"
        "\t\t * monitor\n"
        "\tBand 1:\n"
    )
    lacks = (
        "Wiphy phy0\n"
        "\tSupported interface modes:\n"
        "\t\t * managed\n"
        "\t\t * P2P-client\n"
        "\tBand 1:\n"
    )
    assert _parse_monitor_support(supports) is True
    assert _parse_monitor_support(lacks) is False


def test_interface_info_label():
    from wifiaudit.core.iface import InterfaceInfo

    assert InterfaceInfo("wlan1", bus="usb", driver="rt2800usb", monitor=True).label() == (
        "wlan1  [USB]  driver=rt2800usb  monitor=yes"
    )
    assert "monitor=NO" in InterfaceInfo("wlan0", bus="pci", monitor=False).label()
