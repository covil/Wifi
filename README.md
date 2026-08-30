# wifiaudit

A modular **WiFi security-auditing toolkit** for use during **authorized**
penetration-testing engagements, security research, and lab/CTF work.

It is deliberately structured into four stages:

| Stage | Module | Status | What it does |
|-------|--------|--------|--------------|
| 1. Discovery | `wifiaudit.discovery` | ✅ implemented | Passive enumeration of nearby access points and clients; tags each against your authorized scope. |
| 2. Capture   | `wifiaudit.capture`  | ✅ implemented | Targeted handshake / PMKID capture for **in-scope** networks; analyzes captures for a usable 4-way handshake or PMKID. |
| 3. Crack     | `wifiaudit.crack`    | ✅ implemented | Offline dictionary attack against a captured handshake or PMKID (pure-Python WPA/WPA2-PSK). |
| 4. Report    | `wifiaudit.report`   | ✅ implemented | Evidence-linked findings report built from the tamper-evident audit log. |

Every stage runs behind a mandatory **authorization gate** and writes to a
**tamper-evident audit log**.

---

## ⚖️ Ethical and legal use — read this first

**Intercepting, deauthenticating, or attacking wireless networks you are not
explicitly authorized to test is illegal in most jurisdictions** (e.g. the U.S.
Computer Fraud and Abuse Act, the UK Computer Misuse Act, and equivalents
worldwide). This project is provided for:

- **Authorized penetration testing** with written permission and a defined scope.
- **Security research** on networks and hardware you own or control.
- **Education / CTF / lab** environments.

The toolkit is built to make unauthorized use *harder and more accountable*, not
easier:

1. **Authorization gate.** Nothing runs until a config declares
   `authorized = true`, names an operator, references a signed engagement/permission,
   and provides a non-expired authorization window. See
   [`core/authorization.py`](src/wifiaudit/core/authorization.py).
2. **Explicit scope.** Active operations (capture/crack) will only ever act on
   targets that match your declared scope (BSSIDs / ESSIDs / channels). Discovery
   is passive but still tags every observed network as in- or out-of-scope.
3. **Tamper-evident audit log.** Every action is appended to a hash-chained
   JSONL log so an engagement can be reconstructed and independently verified.
   See [`core/audit.py`](src/wifiaudit/core/audit.py).

You remain fully responsible for operating within the law and your engagement's
rules of engagement. The authors accept no liability for misuse.

---

## 🔌 Hardware and platform requirements

Passive/active 802.11 monitoring requires a wireless adapter that supports
**monitor mode** (and, for later stages, **packet injection**), plus a Linux
host with the right drivers.

**Recommended host:** Linux (Kali, Parrot, or any distro with `iw` /
`aircrack-ng` / `nl80211` drivers). A native Windows host **cannot** put its
built-in adapter into monitor mode — use a Linux VM/live-USB with a USB adapter
passed through, or run natively on Linux.

**Known-good monitor-mode + injection chipsets:**

| Chipset | Example adapters | Band | Notes |
|---------|------------------|------|-------|
| Atheros AR9271 | TP-Link TL-WN722N **v1**, Alfa AWUS036NHA | 2.4 GHz | Very well supported; v2/v3 of the WN722N use a different chipset — avoid. |
| Ralink RT3070 / RT5370 | Alfa AWUS036NH, many small USB dongles | 2.4 GHz | Solid, widely available. |
| Realtek RTL8812AU | Alfa AWUS036ACH | 2.4 / 5 GHz | Dual-band; needs `rtl8812au` DKMS driver. |
| MediaTek MT7612U | Alfa AWUS036ACM | 2.4 / 5 GHz | Good mainline-kernel support. |

**Tools expected on the PATH for live use:** `iw` (discovery), and for later
stages `airodump-ng` / `aircrack-ng` / `hcxdumptool` / `hashcat`.

> You do **not** need any of this to try the toolkit out. The discovery module
> can parse saved scan files offline (see Quickstart), so you can develop and
> test on Windows/macOS with no adapter at all.

---

## Installation

```bash
python -m pip install -e ".[dev]"      # editable install with test deps
```

Requires Python **3.11+** (uses the stdlib `tomllib`).

## Easy mode — just launch the menu

You don't have to install anything by hand or remember any commands. Launch the
toolkit and pick options by number:

```bash
./start.sh          # Linux/macOS   (use: sudo ./start.sh   for live WiFi runs)
start.bat           # Windows       (or double-click it)
```

The **first run installs itself automatically** — it creates a local `.venv`,
installs wifiaudit into it, and then opens the menu. Every run after that goes
straight to the menu. (You only need Python 3.11+ already present.) Once
installed you can also just type `wifiaudit` from anywhere.

You'll get a menu:

```
=== wifiaudit ===
What would you like to do?
  1. Set up (create your config)
  2. Try it offline (demo with sample data, no adapter needed)
  3. Run on real WiFi (guided; Linux + adapter + sudo)
  4. Check the audit log
  5. Quit
Enter 1-5:
```

- **Pick `2`** to see the whole pipeline run against bundled sample data with no
  hardware — it discovers, lets you choose a target, captures, and cracks
  (`AuditLab-AP1` → `Summer2026!`). Great first check that everything works.
- **Pick `1`** once to answer a few questions and create your `config.toml`
  (scope, authorization) — no hand-editing TOML.
- **Pick `3`** (on Linux, with `sudo`) to run the guided attack on a real,
  in-scope network: it scans, shows a numbered menu of in-scope APs, you choose
  one, and it manages monitor mode, captures a handshake, and cracks it.

Everything still passes the authorization gate, scope checks, and audit log. The
per-stage commands below remain available for finer control or scripting.

## Quickstart (offline, no adapter needed)

```bash
# 1. Copy the example config and confirm your authorization.
cp config.example.toml config.toml
#    edit config.toml: set authorized=true, operator, reference, expires, scope

# 2. Run discovery against a bundled sample capture.
python -m wifiaudit discover \
    --config config.toml \
    --input tests/fixtures/airodump_sample.csv \
    --format airodump-csv
```

You'll see the enumerated access points with in-scope rows marked, and an entry
appended to the audit log (`audit.log.jsonl` by default).

### Live discovery (Linux + monitor-mode adapter)

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
python -m wifiaudit discover --config config.toml --live --iface wlan0 --seconds 15
```

## Stage 2 — handshake / PMKID capture

Capture is an **active** stage, so unlike discovery it will only ever act on a
target that matches your `[scope]`; an out-of-scope target is refused before any
capture starts. You can develop and test it offline by replaying a saved capture
file — no adapter needed:

```bash
# Offline: analyze a saved .pcap/.cap for a usable handshake or PMKID.
python -m wifiaudit capture \
    --config config.toml \
    --bssid DE:AD:BE:EF:00:01 --essid AuditLab-AP1 \
    --input tests/fixtures/handshake_sample.pcap
```

You'll see, per station, which EAPOL messages (M1–M4) and/or PMKID were captured
and whether the result is crackable, plus `capture.start` / `capture.complete`
entries in the audit log.

### Live capture (Linux + monitor-mode adapter)

```bash
# Interface already in monitor mode (see below); airodump-ng must be on PATH.
python -m wifiaudit capture --config config.toml \
    --bssid DE:AD:BE:EF:00:01 --essid AuditLab-AP1 \
    --live --iface wlan0 --channel 6 --seconds 60
```

**Two capture methods** (choose via `[capture] tool`, or the menu's "How do you
want to capture?" prompt):

- **`airodump-ng`** — captures the WPA **4-way handshake**. Needs a client to
  (re)connect, so it pairs with deauth. Writes `.cap`.
- **`hcxdumptool`** — captures the **PMKID** directly from the AP. This is
  **clientless**: no connected device and no deauth required, which is ideal when
  the target AP has no clients. Writes `.pcapng` (the parser reads both formats).

**Deauthentication** (actively knocking a client off to force a fast re-handshake)
is an active transmission and is **double-gated**: it runs only when you both set
`[capture] allow_deauth = true` in config *and* pass `--deauth`. When enabled it
is sent in **bounded bursts repeatedly across the capture window** (tunable via
`[capture] deauth_interval`) to maximize the chance of catching a handshake.
Enable it only when your rules of engagement explicitly permit it.

## Stage 3 — offline cracking

Given a capture from stage 2 and a wordlist, recover a WPA/WPA2-PSK passphrase by
testing candidates against a captured 4-way handshake **or** a PMKID. The crypto
is pure Python standard library (PBKDF2-HMAC-SHA1 → PRF-512 → MIC / PMKID), so no
external cracking tool is required and it runs fully offline:

```bash
python -m wifiaudit crack \
    --config config.toml \
    --input tests/fixtures/handshake_sample.pcap \
    --essid AuditLab-AP1 --bssid DE:AD:BE:EF:00:01 \
    --wordlist tests/fixtures/wordlist_sample.txt
```

The bundled sample capture cracks to `Summer2026!`. Notes:

- `--essid` is required — it is the PBKDF2 salt, and (with `--bssid`) is checked
  against `[scope]`; an out-of-scope target is refused before any work is done.
- The recovered passphrase is printed to you and can be written with `--json`,
  but it is **kept out of the audit log** (the log records only that a key was
  found, plus the method and attempt count).
- PMKID material is tested first (it is cheaper — one PMK derivation, no PTK).
- For real-scale wordlists this pure-Python engine is correct but not fast; it is
  meant for validation and modest dictionaries. A `hashcat`/`aircrack-ng` handoff
  is a natural future backend behind the same interface.

## Stage 4 — reporting

Build an evidence-linked report from the engagement's **audit log** — the report
is only as trustworthy as the hash chain it is built from, and it says so:

```bash
python -m wifiaudit report --config config.toml            # writes output/report.md
python -m wifiaudit report --config config.toml --format json --output report.json
```

Recovered passphrases become **HIGH** findings and captured-but-not-cracked
material becomes **MEDIUM** findings, deduplicated to one per network and citing
the audit record numbers that evidence them. The report states whether the audit
chain verified intact, and ends with hardening recommendations. Reporting is
read-only (it summarizes the trail and doesn't act on any network), so it works
even after the authorization window has closed.

## Verifying the audit log

```bash
python -m wifiaudit audit-verify --config config.toml
```

The hash chain is recomputed end-to-end; any insertion, deletion, or edit of a
past record breaks the chain and is reported.

---

## Architecture

```
src/wifiaudit/
├── core/
│   ├── config.py          # TOML config → validated dataclasses
│   ├── authorization.py   # the gate + scope matching
│   ├── audit.py           # hash-chained append-only JSONL log
│   └── errors.py          # typed exception hierarchy
├── discovery/
│   ├── models.py          # AccessPoint / Client / ScanResult
│   ├── parsers.py         # pure iw-scan & airodump-CSV parsers (unit-tested)
│   ├── backends.py        # ScanBackend interface + iw/file backends
│   └── scanner.py         # ties backend + scope tagging + audit together
├── capture/
│   ├── models.py          # CaptureTarget / Handshake / CaptureResult
│   ├── pcap.py            # pure pcap reader + EAPOL parser/analyzer (unit-tested)
│   ├── backends.py        # CaptureBackend interface + replay/airodump backends
│   └── capturer.py        # gate + HARD scope refusal + deauth guard + audit
├── crack/
│   ├── models.py          # CrackableHandshake / CrackablePMKID / CrackResult
│   ├── wpa.py             # pure WPA-PSK crypto: PMK/PTK/MIC/PMKID (unit-tested)
│   ├── extract.py         # pull crackable material out of a capture
│   ├── engine.py          # dictionary search (PMK cached per SSID)
│   └── cracker.py         # gate + scope refusal + audit (passphrase redacted)
├── report/
│   ├── models.py          # Finding / Report (severity-ranked)
│   ├── builder.py         # audit records -> findings (pure, unit-tested)
│   ├── render.py          # Report -> Markdown (pure)
│   └── reporter.py        # read audit log + verify chain + write report
└── cli.py                 # argparse entry point
```

Design principles: **pure parsers** (deterministic, trivially testable),
**backends behind an interface** (live *or* offline, easy to mock), and a **hard
authorization boundary** that every stage passes through.

## Development

```bash
python -m pytest            # run the test suite
python -m pytest --cov      # with coverage
```

## License

MIT — see [LICENSE](LICENSE). Using this software does not grant you permission
to test any network; obtaining that permission is your responsibility.
