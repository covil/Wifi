"""Stage 3: offline analysis of captured material (dictionary attack).

Given a capture from stage 2 and a wordlist, recover a WPA/WPA2-PSK passphrase
by testing candidates against a captured 4-way handshake or PMKID. Every run
passes the authorization gate, is refused for out-of-scope targets, and is
recorded to the tamper-evident audit log (the recovered passphrase is kept out
of the log). See :class:`wifiaudit.crack.cracker.Cracker`.

The cryptographic core (:mod:`wifiaudit.crack.wpa`) and the material extractor
(:mod:`wifiaudit.crack.extract`) are pure, standard-library, and deterministic,
so the whole stage is testable offline with no external cracking tools.
"""

from wifiaudit.crack.cracker import Cracker
from wifiaudit.crack.engine import Hit, iter_wordlist, search
from wifiaudit.crack.extract import extract
from wifiaudit.crack.models import CrackableHandshake, CrackablePMKID, CrackResult
from wifiaudit.crack import wpa

__all__ = [
    "Cracker",
    "extract",
    "search",
    "iter_wordlist",
    "Hit",
    "CrackableHandshake",
    "CrackablePMKID",
    "CrackResult",
    "wpa",
]
