"""Wordlist discovery and reading.

Beta users rarely have a wordlist path memorized, and on Kali the classic list
(`rockyou.txt`) ships gzipped. This module finds wordlists in the usual places
and reads them transparently whether or not they are gzip-compressed.
"""

from __future__ import annotations

import glob
import gzip
from pathlib import Path

# Common locations on Kali / pentest distros, most useful first.
_COMMON = (
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/usr/share/wordlists/fasttrack.txt",
    "/usr/share/wordlists/nmap.lst",
    "/usr/share/wordlists/wifite.txt",
    "/usr/share/dict/words",
)


def list_wordlists(extra: tuple[str, ...] = ()) -> list[str]:
    """Return existing wordlist paths: any ``extra`` first, then common ones."""
    found: list[str] = []
    for candidate in (*extra, *_COMMON):
        if candidate and Path(candidate).is_file():
            found.append(str(candidate))
    for match in sorted(glob.glob("/usr/share/wordlists/*.txt")):
        found.append(match)
    # de-duplicate while preserving order
    return list(dict.fromkeys(found))


def read_wordlist(path: str | Path) -> str:
    """Read a wordlist's text, transparently decompressing ``.gz`` files."""
    p = Path(path)
    if p.suffix == ".gz":
        with gzip.open(p, "rt", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    return p.read_text(encoding="utf-8", errors="replace")


__all__ = ["list_wordlists", "read_wordlist"]
