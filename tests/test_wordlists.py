"""Tests for wordlist discovery and reading."""

from __future__ import annotations

import gzip

from wifiaudit.core.wordlists import list_wordlists, read_wordlist


def test_list_includes_existing_extra_and_skips_missing(tmp_path):
    real = tmp_path / "mylist.txt"
    real.write_text("a\nb\n", encoding="utf-8")
    missing = tmp_path / "nope.txt"

    found = list_wordlists(extra=(str(real), str(missing)))
    assert str(real) in found
    assert str(missing) not in found


def test_read_plain_wordlist(tmp_path):
    p = tmp_path / "w.txt"
    p.write_text("password\nletmein\n", encoding="utf-8")
    assert read_wordlist(p).splitlines() == ["password", "letmein"]


def test_read_gzipped_wordlist(tmp_path):
    p = tmp_path / "rockyou.txt.gz"
    with gzip.open(p, "wt", encoding="utf-8") as fh:
        fh.write("Summer2026!\nhunter2\n")
    assert read_wordlist(p).splitlines() == ["Summer2026!", "hunter2"]
