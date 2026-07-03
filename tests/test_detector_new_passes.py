"""Tests for 4 new detector passes: scytale, bifid, trifid, four-square.

For each cipher, encrypt known English plaintext and verify detection.
"""

from conftest import ob_run
import pytest


def bifid_key_from_keyword(keyword):
    """Generate 25-char bifid grid key from a keyword (I=J merged)."""
    used = set()
    seq = []
    for ch in keyword.upper():
        if ch == 'J': ch = 'I'
        if 'A' <= ch <= 'Z' and ch not in used:
            seq.append(ch); used.add(ch)
    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in used:
            seq.append(ch)
    return ''.join(seq)


def detect_matches(ct, *expected):
    rc, out, err = ob_run("detect", ct)
    if rc != 0:
        return False, f"return code {rc}: {err}"
    out_lower = out.lower()
    for name in expected:
        if name.lower() in out_lower:
            return True, out
    return False, out


# ── Scytale ──

def test_detect_scytale_key3():
    rc, ct, err = ob_run("scytale", "-k", "3", "This is a secret message")
    assert rc == 0, err
    ok, out = detect_matches(ct.strip(), "scytale")
    assert ok, f"Expected scytale in:\n{out}"


def test_detect_scytale_key5():
    rc, ct, err = ob_run("scytale", "-k", "5", "The quick brown fox jumps over lazy dog")
    assert rc == 0, err
    ok, out = detect_matches(ct.strip(), "scytale")
    assert ok, f"Expected scytale in:\n{out}"


def test_detect_scytale_key7():
    rc, ct, err = ob_run("scytale", "-k", "7", "Hello world this is a test of scytale cipher")
    assert rc == 0, err
    ok, out = detect_matches(ct.strip(), "scytale")
    assert ok, f"Expected scytale in:\n{out}"


# ── Bifid ──

def strip_spaces(text):
    return ''.join(text.split())


def test_detect_bifid_keyword():
    k = bifid_key_from_keyword("KEYWORD")
    rc, ct, err = ob_run("bifid", "-k", k, strip_spaces("THIS IS A SECRET MESSAGE"))
    assert rc == 0, f"bifid encrypt failed: rc={rc} err={err}"
    ok, out = detect_matches(ct.strip(), "bifid")
    assert ok, f"Expected bifid in:\n{out}"


def test_detect_bifid_crypto():
    k = bifid_key_from_keyword("CRYPTO")
    rc, ct, err = ob_run("bifid", "-k", k, strip_spaces("THE QUICK BROWN FOX JUMPS OVER"))
    assert rc == 0, f"bifid encrypt failed: rc={rc} err={err}"
    ok, out = detect_matches(ct.strip(), "bifid")
    assert ok, f"Expected bifid in:\n{out}"


def test_detect_bifid_secret():
    k = bifid_key_from_keyword("SECRET")
    rc, ct, err = ob_run("bifid", "-k", k, strip_spaces("HELLO WORLD THIS IS A TEST"))
    assert rc == 0, f"bifid encrypt failed: rc={rc} err={err}"
    ok, out = detect_matches(ct.strip(), "bifid")
    assert ok, f"Expected bifid in:\n{out}"


# ── Trifid ──

def test_detect_trifid_keyword_p5():
    rc, ct, err = ob_run("trifid", "-k", "KEYWORD", "--len", "5", "THIS IS A SECRET MESSAGE")
    assert rc == 0, err
    ok, out = detect_matches(ct.strip(), "trifid")
    assert ok, f"Expected trifid in:\n{out}"


def test_detect_trifid_crypto_p4():
    rc, ct, err = ob_run("trifid", "-k", "CRYPTO", "--len", "4", "THE QUICK BROWN FOX JUMPS OVER")
    assert rc == 0, err
    ok, out = detect_matches(ct.strip(), "trifid")
    assert ok, f"Expected trifid in:\n{out}"


def test_detect_trifid_secret_p6():
    rc, ct, err = ob_run("trifid", "-k", "SECRET", "--len", "6", "HELLO WORLD THIS IS A TEST MESSAGE")
    assert rc == 0, err
    ok, out = detect_matches(ct.strip(), "trifid")
    assert ok, f"Expected trifid in:\n{out}"


# ── Four-Square ──

def test_detect_four_square_keyword_crypto():
    rc, ct, err = ob_run("four-square", "-k", "KEYWORD,CRYPTO", "This is a secret message")
    assert rc == 0, err
    ok, out = detect_matches(ct.strip(), "four-square")
    assert ok, f"Expected four-square in:\n{out}"


def test_detect_four_square_secret_code():
    rc, ct, err = ob_run("four-square", "-k", "SECRET,CODE", "The quick brown fox jumps")
    assert rc == 0, err
    ok, out = detect_matches(ct.strip(), "four-square")
    assert ok, f"Expected four-square in:\n{out}"


def test_detect_four_square_cipher_test():
    rc, ct, err = ob_run("four-square", "-k", "CIPHER,TEST", "Hello world this is a test")
    assert rc == 0, err
    ok, out = detect_matches(ct.strip(), "four-square")
    assert ok, f"Expected four-square in:\n{out}"
