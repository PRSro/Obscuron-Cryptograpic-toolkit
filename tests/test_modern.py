"""Tests for modern cipher CLI commands."""
import hashlib
from conftest import ob_run


def test_md5():
    rc, out, err = ob_run("md5", "hello")
    assert rc == 0, err
    h = hashlib.md5(b"hello").hexdigest()
    assert h in out


def test_sha256():
    rc, out, err = ob_run("sha256", "hello")
    assert rc == 0, err
    h = hashlib.sha256(b"hello").hexdigest()
    assert h in out


def test_sha1():
    rc, out, err = ob_run("sha1", "hello")
    assert rc == 0, err
    h = hashlib.sha1(b"hello").hexdigest()
    assert h in out


def test_base64():
    rc, out, err = ob_run("base_encode", "-b", "64", "hello")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_salsa20():
    key = "0" * 64
    nonce = "0" * 16
    rc, out, err = ob_run("salsa20", "-k", key, "-i", nonce, "--hex-output", "hello")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_chacha20():
    key = "0" * 64
    nonce = "0" * 32
    rc, out, err = ob_run("chacha20", "-k", key, "-i", nonce, "--hex-output", "hello")
    assert rc == 0, err
    assert len(out.strip()) > 0
