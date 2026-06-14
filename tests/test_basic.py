"""Tests for basic/historical cipher CLI commands."""
from conftest import ob_run


def test_rot13():
    rc, out, err = ob_run("rot13", "hello")
    assert rc == 0, err
    assert out.strip() == "uryyb"


def test_caesar():
    rc, out, err = ob_run("caesar", "--key=3", "hello")
    assert rc == 0, err
    assert out.strip() == "khoor"


def test_vigenere():
    rc, out, err = ob_run("vigenere", "-k", "key", "helloworld")
    assert rc == 0, err
    assert out.strip() == "rijvsuyvjn"


def test_atbash():
    rc, out, err = ob_run("atbash", "abc")
    assert rc == 0, err
    assert out.strip() == "zyx"


def test_affine():
    rc, out, err = ob_run("affine", "--a=5", "--b=8", "affine")
    assert rc == 0, err
    assert out.strip() == "ihhwvc"


def test_morse():
    rc, out, err = ob_run("morse", "sos")
    assert rc == 0, err
    assert "... --- ..." in out


def test_base64_decode():
    rc, out, err = ob_run("base_decode", "-b", "64", "hello")
    assert rc == 0, err


def test_hex_encode():
    rc, out, err = ob_run("hex", "68656c6c6f")
    assert rc == 0, err
    assert out.strip() == "hello"


def test_strxor():
    rc, out, err = ob_run("str-xor", "-k", "key", "hello")
    assert rc == 0, err
    assert len(out.strip()) > 0
