"""Tests for general CLI infrastructure (flags, piping, --list, error cases)."""
import base64
from conftest import ob_run


def test_list():
    rc, out, err = ob_run("--list")
    assert rc == 0, err
    # Core commands should be present
    for cmd in ("hex", "base64", "detect", "analyze",
                "rot13", "caesar", "md5", "sha256",
                "aes-ecb", "aes-cbc", "chacha20",
                "rsa-decrypt"):
        assert cmd in out, f"'{cmd}' missing from --list"


def test_list_attack_commands():
    rc, out, err = ob_run("--list")
    assert rc == 0, err
    for cmd in ("ecb-detect", "cbc-padding-oracle", "hash-extend",
                "ecdsa-nonce-reuse", "dh-check", "zip-crack",
                "shamir-reconstruct", "gf256-mul", "gf256-inv"):
        assert cmd in out


def test_list_tls_commands():
    rc, out, err = ob_run("--list")
    assert rc == 0, err
    for cmd in ("tls-fingerprint", "parse-cert"):
        assert cmd in out


def test_help():
    rc, out, err = ob_run("--help")
    assert rc == 0, err
    assert len(out) > 0


def test_unknown_command():
    rc, out, err = ob_run("this-command-does-not-exist", "input")
    assert rc != 0
    assert "ob-crypt" in err or "error" in err.lower() or "unknown" in err.lower()


def test_hex_output_flag():
    rc, out, err = ob_run("hex", "--hex-output", "68656c6c6f")
    assert rc == 0, err
    assert out.strip() == "68656c6c6f"


def _hex(s):
    return s.encode().hex()

def _b64(s):
    return base64.b64encode(s.encode()).decode()

def test_chain_single_step():
    rc, out, err = ob_run("--raw", "chain", "--steps", "hex", _hex("Hello"))
    assert rc == 0, err
    assert out.strip() == "Hello"

def test_chain_two_steps():
    data = _b64(_hex("Hello World"))
    rc, out, err = ob_run("--raw", "chain", "--steps", "base64,hex", data)
    assert rc == 0, err
    assert out.strip() == "Hello World"

def test_chain_three_steps():
    data = _b64(_b64(_hex("Hello World")))
    rc, out, err = ob_run("--raw", "chain", "--steps", "base64,base64,hex", data)
    assert rc == 0, err
    assert out.strip() == "Hello World"

def test_chain_five_steps():
    data = _hex("Test")
    for _ in range(4):
        data = _b64(data)
    rc, out, err = ob_run("--raw", "chain", "--steps",
                          "base64,base64,base64,base64,hex", data)
    assert rc == 0, err
    assert out.strip() == "Test"

def test_chain_ten_steps():
    data = _hex("Hi")
    for _ in range(9):
        data = _b64(data)
    steps = ",".join(["base64"] * 9 + ["hex"])
    rc, out, err = ob_run("--raw", "chain", "--steps", steps, data)
    assert rc == 0, err
    assert out.strip() == "Hi"

def test_chain_with_param():
    cipher = ob_run("caesar", "-s", "3", "Hello")[1].strip()
    data = _hex(cipher)
    rc, out, err = ob_run("--raw", "chain", "--steps", "hex,caesar:23", data)
    assert rc == 0, err
    assert out.strip() == "Hello"

def test_chain_detect():
    data = _b64(_hex("Hello World"))
    rc, out, err = ob_run("--raw", "chain", "--steps", "base64,hex", "--detect", data)
    assert rc == 0, err
    assert "plaintext" in out

def test_chain_unknown_step():
    rc, out, err = ob_run("--raw", "chain", "--steps", "nope,hex", _hex("Hello"))
    assert rc == 0, err
    assert out.strip() == "Hello"

def test_chain_auto_single():
    rc, out, err = ob_run("--raw", "chain", "--auto", _hex("Hello"))
    assert rc == 0, err
    assert out.strip() == "Hello"

def test_chain_auto_multi():
    data = _b64(_hex("Hello World"))
    rc, out, err = ob_run("--raw", "chain", "--auto", data)
    assert rc == 0, err
    assert out.strip() == "Hello World"

def test_chain_auto_deep():
    data = _hex("Hi")
    for _ in range(4):
        data = _b64(data)
    rc, out, err = ob_run("--raw", "chain", "--auto", "--max-depth", "7", data)
    assert rc == 0, err
    assert out.strip() == "Hi"

def test_chain_auto_with_steps():
    data = _b64(_b64(_hex("Hello")))
    rc, out, err = ob_run("--raw", "chain", "--steps", "base64", "--auto", data)
    assert rc == 0, err
    assert out.strip() == "Hello"
