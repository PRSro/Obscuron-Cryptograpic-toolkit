"""Tests for general CLI infrastructure (flags, piping, --list, error cases)."""
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
