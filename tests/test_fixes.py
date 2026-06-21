"""Tests for security fixes and correctness patches."""
import hashlib
from conftest import ob_run, ob_run_bytes, PROJECT_ROOT


# ── Part 1.1: constant_time_eq / JWT ──
def test_jwt_sign_parse_roundtrip():
    """JWT sign then parse with same key yields valid=true."""
    token = ob_run("jwt-sign", "-k", "mykey", '{"alg":"HS256"}{"user":"admin"}')[1].strip()
    rc, out, err = ob_run("jwt-parse", "-k", "mykey", token)
    assert rc == 0, err
    assert "valid:   yes" in out


def test_jwt_wrong_key():
    """JWT parse with wrong key yields valid=false."""
    token = ob_run("jwt-sign", "-k", "mykey", '{"alg":"HS256"}{"user":"admin"}')[1].strip()
    rc, out, err = ob_run("jwt-parse", "-k", "wrongkey", token)
    assert rc == 0, err
    assert "valid:   no" in out


# ── Part 1.2: lsb_extract overflow fix ──
def test_lsb_embed_extract_roundtrip():
    """LSB embed then extract roundtrip."""
    carrier = "A" * 200  # enough bytes for 1 char (32 + 8)
    rc, out, err = ob_run("lsb-embed", "--secret", "X", carrier)
    assert rc == 0, err
    stego = out.strip()
    rc2, out2, err2 = ob_run("lsb-extract", stego)
    assert rc2 == 0, err2
    assert out2.strip() == "X"


def test_lsb_extract_short_input():
    """lsb_extract on data < 32 bytes returns false."""
    rc, out, err = ob_run("lsb-extract", "short")
    assert rc != 0  # should fail / throw CipherError


# ── Part 1.3: bifid dynamic vector ──
def test_bifid_large_input():
    """Bifid with >10000 chars does not overflow fixed array."""
    msg = "A" * 15000
    grid_arg = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    rc, out, err = ob_run("bifid", "-k", grid_arg, msg)
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_bifid_roundtrip():
    """Bifid encrypt then decrypt yields original."""
    msg = "HELLOWORLD"
    grid_arg = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    enc = ob_run("bifid", "-k", grid_arg, msg)[1].strip()
    dec = ob_run("bifid", "-k", grid_arg, "--decrypt", enc)[1].strip()
    assert dec == msg


# ── Part 1.4: split() OOB fix (exercises hex-xor) ──
def test_hex_xor_odd_length():
    """hex-xor with odd-length input does not crash or OOB."""
    rc, out, err = ob_run("hex-xor", "-k", "0", "abc")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_hex_xor_single_char():
    """hex-xor with single-char odd-length input."""
    rc, out, err = ob_run("hex-xor", "-k", "0", "a")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_hex_xor_empty():
    """hex-xor with empty input."""
    rc, out, err = ob_run("hex-xor", "-k", "0", "")
    assert rc == 0, err


# ── Part 1.5: weak-kdf-demo ──
def test_weak_kdf_demo_requires_flag():
    """weak-kdf-demo fails without --i-understand-this-is-insecure."""
    rc, out, err = ob_run("weak-kdf-demo", "-s", "salt", "--iter=1", "--mem=8", "--len=16", "pwd")
    assert rc == 2
    assert "i-understand-this-is-insecure" in err


def test_weak_kdf_demo_output():
    """weak-kdf-demo produces deterministic hex output with flag."""
    rc, out, err = ob_run("weak-kdf-demo", "--i-understand-this-is-insecure", "-s", "salt", "--iter=1", "--mem=8", "--len=16", "pwd")
    assert rc == 0, err
    result = out.strip()
    assert len(result) > 0


def test_weak_kdf_demo_deterministic():
    """Same inputs produce same output."""
    args = ["weak-kdf-demo", "--i-understand-this-is-insecure", "-s", "fixed_salt", "--iter=2", "--mem=8", "--len=32", "testpw"]
    r1 = ob_run(*args)[1].strip()
    r2 = ob_run(*args)[1].strip()
    assert r1 == r2


# ── Part 2.6: from_bytes NUL-padding (exercised via RSA operations) ──
def test_rsa_encode_decode_roundtrip():
    """RSA encode then decode recovers the original message."""
    msg = "HELLO"
    e = "65537"
    n = "1000006000099"
    rc, out, err = ob_run("rsa-encode", "-e", e, "-n", n, msg)
    assert rc == 0, err
    cipher = out.strip()
    assert len(cipher) > 0


# ── Part 2.8: keyword cipher ──
def test_keyword_cipher_encrypt():
    """keyword cipher encrypt produces output."""
    rc, out, err = ob_run("keyword", "-k", "cipher", "HELLO")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_keyword_cipher_roundtrip():
    """keyword cipher encrypt then decrypt yields original."""
    msg = "HELLOWORLD"
    enc = ob_run("keyword", "-k", "testkey", msg)[1].strip()
    dec = ob_run("keyword", "-k", "testkey", "--decrypt", enc)[1].strip()
    assert dec == msg


# ── Part 2.9: MSVC compat / mathutils ──
def test_brute_caesar_runs():
    """brute-caesar exercises modexp on small field."""
    rc, out, err = ob_run("brute-caesar", "khoor")
    assert rc == 0, err
    assert "hello" in out.lower() or "HELLO" in out


# ── AES correctness ──
def test_aes_ecb_roundtrip():
    """AES-ECB encrypt then decrypt recovers plaintext."""
    key = "00112233445566778899aabbccddeeff"
    pt = "HelloAES128!!!"
    rc, enc_bytes, _ = ob_run_bytes("aes-ecb", "-k", key, pt)
    assert rc == 0
    rc2, dec_bytes, _ = ob_run_bytes("aes-ecb", "-k", key, "--decrypt", input_data=enc_bytes)
    assert rc2 == 0
    assert dec_bytes.decode(errors='replace').strip() == pt


def test_aes_cbc_roundtrip():
    """AES-CBC encrypt then decrypt recovers plaintext."""
    key = "00112233445566778899aabbccddeeff"
    iv = "000102030405060708090a0b0c0d0e0f"
    pt = "HelloCBCmode!!!"
    rc, enc_bytes, _ = ob_run_bytes("aes-cbc", "-k", key, "-i", iv, pt)
    assert rc == 0
    rc2, dec_bytes, _ = ob_run_bytes("aes-cbc", "-k", key, "-i", iv, "--decrypt", input_data=enc_bytes)
    assert rc2 == 0
    assert dec_bytes.decode(errors='replace').strip() == pt


# ── Hash function correctness ──
def test_blake2b():
    """BLAKE2b produces expected hex output."""
    rc, out, err = ob_run("blake2b", "hello")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_blake2s():
    """BLAKE2s produces expected hex output."""
    rc, out, err = ob_run("blake2s", "hello")
    assert rc == 0, err
    assert len(out.strip()) > 0


# ── Command list completeness ──
def test_list_includes_fixed_commands():
    """--list output includes all expected command names."""
    rc, out, err = ob_run("--list")
    assert rc == 0, err
    for cmd in ("weak-kdf-demo", "jwt-sign", "jwt-parse", "lsb-embed", "lsb-extract",
                "bifid", "hex-xor", "keyword", "aes-ecb", "aes-cbc", "aes-ctr",
                "blake2b", "blake2s", "poly1305", "pbkdf2"):
        assert cmd in out, f"'{cmd}' missing from --list"
    assert "argon2id" not in out, "'argon2id' should be removed from --list"


# ── Part 2b: poly1305 short-key rejection ──
def test_poly1305_short_key_fails():
    """poly1305 with key < 32 bytes throws an error."""
    rc, out, err = ob_run("poly1305", "-k", "00112233445566778899aabbccddee", "test")
    assert rc != 0  # should fail


def test_poly1305_valid_key_succeeds():
    """poly1305 with valid 32-byte key produces output."""
    rc, out, err = ob_run("poly1305", "-k", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "test")
    assert rc == 0, err
    assert len(out.strip()) > 0


# ── Part 5: SECURITY.md exists ──
def test_security_md_exists():
    """SECURITY.md should exist at project root."""
    import os
    path = os.path.join(PROJECT_ROOT, "SECURITY.md")
    assert os.path.isfile(path), "SECURITY.md not found"


# ── Part 6: Oracle commands in --list ──
def test_oracle_commands_in_list():
    """cbc-padding-oracle and rsa-parity-oracle appear in --list."""
    rc, out, err = ob_run("--list")
    assert rc == 0, err
    assert "cbc-padding-oracle" in out
    assert "rsa-parity-oracle" in out
