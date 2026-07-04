"""Coverage tests for CLI commands not tested elsewhere.

Covers: sha512, pbkdf2, hmac-sha256, hmac-sha512,
        rc4, blowfish, des, urlcode, binary, octal,
        rot47, playfair, scytale, polybius, a1z26,
        keyboard-shift, autokey, beaufort.
"""
import subprocess
from conftest import ob_run, PROJECT_ROOT


OB_CRYPT = PROJECT_ROOT + "/CLI/ob-crypt"


def ob_raw(*args, input_data=None):
    """Run ob-crypt with args, return (returncode, stdout_bytes, stderr_text)."""
    result = subprocess.run(
        [OB_CRYPT] + list(args),
        input=input_data,
        capture_output=True,
        timeout=30,
    )
    return result.returncode, result.stdout, result.stderr.decode()


# ── Hash operations ──

def test_sha512():
    rc, out, err = ob_run("sha512", "hello")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_pbkdf2():
    rc, out, err = ob_run("pbkdf2", "-s", "salt", "--iter=1", "--len=16", "password")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_pbkdf2_different_len():
    rc, out, err = ob_run("pbkdf2", "-s", "salt", "--iter=1", "--len=32", "password")
    assert rc == 0, err
    assert len(out.strip()) > 0


# ── HMAC operations ──

def test_hmac_sha256():
    rc, out, err = ob_run("hmac-sha256", "-k", "key", "message")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_hmac_sha512():
    rc, out, err = ob_run("hmac-sha512", "-k", "key", "message")
    assert rc == 0, err
    assert len(out.strip()) > 0


# ── Outdated ciphers (RC4, Blowfish, DES) ──
# These produce binary output; use ob_raw for roundtrip with raw pipe.

def test_rc4_encrypt():
    rc, out, err = ob_run("rc4", "--hex-output", "-k", "key", "hello")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_rc4_roundtrip_raw():
    """RC4 roundtrip via raw binary pipe (encrypt XOR = decrypt)."""
    rc, enc, _ = ob_raw("rc4", "-k", "00112233445566778899aabbccddeeff", input_data=b"testdata")
    assert rc == 0
    # rc4 is symmetric XOR; strip trailing newline from print_result
    enc_data = enc.rstrip(b"\n")
    rc2, dec, _ = ob_raw("rc4", "-k", "00112233445566778899aabbccddeeff", input_data=enc_data)
    assert rc2 == 0
    assert dec.rstrip(b"\n") == b"testdata"


def test_blowfish_encrypt():
    rc, out, err = ob_run("blowfish", "--hex-output", "-k", "key", "hello")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_blowfish_roundtrip_raw():
    """Blowfish ECB roundtrip via raw binary pipe."""
    key = "00112233445566778899aabbccddeeff"
    rc, enc, _ = ob_raw("blowfish", "-k", key, input_data=b"testdata")
    assert rc == 0
    enc_data = enc.rstrip(b"\n")
    rc2, dec, _ = ob_raw("blowfish", "-k", key, "--decrypt", input_data=enc_data)
    assert rc2 == 0
    assert dec.rstrip(b"\n").rstrip(b"\x00") == b"testdata"


def test_des_encrypt():
    rc, out, err = ob_run("des", "--hex-output", "-k", "0011223344556677", "hello")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_des_roundtrip_raw():
    """DES ECB roundtrip via raw binary pipe."""
    key = "0011223344556677"
    rc, enc, _ = ob_raw("des", "-k", key, input_data=b"testdata")
    assert rc == 0
    enc_data = enc.rstrip(b"\n")
    rc2, dec, _ = ob_raw("des", "-k", key, "--decrypt", input_data=enc_data)
    assert rc2 == 0
    assert dec.rstrip(b"\n").rstrip(b"\x00") == b"testdata"


# ── Encodings ──

def test_urlcode_encode():
    rc, out, err = ob_run("urlcode", "hello world")
    assert rc == 0, err
    assert "hello%20world" in out or out.strip().lower() == "hello%20world"


def test_urlcode_decode():
    rc, out, err = ob_run("urlcode", "--decrypt", "hello%20world")
    assert rc == 0, err
    assert out.strip() == "hello world"


def test_binary_encode():
    rc, out, err = ob_run("binary", "hello")
    assert rc == 0, err
    assert "01101000" in out


def test_binary_decode():
    rc, out, err = ob_run("binary", "--decrypt", "01101000 01100101 01101100 01101100 01101111")
    assert rc == 0, err
    assert "hello" in out


def test_octal_encode():
    rc, out, err = ob_run("octal", "hello")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_octal_decode():
    rc, out, err = ob_run("octal", "--decrypt", "150 145 154 154 157")
    assert rc == 0, err
    assert out.strip() == "hello"


# ── Cipher operations ──

def test_rot47():
    """ROT47 produces different output from input."""
    rc, out, err = ob_run("rot47", "Hello World!")
    assert rc == 0, err
    assert len(out.strip()) > 0
    assert out.strip() != "Hello World!"


def test_rot47_roundtrip():
    """Two ROT47 applications return to original."""
    enc = ob_run("rot47", "Hello")[1].strip()
    dec = ob_run("rot47", enc)[1].strip()
    assert dec == "Hello"


def test_playfair_encrypt():
    rc, out, err = ob_run("playfair", "-k", "KEYWORD", "HELLOWORLD")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_playfair_roundtrip():
    """Playfair decrypt recovers original (with doubled-letter padding X)."""
    msg = "HELLOWORLD"
    enc = ob_run("playfair", "-k", "CRYPTO", msg)[1].strip()
    assert len(enc) >= len(msg)
    dec = ob_run("playfair", "-k", "CRYPTO", "--decrypt", enc)[1].strip()
    # Playfair inserts X between doubled letters and pads
    assert dec.startswith("HEL") and "LOWORLD" in dec


def test_scytale_encrypt():
    rc, out, err = ob_run("scytale", "-k", "4", "HELLOWORLD")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_scytale_roundtrip():
    msg = "HELLOWORLD"
    enc = ob_run("scytale", "-k", "5", msg)[1].strip()
    dec = ob_run("scytale", "-k", "5", "--decrypt", enc)[1].strip()
    assert dec == msg


def test_polybius_encrypt():
    rc, out, err = ob_run("polybius", "HELLO")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_polybius_roundtrip():
    enc = ob_run("polybius", "HELLO")[1].strip()
    dec = ob_run("polybius", "--decrypt", enc)[1].strip()
    assert dec == "HELLO"


def test_a1z26_encode():
    rc, out, err = ob_run("a1z26", "hello")
    assert rc == 0, err
    assert "8-5-12-12-15" in out


def test_keyboard_shift_encrypt():
    rc, out, err = ob_run("keyboard-shift", "-x", "1", "hello")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_keyboard_shift_roundtrip():
    msg = "hello"
    enc = ob_run("keyboard-shift", "-x", "1", msg)[1].strip()
    dec = ob_run("keyboard-shift", "-x", "1", "--decrypt", enc)[1].strip()
    assert dec == msg


def test_keyboard_shift_diagonal():
    msg = "test"
    enc = ob_run("keyboard-shift", "-x", "1", "-y", "1", msg)[1].strip()
    rc, out, err = ob_run("keyboard-shift", "-x", "1", "-y", "1", "--decrypt", enc)
    assert rc == 0, err
    assert out.strip() == msg


def test_autokey_encrypt():
    rc, out, err = ob_run("autokey", "-k", "key", "HELLOWORLD")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_autokey_roundtrip():
    msg = "HELLOWORLD"
    enc = ob_run("autokey", "-k", "key", msg)[1].strip()
    dec = ob_run("autokey", "-k", "key", "--decrypt", enc)[1].strip()
    assert dec == msg


def test_beaufort_encrypt():
    rc, out, err = ob_run("beaufort", "-k", "key", "HELLOWORLD")
    assert rc == 0, err
    assert len(out.strip()) > 0


def test_beaufort_roundtrip():
    msg = "HELLOWORLD"
    enc = ob_run("beaufort", "-k", "key", msg)[1].strip()
    dec = ob_run("beaufort", "-k", "key", enc)[1].strip()
    assert dec == msg


# ── Edge cases ──

def test_empty_input():
    """Commands should not crash on empty input."""
    for cmd in ("sha512", "rot47", "a1z26", "binary", "octal"):
        rc, out, err = ob_run(cmd, "")
        assert rc == 0, f"{cmd} failed on empty input: {err}"
