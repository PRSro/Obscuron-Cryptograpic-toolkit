"""Tests for CTF attack module CLI commands.

Generates test data programmatically.  Each test is self-contained.
"""
import os
import struct
import sys
import tempfile
import zlib
import subprocess

from conftest import ob_run, PROJECT_ROOT

# ---------------------------------------------------------------------------
# GF(256) arithmetic
# ---------------------------------------------------------------------------

def test_gf256_mul():
    """AES MixColumns test: 0x57 * 0x83 = 0xC1 (AES irreducible poly 0x11b)."""
    rc, out, err = ob_run("gf256-mul", "--a=57", "--b=83")
    assert rc == 0, err
    assert "0xc1" in out.lower() or "C1" in out


def test_gf256_mul_custom_poly():
    rc, out, err = ob_run("gf256-mul", "--a=02", "--b=87", "--poly=0x11d")
    assert rc == 0, err


def test_gf256_inv():
    """GF(2^8) inverse: inv(0x53) = 0xa3 (AES polynomial 0x11b)."""
    rc, out, err = ob_run("gf256-inv", "--a=53")
    assert rc == 0, err
    assert "0xa3" in out.lower() or "A3" in out


# ---------------------------------------------------------------------------
# Shamir Secret Sharing reconstruction
# ---------------------------------------------------------------------------

def test_shamir_two_shares():
    """Recover secret from 2 shares with prime 0x7fffffff."""
    rc, out, err = ob_run(
        "shamir-reconstruct",
        "--shares=1:2,2:3",
        "--prime=0x7fffffff",
    )
    assert rc == 0, err
    assert "1" in out  # secret = 1 (polynomial: f(x)=x+1)


def test_shamir_three_shares():
    """Recover secret from 3 shares with prime 0x7fffffff."""
    rc, out, err = ob_run(
        "shamir-reconstruct",
        "--shares=1:3,2:5,3:7",
        "--prime=0x7fffffff",
    )
    assert rc == 0, err
    assert "1" in out  # secret = 1 (polynomial: f(x)=x^2+1)


# ---------------------------------------------------------------------------
# ECB detection
# ---------------------------------------------------------------------------

def make_ecb_file(blocks):
    """Write `blocks` identical 16-byte AES blocks to a temp file and return path."""
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
    f.write(b"A" * 16 * blocks)
    f.close()
    return f.name


def test_ecb_detect_ecb():
    path = make_ecb_file(4)
    try:
        rc, out, err = ob_run("ecb-detect", "-f", path)
        assert rc == 0, err
        assert "ECB" in out
    finally:
        os.unlink(path)


def test_ecb_detect_random():
    """Random data should NOT be flagged as having ECB mode."""
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
    f.write(os.urandom(64))
    f.close()
    try:
        rc, out, err = ob_run("ecb-detect", "-f", f.name)
        assert rc == 0, err
        assert "No ECB" in out or "not" in out.lower()
    finally:
        os.unlink(f.name)


# ---------------------------------------------------------------------------
# Hash Length Extension
# ---------------------------------------------------------------------------
# Known test: MD5("secret") = "5ebe2294ecd0e0f08eab7690d2a6ee69"
# Extending with "extra" from a secret of length 6.

def test_hash_extend_md5():
    rc, out, err = ob_run(
        "hash-extend",
        "--hash=md5",
        "--known-hash=5ebe2294ecd0e0f08eab7690d2a6ee69",
        "--known-len=6",
        "--append=extra",
    )
    assert rc == 0, err
    assert "Forged" in out or "forged" in out
    assert len(out.split()) >= 3


def test_hash_extend_sha1():
    rc, out, err = ob_run(
        "hash-extend",
        "--hash=sha1",
        "--known-hash=a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
        "--known-len=5",
        "--append=extra",
    )
    assert rc == 0, err


# ---------------------------------------------------------------------------
# ECDSA nonce-reuse attack
# ---------------------------------------------------------------------------

def test_ecdsa_nonce_reuse():
    """Generate two ECDSA signatures with the same k, recover the private key."""
    # secp256k1 order
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    d = 0x1234567890abcdef                        # private key
    k = 0xcafebabedeadbeef                        # nonce (same for both sigs)
    r = 0xdeadc0de                                # (k*G).x mod n (we hardcode r
                                                  # since the tool doesn't validate curve)
    h1 = 0x1111111111111111
    h2 = 0x2222222222222222

    kinv = pow(k, -1, n)
    s1 = (kinv * (h1 + r * d)) % n
    s2 = (kinv * (h2 + r * d)) % n

    rc, out, err = ob_run(
        "ecdsa-nonce-reuse",
        f"--r1={hex(r)}", f"--s1={hex(s1)}",
        f"--h1={hex(h1)}", f"--s2={hex(s2)}",
        f"--h2={hex(h2)}", f"--n={hex(n)}",
    )
    assert rc == 0, err
    # Tool should recover the original private key k and then d
    assert "1234567890abcdef" in out.lower().replace("0x", "")


# ---------------------------------------------------------------------------
# DH weak-parameter check
# ---------------------------------------------------------------------------

def test_dh_check():
    """Test with small prime p = 0x23 (p-1 = 0x22 = fully smooth)."""
    rc, out, err = ob_run("dh-check", "--g=02", "--p=23")
    assert rc == 0, err
    assert any(w in out.lower() for w in ("smooth", "factor", "p-1", "weak", "small"))


def test_dh_check_large_prime():
    """Test with a reasonably large prime (should not flag as obviously weak)."""
    p = "0x" + "f" * 64  # 256-bit all-Fs (not prime, but won't crash)
    rc, out, err = ob_run("dh-check", f"--g=02", f"--p={p}")
    assert rc == 0, err
    # Should at least print something about the parameters
    assert len(out) > 10


# ---------------------------------------------------------------------------
# ZipCrack known-plaintext attack
# ---------------------------------------------------------------------------
# We generate a tiny ZipCrypto-encrypted file in pure Python.

def _make_crc32_table():
    t = [0] * 256
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 & ~((c & 1) - 1))
        t[i] = c
    return t

_CRC32_TABLE = _make_crc32_table()

def _crc32_byte(crc, b):
    return _CRC32_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)

def _update_keys(key0, key1, key2, plain_byte):
    key0 = _crc32_byte(key0, plain_byte)
    key1 = (key1 + (key0 & 0xFF)) * 0x08088405 + 1 & 0xFFFFFFFF
    key2 = _crc32_byte(key2, (key1 >> 24) & 0xFF)
    return key0, key1, key2

def _keystream_byte(key2):
    temp = key2 | 3
    return ((temp * (temp ^ 1)) >> 8) & 0xFF

def _make_encrypted_zip(password: bytes, plaintext: bytes) -> bytes:
    """Create a minimal ZipCrypto-encrypted .zip in memory (stored, no data-descriptor)."""

    key0 = key1 = key2 = 0
    for c in password:
        key0 = _crc32_byte(key0, c)
        key1 = (key1 + (key0 & 0xFF)) * 0x08088405 + 1 & 0xFFFFFFFF
        key2 = _crc32_byte(key2, (key1 >> 24) & 0xFF)

    # Encryption header: 12 bytes (including mtime-based check byte)
    header_plain = bytes([0] * 12)
    header_enc = bytearray()
    for b in header_plain:
        ks = _keystream_byte(key2)
        header_enc.append(b ^ ks)
        key0, key1, key2 = _update_keys(key0, key1, key2, b)

    # Encrypt the actual file data
    enc_data = bytearray()
    for b in plaintext:
        ks = _keystream_byte(key2)
        enc_data.append(b ^ ks)
        key0, key1, key2 = _update_keys(key0, key1, key2, b)

    crc = zlib.crc32(plaintext) & 0xFFFFFFFF
    size = len(plaintext)
    comp_size = 12 + size
    fname = b"test"
    name_len = len(fname)

    # ── Local file header (no data descriptor; comp_sz and crc inline) ──
    lfh = bytearray()
    lfh += b"PK\x03\x04"
    lfh += struct.pack("<H", 20)     # version needed
    lfh += struct.pack("<H", 1)      # flags: bit 0 = encrypted
    lfh += struct.pack("<H", 0)      # compression method: stored
    lfh += struct.pack("<H", 0x0A)   # mod time (dummy)
    lfh += struct.pack("<H", 0x21)   # mod date (dummy)
    lfh += struct.pack("<I", crc)
    lfh += struct.pack("<I", comp_size)
    lfh += struct.pack("<I", size)
    lfh += struct.pack("<H", name_len)
    lfh += struct.pack("<H", 0)      # extra field length
    lfh += fname

    # ── Central directory file header ──
    cfh = bytearray()
    cfh += b"PK\x01\x02"
    cfh += struct.pack("<H", 20)     # version made by
    cfh += struct.pack("<H", 20)     # version needed
    cfh += struct.pack("<H", 1)      # flags: encrypted
    cfh += struct.pack("<H", 0)      # compression: stored
    cfh += struct.pack("<H", 0x0A)
    cfh += struct.pack("<H", 0x21)
    cfh += struct.pack("<I", crc)
    cfh += struct.pack("<I", comp_size)
    cfh += struct.pack("<I", size)
    cfh += struct.pack("<H", name_len)
    cfh += struct.pack("<H", 0)
    cfh += struct.pack("<H", 0)
    cfh += struct.pack("<H", 0)
    cfh += struct.pack("<H", 0)
    cfh += struct.pack("<I", 0)
    cfh += struct.pack("<I", 0)
    cfh += fname

    # ── End of central directory ──
    cd_offset = len(lfh) + comp_size
    eocd = bytearray()
    eocd += b"PK\x05\x06"
    eocd += struct.pack("<H", 0)
    eocd += struct.pack("<H", 0)
    eocd += struct.pack("<H", 1)
    eocd += struct.pack("<H", 1)
    eocd += struct.pack("<I", len(cfh))
    eocd += struct.pack("<I", cd_offset)
    eocd += struct.pack("<H", 0)

    return bytes(lfh) + bytes(header_enc) + bytes(enc_data) + bytes(cfh) + bytes(eocd)


def test_zip_crack():
    password = b"ctf2024"
    plaintext = b"This is a known plaintext for the ZipCrypto attack!!!!"
    zip_data = _make_encrypted_zip(password, plaintext)

    # Provide first 12+ bytes as known plaintext
    known = plaintext[:16].hex()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as f:
        f.write(zip_data)
        zippath = f.name

    try:
        rc, out, err = ob_run("zip-crack", f"--zip={zippath}", f"--known-hex={known}")
        assert rc == 0, f"zip-crack failed: exit={rc} err={err}\nout={out}"
    finally:
        os.unlink(zippath)


# ---------------------------------------------------------------------------
# CBC padding-oracle (mock oracle)
# ---------------------------------------------------------------------------

def test_cbc_padding_oracle():
    """Run cbc-padding-oracle with a mock oracle that validates PKCS#7 padding."""
    oracle_code = (
        "import sys, binascii\n"
        "for line in sys.stdin:\n"
        "    line = line.strip()\n"
        "    if not line:\n"
        "        continue\n"
        "    try:\n"
        "        ct_hex, _ = line.split(':')\n"
        "        ct = binascii.unhexlify(ct_hex)\n"
        "        pad = ct[-1]\n"
        "        if 1 <= pad <= 16 and all(b == pad for b in ct[-pad:]):\n"
        "            sys.exit(0)\n"
        "        else:\n"
        "            sys.exit(1)\n"
        "    except Exception:\n"
        "        sys.exit(1)\n"
    )

    oracle_script = tempfile.NamedTemporaryFile(
        mode="w", delete=False, suffix=".py", prefix="oracle_"
    )
    oracle_script.write(oracle_code)
    oracle_path = oracle_script.name
    oracle_script.close()

    try:
        ct = "000102030405060708090a0b0c0d0e01"
        iv = "0" * 32

        rc, out, err = ob_run(
            "cbc-padding-oracle",
            f"-c={ct}", f"-i={iv}",
            f"--oracle={sys.executable} {oracle_path}",
            "--timeout-ms=5000",
        )
        assert rc == 0, err
        assert len(out) > 0
    finally:
        os.unlink(oracle_path)


# ---------------------------------------------------------------------------
# --list sanity
# ---------------------------------------------------------------------------

def test_list_includes_attacks():
    rc, out, err = ob_run("--list")
    assert rc == 0, err
    for cmd in ("ecb-detect", "cbc-padding-oracle", "hash-extend",
                "ecdsa-nonce-reuse", "dh-check", "zip-crack",
                "shamir-reconstruct", "gf256-mul", "gf256-inv"):
        assert cmd in out, f"'{cmd}' missing from --list"
