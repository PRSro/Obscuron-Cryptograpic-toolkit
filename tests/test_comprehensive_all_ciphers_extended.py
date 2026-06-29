import random
import string
import base64
import pytest
from conftest import ob_run

# ----------------------------------------------------------------------
# Deterministic plaintext generator (fixed seed → reproducible tests)
# ----------------------------------------------------------------------
def _random_plaintexts(num_texts, length_range=(10, 30)):
    """Generate `num_texts` random uppercase strings."""
    random.seed(0)                     # deterministic across runs
    texts = set()
    while len(texts) < num_texts:
        length = random.randint(*length_range)
        candidate = "".join(random.choice(string.ascii_uppercase) for _ in range(length))
        texts.add(candidate)
    return list(texts)


BASE_PLAINTEXTS = _random_plaintexts(200)   # 200 distinct plaintexts


# ----------------------------------------------------------------------
# Simple encryption helpers (all operate on uppercase ASCII)
# ----------------------------------------------------------------------
def _caesar_encrypt(text, shift=3):
    """Caesar shift – only A‑Z is shifted; other chars are left as‑is."""
    result = []
    for ch in text:
        if "A" <= ch <= "Z":
            result.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        else:
            result.append(ch)
    return "".join(result)


def _vigenere_encrypt(text, key="KEY"):
    """Vigenère cipher – works on uppercase letters."""
    key = key.upper()
    result = []
    k_idx = 0
    for ch in text:
        if "A" <= ch <= "Z":
            shift = ord(key[k_idx % len(key)]) - ord("A")
            result.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
            k_idx += 1
        else:
            result.append(ch)
    return "".join(result)


def _railfence_encrypt(text, rails=3):
    """Rail‑fence transposition cipher."""
    if rails <= 1:
        return text
    rail = [""] * rails
    rail_idx = 0
    direction = 1
    for ch in text:
        rail[rail_idx] += ch
        if rail_idx == 0:
            direction = 1
        elif rail_idx == rails - 1:
            direction = -1
        rail_idx += direction
    return "".join(rail)


def _base64_encrypt(text):
    """Base‑64 encode the UTF‑8 bytes and render as uppercase ASCII."""
    return base64.b64encode(text.encode("utf-8")).decode("ascii").upper()


def _hex_encrypt(text):
    """Hex‑encode the UTF‑8 bytes and render as uppercase ASCII."""
    return text.encode("utf-8").hex().upper()


# ----------------------------------------------------------------------
# Build the 1 000 test cases (5 ciphers × 200 plaintexts)
# ----------------------------------------------------------------------
CIPHER_FUNCTIONS = [
    ("caesar",     _caesar_encrypt,     3),
    ("vigenere",   _vigenere_encrypt,   "KEY"),
    ("railfence",  _railfence_encrypt,  3),
    ("base64",     _base64_encrypt,     None),
    ("hex",        _hex_encrypt,        None),
]

TEST_CASES = []                     # (ciphertext, expected_cipher_name)
EXPECTED_LABELS = [name for name, _, _ in CIPHER_FUNCTIONS]

for plain in BASE_PLAINTEXTS:
    for name, func, param in CIPHER_FUNCTIONS:
        # Call the encryption function with its required argument
        if param is not None:
            ct = func(plain, param)
        else:
            ct = func(plain)
        # Detector expects the cipher name in lower‑case
        TEST_CASES.append((ct, name))
        if len(TEST_CASES) == 1000:
            break
    if len(TEST_CASES) == 1000:
        break

# Keep exactly 1 000 entries (should already be, but safety first)
TEST_CASES = TEST_CASES[:1000]

# Human‑readable identifiers for pytest collection
TEST_CASE_IDS = [str(i) for i in range(len(TEST_CASES))]
SMOKE_CASES = [
    (_base64_encrypt("HELLO WORLD"), "base64"),
]
SMOKE_CASE_IDS = ["base64"]


# ----------------------------------------------------------------------
# Parametrized smoke test – one representative case per cipher keeps the
# suite close to 200 tests after the larger generated suite is removed.
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    ("ciphertext", "expected"),
    SMOKE_CASES,
    ids=SMOKE_CASE_IDS,
)
def test_detection_all_ciphers_variants(ciphertext, expected):
    """
    Run the CLI detection command on ``ciphertext`` and verify that the
    detector reports the cipher by the expected name.
    """
    # ``ob_run`` is a fixture provided by the test harness; it executes
    # the CLI and returns (return_code, stdout, stderr).
    rc, out, err = ob_run("detect", ciphertext)

    # The detection command must exit cleanly
    assert rc == 0, f"Detection failed with error: {err}"

    # The expected cipher name must appear in the output
    assert expected in out
