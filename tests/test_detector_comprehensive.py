"""Comprehensive cipher detector tests (50 test cases).

Format: ciphertext → expected cipher name(s)
All plaintexts are English. Medium length (~20–60 chars).
"""

from conftest import ob_run
import pytest


def detect_matches(ct, *expected):
    """Run detect on ciphertext, return True if any expected name appears."""
    rc, out, err = ob_run("detect", ct)
    if rc != 0:
        return False, f"return code {rc}: {err}"
    out_lower = out.lower()
    for name in expected:
        if name.lower() in out_lower:
            return True, out
    return False, out


# ── Caesar ──

def test_caesar_shift3():
    ct = "wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj"
    ok, out = detect_matches(ct, "caesar")
    assert ok, f"Expected caesar in:\n{out}"


def test_caesar_shift7():
    ct = "hss aoha nspaalyz pz uva nvsk"
    ok, out = detect_matches(ct, "caesar")
    assert ok, f"Expected caesar in:\n{out}"


def test_caesar_shift13():
    ct = "gb or be abg gb be gung vf gur dhrfgvba"
    # shift 13 = rot13; accept either
    ok, out = detect_matches(ct, "caesar", "rot13")
    assert ok, f"Expected caesar/rot13 in:\n{out}"


def test_caesar_shift19():
    ct = "tld ghm patm rhnk vhngmkr vtg wh yhk rhn"
    ok, out = detect_matches(ct, "caesar")
    assert ok, f"Expected caesar in:\n{out}"


def test_caesar_shift1():
    ct = "uif pomz uijoh xf ibwf up gfbs jt gfbs jutfmg"
    ok, out = detect_matches(ct, "caesar")
    assert ok, f"Expected caesar in:\n{out}"


# ── ROT13 ──

def test_rot13_basic():
    ct = "ryrzragnel zl qrne jngfba gur tnzr vf nsbbg"
    ok, out = detect_matches(ct, "rot13")
    assert ok, f"Expected rot13 in:\n{out}"


def test_rot13_scores():
    ct = "sbhe fpber naq frira lrnef ntb bhe snguref"
    ok, out = detect_matches(ct, "rot13")
    assert ok, f"Expected rot13 in:\n{out}"


# ── ROT47 ──

def test_rot47_basic():
    ct = "E96 D64C6E >6DD286 :D 9:556? C:89E 96C6"
    ok, out = detect_matches(ct, "rot47")
    assert ok, f"Expected rot47 in:\n{out}"


# ── Atbash ──

def test_atbash_basic():
    ct = "gsv jfrxp yildm ulc qfnkh levi gsv ozab wlt"
    ok, out = detect_matches(ct, "atbash")
    assert ok, f"Expected atbash in:\n{out}"


def test_atbash_phrase():
    ct = "rm gsv yvtrmmrmt dzh gsv dliw zmw gsv dliw dzh"
    ok, out = detect_matches(ct, "atbash")
    assert ok, f"Expected atbash in:\n{out}"


# ── Vigenere ──

def test_vigenere_key_key():
    ct = "dlc aygmo zbsux jmh nswtq yzcb xfo pyjc byk"
    ok, out = detect_matches(ct, "vigenere")
    assert ok, f"Expected vigenere in:\n{out}"


def test_vigenere_crypto():
    ct = "ccj iaov xjxmhgiq xl bqk eder"
    ok, out = detect_matches(ct, "vigenere")
    assert ok, f"Expected vigenere in:\n{out}"


def test_vigenere_secret():
    ct = "swm esm olck chmv efyglva teg vs hfv rgy"
    ok, out = detect_matches(ct, "vigenere")
    assert ok, f"Expected vigenere in:\n{out}"


def test_vigenere_flag():
    ct = "yse uswy zmtnm bp hgap tu kpax nd fkfc izxpll"
    ok, out = detect_matches(ct, "vigenere")
    assert ok, f"Expected vigenere in:\n{out}"


def test_vigenere_lemon():
    ct = "hi tcyo xtsfp xdigsw fc op wqzs pzurryx"
    ok, out = detect_matches(ct, "vigenere")
    assert ok, f"Expected vigenere in:\n{out}"


# ── Affine ──

def test_affine_5_8():
    ct = "ZRC KEWSG NPAOV HAT BEQFU AJCP ZRC LIDY XAM"
    ok, out = detect_matches(ct, "affine")
    assert ok, f"Expected affine in:\n{out}"


def test_affine_7_3():
    ct = "DCC GADG TCHGGFSZ HZ QXG TXCY"
    ok, out = detect_matches(ct, "affine")
    assert ok, f"Expected affine in:\n{out}"


def test_affine_3_11():
    ct = "QB OX BK YBQ QB OX QGLQ JN QGX HTXNQJBY"
    ok, out = detect_matches(ct, "affine")
    assert ok, f"Expected affine in:\n{out}"


# ── A1Z26 ──

def test_a1z26_phrase():
    ct = "20 8 5   19 5 3 18 5 20   13 5 19 19 1 7 5   9"
    ok, out = detect_matches(ct, "a1z26")
    assert ok, f"Expected a1z26 in:\n{out}"


def test_a1z26_word():
    ct = "20 8 5 3 1 20 19 1 20 15 14 20 8 5 13 1 20"
    ok, out = detect_matches(ct, "a1z26")
    assert ok, f"Expected a1z26 in:\n{out}"


# ── Hex ──

def test_hex_phrase():
    ct = "74686520717569636b2062726f776e20666f78206a756d7073206f766572"
    ok, out = detect_matches(ct, "hex")
    assert ok, f"Expected hex in:\n{out}"


def test_hex_message():
    ct = "746865206d6573736167652069732068696464656e2068657265"
    ok, out = detect_matches(ct, "hex")
    assert ok, f"Expected hex in:\n{out}"


# ── Base64 ──

def test_base64_phrase():
    ct = "dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw=="
    ok, out = detect_matches(ct, "base64")
    assert ok, f"Expected base64 in:\n{out}"


def test_base64_element():
    ct = "ZWxlbWVudGFyeSBteSBkZWFyIHdhdHNvbiB0aGUgZ2FtZSBpcyBhZm9vdA=="
    ok, out = detect_matches(ct, "base64")
    assert ok, f"Expected base64 in:\n{out}"


def test_base64_truths():
    ct = "d2UgaG9sZCB0aGVzZSB0cnV0aHMgdG8gYmUgc2VsZiBldmlkZW50"
    ok, out = detect_matches(ct, "base64")
    assert ok, f"Expected base64 in:\n{out}"


# ── Binary ──

def test_binary_hello():
    ct = "01101000 01100101 01101100 01101100 01101111 00100000 01110111 01101111 01110010 01101100 01100100"
    ok, out = detect_matches(ct, "binary")
    assert ok, f"Expected binary in:\n{out}"


def test_binary_secret():
    ct = "01110011 01100101 01100011 01110010 01100101 01110100"
    ok, out = detect_matches(ct, "binary")
    assert ok, f"Expected binary in:\n{out}"


# ── Octal ──

def test_octal_message():
    ct = "164 150 145 40 155 145 163 163 141 147 145"
    ok, out = detect_matches(ct, "octal")
    assert ok, f"Expected octal in:\n{out}"


def test_octal_world():
    ct = "150 145 154 154 157 40 167 157 162 154 144"
    ok, out = detect_matches(ct, "octal")
    assert ok, f"Expected octal in:\n{out}"


# ── Morse ──

def test_morse_quick_brown():
    ct = "- .... . / --.- ..- .. -.-. -.- / -... .-. --- .-- -. / ..-. --- -..-"
    ok, out = detect_matches(ct, "morse")
    assert ok, f"Expected morse in:\n{out}"


def test_morse_attack():
    ct = ".- - - .- -.-. -.- / .- - / -.. .- .-- -."
    ok, out = detect_matches(ct, "morse")
    assert ok, f"Expected morse in:\n{out}"


def test_morse_hello():
    ct = ".... . .-.. .-.. --- / .-- --- .-. .-.. -.."
    ok, out = detect_matches(ct, "morse")
    assert ok, f"Expected morse in:\n{out}"


# ── Rail Fence ──

def test_railfence_3rails():
    ct = "tubnjsrldhqikrwfxupoeteayoecoomvhzg"
    ok, out = detect_matches(ct, "railfence")
    assert ok, f"Expected railfence in:\n{out}"


def test_railfence_are_discovered():
    ct = "wecruoerdsoeerntneaivdac"
    ok, out = detect_matches(ct, "railfence")
    assert ok, f"Expected railfence in:\n{out}"


def test_railfence_4rails():
    ct = "ateolagtrntdlhltssgltiio"
    ok, out = detect_matches(ct, "railfence")
    assert ok, f"Expected railfence in:\n{out}"


# ── Columnar Transposition ──

def test_columnar_zebra():
    ct = "UROPEKNUHCWJQBFMTIOX"
    ok, out = detect_matches(ct, "columnar")
    assert ok, f"Expected columnar in:\n{out}"


def test_columnar_cat():
    ct = "HUKOFXTQCRNXEIBWOX"
    ok, out = detect_matches(ct, "columnar")
    assert ok, f"Expected columnar in:\n{out}"


# ── Bacon ──

def test_bacon_hello_world():
    ct = "AABBB AABAA ABABB ABABB ABBBA BABBA ABBBA BAAAB ABABB AAABB"
    ok, out = detect_matches(ct, "bacon")
    assert ok, f"Expected bacon in:\n{out}"


def test_bacon_secret():
    ct = "BAABA AABAA AAABA BAAAB AABAA BAABB"
    ok, out = detect_matches(ct, "bacon")
    assert ok, f"Expected bacon in:\n{out}"


# ── XOR Single-Byte ──

def test_xor_key42():
    ct = "5e424f0a5b5f4349410a4858455d440a4c45520a405f475a59"
    ok, out = detect_matches(ct, "xor")
    assert ok, f"Expected xor in:\n{out}"


def test_xor_key55():
    ct = "213d30752630362730217538302626343230753d302730"
    ok, out = detect_matches(ct, "xor")
    assert ok, f"Expected xor in:\n{out}"


# ── Keyword Cipher ──

def test_keyword_secret():
    ct = "qdfp fp s ptcotq jtppsbt qdsq jupq et dfrrtk aolj tvtoylkt"
    ok, out = detect_matches(ct, "keyword")
    assert ok, f"Expected keyword in:\n{out}"


def test_keyword_crypto():
    ct = "CGG QBCQ AGQQQTMN DN IJQ AJGP"
    ok, out = detect_matches(ct, "keyword")
    assert ok, f"Expected keyword in:\n{out}"


# ── Beaufort ──

def test_beaufort_key():
    ct = "RXU UKQIU XTQCX ZKN VEYPG WJUT LRG TYLG VWY"
    ok, out = detect_matches(ct, "beaufort")
    assert ok, f"Expected beaufort in:\n{out}"


def test_beaufort_navy():
    ct = "UM UU ZJ IKU HH XJ HOYU SD FGW FEJICQZN"
    ok, out = detect_matches(ct, "beaufort")
    assert ok, f"Expected beaufort in:\n{out}"


# ── URL Encoded ──

def test_url_quick_brown():
    ct = "the%20quick%20brown%20fox%20jumps%20over%20the%20lazy%20dog"
    ok, out = detect_matches(ct, "url")
    assert ok, f"Expected url in:\n{out}"


def test_url_hello():
    ct = "hello%20world%20this%20is%20a%20url%20encoded%20message"
    ok, out = detect_matches(ct, "url")
    assert ok, f"Expected url in:\n{out}"


# ── Base32 ──

def test_base32_long():
    ct = "ORUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DTEBXXMZLSEB2GQZJANRQXU6JAMRXWO==="
    ok, out = detect_matches(ct, "base32")
    assert ok, f"Expected base32 in:\n{out}"


# ── Polybius Square ──

def test_polybius_message():
    ct = "44 23 15 32 15 43 43 11 22 15 24 43 23 24 14 14 15 33"
    ok, out = detect_matches(ct, "polybius")
    assert ok, f"Expected polybius in:\n{out}"


# ── Base64URL (URL-safe variant) ──

def test_base64url_hidden():
    ct = "dGhlIGhpZGRlbiBzZWNyZXQgbWVzc2FnZSByaWdodCBoZXJl"
    ok, out = detect_matches(ct, "base64")
    assert ok, f"Expected base64 in:\n{out}"
