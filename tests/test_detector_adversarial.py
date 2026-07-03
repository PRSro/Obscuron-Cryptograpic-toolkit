"""50 adversarial detector tests: non-English inputs that should NOT
be misclassified as plaintext — leetspeak flags and hashed flags."""

import hashlib
import base64
import pytest
from conftest import ob_run


def sha256_hex(text):
    return hashlib.sha256(text.encode()).hexdigest()


def build_cases():
    cases = []

    # ── Leetspeak flags (20): flag format with leet substitutions ──
    leet_flags = [
        # Basic leet substitutions
        "flag{th1s_1s_l33t_sp34k_f0r_4_fl4g}",
        "ctf{w3_4r3_l00k1ng_f0r_th3_k3y}",
        "flag{7h3_m3554g3_1s_h1dd3n_1n_7h3_l33t}",
        "kctf{1_c4n7_b3l13v3_y0u_f0und_7h1s}",
        "picoctf{leet_sp33k_d3t3ct0r_ch4ll3ng3}",
        "htb{4d4pt_0r_p3r1sh_1n_7h3_l33t}",
        "thm{d0n7_7ru57_th3_l33t_1t_l135}",
        "obscuron{4n0th3r_d4y_4n0th3r_fl4g}",
        "crypto{l33t_3ncr1pt10n_1s_n0t_s3cur3}",
        "hunt{7h3_l33t_h1d3s_1n_pl41n_s1ght}",

        # Complex leet with symbols and mixed casing
        "flag{_}",
        "ctf{u_kn0w_h0w_7h3_fl4g_l00k5}",
        "kctf{w3_d0_n07_h4v3_4_fl4g_y37}",
        "flag{1f_y0u_d0n7_h4v3_4_fl4g_m4k3_0n3_up}",
        "ctf{n0w_y0u_s33_m3_n0w_y0u_d0n7}",
        "picoctf{7h3_fl4g_15_4_l13}",
        "htb{h0n3y_p0t_0r_l33t_p0t_7h4t_15_7h3_qu35710n}",
        "thm{n3v3r_g0nn4_g1v3_y0u_up_n3v3r_g0nn4_l37_y0u_d0wn}",
        "obscuron{l33t_t3xt_m4k3s_f0r_g00d_fl4gs}",
        "crypto{0n3_5h0r7_fl4g_15_w0r7h_4_7h0u54nd_w0rd5}",

    ]

    for flag_text in leet_flags:
        cases.append(("leet_flag", flag_text, "ctf-flag"))

    # ── Hashed flags (20): SHA-256 of flag strings ──
    raw_flags = [
        "flag{this_is_a_secret_message}",
        "ctf{the_answer_is_forty_two}",
        "flag{hidden_in_plain_sight}",
        "picoctf{never_trust_user_input}",
        "htb{root_the_box_and_own_the_network}",
        "thm{blue_team_detects_everything}",
        "obscuron{detector_perfection_roadmap}",
        "crypto{rsa_weak_key_detected}",
        "hunt{threat_hunting_successful}",
        "flag{quadgram_scoring_for_transpositions}",
        "ctf{systematic_key_generation}",
        "flag{recursive_decode_pipeline}",
        "kctf{identity_noop_penalties}",
        "picoctf{confidence_calibration}",
        "htb{input_profile_and_family_weight}",
        "thm{xor_hex_predecode_fixed}",
        "obscuron{bifid_detection_pass_added}",
        "crypto{scytale_railfence_improved}",
        "hunt{real_world_corpus_1000_tests}",
        "flag{adversarial_inputs_not_plaintext}",
    ]

    for raw_flag in raw_flags:
        hashed = sha256_hex(raw_flag)
        cases.append(("hashed_flag", hashed, "sha256"))

    # ── Base64-encoded flags (10): should NOT be plaintext ──
    b64_flags = [
        "flag{this_is_base64_encoded}",
        "ctf{hidden_in_base64}",
        "flag{we_are_legion}",
        "kctf{decode_or_perish}",
        "picoctf{base64_is_not_encryption}",
        "htb{encode_everything}",
        "thm{looks_like_noise}",
        "obscuron{encoding_is_not_ciphering}",
        "crypto{base64_for_transport_not_security}",
        "hunt{hunters_always_find_the_flag}",
    ]

    for raw_flag in b64_flags:
        encoded = base64.b64encode(raw_flag.encode()).decode()
        cases.append(("b64_flag", encoded, "base64"))

    assert len(cases) == 50, f"Expected 50 cases, got {len(cases)}"
    return cases


ADVERSARIAL_CASES = build_cases()


@pytest.mark.parametrize(
    ("family", "ciphertext", "expected"),
    ADVERSARIAL_CASES,
    ids=[f"{family}-{i:03d}" for i, (family, _, _) in enumerate(ADVERSARIAL_CASES)],
)
def test_detector_adversarial(family, ciphertext, expected):
    rc, out, err = ob_run("detect", "--top", "5", ciphertext)
    assert rc == 0, f"{family} detector command failed: {err}"
    assert expected in out.lower()
