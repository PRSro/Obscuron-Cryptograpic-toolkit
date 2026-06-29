"""Large real-world detector corpus.

The corpus is deterministic and uses readable sentences or CTF-style flags
instead of random uppercase strings, so failures are useful detector signals.
"""

import base64
import urllib.parse

import pytest

from conftest import ob_run


SUBJECTS = [
    "incident response team",
    "forensic analyst",
    "security engineer",
    "malware researcher",
    "red team operator",
    "blue team lead",
    "cryptography student",
    "network defender",
    "threat hunter",
    "reverse engineer",
]

ACTIONS = [
    "reviewed the packet capture after the alert fired",
    "documented the key rotation process before deployment",
    "validated the backup codes during the tabletop exercise",
    "compared the decoded message with the original report",
    "confirmed the access token expired before midnight",
    "mapped the suspicious login to a known phishing campaign",
    "triaged the encrypted note from the compromised laptop",
    "checked the firewall logs for unusual outbound traffic",
    "tested the recovery phrase in an isolated lab environment",
    "wrote a concise summary for the morning handoff",
]

DETAILS = [
    "the evidence stayed consistent across three independent systems",
    "the operator included a timestamp and a case number",
    "the message contained long sentences with ordinary English words",
    "the flag followed the expected competition format",
    "the payload was copied from a realistic support ticket",
    "the team needed a reliable detector result for automation",
    "the sample included punctuation, numbers, and mixed casing",
    "the report emphasized accuracy over speed",
    "the decoded text matched the customer escalation notes",
    "the exercise ended with a clean audit trail",
]

FLAG_PREFIXES = ["flag", "ctf", "obscuron", "crypto", "hunt"]
FLAG_TOPICS = [
    "real_world_detector_case",
    "long_sentence_payload",
    "incident_response_ready",
    "blue_team_validation",
    "cipher_pipeline_checked",
    "forensics_note_recovered",
    "rotation_policy_verified",
    "encoded_report_found",
    "threat_hunter_confirmed",
    "automation_signal_clean",
]


def real_sentence(index):
    subject = SUBJECTS[index % len(SUBJECTS)]
    action = ACTIONS[(index // len(SUBJECTS)) % len(ACTIONS)]
    detail = DETAILS[(index // (len(SUBJECTS) * len(ACTIONS))) % len(DETAILS)]
    return (
        f"Case {index:04d}: The {subject} {action}, and {detail}. "
        f"This long sentence is designed to look like normal operational text."
    )


def flag_value(index):
    prefix = FLAG_PREFIXES[index % len(FLAG_PREFIXES)]
    topic = FLAG_TOPICS[(index // len(FLAG_PREFIXES)) % len(FLAG_TOPICS)]
    return f"{prefix}{{{topic}_{index:04d}}}"


def rot13(text):
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def atbash(text):
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr(ord("z") - (ord(ch) - ord("a"))))
        elif "A" <= ch <= "Z":
            out.append(chr(ord("Z") - (ord(ch) - ord("A"))))
        else:
            out.append(ch)
    return "".join(out)


def caesar(text, shift):
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.",
}


def morse(text):
    words = []
    for word in text.upper().split():
        letters = [MORSE[ch] for ch in word if ch in MORSE]
        if letters:
            words.append(" ".join(letters))
    return " / ".join(words)


def build_cases():
    cases = []

    for i in range(140):
        cases.append(("plaintext", real_sentence(i), "plaintext"))

    for i in range(120):
        cases.append(("ctf_flag", flag_value(i), "ctf-flag"))

    for i in range(140):
        text = real_sentence(i + 200)
        cases.append(("hex", text.encode("utf-8").hex(), "hex"))

    for i in range(140):
        text = real_sentence(i + 400)
        encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
        cases.append(("base64", encoded, "base64"))

    for i in range(100):
        text = real_sentence(i + 600)
        cases.append(("url", urllib.parse.quote(text), "url"))

    for i in range(90):
        text = real_sentence(i + 800)
        cases.append(("rot13", rot13(text), "rot13"))

    for i in range(90):
        text = real_sentence(i + 1000)
        cases.append(("atbash", atbash(text), "atbash"))

    for i in range(90):
        text = real_sentence(i + 1200)
        shift = 3 if i % 2 == 0 else 5
        cases.append(("caesar", caesar(text, shift), "caesar"))

    for i in range(90):
        text = f"security team found flag number {i:04d}"
        cases.append(("morse", morse(text), "morse"))

    assert len(cases) == 1000
    return cases


REALWORLD_CASES = build_cases()


@pytest.mark.parametrize(
    ("family", "ciphertext", "expected"),
    REALWORLD_CASES,
    ids=[f"{family}-{i:04d}" for i, (family, _, _) in enumerate(REALWORLD_CASES)],
)
def test_detector_realworld_1000(family, ciphertext, expected):
    rc, out, err = ob_run("detect", "--top", "5", ciphertext)
    assert rc == 0, f"{family} detector command failed: {err}"
    assert expected in out.lower()
