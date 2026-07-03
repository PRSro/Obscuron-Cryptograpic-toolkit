"""Obscuron Crypto Suite — C++ accelerated cipher library.

Provides Python bindings to all cipher and encoding functions,
plus a pure-Python FileDetector class for CTF file analysis.
"""

from _obscuron_core import *
import os
import re
import json
import base64 as _b64

__all__ = [
    # basic_ciphers
    "split", "parser", "reverser", "deconvert_pair",
    "base_convert", "base_deconvert",
    "custom_rot", "rot13", "a1z26", "keyboard_shift",
    # historical_ciphers
    "atbash", "caesar",
    "vigenere", "autokey", "beaufort",
    "railfence", "scytale_encrypt", "scytale_decrypt",
    "polybius_encrypt", "polybius_decrypt",
    "columnar_encrypt", "columnar_decrypt",
    "playfair", "bifid_encrypt", "bifid_decrypt", "build_bifid_grid",
    "trifid", "four_square", "adfgvx", "bacon",
    "porta", "gronsfeld", "hill_encrypt", "hill_decrypt",
    "nihilist_encrypt", "nihilist_decrypt",
    "morse_encode", "morse_decode",
    "braille_to_dots", "braille_print_dots",
    "simple_dots_to_braille", "braille_to_simple_dots",
    "braille_encode", "braille_decode",
    # essential_ciphers
    "raw_bytes_print",
    "large_encrypt", "large_decrypt",
    "hex_xor", "str_xor", "urlcode",
    "codepoint_to_utf8", "utf8_to_codepoint",
    "rot8000_cp", "rot8000",
    "octal", "binary",
    # bytes
    "little_endian_encode", "big_endian_encode",
    "little_endian_decode", "big_endian_decode",
    "proper_base_convert",
    # standard_ciphers
    "rot47", "keyword_cipher",
    "substitution_encrypt", "substitution_decrypt",
    "frequency_analysis", "substitution_solve",
    "index_of_coincidence", "find_key_lengths",
    # outdated_ciphers
    "rc4", "des_ecb", "des3_ecb",
    "blowfish_ecb", "vigenere_autokey_broken", "enigma",
    # bruteforce_ciphers
    "brute_rotate", "brute_rot_all",
    "brute_caesar_all", "brute_railfence_all",
    "brute_xor_single_byte", "brute_vigenere_keylength",
    # modern_ciphers (hashes)
    "md5_hash", "sha1_hash", "sha256_hash", "sha384_hash", "sha512_hash",
    "sha3_224_hash", "sha3_256_hash", "sha3_384_hash", "sha3_512_hash",
    "shake128_hash", "shake256_hash",
    "blake2b_hash", "blake2s_hash",
    "hmac_sha256", "hmac_sha512",
    # modern_ciphers (symmetric)
    "aes_encrypt", "aes_decrypt",
    "chacha20_crypt", "poly1305_mac",
    # modern_ciphers (KDF)
    "pbkdf2_sha256", "argon2id_hash",
    "bcrypt_hash", "scrypt_hash",
    # modern_ciphers (JWT, QR, stego)
    "jwt_sign", "jwt_parse",
    "generate_qr_matrix",
    "lsb_embed", "lsb_extract",
    # encoding helpers
    "hex_decode_str",
    "base64_encode", "base64_decode",
    "base64url_encode", "base64url_decode",
    # detector
    "score_english", "compute_entropy", "compute_ioc",
    "sniff_encoding", "detect_cipher",
    # FileDetector
    "FileDetector",
]


class FileDetector:
    """Pure-Python detector for identifying cryptographic schemes in files and data.

    Accepts a file path or raw bytes and runs multiple detection heuristics.
    """

    def __init__(self, data):
        if isinstance(data, str) and os.path.exists(data):
            with open(data, 'rb') as f:
                self._raw = f.read()
            self._text = self._raw.decode('utf-8', errors='replace')
            self._is_file = True
        else:
            if isinstance(data, str):
                self._raw = data.encode('utf-8', errors='replace')
                self._text = data
            else:
                self._raw = data
                self._text = data.decode('utf-8', errors='replace')
            self._is_file = False

    def detect(self, top_n=5):
        results = []

        checks = [
            ('hash', self.detect_hash),
            ('jwt', self.detect_jwt),
            ('encoding', self.detect_encoding),
            ('pgp', self.detect_pgp),
            ('rsa', self.detect_rsa),
            ('aes', self.detect_aes),
        ]

        for scheme, method in checks:
            try:
                r = method()
                if r is not None:
                    r['scheme'] = scheme
                    r['suggested_command'] = self.suggested_command(
                        r.get('type', r.get('encoding', scheme))
                    )
                    results.append(r)
            except Exception:
                pass

        seen = set()
        unique = []
        for r in results:
            key = r.get('type', r.get('encoding', r['scheme']))
            if key not in seen:
                seen.add(key)
                unique.append(r)

        unique.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        return unique[:top_n]

    def detect_rsa(self):
        text = self._text
        if '-----BEGIN RSA PRIVATE KEY-----' in text:
            return {'type': 'rsa_private_key', 'details': 'PEM RSA private key', 'confidence': 0.95}
        if '-----BEGIN PRIVATE KEY-----' in text:
            return {'type': 'rsa_private_key', 'details': 'PEM PKCS#8 private key', 'confidence': 0.90}
        if '-----BEGIN RSA PUBLIC KEY-----' in text:
            return {'type': 'rsa_public_key', 'details': 'PEM RSA public key', 'confidence': 0.95}
        if '-----BEGIN PUBLIC KEY-----' in text:
            return {'type': 'rsa_public_key', 'details': 'PEM X.509 public key', 'confidence': 0.90}
        n = len(self._raw)
        bits_map = {128: 1024, 256: 2048, 384: 3072, 512: 4096}
        if n in bits_map and any(b > 0x7F for b in self._raw[:10]):
            return {'type': 'rsa_ciphertext', 'bits': bits_map[n],
                    'details': f'{bits_map[n]}-bit RSA modulus', 'confidence': 0.60}
        return None

    def detect_aes(self):
        n = len(self._raw)
        if n < 16 or n % 16 != 0:
            return None
        try:
            ent = compute_entropy(self._raw if any(b > 127 for b in self._raw) else self._text)
        except Exception:
            ent = 0.0
        blocks = [self._raw[i:i+16] for i in range(0, n, 16)]
        reps = len(blocks) - len(set(blocks))
        if reps > 0 and ent > 6.0:
            return {'type': 'aes_ecb', 'block_size': 16, 'entropy': ent,
                    'ecb_block_repetition': reps, 'confidence': 0.70}
        if ent > 7.0:
            return {'type': 'aes_cbc_ctr', 'block_size': 16, 'entropy': ent,
                    'ecb_block_repetition': 0, 'confidence': 0.50}
        return None

    def detect_pgp(self):
        text = self._text
        if '-----BEGIN PGP MESSAGE-----' in text:
            return {'type': 'pgp_message', 'details': 'PGP encrypted message', 'confidence': 0.90}
        if '-----BEGIN PGP PUBLIC KEY BLOCK-----' in text:
            return {'type': 'pgp_public_key', 'details': 'PGP public key block', 'confidence': 0.90}
        if '-----BEGIN PGP PRIVATE KEY BLOCK-----' in text:
            return {'type': 'pgp_private_key', 'details': 'PGP private key block', 'confidence': 0.90}
        if len(self._raw) > 2 and self._raw[0] in (0x85, 0x84, 0x94, 0x95):
            return {'type': 'pgp_binary', 'details': 'Binary PGP packet data', 'confidence': 0.70}
        return None

    def detect_jwt(self):
        text = self._text.strip()
        parts = text.split('.')
        if len(parts) != 3 or not all(parts):
            return None
        try:
            hdr = parts[0]
            pad = 4 - len(hdr) % 4
            if pad == 4:
                pad = 0
            json.loads(_b64.urlsafe_b64decode(hdr + '=' * pad).decode('utf-8'))
            return {'type': 'jwt', 'details': 'JWT token',
                    'header': parts[0], 'payload': parts[1], 'confidence': 0.90}
        except Exception:
            return None

    def detect_hash(self):
        text = self._text.strip()
        if text.startswith('$2b$') or text.startswith('$2a$') or text.startswith('$2y$'):
            return {'type': 'bcrypt', 'details': 'bcrypt hash', 'confidence': 0.90}
        if text.startswith('$argon2id$'):
            return {'type': 'argon2', 'details': 'Argon2id hash', 'confidence': 0.90}
        if text.startswith('$pbkdf2$'):
            return {'type': 'pbkdf2', 'details': 'PBKDF2 hash', 'confidence': 0.90}
        if not re.match(r'^[0-9a-fA-F]+$', text):
            return None
        n = len(text)
        sizes = {32: ('MD5', 0.85), 40: ('SHA1', 0.85), 56: ('SHA224', 0.80),
                 64: ('SHA256', 0.85), 96: ('SHA384', 0.80), 128: ('SHA512', 0.85)}
        if n in sizes:
            name, conf = sizes[n]
            return {'type': name.lower(), 'details': f'{name} hex hash', 'confidence': conf}
        return None

    def detect_encoding(self):
        try:
            enc = sniff_encoding(self._text)
            if enc != 'text':
                return {'encoding': enc, 'confidence': 0.80}
        except Exception:
            pass

        text = self._text.strip()
        clean = text.replace('=', '').replace(' ', '').replace('\n', '')
        if re.match(r'^[A-Z2-7]+$', clean) and len(clean) % 8 <= 2:
            return {'encoding': 'base32', 'confidence': 0.70}
        if re.match(r'^[1-9A-HJ-NP-Za-km-z]+$', text.strip()):
            return {'encoding': 'base58', 'confidence': 0.60}
        if (text.startswith('<~') and text.endswith('~>')) or \
           (text.startswith('~<') and text.endswith('~>')):
            return {'encoding': 'base85', 'confidence': 0.85}
        if text.startswith('begin ') and 'end' in text:
            return {'encoding': 'uuencode', 'confidence': 0.70}

        return None

    @staticmethod
    def suggested_command(scheme):
        cmds = {
            'aes_ecb': 'ob-crypt aes-ecb --decrypt -k <key>',
            'aes_cbc_ctr': 'ob-crypt aes-cbc --decrypt -k <key> -i <iv>',
            'jwt': 'ob-crypt jwt-parse',
            'pgp_message': 'gpg --decrypt',
            'pgp_public_key': 'gpg --import',
            'pgp_private_key': 'gpg --import',
            'pgp_binary': 'gpg --decrypt',
            'rsa_public_key': 'openssl rsa -pubin -in <file> -text',
            'rsa_private_key': 'openssl rsa -in <file> -text',
            'rsa_ciphertext': 'openssl rsautl -decrypt -inkey <key>',
            'md5': 'ob-crypt md5',
            'sha1': 'ob-crypt sha1',
            'sha224': 'ob-crypt sha224',
            'sha256': 'ob-crypt sha256',
            'sha384': 'ob-crypt sha384',
            'sha512': 'ob-crypt sha512',
            'bcrypt': 'hashcat -m 3200',
            'argon2': 'hashcat -m 12800',
            'pbkdf2': 'hashcat -m 10900',
            'hex': 'ob-crypt hex',
            'base64': 'ob-crypt base64',
            'base32': 'ob-crypt base32',
            'base58': 'hashcat -m 17800',
            'base85': 'ob-crypt base85',
            'uuencode': 'uudecode',
        }
        return cmds.get(scheme, f'ob-crypt {scheme}')
