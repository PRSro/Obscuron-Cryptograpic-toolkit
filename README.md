# Obscuron Crypto Suite

A comprehensive cryptographic toolkit in C++17 — CLI automation meets a full-featured Qt6 desktop GUI. Classical ciphers, modern cryptography, encoding schemes, cryptanalysis, brute-force, cipher detection, RSA/EC/TLS attacks, visualizer widgets, and a 3-language plugin system — all in one native binary pair.

> **Status:** Pre-release · Last open-source version

---

## Key Features

- **100+ CLI commands** — pipe-friendly, scriptable, single-binary
- **Drag-and-drop GUI** — recipe workspace with undo/redo, JSON import/export, macro scripts
- **Cipher detector** — multi-layer heuristic detection with branch explorer, key recovery
- **9 Visualizer widgets** — FrequencyHistogram, EntropyHeatmap, ShannonEntropyGraph, EncodingWheel, AutocorrelationGraph, NGramHeatmap, HexDiffViewer, DataMiniMap, BlockCipherModeViz
- **RSA attack suite** — Wiener, Hastad, Common Modulus, Fermat, Pollard, parity oracle
- **Elliptic curve & DLP** — EC arithmetic, BSGS, Pohlig-Hellman, LLL reduction
- **TLS analysis** — handshake fingerprinting, certificate parsing, pcap decryption
- **Plugin system** — C `.so`, Python, JavaScript — all loaded at runtime
- **Script engine** — JavaScript macro scripting with cipher bindings
- **Embedded Python** — CPython 3.14 host for in-process Python plugins
- **AI-assisted solving** — 9 provider integrations, SageMath runner
- **Themes** — Dark, Light, OLED modes with custom accent colours
- **100+ test cases** — Python pytest suite

---

## Architecture

```
Obscuron-Crypto-Suite/
├── CLI/                        # ob-crypt binary (standalone)
│   ├── main.cpp
│   ├── Makefile                # Native build, no Qt required
│   ├── src/                    # CLI-only handler registrations
│   ├── includes/               # Shared cipher headers
│   │   ├── basic_ciphers.h
│   │   ├── modern_ciphers.h
│   │   ├── detector.h
│   │   ├── plugin_api.h        # C ABI plugin interface
│   │   └── ...
│   └── docs/                   # Man page, usage docs
│
├── GUI/                        # Desktop binary
│   ├── Obscuron-Crypto-Suite.pro
│   ├── src/                    # 28 GUI source files
│   ├── include/                # 30 GUI header files
│   ├── plugins/                # C plugin examples
│   └── docs/
│
├── tests/                      # Python pytest suite
│   ├── conftest.py             # ob_run() helpers
│   ├── test_basic.py
│   ├── test_detector.py
│   ├── test_modern.py
│   └── ...
│
├── AGENTS.md
└── LICENSE
```

Both binaries compile a shared cipher core from `CLI/src/` against `CLI/includes/`.

---

## Ciphers & Operations

### Basic Ciphers
| Command | Description |
|---------|-------------|
| `custom-rot` | Rotate letters by arbitrary shift |
| `rot13` | ROT13 |
| `a1z26` | A1Z26 encoding (A=1, B=2, …) |
| `keyboard-shift` | Shift characters on QWERTY layout |

### Historical / Classical
| Command | Description |
|---------|-------------|
| `atbash` | Reverse-alphabet substitution |
| `affine` | Affine cipher `E(x) = (ax + b) mod 26` |
| `caesar` | Caesar shift by key |
| `vigenere` | Vigenère with keyword |
| `autokey` | Autokey cipher |
| `beaufort` | Beaufort cipher |
| `railfence` | Rail Fence transposition (zigzag) |
| `scytale` | Scytale transposition |
| `polybius` | Polybius square |
| `columnar` | Columnar transposition with keyword |
| `playfair` | Playfair digraph substitution |
| `bifid` | Bifid cipher |
| `trifid` | Trifid cipher |
| `four-square` | Four-Square cipher |
| `adfgvx` | ADFGVX cipher |
| `bacon` | Baconian 5-bit encoding |
| `morse` | Morse code encode/decode |
| `braille` | Braille dot-pattern encode/decode |
| `enigma` | Enigma machine simulation |

### Encoding & Essential
| Command | Description |
|---------|-------------|
| `base_encode` / `base_decode` | Big-integer base conversion (2–85) |
| `hex` | Hex string ↔ raw bytes |
| `base64` | Base64 (RFC 4648) |
| `hex-xor` / `str-xor` | XOR against hex byte or string |
| `urlcode` | URL percent-encoding |
| `rot8000` | Unicode-aware rotation |
| `octal` | Octal encoding |
| `binary` | Binary encoding |

### Standard & Cryptanalysis
| Command | Description |
|---------|-------------|
| `rot47` | ROT47 (printable ASCII) |
| `keyword` | Keyword monoalphabetic substitution |
| `substitution` | Arbitrary substitution cipher |
| `substitution-solve` | Auto-solve via frequency analysis |

### Outdated / Weak Ciphers
| Command | Description |
|---------|-------------|
| `rc4` | RC4 stream cipher |
| `des` | DES ECB (56-bit) |
| `des3` | Triple-DES ECB |
| `blowfish` | Blowfish ECB |

### Modern Ciphers & Cryptography
| Command | Description |
|---------|-------------|
| `md5`, `sha1`, `sha256`, `sha512` | Standard hashes |
| `blake2b`, `blake2s` | BLAKE2 keyed/unkeyed hashes |
| `hmac-sha256`, `hmac-sha512` | HMAC |
| `pbkdf2` | PBKDF2 key derivation |
| `argon2id` | Argon2id memory-hard KDF |
| `aes-ecb`, `aes-cbc`, `aes-ctr` | AES (128/192/256-bit) |
| `chacha20` | ChaCha20 stream cipher |
| `salsa20` | Salsa20/20 stream cipher |
| `poly1305` | Poly1305 authenticator |
| `xor` | XOR with repeating hex key |
| `jwt-parse`, `jwt-sign` | JWT handling |
| `qr` | QR code ASCII art |
| `lsb-embed`, `lsb-extract` | LSB steganography |

### RSA & Public-Key Attacks
| Command | Description |
|---------|-------------|
| `rsa-encode`, `rsa-decrypt` | RSA encrypt/decrypt with CRT |
| `rsa-info` | Key analysis (bit size, Wiener feasibility) |
| `rsa-wiener` | Wiener's continued-fraction attack |
| `rsa-hastad` | Hastad's broadcast attack |
| `rsa-common-modulus` | Common modulus attack |
| `rsa-factor-fermat` | Fermat factorization |
| `rsa-factor-pollard` | Pollard's Rho |
| `rsa-parity-oracle` | Bleichenbacher LSB oracle |

### Elliptic Curve & Discrete Log
| Command | Description |
|---------|-------------|
| `ec-add` | EC point addition |
| `ec-mul` | EC scalar multiplication |
| `dlp-bsgs` | Baby-step giant-step DLP |
| `dlp-pohlig` | Pohlig-Hellman DLP |
| `lll` | LLL lattice reduction |
| `dh-check` | DH weak-parameter check |

### Attack Modules (CTF)
| Command | Description |
|---------|-------------|
| `ecb-detect` | AES-ECB block-repeat detection |
| `cbc-padding-oracle` | CBC padding oracle attack |
| `hash-extend` | Hash length extension |
| `ecdsa-nonce-reuse` | ECDSA nonce reuse → key recovery |
| `zip-crack` | ZipCrypto known-plaintext attack |
| `shamir-reconstruct` | Shamir's secret reconstruction |
| `gf256-mul`, `gf256-inv` | GF(2⁸) arithmetic |

### TLS Utilities
| Command | Description |
|---------|-------------|
| `tls-fingerprint` | Handshake fingerprinting |
| `parse-cert` | X.509 certificate parsing |

### Brute-Force Tools
| Command | Description |
|---------|-------------|
| `brute-rotate` | All 26 ROT variations |
| `brute-caesar` | All 25 Caesar shifts |
| `brute-railfence` | Rail Fence up to N rails |
| `brute-xor` | All 256 single-byte XOR keys |
| `brute-vigenere` | Vigenère key search |

### Detection & Analysis
| Command | Description |
|---------|-------------|
| `detect [--top N] [--solve]` | Automatic cipher detection with branch explorer |
| `analyze` | Statistical analysis (entropy, IoC, byte distribution) |
| `chain --steps <s1,s2,…>` | Multi-step pipeline with optional auto-detect |

### Byte Utilities
| Command | Description |
|---------|-------------|
| `little-endian`, `big-endian` | Integer-to-N-byte endian encoding |
| `proper-base` | Chunk-oriented base encoding |

---

## CLI Usage

```
Usage: ob-crypt [options] <cipher> [input] [parameters]

Global options:
  --raw                     Machine-readable output (no labels)
  --hex-input               Decode input from hex before processing
  --hex-output              Encode output as hex
  -f <file>                 Read input from file
  -                         Read input from stdin

Modes:
  ob-crypt [--list]         List all ciphers
  ob-crypt [--help|-h]      Show help
  ob-crypt detect [--top N] <input>   Detect cipher
  ob-crypt analyze <input>            Statistical analysis
  ob-crypt chain --steps <s1,s2,…>    Multi-step pipeline
```

### CLI Examples

```bash
# Caesar encrypt (shift 7)
echo "hello world" | ./ob-crypt caesar -s 7

# Vigenère decrypt
./ob-crypt vigenere -k secret --decrypt "olssv dvysk"

# Automatic cipher detection
./ob-crypt detect "uryyb jbeyq"

# Multi-step: base64 → hex
./ob-crypt chain --steps "base64,hex" "SGVsbG8="

# Brute-force single-byte XOR
./ob-crypt brute-xor < cipher.bin

# All commands
./ob-crypt --list
```

### Input Sources

1. **Inline:** `./ob-crypt caesar "hello"`
2. **File:** `./ob-crypt caesar -f input.txt`
3. **Stdin:** `echo "hello" | ./ob-crypt caesar -` or pipe without arg
4. **Hex:** `./ob-crypt --hex-input caesar "68656c6c6f"`

---

## GUI Features

### Recipe Workspace
- Drag-and-drop operation pipeline with undo/redo
- Input/output panels, reorderable step list
- Import/export recipes as JSON or macro scripts
- Async execution via QThread with real-time output

### Solve Window
- SageMath / Python runner with live output
- AI-assisted cryptanalysis (9 providers)
- CTF panel for quick challenge solving

### Plugin System
- **C .so** — native shared libraries via `dlopen`
- **Python .py** — embedded CPython 3.14, direct `import obscuron`
- **JavaScript .js** — QJSEngine sandbox with `crypto.*` bridge
- Auto-scanned from `~/.obscuron/plugins/`

### Visualizer Widgets
| Widget | Purpose |
|--------|---------|
| Frequency Histogram | Letter frequency vs English |
| Entropy Heatmap | Per-block byte randomness |
| Shannon Entropy Graph | Rolling entropy over sliding window |
| Encoding Wheel | Binary/octal/decimal/hex/base64 |
| Autocorrelation Graph | Periodicity detection |
| NGram Heatmap | N-gram frequency matrix |
| HexDiff Viewer | Side-by-side hex comparison |
| Data MiniMap | Full-input byte overview |
| Block Cipher Mode Viz | ECB/CBC/CTR mode animation |

### Advanced Dialogs
- AES / ChaCha20 / AES-GCM parameter configuration
- RSA attack dialog (Wiener, Hastad, Fermat, Pollard, parity oracle)
- TLS fingerprinting, certificate parsing, pcap decryption
- Number conversion (base arithmetic, big integers)
- Settings: theme, font, display, performance

### Themes
Dark (default), Light, OLED — with custom accent colour picker.

---

## Building

### Prerequisites

| Dependency | CLI | GUI |
|------------|-----|-----|
| C++17 compiler (g++ ≥ 8 / clang ≥ 7) | Required | Required |
| NTL (Number Theory Library) | Optional | Required |
| Qt 6 (Widgets + QML modules) | — | Required |
| libsodium | Optional¹ | — |

¹ Linked but unused in current builds.

Debian/Ubuntu:
```bash
sudo apt install build-essential libntl-dev qt6-base-dev
```

Arch:
```bash
sudo pacman -S base-devel ntl qt6-base
```

### Build CLI
```bash
cd CLI && make -j4
```
Produces `CLI/ob-crypt`.

### Build GUI
```bash
cd GUI && qmake6 && make -j4
```
Produces `GUI/Obscuron-Crypto-Suite`.

### Run Tests
```bash
cd tests && python -m pytest
```
(Requires CLI binary built first.)

---

## Dependencies

- **NTL** (LGPL v2.1+) — number theory; required for RSA/EC/DLP operations and dialogs
- **Qt 6** (LGPL v3) — widgets, QML, script engine; GUI only
- **CPython 3.14** (PSF) — embedded plugin host; GUI only
- All cipher implementations (AES, ChaCha20, BLAKE2, MD5, SHA, RC4, DES, Blowfish, Poly1305, Argon2id) are **custom C++** — no OpenSSL/libcrypto dependency.

---

## License

MIT — see `LICENSE`.

Copyright © 2026 PRS.
