#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
namespace py = pybind11;

#include "../includes/basic_ciphers.h"
#include "../includes/historical_ciphers.h"
#include "../includes/essential_ciphers.h"
#include "../includes/bytes.h"
#include "../includes/standard_ciphers.h"
#include "../includes/outdated_ciphers.h"
#include "../includes/bruteforce_ciphers.h"
#include "../includes/modern_ciphers.h"
#include "../includes/detector.h"
#include "../includes/context.h"

PYBIND11_MODULE(_obscuron_core, m) {
    m.doc() = "Obscuron Crypto Suite — C++ accelerated cipher library";

    // ── basic_ciphers ──

    m.def("split", [](const std::string &a) {
        std::string out; split(a, out); return out;
    });
    m.def("parser", [](const std::string &a) {
        std::string out; parser(a, out); return out;
    });
    m.def("reverser", [](const std::string &a) {
        std::string out; reverser(a, out); return out;
    });
    m.def("deconvert_pair", &deconvert_pair);
    m.def("base_convert", [](long long b, int base) {
        std::string out; base_convert(b, out, base); return out;
    });
    m.def("base_deconvert", [](const std::string &a, int base) {
        long long b; base_deconvert(a, b, base); return b;
    });
    m.def("custom_rot", [](const std::string &a, int add) {
        std::string out; custom_rot(a, add, out); return out;
    }, py::arg("text"), py::arg("shift"));
    m.def("rot13", [](const std::string &a) {
        std::string out; rot13(a, out); return out;
    });
    m.def("a1z26", [](const std::string &a, char sep) {
        std::string out; a1z26(a, out, sep); return out;
    }, py::arg("text"), py::arg("sep") = '-');
    m.def("keyboard_shift", [](const std::string &a, int dx, int dy, bool encrypt) {
        std::string out; keyboard_shift(a, out, dx, dy, encrypt); return out;
    }, py::arg("text"), py::arg("dx"), py::arg("dy") = 0, py::arg("encrypt") = true);

    // ── historical_ciphers ──

    m.def("atbash", [](const std::string &a) {
        std::string out; atbash(a, out); return out;
    });
    m.def("caesar", [](const std::string &a) {
        std::string out; caesar(a, out); return out;
    });
    m.def("vigenere", [](const std::string &a, const std::string &key, bool encrypt) {
        std::string out; vigenere(a, key, out, encrypt); return out;
    }, py::arg("text"), py::arg("key"), py::arg("encrypt") = true);
    m.def("autokey", [](const std::string &a, const std::string &key, bool encrypt) {
        std::string out; autokey(a, key, out, encrypt); return out;
    }, py::arg("text"), py::arg("key"), py::arg("encrypt") = true);
    m.def("beaufort", [](const std::string &a, const std::string &key) {
        std::string out; beaufort(a, key, out); return out;
    });
    m.def("railfence", [](const std::string &a, int key, int offset) {
        std::string out; railfence(a, out, key, offset); return out;
    }, py::arg("text"), py::arg("key"), py::arg("offset") = 0);
    m.def("scytale_encrypt", [](const std::string &a, int m) {
        std::string out; scytale_encrypt(a, out, m); return out;
    });
    m.def("scytale_decrypt", [](const std::string &a, int m) {
        std::string out; scytale_decrypt(a, out, m); return out;
    });
    m.def("polybius_encrypt", [](const std::string &alphabet, const std::string &a) {
        std::string out; polybius_encrypt(alphabet, a, out); return out;
    }, py::arg("alphabet"), py::arg("text"));
    m.def("polybius_decrypt", [](const std::string &alphabet, const std::string &a) {
        std::string out; polybius_decrypt(alphabet, a, out); return out;
    }, py::arg("alphabet"), py::arg("text"));
    m.def("columnar_encrypt", [](const std::string &a, const std::string &key) {
        std::string out; columnar_encrypt(a, out, key); return out;
    });
    m.def("columnar_decrypt", [](const std::string &a, const std::string &key, int original_len) {
        std::string out; columnar_decrypt(a, out, key, original_len); return out;
    }, py::arg("text"), py::arg("key"), py::arg("original_len"));
    m.def("playfair", [](const std::string &a, const std::string &key, bool encrypt) {
        std::string out; playfair(a, out, key, encrypt); return out;
    }, py::arg("text"), py::arg("key"), py::arg("encrypt") = true);

    m.def("bifid_encrypt", [](const std::string &msg, py::list rows) {
        if (py::len(rows) != 5)
            throw std::runtime_error("bifid needs exactly 5 rows of 6 chars");
        std::string r[5];
        for (int i = 0; i < 5; i++) r[i] = rows[i].cast<std::string>();
        char grid[6][6]; int row_of[256], col_of[256];
        build_bifid_grid(r, grid, row_of, col_of);
        std::string out; bifid_encrypt(msg, out, grid, row_of, col_of); return out;
    });
    m.def("bifid_decrypt", [](const std::string &msg, py::list rows) {
        if (py::len(rows) != 5)
            throw std::runtime_error("bifid needs exactly 5 rows of 6 chars");
        std::string r[5];
        for (int i = 0; i < 5; i++) r[i] = rows[i].cast<std::string>();
        char grid[6][6]; int row_of[256], col_of[256];
        build_bifid_grid(r, grid, row_of, col_of);
        std::string out; bifid_decrypt(msg, out, grid, row_of, col_of); return out;
    });
    m.def("build_bifid_grid", [](py::list rows) {
        if (py::len(rows) != 5)
            throw std::runtime_error("bifid needs exactly 5 rows of 6 chars");
        std::string r[5];
        for (int i = 0; i < 5; i++) r[i] = rows[i].cast<std::string>();
        char grid[6][6]; int row_of[256], col_of[256];
        build_bifid_grid(r, grid, row_of, col_of);
        py::list out;
        for (int i = 0; i < 6; i++) out.append(py::str(grid[i], 6));
        return out;
    });

    m.def("trifid", [](const std::string &a, const std::string &key, int period, bool encrypt) {
        std::string out; trifid(a, out, key, period, encrypt); return out;
    }, py::arg("text"), py::arg("key"), py::arg("period"), py::arg("encrypt") = true);
    m.def("four_square", [](const std::string &a, const std::string &key1, const std::string &key2, bool encrypt) {
        std::string out; four_square(a, out, key1, key2, encrypt); return out;
    }, py::arg("text"), py::arg("key1"), py::arg("key2"), py::arg("encrypt") = true);
    m.def("adfgvx", [](const std::string &a, const std::string &polybius_key, const std::string &col_key, bool encrypt) {
        std::string out; adfgvx(a, out, polybius_key, col_key, encrypt); return out;
    }, py::arg("text"), py::arg("polybius_key"), py::arg("col_key"), py::arg("encrypt") = true);
    m.def("bacon", [](const std::string &a, bool encrypt) {
        std::string out; bacon(a, out, encrypt); return out;
    }, py::arg("text"), py::arg("encrypt") = true);

    m.def("morse_encode", [](const std::string &a) {
        std::string out; morse_encode(a, out); return out;
    });
    m.def("morse_decode", [](const std::string &a) {
        std::string out; morse_decode(a, out); return out;
    });

    m.def("braille_to_dots", [](const std::string &cell) {
        std::string out; braille_to_dots(cell, out); return out;
    });
    m.def("braille_print_dots", &braille_print_dots);
    m.def("simple_dots_to_braille", [](const std::string &dots) {
        std::string out; simple_dots_to_braille(dots, out); return out;
    });
    m.def("braille_to_simple_dots", [](const std::string &cell) {
        std::string out; braille_to_simple_dots(cell, out); return out;
    });
    m.def("braille_encode", [](const std::string &a) {
        std::string out; braille_encode(a, out); return out;
    });
    m.def("braille_decode", [](const std::string &a) {
        std::string out; braille_decode(a, out); return out;
    });

    // ── new historical_ciphers (Porta, Gronsfeld, Hill, Nihilist) ──

    m.def("porta", [](const std::string &a, const std::string &key) {
        std::string out; porta(a, key, out); return out;
    }, py::arg("text"), py::arg("key"));
    m.def("gronsfeld", [](const std::string &a, const std::string &key, bool encrypt) {
        std::string out; gronsfeld(a, key, out, encrypt); return out;
    }, py::arg("text"), py::arg("key"), py::arg("encrypt") = true);
    m.def("hill_encrypt", [](const std::string &a, int a11, int a12, int a21, int a22) -> std::string {
        std::string out;
        if (!hill_encrypt(a, out, a11, a12, a21, a22))
            throw std::runtime_error("hill_encrypt failed");
        return out;
    }, py::arg("text"), py::arg("a11"), py::arg("a12"), py::arg("a21"), py::arg("a22"));
    m.def("hill_decrypt", [](const std::string &a, int a11, int a12, int a21, int a22) -> std::string {
        std::string out;
        if (!hill_decrypt(a, out, a11, a12, a21, a22))
            throw std::runtime_error("hill_decrypt failed (non-invertible matrix)");
        return out;
    }, py::arg("text"), py::arg("a11"), py::arg("a12"), py::arg("a21"), py::arg("a22"));
    m.def("nihilist_encrypt", [](const std::string &a, const std::string &key) {
        std::string out; nihilist_encrypt(a, out, key); return out;
    }, py::arg("text"), py::arg("key"));
    m.def("nihilist_decrypt", [](const std::string &a, const std::string &key) {
        std::string out; nihilist_decrypt(a, out, key); return out;
    }, py::arg("text"), py::arg("key"));

    // ── essential_ciphers ──

    m.def("raw_bytes_print", &raw_bytes_print);
    m.def("large_encrypt", [](const std::string &a, int base) {
        std::string out; large_encrypt(a, out, base); return out;
    }, py::arg("text"), py::arg("base") = 36);
    m.def("large_decrypt", [](const std::string &a, int base) {
        std::string out; large_decrypt(a, out, base); return out;
    }, py::arg("text"), py::arg("base") = 36);
    m.def("hex_xor", [](const std::string &a, unsigned char key) {
        std::string out; hex_xor(a, key, out); return out;
    });
    m.def("str_xor", [](const std::string &a, const std::string &b) {
        std::string out; str_xor(a, b, out); return py::bytes(out);
    });
    m.def("urlcode", [](const std::string &a, bool encrypt) {
        std::string out; urlcode(a, out, encrypt); return out;
    }, py::arg("text"), py::arg("encrypt") = true);
    m.def("codepoint_to_utf8", [](unsigned int cp) {
        std::string out; codepoint_to_utf8(cp, out); return out;
    });
    m.def("utf8_to_codepoint", [](const std::string &a, int i) {
        int pos = i;
        unsigned int cp = utf8_to_codepoint(a, pos);
        return py::make_tuple(cp, pos);
    });
    m.def("rot8000_cp", &rot8000_cp);
    m.def("rot8000", [](const std::string &a, int key, bool encrypt) {
        std::string out; rot8000(a, out, key, encrypt); return out;
    }, py::arg("text"), py::arg("key"), py::arg("encrypt") = true);
    m.def("octal", [](const std::string &a, bool encrypt) {
        std::string out; octal(a, out, encrypt); return out;
    }, py::arg("text"), py::arg("encrypt") = true);
    m.def("binary", [](const std::string &a, bool encrypt) {
        std::string out; binary(a, out, encrypt); return out;
    }, py::arg("text"), py::arg("encrypt") = true);

    // ── bytes ──

    m.def("little_endian_encode", [](long long val, int bytes) {
        std::string out; little_endian_encode(val, out, bytes); return out;
    }, py::arg("val"), py::arg("bytes") = 8);
    m.def("big_endian_encode", [](long long val, int bytes) {
        std::string out; big_endian_encode(val, out, bytes); return out;
    }, py::arg("val"), py::arg("bytes") = 8);
    m.def("little_endian_decode", [](const std::string &a) {
        long long out; little_endian_decode(a, out); return out;
    });
    m.def("big_endian_decode", [](const std::string &a) {
        long long out; big_endian_decode(a, out); return out;
    });
    m.def("proper_base_convert", [](const std::string &input, int bits_per_char, const std::string &alphabet) {
        std::string out; proper_base_convert(input, out, bits_per_char, alphabet); return out;
    }, py::arg("input"), py::arg("bits_per_char"), py::arg("alphabet"));

    // ── standard_ciphers ──

    m.def("rot47", [](const std::string &a) {
        std::string out; rot47(a, out); return out;
    });
    m.def("keyword_cipher", [](const std::string &a, const std::string &keyword, bool encrypt) {
        std::string out; keyword_cipher(a, out, keyword, encrypt); return out;
    }, py::arg("text"), py::arg("keyword"), py::arg("encrypt") = true);
    m.def("substitution_encrypt", [](const std::string &a, const std::string &key) {
        std::string out; substitution_encrypt(a, out, key); return out;
    });
    m.def("substitution_decrypt", [](const std::string &a, const std::string &key) {
        std::string out; substitution_decrypt(a, out, key); return out;
    });
    m.def("frequency_analysis", [](const std::string &a) {
        std::vector<std::pair<char, double>> freqs;
        frequency_analysis(a, freqs);
        py::list result;
        for (auto &f : freqs) result.append(py::make_tuple(f.first, f.second));
        return result;
    });
    m.def("substitution_solve", [](const std::string &a) {
        std::string out, mapping;
        substitution_solve(a, out, mapping);
        return py::make_tuple(out, mapping);
    });
    m.def("index_of_coincidence", &index_of_coincidence);
    m.def("find_key_lengths", [](const std::string &a, int max_len) {
        std::vector<int> lengths;
        find_key_lengths(a, lengths, max_len);
        return lengths;
    }, py::arg("text"), py::arg("max_len") = 20);
    // ── outdated_ciphers ──

    m.def("rc4", [](const std::string &input, const std::string &key) {
        std::string out; rc4(input, out, key); return py::bytes(out);
    });
    m.def("des_ecb", [](const std::string &input, const std::string &key, bool encrypt) {
        std::string out; des_ecb(input, out, key, encrypt); return py::bytes(out);
    }, py::arg("input"), py::arg("key"), py::arg("encrypt") = true);
    m.def("des3_ecb", [](const std::string &input, const std::string &key, bool encrypt) {
        std::string out; des3_ecb(input, out, key, encrypt); return py::bytes(out);
    }, py::arg("input"), py::arg("key"), py::arg("encrypt") = true);
    m.def("blowfish_ecb", [](const std::string &input, const std::string &key, bool encrypt) {
        std::string out; blowfish_ecb(input, out, key, encrypt); return py::bytes(out);
    }, py::arg("input"), py::arg("key"), py::arg("encrypt") = true);
    m.def("vigenere_autokey_broken", [](const std::string &a, const std::string &key, bool encrypt) {
        std::string out; vigenere_autokey_broken(a, key, out, encrypt); return out;
    }, py::arg("text"), py::arg("key"), py::arg("encrypt") = true);
    m.def("enigma", [](const std::string &input, const std::vector<int> &rotors, const std::vector<int> &offsets, const std::vector<std::pair<int,int>> &plugboard) {
        std::string out; enigma(input, out, rotors, offsets, plugboard); return out;
    });

    // ── bruteforce_ciphers ──

    m.def("brute_rotate", [](const std::string &a) {
        std::string s = a; brute_rotate(s); return s;
    });
    m.def("brute_rot_all", &brute_rot_all);
    m.def("brute_caesar_all", &brute_caesar_all);
    m.def("brute_railfence_all", &brute_railfence_all);
    m.def("brute_xor_single_byte", [](const std::string &a) {
        auto vec = brute_xor_single_byte(a);
        py::list result;
        for (auto &s : vec) result.append(py::bytes(s));
        return result;
    });
    m.def("brute_vigenere_keylength", &brute_vigenere_keylength);

    // ── modern_ciphers (hashes) ──

    m.def("md5_hash", [](const std::string &text) {
        std::string out; md5_hash(text, out); return out;
    }, py::arg("text"));
    m.def("sha1_hash", [](const std::string &text) {
        std::string out; sha1_hash(text, out); return out;
    }, py::arg("text"));
    m.def("sha256_hash", [](const std::string &text) {
        std::string out; sha256_hash(text, out); return out;
    }, py::arg("text"));
    m.def("sha512_hash", [](const std::string &text) {
        std::string out; sha512_hash(text, out); return out;
    }, py::arg("text"));
    m.def("sha384_hash", [](const std::string &text) {
        std::string out; sha384_hash(text, out); return out;
    }, py::arg("text"));
    m.def("sha3_224_hash", [](const std::string &text) {
        std::string out; sha3_224_hash(text, out); return out;
    }, py::arg("text"));
    m.def("sha3_256_hash", [](const std::string &text) {
        std::string out; sha3_256_hash(text, out); return out;
    }, py::arg("text"));
    m.def("sha3_384_hash", [](const std::string &text) {
        std::string out; sha3_384_hash(text, out); return out;
    }, py::arg("text"));
    m.def("sha3_512_hash", [](const std::string &text) {
        std::string out; sha3_512_hash(text, out); return out;
    }, py::arg("text"));
    m.def("shake128_hash", [](const std::string &text, size_t out_len) {
        std::string out; shake128_hash(text, out, out_len); return out;
    }, py::arg("text"), py::arg("out_len") = 32);
    m.def("shake256_hash", [](const std::string &text, size_t out_len) {
        std::string out; shake256_hash(text, out, out_len); return out;
    }, py::arg("text"), py::arg("out_len") = 32);
    m.def("blake2b_hash", [](const std::string &text, const std::string &key) {
        std::string out; blake2b_hash(text, out, key); return out;
    }, py::arg("text"), py::arg("key") = "");
    m.def("blake2s_hash", [](const std::string &text, const std::string &key) {
        std::string out; blake2s_hash(text, out, key); return out;
    }, py::arg("text"), py::arg("key") = "");
    m.def("hmac_sha256", [](const std::string &text, const std::string &key) {
        std::string out; hmac_sha256(text, key, out); return out;
    }, py::arg("text"), py::arg("key"));
    m.def("hmac_sha512", [](const std::string &text, const std::string &key) {
        std::string out; hmac_sha512(text, key, out); return out;
    }, py::arg("text"), py::arg("key"));

    // ── modern_ciphers (symmetric) ──

    m.def("aes_encrypt", [](const py::bytes &input, const py::bytes &key, const py::bytes &iv, int mode) -> py::bytes {
        std::string out;
        if (!aes_encrypt(std::string(input), std::string(key), std::string(iv), mode, out))
            throw py::value_error("AES operation failed");
        return py::bytes(out);
    }, py::arg("input"), py::arg("key"), py::arg("iv"), py::arg("mode"));
    m.def("aes_decrypt", [](const py::bytes &input, const py::bytes &key, const py::bytes &iv, int mode) -> py::bytes {
        std::string out;
        if (!aes_decrypt(std::string(input), std::string(key), std::string(iv), mode, out))
            throw py::value_error("AES operation failed");
        return py::bytes(out);
    }, py::arg("input"), py::arg("key"), py::arg("iv"), py::arg("mode"));
    m.def("chacha20_crypt", [](const py::bytes &input, const py::bytes &key, const py::bytes &nonce, uint32_t counter) -> py::bytes {
        std::string out;
        chacha20_crypt(std::string(input), std::string(key), std::string(nonce), counter, out);
        return py::bytes(out);
    }, py::arg("input"), py::arg("key"), py::arg("nonce"), py::arg("counter") = 0);
    m.def("poly1305_mac", [](const py::bytes &input, const py::bytes &key) -> py::bytes {
        std::string out;
        poly1305_mac(std::string(input), std::string(key), out);
        return py::bytes(out);
    }, py::arg("input"), py::arg("key"));

    // ── modern_ciphers (KDF) ──

    m.def("pbkdf2_sha256", [](const std::string &password, const std::string &salt, uint32_t iterations, uint32_t length) -> py::bytes {
        std::string out;
        pbkdf2_sha256(password, salt, iterations, length, out);
        return py::bytes(out);
    }, py::arg("password"), py::arg("salt"), py::arg("iterations"), py::arg("length"));
    m.def("argon2id_hash", [](const std::string &password, const std::string &salt, uint32_t iterations, uint32_t memory_kb, uint32_t length, uint32_t parallelism) -> py::bytes {
        std::string out;
        if (!argon2id_hash(password, salt, iterations, memory_kb, parallelism, length, out))
            throw std::runtime_error("argon2id failed");
        return py::bytes(out);
    }, py::arg("password"), py::arg("salt"), py::arg("iterations"), py::arg("memory_kb"), py::arg("length"), py::arg("parallelism") = 1);
    m.def("bcrypt_hash", [](const std::string &password, const std::string &salt, uint32_t rounds) -> std::string {
        std::string out;
        if (!bcrypt_hash(password, salt, rounds, out))
            throw std::runtime_error("bcrypt failed");
        return out;
    }, py::arg("password"), py::arg("salt"), py::arg("rounds") = 10);
    m.def("scrypt_hash", [](const std::string &password, const std::string &salt, uint32_t N, uint32_t r, uint32_t p, uint32_t dkLen) -> py::bytes {
        std::string out;
        if (!scrypt_hash(password, salt, N, r, p, dkLen, out))
            throw std::runtime_error("scrypt failed");
        return py::bytes(out);
    }, py::arg("password"), py::arg("salt"), py::arg("N"), py::arg("r"), py::arg("p"), py::arg("dkLen") = 32);

    // ── modern_ciphers (JWT) ──

    m.def("jwt_sign", [](const std::string &header, const std::string &payload, const std::string &key) {
        return jwt_sign(header, payload, key);
    }, py::arg("header"), py::arg("payload"), py::arg("key"));
    m.def("jwt_parse", [](const std::string &token, const std::string &key) -> py::dict {
        JwtToken tok = jwt_parse(token, key);
        py::dict d;
        d["header"] = tok.header;
        d["payload"] = tok.payload;
        d["signature"] = tok.signature;
        d["valid"] = tok.signature_valid;
        return d;
    }, py::arg("token"), py::arg("key") = "");

    // ── modern_ciphers (QR) ──

    m.def("generate_qr_matrix", [](const std::string &text) -> py::list {
        auto matrix = generate_qr_matrix(text);
        py::list result;
        for (auto &row : matrix) {
            py::list row_list;
            for (bool val : row) row_list.append(val);
            result.append(row_list);
        }
        return result;
    }, py::arg("text"));

    // ── modern_ciphers (stego) ──

    m.def("lsb_embed", [](const py::bytes &carrier, const std::string &secret) -> py::bytes {
        std::string out;
        if (!lsb_embed(std::string(carrier), secret, out))
            throw std::runtime_error("lsb_embed failed");
        return py::bytes(out);
    }, py::arg("carrier"), py::arg("secret"));
    m.def("lsb_extract", [](const py::bytes &data) -> std::string {
        std::string out;
        if (!lsb_extract(std::string(data), out))
            throw std::runtime_error("lsb_extract failed");
        return out;
    }, py::arg("data"));

    // ── encoding helpers ──

    m.def("hex_decode_str", [](const std::string &hex) -> py::bytes {
        return py::bytes(hex_decode_str(hex));
    }, py::arg("hex"));
    m.def("base64_encode", [](const std::string &in) {
        return base64_encode(in);
    }, py::arg("text"));
    m.def("base64_decode", [](const std::string &in) {
        return base64_decode(in);
    }, py::arg("text"));
    m.def("base64url_encode", [](const std::string &in) {
        return base64url_encode(in);
    }, py::arg("text"));
    m.def("base64url_decode", [](const std::string &in) {
        return base64url_decode(in);
    }, py::arg("text"));

    // ── detector ──

    m.def("score_english", [](const std::string &text) -> double {
        return score_english(text);
    }, py::arg("text"));
    m.def("compute_entropy", [](const std::string &input) -> double {
        return compute_entropy(input);
    }, py::arg("input"));
    m.def("compute_ioc", [](const std::string &input) -> double {
        return compute_ioc(input);
    }, py::arg("input"));
    m.def("sniff_encoding", [](const std::string &input) -> std::string {
        return sniff_encoding(input);
    }, py::arg("input"));
    m.def("detect_cipher", [](const std::string &text, int top_n) -> py::list {
        auto results = detect_cipher(text, top_n);
        py::list out;
        for (auto &c : results) {
            py::dict d;
            d["cipher"] = c.cipher_name;
            d["decrypted"] = c.decrypted;
            d["key"] = c.key;
            d["confidence"] = c.confidence;
            out.append(d);
        }
        return out;
    }, py::arg("text"), py::arg("top_n") = 3);

    // module-level constants
    m.attr("padding") = py::str(std::string(1, padding));
}
