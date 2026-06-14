#ifndef MODERN_CIPHERS_H
#define MODERN_CIPHERS_H

#include <string>
#include <vector>
#include <utility>
#include <cstdint>

// Hashes
std::string base64_encode(const std::string &in);
std::string base64_decode(const std::string &in);
std::string base64url_encode(const std::string &in);
std::string base64url_decode(const std::string &in);
std::string to_hex(const unsigned char *data, size_t len);
std::string from_hex(const std::string &hex);

void md5_hash(const std::string &input, std::string &output);

struct MD5State { uint32_t h0, h1, h2, h3; };
MD5State md5_state_from_hash(const std::string &hash_hex);
bool md5_hash_continue(const MD5State &state, uint64_t processed_bytes, const std::string &extra, std::string &output);

void sha1_hash(const std::string &input, std::string &output);

struct SHA1State { uint32_t h0, h1, h2, h3, h4; };
SHA1State sha1_state_from_hash(const std::string &hash_hex);
bool sha1_hash_continue(const SHA1State &state, uint64_t processed_bytes, const std::string &extra, std::string &output);

void sha256_hash(const std::string &input, std::string &output);

struct SHA256State { uint32_t h[8]; };
SHA256State sha256_state_from_hash(const std::string &hash_hex);
bool sha256_hash_continue(const SHA256State &state, uint64_t processed_bytes, const std::string &extra, std::string &output);

void sha512_hash(const std::string &input, std::string &output);
void blake2b_hash(const std::string &input, std::string &output, const std::string &key = "");
void blake2s_hash(const std::string &input, std::string &output, const std::string &key = "");

// HMAC
void hmac_sha256(const std::string &input, const std::string &key, std::string &output);
void hmac_sha512(const std::string &input, const std::string &key, std::string &output);

// Key Derivation Functions
void pbkdf2_sha256(const std::string &password, const std::string &salt, uint32_t iterations, uint32_t key_len, std::string &output);
bool argon2id_hash(const std::string &password, const std::string &salt, uint32_t iterations, uint32_t memory_kb, uint32_t parallelism, uint32_t key_len, std::string &output);

// Symmetric Ciphers
// Mode: 0=ECB, 1=CBC, 2=CTR
bool aes_encrypt(const std::string &plaintext, const std::string &key, const std::string &iv, int mode, std::string &ciphertext);
bool aes_decrypt(const std::string &ciphertext, const std::string &key, const std::string &iv, int mode, std::string &plaintext, bool strip_pkcs7 = true);

void chacha20_crypt(const std::string &input, const std::string &key, const std::string &nonce, uint32_t counter, std::string &output);
void salsa20_crypt(const std::string &input, const std::string &key, const std::string &nonce, uint32_t counter, std::string &output);
void poly1305_mac(const std::string &input, const std::string &key, std::string &mac);

// JWT (JSON Web Tokens)
struct JwtToken {
    std::string header;
    std::string payload;
    std::string signature;
    bool signature_valid;
};
JwtToken jwt_parse(const std::string &token, const std::string &key = "");
std::string jwt_sign(const std::string &header_json, const std::string &payload_json, const std::string &key);

// QR Code generation (basic matrix generator)
std::vector<std::vector<bool>> generate_qr_matrix(const std::string &text);

// Steganography
// Encodes text into carrier BMP/PNG (represented by raw RGBA/RGB bytes or just a simplified LSB operation on string data)
bool lsb_extract(const std::string &carrier_data, std::string &extracted_text);
bool lsb_embed(const std::string &carrier_data, const std::string &text_to_embed, std::string &stego_data);

// ── TLS / SSL Structures ─────────────────────────────────────────

struct TlsFingerprint {
    std::string version;
    std::string key_exchange;
    std::string cipher;
    std::string mac;
    int key_bits = 0;
    bool is_pem = false;
    bool is_der = false;
    bool has_pkcs1_padding = false;
    std::vector<std::string> risk_flags;
    std::string suggested_attack;
};

struct CertInfo {
    std::string subject_cn;
    std::string subject_o;
    std::string issuer;
    std::string valid_from;
    std::string valid_until;
    std::string pubkey_algo;
    int pubkey_bits = 0;
    std::string serial_hex;
    std::string sha256_fingerprint;
    std::string modulus_hex;
    std::string exponent_hex;
    std::vector<std::string> san_entries;
    std::vector<std::string> key_usage;
    bool is_expired = false;
    bool is_self_signed = false;
};

TlsFingerprint tls_fingerprint(const std::string &input);
CertInfo parse_certificate(const std::string &pem_or_hex);

#endif // MODERN_CIPHERS_H
