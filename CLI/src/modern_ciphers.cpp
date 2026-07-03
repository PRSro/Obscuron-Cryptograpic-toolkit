#include "../includes/modern_ciphers.h"
#include "../includes/asn1.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <cmath>
#include <ctime>

// ─────────────────────────────────────────────────────────────────────────────
// Utility functions: Base64URL, Hex
// ─────────────────────────────────────────────────────────────────────────────

static const std::string B64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::string &in) {
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(B64_CHARS[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(B64_CHARS[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::string base64_decode(const std::string &in) {
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[B64_CHARS[i]] = i;
    std::string out;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) continue;
        val = (val << 6) + T[c];
        valb += 6;
        while (valb >= 0) {
            out.push_back((char)((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

std::string base64url_encode(const std::string &in) {
    std::string s = base64_encode(in);
    std::replace(s.begin(), s.end(), '+', '-');
    std::replace(s.begin(), s.end(), '/', '_');
    s.erase(std::remove(s.begin(), s.end(), '='), s.end());
    return s;
}

std::string base64url_decode(const std::string &in) {
    std::string s = in;
    std::replace(s.begin(), s.end(), '-', '+');
    std::replace(s.begin(), s.end(), '_', '/');
    while (s.size() % 4) s.push_back('=');
    return base64_decode(s);
}

std::string to_hex(const unsigned char *data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << (int)data[i];
    }
    return ss.str();
}

std::string from_hex(const std::string &hex) {
    std::string out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), nullptr, 16);
        out.push_back(byte);
    }
    return out;
}


// ─────────────────────────────────────────────────────────────────────────────
// Hashes: MD5, SHA-1, SHA-256, SHA-512, BLAKE2b, BLAKE2s
// ─────────────────────────────────────────────────────────────────────────────

// MD5 implementation
void md5_hash(const std::string &input, std::string &output) {
    // Left-rotate helper
    auto F = [](uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); };
    auto G = [](uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); };
    auto H = [](uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; };
    auto I = [](uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); };
    auto LROT = [](uint32_t x, uint32_t c) { return (x << c) | (x >> (32 - c)); };

    uint32_t h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476;

    // Table of constants
    static const uint32_t k[] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };

    static const uint32_t r[] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };

    // Padding
    std::string padded = input;
    uint64_t bit_len = padded.size() * 8;
    padded.push_back((char)0x80);
    while ((padded.size() * 8) % 512 != 448) padded.push_back(0);
    for (int i = 0; i < 8; i++) padded.push_back((char)((bit_len >> (i * 8)) & 0xFF));

    // Process blocks
    for (size_t offset = 0; offset < padded.size(); offset += 64) {
        uint32_t w[16];
        for (int i = 0; i < 16; i++) {
            w[i] = ((unsigned char)padded[offset + i*4 + 0]) |
                   (((unsigned char)padded[offset + i*4 + 1]) << 8) |
                   (((unsigned char)padded[offset + i*4 + 2]) << 16) |
                   (((unsigned char)padded[offset + i*4 + 3]) << 24);
        }

        uint32_t a = h0, b = h1, c = h2, d = h3;

        for (uint32_t i = 0; i < 64; i++) {
            uint32_t f, g;
            if (i < 16) {
                f = F(b, c, d); g = i;
            } else if (i < 32) {
                f = G(b, c, d); g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = H(b, c, d); g = (3 * i + 5) % 16;
            } else {
                f = I(b, c, d); g = (7 * i) % 16;
            }
            uint32_t temp = d;
            d = c;
            c = b;
            b = b + LROT(a + f + k[i] + w[g], r[i]);
            a = temp;
        }

        h0 += a; h1 += b; h2 += c; h3 += d;
    }

    unsigned char digest[16];
    for (int i = 0; i < 4; i++) {
        digest[i]      = (unsigned char)((h0 >> (i * 8)) & 0xFF);
        digest[4 + i]  = (unsigned char)((h1 >> (i * 8)) & 0xFF);
        digest[8 + i]  = (unsigned char)((h2 >> (i * 8)) & 0xFF);
        digest[12 + i] = (unsigned char)((h3 >> (i * 8)) & 0xFF);
    }
    output = to_hex(digest, 16);
}

// SHA-1 implementation
void sha1_hash(const std::string &input, std::string &output) {
    auto LROT = [](uint32_t x, uint32_t c) { return (x << c) | (x >> (32 - c)); };

    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;

    std::string padded = input;
    uint64_t bit_len = padded.size() * 8;
    padded.push_back((char)0x80);
    while ((padded.size() * 8) % 512 != 448) padded.push_back(0);
    for (int i = 7; i >= 0; i--) padded.push_back((char)((bit_len >> (i * 8)) & 0xFF));

    for (size_t offset = 0; offset < padded.size(); offset += 64) {
        uint32_t w[80] = {0};
        for (int i = 0; i < 16; i++) {
            w[i] = (((unsigned char)padded[offset + i*4 + 0]) << 24) |
                   (((unsigned char)padded[offset + i*4 + 1]) << 16) |
                   (((unsigned char)padded[offset + i*4 + 2]) << 8) |
                   ((unsigned char)padded[offset + i*4 + 3]);
        }
        for (int i = 16; i < 80; i++) {
            w[i] = LROT(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        }

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;

        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | (~b & d); k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d; k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d; k = 0xCA62C1D6;
            }
            uint32_t temp = LROT(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = LROT(b, 30);
            b = a;
            a = temp;
        }

        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    }

    unsigned char digest[20];
    for (int i = 0; i < 5; i++) {
        uint32_t h = (i == 0) ? h0 : (i == 1) ? h1 : (i == 2) ? h2 : (i == 3) ? h3 : h4;
        digest[i*4 + 0] = (unsigned char)(h >> 24);
        digest[i*4 + 1] = (unsigned char)(h >> 16);
        digest[i*4 + 2] = (unsigned char)(h >> 8);
        digest[i*4 + 3] = (unsigned char)h;
    }
    output = to_hex(digest, 20);
}

// SHA-256 implementation
void sha256_hash(const std::string &input, std::string &output) {
    auto ROTR = [](uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); };

    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    static const uint32_t k[] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    std::string padded = input;
    uint64_t bit_len = padded.size() * 8;
    padded.push_back((char)0x80);
    while ((padded.size() * 8) % 512 != 448) padded.push_back(0);
    for (int i = 7; i >= 0; i--) padded.push_back((char)((bit_len >> (i * 8)) & 0xFF));

    for (size_t offset = 0; offset < padded.size(); offset += 64) {
        uint32_t w[64] = {0};
        for (int i = 0; i < 16; i++) {
            w[i] = (((unsigned char)padded[offset + i*4 + 0]) << 24) |
                   (((unsigned char)padded[offset + i*4 + 1]) << 16) |
                   (((unsigned char)padded[offset + i*4 + 2]) << 8) |
                   ((unsigned char)padded[offset + i*4 + 3]);
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ROTR(w[i-15], 7) ^ ROTR(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = ROTR(w[i-2], 17) ^ ROTR(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], _h = h[7];

        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = _h + S1 + ch + k[i] + w[i];
            uint32_t S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            _h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += _h;
    }

    unsigned char digest[32];
    for (int i = 0; i < 8; i++) {
        digest[i*4 + 0] = (unsigned char)(h[i] >> 24);
        digest[i*4 + 1] = (unsigned char)(h[i] >> 16);
        digest[i*4 + 2] = (unsigned char)(h[i] >> 8);
        digest[i*4 + 3] = (unsigned char)h[i];
    }
    output = to_hex(digest, 32);
}

// SHA-512 implementation
void sha512_hash(const std::string &input, std::string &output) {
    auto ROTR = [](uint64_t x, uint64_t n) { return (x >> n) | (x << (64 - n)); };

    uint64_t h[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    static const uint64_t k[] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };

    std::string padded = input;
    uint64_t bit_len = padded.size() * 8;
    padded.push_back((char)0x80);
    while ((padded.size() * 8) % 1024 != 896) padded.push_back(0);
    // Write 128-bit bit length (mostly 0s for normal inputs)
    for (int i = 0; i < 8; i++) padded.push_back(0);
    for (int i = 7; i >= 0; i--) padded.push_back((char)((bit_len >> (i * 8)) & 0xFF));

    for (size_t offset = 0; offset < padded.size(); offset += 128) {
        uint64_t w[80] = {0};
        for (int i = 0; i < 16; i++) {
            w[i] = 0;
            for (int j = 0; j < 8; j++) {
                w[i] = (w[i] << 8) | (unsigned char)padded[offset + i*8 + j];
            }
        }
        for (int i = 16; i < 80; i++) {
            uint64_t s0 = ROTR(w[i-15], 1) ^ ROTR(w[i-15], 8) ^ (w[i-15] >> 7);
            uint64_t s1 = ROTR(w[i-2], 19) ^ ROTR(w[i-2], 61) ^ (w[i-2] >> 6);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        uint64_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], _h = h[7];

        for (int i = 0; i < 80; i++) {
            uint64_t S1 = ROTR(e, 14) ^ ROTR(e, 18) ^ ROTR(e, 41);
            uint64_t ch = (e & f) ^ (~e & g);
            uint64_t temp1 = _h + S1 + ch + k[i] + w[i];
            uint64_t S0 = ROTR(a, 28) ^ ROTR(a, 34) ^ ROTR(a, 39);
            uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint64_t temp2 = S0 + maj;

            _h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += _h;
    }

    unsigned char digest[64];
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            digest[i*8 + j] = (unsigned char)(h[i] >> ((7 - j) * 8));
        }
    }
    output = to_hex(digest, 64);
}

void sha384_hash(const std::string &input, std::string &output) {
    auto ROTR = [](uint64_t x, uint64_t n) { return (x >> n) | (x << (64 - n)); };

    uint64_t h[8] = {
        0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
        0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
    };

    static const uint64_t k[] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };

    std::string padded = input;
    uint64_t bit_len = padded.size() * 8;
    padded.push_back((char)0x80);
    while ((padded.size() * 8) % 1024 != 896) padded.push_back(0);
    for (int i = 0; i < 8; i++) padded.push_back(0);
    for (int i = 7; i >= 0; i--) padded.push_back((char)((bit_len >> (i * 8)) & 0xFF));

    for (size_t offset = 0; offset < padded.size(); offset += 128) {
        uint64_t w[80] = {0};
        for (int i = 0; i < 16; i++) {
            w[i] = 0;
            for (int j = 0; j < 8; j++)
                w[i] = (w[i] << 8) | (unsigned char)padded[offset + i*8 + j];
        }
        for (int i = 16; i < 80; i++) {
            uint64_t s0 = ROTR(w[i-15], 1) ^ ROTR(w[i-15], 8) ^ (w[i-15] >> 7);
            uint64_t s1 = ROTR(w[i-2], 19) ^ ROTR(w[i-2], 61) ^ (w[i-2] >> 6);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint64_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], _h = h[7];
        for (int i = 0; i < 80; i++) {
            uint64_t S1 = ROTR(e, 14) ^ ROTR(e, 18) ^ ROTR(e, 41);
            uint64_t ch = (e & f) ^ (~e & g);
            uint64_t temp1 = _h + S1 + ch + k[i] + w[i];
            uint64_t S0 = ROTR(a, 28) ^ ROTR(a, 34) ^ ROTR(a, 39);
            uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint64_t temp2 = S0 + maj;
            _h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += _h;
    }

    unsigned char digest[48];
    for (int i = 0; i < 6; i++) {
        for (int j = 0; j < 8; j++)
            digest[i*8 + j] = (unsigned char)(h[i] >> ((7 - j) * 8));
    }
    output = to_hex(digest, 48);
}

// ── SHA3 / Keccak sponge ─────────────────────────────────────────────────
// Keccak-f[1600] permutation constants
static const int KECCAK_ROUNDS = 24;
static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int KECCAK_RHO[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int KECCAK_PI[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};

static void keccak_f1600(uint64_t st[25]) {
    for (int r = 0; r < 24; r++) {
        // θ step
        uint64_t C[5], D[5];
        for (int i = 0; i < 5; i++)
            C[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
        for (int i = 0; i < 5; i++)
            D[i] = C[(i+4)%5] ^ ((C[(i+1)%5] << 1) | (C[(i+1)%5] >> 63));
        for (int i = 0; i < 25; i++)
            st[i] ^= D[i % 5];

        // ρ and π steps
        uint64_t last = st[1];
        for (int i = 0; i < 24; i++) {
            int j = KECCAK_PI[i];
            uint64_t t = st[j];
            st[j] = ((last << KECCAK_RHO[i]) | (last >> (64 - KECCAK_RHO[i])));
            last = t;
        }

        // χ step
        for (int i = 0; i < 5; i++) {
            int o = i * 5;
            uint64_t t[5] = {st[o], st[o+1], st[o+2], st[o+3], st[o+4]};
            for (int j = 0; j < 5; j++)
                st[o+j] = t[j] ^ (~t[(j+1)%5] & t[(j+2)%5]);
        }

        // ι step
        st[0] ^= KECCAK_RC[r];
    }
}

static void keccak_sponge(const uint8_t *input, size_t input_len, uint8_t *output, size_t output_len, int rate_bytes, uint8_t suffix) {
    uint64_t st[25] = {0};
    uint8_t *state_bytes = (uint8_t*)st;

    // Absorb
    for (size_t i = 0; i < input_len; i += rate_bytes) {
        for (int j = 0; j < rate_bytes && i + j < input_len; j++)
            state_bytes[j] ^= input[i + j];
        keccak_f1600(st);
    }

    // Padding with suffix followed by 0x80
    size_t offset = input_len % rate_bytes;
    state_bytes[offset] ^= suffix;
    state_bytes[rate_bytes - 1] ^= 0x80;
    keccak_f1600(st);

    // Squeeze
    size_t written = 0;
    while (written < output_len) {
        size_t chunk = std::min((size_t)rate_bytes, output_len - written);
        memcpy(output + written, state_bytes, chunk);
        written += chunk;
        if (written < output_len) keccak_f1600(st);
    }
}

void sha3_224_hash(const std::string &input, std::string &output) {
    uint8_t digest[28];
    keccak_sponge((const uint8_t*)input.data(), input.size(), digest, 28, 1152 / 8, 0x06);
    output = to_hex(digest, 28);
}

void sha3_256_hash(const std::string &input, std::string &output) {
    uint8_t digest[32];
    keccak_sponge((const uint8_t*)input.data(), input.size(), digest, 32, 1088 / 8, 0x06);
    output = to_hex(digest, 32);
}

void sha3_384_hash(const std::string &input, std::string &output) {
    uint8_t digest[48];
    keccak_sponge((const uint8_t*)input.data(), input.size(), digest, 48, 832 / 8, 0x06);
    output = to_hex(digest, 48);
}

void sha3_512_hash(const std::string &input, std::string &output) {
    uint8_t digest[64];
    keccak_sponge((const uint8_t*)input.data(), input.size(), digest, 64, 576 / 8, 0x06);
    output = to_hex(digest, 64);
}

void shake128_hash(const std::string &input, std::string &output, size_t out_len) {
    uint8_t *digest = new uint8_t[out_len];
    keccak_sponge((const uint8_t*)input.data(), input.size(), digest, out_len, 1344 / 8, 0x1F);
    output = to_hex(digest, out_len);
    delete[] digest;
}

void shake256_hash(const std::string &input, std::string &output, size_t out_len) {
    uint8_t *digest = new uint8_t[out_len];
    keccak_sponge((const uint8_t*)input.data(), input.size(), digest, out_len, 1088 / 8, 0x1F);
    output = to_hex(digest, out_len);
    delete[] digest;
}

// ── bcrypt / eksblowfish ─────────────────────────────────────────────────
// Blowfish P-array and S-boxes initialized from π hex digits
static const uint32_t BF_P_DEFAULT[18] = {
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
    0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
    0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b
};

static const uint32_t BF_S_DEFAULT[4][256] = {
    {0xd1310ba6,0x98dfb5ac,0x2ffd72db,0xd01adfb7,0xb8e1afed,0x6a267e96,0xba7c9045,0xf12c7f99,
     0x24a19947,0xb3916cf7,0x0801f2e2,0x858efc16,0x636920d8,0x71574e69,0xa458fea3,0xf4933d7e,
     0x0d95748f,0x728eb658,0x718bcd58,0x82154aee,0x7b54a41d,0xc25a59b5,0x9c30d539,0x2af26013,
     0xc5d1b023,0x286085f0,0xca417918,0xb8db38ef,0x8e79dcb0,0x603a180e,0x6c9e0e8b,0xb01e8a3e,
     0xd71577c1,0xbd314b27,0x78af2fda,0x55605c60,0xe65525f3,0xaa55ab94,0x57489862,0x63e81440,
     0x55ca396a,0x2aab10b6,0xb4cc5c34,0x1141e8ce,0xa15486af,0x7c72e993,0xb3ee1411,0x636fbc2a,
     0x2ba9c55d,0x741831f6,0xce5c3e16,0x9b87931e,0xafd6ba33,0x6c24cf5c,0x7a325381,0x28958677,
     0x3b8f4898,0x6b4bb9af,0xc4bfe81b,0x66282193,0x61d809cc,0xfb21a991,0x487cac60,0x5dec8032,
     0xef845d5d,0xe98575b1,0xdc262302,0xeb651b88,0x23893e81,0xd396acc5,0x0f6d6ff3,0x83f44239,
     0x2e0b4482,0xa4842004,0x69c8f04a,0x9e1f9b5e,0x21c66842,0xf6e96c9a,0x670c9c61,0xabd388f0,
     0x6a51a0d2,0xd8542f68,0x960fa728,0xab5133a3,0x6eef0b6c,0x137a3be4,0xba3bf050,0x7efb2a98,
     0xa1f1651d,0x39af0176,0x66ca593e,0x82430e88,0x8cee8619,0x456f9fb4,0x7d84a5c3,0x3b8b5ebe,
     0xe06f75d8,0x85c12073,0x401a449f,0x56c16aa6,0x4ed3aa62,0x363f7706,0x1bfedf72,0x429b023d,
     0x37d0d724,0xd00a1248,0xdb0fead3,0x49f1c09b,0x075372c9,0x80991b7b,0x25d479d8,0xf6e8def7,
     0xe3fe501a,0xb6794c3b,0x976ce0bd,0x04c006ba,0xc1a94fb6,0x409f60c4,0x5e5c9ec2,0x196a2463,
     0x68fb6faf,0x3e6c53b5,0x1339b2eb,0x3b52ec6f,0x6dfc511f,0x9b30952c,0xcc814544,0xaf5ebd09,
     0xbee3d004,0xde334afd,0x660f2807,0x192e4bb3,0xc0cba857,0x45c8740f,0xd20b5f39,0xb9d3fbdb,
     0x5579c0bd,0x1a60320a,0xd6a100c6,0x402c7279,0x679f25fe,0xfb1fa3cc,0x8ea5e9f8,0xdb3222f8,
     0x3c7516df,0xfd616b15,0x2f501ec8,0xad0552ab,0x323db5fa,0xfd238760,0x53317b48,0x3e00df82,
     0x9e5c57bb,0xca6f8ca0,0x1a87562e,0xdf1769db,0xd542a8f6,0x287effc3,0xac6732c6,0x8c4f5573,
     0x695b27b0,0xbbca58c8,0xe1ffa35d,0xb8f011a0,0x10fa3d98,0xfd2183b8,0x4afcb56c,0x2dd1d35b,
     0x9a53e479,0xb6f84565,0xd28e49bc,0x4bfb9790,0xe1ddf2da,0xa4cb7e33,0x62fb1341,0xcee4c6e8,
     0xef20cada,0x36774c01,0xd07e9efe,0x2bf11fb4,0x95dbda4d,0xae909198,0xeaad8e71,0x6b93d5a0,
     0xd08ed1d0,0xafc725e0,0x8e3c5b2f,0x8e7594b7,0x8ff6e2fb,0xf2122b64,0x8888b812,0x900df01c,
     0x4fad5ea0,0x688fc31c,0xd1cff191,0xb3a8c1ad,0x2f2f2218,0xbe0e1777,0xea752dfe,0x8b021fa1,
     0xe5a0cc0f,0xb56f74e8,0x18acf3d6,0xce89e299,0xb4a84fe0,0xfd13e0b7,0x7cc43b81,0xd2ada8d9,
     0x165fa266,0x80957705,0x93cc7314,0x211a1477,0xe6ad2065,0x77b5fa86,0xc75442f5,0xfb9d35cf,
     0xebcdaf0c,0x7b3e89a0,0xd6411bd3,0xae1e7e49,0x00250e2d,0x2071b35e,0x226800bb,0x57b8e0af,
     0x2464369b,0xf009b91e,0x5563911d,0x59dfa6aa,0x78c14389,0xd95a537f,0x207d5ba2,0x02e5b9c5,
     0x83260376,0x6295cfa9,0x11c81968,0x4e734a41,0xb3472dca,0x7b14a94a,0x1c510043,0x224bcaea,
     0x57087a72,0xbea4e690,0xd0d0c304,0x4f51a8b,0x44f589a9,0x5579f8f3,0x5b145546,0x4e84b3b3,
     0xc21167f5,0x1ca48bab,0x60cf1b1d,0x9e3a6df6,0x4f2d5cb6,0xc6753ba7,0xbb1f3e3e,0x9b45226d},
    {0xe72d7d37,0x8ad289b9,0x60cdcfb1,0x2327d52c,0x3998c6ec,0x189e3ac4,0x17763b0e,0x860f179d,
     0xe6ae5ee3,0x5628deaf,0x8ec16857,0xb02bbf5b,0x2d958815,0x8351dd0c,0xb8786a36,0x67beb80a,
     0x27e21bef,0x87a093dc,0x6180d9f7,0xdb0dc7c8,0x8348b7b0,0x1ea9f133,0x2a02cd91,0x7fa4d348,
     0xb1d1b307,0x3e8b9e1f,0x9ef15634,0x614b79ef,0xb14bef5d,0x2705c97e,0x0cf3160d,0xa2430be0,
     0x8f8fe78e,0x27a2eb5b,0xb570dd54,0x1b225aa7,0x8dfb4144,0xa8f8f540,0x2f9a68c4,0x54de2bea,
     0xfc2b0b9a,0x86c12143,0x63d326d6,0xd32eb7bb,0x6cc5cf79,0x38584cc5,0x3f8f7ed5,0xb9fa51c7,
     0xaa994a6e,0xceac7a7f,0xc86f03ac,0x48eafcb0,0x1c82cf3d,0xc1e65d5a,0xaae9a4a3,0x75b3ebe7,
     0xb0c56c9e,0x9d58b1b9,0x98d9d1da,0x59e89e60,0xa5b67d39,0xacfd9af0,0x57b96abd,0x6e52e231,
     0x209d9bb3,0x24225888,0xdabba29a,0x2106fff7,0xd577a365,0x3096bc4f,0x9358f985,0x685c5b80,
     0x2cc07852,0xaa74550c,0xa14f6c8d,0xc7005e88,0x285aa017,0x1eb8ea13,0x36b9e63a,0x7c017620,
     0x6754ffc4,0x6edc59a6,0x8d3fe79a,0xecbd7362,0x3ec2959a,0x4f18c323,0xc26d9cac,0x1c34122d,
     0x2ffba206,0x7b2a9bc4,0x76add6c7,0x7f6db14f,0xa099d6f9,0x4185cfdf,0x6f9a1cce,0x7954a1cc,
     0x256874fe,0x6a1c3ccc,0xc831af91,0x377a62eb,0x7b2a2011,0x9c74d139,0x464e2cc0,0x9b9aca22,
     0x804fb790,0x45f9a37a,0x233cc12a,0x9406f91e,0x99a2a56c,0x10ccf59a,0x3e251ac0,0xd109d38a,
     0x20bc40c6,0x8a6be6e8,0x45bfd43c,0xfb147a5c,0xb957f241,0x7dae0d6c,0xb5d99c75,0xb9b49faf,
     0x436a1bda,0x93e7325b,0x14a9c5ae,0xaa3a574d,0x7dad5476,0x9f43c72e,0x48eb3c27,0xab40436c,
     0xec5cd626,0x16e1a75a,0xf4ac1ebc,0x300fb6da,0xd6f1d918,0xcd1dd3cb,0xb23d0980,0xdc42048f,
     0x1941393b,0x27b5c625,0x6b357541,0x19c6eca5,0x8bb57192,0xdd563fe4,0x4acc35d5,0xc88e5a83,
     0x96be1be2,0xa8dc1c99,0x82af8227,0x2030e029,0x23ddedaf,0xf747f8b8,0x6ce95b74,0x8a814ec0,
     0x51708ef3,0x689e7eee,0xd4b3bbec,0x74748fec,0xb46e85d2,0x5f611991,0x3f73cb43,0x2c38025b,
     0xccb43a6c,0x9433e111,0xa85ce624,0xa630d25b,0x0e0f0000,0x32f5afca,0xdd3e4afd,0xc4584481,
     0x4f086326,0xa455e47e,0xce2d83d7,0x2f3aac80,0x1c2479f9,0xfcfd5441,0xffa4e342,0xde449f2b,
     0x3c93df27,0x7bd01b75,0x5d5b1d5e,0x4968ef0c,0x59e66f92,0xdb6f82cf,0x380fb5cb,0xd46c043d,
     0xcb5b91c7,0xeaea623e,0x41640a7a,0x9aea0216,0x6540e744,0x0fea8e94,0x0fde32c2,0xac88c5a8,
     0x0f7b8bc0,0x293c1a95,0x40e64e8e,0x855e59b4,0xe3e2e012,0x21464af3,0xd4b8ad77,0xb6957e97,
     0x46c54225,0x30152c89,0x3595959d,0x40cadf8f,0x2b1d9d5b,0x06584ef6,0x3249e258,0xfc896584,
     0xb4956582,0xe5c74fc2,0xba7d6fc4,0xaa77b6e1,0x8fcf7a22,0xafbb1461,0xa7dac258,0x9a0cc1f2,
     0x0ed86a94,0x3011d113,0x0e9ea1b1,0xafc1c06b,0x5bfea6c8,0x7467078c,0x8fc80636,0x8583b347,
     0x6e1c9d76,0x38672c5b,0x3c97e26a,0xdc01c207,0xb7c55744,0xb5ec8c6b,0xa84fdeaf,0x35d412d3,
     0x6250ff76,0xcf682f3f,0xd352f32f,0xb66ac375,0xc4eec5c5,0xd3c2be37,0x80fcf29e,0x6de2550a,
     0xd6355ed4,0xcb3cf1aa,0xe8efd320,0x026df4af,0x11028c0d,0x50d64ceb,0x2e8e3e4e,0x7e7d0f9e,
     0xf19829d4,0xda416356,0x1e276946,0xc6149a88,0xbd6a5e68,0xa4a0a61f,0x19222ce0,0x22c42b67},
    {0x8c8f2c44,0xad2d6f93,0x65d6f42b,0x470ba2cd,0xc29f5a55,0x3543bbd6,0x9123a4d4,0x72cb54e6,
     0x5a84b56a,0x258e4dff,0xd67f1a5c,0x36ba520b,0xb3f835a6,0xfb307f68,0x49be6ca4,0x6a13c69b,
     0x34f7abeb,0x90e19fcc,0x4b0c5f7d,0xc057c4e5,0xf21049b5,0xdd3d426a,0xaa9c7256,0x52015e1b,
     0x2de6c77e,0x5b85cb12,0xa73fb4f8,0xf5439a10,0xb5d882b8,0x3b0f9c13,0x2ac08941,0x1e37b176,
     0x6e0294be,0xcc7ce578,0xaa256bd9,0x1ed810f4,0xe5631653,0x1c6aad21,0xb8c4876b,0x55dc7b3e,
     0x55497e1a,0x7bdf7cb0,0x8f003bc0,0xdb62e2b4,0xe0d9f5cb,0x951b303c,0xedd043bb,0x29a64d1f,
     0xd09bd1c5,0xa14e94b6,0x20371ad3,0x5c260b2e,0xaa4d41f4,0x3a31be28,0x3d5f7ff3,0x8293f8b2,
     0x10cfeef3,0x2ebacf60,0xfe4823dc,0xde9d8bde,0xd13f3e90,0x7b32918a,0xf54fa07b,0x001fcda8,
     0xab50a2a9,0xaef9e616,0x4e272ba0,0xd779c1d2,0x62ddc9ef,0x594436f2,0x8b9dfe69,0x1d145af6,
     0x1671cb7b,0xa0b094d9,0xbc6ec39e,0x792cedc7,0x4ec60b18,0xc93da6de,0xe5248424,0x47a9569d,
     0x2398be3b,0xf25ace97,0x87546c2c,0x270ae234,0x98bc70d2,0xc9cb4af5,0x320cd871,0x0f8a4c6b,
     0x5ef448c2,0xce7e108b,0xc05039d0,0x17d1d3d7,0x5001397b,0x72f30fe4,0xd6ba45ae,0x54e8bde2,
     0x1bb4b7fa,0x53c9d01b,0xe5b76682,0xc4d7e5d7,0x7b4e382c,0x89d7edad,0x5313c485,0xe4e6effd,
     0x77bfb1fe,0xfec50db6,0x089ac372,0xa36e957f,0x7bb2b606,0x30d0baa0,0x66dfa9be,0x7b9e165c,
     0xd29b0fee,0x10ea267d,0x8d4c3ca3,0x5e63ff63,0x4d911d12,0x184b89a3,0xed14e139,0x7b9fce69,
     0x8f05eaf0,0xfc7605d3,0x404a7e3b,0x2003790b,0xe4772049,0xe99b3941,0x5da5c2b4,0xd536cb5e,
     0xfc7246be,0xb8a0796a,0xb10500aa,0x5f9f6e40,0x56b81ed1,0x378f651f,0x9b5b4968,0x2562a4aa,
     0xe0a378d0,0xda5302bd,0x3c007e1a,0x559bffb1,0x3cbc8830,0x18e95e40,0x3d10a9b7,0x0ca94be0,
     0x3d85c2d5,0x58d0b3eb,0xa7b68a5e,0xa125c6d4,0xa52d9091,0xd2383305,0xc8f13c94,0xc5e37e1a,
     0xe0cea4d4,0x645faf3f,0xccc13371,0xf01252a8,0x6597db1a,0x4c40b59d,0xd08eafbb,0x68bf0624,
     0x2e2bf88,0x6a1591cd,0xcbe59eaa,0x2a3929ac,0xe44fe456,0x40015a12,0x4695bcdb,0xe80e55b8,
     0x60d79d5b,0x1a31e238,0xebe51c1a,0xaff3c92d,0x3937bed3,0xb350189d,0x50309856,0xc21100ec,
     0xad01b377,0x6940455e,0x2fd82e3e,0x4db68a1b,0x8259df4e,0xbe63ecd7,0x2109a8f0,0x646dd7f8,
     0xe94f0f19,0x941ae9aa,0x51a124b8,0xfa38e3e7,0xd4fd579e,0xb4be1ba2,0x4c6c542b,0x1d3cfa5e,
     0x3f65c2b4,0xf23c22f7,0xfccf5384,0x469c28d0,0xeedb3f8f,0x3ad29aab,0xf9dbb1b2,0xd0f4d501,
     0x4b71095b,0xd9093ba9,0x70b55199,0x1ca3f67c,0xaef4abe5,0xa4e35ddc,0x52e0b6ad,0x87c5f1a6,
     0xf9130ea0,0xba2cfb7e,0xf740e0d7,0xa1088f1,0xa88e2e2f,0xd626c04c,0x71fe3662,0x342cb8b3,
     0xec2198b5,0xa616bcf6,0xbc86e86d,0xab630a97,0xc70b4625,0x7ca2a24e,0xecb932c9,0xb34ce04b,
     0x050e98b8,0x56d5277c,0x124a47cb,0x56918f47,0xc12a2650,0x4d0f3923,0xb8a15292,0xb312c1b6,
     0x385a1db1,0xd5412af7,0x1c24d78e,0x7955ffbe,0x2b1c6a23,0xd2a62ae3,0xecc6f5b3,0x0e5e9a3b,
     0x4f98e6ad,0xcdc9276e,0xcb11024f,0xbc7c2a5d,0x5ad1a0c9,0x99716dba,0xef1d91f2,0x31be2b9a,
     0x475e3d5b,0x2779f226,0xd9c44f18,0x9bbc85cd,0x4bbdd819,0x4e793d62,0x66c3e649,0x567406fe},
    {0xc3555657,0xfce233c9,0x8124e0bb,0x1763d0a3,0x23899ba8,0xbb43e0f6,0xe15e72f8,0xa9e21bcd,
     0x7f9c7f05,0xf3278831,0x9b63ea06,0x0fa0d6a1,0x2f0c34b6,0x8b8494dc,0x3b349504,0x5dae1a35,
     0x3ffe1e7d,0x7603d3d7,0x2c0d4671,0x1e65eb7d,0xf50d58f7,0x3bbf9a1a,0xd4fce210,0x92d50e8d,
     0x8e53c538,0x988c96f6,0xa87fb44a,0x6cfe5824,0xd31cb90f,0x2ebda1c0,0x8fabb6c8,0xa0443a60,
     0xb1d8b05e,0xb1985eb9,0xca7e941a,0x44d060b9,0x6be72dab,0x83658c87,0x3ebc1b10,0xcdcf6d70,
     0x535d2f47,0xfb357450,0xfa1799d2,0x10faf556,0xaabf87d2,0x48064b0e,0x3d16579d,0x422299e3,
     0xb8d74706,0x981a90c8,0xbd2316ce,0xda1da6ad,0xf1f80f24,0xed3f3e23,0x2e9a097b,0x6090c7e1,
     0x868d294b,0x734e5cd6,0x3cd88147,0xc2485a1d,0xd4c68ba1,0xed5adaef,0xf7b5070c,0xda9d04cf,
     0x0a46c7a0,0x2879e4d1,0xe6eb382e,0xb3860358,0x3cbff0ec,0x8a1b2f1a,0x89ea86be,0xa150320e,
     0xb9cebfc0,0xac99b051,0x7ef3d158,0xc4adc7b6,0x5f2ffaac,0x8c7caba6,0x883f3ac0,0x0a285dc9,
     0x35dd5292,0xfc3509f7,0x2763aa41,0xaa144398,0x87c594e4,0x9a953a5a,0x39bcefd6,0xe6655a05,
     0xb1ee3402,0x9413106a,0x9f02671a,0xf503cf57,0x44b521b9,0x2a0f67e6,0x466886c3,0xf0d6a14e,
     0x9eccfb0f,0x2d39e787,0x74e8c4c4,0x3f9be0ab,0x9ff3dfb6,0xe5e8f195,0xdd22b8b8,0x448c202b,
     0x3e4ac757,0x3e08df53,0x3e11e9ea,0xe4f5239e,0x58b68157,0x8950bcd5,0xba2959fa,0x7d80dc45,
     0x2eaa14e3,0xdc41923a,0x437e45d0,0x53dcad72,0x981a7c19,0x146101bc,0xee037979,0x374a727b,
     0xc6516dc5,0x93f23e52,0xde954fa2,0x65e84120,0x8ae1031f,0xed25eefd,0x085f0fdf,0xc7353faa,
     0xd7e5538b,0x55a8eff6,0x1bb3cb54,0x3a186670,0xf77b20ca,0x749646e4,0xffe56df0,0xc2c4ba03,
     0x597c33eb,0x90f7e13b,0x4ce4683a,0x891778ab,0x9bc0377e,0x64e5e8eb,0x95ad2c42,0xaccf09cd,
     0xf694d7bc,0x48b6d8f1,0x259e6f0b,0x83337790,0x63bc53a1,0x530fe54f,0xa6ae9c17,0x6cfb108e,
     0x7f8795e8,0xcc434205,0xc6ea9241,0x9437e5d9,0x9bff244e,0x0a63bd11,0x475c9c87,0x8c3c03b0,
     0xf2234e5a,0xa3a2c4d8,0x5f9b1e3d,0xadf8c15a,0x4b0c9c12,0xe4a79ef9,0xbb4d6c0b,0x90f0dd1e,
     0xec66adf3,0x14d33e0a,0x12a93077,0x912111a2,0x1f02ae20,0xa2bb1f6c,0x2b3a3cd8,0x9d73e234,
     0x72d353fb,0xfa2cf926,0xddc312f0,0x101733ff,0x637b89df,0x19d36111,0x4eb8709b,0xdf76853f,
     0xed7a2a98,0x05eff0e3,0x7a5a60a8,0x2c7d217b,0x63694667,0xaa4ba302,0x09cd6348,0x3d24cfed,
     0x0d91d78b,0xddd937d8,0x9ff38997,0x97c3a92e,0x14b8c6a3,0x3a706ada,0xfc55a4d9,0xa1443e7f}
};

static uint32_t BF_F(const uint32_t *sbox, uint32_t x) {
    uint8_t a = (x >> 24) & 0xFF;
    uint8_t b = (x >> 16) & 0xFF;
    uint8_t c = (x >> 8) & 0xFF;
    uint8_t d = x & 0xFF;
    return (sbox[0*256 + a] + sbox[1*256 + b]) ^ (sbox[2*256 + c] + sbox[3*256 + d]);
}

static void blowfish_encrypt(uint32_t &L, uint32_t &R, const uint32_t *P, const uint32_t (*S)[256]) {
    for (int i = 0; i < 16; i++) {
        L ^= P[i];
        R ^= BF_F(*S, L);
        std::swap(L, R);
    }
    std::swap(L, R);
    R ^= P[16];
    L ^= P[17];
}

static void blowfish_expand_key(uint32_t *P, uint32_t (*S)[256], const uint8_t *key, size_t key_len, const uint8_t *salt, size_t salt_len) {
    size_t j = 0;
    for (int i = 0; i < 18; i++) {
        uint32_t data = 0;
        for (int k = 0; k < 4; k++) {
            data = (data << 8) | key[j++ % key_len];
        }
        P[i] ^= data;
    }

    uint32_t L = 0, R = 0;
    for (int i = 0; i < 18; i += 2) {
        if (salt) {
            L ^= ((uint32_t)salt[0] << 24) | ((uint32_t)salt[1] << 16) | ((uint32_t)salt[2] << 8) | salt[3];
            R ^= ((uint32_t)salt[4] << 24) | ((uint32_t)salt[5] << 16) | ((uint32_t)salt[6] << 8) | salt[7];
            salt += 8; salt_len -= 8;
            if (salt_len == 0) { salt -= 8; salt_len = 8; }
        }
        blowfish_encrypt(L, R, P, S);
        P[i] = L;
        P[i+1] = R;
    }

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 256; j += 2) {
            if (salt) {
                L ^= ((uint32_t)salt[0] << 24) | ((uint32_t)salt[1] << 16) | ((uint32_t)salt[2] << 8) | salt[3];
                R ^= ((uint32_t)salt[4] << 24) | ((uint32_t)salt[5] << 16) | ((uint32_t)salt[6] << 8) | salt[7];
                salt += 8; salt_len -= 8;
                if (salt_len == 0) { salt -= 8; salt_len = 8; }
            }
            blowfish_encrypt(L, R, P, S);
            S[i][j] = L;
            S[i][j+1] = R;
        }
    }
}

static void eksblowfish(uint32_t *P, uint32_t (*S)[256], const uint8_t *key, size_t key_len, const uint8_t *salt, size_t salt_len, uint32_t rounds) {
    blowfish_expand_key(P, S, key, key_len, salt, salt_len);
    for (uint32_t r = 0; r < rounds; r++) {
        blowfish_expand_key(P, S, key, key_len, nullptr, 0);
        blowfish_expand_key(P, S, salt, salt_len, nullptr, 0);
    }
}

static const char BF_BASE64[65] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static void bf_encode(uint8_t *data, size_t len, std::string &out) {
    for (size_t i = 0; i < len; ) {
        uint32_t v = 0;
        int bits = 0;
        while (bits < 24 && i < len) {
            v = (v << 8) | data[i++];
            bits += 8;
        }
        int remain = bits;
        while (remain > 0) {
            remain -= 6;
            out += BF_BASE64[(v >> remain) & 0x3F];
        }
    }
}

bool bcrypt_hash(const std::string &password, const std::string &salt, uint32_t rounds, std::string &output) {
    if (rounds < 4 || rounds > 31) return false;
    if (salt.size() != 16) return false;

    uint32_t P[18];
    uint32_t S[4][256];
    memcpy(P, BF_P_DEFAULT, sizeof(P));
    memcpy(S, BF_S_DEFAULT, sizeof(S));

    std::string pw = password;
    if (pw.size() < 72) pw.append(72 - pw.size(), '\0');
    if (pw.size() > 72) pw.resize(72);

    eksblowfish(P, S, (const uint8_t*)pw.data(), pw.size(), (const uint8_t*)salt.data(), salt.size(), rounds);

    // Encrypt "OrpheanBeholderScryDoubt" 64 times
    const char *magic = "OrpheanBeholderScryDoubt";
    uint32_t L = ((uint32_t)magic[0] << 24) | ((uint32_t)magic[1] << 16) | ((uint32_t)magic[2] << 8) | magic[3];
    uint32_t R = ((uint32_t)magic[4] << 24) | ((uint32_t)magic[5] << 16) | ((uint32_t)magic[6] << 8) | magic[7];
    uint32_t L2 = ((uint32_t)magic[8] << 24) | ((uint32_t)magic[9] << 16) | ((uint32_t)magic[10] << 8) | magic[11];
    uint32_t R2 = ((uint32_t)magic[12] << 24) | ((uint32_t)magic[13] << 16) | ((uint32_t)magic[14] << 8) | magic[15];
    uint32_t L3 = ((uint32_t)magic[16] << 24) | ((uint32_t)magic[17] << 16) | ((uint32_t)magic[18] << 8) | magic[19];
    uint32_t R3 = ((uint32_t)magic[20] << 24) | ((uint32_t)magic[21] << 16) | ((uint32_t)magic[22] << 8) | magic[23];

    for (int i = 0; i < 64; i++) {
        blowfish_encrypt(L, R, P, S);
        blowfish_encrypt(L2, R2, P, S);
        blowfish_encrypt(L3, R3, P, S);
    }

    uint8_t hash[24];
    // Convert to little-endian bytes
    for (int i = 0; i < 4; i++) {
        hash[i] = (L >> (i * 8)) & 0xFF;
        hash[4+i] = (R >> (i * 8)) & 0xFF;
        hash[8+i] = (L2 >> (i * 8)) & 0xFF;
        hash[12+i] = (R2 >> (i * 8)) & 0xFF;
        hash[16+i] = (L3 >> (i * 8)) & 0xFF;
        hash[20+i] = (R3 >> (i * 8)) & 0xFF;
    }

    output = "$2b$";
    if (rounds < 10) output += "0";
    output += std::to_string(rounds) + "$";
    bf_encode((uint8_t*)salt.data(), 16, output);
    bf_encode(hash, 23, output);
    return true;
}

// ── scrypt ────────────────────────────────────────────────────────────────
static uint32_t scrypt_rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void salsa20_8_core(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    memcpy(x, in, 64);
    for (int i = 0; i < 8; i++) {
        x[4] ^= scrypt_rotl(x[0] + x[12], 7);  x[8] ^= scrypt_rotl(x[4] + x[0], 9);
        x[12] ^= scrypt_rotl(x[8] + x[4], 13); x[0] ^= scrypt_rotl(x[12] + x[8], 18);
        x[9] ^= scrypt_rotl(x[5] + x[1], 7);   x[13] ^= scrypt_rotl(x[9] + x[5], 9);
        x[1] ^= scrypt_rotl(x[13] + x[9], 13); x[5] ^= scrypt_rotl(x[1] + x[13], 18);
        x[14] ^= scrypt_rotl(x[10] + x[6], 7); x[2] ^= scrypt_rotl(x[14] + x[10], 9);
        x[6] ^= scrypt_rotl(x[2] + x[14], 13); x[10] ^= scrypt_rotl(x[6] + x[2], 18);
        x[3] ^= scrypt_rotl(x[15] + x[11], 7); x[7] ^= scrypt_rotl(x[3] + x[15], 9);
        x[11] ^= scrypt_rotl(x[7] + x[3], 13); x[15] ^= scrypt_rotl(x[11] + x[7], 18);
        x[1] ^= scrypt_rotl(x[0] + x[3], 7);   x[2] ^= scrypt_rotl(x[1] + x[0], 9);
        x[3] ^= scrypt_rotl(x[2] + x[1], 13);  x[0] ^= scrypt_rotl(x[3] + x[2], 18);
        x[6] ^= scrypt_rotl(x[5] + x[4], 7);   x[7] ^= scrypt_rotl(x[6] + x[5], 9);
        x[4] ^= scrypt_rotl(x[7] + x[6], 13);  x[5] ^= scrypt_rotl(x[4] + x[7], 18);
        x[11] ^= scrypt_rotl(x[10] + x[9], 7); x[8] ^= scrypt_rotl(x[11] + x[10], 9);
        x[9] ^= scrypt_rotl(x[8] + x[11], 13); x[10] ^= scrypt_rotl(x[9] + x[8], 18);
        x[12] ^= scrypt_rotl(x[15] + x[14], 7); x[13] ^= scrypt_rotl(x[12] + x[15], 9);
        x[14] ^= scrypt_rotl(x[13] + x[12], 13); x[15] ^= scrypt_rotl(x[14] + x[13], 18);
    }
    for (int i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

static void scrypt_block_mix(uint8_t *B, size_t r) {
    uint32_t X[16];
    memcpy(X, B + (2*r - 1) * 64, 64);
    for (size_t i = 0; i < 2*r; i++) {
        uint32_t Y[16];
        for (int j = 0; j < 16; j++)
            Y[j] = ((uint32_t*)B)[i*16 + j] ^ X[j];
        salsa20_8_core(X, Y);
        memcpy(B + (i/2 + (i%2)*r) * 64, X, 64);
    }
}

static void scrypt_romix(uint8_t *B, size_t r, uint32_t N) {
    size_t block_bytes = 128 * r;
    std::vector<uint8_t> V(N * block_bytes);
    for (uint32_t i = 0; i < N; i++) {
        memcpy(&V[i * block_bytes], B, block_bytes);
        scrypt_block_mix(B, r);
    }
    for (uint32_t i = 0; i < N; i++) {
        uint32_t j = ((uint32_t*)B)[(2*r - 1) * 4] & (N - 1);
        for (size_t k = 0; k < block_bytes / 4; k++)
            ((uint32_t*)B)[k] ^= ((uint32_t*)&V[j * block_bytes])[k];
        scrypt_block_mix(B, r);
    }
}

bool scrypt_hash(const std::string &password, const std::string &salt, uint32_t N, uint32_t r, uint32_t p, uint32_t dkLen, std::string &output) {
    if (N < 2 || (N & (N - 1)) != 0) return false;

    // Step 1: B = PBKDF2-HMAC-SHA256(password, salt, 1, p * 128 * r)
    std::string B;
    pbkdf2_sha256(password, salt, 1, p * 128 * r, B);
    std::string B_raw = from_hex(B);

    // Step 2: ROMix each block
    for (uint32_t i = 0; i < p; i++) {
        scrypt_romix((uint8_t*)B_raw.data() + i * 128 * r, r, N);
    }

    // Step 3: DK = PBKDF2-HMAC-SHA256(password, B', 1, dkLen)
    pbkdf2_sha256(password, B_raw, 1, dkLen, output);
    return true;
}

void weak_kdf_demo(const std::string &password, const std::string &salt, uint32_t iterations, uint32_t memory_kb, uint32_t key_len, std::string &output) {
    std::string state = password + salt;
    for (uint32_t iter = 0; iter < iterations; ++iter) {
        std::string round_input = state + std::to_string(iter) + std::to_string(memory_kb);
        std::string hash_out;
        blake2b_hash(round_input, hash_out);
        state = hash_out;
    }
    output = state.substr(0, key_len * 2);
}

// BLAKE2s & BLAKE2b implementation
static const uint32_t BLAKE2S_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static const uint64_t BLAKE2B_IV[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL, 0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};

static const uint8_t BLAKE2_SIGMA[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

void blake2s_hash(const std::string &input, std::string &output, const std::string &key) {
    uint32_t h[8];
    std::copy(BLAKE2S_IV, BLAKE2S_IV + 8, h);
    h[0] ^= 0x01010000 ^ (key.size() << 8) ^ 32;

    auto G = [](uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, uint32_t x, uint32_t y) {
        auto ROTR = [](uint32_t val, int count) { return (val >> count) | (val << (32 - count)); };
        a = a + b + x;
        d = ROTR(d ^ a, 16);
        c = c + d;
        b = ROTR(b ^ c, 12);
        a = a + b + y;
        d = ROTR(d ^ a, 8);
        c = c + d;
        b = ROTR(b ^ c, 7);
    };

    std::string data;
    if (!key.empty()) {
        data = key;
        data.resize(64, 0);
    }
    data += input;

    size_t bytes_left = data.size();
    size_t chunk_offset = 0;
    uint32_t t[2] = {0, 0};

    do {
        size_t block_bytes = std::min(bytes_left, (size_t)64);
        bytes_left -= block_bytes;
        
        t[0] += block_bytes;
        if (t[0] < block_bytes) t[1]++;

        uint32_t f0 = (bytes_left == 0) ? 0xFFFFFFFF : 0;

        uint32_t m[16] = {0};
        for (int i = 0; i < 16; i++) {
            size_t idx = chunk_offset + i*4;
            if (idx < data.size()) {
                m[i] = ((unsigned char)data[idx]) |
                       ((idx + 1 < data.size() ? (unsigned char)data[idx+1] : 0) << 8) |
                       ((idx + 2 < data.size() ? (unsigned char)data[idx+2] : 0) << 16) |
                       ((idx + 3 < data.size() ? (unsigned char)data[idx+3] : 0) << 24);
            }
        }

        uint32_t v[16];
        std::copy(h, h + 8, v);
        std::copy(BLAKE2S_IV, BLAKE2S_IV + 8, v + 8);
        v[12] ^= t[0];
        v[13] ^= t[1];
        v[14] ^= f0;

        for (int r = 0; r < 10; r++) {
            G(v[0], v[4], v[8],  v[12], m[BLAKE2_SIGMA[r][0]],  m[BLAKE2_SIGMA[r][1]]);
            G(v[1], v[5], v[9],  v[13], m[BLAKE2_SIGMA[r][2]],  m[BLAKE2_SIGMA[r][3]]);
            G(v[2], v[6], v[10], v[14], m[BLAKE2_SIGMA[r][4]],  m[BLAKE2_SIGMA[r][5]]);
            G(v[3], v[7], v[11], v[15], m[BLAKE2_SIGMA[r][6]],  m[BLAKE2_SIGMA[r][7]]);
            G(v[0], v[5], v[10], v[15], m[BLAKE2_SIGMA[r][8]],  m[BLAKE2_SIGMA[r][9]]);
            G(v[1], v[6], v[11], v[12], m[BLAKE2_SIGMA[r][10]], m[BLAKE2_SIGMA[r][11]]);
            G(v[2], v[7], v[8],  v[13], m[BLAKE2_SIGMA[r][12]], m[BLAKE2_SIGMA[r][13]]);
            G(v[3], v[4], v[9],  v[14], m[BLAKE2_SIGMA[r][14]], m[BLAKE2_SIGMA[r][15]]);
        }

        for (int i = 0; i < 8; i++) {
            h[i] ^= v[i] ^ v[i+8];
        }

        chunk_offset += 64;
    } while (bytes_left > 0);

    unsigned char digest[32];
    for (int i = 0; i < 8; i++) {
        digest[i*4 + 0] = (unsigned char)(h[i] & 0xFF);
        digest[i*4 + 1] = (unsigned char)((h[i] >> 8) & 0xFF);
        digest[i*4 + 2] = (unsigned char)((h[i] >> 16) & 0xFF);
        digest[i*4 + 3] = (unsigned char)((h[i] >> 24) & 0xFF);
    }
    output = to_hex(digest, 32);
}

void blake2b_hash(const std::string &input, std::string &output, const std::string &key) {
    uint64_t h[8];
    std::copy(BLAKE2B_IV, BLAKE2B_IV + 8, h);
    h[0] ^= 0x01010000 ^ (key.size() << 8) ^ 64;

    auto G = [](uint64_t &a, uint64_t &b, uint64_t &c, uint64_t &d, uint64_t x, uint64_t y) {
        auto ROTR = [](uint64_t val, int count) { return (val >> count) | (val << (64 - count)); };
        a = a + b + x;
        d = ROTR(d ^ a, 32);
        c = c + d;
        b = ROTR(b ^ c, 24);
        a = a + b + y;
        d = ROTR(d ^ a, 16);
        c = c + d;
        b = ROTR(b ^ c, 63);
    };

    std::string data;
    if (!key.empty()) {
        data = key;
        data.resize(128, 0);
    }
    data += input;

    size_t bytes_left = data.size();
    size_t chunk_offset = 0;
    uint64_t t[2] = {0, 0};

    do {
        size_t block_bytes = std::min(bytes_left, (size_t)128);
        bytes_left -= block_bytes;
        
        t[0] += block_bytes;
        if (t[0] < block_bytes) t[1]++;

        uint64_t f0 = (bytes_left == 0) ? 0xFFFFFFFFFFFFFFFFULL : 0;

        uint64_t m[16] = {0};
        for (int i = 0; i < 16; i++) {
            size_t idx = chunk_offset + i*8;
            m[i] = 0;
            for (int j = 0; j < 8; j++) {
                if (idx + j < data.size()) {
                    m[i] |= ((uint64_t)(unsigned char)data[idx + j]) << (j * 8);
                }
            }
        }

        uint64_t v[16];
        std::copy(h, h + 8, v);
        std::copy(BLAKE2B_IV, BLAKE2B_IV + 8, v + 8);
        v[12] ^= t[0];
        v[13] ^= t[1];
        v[14] ^= f0;

        for (int r = 0; r < 12; r++) {
            G(v[0], v[4], v[8],  v[12], m[BLAKE2_SIGMA[r][0]],  m[BLAKE2_SIGMA[r][1]]);
            G(v[1], v[5], v[9],  v[13], m[BLAKE2_SIGMA[r][2]],  m[BLAKE2_SIGMA[r][3]]);
            G(v[2], v[6], v[10], v[14], m[BLAKE2_SIGMA[r][4]],  m[BLAKE2_SIGMA[r][5]]);
            G(v[3], v[7], v[11], v[15], m[BLAKE2_SIGMA[r][6]],  m[BLAKE2_SIGMA[r][7]]);
            G(v[0], v[5], v[10], v[15], m[BLAKE2_SIGMA[r][8]],  m[BLAKE2_SIGMA[r][9]]);
            G(v[1], v[6], v[11], v[12], m[BLAKE2_SIGMA[r][10]], m[BLAKE2_SIGMA[r][11]]);
            G(v[2], v[7], v[8],  v[13], m[BLAKE2_SIGMA[r][12]], m[BLAKE2_SIGMA[r][13]]);
            G(v[3], v[4], v[9],  v[14], m[BLAKE2_SIGMA[r][14]], m[BLAKE2_SIGMA[r][15]]);
        }

        for (int i = 0; i < 8; i++) {
            h[i] ^= v[i] ^ v[i+8];
        }

        chunk_offset += 128;
    } while (bytes_left > 0);

    unsigned char digest[64];
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            digest[i*8 + j] = (unsigned char)(h[i] >> ((7 - j) * 8));
        }
    }
    output = to_hex(digest, 64);
}

// ── Hash state-continuation for length extension attacks ─────────────

// MD5 state from known hash (little-endian digest bytes)
MD5State md5_state_from_hash(const std::string &hash_hex) {
    MD5State s;
    std::string raw = from_hex(hash_hex);
    if (raw.size() < 16) { s.h0 = s.h1 = s.h2 = s.h3 = 0; return s; }
    auto rd = [&](int off) {
        return ((uint32_t)(unsigned char)raw[off]) |
               (((uint32_t)(unsigned char)raw[off+1]) << 8) |
               (((uint32_t)(unsigned char)raw[off+2]) << 16) |
               (((uint32_t)(unsigned char)raw[off+3]) << 24);
    };
    s.h0 = rd(0); s.h1 = rd(4); s.h2 = rd(8); s.h3 = rd(12);
    return s;
}

bool md5_hash_continue(const MD5State &state, uint64_t processed_bytes,
                        const std::string &extra, std::string &output) {
    auto F = [](uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); };
    auto G = [](uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); };
    auto H_ = [](uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; };
    auto I = [](uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); };
    auto LROT = [](uint32_t x, uint32_t c) { return (x << c) | (x >> (32 - c)); };

    static const uint32_t k[] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };
    static const uint32_t r[] = {
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
    };

    uint32_t h0 = state.h0, h1 = state.h1, h2 = state.h2, h3 = state.h3;
    std::string data = extra;
    uint64_t total_bits = (processed_bytes + extra.size()) * 8;

    data.push_back((char)0x80);
    while ((data.size() * 8) % 512 != 448) data.push_back(0);
    for (int i = 0; i < 8; i++)
        data.push_back((char)((total_bits >> (i * 8)) & 0xFF));

    for (size_t offset = 0; offset < data.size(); offset += 64) {
        uint32_t w[16];
        for (int i = 0; i < 16; i++) {
            w[i] = ((unsigned char)data[offset + i*4]) |
                   (((unsigned char)data[offset + i*4 + 1]) << 8) |
                   (((unsigned char)data[offset + i*4 + 2]) << 16) |
                   (((unsigned char)data[offset + i*4 + 3]) << 24);
        }
        uint32_t a = h0, b = h1, c = h2, d = h3;
        for (uint32_t i = 0; i < 64; i++) {
            uint32_t f, g;
            if (i < 16)      { f = F(b, c, d); g = i; }
            else if (i < 32) { f = G(b, c, d); g = (5 * i + 1) % 16; }
            else if (i < 48) { f = H_(b, c, d); g = (3 * i + 5) % 16; }
            else             { f = I(b, c, d); g = (7 * i) % 16; }
            uint32_t temp = d;
            d = c;
            c = b;
            b = b + LROT(a + f + k[i] + w[g], r[i]);
            a = temp;
        }
        h0 += a; h1 += b; h2 += c; h3 += d;
    }

    unsigned char digest[16];
    for (int i = 0; i < 4; i++) {
        digest[i]      = (unsigned char)((h0 >> (i * 8)) & 0xFF);
        digest[4 + i]  = (unsigned char)((h1 >> (i * 8)) & 0xFF);
        digest[8 + i]  = (unsigned char)((h2 >> (i * 8)) & 0xFF);
        digest[12 + i] = (unsigned char)((h3 >> (i * 8)) & 0xFF);
    }
    output = to_hex(digest, 16);
    return true;
}

SHA1State sha1_state_from_hash(const std::string &hash_hex) {
    SHA1State s;
    std::string raw = from_hex(hash_hex);
    if (raw.size() < 20) { s.h0 = s.h1 = s.h2 = s.h3 = s.h4 = 0; return s; }
    auto rd = [&](int off) {
        return (((uint32_t)(unsigned char)raw[off]) << 24) |
               (((uint32_t)(unsigned char)raw[off+1]) << 16) |
               (((uint32_t)(unsigned char)raw[off+2]) << 8) |
               ((uint32_t)(unsigned char)raw[off+3]);
    };
    s.h0 = rd(0); s.h1 = rd(4); s.h2 = rd(8); s.h3 = rd(12); s.h4 = rd(16);
    return s;
}

bool sha1_hash_continue(const SHA1State &state, uint64_t processed_bytes,
                         const std::string &extra, std::string &output) {
    auto LROT = [](uint32_t x, uint32_t c) { return (x << c) | (x >> (32 - c)); };
    uint32_t h0 = state.h0, h1 = state.h1, h2 = state.h2, h3 = state.h3, h4 = state.h4;

    std::string data = extra;
    uint64_t total_bits = (processed_bytes + extra.size()) * 8;
    data.push_back((char)0x80);
    while ((data.size() * 8) % 512 != 448) data.push_back(0);
    for (int i = 7; i >= 0; i--) data.push_back((char)((total_bits >> (i * 8)) & 0xFF));

    for (size_t offset = 0; offset < data.size(); offset += 64) {
        uint32_t w[80] = {0};
        for (int i = 0; i < 16; i++) {
            w[i] = (((unsigned char)data[offset + i*4]) << 24) |
                   (((unsigned char)data[offset + i*4 + 1]) << 16) |
                   (((unsigned char)data[offset + i*4 + 2]) << 8) |
                   ((unsigned char)data[offset + i*4 + 3]);
        }
        for (int i = 16; i < 80; i++)
            w[i] = LROT(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        for (int i = 0; i < 80; i++) {
            uint32_t f, kk;
            if (i < 20)      { f = (b & c) | (~b & d); kk = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d;          kk = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); kk = 0x8F1BBCDC; }
            else             { f = b ^ c ^ d;          kk = 0xCA62C1D6; }
            uint32_t temp = LROT(a, 5) + f + e + kk + w[i];
            e = d; d = c; c = LROT(b, 30); b = a; a = temp;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    }

    unsigned char digest[20];
    for (int i = 0; i < 5; i++) {
        uint32_t h = (i == 0) ? h0 : (i == 1) ? h1 : (i == 2) ? h2 : (i == 3) ? h3 : h4;
        digest[i*4]     = (unsigned char)(h >> 24);
        digest[i*4 + 1] = (unsigned char)(h >> 16);
        digest[i*4 + 2] = (unsigned char)(h >> 8);
        digest[i*4 + 3] = (unsigned char)h;
    }
    output = to_hex(digest, 20);
    return true;
}

SHA256State sha256_state_from_hash(const std::string &hash_hex) {
    SHA256State s;
    std::string raw = from_hex(hash_hex);
    for (int i = 0; i < 8 && i * 4 + 4 <= (int)raw.size(); i++) {
        s.h[i] = (((uint32_t)(unsigned char)raw[i*4]) << 24) |
                 (((uint32_t)(unsigned char)raw[i*4+1]) << 16) |
                 (((uint32_t)(unsigned char)raw[i*4+2]) << 8) |
                 ((uint32_t)(unsigned char)raw[i*4+3]);
    }
    return s;
}

bool sha256_hash_continue(const SHA256State &state, uint64_t processed_bytes,
                           const std::string &extra, std::string &output) {
    auto ROTR = [](uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); };
    uint32_t h[8];
    for (int i = 0; i < 8; i++) h[i] = state.h[i];

    static const uint32_t k[] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    std::string data = extra;
    uint64_t total_bits = (processed_bytes + extra.size()) * 8;
    data.push_back((char)0x80);
    while ((data.size() * 8) % 512 != 448) data.push_back(0);
    for (int i = 7; i >= 0; i--) data.push_back((char)((total_bits >> (i * 8)) & 0xFF));

    for (size_t offset = 0; offset < data.size(); offset += 64) {
        uint32_t w[64] = {0};
        for (int i = 0; i < 16; i++) {
            w[i] = (((unsigned char)data[offset + i*4]) << 24) |
                   (((unsigned char)data[offset + i*4 + 1]) << 16) |
                   (((unsigned char)data[offset + i*4 + 2]) << 8) |
                   ((unsigned char)data[offset + i*4 + 3]);
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ROTR(w[i-15], 7) ^ ROTR(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = ROTR(w[i-2], 17) ^ ROTR(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], _h = h[7];

        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = _h + S1 + ch + k[i] + w[i];
            uint32_t S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            _h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += _h;
    }

    unsigned char digest[32];
    for (int i = 0; i < 8; i++) {
        digest[i*4]     = (unsigned char)(h[i] >> 24);
        digest[i*4 + 1] = (unsigned char)(h[i] >> 16);
        digest[i*4 + 2] = (unsigned char)(h[i] >> 8);
        digest[i*4 + 3] = (unsigned char)h[i];
    }
    output = to_hex(digest, 32);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// HMAC-SHA256 & HMAC-SHA512
// ─────────────────────────────────────────────────────────────────────────────
// HMAC-SHA256 & HMAC-SHA512
// ─────────────────────────────────────────────────────────────────────────────

void hmac_sha256(const std::string &input, const std::string &key, std::string &output) {
    std::string real_key = key;
    if (real_key.size() > 64) {
        std::string hex_key;
        sha256_hash(real_key, hex_key);
        real_key = from_hex(hex_key);
    }
    real_key.resize(64, 0);

    std::string ipad = real_key;
    std::string opad = real_key;
    for (int i = 0; i < 64; i++) {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5C;
    }

    std::string inner_hash;
    sha256_hash(ipad + input, inner_hash);
    sha256_hash(opad + from_hex(inner_hash), output);
}

void hmac_sha512(const std::string &input, const std::string &key, std::string &output) {
    std::string real_key = key;
    if (real_key.size() > 128) {
        std::string hex_key;
        sha512_hash(real_key, hex_key);
        real_key = from_hex(hex_key);
    }
    real_key.resize(128, 0);

    std::string ipad = real_key;
    std::string opad = real_key;
    for (int i = 0; i < 128; i++) {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5C;
    }

    std::string inner_hash;
    sha512_hash(ipad + input, inner_hash);
    sha512_hash(opad + from_hex(inner_hash), output);
}

// ─────────────────────────────────────────────────────────────────────────────
// PBKDF2 & Argon2id
// ─────────────────────────────────────────────────────────────────────────────

void pbkdf2_sha256(const std::string &password, const std::string &salt, uint32_t iterations, uint32_t key_len, std::string &output) {
    std::string derived;
    uint32_t block_idx = 1;
    
    while (derived.size() < key_len) {
        std::string block_salt = salt;
        block_salt.push_back((char)(block_idx >> 24));
        block_salt.push_back((char)(block_idx >> 16));
        block_salt.push_back((char)(block_idx >> 8));
        block_salt.push_back((char)block_idx);

        std::string u;
        hmac_sha256(block_salt, password, u);
        std::string f = from_hex(u);

        for (uint32_t iter = 1; iter < iterations; ++iter) {
            std::string next_u;
            hmac_sha256(from_hex(u), password, next_u);
            u = next_u;
            std::string raw_u = from_hex(u);
            for (size_t b = 0; b < f.size(); ++b) {
                f[b] ^= raw_u[b];
            }
        }
        derived += f;
        block_idx++;
    }
    output = to_hex((const unsigned char*)derived.data(), key_len);
}

// Argon2id core logic (simplified educational implementation)
bool argon2id_hash(const std::string &password, const std::string &salt, uint32_t iterations, uint32_t memory_kb, uint32_t parallelism, uint32_t key_len, std::string &output) {
    // Basic structural checks. Return empty or dummy hex string if invalid
    if (memory_kb < 8) memory_kb = 8;
    if (parallelism == 0) parallelism = 1;

    // For local iteration testing and visual metrics in Obscuron's UI, this simplified implementation
    // uses Blake2b hashing with memory-hard block mixing to simulate resource consumption.
    std::string combined_salt = salt + std::to_string(iterations) + std::to_string(memory_kb) + std::to_string(parallelism);
    std::string key_material;
    
    // Perform memory block operations to match memory-hard latency patterns
    std::vector<uint32_t> block_mem(memory_kb * 256, 0xABCDEF12);
    // Mimic the state compression mixing steps of Argon2 by applying a sequence of BLAKE2b rounds
    for (uint32_t iter = 0; iter < iterations; ++iter) {
        for (uint32_t p = 0; p < parallelism; ++p) {
            std::string block_input = password + combined_salt + std::to_string(iter) + std::to_string(p);
            std::string mix;
            blake2b_hash(block_input, mix);
            // Mix state values pseudo-randomly over the memory matrix to make cache optimization harder
            for (size_t i = 0; i < block_mem.size(); i += 16) {
                uint32_t offset = (unsigned char)mix[i % mix.size()] % block_mem.size();
                block_mem[i % block_mem.size()] ^= block_mem[offset];
            }
        }
    }
    
    // Hash final block state
    std::string raw_state((char*)block_mem.data(), std::min((size_t)256, block_mem.size() * sizeof(uint32_t)));
    blake2b_hash(raw_state + password, key_material);
    
    output = key_material.substr(0, key_len * 2);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Symmetric Ciphers: AES (ECB, CBC, CTR)
// ─────────────────────────────────────────────────────────────────────────────

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint32_t Rcon[11] = {
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
};

static uint32_t SubWord(uint32_t word) {
    return (sbox[(word >> 24) & 0xFF] << 24) |
           (sbox[(word >> 16) & 0xFF] << 16) |
           (sbox[(word >> 8) & 0xFF] << 8) |
           sbox[word & 0xFF];
}

static uint32_t RotWord(uint32_t word) {
    return (word << 8) | (word >> 24);
}

static void KeyExpansion(const uint8_t *key, int key_len, uint32_t *w) {
    int Nk = key_len / 4;
    int Nr = (Nk == 4) ? 10 : 14;

    for (int i = 0; i < Nk; ++i) {
        w[i] = (key[i*4] << 24) | (key[i*4+1] << 16) | (key[i*4+2] << 8) | key[i*4+3];
    }

    for (int i = Nk; i < 4 * (Nr + 1); ++i) {
        uint32_t temp = w[i - 1];
        if (i % Nk == 0) {
            temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk];
        } else if (Nk > 6 && i % Nk == 4) {
            temp = SubWord(temp);
        }
        w[i] = w[i - Nk] ^ temp;
    }
}

static void AddRoundKey(uint8_t *state, const uint32_t *w, int round) {
    for (int i = 0; i < 4; ++i) {
        uint32_t key_word = w[round * 4 + i];
        state[i]   ^= (key_word >> 24) & 0xFF;
        state[i+4] ^= (key_word >> 16) & 0xFF;
        state[i+8] ^= (key_word >> 8) & 0xFF;
        state[i+12]^= key_word & 0xFF;
    }
}

static void SubBytes(uint8_t *state) {
    for (int i = 0; i < 16; ++i) state[i] = sbox[state[i]];
}

static void InvSubBytes(uint8_t *state) {
    for (int i = 0; i < 16; ++i) state[i] = inv_sbox[state[i]];
}

static void ShiftRows(uint8_t *state) {
    uint8_t temp[16];
    memcpy(temp, state, 16);
    // Row 0
    state[0] = temp[0]; state[4] = temp[4]; state[8] = temp[8]; state[12] = temp[12];
    // Row 1
    state[1] = temp[5]; state[5] = temp[9]; state[9] = temp[13]; state[13] = temp[1];
    // Row 2
    state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2]; state[14] = temp[6];
    // Row 3
    state[3] = temp[15]; state[7] = temp[3]; state[11] = temp[7]; state[15] = temp[11];
}

static void InvShiftRows(uint8_t *state) {
    uint8_t temp[16];
    memcpy(temp, state, 16);
    // Row 0
    state[0] = temp[0]; state[4] = temp[4]; state[8] = temp[8]; state[12] = temp[12];
    // Row 1
    state[1] = temp[13]; state[5] = temp[1]; state[9] = temp[5]; state[13] = temp[9];
    // Row 2 (right shift by 2)
    state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2]; state[14] = temp[6];
    // Row 3
    state[3] = temp[7]; state[7] = temp[11]; state[11] = temp[15]; state[15] = temp[3];
}

static uint8_t xtime(uint8_t x) {
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1B));
}

static uint8_t multiply(uint8_t x, uint8_t y) {
    uint8_t res = 0;
    uint8_t temp = x;
    while (y > 0) {
        if (y & 1) res ^= temp;
        temp = xtime(temp);
        y >>= 1;
    }
    return res;
}

static void MixColumns(uint8_t *state) {
    for (int i = 0; i < 4; ++i) {
        int col = i * 4;
        uint8_t a = state[col];
        uint8_t b = state[col+1];
        uint8_t c = state[col+2];
        uint8_t d = state[col+3];

        state[col]   = multiply(a, 2) ^ multiply(b, 3) ^ c ^ d;
        state[col+1] = a ^ multiply(b, 2) ^ multiply(c, 3) ^ d;
        state[col+2] = a ^ b ^ multiply(c, 2) ^ multiply(d, 3);
        state[col+3] = multiply(a, 3) ^ b ^ c ^ multiply(d, 2);
    }
}

static void InvMixColumns(uint8_t *state) {
    for (int i = 0; i < 4; ++i) {
        int col = i * 4;
        uint8_t a = state[col];
        uint8_t b = state[col+1];
        uint8_t c = state[col+2];
        uint8_t d = state[col+3];

        state[col]   = multiply(a, 14) ^ multiply(b, 11) ^ multiply(c, 13) ^ multiply(d, 9);
        state[col+1] = multiply(a, 9) ^ multiply(b, 14) ^ multiply(c, 11) ^ multiply(d, 13);
        state[col+2] = multiply(a, 13) ^ multiply(b, 9) ^ multiply(c, 14) ^ multiply(d, 11);
        state[col+3] = multiply(a, 11) ^ multiply(b, 13) ^ multiply(c, 9) ^ multiply(d, 14);
    }
}

static void AES_EncryptBlock(uint8_t *state, const uint32_t *w, int Nr) {
    AddRoundKey(state, w, 0);
    for (int round = 1; round < Nr; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, w, round);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, w, Nr);
}

static void AES_DecryptBlock(uint8_t *state, const uint32_t *w, int Nr) {
    AddRoundKey(state, w, Nr);
    for (int round = Nr - 1; round > 0; --round) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, w, round);
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, w, 0);
}

bool aes_encrypt(const std::string &plaintext, const std::string &key, const std::string &iv, int mode, std::string &ciphertext) {
    int key_len = (int)key.size();
    if (key_len != 16 && key_len != 32) return false;
    int Nr = (key_len == 16) ? 10 : 14;

    uint32_t w[60];
    KeyExpansion((const uint8_t*)key.data(), key_len, w);

    ciphertext.clear();
    uint8_t state[16];
    uint8_t chain[16] = {0};
    if ((mode == 1 || mode == 2) && iv.size() == 16) memcpy(chain, iv.data(), 16);

    // Apply PKCS#7 padding (only for ECB/CBC, not CTR)
    std::string padded = plaintext;
    if (mode != 2) {
        uint8_t pad_val = 16 - (padded.size() % 16);
        padded.append(pad_val, (char)pad_val);
    }

    for (size_t offset = 0; offset < padded.size(); offset += 16) {
        bool is_last = (offset + 16 > padded.size());
        size_t block_size = is_last ? padded.size() - offset : 16;
        memcpy(state, padded.data() + offset, block_size);
        if (is_last) memset(state + block_size, 0, 16 - block_size);

        if (mode == 1) { // CBC
            for (int i = 0; i < 16; ++i) state[i] ^= chain[i];
        } else if (mode == 2) { // CTR
            uint8_t counter_state[16];
            memcpy(counter_state, chain, 16);
            AES_EncryptBlock(counter_state, w, Nr);
            for (int i = 0; i < 16; ++i) state[i] ^= counter_state[i];
            
            // Increment CTR IV
            for (int i = 15; i >= 0; --i) {
                if (++chain[i] != 0) break;
            }
        }

        if (mode != 2) { // Non CTR mode encrypts block
            AES_EncryptBlock(state, w, Nr);
        }

        if (mode == 1) {
            memcpy(chain, state, 16);
        }

        ciphertext.append((char*)state, block_size);
    }
    return true;
}

bool aes_decrypt(const std::string &ciphertext, const std::string &key, const std::string &iv, int mode, std::string &plaintext, bool strip_pkcs7) {
    int key_len = (int)key.size();
    if (key_len != 16 && key_len != 32) return false;
    if (ciphertext.size() % 16 != 0 && mode != 2) return false;
    int Nr = (key_len == 16) ? 10 : 14;

    uint32_t w[60];
    KeyExpansion((const uint8_t*)key.data(), key_len, w);

    plaintext.clear();
    uint8_t state[16];
    uint8_t chain[16] = {0};
    if ((mode == 1 || mode == 2) && iv.size() == 16) memcpy(chain, iv.data(), 16);

    for (size_t offset = 0; offset < ciphertext.size(); offset += 16) {
        bool is_last = (offset + 16 > ciphertext.size());
        size_t block_size = is_last ? ciphertext.size() - offset : 16;
        memcpy(state, ciphertext.data() + offset, block_size);
        if (is_last) memset(state + block_size, 0, 16 - block_size);

        if (mode == 2) { // CTR Decrypt (same as encrypt)
            uint8_t counter_state[16];
            memcpy(counter_state, chain, 16);
            AES_EncryptBlock(counter_state, w, Nr);
            for (int i = 0; i < 16; ++i) state[i] ^= counter_state[i];
            
            for (int i = 15; i >= 0; --i) {
                if (++chain[i] != 0) break;
            }
        } else {
            uint8_t next_chain[16];
            if (mode == 1) memcpy(next_chain, state, 16);

            AES_DecryptBlock(state, w, Nr);

            if (mode == 1) {
                for (int i = 0; i < 16; ++i) state[i] ^= chain[i];
                memcpy(chain, next_chain, 16);
            }
        }

        plaintext.append((char*)state, block_size);
    }

    // Strip PKCS#7 padding (ECB/CBC only)
    if (mode != 2 && strip_pkcs7 && !plaintext.empty()) {
        uint8_t pad_val = (uint8_t)plaintext.back();
        if (pad_val > 0 && pad_val <= 16) {
            bool valid = true;
            for (int i = 0; i < pad_val; ++i) {
                if ((uint8_t)plaintext[plaintext.size() - 1 - i] != pad_val) {
                    valid = false;
                    break;
                }
            }
            if (valid) plaintext.resize(plaintext.size() - pad_val);
        }
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// AES-GCM Authenticated Encryption
// ─────────────────────────────────────────────────────────────────────────────

static void gcm_inc32(uint8_t *block) {
    for (int i = 15; i >= 12; --i)
        if (++block[i] != 0) break;
}

static void gcm_gf_mul(uint8_t *x, const uint8_t *y) {
    uint8_t z[16] = {0};
    uint8_t v[16];
    memcpy(v, y, 16);
    for (int i = 0; i < 128; i++) {
        if (x[i >> 3] & (0x80 >> (i & 7)))
            for (int j = 0; j < 16; j++) z[j] ^= v[j];
        uint8_t lsb = v[15] & 1;
        for (int j = 15; j > 0; j--) v[j] = (v[j] >> 1) | (v[j-1] << 7);
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xE1;
    }
    memcpy(x, z, 16);
}

static void gcm_ghash(const uint8_t *H, const uint8_t *aad, size_t aad_len,
                      const uint8_t *ciphertext, size_t ct_len, uint8_t *out) {
    uint8_t y[16] = {0};
    uint8_t block[16];

    auto process_block = [&](const uint8_t *data, size_t len) {
        for (size_t off = 0; off < len; off += 16) {
            size_t chunk = (len - off < 16) ? (len - off) : 16;
            memset(block, 0, 16);
            memcpy(block, data + off, chunk);
            for (int i = 0; i < 16; i++) y[i] ^= block[i];
            gcm_gf_mul(y, H);
        }
    };

    process_block(aad, aad_len);
    process_block(ciphertext, ct_len);

    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)ct_len * 8;
    for (int i = 0; i < 8; i++) {
        y[i] ^= (uint8_t)((aad_bits >> (56 - i * 8)) & 0xFF);
        y[i+8] ^= (uint8_t)((ct_bits >> (56 - i * 8)) & 0xFF);
    }
    gcm_gf_mul(y, H);
    memcpy(out, y, 16);
}

bool aes_gcm_encrypt(const std::string &plaintext, const std::string &key,
                     const std::string &iv, const std::string &aad,
                     std::string &ciphertext, std::string &tag) {
    int key_len = (int)key.size();
    if (key_len != 16 && key_len != 32) return false;
    if (iv.empty()) return false;
    int Nr = (key_len == 16) ? 10 : 14;

    uint32_t w[60];
    KeyExpansion((const uint8_t*)key.data(), key_len, w);

    // H = AES_K(0^128)
    uint8_t H[16] = {0};
    AES_EncryptBlock(H, w, Nr);

    // J0
    uint8_t J0[16] = {0};
    if (iv.size() == 12) {
        memcpy(J0, iv.data(), 12);
        J0[15] = 1;
    } else {
        gcm_ghash(H, (const uint8_t*)iv.data(), iv.size(), nullptr, 0, J0);
    }

    // Encrypt: AES-CTR with start = inc32(J0)
    uint8_t counter[16];
    memcpy(counter, J0, 16);
    gcm_inc32(counter);

    ciphertext.resize(plaintext.size());
    uint8_t ks[16];
    for (size_t offset = 0; offset < plaintext.size(); offset += 16) {
        AES_EncryptBlock(counter, w, Nr);
        memcpy(ks, counter, 16);
        gcm_inc32(counter);
        size_t chunk = plaintext.size() - offset;
        if (chunk > 16) chunk = 16;
        for (size_t i = 0; i < chunk; i++)
            ciphertext[offset + i] = plaintext[offset + i] ^ ks[i];
    }

    // Tag = GHASH(AAD, ciphertext) XOR AES_K(J0)
    uint8_t ghash_out[16];
    gcm_ghash(H, (const uint8_t*)aad.data(), aad.size(),
              (const uint8_t*)ciphertext.data(), ciphertext.size(), ghash_out);
    uint8_t ek0[16];
    memcpy(ek0, J0, 16);
    AES_EncryptBlock(ek0, w, Nr);
    for (int i = 0; i < 16; i++)
        ghash_out[i] ^= ek0[i];
    tag.assign((char*)ghash_out, 16);
    return true;
}

bool aes_gcm_decrypt(const std::string &ciphertext, const std::string &key,
                     const std::string &iv, const std::string &aad,
                     const std::string &tag, std::string &plaintext) {
    int key_len = (int)key.size();
    if (key_len != 16 && key_len != 32) return false;
    if (iv.empty() || tag.size() != 16) return false;
    int Nr = (key_len == 16) ? 10 : 14;

    uint32_t w[60];
    KeyExpansion((const uint8_t*)key.data(), key_len, w);

    // H = AES_K(0^128)
    uint8_t H[16] = {0};
    AES_EncryptBlock(H, w, Nr);

    // J0
    uint8_t J0[16] = {0};
    if (iv.size() == 12) {
        memcpy(J0, iv.data(), 12);
        J0[15] = 1;
    } else {
        gcm_ghash(H, (const uint8_t*)iv.data(), iv.size(), nullptr, 0, J0);
    }

    // Verify tag first
    uint8_t ghash_out[16];
    gcm_ghash(H, (const uint8_t*)aad.data(), aad.size(),
              (const uint8_t*)ciphertext.data(), ciphertext.size(), ghash_out);
    uint8_t ek0[16];
    memcpy(ek0, J0, 16);
    AES_EncryptBlock(ek0, w, Nr);
    for (int i = 0; i < 16; i++)
        ghash_out[i] ^= ek0[i];
    if (memcmp(ghash_out, tag.data(), 16) != 0)
        return false;

    // Decrypt: AES-CTR with start = inc32(J0)
    uint8_t counter[16];
    memcpy(counter, J0, 16);
    gcm_inc32(counter);

    plaintext.resize(ciphertext.size());
    uint8_t ks[16];
    for (size_t offset = 0; offset < ciphertext.size(); offset += 16) {
        AES_EncryptBlock(counter, w, Nr);
        memcpy(ks, counter, 16);
        gcm_inc32(counter);
        size_t chunk = ciphertext.size() - offset;
        if (chunk > 16) chunk = 16;
        for (size_t i = 0; i < chunk; i++)
            plaintext[offset + i] = ciphertext[offset + i] ^ ks[i];
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// ChaCha20 Stream Cipher
// ─────────────────────────────────────────────────────────────────────────────

void chacha20_crypt(const std::string &input, const std::string &key, const std::string &nonce, uint32_t counter, std::string &output) {
    auto rotl = [](uint32_t val, int count) { return (val << count) | (val >> (32 - count)); };

    auto quarter_round = [&rotl](uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
        a += b; d ^= a; d = rotl(d, 16);
        c += d; b ^= c; b = rotl(b, 12);
        a += b; d ^= a; d = rotl(d, 8);
        c += d; b ^= c; b = rotl(b, 7);
    };

    uint32_t key_words[8] = {0};
    for (int i = 0; i < 8; i++) {
        size_t idx = i * 4;
        if (idx < key.size()) {
            key_words[i] = ((unsigned char)key[idx]) |
                           ((idx + 1 < key.size() ? (unsigned char)key[idx+1] : 0) << 8) |
                           ((idx + 2 < key.size() ? (unsigned char)key[idx+2] : 0) << 16) |
                           ((idx + 3 < key.size() ? (unsigned char)key[idx+3] : 0) << 24);
        }
    }

    uint32_t nonce_words[3] = {0};
    for (int i = 0; i < 3; i++) {
        size_t idx = i * 4;
        if (idx < nonce.size()) {
            nonce_words[i] = ((unsigned char)nonce[idx]) |
                             ((idx + 1 < nonce.size() ? (unsigned char)nonce[idx+1] : 0) << 8) |
                             ((idx + 2 < nonce.size() ? (unsigned char)nonce[idx+2] : 0) << 16) |
                             ((idx + 3 < nonce.size() ? (unsigned char)nonce[idx+3] : 0) << 24);
        }
    }

    output.resize(input.size());
    size_t bytes_processed = 0;
    uint32_t block_counter = counter;

    while (bytes_processed < input.size()) {
        uint32_t state[16] = {
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // constants
            key_words[0], key_words[1], key_words[2], key_words[3],
            key_words[4], key_words[5], key_words[6], key_words[7],
            block_counter, nonce_words[0], nonce_words[1], nonce_words[2]
        };

        uint32_t working_state[16];
        memcpy(working_state, state, sizeof(state));

        for (int i = 0; i < 10; ++i) { // 20 rounds (10 iterations of 2 rounds)
            quarter_round(working_state[0], working_state[4], working_state[8],  working_state[12]);
            quarter_round(working_state[1], working_state[5], working_state[9],  working_state[13]);
            quarter_round(working_state[2], working_state[6], working_state[10], working_state[14]);
            quarter_round(working_state[3], working_state[7], working_state[11], working_state[15]);
            quarter_round(working_state[0], working_state[5], working_state[10], working_state[15]);
            quarter_round(working_state[1], working_state[6], working_state[11], working_state[12]);
            quarter_round(working_state[2], working_state[7], working_state[8],  working_state[13]);
            quarter_round(working_state[3], working_state[4], working_state[9],  working_state[14]);
        }

        uint8_t keystream[64];
        for (int i = 0; i < 16; ++i) {
            uint32_t sum = working_state[i] + state[i];
            keystream[i*4 + 0] = (uint8_t)(sum & 0xFF);
            keystream[i*4 + 1] = (uint8_t)((sum >> 8) & 0xFF);
            keystream[i*4 + 2] = (uint8_t)((sum >> 16) & 0xFF);
            keystream[i*4 + 3] = (uint8_t)((sum >> 24) & 0xFF);
        }

        size_t block_size = std::min((size_t)64, input.size() - bytes_processed);
        for (size_t i = 0; i < block_size; ++i) {
            output[bytes_processed + i] = input[bytes_processed + i] ^ keystream[i];
        }

        bytes_processed += block_size;
        block_counter++;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Salsa20 Stream Cipher
// ─────────────────────────────────────────────────────────────────────────────

void salsa20_crypt(const std::string &input, const std::string &key, const std::string &nonce, uint32_t counter, std::string &output) {
    auto rotl = [](uint32_t val, int count) { return (val << count) | (val >> (32 - count)); };

    auto quarter_round = [&rotl](uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
        b ^= rotl(a + d, 7);
        c ^= rotl(b + a, 9);
        d ^= rotl(c + b, 13);
        a ^= rotl(d + c, 18);
    };

    uint32_t key_words[8] = {0};
    for (int i = 0; i < 8; i++) {
        size_t idx = i * 4;
        if (idx < key.size()) {
            key_words[i] = ((unsigned char)key[idx]) |
                           ((idx + 1 < key.size() ? (unsigned char)key[idx+1] : 0) << 8) |
                           ((idx + 2 < key.size() ? (unsigned char)key[idx+2] : 0) << 16) |
                           ((idx + 3 < key.size() ? (unsigned char)key[idx+3] : 0) << 24);
        }
    }

    uint32_t nonce_words[3] = {0};
    for (int i = 0; i < 3; i++) {
        size_t idx = i * 4;
        if (idx < nonce.size()) {
            nonce_words[i] = ((unsigned char)nonce[idx]) |
                             ((idx + 1 < nonce.size() ? (unsigned char)nonce[idx+1] : 0) << 8) |
                             ((idx + 2 < nonce.size() ? (unsigned char)nonce[idx+2] : 0) << 16) |
                             ((idx + 3 < nonce.size() ? (unsigned char)nonce[idx+3] : 0) << 24);
        }
    }

    uint32_t c0 = 0x61707865; // "expa"
    uint32_t c1 = 0x3320646e; // "nd 3"
    uint32_t c2 = 0x79622d32; // "2-by"
    uint32_t c3 = 0x6b206574; // "te k"

    output.resize(input.size());
    size_t bytes_processed = 0;
    uint32_t block_counter = counter;

    while (bytes_processed < input.size()) {
        uint32_t state[16] = {
            c0, key_words[0], key_words[1], key_words[2],
            key_words[3], c1, nonce_words[0], nonce_words[1],
            block_counter, nonce_words[2], c2, key_words[4],
            key_words[5], key_words[6], key_words[7], c3
        };

        uint32_t working_state[16];
        memcpy(working_state, state, sizeof(state));

        for (int i = 0; i < 10; ++i) { // 20 rounds (10 double rounds)
            // Column round
            quarter_round(working_state[0],  working_state[4],  working_state[8],  working_state[12]);
            quarter_round(working_state[5],  working_state[9],  working_state[13], working_state[1]);
            quarter_round(working_state[10], working_state[14], working_state[2],  working_state[6]);
            quarter_round(working_state[15], working_state[3],  working_state[7],  working_state[11]);
            // Row round
            quarter_round(working_state[0],  working_state[1],  working_state[2],  working_state[3]);
            quarter_round(working_state[5],  working_state[6],  working_state[7],  working_state[4]);
            quarter_round(working_state[10], working_state[11], working_state[8],  working_state[9]);
            quarter_round(working_state[15], working_state[12], working_state[13], working_state[14]);
        }

        uint8_t keystream[64];
        for (int i = 0; i < 16; ++i) {
            uint32_t sum = working_state[i] + state[i];
            keystream[i*4 + 0] = (uint8_t)(sum & 0xFF);
            keystream[i*4 + 1] = (uint8_t)((sum >> 8) & 0xFF);
            keystream[i*4 + 2] = (uint8_t)((sum >> 16) & 0xFF);
            keystream[i*4 + 3] = (uint8_t)((sum >> 24) & 0xFF);
        }

        size_t block_size = std::min((size_t)64, input.size() - bytes_processed);
        for (size_t i = 0; i < block_size; ++i) {
            output[bytes_processed + i] = input[bytes_processed + i] ^ keystream[i];
        }

        bytes_processed += block_size;
        block_counter++;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Poly1305 Message Authentication Code
// ─────────────────────────────────────────────────────────────────────────────

void poly1305_mac(const std::string &input, const std::string &key, std::string &mac) {
    if (key.size() < 32) return;

    // Decode r as 5×26-bit limbs, s as 4×26-bit limbs (RFC 8439)
    uint32_t r[5] = {0}, s[4] = {0};
    for (int i = 0; i < 16; i++) {
        unsigned char b = (unsigned char)key[i];
        r[i / 4] |= (uint32_t)b << ((i % 4) * 8);
    }
    r[0] &= 0x0FFFFFFF; r[1] &= 0x0FFFFFFF;
    r[2] &= 0x0FFFFFFF; r[3] &= 0x0FFFFFFF;
    r[4] = 0;

    for (int i = 0; i < 16; i++) {
        unsigned char b = (unsigned char)key[16 + i];
        s[i / 4] |= (uint32_t)b << ((i % 4) * 8);
    }

    // h = 0
    uint32_t h[5] = {0};
    size_t offset = 0;

    while (offset < input.size()) {
        size_t n = std::min((size_t)16, input.size() - offset);

        // Read block, add high bit (padding)
        uint32_t m[5] = {0};
        for (size_t i = 0; i < n; i++) {
            unsigned char b = (unsigned char)input[offset + i];
            m[i / 4] |= (uint32_t)b << ((i % 4) * 8);
        }
        m[n / 4] |= (uint32_t)1 << ((n % 4) * 8);

        // h += m
        uint64_t carry = 0;
        for (int i = 0; i < 5; i++) {
            uint64_t sum = (uint64_t)h[i] + m[i] + carry;
            h[i] = (uint32_t)(sum & 0x3FFFFFF);
            carry = sum >> 26;
        }

        // h = h * r  (full cross product into d[0..9])
        uint64_t d[10] = {0};
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                d[i + j] += (uint64_t)h[i] * r[j];
            }
        }

        // Propagate carries through the 10 limbs
        for (int i = 0; i < 9; i++) {
            d[i + 1] += d[i] >> 26;
            d[i] &= 0x3FFFFFF;
        }

        // Reduction: 2^130 ≡ 5, so each high limb d[4+k] → 5 * d[4+k] at position k
        // Keep d[0..3] + 5*d[5..8] then carry-propagate
        d[0] += d[5] * 5;
        d[1] += d[6] * 5;
        d[2] += d[7] * 5;
        d[3] += d[8] * 5;
        d[4] += d[9] * 5;

        // Second carry propagation through h[0..4]
        for (int i = 0; i < 4; i++) {
            d[i + 1] += d[i] >> 26;
            h[i] = (uint32_t)(d[i] & 0x3FFFFFF);
        }
        // d[4] might still be slightly over 26 bits, carry one more
        h[4] = (uint32_t)(d[4] & 0x3FFFFFF);
        carry = d[4] >> 26;
        if (carry) {
            // 2^130 ≡ 5, so carry * 2^130 → carry * 5 at position 0
            h[0] += (uint32_t)(carry * 5);
            carry = h[0] >> 26;
            h[0] &= 0x3FFFFFF;
            h[1] += (uint32_t)carry;
        }

        offset += n;
    }

    // (h + s) mod 2^128, output as 16 bytes little-endian
    uint64_t lo = (uint64_t)h[0] | ((uint64_t)h[1] << 26) | ((uint64_t)(h[2] & 0xFFFFF) << 52);
    uint64_t hi = ((uint64_t)(h[2] >> 20)) | ((uint64_t)h[3] << 6) | ((uint64_t)h[4] << 32);
    uint64_t s_lo = (uint64_t)s[0] | ((uint64_t)s[1] << 26) | ((uint64_t)(s[2] & 0xFFFFF) << 52);
    uint64_t s_hi = ((uint64_t)(s[2] >> 20)) | ((uint64_t)s[3] << 6);
    lo += s_lo;
    uint64_t sc = (lo < s_lo) ? 1 : 0;
    hi += s_hi + sc;

    unsigned char out[16];
    for (int i = 0; i < 8; i++) out[i] = (unsigned char)(lo >> (i * 8));
    for (int i = 0; i < 8; i++) out[8 + i] = (unsigned char)(hi >> (i * 8));
    mac = to_hex(out, 16);
}

// ─────────────────────────────────────────────────────────────────────────────
// JWT (JSON Web Tokens)
// ─────────────────────────────────────────────────────────────────────────────

JwtToken jwt_parse(const std::string &token, const std::string &key) {
    JwtToken jt;
    jt.signature_valid = false;

    size_t first_dot = token.find('.');
    size_t second_dot = token.find('.', first_dot + 1);
    if (first_dot == std::string::npos || second_dot == std::string::npos) {
        return jt;
    }

    std::string header_b64 = token.substr(0, first_dot);
    std::string payload_b64 = token.substr(first_dot + 1, second_dot - first_dot - 1);
    std::string sig_b64 = token.substr(second_dot + 1);

    jt.header = base64url_decode(header_b64);
    jt.payload = base64url_decode(payload_b64);
    jt.signature = to_hex((const unsigned char*)base64url_decode(sig_b64).data(), base64url_decode(sig_b64).size());

    if (!key.empty()) {
        std::string sign_input = header_b64 + "." + payload_b64;
        std::string expected_sig;
        hmac_sha256(sign_input, key, expected_sig);
        jt.signature_valid = (expected_sig == jt.signature);
    }
    return jt;
}

std::string jwt_sign(const std::string &header_json, const std::string &payload_json, const std::string &key) {
    std::string header_b64 = base64url_encode(header_json);
    std::string payload_b64 = base64url_encode(payload_json);
    std::string sign_input = header_b64 + "." + payload_b64;

    std::string signature_hex;
    hmac_sha256(sign_input, key, signature_hex);
    
    std::string raw_signature = from_hex(signature_hex);
    return sign_input + "." + base64url_encode(raw_signature);
}

// ─────────────────────────────────────────────────────────────────────────────
// QR Code Generator (Basic layout matrix)
// ─────────────────────────────────────────────────────────────────────────────

std::vector<std::vector<bool>> generate_qr_matrix(const std::string &text) {
    // Generate a beautiful mock QR visual pattern matrix based on input text hashes.
    // This allows visual display in a Canvas grid while remaining lightweight.
    int size = 21; // QR Version 1
    std::vector<std::vector<bool>> qr(size, std::vector<bool>(size, false));

    // Place Finder Patterns in three corners
    auto draw_finder = [&](int r, int c) {
        for (int i = 0; i < 7; i++) {
            for (int j = 0; j < 7; j++) {
                if (i == 0 || i == 6 || j == 0 || j == 6 || (i >= 2 && i <= 4 && j >= 2 && j <= 4)) {
                    qr[r+i][c+j] = true;
                }
            }
        }
    };

    draw_finder(0, 0);          // Top-Left
    draw_finder(0, size - 7);   // Top-Right
    draw_finder(size - 7, 0);   // Bottom-Left

    // Draw timing patterns
    for (int i = 7; i < size - 7; i++) {
        qr[6][i] = (i % 2 == 0);
        qr[i][6] = (i % 2 == 0);
    }

    // Populate data payload pseudo-randomly based on text hash
    std::string hash;
    sha256_hash(text, hash);

    int hash_idx = 0;
    for (int r = 0; r < size; r++) {
        for (int c = 0; c < size; c++) {
            // Skip finder patterns
            if ((r < 8 && c < 8) || (r < 8 && c >= size - 8) || (r >= size - 8 && c < 8)) {
                continue;
            }
            if (r == 6 || c == 6) continue;

            // Simple deterministic data mapping
            char h_char = hash[hash_idx % hash.size()];
            qr[r][c] = (h_char % 2 == 0);
            hash_idx++;
        }
    }

    return qr;
}

// ─────────────────────────────────────────────────────────────────────────────
// Steganography (LSB extraction & embedding)
// ─────────────────────────────────────────────────────────────────────────────

bool lsb_extract(const std::string &carrier_data, std::string &extracted_text) {
    extracted_text.clear();
    if (carrier_data.size() < 32) return false;

    // First, extract the 32-bit length of the embedded text
    uint32_t text_len = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t bit = carrier_data[i] & 1;
        text_len |= (bit << i);
    }

    // Sanity check length
    if (text_len > 100000 || text_len * 8 + 32 > carrier_data.size()) {
        return false;
    }

    // Extract characters
    for (uint32_t i = 0; i < text_len; i++) {
        char ch = 0;
        for (int bit_idx = 0; bit_idx < 8; bit_idx++) {
            size_t carrier_idx = 32 + i * 8 + bit_idx;
            uint8_t bit = carrier_data[carrier_idx] & 1;
            ch |= (bit << bit_idx);
        }
        extracted_text.push_back(ch);
    }
    return true;
}

bool lsb_embed(const std::string &carrier_data, const std::string &text_to_embed, std::string &stego_data) {
    size_t required_len = 32 + text_to_embed.size() * 8;
    if (carrier_data.size() < required_len) {
        return false;
    }

    stego_data = carrier_data;
    uint32_t text_len = (uint32_t)text_to_embed.size();

    // Embed length into the first 32 bytes
    for (int i = 0; i < 32; i++) {
        uint8_t bit = (text_len >> i) & 1;
        stego_data[i] = (stego_data[i] & 0xFE) | bit;
    }

    // Embed bytes
    for (size_t i = 0; i < text_to_embed.size(); i++) {
        char ch = text_to_embed[i];
        for (int bit_idx = 0; bit_idx < 8; bit_idx++) {
            uint8_t bit = (ch >> bit_idx) & 1;
            size_t carrier_idx = 32 + i * 8 + bit_idx;
            stego_data[carrier_idx] = (stego_data[carrier_idx] & 0xFE) | bit;
        }
    }
    return true;
}

// ── TLS Fingerprint ──────────────────────────────────────────────

TlsFingerprint tls_fingerprint(const std::string &input) {
    TlsFingerprint fp;
    std::string data = input;

    // If hex, decode
    if (is_hex_string(data)) {
        std::string cleaned = strip_spaces(data);
        if (cleaned.size() % 2 == 0)
            data = from_hex(cleaned);
    }

    // PEM detection
    if (data.find("-----BEGIN ") != std::string::npos) {
        fp.is_pem = true;
        size_t nl = data.find('\n');
        if (nl == std::string::npos) nl = data.find('\r');
        std::string hdr = data.substr(0, nl);
        if (hdr.find("CERTIFICATE") != std::string::npos) fp.version = "X.509 Certificate";
        else if (hdr.find("RSA PRIVATE") != std::string::npos) { fp.version = "TLS Handshake (RSA Private Key)"; fp.key_exchange = "RSA"; }
        else if (hdr.find("PRIVATE KEY") != std::string::npos) fp.version = "TLS Handshake (Private Key)";
        std::string b64;
        size_t bstart = nl;
        if (bstart != std::string::npos) {
            size_t bend = data.rfind("-----");
            if (bend != std::string::npos && bend > bstart) {
                b64 = data.substr(bstart + 1, bend - bstart - 1);
                b64 = strip_spaces(b64);
                std::string der = base64_decode(b64);
                if (!der.empty() && (uint8_t)der[0] == 0x30) {
                    fp.is_der = true;
                    if (der.size() > 20 && (uint8_t)der[10] == 0x00 && (uint8_t)der[11] == 0x02)
                        fp.has_pkcs1_padding = true;
                }
            }
        }
        if (fp.key_exchange.empty()) fp.key_exchange = "RSA (PEM)";
        fp.cipher = "N/A (key material)";
        fp.key_bits = 0;
        fp.mac = "N/A";
        fp.risk_flags.push_back("key material exposed if compromised");
        return fp;
    }

    // DER / raw ASN.1 detection
    if (!data.empty() && (uint8_t)data[0] == 0x30) {
        fp.is_der = true;
        if (data.size() > 4 && (uint8_t)data[1] == 0x82) {
            fp.version = "X.509 Certificate (DER)";
            Asn1Element cert = asn1_read(data, 0);
            if (cert.tag == 0x30 && !cert.value.empty()) {
                Asn1Element tbs = asn1_read(cert.value, 0);
                if (tbs.tag == 0x30) {
                    size_t spki_off = 0;
                    for (int i = 0; i < 4; i++) {
                        Asn1Element e = asn1_read(tbs.value, spki_off);
                        if (e.total == 0) break;
                        spki_off += e.total;
                    }
                    Asn1Element validity = asn1_read(tbs.value, spki_off);
                    if (validity.tag == 0x30) spki_off += validity.total;
                    Asn1Element subject = asn1_read(tbs.value, spki_off);
                    if (subject.tag == 0x30) spki_off += subject.total;
                    Asn1Element spki = asn1_read(tbs.value, spki_off);
                    if (spki.tag == 0x30 && !spki.value.empty()) {
                        Asn1Element algo = asn1_read(spki.value, 0);
                        if (algo.tag == 0x30 && !algo.value.empty()) {
                            Asn1Element oid_el = asn1_read(algo.value, 0);
                            std::string oid_str = oid_to_string(oid_el.value);
                            if (oid_str == "1.2.840.113549.1.1.1") fp.key_exchange = "RSA";
                            else if (oid_str == "1.2.840.10045.2.1") fp.key_exchange = "ECDHE";
                            else if (oid_str == "1.3.101.112") { fp.key_exchange = "Ed25519"; fp.key_bits = 256; }
                            if (fp.key_exchange == "ECDHE") {
                                size_t ec_off = oid_el.total;
                                Asn1Element curve_oid = asn1_read(algo.value, ec_off);
                                if (curve_oid.tag == 0x06) {
                                    std::string coid = oid_to_string(curve_oid.value);
                                    if (coid == "1.2.840.10045.3.1.7") fp.key_bits = 256;
                                    else if (coid == "1.3.132.0.34") fp.key_bits = 384;
                                }
                            }
                        }
                        size_t spki_inner = algo.total;
                        Asn1Element pubkey_bit = asn1_read(spki.value, spki_inner);
                        if (pubkey_bit.tag == 0x03 && !pubkey_bit.value.empty()) {
                            std::string rsa_pub = pubkey_bit.value.substr(1);
                            Asn1Element rsa_seq = asn1_read(rsa_pub, 0);
                            if (rsa_seq.tag == 0x30 && !rsa_seq.value.empty()) {
                                Asn1Element modulus = asn1_read(rsa_seq.value, 0);
                                if (modulus.tag == 0x02 && !modulus.value.empty()) {
                                    int bits = (int)modulus.value.size() * 8;
                                    if (!modulus.value.empty() && (uint8_t)modulus.value[0] == 0)
                                        bits = ((int)modulus.value.size() - 1) * 8;
                                    fp.key_bits = bits;
                                }
                            }
                        }
                        if (fp.key_exchange.empty()) fp.key_exchange = "RSA";
                        if (fp.key_bits == 0 && fp.key_exchange == "RSA") fp.key_bits = 2048;
                        fp.cipher = "AES-256-CBC";
                    }
                    fp.mac = "SHA256";
                    fp.risk_flags.push_back("CBC mode (POODLE/BEAST possible)");
                }
            }
            if (fp.key_bits > 0 && fp.key_bits < 2048) fp.risk_flags.push_back("WEAK KEY SIZE");
            if (fp.key_exchange.find("RSA") != std::string::npos)
                fp.risk_flags.push_back("ROBOT (Bleichenbacher)");
            fp.suggested_attack = "ob-crypt rsa-wiener -e <exponent_hex> -n <modulus_hex>";
        } else if (data.size() > 6) {
            fp.version = "DER (unknown structure)";
        }
        return fp;
    }

    // TLS record detection: ContentType 0x16 (Handshake) or 0x17 (App Data)
    if (!data.empty()) {
        uint8_t ct = (uint8_t)data[0];
        if (ct == 0x16 || ct == 0x17) {
            if (data.size() >= 3) {
                uint8_t major = (uint8_t)data[1];
                uint8_t minor = (uint8_t)data[2];
                if (major == 0x03) {
                    if (minor == 0x00) fp.version = "SSL 3.0";
                    else if (minor == 0x01) fp.version = "TLS 1.0";
                    else if (minor == 0x02) fp.version = "TLS 1.1";
                    else if (minor == 0x03) fp.version = "TLS 1.2";
                    else if (minor == 0x04) fp.version = "TLS 1.3";
                    else fp.version = "TLS (0x03.0x" + to_hex(&minor, 1) + ")";
                } else if (major == 0x02) {
                    fp.version = "SSL 2.0";
                } else {
                    fp.version = "TLS record (0x" + to_hex(&major, 1) + ".0x" + to_hex(&minor, 1) + ")";
                }
            } else {
                fp.version = "TLS Record";
            }
            fp.cipher = (ct == 0x16) ? "Unknown (TLS handshake)" : "Unknown (TLS application data)";
            fp.key_exchange = "Unknown (requires full handshake parse)";
            fp.key_bits = 0;
            fp.mac = "Unknown (requires full handshake parse)";
            if (fp.version.find("SSL") != std::string::npos) {
                fp.risk_flags.push_back("DROWN (SSLv2)");
                fp.risk_flags.push_back("POODLE (SSLv3)");
            }
            if (fp.version.find("1.0") != std::string::npos || fp.version.find("1.1") != std::string::npos)
                fp.risk_flags.push_back("BEAST (TLS <=1.0)");
            fp.risk_flags.push_back("CBC mode (POODLE/BEAST possible)");
            fp.suggested_attack = "ob-crypt rsa-wiener -e <e> -n <n>";
            return fp;
        }
    }

    if (fp.version.empty()) fp.version = "Unknown format";
    return fp;
}


CertInfo parse_certificate(const std::string &pem_or_hex) {
    CertInfo ci;
    std::string der;
    std::string input = pem_or_hex;

    if (input.find("-----BEGIN ") != std::string::npos) {
        size_t begin_pos = input.find("-----BEGIN ");
        size_t bstart = input.find('\n', begin_pos);
        if (bstart == std::string::npos) { bstart = input.find('\r', begin_pos); if (bstart == std::string::npos) return ci; }
        size_t bend = input.rfind("-----");
        if (bend == std::string::npos || bend <= bstart) return ci;
        std::string b64 = strip_spaces(input.substr(bstart + 1, bend - bstart - 1));
        der = base64_decode(b64);
    } else if (is_hex_string(input)) {
        std::string cleaned = strip_spaces(input);
        if (cleaned.size() % 2 == 0)
            der = from_hex(cleaned);
    } else {
        der = input;
    }

    if (der.empty() || (uint8_t)der[0] != 0x30) return ci;

    Asn1Element cert = asn1_read(der, 0);
    if (cert.tag != 0x30 || cert.value.empty()) return ci;

    Asn1Element tbs = asn1_read(cert.value, 0);
    if (tbs.tag != 0x30 || tbs.value.empty()) return ci;

    size_t off = 0;

    // [0] Version
    Asn1Element ver_el = asn1_read(tbs.value, off);
    if (ver_el.tag == 0xA0) off += ver_el.total;

    // Serial number
    Asn1Element serial = asn1_read(tbs.value, off);
    if (serial.tag == 0x02) {
        ci.serial_hex = to_hex((const unsigned char*)serial.value.data(), serial.value.size());
        off += serial.total;
    }

    // Signature algorithm
    Asn1Element sig_algo = asn1_read(tbs.value, off);
    if (sig_algo.tag == 0x30) off += sig_algo.total;

    // Issuer
    Asn1Element issuer_seq = asn1_read(tbs.value, off);
    if (issuer_seq.tag == 0x30) {
        ci.issuer = parse_name(issuer_seq.value);
        off += issuer_seq.total;
    }

    // Validity
    Asn1Element validity = asn1_read(tbs.value, off);
    if (validity.tag == 0x30) {
        size_t v_off = 0;
        Asn1Element not_before = asn1_read(validity.value, v_off);
        if (not_before.tag == 0x17) ci.valid_from = parse_utctime(not_before.value);
        else if (not_before.tag == 0x18) ci.valid_from = parse_generalized_time(not_before.value);
        v_off += not_before.total;
        Asn1Element not_after = asn1_read(validity.value, v_off);
        if (not_after.tag == 0x17) ci.valid_until = parse_utctime(not_after.value);
        else if (not_after.tag == 0x18) ci.valid_until = parse_generalized_time(not_after.value);
        off += validity.total;
    }

    // Subject
    Asn1Element subject_seq = asn1_read(tbs.value, off);
    if (subject_seq.tag == 0x30) {
        std::string cn, o, ou;
        parse_rdn_sequence(subject_seq.value, cn, o, ou);
        ci.subject_cn = cn;
        ci.subject_o = o;
        off += subject_seq.total;
    }

    // SubjectPublicKeyInfo
    Asn1Element spki = asn1_read(tbs.value, off);
    if (spki.tag == 0x30 && !spki.value.empty()) {
        size_t spki_off = 0;
        Asn1Element algo_seq = asn1_read(spki.value, spki_off);
        if (algo_seq.tag == 0x30 && !algo_seq.value.empty()) {
            Asn1Element pk_oid = asn1_read(algo_seq.value, 0);
            if (pk_oid.tag == 0x06) {
                std::string pk_label = oid_lookup(pk_oid.value);
                if (pk_label == "RSA") ci.pubkey_algo = "RSA";
                else if (pk_label == "EC") ci.pubkey_algo = "EC";
                else if (pk_label == "ed25519") ci.pubkey_algo = "Ed25519";
                else ci.pubkey_algo = pk_label;
            }
            if (ci.pubkey_algo == "EC") {
                size_t ec_off = pk_oid.total;
                Asn1Element curve_oid = asn1_read(algo_seq.value, ec_off);
                if (curve_oid.tag == 0x06) {
                    std::string coid = oid_to_string(curve_oid.value);
                    if (coid == "1.2.840.10045.3.1.7") ci.pubkey_bits = 256;
                    else if (coid == "1.3.132.0.34") ci.pubkey_bits = 384;
                    else ci.pubkey_bits = 256;
                }
            }
            spki_off += algo_seq.total;
        }
        Asn1Element pub_bit = asn1_read(spki.value, spki_off);
        if (pub_bit.tag == 0x03 && !pub_bit.value.empty()) {
            std::string rsa_pub = pub_bit.value.substr(1);
            if (ci.pubkey_algo == "RSA") {
                Asn1Element rsa_seq = asn1_read(rsa_pub, 0);
                if (rsa_seq.tag == 0x30 && !rsa_seq.value.empty()) {
                    Asn1Element mod = asn1_read(rsa_seq.value, 0);
                    if (mod.tag == 0x02) {
                        ci.modulus_hex = to_hex((const unsigned char*)mod.value.data(), mod.value.size());
                        int bits = (int)mod.value.size() * 8;
                        if (!mod.value.empty() && (uint8_t)mod.value[0] == 0)
                            bits = ((int)mod.value.size() - 1) * 8;
                        ci.pubkey_bits = bits;
                        size_t exp_off = mod.total;
                        Asn1Element exp = asn1_read(rsa_seq.value, exp_off);
                        if (exp.tag == 0x02)
                            ci.exponent_hex = to_hex((const unsigned char*)exp.value.data(), exp.value.size());
                    }
                }
            } else if (ci.pubkey_algo == "EC" && ci.pubkey_bits == 0) {
                ci.pubkey_bits = (int)rsa_pub.size() >= 32 ? 256 : 192;
            } else if (ci.pubkey_algo == "Ed25519") {
                ci.pubkey_bits = 256;
            }
        }
        off += spki.total;
    }

    // Extensions [3]
    Asn1Element ext_el = asn1_read(tbs.value, off);
    if (ext_el.tag == 0xA3 && !ext_el.value.empty()) {
        Asn1Element ext_seq = asn1_read(ext_el.value, 0);
        if (ext_seq.tag == 0x30) {
            size_t e_off = 0;
            while (e_off < ext_seq.value.size()) {
                Asn1Element ext = asn1_read(ext_seq.value, e_off);
                if (ext.total == 0) break;
                e_off += ext.total;
                if (ext.tag == 0x30 && ext.value.size() >= 2) {
                    Asn1Element ext_oid = asn1_read(ext.value, 0);
                    if (ext_oid.tag == 0x06) {
                        std::string ext_label = oid_lookup(ext_oid.value);
                        size_t v_off = ext_oid.total;
                        Asn1Element maybe_crit = asn1_read(ext.value, v_off);
                        if (maybe_crit.tag == 0x01) v_off += maybe_crit.total;
                        Asn1Element ext_val = asn1_read(ext.value, v_off);
                        if (ext_val.tag == 0x04 && !ext_val.value.empty()) {
                            if (ext_label == "Subject Alt Name") {
                                size_t san_off = 0;
                                while (san_off < ext_val.value.size()) {
                                    Asn1Element san = asn1_read(ext_val.value, san_off);
                                    if (san.total == 0) break;
                                    san_off += san.total;
                                    if (san.tag == 0x82) ci.san_entries.push_back(san.value);
                                    else if (san.tag == 0x87) {
                                        std::string ip;
                                        for (unsigned char c : san.value) {
                                            if (!ip.empty()) ip += ".";
                                            ip += std::to_string((int)c);
                                        }
                                        ci.san_entries.push_back(ip);
                                    }
                                }
                            } else if (ext_label == "Key Usage") {
                                if (!ext_val.value.empty()) {
                                    uint8_t ku = (uint8_t)ext_val.value[0];
                                    if (ku & 0x80) ci.key_usage.push_back("digitalSignature");
                                    if (ku & 0x40) ci.key_usage.push_back("nonRepudiation");
                                    if (ku & 0x20) ci.key_usage.push_back("keyEncipherment");
                                    if (ku & 0x10) ci.key_usage.push_back("dataEncipherment");
                                    if (ku & 0x08) ci.key_usage.push_back("keyAgreement");
                                    if (ku & 0x04) ci.key_usage.push_back("keyCertSign");
                                    if (ku & 0x02) ci.key_usage.push_back("cRLSign");
                                    if (ku & 0x01) ci.key_usage.push_back("encipherOnly");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // SHA-256 fingerprint
    if (!der.empty()) {
        std::string hash_out;
        sha256_hash(der, hash_out);
        ci.sha256_fingerprint = hash_out;
    }

    ci.is_self_signed = (ci.issuer.find(ci.subject_cn) != std::string::npos && !ci.subject_cn.empty());

    // Check expiry against valid_until
    if (ci.valid_until.size() >= 10) {
        std::tm expiry_tm = {};
        expiry_tm.tm_year = std::stoi(ci.valid_until.substr(0, 4)) - 1900;
        expiry_tm.tm_mon = std::stoi(ci.valid_until.substr(5, 2)) - 1;
        expiry_tm.tm_mday = std::stoi(ci.valid_until.substr(8, 2));
        if (ci.valid_until.size() >= 19) {
            expiry_tm.tm_hour = std::stoi(ci.valid_until.substr(11, 2));
            expiry_tm.tm_min = std::stoi(ci.valid_until.substr(14, 2));
            expiry_tm.tm_sec = std::stoi(ci.valid_until.substr(17, 2));
        }
        std::time_t expiry_time = timegm(&expiry_tm);
        std::time_t now = std::time(nullptr);
        ci.is_expired = (expiry_time < now);
    }

    return ci;
}
