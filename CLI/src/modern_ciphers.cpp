#include "../includes/modern_ciphers.h"
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

// ── ASN.1 / DER helpers (static) ─────────────────────────────────

struct Asn1Element {
    uint8_t tag;
    std::string value;
    size_t total = 0;
};

static Asn1Element asn1_read(const std::string &der, size_t off) {
    Asn1Element el;
    if (off >= der.size()) return el;
    el.tag = (uint8_t)der[off++];
    el.total = 1;
    if (off >= der.size()) { el.total = 0; return el; }
    uint8_t len_byte = (uint8_t)der[off++];
    el.total++;
    size_t length = 0;
    if (len_byte < 0x80) {
        length = len_byte;
    } else {
        uint8_t num_bytes = len_byte & 0x7F;
        if (num_bytes > 8 || off + num_bytes > der.size()) { el.total = 0; return el; }
        for (uint8_t i = 0; i < num_bytes; i++) {
            length = (length << 8) | (uint8_t)der[off++];
            el.total++;
        }
    }
    if (off + length > der.size()) { el.total = 0; return el; }
    el.value = der.substr(off, length);
    el.total += length;
    return el;
}

static std::string oid_to_string(const std::string &o) {
    if (o.empty()) return "";
    std::string r;
    uint8_t first = (uint8_t)o[0];
    r = std::to_string(first / 40) + "." + std::to_string(first % 40);
    uint64_t val = 0;
    for (size_t i = 1; i < o.size(); i++) {
        uint8_t b = (uint8_t)o[i];
        val = (val << 7) | (b & 0x7F);
        if (!(b & 0x80)) { r += "." + std::to_string(val); val = 0; }
    }
    return r;
}

static std::string parse_utf8_or_string(const std::string &v) {
    return v;
}

static bool is_hex_string(const std::string &s) {
    if (s.empty()) return false;
    for (char c : s) if (!isxdigit((unsigned char)c) && c != ' ' && c != '\n' && c != '\r' && c != '\t') return false;
    return true;
}

static std::string strip_spaces(const std::string &s) {
    std::string r;
    for (char c : s) if (c != ' ' && c != '\n' && c != '\r' && c != '\t') r += c;
    return r;
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

// ── OID table for X.509 parsing ──────────────────────────────────

struct OidEntry { const char *dots; const char *label; };
static const OidEntry OID_TABLE[] = {
    {"2.5.4.3", "CN"},
    {"2.5.4.4", "SN"},
    {"2.5.4.5", "serialNumber"},
    {"2.5.4.6", "C"},
    {"2.5.4.7", "L"},
    {"2.5.4.8", "ST"},
    {"2.5.4.9", "STREET"},
    {"2.5.4.10", "O"},
    {"2.5.4.11", "OU"},
    {"2.5.4.12", "title"},
    {"2.5.4.17", "postalCode"},
    {"2.5.4.42", "GN"},
    {"2.5.4.43", "initials"},
    {"1.2.840.113549.1.9.1", "emailAddress"},
    {"1.2.840.113549.1.1.1", "RSA"},
    {"1.2.840.10045.2.1", "EC"},
    {"1.2.840.113549.1.1.5", "sha1WithRSA"},
    {"1.2.840.113549.1.1.11", "sha256WithRSA"},
    {"1.2.840.113549.1.1.12", "sha384WithRSA"},
    {"1.2.840.113549.1.1.13", "sha512WithRSA"},
    {"1.2.840.10045.4.3.2", "ecdsaWithSHA256"},
    {"1.2.840.10045.4.3.3", "ecdsaWithSHA384"},
    {"1.3.101.112", "ed25519"},
    {"1.3.101.113", "ed448"},
    {"2.5.29.15", "Key Usage"},
    {"2.5.29.17", "Subject Alt Name"},
    {"2.5.29.19", "Basic Constraints"},
    {"2.5.29.37", "Extended Key Usage"},
    {"2.5.29.14", "Subject Key Identifier"},
    {"2.5.29.35", "Authority Key Identifier"},
    {nullptr, nullptr}
};

static std::string oid_lookup(const std::string &oid_bytes) {
    std::string dots = oid_to_string(oid_bytes);
    for (int i = 0; OID_TABLE[i].dots != nullptr; i++) {
        if (dots == OID_TABLE[i].dots) return OID_TABLE[i].label;
    }
    return dots;
}

// ── ASN.1 time helpers ───────────────────────────────────────────

static std::string parse_utctime(const std::string &v) {
    if (v.size() < 11) return v;
    int yy = std::stoi(v.substr(0, 2));
    if (yy < 50) yy += 2000; else yy += 1900;
    return std::to_string(yy) + "-" + v.substr(2, 2) + "-" + v.substr(4, 2) + " " +
           v.substr(6, 2) + ":" + v.substr(8, 2) + ":" + v.substr(10, 2) + " UTC";
}

static std::string parse_generalized_time(const std::string &v) {
    if (v.size() < 13) return v;
    return v.substr(0, 4) + "-" + v.substr(4, 2) + "-" + v.substr(6, 2) + " " +
           v.substr(8, 2) + ":" + v.substr(10, 2) + ":" + v.substr(12, 2) + " UTC";
}

// ── Certificate Parser ───────────────────────────────────────────

static void parse_rdn_sequence(const std::string &seq_val, std::string &cn, std::string &o, std::string &ou) {
    size_t off = 0;
    while (off < seq_val.size()) {
        Asn1Element rdn_set = asn1_read(seq_val, off);
        if (rdn_set.total == 0) break;
        off += rdn_set.total;
        size_t soff = 0;
        while (soff < rdn_set.value.size()) {
            Asn1Element attr_seq = asn1_read(rdn_set.value, soff);
            if (attr_seq.total == 0) break;
            soff += attr_seq.total;
            if (attr_seq.tag == 0x30) {
                Asn1Element oid_el = asn1_read(attr_seq.value, 0);
                if (oid_el.tag == 0x06) {
                    std::string label = oid_lookup(oid_el.value);
                    size_t val_off = oid_el.total;
                    Asn1Element val_el = asn1_read(attr_seq.value, val_off);
                    std::string str_val = parse_utf8_or_string(val_el.value);
                    if (label == "CN") { if (cn.empty()) cn = str_val; }
                    else if (label == "O") { if (o.empty()) o = str_val; }
                    else if (label == "OU") { if (ou.empty()) ou = str_val; }
                }
            }
        }
    }
}

static std::string parse_name(const std::string &seq_val) {
    std::string cn, o, ou;
    parse_rdn_sequence(seq_val, cn, o, ou);
    std::string r;
    if (!cn.empty()) r += "CN=" + cn;
    if (!o.empty()) { if (!r.empty()) r += ", "; r += "O=" + o; }
    if (!ou.empty()) { if (!r.empty()) r += ", "; r += "OU=" + ou; }
    return r.empty() ? "(unable to parse)" : r;
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
