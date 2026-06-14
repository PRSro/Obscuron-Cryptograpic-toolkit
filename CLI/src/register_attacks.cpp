#include "../includes/register_handlers.h"
#include "../includes/modern_ciphers.h"
#include "../includes/bigint.hpp"
#include "../includes/ntl_bridge.h"
#include <NTL/ZZ.h>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <algorithm>
#include <thread>
#include <future>
#include <chrono>
#include <set>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <cmath>
#include <climits>
#include <array>
#include <fstream>
#include <iomanip>
#include <NTL/ZZ_p.h>

NTL_CLIENT

static ZZ zz_from_hex(const std::string &s) {
    std::string h = s;
    if (h.empty()) return ZZ::zero();
    ZZ r = ZZ::zero();
    for (size_t i = 0; i < h.size(); i++) {
        r *= 16;
        char c = h[i];
        if (c >= '0' && c <= '9')       r += (c - '0');
        else if (c >= 'a' && c <= 'f')  r += (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')  r += (c - 'A' + 10);
    }
    return r;
}

static std::string zz_to_hex(const ZZ &z) {
    if (z == 0) return "0";
    std::string h;
    ZZ tmp = z;
    while (tmp > 0) {
        long d = conv<long>(tmp % 16);
        if (d < 10) h = char('0' + d) + h;
        else        h = char('a' + d - 10) + h;
        tmp /= 16;
    }
    return h;
}

static std::string strip_0x(const std::string &s) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        return s.substr(2);
    return s;
}

static std::string hex_encode(const std::string &bytes) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    for (unsigned char c : bytes) {
        out += hex[c >> 4];
        out += hex[c & 0x0f];
    }
    return out;
}

static std::string hex_decode(const std::string &hex) {
    std::string out;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        auto hton = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        };
        out += (char)((hton(hex[i]) << 4) | hton(hex[i+1]));
    }
    return out;
}

static std::string printable_or_hex(const std::string &data) {
    bool printable = true;
    for (unsigned char c : data)
        if (c < 32 && c != '\n' && c != '\t' && c != '\r') { printable = false; break; }
    if (printable) return data;
    return "[hex] " + hex_encode(data);
}

// ── CRC32 table for ZipCrypto ──
static uint32_t crc32_table[256];
static bool crc32_table_init = false;

static void init_crc32_table() {
    if (crc32_table_init) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c >> 1) ^ (0xEDB88320 & ~((c & 1) - 1));
        crc32_table[i] = c;
    }
    crc32_table_init = true;
}

static uint32_t crc32_byte(uint32_t crc, uint8_t b) {
    return (crc >> 8) ^ crc32_table[(crc ^ b) & 0xFF];
}

// ── ZipCrypto keystream byte from key2 ──
static uint8_t zip_keystream_byte(uint32_t key2) {
    uint32_t t = key2 | 3;
    return (uint8_t)((t * (t ^ 1)) >> 8);
}

// ─────────────────────────────────────────────────────────────────────────────
// GF(2^8) helpers for AES
// ─────────────────────────────────────────────────────────────────────────────

// ── Safe endian-independent memory reads (avoids unaligned access on ARM) ──
static uint16_t load16(const char *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t load32(const char *p) { uint32_t v; memcpy(&v, p, 4); return v; }

static uint8_t gf256_mul(uint8_t a, uint8_t b, uint16_t poly) {
    uint8_t res = 0;
    while (b) {
        if (b & 1) res ^= a;
        uint8_t hi = a & 0x80;
        a = (uint8_t)(a << 1);
        if (hi) a ^= (uint8_t)(poly & 0xFF);
        b >>= 1;
    }
    return res;
}

static uint8_t gf256_inv(uint8_t a, uint16_t poly) {
    if (a == 0) return 0;
    uint8_t res = 1;
    uint8_t b = a;
    for (int i = 0; i < 6; i++) {
        b = gf256_mul(b, b, poly);
        res = gf256_mul(res, b, poly);
    }
    return gf256_mul(res, res, poly);
}

// ─────────────────────────────────────────────────────────────────────────────
// Lagrange interpolation over GF(p) for Shamir reconstruction
// ─────────────────────────────────────────────────────────────────────────────

static BigInt lagrange_at_zero(const std::vector<BigInt> &xs, const std::vector<BigInt> &ys, const BigInt &prime) {
    BigInt result(0ULL);
    BigInt one(1ULL);
    for (size_t i = 0; i < xs.size(); i++) {
        BigInt num(1ULL);
        BigInt den(1ULL);
        for (size_t j = 0; j < xs.size(); j++) {
            if (i == j) continue;
            num = (num * (prime - xs[j])) % prime;
            den = (den * (xs[i] - xs[j])) % prime;
        }
        num = (num * ys[i]) % prime;
        BigInt den_inv = den.modinv(prime);
        result = (result + num * den_inv) % prime;
    }
    if (result.negative) result = result + prime;
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Trial division for DH smoothness check
// ─────────────────────────────────────────────────────────────────────────────

static std::vector<uint64_t> trial_factors_small(uint64_t limit) {
    static std::vector<uint64_t> primes;
    if (primes.empty()) {
        std::vector<bool> sieve(limit + 1, true);
        for (uint64_t i = 2; i <= limit; i++) {
            if (sieve[i]) {
                primes.push_back(i);
                for (uint64_t j = i * i; j <= limit; j += i)
                    sieve[j] = false;
            }
        }
    }
    return primes;
}

void register_attack_handlers(HandlerMap &map) {

    // ── 1. AES-ECB block-repeat detector ──
    map["ecb-detect"] = [](const Context &ctx) {
        std::string input;
        if (ctx.has("--hex"))
            input = hex_decode(ctx.flag("--hex"));
        else
            input = ctx.input;

        if (input.size() < 16)
            throw CipherError("ecb-detect: input too short (need at least 16 bytes)");

        size_t n_blocks = input.size() / 16;
        std::map<std::string, std::vector<size_t>> block_map;
        for (size_t i = 0; i < n_blocks; i++) {
            std::string block = input.substr(i * 16, 16);
            block_map[block].push_back(i);
        }

        size_t dup_count = 0;
        std::vector<size_t> dup_offsets;
        for (const auto &kv : block_map) {
            if (kv.second.size() > 1) {
                dup_count += kv.second.size() - 1;
                for (size_t off : kv.second)
                    dup_offsets.push_back(off * 16);
            }
        }

        double ratio = n_blocks > 0 ? (double)dup_count / n_blocks : 0.0;

        if (dup_count > 0) {
            std::cout << "AES-ECB detected: " << dup_count
                      << " repeated 16-byte blocks at offsets [";
            for (size_t i = 0; i < dup_offsets.size(); i++) {
                if (i > 0) std::cout << ", ";
                std::cout << dup_offsets[i];
            }
            std::cout << "]\n";
            std::cout << "Confidence: " << (ratio * 100.0) << "% ("
                      << dup_count << "/" << n_blocks << " blocks duplicated)\n";
        } else {
            std::cout << "No ECB pattern detected (likely CBC/CTR/GCM or not AES)\n";
        }
    };

    // ── 2. CBC Padding Oracle ──
    map["cbc-padding-oracle"] = [](const Context &ctx) {
        std::string c_hex = ctx.flag("-c");
        std::string iv_hex = ctx.flag("-i");
        std::string oracle_cmd = ctx.flag("--oracle");
        int block_size = ctx.opt_int_flag("--block-size", 16);
        int timeout_ms = ctx.opt_int_flag("--timeout-ms", 5000);

        if (block_size != 16)
            throw CipherError("cbc-padding-oracle: only 16-byte blocks supported");

        std::string ciphertext = hex_decode(c_hex);
        std::string iv = hex_decode(iv_hex);

        if (ciphertext.empty() || ciphertext.size() % 16 != 0)
            throw CipherError("cbc-padding-oracle: ciphertext must be non-empty and block-aligned");
        if (iv.size() != 16)
            throw CipherError("cbc-padding-oracle: IV must be exactly 16 bytes");

        auto oracle_query = [&](const std::string &ct_hex, const std::string &iv_hex) -> bool {
            std::string query = ct_hex + ":" + iv_hex;
            std::string shell_cmd = "echo '" + query + "' | " + oracle_cmd;
            auto future = std::async(std::launch::async, [&shell_cmd]() -> int {
                FILE *fp = popen(shell_cmd.c_str(), "r");
                if (!fp) return -1;
                std::string result;
                char buf[256];
                while (fgets(buf, sizeof(buf), fp)) result += buf;
                int rc = pclose(fp);
                return rc;
            });
            if (future.wait_for(std::chrono::milliseconds(timeout_ms))
                == std::future_status::timeout)
                throw CipherError("cbc-padding-oracle: oracle query timed out");
            int rc = future.get();
            return rc == 0;
        };

        size_t n_blocks = ciphertext.size() / 16;
        std::vector<std::string> blocks;
        blocks.push_back(iv);
        for (size_t i = 0; i < n_blocks; i++)
            blocks.push_back(ciphertext.substr(i * 16, 16));

        std::string recovered;
        uint64_t query_count = 0;

        for (size_t b = 1; b < blocks.size(); b++) {
            std::vector<uint8_t> intermediate(16, 0);
            for (int byte_idx = 15; byte_idx >= 0; byte_idx--) {
                uint8_t pad_val = (uint8_t)(16 - byte_idx);
                bool found = false;

                for (int guess = 0; guess < 256; guess++) {
                    if (byte_idx == 15 && guess == 0) continue; // skip 0 for last byte (would be wrong padding)

                    std::string modified_prev(16, 0);
                    for (int k = 15; k > byte_idx; k--)
                        modified_prev[k] = (uint8_t)(intermediate[k] ^ pad_val);
                    modified_prev[byte_idx] = (uint8_t)guess;

                    std::string query_ct = hex_encode(modified_prev + blocks[b]);
                    query_count++;
                    if (oracle_query(query_ct, "")) {
                        intermediate[byte_idx] = (uint8_t)(guess ^ pad_val);
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    if (byte_idx == 15) {
                        intermediate[byte_idx] = (uint8_t)(0x01 ^ 0x01);
                        found = true;
                    } else {
                        throw CipherError("cbc-padding-oracle: failed to recover byte at position "
                                          + std::to_string(byte_idx) + " in block " + std::to_string(b));
                    }
                }
            }

            for (int i = 0; i < 16; i++) {
                recovered += (char)(intermediate[i] ^ (uint8_t)blocks[b-1][i]);
            }
        }

        std::cout << "Recovered plaintext:\n" << printable_or_hex(recovered) << "\n";
        std::cout << "Query count: " << query_count << "\n";
    };

    // ── 3. Hash Length Extension ──
    map["hash-extend"] = [](const Context &ctx) {
        std::string hash_type = ctx.flag("--hash");
        std::string known_hash_hex = ctx.flag("--known-hash");
        int known_len = ctx.int_flag("--known-len");
        std::string append_str = ctx.flag("--append");

        // Build glue padding for the original message of known_len bytes
        auto build_md_padding = [](uint64_t msg_len, bool big_endian) -> std::string {
            std::string pad;
            pad.push_back((char)0x80);
            uint64_t pad_len = 1;
            while ((msg_len + pad_len + 8) % 64 != 0) {
                pad.push_back(0);
                pad_len++;
            }
            uint64_t bit_len = msg_len * 8;
            for (int i = 0; i < 8; i++) {
                int shift = big_endian ? (7 - i) * 8 : i * 8;
                pad.push_back((char)((bit_len >> shift) & 0xFF));
            }
            return pad;
        };

        std::string forged_hash;
        bool ok = false;
        uint64_t processed_bytes;

        std::string padding6 = build_md_padding((uint64_t)known_len, false);
        std::string padding_be = build_md_padding((uint64_t)known_len, true);
        uint64_t glue_len;

        if (hash_type == "md5") {
            glue_len = padding6.size();
            processed_bytes = (uint64_t)known_len + glue_len;
            MD5State st = md5_state_from_hash(known_hash_hex);
            ok = md5_hash_continue(st, processed_bytes, append_str, forged_hash);
            processed_bytes -= glue_len; // for output: total = known + glue + append
        } else if (hash_type == "sha1") {
            glue_len = padding_be.size();
            processed_bytes = (uint64_t)known_len + glue_len;
            SHA1State st = sha1_state_from_hash(known_hash_hex);
            ok = sha1_hash_continue(st, processed_bytes, append_str, forged_hash);
            processed_bytes -= glue_len;
        } else if (hash_type == "sha256") {
            glue_len = padding_be.size();
            processed_bytes = (uint64_t)known_len + glue_len;
            SHA256State st = sha256_state_from_hash(known_hash_hex);
            ok = sha256_hash_continue(st, processed_bytes, append_str, forged_hash);
            processed_bytes -= glue_len;
        } else {
            throw CipherError("hash-extend: unsupported hash type (use md5, sha1, or sha256)");
        }

        if (!ok)
            throw CipherError("hash-extend: hash continuation failed");

        // Build the bytes the attacker appends: glue_padding + append
        std::string attack_bytes;
        if (hash_type == "md5")
            attack_bytes = padding6 + append_str;
        else
            attack_bytes = padding_be + append_str;

        std::cout << "Forged hash: " << forged_hash << "\n";
        std::cout << "Bytes to append (hex): " << hex_encode(attack_bytes) << "\n";
        std::cout << "Total appended length: " << attack_bytes.size() << " bytes\n";
        if (!ctx.raw) std::cout << std::flush;
    };

    // ── 4. ECDSA Nonce Reuse ──
    map["ecdsa-nonce-reuse"] = [](const Context &ctx) {
        std::string r1_hex = strip_0x(ctx.flag("--r1"));
        std::string r2_hex = strip_0x(ctx.opt_flag("--r2", r1_hex));
        std::string s1_hex = strip_0x(ctx.flag("--s1"));
        std::string s2_hex = strip_0x(ctx.flag("--s2"));
        std::string h1_hex = strip_0x(ctx.flag("--h1"));
        std::string h2_hex = strip_0x(ctx.flag("--h2"));
        std::string n_hex = strip_0x(ctx.flag("--n"));

        ZZ r1 = zz_from_hex(r1_hex);
        ZZ r2 = zz_from_hex(r2_hex);
        ZZ s1 = zz_from_hex(s1_hex);
        ZZ s2 = zz_from_hex(s2_hex);
        ZZ h1 = zz_from_hex(h1_hex);
        ZZ h2 = zz_from_hex(h2_hex);
        ZZ n = zz_from_hex(n_hex);

        if (n == 0)
            throw CipherError("ecdsa-nonce-reuse: curve order n must be non-zero");
        if (r1 != r2)
            throw CipherError("ecdsa-nonce-reuse: r values differ — signatures do not share the same nonce");
        ZZ r = r1;

        ZZ_p::init(n);

        ZZ_p r_p = to_ZZ_p(r);
        ZZ_p s1_p = to_ZZ_p(s1);
        ZZ_p s2_p = to_ZZ_p(s2);
        ZZ_p h1_p = to_ZZ_p(h1);
        ZZ_p h2_p = to_ZZ_p(h2);

        // k = (h1 - h2) / (s1 - s2) mod n
        ZZ_p k_p = (h1_p - h2_p) * inv(s1_p - s2_p);
        ZZ k = rep(k_p);

        // d = (s1 * k - h1) / r mod n
        ZZ_p d_p = (s1_p * k_p - h1_p) * inv(r_p);
        ZZ d = rep(d_p);

        std::cout << "Recovered k (hex): " << zz_to_hex(k) << "\n";
        std::cout << "Recovered k (dec): " << k << "\n";
        std::cout << "Recovered private key d (hex): " << zz_to_hex(d) << "\n";
        std::cout << "Recovered private key d (dec): " << d << "\n";
    };

    // ── 5. DH Weak Parameters Check ──
    map["dh-check"] = [](const Context &ctx) {
        std::string g_hex = strip_0x(ctx.flag("--g"));
        std::string p_hex = strip_0x(ctx.flag("--p"));
        std::string pub_a_hex = strip_0x(ctx.opt_flag("--pubkey-a", ""));
        std::string pub_b_hex = strip_0x(ctx.opt_flag("--pubkey-b", ""));
        bool has_pubkeys = !pub_a_hex.empty() && !pub_b_hex.empty();

        ZZ p = zz_from_hex(p_hex);
        ZZ g = zz_from_hex(g_hex);

        if (p == 0)
            throw CipherError("dh-check: modulus p must be non-zero");

        // Check p-1 smoothness: trial factor up to 10^6
        ZZ pm1 = p - 1;
        ZZ remaining = pm1;
        auto primes = trial_factors_small(1000000);

        std::vector<uint64_t> smooth_factors;
        for (uint64_t pr : primes) {
            ZZ pz = ZZ(pr);
            while (remaining % pz == 0) {
                smooth_factors.push_back(pr);
                remaining /= pz;
            }
        }

        bool fully_smooth = (remaining == 1);
        bool partially_smooth = (!smooth_factors.empty());

        std::cout << "p-1 trial factoring (primes up to 10^6):\n";
        std::cout << "  Smooth factors found: " << smooth_factors.size() << "\n";
        if (!smooth_factors.empty()) {
            std::cout << "  Factors: ";
            for (size_t i = 0; i < smooth_factors.size() && i < 50; i++) {
                if (i > 0) std::cout << ", ";
                std::cout << smooth_factors[i];
            }
            if (smooth_factors.size() > 50) std::cout << ", ...";
            std::cout << "\n";
        }
        std::cout << "  Remaining cofactor bits: " << NumBits(remaining) << "\n";

        if (fully_smooth) {
            std::cout << "Assessment: FULLY SMOOTH (p-1 factorization complete)\n";
            if (has_pubkeys) {
                // Attempt Pohlig-Hellman via ntl bridge
                std::string x_hex, err;
                if (ntl_pohlig_hellman(g_hex, pub_a_hex, p_hex, x_hex, err)) {
                    std::cout << "Key recovered via Pohlig-Hellman:\n";
                    std::cout << "  x (hex): " << x_hex << "\n";
                    std::cout << "  x (dec): " << BigInt::from_hex(x_hex).toString() << "\n";
                    std::cout << "Result: BROKEN (fully smooth, key recovered)\n";
                } else {
                    std::cout << "  Pohlig-Hellman failed: " << err << "\n";
                    std::cout << "Result: WEAK (partially smooth)\n";
                }
            } else {
                std::cout << "Result: WEAK (p-1 fully smooth, provide --pubkey-a/--pubkey-b to attempt key recovery)\n";
            }
        } else if (partially_smooth) {
            std::cout << "Result: WEAK (partially smooth)\n";
        } else {
            std::cout << "Result: SAFE (no small factors in p-1 up to 10^6)\n";
        }
    };

    // ── 6. ZipCrypto Known-Plaintext Attack ──
    map["zip-crack"] = [](const Context &ctx) {
        init_crc32_table();

        std::string zip_path = ctx.flag("--zip");
        std::string known_plain = ctx.has("--known") ? ctx.flag("--known")
                                 : ctx.has("--known-hex") ? hex_decode(ctx.flag("--known-hex"))
                                 : "";

        if (known_plain.empty())
            throw CipherError("zip-crack: need --known or --known-hex (at least 12 bytes recommended)");
        if (known_plain.size() < 12)
            throw CipherError("zip-crack: known plaintext too short (need >= 12 bytes)");

        // Read zip file
        std::string zip_data = read_file(zip_path);
        if (zip_data.size() < 30)
            throw CipherError("zip-crack: file too small or not a zip");

        // Parse local file headers
        struct ZipFileEntry {
            std::string filename;
            uint16_t comp_method;
            uint32_t crc32_val;
            uint32_t comp_size;
            uint32_t uncomp_size;
            uint16_t flag;
            size_t data_offset;
            size_t header_offset;
        };

        std::vector<ZipFileEntry> entries;
        size_t pos = 0;

        while (pos + 30 <= zip_data.size()) {
            if ((unsigned char)zip_data[pos] != 0x50 || (unsigned char)zip_data[pos+1] != 0x4B)
                break;
            uint16_t sig = load16(zip_data.data() + pos + 2);
            if (sig != 0x0403) break;

            uint16_t flag = load16(zip_data.data() + pos + 6);
            uint16_t comp_meth = load16(zip_data.data() + pos + 8);
            uint32_t crc32_v = load32(zip_data.data() + pos + 14);
            uint32_t comp_sz = load32(zip_data.data() + pos + 18);
            uint32_t uncomp_sz = load32(zip_data.data() + pos + 22);
            uint16_t name_len = load16(zip_data.data() + pos + 26);
            uint16_t extra_len = load16(zip_data.data() + pos + 28);

            if (pos + 30 + name_len + extra_len > zip_data.size())
                throw CipherError("zip-crack: truncated local file header");

            std::string fname = zip_data.substr(pos + 30, name_len);

            ZipFileEntry entry;
            entry.filename = fname;
            entry.comp_method = comp_meth;
            entry.crc32_val = crc32_v;
            entry.comp_size = comp_sz;
            entry.uncomp_size = uncomp_sz;
            entry.flag = flag;
            entry.header_offset = pos;
            entry.data_offset = pos + 30 + name_len + extra_len;
            entries.push_back(entry);

            if (comp_sz == 0xFFFFFFFF) break;
            pos = entry.data_offset + comp_sz;
        }

        if (entries.empty())
            throw CipherError("zip-crack: no local file entries found");

        // Find an encrypted entry with enough data for our known plaintext
        int target_idx = -1;

        for (size_t ei = 0; ei < entries.size(); ei++) {
            auto &e = entries[ei];
            if (!(e.flag & 1)) continue;

            size_t data_avail = (e.data_offset + e.comp_size <= zip_data.size())
                                ? e.comp_size : (zip_data.size() - e.data_offset);

            if (data_avail >= known_plain.size()) {
                target_idx = (int)ei;
                break;
            }
        }

        if (target_idx < 0)
            throw CipherError("zip-crack: no encrypted entry with enough data for known plaintext");

        auto &target = entries[target_idx];
        const uint8_t *ct_data = (const uint8_t*)(zip_data.data() + target.data_offset);

        // Skip 12-byte ZipCrypto encryption header
        size_t data_skip = 12;
        size_t data_avail = target.comp_size > data_skip ? target.comp_size - data_skip : 0;
        if (data_avail < known_plain.size())
            throw CipherError("zip-crack: not enough data after encryption header for known plaintext");

        // Build keystream from known plaintext (aligned after header)
        std::vector<uint8_t> keystream_bytes(known_plain.size());
        for (size_t i = 0; i < known_plain.size(); i++)
            keystream_bytes[i] = ct_data[data_skip + i] ^ (uint8_t)known_plain[i];

        // ── Key Recovery ──
        // Enumerate key2[0] matching keystream[0]. Then extend through a few
        // positions and verify candidate paths against known plaintext.

        // Keystream byte ks = ((t * (t^1)) >> 8) & 0xFF where t = key2 | 3
        std::cout << "Enumerating key2 candidates (scanning 2^30 values)...\n";
        std::vector<uint32_t> candidates;
        {
            candidates.reserve(4500000);
            for (uint32_t hi = 0; hi < (1u << 30); hi++) {
                uint32_t t = (hi << 2) | 3;
                if ((((t * (t ^ 1)) >> 8) & 0xFF) == keystream_bytes[0]) {
                    candidates.push_back(t);
                }
            }
        }
        std::cout << "Position 0: " << candidates.size() << " key2 candidates\n";
        if (candidates.empty())
            throw CipherError("zip-crack: no key2 matches keystream[0]");

        // Extend through positions 1..3 (4 levels of verification is enough)
        struct Backlink { uint32_t prev; uint8_t k1b; };
        std::unordered_map<uint32_t, Backlink> backlinks;
        size_t max_extend = std::min(size_t(4), known_plain.size());

        for (size_t pos = 1; pos < max_extend; pos++) {
            uint8_t target_ks = keystream_bytes[pos];
            std::unordered_map<uint32_t, Backlink> next_map;
            uint64_t total = 0;

            for (uint32_t cur : candidates) {
                for (int k1b = 0; k1b < 256; k1b++) {
                    uint32_t nxt = crc32_byte(cur, (uint8_t)k1b);
                    uint32_t t = nxt | 3;
                    if ((((t * (t ^ 1)) >> 8) & 0xFF) == target_ks) {
                        if (!next_map.count(nxt))
                            next_map[nxt] = {cur, (uint8_t)k1b};
                        break;  // one k1b per candidate is enough
                    }
                    total++;
                }
            }

            for (auto &kv : next_map)
                backlinks[kv.first] = kv.second;

            candidates.clear();
            for (auto &kv : next_map)
                candidates.push_back(kv.first);

            std::cout << "Position " << pos << ": " << candidates.size() << " candidates (in ~" << (total*5/1000000000) << "s)\n";

            if (candidates.empty())
                throw CipherError("zip-crack: key recovery failed at position " + std::to_string(pos));
        }

        // Verify candidates: trace back each surviving path and decrypt known plaintext
        size_t chain_len = std::min(max_extend, known_plain.size());
        std::vector<uint32_t> verified_keys;
        std::vector<uint8_t> verified_k1b;
        size_t verified_count = 0;

        for (uint32_t final_k2 : candidates) {
            // Reconstruct chain
            std::vector<uint32_t> k2_chain(chain_len);
            std::vector<uint8_t> k1b_chain(chain_len - 1);
            k2_chain[chain_len - 1] = final_k2;
            bool ok = true;
            for (int i = (int)(chain_len - 1); i >= 1 && ok; i--) {
                auto it = backlinks.find(k2_chain[i]);
                if (it == backlinks.end()) { ok = false; break; }
                k2_chain[i - 1] = it->second.prev;
                k1b_chain[i - 1] = it->second.k1b;
            }
            if (!ok) continue;

            // Decrypt and verify
            bool match = true;
            for (size_t i = 0; i < chain_len && match; i++) {
                uint8_t ks = zip_keystream_byte(k2_chain[i]);
                match = ((ct_data[data_skip + i] ^ ks) == (uint8_t)known_plain[i]);
            }
            if (match) {
                verified_keys = k2_chain;
                verified_k1b = k1b_chain;
                verified_count++;
            }
        }

        if (verified_count == 0)
            throw CipherError("zip-crack: no candidate matched known plaintext");

        std::cout << "\nVerified candidates: " << verified_count << "\n";
        if (verified_count > 1) {
            std::cout << "Warning: multiple candidates match; using first.\n";
        }

        // Decrypt: extend the key2 chain through the entire compressed data
        // We have chain_len positions verified. For the remaining bytes, extend
        // by continuing the CRC32 update using the last known k1b.
        size_t total_to_decrypt = std::min(target.comp_size, (uint32_t)(zip_data.size() - target.data_offset));
        size_t decrypt_start = data_skip;
        size_t decrypt_end = std::min(total_to_decrypt, decrypt_start + known_plain.size() * 2); // extra for safety
        if (decrypt_end < decrypt_start + known_plain.size())
            decrypt_end = decrypt_start + known_plain.size();

        std::vector<uint8_t> decrypted;
        decrypted.reserve(decrypt_end - decrypt_start);

        // Re-verify: start by decrypting the known range
        for (size_t i = 0; i < chain_len; i++) {
            uint8_t ks = zip_keystream_byte(verified_keys[i]);
            decrypted.push_back(ct_data[decrypt_start + i] ^ ks);
        }

        // Extend beyond the recovered chain with brute-force k1b
        uint32_t k2_ext = verified_keys.back();
        for (size_t i = chain_len; i < decrypt_end - decrypt_start; i++) {
            // Try all 256 k1b to find one that matches the keystream
            bool found = false;
            for (int k1b = 0; k1b < 256; k1b++) {
                uint32_t nxt = crc32_byte(k2_ext, (uint8_t)k1b);
                uint32_t t = nxt | 3;
                if ((((t * (t ^ 1)) >> 8) & 0xFF) == keystream_bytes[i]) {
                    k2_ext = nxt;
                    uint8_t ks = zip_keystream_byte(k2_ext);
                    decrypted.push_back(ct_data[decrypt_start + i] ^ ks);
                    found = true;
                    break;
                }
            }
            if (!found) break;
        }

        // Verify all decrypted bytes against known plaintext
        bool pt_matches = (decrypted.size() >= known_plain.size());
        for (size_t i = 0; pt_matches && i < known_plain.size(); i++)
            pt_matches = (decrypted[i] == (uint8_t)known_plain[i]);

        std::cout << "\nKnown plaintext match: " << (pt_matches ? "YES" : "NO") << "\n";
        if (!pt_matches)
            std::cout << "Warning: decrypted bytes do not match known plaintext\n";

        std::string pt_str((char*)decrypted.data(), std::min(decrypted.size(), known_plain.size()));
        std::cout << "Decrypted (" << decrypted.size() << " bytes, showing first " << known_plain.size() << "):\n"
                  << printable_or_hex(pt_str) << "\n";

        // Write full output if requested
        if (ctx.has("-o")) {
            std::string out_path = ctx.flag("-o");
            std::ofstream ofs(out_path, std::ios::binary);
            if (!ofs) throw CipherError("zip-crack: cannot write output file");
            ofs.write((const char*)decrypted.data(), decrypted.size());
            std::cout << "Written to: " << out_path << "\n";
        }
    };

    // ── 7. Shamir's Secret Sharing Reconstruction ──
    map["shamir-reconstruct"] = [](const Context &ctx) {
        std::string shares_str = ctx.flag("--shares");
        std::string prime_hex = strip_0x(ctx.flag("--prime"));

        BigInt prime = BigInt::from_hex(prime_hex);

        // Parse shares: "x1:y1,x2:y2,...,xk:yk"
        std::vector<BigInt> xs, ys;
        std::string cur;
        for (char ch : shares_str) {
            if (ch == ',') {
                if (!cur.empty()) {
                    auto colon = cur.find(':');
                    if (colon == std::string::npos)
                        throw CipherError("shamir-reconstruct: invalid share format (expect x:y)");
                    xs.push_back(BigInt::from_auto(cur.substr(0, colon)));
                    ys.push_back(BigInt::from_auto(cur.substr(colon + 1)));
                    cur.clear();
                }
            } else {
                cur += ch;
            }
        }
        if (!cur.empty()) {
            auto colon = cur.find(':');
            if (colon == std::string::npos)
                throw CipherError("shamir-reconstruct: invalid share format (expect x:y)");
            xs.push_back(BigInt::from_auto(cur.substr(0, colon)));
            ys.push_back(BigInt::from_auto(cur.substr(colon + 1)));
        }

        if (xs.size() < 2)
            throw CipherError("shamir-reconstruct: need at least 2 shares");

        BigInt secret = lagrange_at_zero(xs, ys, prime);
        std::string secret_hex = secret.toHex();
        std::string secret_bytes = secret.toBytes();

        std::cout << "Recovered secret (hex): " << secret_hex << "\n";
        std::cout << "Recovered secret (dec): " << secret.toString() << "\n";

        bool printable = true;
        for (unsigned char c : secret_bytes)
            if (c < 32 && c != '\n' && c != '\t') { printable = false; break; }
        if (printable && !secret_bytes.empty())
            std::cout << "Recovered secret (ASCII): " << secret_bytes << "\n";
    };

    // ── 8a. GF(2^8) Multiply ──
    map["gf256-mul"] = [](const Context &ctx) {
        std::string a_hex = ctx.flag("--a");
        std::string b_hex = ctx.flag("--b");
        std::string poly_hex = ctx.opt_flag("--poly", "0x11b");
        poly_hex = strip_0x(poly_hex);

        if (a_hex.size() > 2) a_hex = a_hex.substr(a_hex.size() - 2);
        if (b_hex.size() > 2) b_hex = b_hex.substr(b_hex.size() - 2);

        unsigned long a_val = strtoul(a_hex.c_str(), nullptr, 16);
        unsigned long b_val = strtoul(b_hex.c_str(), nullptr, 16);
        unsigned long poly_val = strtoul(poly_hex.c_str(), nullptr, 16);

        uint8_t result = gf256_mul((uint8_t)a_val, (uint8_t)b_val, (uint16_t)poly_val);

        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)result << std::dec << "\n";
    };

    // ── 8b. GF(2^8) Inverse ──
    map["gf256-inv"] = [](const Context &ctx) {
        std::string a_hex = ctx.flag("--a");
        std::string poly_hex = ctx.opt_flag("--poly", "0x11b");
        poly_hex = strip_0x(poly_hex);

        if (a_hex.size() > 2) a_hex = a_hex.substr(a_hex.size() - 2);

        unsigned long a_val = strtoul(a_hex.c_str(), nullptr, 16);
        unsigned long poly_val = strtoul(poly_hex.c_str(), nullptr, 16);

        uint8_t result = gf256_inv((uint8_t)a_val, (uint16_t)poly_val);

        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)result << std::dec << "\n";
    };
}
