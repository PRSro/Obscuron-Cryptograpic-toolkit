#include "../includes/rsa_pss.h"
#include "../includes/modern_ciphers.h"
#include "../includes/bigint.hpp"
#include <NTL/ZZ.h>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdlib>

NTL_CLIENT

// ── MGF1 (Mask Generation Function) ──
static std::string mgf1(const std::string &seed, size_t maskLen, int hash_type) {
    std::string T;
    for (uint32_t counter = 0; T.size() < maskLen; counter++) {
        std::string c_bytes;
        c_bytes += (char)((counter >> 24) & 0xFF);
        c_bytes += (char)((counter >> 16) & 0xFF);
        c_bytes += (char)((counter >> 8) & 0xFF);
        c_bytes += (char)(counter & 0xFF);
        std::string input = seed + c_bytes;
        std::string block;
        if (hash_type == 512) { sha512_hash(input, block); block = from_hex(block); }
        else if (hash_type == 384) { sha384_hash(input, block); block = from_hex(block); }
        else { sha256_hash(input, block); block = from_hex(block); }
        T += block;
    }
    return T.substr(0, maskLen);
}

// ── EMSA-PSS encode ──
static bool emsa_pss_encode(const std::string &mHash, int salt_len,
                            size_t emBits, int hash_type,
                            std::string &EM, std::string &error) {
    size_t hLen = (hash_type == 512) ? 64 : (hash_type == 384) ? 48 : 32;
    if (mHash.size() != hLen) { error = "emsa-pss: hash length mismatch"; return false; }
    if (emBits < hLen * 8 + salt_len * 8 + 9) { error = "emsa-pss: modulus too small"; return false; }
    size_t emLen = (emBits + 7) / 8;
    // Generate random salt
    std::string salt;
    if (salt_len > 0) {
        std::ifstream urand("/dev/urandom", std::ios::binary);
        salt.resize(salt_len);
        urand.read(&salt[0], salt_len);
    }
    // M' = 0x00 00 00 00 00 00 00 00 || mHash || salt
    std::string Mprime(8, '\0');
    Mprime += mHash;
    Mprime += salt;
    // H = Hash(M')
    std::string H;
    if (hash_type == 512) { sha512_hash(Mprime, H); H = from_hex(H); }
    else if (hash_type == 384) { sha384_hash(Mprime, H); H = from_hex(H); }
    else { sha256_hash(Mprime, H); H = from_hex(H); }
    // DB = PS || 0x01 || salt
    size_t psLen = emLen - hLen - salt_len - 2;
    std::string DB(psLen, '\0');
    DB += (char)0x01;
    DB += salt;
    // dbMask = MGF1(H, emLen - hLen - 1)
    std::string dbMask = mgf1(H, emLen - hLen - 1, hash_type);
    // maskedDB = DB XOR dbMask
    for (size_t i = 0; i < dbMask.size(); i++)
        DB[i] ^= dbMask[i];
    // Clear leftmost (8*emLen - emBits) bits of maskedDB[0]
    size_t zeroBits = 8 * emLen - emBits;
    if (zeroBits > 0) {
        unsigned char mask = (unsigned char)(0xFF >> zeroBits);
        DB[0] = (char)((unsigned char)DB[0] & mask);
    }
    // EM = maskedDB || H || 0xBC
    EM = DB + H + (char)0xBC;
    return true;
}

// ── EMSA-PSS verify ──
static bool emsa_pss_verify(const std::string &mHash, const std::string &EM,
                            int salt_len, size_t emBits, int hash_type,
                            bool &valid, std::string &error) {
    valid = false;
    size_t hLen = (hash_type == 512) ? 64 : (hash_type == 384) ? 48 : 32;
    if (mHash.size() != hLen) { error = "emsa-pss: hash length mismatch"; return true; }
    size_t emLen = (emBits + 7) / 8;
    if (EM.size() != emLen) return true;
    if (EM.back() != (char)0xBC) return true;
    std::string maskedDB = EM.substr(0, emLen - hLen - 1);
    std::string H = EM.substr(emLen - hLen - 1, hLen);
    // dbMask = MGF1(H, emLen - hLen - 1)
    std::string dbMask = mgf1(H, emLen - hLen - 1, hash_type);
    // DB = maskedDB XOR dbMask
    for (size_t i = 0; i < dbMask.size(); i++)
        maskedDB[i] ^= dbMask[i];
    // Check leftmost (8*emLen - emBits) bits of DB[0] are 0
    size_t zeroBits = 8 * emLen - emBits;
    if (zeroBits > 0) {
        unsigned char mask = (unsigned char)(0xFF >> zeroBits);
        if (((unsigned char)maskedDB[0] & ~mask) != 0) return true;
    }
    // Check padding
    size_t psLen = emLen - hLen - salt_len - 2;
    for (size_t i = 0; i < psLen; i++)
        if ((unsigned char)maskedDB[i] != 0) return true;
    if ((unsigned char)maskedDB[psLen] != 0x01) return true;
    std::string salt = maskedDB.substr(psLen + 1, salt_len);
    // M' = 0x00...00 || mHash || salt
    std::string Mprime(8, '\0');
    Mprime += mHash;
    Mprime += salt;
    std::string H2;
    if (hash_type == 512) { sha512_hash(Mprime, H2); H2 = from_hex(H2); }
    else if (hash_type == 384) { sha384_hash(Mprime, H2); H2 = from_hex(H2); }
    else { sha256_hash(Mprime, H2); H2 = from_hex(H2); }
    valid = (H == H2);
    return true;
}

// ── RSA-PSS API ──

bool rsa_pss_keygen(int bits,
                    std::string &n_hex, std::string &e_hex, std::string &d_hex,
                    std::string &error) {
    if (bits < 512 || bits > 16384) { error = "rsa-pss: bits must be 512-16384"; return false; }
    int half = bits / 2;
    ZZ p, q, n, phi, e = conv<ZZ>(65537), d, unused;
    // Generate p, q
    bool found = false;
    for (int attempt = 0; attempt < 100 && !found; attempt++) {
        GenPrime(p, half, 50);
        GenPrime(q, half, 50);
        if (p == q) continue;
        if (p < q) { ZZ t = p; p = q; q = t; }
        n = p * q;
        if (NumBits(n) != (long)bits) continue;
        phi = (p - 1) * (q - 1);
        if (GCD(e, phi) != 1) continue;
        d = InvMod(e, phi);
        found = true;
    }
    if (!found) { error = "rsa-pss_keygen: failed to generate primes"; return false; }
    std::stringstream ss_n, ss_e, ss_d;
    ss_n << n; n_hex = ss_n.str();
    ss_e << e; e_hex = ss_e.str();
    ss_d << d; d_hex = ss_d.str();
    return true;
}

bool rsa_pss_sign(const std::string &message,
                  const std::string &n_hex_in, const std::string &d_hex_in,
                  int salt_len,
                  std::string &sig_hex,
                  std::string &error) {
    BigInt n = BigInt::from_auto(n_hex_in), d = BigInt::from_auto(d_hex_in);
    size_t modBits = 0;
    BigInt tmp = n;
    while (tmp > BigInt(0)) { tmp = tmp / 2; modBits++; }
    int hash_type = 256;
    if (modBits >= 384 * 8 + 1) hash_type = 512;
    else if (modBits >= 256 * 8 + 1) hash_type = 256;
    size_t hLen = (hash_type == 512) ? 64 : 32;
    // Hash message
    std::string mHash;
    if (hash_type == 512) { sha512_hash(message, mHash); mHash = from_hex(mHash); }
    else if (hash_type == 384) { sha384_hash(message, mHash); mHash = from_hex(mHash); }
    else { sha256_hash(message, mHash); mHash = from_hex(mHash); }
    // EMSA-PSS encode
    std::string EM;
    if (!emsa_pss_encode(mHash, salt_len >= 0 ? salt_len : (int)hLen,
                         modBits - 1, hash_type, EM, error))
        return false;
    // OS2IP
    BigInt m = BigInt::from_bytes(EM);
    // RSA sign: s = m^d mod n
    BigInt s = m.modexp(d, n);
    std::string tmp_sig = s.toHex();
    if (tmp_sig.size() >= 2 && tmp_sig[0] == '0' && (tmp_sig[1] == 'x' || tmp_sig[1] == 'X'))
        sig_hex = tmp_sig.substr(2);
    else
        sig_hex = tmp_sig;
    return true;
}

bool rsa_pss_verify(const std::string &message,
                    const std::string &n_hex_in, const std::string &e_hex_in,
                    const std::string &sig_hex_in,
                    int salt_len,
                    bool &valid,
                    std::string &error) {
    valid = false;
    BigInt n = BigInt::from_auto(n_hex_in), e = BigInt::from_auto(e_hex_in), sig = BigInt::from_auto(sig_hex_in);
    if (sig >= n) return true;
    size_t modBits = 0;
    BigInt tmp = n;
    while (tmp > BigInt(0)) { tmp = tmp / 2; modBits++; }
    int hash_type = 256;
    if (modBits >= 384 * 8 + 1) hash_type = 512;
    else if (modBits >= 256 * 8 + 1) hash_type = 256;
    size_t hLen = (hash_type == 512) ? 64 : 48;
    // RSA verify: m = sig^e mod n
    BigInt m = sig.modexp(e, n);
    std::string EM = m.toBytes();
    // EMSA-PSS verify
    std::string mHash;
    if (hash_type == 512) { sha512_hash(message, mHash); mHash = from_hex(mHash); }
    else if (hash_type == 384) { sha384_hash(message, mHash); mHash = from_hex(mHash); }
    else { sha256_hash(message, mHash); mHash = from_hex(mHash); }
    return emsa_pss_verify(mHash, EM, salt_len >= 0 ? salt_len : (int)hLen,
                          modBits - 1, hash_type, valid, error);
}
