#include "../includes/eddsa.h"
#include "../includes/modern_ciphers.h"
#include <NTL/ZZ.h>
#include <fstream>
#include <cstring>
#include <cstdlib>

NTL_CLIENT

// ── Ed25519 constants ──
// q = 2^255 - 19
static ZZ q() {
    static ZZ v = (conv<ZZ>(1) << 255) - conv<ZZ>(19);
    return v;
}
// d = -121665 * inv(121666) mod q
static ZZ d_coeff() {
    static ZZ v = (q() - (conv<ZZ>(121665) * InvMod(conv<ZZ>(121666), q())) % q()) % q();
    return v;
}
// l = 2^252 + 27742317777372353535851937790883648493
static ZZ l_order() {
    static ZZ v = (conv<ZZ>(1) << 252) + conv<ZZ>("27742317777372353535851937790883648493");
    return v;
}
// Base point B (y coordinate)
static ZZ By_coord() {
    static ZZ v = (conv<ZZ>(4) * InvMod(conv<ZZ>(5), q())) % q();
    return v;
}
// Compute Bx from By
static ZZ Bx_coord() {
    ZZ y = By_coord();
    ZZ y2 = (y * y) % q();
    // x^2 = (y^2 - 1) / (d*y^2 + 1)  [for curve -x^2 + y^2 = 1 + d*x^2*y^2]
    // x^2 = (1 - y^2) / (d*y^2 + 1)  [for curve x^2 + y^2 = 1 + d*x^2*y^2 with a=-1]
    // Actually for edwards curve: a*x^2 + y^2 = 1 + d*x^2*y^2
    // With a = -1: -x^2 + y^2 = 1 + d*x^2*y^2 => x^2 = (y^2 - 1) / (d*y^2 + 1)
    ZZ num = (y2 - 1) % q();
    if (num < 0) num += q();
    ZZ denom = (d_coeff() * y2 + 1) % q();
    ZZ x2 = (num * InvMod(denom, q())) % q();
    // sqrt mod q for q ≡ 5 mod 8
    ZZ exp = (q() + 3) / 8;
    ZZ x = PowerMod(x2, exp, q());
    if ((x * x) % q() != x2) {
        ZZ sqrt_neg = PowerMod(conv<ZZ>(2), (q() - 1) / 4, q());
        x = (PowerMod(x2, (q() + 3) / 8, q()) * sqrt_neg) % q();
    }
    if ((x * x) % q() != x2) {
        static ZZ fallback_Bx = conv<ZZ>("15112221349535800766814251411797820871980701040933997646245335598838263846299");
        return fallback_Bx;
    }
    if ((x % 2) != 0) x = q() - x;
    return x;
}

struct Pt {
    ZZ X, Y, Z, T;
};

static Pt pt_id() {
    Pt p;
    p.X = 0; p.Y = 1; p.Z = 1; p.T = 0;
    return p;
}

static Pt pt_add(const Pt &P, const Pt &Q) {
    ZZ qq = q();
    ZZ A = ((P.Y - P.X) * (Q.Y - Q.X)) % qq;
    ZZ B = ((P.Y + P.X) * (Q.Y + Q.X)) % qq;
    ZZ C = (P.T * Q.T * d_coeff() * 2) % qq;
    ZZ D = (P.Z * Q.Z * 2) % qq;
    ZZ E = (B - A) % qq; if (E < 0) E += qq;
    ZZ F = (D - C) % qq; if (F < 0) F += qq;
    ZZ G = (D + C) % qq;
    ZZ H = (B + A) % qq;
    Pt R;
    R.X = (E * F) % qq;
    R.Y = (G * H) % qq;
    R.T = (E * H) % qq;
    R.Z = (F * G) % qq;
    return R;
}

static Pt pt_dbl(const Pt &P) {
    ZZ qq = q();
    ZZ A = (P.X * P.X) % qq;
    ZZ B = (P.Y * P.Y) % qq;
    ZZ C = (2 * P.Z * P.Z) % qq;
    ZZ D = (qq - A) % qq; // -A mod q
    ZZ E = ((P.X + P.Y) * (P.X + P.Y) - A - B) % qq; if (E < 0) E += qq;
    ZZ G = (D + B) % qq;
    ZZ F = (G - C) % qq; if (F < 0) F += qq;
    ZZ H = (D - B) % qq; if (H < 0) H += qq;
    Pt R;
    R.X = (E * F) % qq;
    R.Y = (G * H) % qq;
    R.T = (E * H) % qq;
    R.Z = (F * G) % qq;
    return R;
}

static Pt pt_mul(const ZZ &scalar, const Pt &P) {
    if (scalar == 0) return pt_id();
    ZZ s = scalar % l_order();
    if (s == 0) return pt_id();
    Pt R = pt_id();
    bool active = false;
    Pt Q = P;
    for (long i = NumBits(s) - 1; i >= 0; i--) {
        if (active) R = pt_dbl(R);
        if (bit(s, i)) {
            if (!active) { R = Q; active = true; }
            else R = pt_add(R, Q);
        }
    }
    return R;
}

static void random_bytes(unsigned char *buf, size_t len) {
    std::ifstream urand("/dev/urandom", std::ios::binary);
    urand.read((char*)buf, len);
}

static std::string hex_from_bytes(const unsigned char *data, size_t len) {
    return to_hex(data, len);
}

static std::string scalar_clamp(const std::string &hash32) {
    unsigned char buf[32];
    memcpy(buf, hash32.data(), 32);
    buf[0] &= 248;
    buf[31] &= 127;
    buf[31] |= 64;
    return std::string((char*)buf, 32);
}

static ZZ decode_scalar(const std::string &bytes) {
    ZZ r = ZZ::zero();
    for (int i = (int)bytes.size() - 1; i >= 0; i--) {
        r *= 256;
        r += (unsigned char)bytes[i];
    }
    return r;
}

static std::string encode_point(const Pt &P, const ZZ &qq) {
    ZZ zi = InvMod(P.Z, qq);
    ZZ x = (P.X * zi) % qq; if (x < 0) x += qq;
    ZZ y = (P.Y * zi) % qq; if (y < 0) y += qq;
    unsigned char buf[32];
    for (int i = 0; i < 32; i++) {
        long byte_val = conv<long>(y % 256);
        buf[i] = (unsigned char)byte_val;
        y /= 256;
    }
    if ((x % 2) != 0)
        buf[31] |= 0x80;
    return std::string((char*)buf, 32);
}


static Pt decode_point(const std::string &bytes, const ZZ &qq) {
    unsigned char buf[32];
    memcpy(buf, bytes.data(), 32);
    bool x_odd = (buf[31] & 0x80) != 0;
    buf[31] &= 0x7F;
    ZZ y = ZZ::zero();
    for (int i = 31; i >= 0; i--) {
        y *= 256;
        y += buf[i];
    }
    ZZ y2 = (y * y) % qq;
    ZZ num = (y2 - 1) % qq; if (num < 0) num += qq;
    ZZ denom = (d_coeff() * y2 + 1) % qq;
    ZZ u = (num * InvMod(denom, qq)) % qq;
    ZZ exp = (qq + 3) / 8;
    ZZ x = PowerMod(u, exp, qq);
    if ((x * x) % qq != u) {
        ZZ sqrt_neg = PowerMod(conv<ZZ>(2), (qq - 1) / 4, qq);
        x = (PowerMod(u, (qq + 3) / 8, qq) * sqrt_neg) % qq;
    }
    if ((x % 2) != (x_odd ? 1 : 0)) x = qq - x;
    Pt P;
    P.X = x; P.Y = y; P.Z = 1;
    P.T = (x * y) % qq;
    return P;
}

// ── Ed25519 API ──

bool ed25519_keygen(std::string &priv_hex, std::string &pub_hex,
                    std::string &) {
    unsigned char seed[32];
    random_bytes(seed, 32);
    std::string seed_str((char*)seed, 32);
    std::string hash;
    sha512_hash(seed_str, hash);
    std::string raw_hash = from_hex(hash);
    std::string clamped = scalar_clamp(raw_hash.substr(0, 32));
    ZZ s = decode_scalar(clamped);
    ZZ qq = q();
    Pt base;
    base.X = Bx_coord(); base.Y = By_coord();
    base.Z = 1; base.T = (base.X * base.Y) % qq;
    Pt pub = pt_mul(s, base);
    std::string pubkey = encode_point(pub, qq);
    priv_hex = hex_from_bytes(seed, 32);
    pub_hex = hex_from_bytes((const unsigned char*)pubkey.data(), 32);
    return true;
}

bool ed25519_sign(const std::string &message,
                  const std::string &priv_hex,
                  std::string &sig_hex,
                  std::string &error) {
    std::string seed = from_hex(priv_hex);
    if (seed.size() != 32) { error = "ed25519: private key must be 32 bytes"; return false; }
    std::string hash;
    sha512_hash(seed, hash);
    std::string raw_hash = from_hex(hash);
    std::string clamped = scalar_clamp(raw_hash.substr(0, 32));
    ZZ s = decode_scalar(clamped);
    std::string prefix = raw_hash.substr(32, 32);
    std::string nonce_input = prefix + message;
    std::string nonce_hash;
    sha512_hash(nonce_input, nonce_hash);
    ZZ nonce = decode_scalar(from_hex(nonce_hash)) % l_order();
    ZZ qq = q();
    Pt base;
    base.X = Bx_coord(); base.Y = By_coord();
    base.Z = 1; base.T = (base.X * base.Y) % qq;
    Pt Rpt = pt_mul(nonce, base);
    std::string R_enc = encode_point(Rpt, qq);
    // Compute public key
    Pt pub = pt_mul(s, base);
    std::string pub_enc = encode_point(pub, qq);
    // h = SHA-512(R_enc + pub_enc + message) mod l
    std::string h_input = R_enc + pub_enc + message;
    std::string h_hash;
    sha512_hash(h_input, h_hash);
    ZZ h_int = decode_scalar(from_hex(h_hash)) % l_order();
    ZZ S = (nonce + h_int * s) % l_order();
    // Encode signature: R_enc (32 bytes) + S (32 bytes, little-endian)
    unsigned char Sbytes[32];
    ZZ Stmp = S;
    for (int i = 0; i < 32; i++) {
        long sb = conv<long>(Stmp % 256);
        Sbytes[i] = (unsigned char)sb;
        Stmp /= 256;
    }
    std::string sig = R_enc + std::string((char*)Sbytes, 32);
    sig_hex = hex_from_bytes((const unsigned char*)sig.data(), 64);
    return true;
}

bool ed25519_verify(const std::string &message,
                    const std::string &pub_hex,
                    const std::string &sig_hex,
                    bool &valid,
                    std::string &error) {
    valid = false;
    std::string sig = from_hex(sig_hex);
    if (sig.size() != 64) { error = "ed25519: signature must be 64 bytes"; return true; }
    std::string pub = from_hex(pub_hex);
    if (pub.size() != 32) { error = "ed25519: public key must be 32 bytes"; return true; }
    std::string R_enc = sig.substr(0, 32);
    std::string S_enc = sig.substr(32, 32);
    ZZ qq = q();
    ZZ S = decode_scalar(S_enc);
    if (S >= l_order()) return true;
    Pt Rpt = decode_point(R_enc, qq);
    Pt Q = decode_point(pub, qq);
    // h = SHA-512(R_enc + pub + message) mod l
    std::string h_input = R_enc + pub + message;
    std::string h_hash;
    sha512_hash(h_input, h_hash);
    ZZ h_int = decode_scalar(from_hex(h_hash)) % l_order();
    Pt base;
    base.X = Bx_coord(); base.Y = By_coord();
    base.Z = 1; base.T = (base.X * base.Y) % qq;
    // Verify: S*B = R + h*Q
    Pt SB = pt_mul(S, base);
    Pt hQ = pt_mul(h_int, Q);
    Pt RhQ = pt_add(Rpt, hQ);
    ZZ zi_SB = InvMod(SB.Z, qq);
    ZZ SBx = (SB.X * zi_SB) % qq; if (SBx < 0) SBx += qq;
    ZZ SBy = (SB.Y * zi_SB) % qq; if (SBy < 0) SBy += qq;
    ZZ zi_RhQ = InvMod(RhQ.Z, qq);
    ZZ RhQx = (RhQ.X * zi_RhQ) % qq; if (RhQx < 0) RhQx += qq;
    ZZ RhQy = (RhQ.Y * zi_RhQ) % qq; if (RhQy < 0) RhQy += qq;
    valid = (SBx == RhQx && SBy == RhQy);
    return true;
}
