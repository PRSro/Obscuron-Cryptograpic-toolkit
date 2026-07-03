#include "../includes/ecdsa.h"
#include "../includes/modern_ciphers.h"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <fstream>
#include <cstdlib>
#include <cstring>

NTL_CLIENT

struct CurveDef {
    const char *name;
    const char *p;
    const char *a;
    const char *b;
    const char *Gx;
    const char *Gy;
    const char *n;
    int hlen;
};

static const CurveDef CURVES[] = {
    {
        "secp256k1",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        "0",
        "7",
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        32
    },
    {
        "P-256",
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        32
    },
    {
        "P-384",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        48
    },
    {nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, 0}
};

static const CurveDef *find_curve(const std::string &name) {
    for (int i = 0; CURVES[i].name != nullptr; i++)
        if (name == CURVES[i].name) return &CURVES[i];
    return nullptr;
}

static ZZ zz_hex(const char *hex) {
    if (!hex || !*hex) return ZZ::zero();
    std::string s = hex;
    ZZ r = ZZ::zero();
    for (char c : s) {
        r *= 16;
        if (c >= '0' && c <= '9') r += (c - '0');
        else if (c >= 'a' && c <= 'f') r += (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') r += (c - 'A' + 10);
    }
    return r;
}

static std::string hex_from_zz(const ZZ &z) {
    if (z == 0) return "0";
    std::string h;
    ZZ tmp = z;
    while (tmp > 0) {
        long d = conv<long>(tmp % 16);
        if (d < 10) h = char('0' + d) + h;
        else h = char('A' + d - 10) + h;
        tmp /= 16;
    }
    return h;
}

static void random_bytes(unsigned char *buf, size_t len) {
    std::ifstream urand("/dev/urandom", std::ios::binary);
    urand.read((char*)buf, len);
}

static ZZ random_zz_mod(const ZZ &mod) {
    long bits = NumBits(mod);
    ZZ r;
    do {
        unsigned char buf[64];
        size_t nbytes = (bits + 7) / 8;
        if (nbytes > 64) nbytes = 64;
        random_bytes(buf, nbytes);
        r = ZZ::zero();
        for (size_t i = 0; i < nbytes; i++) {
            r *= 256;
            r += (long)buf[i];
        }
        r %= mod;
    } while (r == 0);
    return r;
}

static ZZ hash_to_zz(const std::string &msg, const ZZ &n, int hlen) {
    std::string h;
    if (hlen == 32) sha256_hash(msg, h);
    else sha384_hash(msg, h);
    h = from_hex(h);
    size_t blen = h.size() > (size_t)hlen ? (size_t)hlen : h.size();
    ZZ e = ZZ::zero();
    for (size_t i = 0; i < blen; i++) {
        e *= 256;
        e += (unsigned char)h[i];
    }
    e %= n;
    return e;
}

// Proper EC operations using NTL directly
static void point_dbl(const ZZ &x, const ZZ &y, const ZZ &a, const ZZ &p,
                      ZZ &xr, ZZ &yr) {
    ZZ xx = x, yy = y;
    ZZ xsq = (xx * xx) % p; if (xsq < 0) xsq += p;
    ZZ num = (3 * xsq + a) % p; if (num < 0) num += p;
    ZZ den = (2 * yy) % p; if (den < 0) den += p;
    ZZ lam = (num * InvMod(den, p)) % p; if (lam < 0) lam += p;
    ZZ lam_sq = (lam * lam) % p; if (lam_sq < 0) lam_sq += p;
    xr = (lam_sq - 2 * xx) % p; if (xr < 0) xr += p;
    ZZ dx = (xx - xr) % p; if (dx < 0) dx += p;
    ZZ ldx = (lam * dx) % p; if (ldx < 0) ldx += p;
    yr = (ldx - yy) % p; if (yr < 0) yr += p;
}

static bool point_add(const ZZ &x1, const ZZ &y1,
                      const ZZ &x2, const ZZ &y2,
                      const ZZ &a, const ZZ &p,
                      ZZ &xr, ZZ &yr) {
    ZZ xx1 = x1, yy1 = y1, xx2 = x2, yy2 = y2;
    if (xx1 == 0 && yy1 == 0) { xr = xx2; yr = yy2; return true; }
    if (xx2 == 0 && yy2 == 0) { xr = xx1; yr = yy1; return true; }
    if (xx1 == xx2) {
        if (yy1 == yy2) {
            point_dbl(xx1, yy1, a, p, xr, yr);
            return true;
        }
        return false;
    }
    ZZ num = (yy2 - yy1) % p; if (num < 0) num += p;
    ZZ den = (xx2 - xx1) % p; if (den < 0) den += p;
    ZZ lam = (num * InvMod(den, p)) % p; if (lam < 0) lam += p;
    ZZ lam_sq = (lam * lam) % p; if (lam_sq < 0) lam_sq += p;
    xr = (lam_sq - xx1 - xx2) % p; if (xr < 0) xr += p;
    ZZ dx = (xx1 - xr) % p; if (dx < 0) dx += p;
    ZZ ldx = (lam * dx) % p; if (ldx < 0) ldx += p;
    yr = (ldx - yy1) % p; if (yr < 0) yr += p;
    return true;
}

static bool ec_mul(const ZZ &k, const ZZ &Px, const ZZ &Py,
                   const ZZ &a, const ZZ &p,
                   ZZ &Rx, ZZ &Ry) {
    if (k == 0) { Rx = 0; Ry = 0; return true; }
    ZZ rx = ZZ::zero(), ry = ZZ::zero();
    ZZ kk = k;
    for (long i = NumBits(kk) - 1; i >= 0; i--) {
        if (rx != 0 || ry != 0)
            point_dbl(rx, ry, a, p, rx, ry);
        if (bit(kk, i)) {
            if (rx == 0 && ry == 0) {
                rx = Px; ry = Py;
            } else {
                if (!point_add(rx, ry, Px, Py, a, p, rx, ry))
                    return false;
            }
        }
    }
    Rx = rx; Ry = ry;
    return true;
}

// ── ECDSA API ──

bool ecdsa_keygen(const std::string &curve_name,
                  std::string &d_hex,
                  std::string &Qx_hex, std::string &Qy_hex,
                  std::string &error) {
    const CurveDef *c = find_curve(curve_name);
    if (!c) { error = "unknown curve: " + curve_name; return false; }
    ZZ p = zz_hex(c->p), a = zz_hex(c->a);
    ZZ Gx = zz_hex(c->Gx), Gy = zz_hex(c->Gy), n = zz_hex(c->n);
    ZZ d = random_zz_mod(n);
    ZZ Qx, Qy;
    if (!ec_mul(d, Gx, Gy, a, p, Qx, Qy)) {
        error = "ecdsa_keygen: point multiplication failed";
        return false;
    }
    d_hex = hex_from_zz(d);
    Qx_hex = hex_from_zz(Qx);
    Qy_hex = hex_from_zz(Qy);
    return true;
}

bool ecdsa_sign(const std::string &message,
                const std::string &d_hex_in,
                const std::string &curve_name,
                std::string &r_hex, std::string &s_hex,
                std::string &error) {
    const CurveDef *c = find_curve(curve_name);
    if (!c) { error = "unknown curve: " + curve_name; return false; }
    ZZ p = zz_hex(c->p), a = zz_hex(c->a);
    ZZ Gx = zz_hex(c->Gx), Gy = zz_hex(c->Gy), n = zz_hex(c->n);
    ZZ d = zz_hex(d_hex_in.c_str());
    if (d == 0 || d >= n) { error = "ecdsa_sign: invalid private key"; return false; }
    ZZ e = hash_to_zz(message, n, c->hlen);
    int attempts = 0;
    ZZ r, s, k, Rx, Ry;
    do {
        if (++attempts > 1000) { error = "ecdsa_sign: too many attempts"; return false; }
        k = random_zz_mod(n);
        if (!ec_mul(k, Gx, Gy, a, p, Rx, Ry)) {
            error = "ecdsa_sign: point multiplication failed";
            return false;
        }
        r = Rx % n;
    } while (r == 0);
    ZZ_p::init(n);
    ZZ_p k_p = to_ZZ_p(k);
    ZZ_p r_p = to_ZZ_p(r);
    ZZ_p d_p = to_ZZ_p(d);
    ZZ_p e_p = to_ZZ_p(e);
    s = rep(inv(k_p) * (e_p + r_p * d_p));
    if (s == 0) {
        ZZ_p s_p2 = to_ZZ_p(s);
        s_p2 = inv(k_p) * (e_p + r_p * d_p);
        s = rep(s_p2);
        if (s == 0) { error = "ecdsa_sign: s=0"; return false; }
    }
    r_hex = hex_from_zz(r);
    s_hex = hex_from_zz(s);
    return true;
}

bool ecdsa_verify(const std::string &message,
                  const std::string &Qx_hex_in, const std::string &Qy_hex_in,
                  const std::string &r_hex_in, const std::string &s_hex_in,
                  const std::string &curve_name,
                  bool &valid,
                  std::string &error) {
    valid = false;
    const CurveDef *c = find_curve(curve_name);
    if (!c) { error = "unknown curve: " + curve_name; return false; }
    ZZ p = zz_hex(c->p), a = zz_hex(c->a);
    ZZ Gx = zz_hex(c->Gx), Gy = zz_hex(c->Gy), n = zz_hex(c->n);
    ZZ Qx = zz_hex(Qx_hex_in.c_str());
    ZZ Qy = zz_hex(Qy_hex_in.c_str());
    ZZ r = zz_hex(r_hex_in.c_str());
    ZZ s = zz_hex(s_hex_in.c_str());
    if (r < 1 || r >= n || s < 1 || s >= n) return true;
    ZZ e = hash_to_zz(message, n, c->hlen);
    ZZ_p::init(n);
    ZZ_p s_p = to_ZZ_p(s);
    ZZ_p w = inv(s_p);
    ZZ u1 = rep(to_ZZ_p(e) * w);
    ZZ u2 = rep(to_ZZ_p(r) * w);
    ZZ R1x, R1y, R2x, R2y, Rx, Ry;
    if (!ec_mul(u1, Gx, Gy, a, p, R1x, R1y)) return true;
    if (!ec_mul(u2, Qx, Qy, a, p, R2x, R2y)) return true;
    if (!point_add(R1x, R1y, R2x, R2y, a, p, Rx, Ry)) return true;
    if (Rx == 0 && Ry == 0) return true;
    valid = ((Rx % n) == r);
    return true;
}
