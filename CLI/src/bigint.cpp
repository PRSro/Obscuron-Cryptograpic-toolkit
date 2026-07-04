// bigint.cpp — arbitrary-precision arithmetic for asymmetric crypto (RSA, ECDH).
// For small uint64_t-precision operations use mathutils.cpp instead.
//
// Duplicates: modexp and extended_gcd exist in both this file and mathutils.cpp.
//   bigint.cpp:    BigInt versions    (arbitrary precision)
//   mathutils.cpp: uint64_t versions  (≤64-bit operands)
// RSA callers must use the BigInt versions — uint64_t will overflow silently.

#include "../includes/bigint.hpp"
#include <stdexcept>

void BigInt::trim() {
    while (limbs.size() > 1 && limbs.back() == 0)
        limbs.pop_back();
}

int BigInt::compare(const BigInt& other) const {
    if (limbs.size()!=other.limbs.size())
        return limbs.size()>other.limbs.size()?1:-1;
    int n=limbs.size();
    for (int i=n-1; i>=0; i--) {
        if (limbs[i]!=other.limbs[i])
            return limbs[i]>other.limbs[i]?1:-1;
    }
    return 0;
}

bool BigInt::operator==(const BigInt& other) const {
    return negative == other.negative && compare(other) == 0;
}
bool BigInt::operator!=(const BigInt& other) const {return !(*this==other);}
bool BigInt::operator<(const BigInt& other) const {
    if (negative!=other.negative) return negative;
    return negative?compare(other)>0:compare(other)<0;
}
bool BigInt::operator> (const BigInt& other) const { return other<*this; }
bool BigInt::operator<=(const BigInt& other) const { return !(other<*this); }
bool BigInt::operator>=(const BigInt& other) const { return !(*this<other); }

BigInt BigInt::add_magnitudes(const BigInt& other) const {
    std::vector<uint32_t> result;
    uint64_t carry = 0;
    size_t n = limbs.size() > other.limbs.size() ? limbs.size() : other.limbs.size();
    for (size_t i = 0; i < n || carry; i++) {
        uint64_t sum = carry;
        if (i < limbs.size()) sum+=limbs[i];
        if (i < other.limbs.size()) sum+=other.limbs[i];
        result.push_back((uint32_t)(sum&0xFFFFFFFF));
        carry = sum >> 32;
    }
    return BigInt(false, result);
}

BigInt BigInt::sub_magnitudes(const BigInt& other) const {
    std::vector<uint32_t> result;
    int64_t borrow=0;
    size_t n=limbs.size();
    for (size_t i=0; i<n; i++) {
        int64_t diff = (int64_t)limbs[i]-borrow-(i<other.limbs.size()?other.limbs[i]:0);
        if (diff < 0) { diff += (1LL << 32); borrow = 1; }
        else borrow = 0;
        result.push_back((uint32_t)diff);
    }
    BigInt r(false, result);
    r.trim();
    return r;
}

BigInt BigInt::operator+(const BigInt& other) const {
    if (negative == other.negative) {
        BigInt r = add_magnitudes(other);
        r.negative = negative;
        return r;
    }
    int cmp=compare(other);
    if (cmp==0) return BigInt(0ULL);
    if (cmp>0) {
        BigInt r=sub_magnitudes(other);
        r.negative=negative;
        return r;
    }
    BigInt r=other.sub_magnitudes(*this);
    r.negative=other.negative;
    return r;
}

BigInt BigInt::operator-(const BigInt& other) const {
    BigInt neg_other=other;
    neg_other.negative=!other.negative;
    return *this+neg_other;
}

BigInt BigInt::operator*(const BigInt& other) const {
    std::vector<uint32_t> result(limbs.size() + other.limbs.size(), 0);
    for (size_t i = 0; i < limbs.size(); i++) {
        uint64_t carry = 0;
        for (size_t j = 0; j < other.limbs.size() || carry; j++) {
            uint64_t cur=result[i+j];
            uint64_t mul=(j<other.limbs.size())?(uint64_t)limbs[i]*other.limbs[j]:0;
            cur+=mul+carry;
            result[i+j]=(uint32_t)(cur&0xFFFFFFFF);
            carry=cur>>32;
        }
    }
    BigInt r(negative != other.negative, result);
    r.trim();
    return r;
}

static uint32_t divmod2by1(uint64_t hi, uint64_t lo, uint64_t d, uint64_t& rem) {
    uint64_t n = (hi << 32) | lo;
    uint64_t q = n / d;
    rem = n % d;
    return (uint32_t)q;
}

std::pair<BigInt, BigInt> BigInt::divmod_internal(const BigInt& a, const BigInt& b) {
    BigInt zero(0ULL);

    if (b == zero) throw std::runtime_error("BigInt: division by zero");

    BigInt abs_a = a; abs_a.negative = false;
    BigInt abs_b = b; abs_b.negative = false;

    int cmp = abs_a.compare(abs_b);
    if (cmp < 0) return {zero, abs_a};
    if (cmp == 0) return {BigInt(1ULL), zero};

    if (abs_b.limbs.size() == 1) {
        uint64_t d = abs_b.limbs[0];
        uint64_t rem = 0;
        std::vector<uint32_t> q_limbs(abs_a.limbs.size());
        for (int i = (int)abs_a.limbs.size() - 1; i >= 0; i--) {
            uint64_t cur = (rem << 32) | abs_a.limbs[i];
            q_limbs[i] = (uint32_t)(cur / d);
            rem = cur % d;
        }
        BigInt q(false, q_limbs); q.trim();
        return {q, BigInt(rem)};
    }

    int shift = 0;
    uint32_t msb = abs_b.limbs.back();
    while ((msb & 0x80000000u) == 0) { msb <<= 1; shift++; }

    auto shl = [](const std::vector<uint32_t>& v, int sh) -> std::vector<uint32_t> {
        if (sh == 0) return v;
        std::vector<uint32_t> r(v.size() + 1, 0);
        for (size_t i = 0; i < v.size(); i++) {
            r[i]   |= v[i] << sh;
            r[i+1] |= v[i] >> (32 - sh);
        }
        return r;
    };

    std::vector<uint32_t> v = shl(abs_b.limbs, shift);
    while (!v.empty() && v.back() == 0) v.pop_back();
    int n = (int)v.size();

    std::vector<uint32_t> u = shl(abs_a.limbs, shift);
    while ((int)u.size() <= n) u.push_back(0);
    u.push_back(0);

    int m = (int)u.size() - n - 1;

    std::vector<uint32_t> q_limbs(m + 1, 0);

    uint64_t vn1 = v[n-1];
    uint64_t vn2 = n >= 2 ? v[n-2] : 0;

    for (int j = m; j >= 0; j--) {
        uint64_t u_top = ((uint64_t)u[j+n] << 32) | u[j+n-1];

        uint64_t qhat = u_top / vn1;
        uint64_t rhat = u_top % vn1;

        while (qhat >= (1ULL << 32) ||
               qhat * vn2 > ((rhat << 32) | u[j+n-2])) {
            qhat--;
            rhat += vn1;
            if (rhat >= (1ULL << 32)) break;
        }

        int64_t borrow = 0;
        for (int i = 0; i <= n; i++) {
            uint64_t prod = qhat * (i < n ? v[i] : 0);
            int64_t diff  = (int64_t)u[j+i] - borrow - (int64_t)(prod & 0xFFFFFFFF);
            u[j+i] = (uint32_t)diff;
            borrow = (int64_t)(prod >> 32) - (diff >> 32);
        }

        q_limbs[j] = (uint32_t)qhat;

        if (borrow != 0) {
            q_limbs[j]--;
            uint64_t carry = 0;
            for (int i = 0; i <= n; i++) {
                uint64_t s = (uint64_t)u[j+i] + (i < n ? v[i] : 0) + carry;
                u[j+i] = (uint32_t)s;
                carry   = s >> 32;
            }
        }
    }

    std::vector<uint32_t> r_limbs(n);
    if (shift > 0) {
        for (int i = 0; i < n-1; i++)
            r_limbs[i] = (u[i] >> shift) | (u[i+1] << (32 - shift));
        r_limbs[n-1] = u[n-1] >> shift;
    } else {
        for (int i = 0; i < n; i++) r_limbs[i] = u[i];
    }

    BigInt q(false, q_limbs); q.trim();
    BigInt r(false, r_limbs); r.trim();
    return {q, r};
}

BigInt BigInt::operator/(const BigInt& other) const {
    auto [q, r] = divmod_internal(*this, other);
    q.negative = (negative != other.negative) && !(q == BigInt(0ULL));
    return q;
}

BigInt BigInt::operator%(const BigInt& other) const {
    auto [q, r] = divmod_internal(*this, other);
    if (r != BigInt(0ULL) && negative != other.negative) {
        BigInt abs_other = other; abs_other.negative = false;
        r = abs_other - r;
    }
    r.negative = false;
    return r;
}

std::string BigInt::toString() const {
    if (limbs.size() == 1 && limbs[0] == 0) return "0";

    BigInt val = *this;
    val.negative = false;
    BigInt base(1000000000ULL);

    std::string result;
    while (val > BigInt(0ULL)) {
        auto [q, r] = divmod_internal(val, base);
        uint64_t chunk = r.limbs.size() > 0 ? r.limbs[0] : 0;

        std::string part = std::to_string(chunk);
        if (q != BigInt(0ULL))
            while (part.size() < 9) part = "0" + part;

        result = part + result;
        val = q;
    }

    if (negative) result = "-" + result;
    return result;
}

BigInt::BigInt(const std::string& str) : negative(false) {
    limbs.push_back(0);
    if (str.empty()) return;

    int start = 0;
    if (str[0] == '-') { negative = true; start = 1; }
    else if (str[0] == '+') { start = 1; }

    BigInt ten(10ULL);
    for (int i = start; i < (int)str.size(); i++) {
        if (!isdigit(str[i])) throw std::runtime_error("BigInt: invalid decimal string");
        *this = *this * ten + BigInt((uint64_t)(str[i] - '0'));
    }

    if (limbs.size() == 1 && limbs[0] == 0) negative = false;
}

BigInt BigInt::from_hex(const std::string& hex) {
    std::string h = hex;
    bool neg = false;
    if (!h.empty() && h[0] == '-') { neg = true; h = h.substr(1); }
    if (h.size() >= 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X'))
        h = h.substr(2);

    while (h.size() % 8 != 0) h = "0" + h;

    std::vector<uint32_t> limbs_vec;
    for (int i = (int)h.size() - 8; i >= 0; i -= 8) {
        uint32_t limb = (uint32_t)std::stoul(h.substr(i, 8), nullptr, 16);
        limbs_vec.push_back(limb);
    }

    BigInt r(neg, limbs_vec);
    r.trim();
    return r;
}

BigInt BigInt::from_auto(const std::string& s) {
    std::string h = s;
    if (h.empty()) return BigInt();
    if (h.size() >= 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X'))
        return from_hex(h.substr(2));
    bool has_hex = false;
    for (char c : h) {
        if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            has_hex = true;
            break;
        }
    }
    if (has_hex) return from_hex(h);
    return BigInt(h);
}

std::string BigInt::toHex() const {
    if (limbs.size() == 1 && limbs[0] == 0) return "0x0";
    std::string result;
    for (int i = (int)limbs.size() - 1; i >= 0; i--) {
        char buf[9];
        snprintf(buf, sizeof(buf), "%08x", limbs[i]);
        result += buf;
    }
    size_t start = result.find_first_not_of('0');
    result = (start == std::string::npos) ? "0" : result.substr(start);
    return (negative ? "-0x" : "0x") + result;
}

BigInt BigInt::modexp(const BigInt& exp, const BigInt& mod) const {
    if (mod == BigInt(1ULL)) return BigInt(0ULL);

    BigInt result(1ULL);
    BigInt base = *this % mod;
    BigInt e    = exp;
    BigInt zero(0ULL);
    BigInt two(2ULL);

    while (e > zero) {
        if (e.limbs[0] & 1)
            result = (result * base) % mod;
        e = e / two;
        base = (base * base) % mod;
    }
    return result;
}

static BigInt extended_gcd_big(BigInt a, BigInt b, BigInt& x, BigInt& y) {
    if (b == BigInt(0ULL)) {
        x = BigInt(1ULL); y = BigInt(0ULL);
        return a;
    }
    BigInt x1, y1;
    BigInt g = extended_gcd_big(b, a % b, x1, y1);
    x = y1;
    BigInt q = a / b;
    BigInt sub = q * y1;
    y = x1 - sub;
    return g;
}

BigInt BigInt::modinv(const BigInt& mod) const {
    BigInt x, y;
    BigInt a = *this;
    a.negative = false;
    BigInt m = mod;
    m.negative = false;

    BigInt g = extended_gcd_big(a, m, x, y);

    if (g != BigInt(1ULL))
        throw std::runtime_error("BigInt::modinv: not invertible (gcd != 1)");

    if (x.negative) {
        x.negative = false;
        x = m - x;
    }
    x = x % m;
    return x;
}

BigInt BigInt::crt(const std::vector<BigInt>& remainders,
                   const std::vector<BigInt>& moduli) {
    if (remainders.size() != moduli.size() || remainders.empty())
        throw std::runtime_error("CRT: mismatched inputs");

    BigInt M(1ULL);
    for (const auto& m : moduli) M = M * m;

    BigInt result(0ULL);
    for (size_t i = 0; i < moduli.size(); i++) {
        BigInt Mi = M / moduli[i];
        BigInt inv = Mi.modinv(moduli[i]);
        result = result + remainders[i] * Mi * inv;
    }

    return result % M;
}

BigInt rsa_decrypt(const BigInt& c, const BigInt& d, const BigInt& n) {
    return c.modexp(d, n);
}

BigInt rsa_compute_d(const BigInt& p, const BigInt& q, const BigInt& e) {
    BigInt one(1ULL);
    BigInt pm1 = p - one;
    BigInt qm1 = q - one;

    BigInt x, y;
    BigInt g = extended_gcd_big(pm1, qm1, x, y);
    BigInt lambda = (pm1 / g) * qm1;

    return e.modinv(lambda);
}

BigInt rsa_crt_decrypt(const BigInt& c,
                       const BigInt& p,  const BigInt& q,
                       const BigInt& dp, const BigInt& dq,
                       const BigInt& qinv) {
    BigInt m1 = c.modexp(dp, p);
    BigInt m2 = c.modexp(dq, q);
    BigInt diff = (m1 - m2 + p) % p;
    BigInt h    = (qinv * diff) % p;
    return m2 + q * h;
}

static const std::string BASE_ALPHABET =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "!#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\"";

std::string BigInt::toBase(int base, const std::string& alphabet) const {
    if (base < 2) return "";
    std::string abc = alphabet.empty() ? BASE_ALPHABET.substr(0, base) : alphabet;
    if ((int)abc.size() < base) return "";
    if (limbs.empty()) return std::string(1, abc[0]);
    if (*this == BigInt(0ULL)) return std::string(1, abc[0]);
    BigInt n = *this;
    n.negative = false;
    BigInt base_big((uint64_t)base);
    std::string result;
    while (n > BigInt(0ULL)) {
        auto [q, r] = divmod_internal(n, base_big);
        uint64_t digit = r.limbs.empty() ? 0 : r.limbs[0];
        result = abc[digit] + result;
        n = q;
    }
    return result;
}

BigInt BigInt::from_base(const std::string& str, int base, const std::string& alphabet) {
    if (base < 2)
        throw std::runtime_error("BigInt::from_base: base must be >= 2, got " + std::to_string(base));
    std::string abc = alphabet.empty() ? BASE_ALPHABET.substr(0, base) : alphabet;
    if ((int)abc.size() < base)
        throw std::runtime_error("BigInt::from_base: alphabet length (" + std::to_string(abc.size())
            + ") < base (" + std::to_string(base) + ")");
    BigInt result(0ULL);
    BigInt base_big((uint64_t)base);
    for (char c : str) {
        auto pos = abc.find(c);
        if (pos == std::string::npos)
            throw std::runtime_error("BigInt::from_base: invalid character for base " + std::to_string(base));
        result = result * base_big + BigInt((uint64_t)pos);
    }
    return result;
}

std::string BigInt::toBytes() const {
    std::string result;
    for (int i = (int)limbs.size() - 1; i >= 0; i--) {
        uint32_t limb = limbs[i];
        result += (char)((limb >> 24) & 0xFF);
        result += (char)((limb >> 16) & 0xFF);
        result += (char)((limb >>  8) & 0xFF);
        result += (char)( limb        & 0xFF);
    }
    size_t start = result.find_first_not_of('\0');
    return (start == std::string::npos) ? "" : result.substr(start);
}

BigInt BigInt::from_bytes(const std::string& bytes) {
    std::vector<uint32_t> limbs_vec;
    std::string padded = bytes;
    while (padded.size() % 4 != 0) padded = "\x00" + padded;

    for (int i = (int)padded.size() - 4; i >= 0; i -= 4) {
        uint32_t limb = ((uint8_t)padded[i]   << 24) |
                        ((uint8_t)padded[i+1] << 16) |
                        ((uint8_t)padded[i+2] <<  8) |
                         (uint8_t)padded[i+3];
        limbs_vec.push_back(limb);
    }
    BigInt r(false, limbs_vec);
    r.trim();
    return r;
}

std::ostream& operator<<(std::ostream& os, const BigInt& n) {
    os << n.toString();
    return os;
}
