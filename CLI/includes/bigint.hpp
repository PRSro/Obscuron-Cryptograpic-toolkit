#include <vector>
#include <cstdint>
#include <string>
#include <ostream>

class BigInt {
public:
    std::vector<uint32_t> limbs;
    bool negative;
    BigInt():negative(false) { limbs.push_back(0); }
    BigInt(uint64_t val):negative(false) {
        if (val==0) {limbs.push_back(0); return;}
        while (val>0) {
            limbs.push_back((uint32_t)(val&0xFFFFFFFF));
            val>>=32;
        }
    }
    BigInt(bool neg, std::vector<uint32_t> l) : negative(neg), limbs(l) {}
    BigInt(const std::string& str);
    BigInt operator+(const BigInt& other) const;
    BigInt operator-(const BigInt& other) const;
    BigInt operator*(const BigInt& other) const;
    BigInt operator/(const BigInt& other) const;
    BigInt operator%(const BigInt& other) const;
    bool operator==(const BigInt& other) const;
    bool operator!=(const BigInt& other) const;
    bool operator< (const BigInt& other) const;
    bool operator> (const BigInt& other) const;
    bool operator<=(const BigInt& other) const;
    bool operator>=(const BigInt& other) const;
    std::string toString() const;
    std::string toBase(int base, const std::string& alphabet = "") const;
    static BigInt from_base(const std::string& str, int base, const std::string& alphabet = "");
    std::string toHex() const;
    std::string toBytes() const;
    friend std::ostream& operator<<(std::ostream& os, const BigInt& n);
    BigInt modexp(const BigInt& exp, const BigInt& mod) const;
    BigInt modinv(const BigInt& mod) const;
    static BigInt crt(const std::vector<BigInt>& remainders,
                      const std::vector<BigInt>& moduli);
    static BigInt from_hex(const std::string& hex);
    static BigInt from_auto(const std::string& s);
    static BigInt from_bytes(const std::string& bytes);
private:
    void trim();
    int  compare(const BigInt& other) const;
    BigInt add_magnitudes(const BigInt& other) const;
    BigInt sub_magnitudes(const BigInt& other) const;
    static std::pair<BigInt,BigInt> divmod_internal(const BigInt& a, const BigInt& b);
};

BigInt rsa_decrypt(const BigInt& c, const BigInt& d, const BigInt& n);
BigInt rsa_compute_d(const BigInt& p, const BigInt& q, const BigInt& e);
BigInt rsa_crt_decrypt(const BigInt& c,
                       const BigInt& p, const BigInt& q,
                       const BigInt& dp, const BigInt& dq,
                       const BigInt& qinv);
