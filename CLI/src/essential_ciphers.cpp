#include "../includes/essential_ciphers.h"
#include <cstdio>
#include <cctype>
void raw_bytes_print(const std::string &a) {
    for (char c : a)
        std::cout << (int)(unsigned char)c << ' ';
}

void large_encrypt(const std::string &a, std::string &out, int base) {
    out="";
    std::string temp=a;
    if (base <= 62) {
        for (char ch : temp) {
            std::string part;
            base_convert((long long)(unsigned char)ch, part, base);
            out += part + ' ';
        }
    } else {
        for (char ch : temp) {
            std::string part;
            base_convert_full((long long)(unsigned char)ch, part, base);
            out += part + ' ';
        }
    }
}

void large_decrypt(const std::string &a, std::string &out, int base) {
    out = "";
    std::string token;
    if (base <= 62) {
        for (char c : a + " ") {
            if (c == ' ') {
                if (token.empty()) continue;
                long long val;
                base_deconvert(token, val, base);
                out += (char)(unsigned char)val;
                token = "";
            } else {
                token += c;
            }
        }
    } else {
        for (char c : a + " ") {
            if (c == ' ') {
                if (token.empty()) continue;
                long long val;
                base_deconvert_full(token, val, base);
                out += (char)(unsigned char)val;
                token = "";
            } else {
                token += c;
            }
        }
    }
}

void hex_xor(const std::string &a, unsigned char key, std::string &out) {
    out="";
    std::string clean;
    if (a.find(' ') != std::string::npos) {
        parser(a, clean);
    } else {
        std::string paired;
        split(a, paired);
        parser(paired, clean);
    }
    int m=clean.length();
    for (int i = 0; i < m; i += 2) {
        std::string pair = { clean.at(i), clean.at(i+1) };
        unsigned char byte = (unsigned char)deconvert_pair(pair, 16);
        byte ^= key;
        std::string part;
        base_convert((long long)byte, part, 16);
        if (part.length() == 1) part = "0" + part;
        out += part + ' ';
    }
}

void str_xor(const std::string &a, const std::string &b, std::string &out) {
    int n=(a.length()<b.length())?a.length():b.length();
    out="";
    for (int i = 0; i < n; i++) {
        out += (char)(a[i] ^ b[i]);
    }
}

void urlcode(const std::string &a, std::string &out, bool encrypt) {
    out="";
    if (encrypt) {
        for (unsigned char ch : a) {
            if (isalnum(ch) || ch=='-' || ch=='_' || ch=='.' || ch=='~') {
                out += ch;
            } else {
                char buf[4];
                snprintf(buf, sizeof(buf), "%%%02x", ch);
                out += buf;
            }
        }
    } else {
        int n = a.length();
        for (int i=0; i<n; i++) {
            if (a[i]=='%' && i+2<n) {
                std::string hex = {a[i+1], a[i+2]};
                long long val;
                base_deconvert(hex, val, 16);
                out += (char)val;
                i += 2;
            } else if (a[i]=='+') {
                out += ' ';
            } else {
                out += a[i];
            }
        }
    }
}

void codepoint_to_utf8(unsigned int cp, std::string &out) {
    if (cp <= 0x7F) {
        out += (char)cp;
    } else if (cp <= 0x7FF) {
        out += (char)(0xC0 | (cp >> 6));
        out += (char)(0x80 | (cp & 0x3F));
    } else if (cp <= 0xFFFF) {
        out += (char)(0xE0 | (cp >> 12));
        out += (char)(0x80 | ((cp >> 6) & 0x3F));
        out += (char)(0x80 | (cp & 0x3F));
    } else {
        out += (char)(0xF0 | (cp >> 18));
        out += (char)(0x80 | ((cp >> 12) & 0x3F));
        out += (char)(0x80 | ((cp >> 6) & 0x3F));
        out += (char)(0x80 | (cp & 0x3F));
    }
}

unsigned int utf8_to_codepoint(const std::string &a, int &i) {
    int n = (int)a.length();
    unsigned char c = (unsigned char)a[i];
    if (c <= 0x7F) {
        return c;
    } else if ((c & 0xE0) == 0xC0) {
        if (i + 1 >= n) { return 0xFFFD; }
        unsigned int cp = (c & 0x1F) << 6;
        cp |= ((unsigned char)a[++i] & 0x3F);
        return cp;
    } else if ((c & 0xF0) == 0xE0) {
        if (i + 2 >= n) { i += (n - i - 1); return 0xFFFD; }
        unsigned int cp = (c & 0x0F) << 12;
        cp |= ((unsigned char)a[++i] & 0x3F) << 6;
        cp |= ((unsigned char)a[++i] & 0x3F);
        return cp;
    } else {
        if (i + 3 >= n) { i += (n - i - 1); return 0xFFFD; }
        unsigned int cp = (c & 0x07) << 18;
        cp |= ((unsigned char)a[++i] & 0x3F) << 12;
        cp |= ((unsigned char)a[++i] & 0x3F) << 6;
        cp |= ((unsigned char)a[++i] & 0x3F);
        return cp;
    }
}

unsigned int rot8000_cp(unsigned int cp, int key, bool encrypt) {
    int k26 = ((key % 26) + 26) % 26;
    int k25 = ((key % 25) + 25) % 25;
    int k10 = ((key % 10) + 10) % 10;

    if (!encrypt) {
        k26 = (26 - k26) % 26;
        k25 = (25 - k25) % 25;
        k10 = (10 - k10) % 10;
    }

    if (cp >= 0x41 && cp <= 0x5A)
        return 0x41 + (cp - 0x41 + k26) % 26;
    if (cp >= 0x61 && cp <= 0x7A)
        return 0x61 + (cp - 0x61 + k26) % 26;
    if (cp >= 0x0391 && cp <= 0x03A9)
        return 0x0391 + (cp - 0x0391 + k25) % 25;
    if (cp >= 0x03B1 && cp <= 0x03C9)
        return 0x03B1 + (cp - 0x03B1 + k25) % 25;
    if (cp >= 0x24B6 && cp <= 0x24CF)
        return 0x24B6 + (cp - 0x24B6 + k26) % 26;
    if (cp >= 0x24D0 && cp <= 0x24E9)
        return 0x24D0 + (cp - 0x24D0 + k26) % 26;
    if (cp >= 0x30 && cp <= 0x39)
        return 0x30 + (cp - 0x30 + k10) % 10;
    return cp;
}

void rot8000(const std::string &a, std::string &out, int key, bool encrypt) {
    out = "";
    for (int i = 0; i < (int)a.length(); i++) {
        unsigned int cp = utf8_to_codepoint(a, i);
        unsigned int rotated = rot8000_cp(cp, key, encrypt);
        codepoint_to_utf8(rotated, out);
    }
}

void octal(const std::string &a, std::string &out, bool encrypt) {
    out = "";
    if (encrypt) {
        for (unsigned char ch : a) {
            std::string part;
            base_convert((long long)ch, part, 8);
            out += part + " ";
        }
    } else {
        std::string token;
        for (char c : a + " ") {
            if (c == ' ') {
                if (token.empty()) continue;
                long long val;
                base_deconvert(token, val, 8);
                out += (char)(unsigned char)val;
                token = "";
            } else {
                token += c;
            }
        }
    }
}

void binary(const std::string &a, std::string &out, bool encrypt) {
    out = "";
    if (encrypt) {
        for (unsigned char ch : a) {
            std::string part;
            base_convert((long long)ch, part, 2);
            while ((int)part.length() < 8) part = "0" + part;
            out += part + " ";
        }
    } else {
        std::string token;
        for (char c : a + " ") {
            if (c == ' ') {
                if (token.empty()) continue;
                long long val;
                base_deconvert(token, val, 2);
                out += (char)(unsigned char)val;
                token = "";
            } else {
                token += c;
            }
        }
    }
}
