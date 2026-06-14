#include "../includes/basic_ciphers.h"
#include <stdexcept>

const char padding='0';
const std::string alphabet="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const std::string alphabet_full=alphabet+"!\"#$%&'()*+,-./:;<=>?@[";
const std::string alphabet_to_morse="abcdefghijklmnopqrstuvwxyz0123456789 ";
const std::string morse_to_alphabet[38] = {
    ".-",    "-...",  "-.-.",  "-..",   ".",     "..-.",  "--.",   "....",
    "..",    ".---",  "-.-",   ".-..",  "--",    "-.",    "---",   ".--.",
    "--.-",  ".-.",   "...",   "-",     "..-",   "...-",  ".--",   "-..-",
    "-.--",  "--..",  "-----", ".----", "..---", "...--", "....-", ".....",
    "-....", "--...", "---..", "----.", "/",     ""
};
const std::string braille_alphabet = "abcdefghijklmnopqrstuvwxyz ";
const std::string braille_map[28] = {
    "100000", "110000", "100100", "100110", "100010", "110100",
    "110110", "110010", "010100", "010110", "101000", "111000",
    "101100", "101110", "101010", "111100", "111110", "111010",
    "011100", "011110", "101001", "111001", "010111", "101101",
    "101111", "101011", "000000", ""
};
const std::string digit_map[10] = {
    "010110", "100000", "110000", "100100", "100110",
    "100010", "110100", "110110", "110010", "010100"
};
const std::string NUMBER_INDICATOR = "010111";
const std::string LETTER_INDICATOR = "000001";

const std::string KB_ROWS[3] = {
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm"
};

void split(const std::string &a, std::string &c) {
    std::string seq;
    int s=a.length();
    c="";
    if (s%2==1) {
        seq= {padding, a.at(0)};
        c+=seq+' ';
        for(int i=1; i<s; i+=2) {
            seq= {a.at(i), a.at(i+1)};
            c+=seq+' ';
        }
    }
    else {
        for(int i=0; i<s; i+=2) {
            seq={a.at(i), a.at(i+1)};
            c+=seq+' ';
        }
    }
}

void parser(const std::string &a, std::string &out) {
    out="";
    for(char l:a) {
        if (l==' ') {
            continue;
        }
        else out+=l;
    }
}

void reverser(const std::string &a, std::string &c) {
    c="";
    int n=a.length();
    std::string seq;
    for (int y=n-1; y>=0; y--) {
        seq=a.at(y);
        c+=seq;
    }
}

int deconvert_pair(const std::string &pair, int base) {
    size_t h = alphabet.find(pair.at(0));
    size_t l  = alphabet.find(pair.at(1));
    if (h == std::string::npos || l == std::string::npos) {
        throw std::invalid_argument("deconvert_pair: character not in alphabet");
    }
    return h * base + l;
}

void base_deconvert(const std::string &a, long long &b, int base) {
    if (a.empty()) { b = 0; return; }
    bool negative = (a[0] == '-');
    std::string temp = negative ? a.substr(1) : a;
    b = 0;
    for (size_t i = 0; i < temp.size(); i++) {
        size_t val = alphabet.find(temp[i]);
        if (val == std::string::npos)
            throw std::invalid_argument("base_deconvert: character not in alphabet");
        b = b * base + (long long)val;
    }
    if (negative) b *= -1;
}

void base_convert(long long b, std::string &final, int base) {
    final="";
    if (b==0) {
        final="0";
        return;
    }
    long long d=std::abs(b);
    while(d!=0) {
        int r=d%base;
        final+=alphabet.at(r);
        d/=base;
    }
    std::string temp;
    reverser(final, temp);
    final=temp;
    if(b<0) final.insert(0, "-");
}

void base_deconvert_full(const std::string &a, long long &b, int base) {
    if (a.empty()) { b = 0; return; }
    bool negative = (a[0] == '-');
    std::string temp = negative ? a.substr(1) : a;
    b = 0;
    for (size_t i = 0; i < temp.size(); i++) {
        size_t val = alphabet_full.find(temp[i]);
        if (val == std::string::npos)
            throw std::invalid_argument("base_deconvert_full: character not in extended alphabet");
        b = b * base + (long long)val;
    }
    if (negative) b *= -1;
}

void base_convert_full(long long b, std::string &final, int base) {
    final="";
    if (b==0) { final="0"; return; }
    long long d=std::abs(b);
    while(d!=0) {
        int r=d%base;
        final+=alphabet_full.at(r);
        d/=base;
    }
    std::string temp;
    reverser(final, temp);
    final=temp;
    if(b<0) final.insert(0, "-");
}

void custom_rot(const std::string &a, int add, std::string &out){
    out="";
    for (char c:a) {
        if (c>='a' && c<='z') {
            out+= (char)(((c-'a')+add+26)%26+'a');
        } else if (c>='A' && c<='Z') {
            out += (char)(((c-'A')+add+26)%26+'A');
        } else {
            out += c;
        }
    }
}

void rot13(const std::string &a, std::string &out){
    custom_rot(a, 13, out);
}

void a1z26(const std::string &a, std::string &out, char sep){
    bool first = true;
    for(char c:a){
        if(c>='A' && c<='Z'){
            if(!first) out+=sep;
            out+=std::to_string(c-'A'+1);
            first=false;
        } else if(c>='a' && c<='z'){
            if(!first) out+=sep;
            out+=std::to_string(c-'a'+1);
            first=false;
        } else {
            out+=c;
        }
    }
}

void keyboard_shift(const std::string &a, std::string &out, int n, bool encrypt) {
    out = "";
    int shift = encrypt ? n : -n;
    for (char c : a) {
        char lower = (c >= 'A' && c <= 'Z') ? c-'A'+'a' : c;
        bool found = false;
        for (int row = 0; row < 3; row++) {
            size_t pos = KB_ROWS[row].find(lower);
            if (pos != std::string::npos) {
                int len = KB_ROWS[row].length();
                int newpos = ((int)pos + shift % len + len) % len;
                char result = KB_ROWS[row][newpos];
                if (c >= 'A' && c <= 'Z') result = result-'a'+'A';
                out += result;
                found = true;
                break;
            }
        }
        if (!found) out += c;
    }
}

#include <cstdio>

#define SEP  "─────────────────────────────────────────────────────────────────────────────────────\n"
#define ROW  "│ %-20s │ %-30s │ %-22s │\n"

void suggestions() {
    std::cout << "THE OBSCURON's PERSONAL HEX LIBRARY IN CPP FOR SPEED AND EFFICIENCY\n";
    std::cout << "═════════════════════════════════════════════════════════════════════════════════════\n";
    printf(ROW, "function", "intent", "params");
    std::cout << SEP;
    std::cout << "── basic_ciphers ──────────────────────────────────────────────────────────────────\n";
    printf(ROW, "split",             "chunk string into hex pairs",     "(str, &out)");
    printf(ROW, "parser",            "strip spaces from hex string",    "(str, &out)");
    printf(ROW, "reverser",          "reverse a string",                "(str, &out)");
    printf(ROW, "deconvert_pair",    "pair->value in any base",         "(str, base) -> int");
    printf(ROW, "base_convert",      "number -> string, base 2-62",     "(ll, &out, base)");
    printf(ROW, "base_deconvert",    "string -> number, base 2-62",     "(str, &ll, base)");
    printf(ROW, "custom_rot",        "rotate string by N",              "(str, add, &out)");
    printf(ROW, "rot13",             "ROT13 substitution",              "(str, &out)");
    printf(ROW, "a1z26",             "A1Z26 letter->number cipher",     "(str, &out, sep)");
    printf(ROW, "keyboard_shift",    "shift keyboard rows",             "(str, &out, n, enc)");
    printf(ROW, "suggestions",       "print this help table",           "none");
    std::cout << "── historical_ciphers ─────────────────────────────────────────────────────────────\n";
    printf(ROW, "atbash",            "reverse alphabet mapping",        "(str, &out)");
    printf(ROW, "caesar",            "shift by 3 (default)",            "(str, &out)");
    printf(ROW, "vigenere",          "polyalphabetic shift by key",     "(str, key, &out, enc)");
    printf(ROW, "autokey",           "Vigenere with prime key",         "(str, key, &out, enc)");
    printf(ROW, "beaufort",          "reciprocal Vigenere variant",     "(str, key, &out)");
    printf(ROW, "railfence",         "zigzag transposition",            "(str, &out, key, off)");
    printf(ROW, "scytale_encrypt",   "spiral transposition encrypt",    "(str, &out, m)");
    printf(ROW, "scytale_decrypt",   "spiral transposition decrypt",    "(str, &out, m)");
    printf(ROW, "polybius_encrypt",  "5x5 grid encrypt",                "(alph, str, &out)");
    printf(ROW, "polybius_decrypt",  "5x5 grid decrypt",                "(alph, str, &out)");
    printf(ROW, "columnar_encrypt",  "column transposition encrypt",    "(str, &out, key)");
    printf(ROW, "columnar_decrypt",  "column transposition decrypt",    "(str, &out, key, len)");
    printf(ROW, "build_playfair_grid","build 5x5 Playfair grid",        "(key, grid)");
    printf(ROW, "playfair",          "digraph substitution cipher",     "(str, &out, key, enc)");
    printf(ROW, "build_bifid_grid",  "build 6x6 Bifid grid",            "(rows, grid, r, c)");
    printf(ROW, "bifid_encrypt",     "fractionating transp encrypt",    "(msg, &out, grid, r, c)");
    printf(ROW, "bifid_decrypt",     "fractionating transp decrypt",    "(msg, &out, grid, r, c)");
    printf(ROW, "build_trifid_grid", "build 3x3x3 Trifid grid",         "(key, grid)");
    printf(ROW, "trifid",            "3D fractionating cipher",         "(str, &out, key, per, enc)");
    printf(ROW, "build_foursquare_grid","build 5x5 Foursquare grid",   "(key, grid)");
    printf(ROW, "build_standard_grid","build A-Z 5x5 grid",             "(grid)");
    printf(ROW, "four_square",       "digraph 4-square cipher",         "(str, &out, k1, k2, enc)");
    printf(ROW, "build_adfgvx_grid", "build 6x6 ADFGVX grid",           "(key, grid)");
    printf(ROW, "adfgvx",            "ADFGVX fractionation cipher",     "(str, &out, pk, ck, enc)");
    printf(ROW, "bacon",             "5-bit binary substitution",        "(str, &out, enc)");
    printf(ROW, "morse_encode",      "text -> morse code",              "(str, &out)");
    printf(ROW, "morse_decode",      "morse code -> text",              "(str, &out)");
    printf(ROW, "braille_to_dots",   "braille cell -> dot string",      "(cell, &out)");
    printf(ROW, "braille_print_dots","print braille dot art",           "(str)");
    printf(ROW, "simple_dots_to_braille","simple dots -> braille",      "(dots, &out)");
    printf(ROW, "braille_to_simple_dots","braille -> simple dots",      "(cell, &out)");
    printf(ROW, "braille_encode",    "text -> braille",                 "(str, &out)");
    printf(ROW, "braille_decode",    "braille -> text",                 "(str, &out)");
    std::cout << "── essential_ciphers ──────────────────────────────────────────────────────────────\n";
    printf(ROW, "raw_bytes_print",   "print raw byte hex values",       "(str)");
    printf(ROW, "large_encrypt",     "encrypt string, base 2-62",       "(str, &out, base)");
    printf(ROW, "large_decrypt",     "decrypt string, base 2-62",       "(str, &out, base)");
    printf(ROW, "hex_xor",           "XOR hex string vs byte key",      "(str, key, &out)");
    printf(ROW, "str_xor",           "XOR two equal-length strings",    "(a, b, &out)");
    printf(ROW, "urlcode",           "URL encode/decode",               "(str, &out, enc)");
    printf(ROW, "codepoint_to_utf8", "codepoint -> UTF-8 bytes",        "(cp, &out)");
    printf(ROW, "utf8_to_codepoint", "UTF-8 -> codepoint",              "(str, &i) -> uint");
    printf(ROW, "rot8000_cp",        "rotate single Unicode codepoint", "(cp, key, enc) -> uint");
    printf(ROW, "rot8000",           "ROT8000 on full string",          "(str, &out, key, enc)");
    printf(ROW, "octal",             "octal encode/decode",             "(str, &out, enc)");
    printf(ROW, "binary",            "binary encode/decode",            "(str, &out, enc)");
    std::cout << "── bytes ──────────────────────────────────────────────────────────────────────────\n";
    printf(ROW, "little_endian_encode","encode val as LE bytes",        "(val, &out, bytes)");
    printf(ROW, "big_endian_encode", "encode val as BE bytes",          "(val, &out, bytes)");
    printf(ROW, "little_endian_decode","decode LE bytes -> val",        "(str, &ll)");
    printf(ROW, "big_endian_decode", "decode BE bytes -> val",          "(str, &ll)");
    printf(ROW, "proper_base_convert","chunk-oriented base encode",     "(in, &out, bpc, alph)");
    std::cout << "── standard_ciphers ───────────────────────────────────────────────────────────────\n";
    printf(ROW, "rot47",             "ROT47 (printable ASCII)",         "(str, &out)");
    printf(ROW, "keyword_cipher",    "monoalphabetic keyword shift",    "(str, &out, kw, enc)");
    printf(ROW, "substitution_encrypt","arbitrary substitution enc",    "(str, &out, key)");
    printf(ROW, "substitution_decrypt","arbitrary substitution dec",    "(str, &out, key)");
    printf(ROW, "frequency_analysis","letter frequency distribution",   "(str, &freqs)");
    printf(ROW, "substitution_solve","solve via frequency mapping",     "(str, &out, &map)");
    printf(ROW, "index_of_coincidence","measure of letter randomness",  "(str) -> double");
    printf(ROW, "find_key_lengths",  "Kasiski key length candidates",   "(str, &lens, max)");
    std::cout << "── outdated_ciphers ────────────────────────────────────────────────────────────────\n";
    printf(ROW, "rc4",               "RC4 stream cipher",               "(in, &out, key)");
    printf(ROW, "des_ecb",           "DES in ECB mode (56-bit key)",    "(in, &out, key, enc)");
    printf(ROW, "des3_ecb",          "Triple-DES EDE in ECB mode",      "(in, &out, key, enc)");
    printf(ROW, "blowfish_ecb",      "Blowfish in ECB mode",            "(in, &out, key, enc)");
    printf(ROW, "vigenere_autokey_broken","repeating-key Vigenere",     "(str, key, &out, enc)");
    printf(ROW, "enigma",            "3-rotor Enigma simulation",       "(in, &out, rot, off, pb)");
    std::cout << "── ntl_bridge ─────────────────────────────────────────────────────────────────────\n";
    printf(ROW, "ntl_rsa_decrypt",    "RSA decrypt (hex in/out)",         "(c,d,n, &out, &err)");
    printf(ROW, "ntl_rsa_wiener",     "Wiener attack on small d",          "(e,n, &d, &err)");
    printf(ROW, "ntl_rsa_hastad",     "Hastad broadcast attack",           "(vec&lt;c&gt;, vec&lt;n&gt;, e, &out, &err)");
    printf(ROW, "ntl_ec_add",         "EC point addition",                 "(x1,y1,x2,y2,a,p, &xr,&yr, &err)");
    printf(ROW, "ntl_ec_scalar_mul",  "EC scalar multiplication",          "(k,x,y,a,p, &xr,&yr, &err)");
    printf(ROW, "ntl_bsgs",           "Baby-step giant-step DLP",          "(g,h,p, &x, &err)");
    printf(ROW, "ntl_pohlig_hellman", "Pohlig-Hellman DLP",                "(g,h,p, &x, &err)");
    printf(ROW, "ntl_lll",            "LLL lattice reduction (FP)",        "(mat, &out, &err)");
    std::cout << "── bruteforce_ciphers ─────────────────────────────────────────────────────────────\n";
    printf(ROW, "brute_rotate",      "brute force all ROT shifts",      "(str)");
    printf(ROW, "brute_rot_all",     "brute Caesar+ROT47+rot8000",      "(str)");
    printf(ROW, "brute_caesar_all",  "brute force Caesar 1-25",         "(str) -> vec<str>");
    printf(ROW, "brute_railfence_all","brute rail keys up to max",      "(str, max) -> vec<str>");
    printf(ROW, "brute_xor_single_byte","brute single-byte XOR keys",   "(str) -> vec<str>");
    printf(ROW, "brute_vigenere_keylength","brute Vigenere key lengths","(str, max) -> vec<str>");
    std::cout << "── detector ────────────────────────────────────────────────────────────────────────\n";
    printf(ROW, "detect_cipher",     "auto-detect cipher type",          "(str, top_n) -> vec<Candidate>");
    printf(ROW, "score_english",     "chi-squared vs English",           "(str) -> double");
    printf(ROW, "compute_entropy",   "Shannon entropy of bytes",         "(str) -> double");
    printf(ROW, "compute_ioc",       "index of coincidence",             "(str) -> double");
    printf(ROW, "sniff_encoding",    "detect hex/base64/binary/text",    "(str) -> str");
    std::cout << "─────────────────────────────────────────────────────────────────────────────────────\n";
    std::cout << "│ supported bases: 2 (bin)  8 (oct)  10 (dec)  16 (hex)  36 (alphanum lower)         │\n";
    std::cout << "│                  62 (full alphanumeric)  85 (full printable ASCII)                 │\n";
    std::cout << "│ alphabet (2-62):  0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ   │\n";
    std::cout << "│ alphabet (63-85): + !\"#$%&'()*+,-./:;<=>?@[                                       │\n";
    std::cout << "═════════════════════════════════════════════════════════════════════════════════════\n";
}
