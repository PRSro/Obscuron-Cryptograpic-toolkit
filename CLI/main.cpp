#include "includes/register_handlers.h"
#include "includes/detector.h"
#include "includes/bytes.h"
#include <cstdio>
#include <unistd.h>
#include <unordered_set>

std::string read_file(const std::string &path) {
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f) throw CipherError(std::string("cannot open '") + path + "'");
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::string read_stdin() {
    std::ostringstream ss;
    ss << std::cin.rdbuf();
    return ss.str();
}

Context parse_args(int argc, char *argv[]) {
    Context ctx;
    bool hex_input = false;
    bool stdin_mode = false;
    std::string input_file;
    std::string input;

    int i = 1;
    bool end_of_flags = false;
    while (i < argc) {
        std::string arg = argv[i];
        if (arg == "--") { end_of_flags = true; i++; continue; }
        if (end_of_flags) {
            if (ctx.input.empty()) ctx.input = arg;
            else ctx.input += " " + arg;
            i++; continue;
        }
        if (arg == "--raw") { ctx.raw = true; i++; }
        else if (arg == "--hex-input") { hex_input = true; i++; }
        else if (arg == "--hex-output") { ctx.hex_output = true; i++; }
        else if (arg == "-f") {
            if (++i >= argc) throw CipherError("-f requires a file path");
            input_file = argv[i++];
        }
        else if (arg == "-") { stdin_mode = true; i++; }
        else if (arg == "--help" || arg == "-h") { ctx.mode = "help"; i++; }
        else if (arg == "--list") { ctx.mode = "list"; i++; }
        else if (ctx.mode.empty()) { ctx.mode = arg; i++; }
        else { ctx.args.push_back(arg); i++; }
    }

    if (ctx.mode == "help" || ctx.mode == "list") return ctx;

    if (!input_file.empty()) {
        ctx.input = read_file(input_file);
    } else if (stdin_mode) {
        ctx.input = read_stdin();
        if (!ctx.input.empty() && ctx.input.back() == '\n') ctx.input.pop_back();
    } else {
        for (size_t ai = 0; ai < ctx.args.size(); ai++) {
            const std::string &a = ctx.args[ai];
            if (a == "-f" || a == "-") continue;
            if (!a.empty() && a[0] == '-') {
    // Check if this looks like a flag (only alnum, -, = chars after leading '-')
    bool is_flag_like = true;
    for (size_t ci = 1; ci < a.size(); ci++) {
        unsigned char c = a[ci];
        if (!std::isalnum(c) && c != '-' && c != '=') {
            is_flag_like = false; break;
        }
    }
    if (!is_flag_like) { input = a; break; }
    static const std::unordered_set<std::string> vf = {
        "-s","-k","--steps","--min-confidence","--top","--max-depth",
        "-e","-n","-a","-b","-c","-d","-e1","-e2","-c1","-c2",
        "-p","--e","--oracle","--timeout","-i","--ciphertexts",
        "--moduli","--x1","--y1","--x2","--y2","--a","--p",
        "--k","--x","--y","--g","--h","--matrix",
        "--b","--key","--text","--iv","--nonce","--aad","--tag",
        "--password","--salt","--info","--ikm","--seed","--offset",
        "--len","--cols","--rails","--depth","--layers","--radius",
        "--secret", "--qx", "--qy", "--r", "--s", "--curve",
        "--pubkey", "--sig", "--bits"
    };
    size_t eq = a.find('=');
    if (eq != std::string::npos) continue;
    if (vf.count(a)) { ai++; continue; }
    if (a == "--help" || a == "-h" || a == "--list" || a == "--raw"
        || a == "--verbose" || a == "--decrypt" || a == "--hex-input"
        || a == "--hex-output" || a == "--solve" || a == "--auto"
    || a == "--no-branch" || a == "--detect" || a == "--debug" || a == "--json"
    || a == "--i-understand-this-is-insecure" || a == "--aggressive") { continue; }
            }
            input = a;
            break;
        }
        if (!input.empty()) {
            ctx.input = input;
        } else if (!isatty(0)) {
            ctx.input = read_stdin();
            if (!ctx.input.empty() && ctx.input.back() == '\n') ctx.input.pop_back();
        } else {
            throw CipherError("missing input argument");
        }
    }

    if (hex_input) ctx.input = hex_decode_str(ctx.input);
    return ctx;
}

static void print_list() {
    const char *names[] = {
        "a1z26", "adfgvx", "aes-cbc", "aes-ctr", "aes-ecb", "aes-gcm", "affine",
        "analyze", "atbash", "autokey", "bacon", "base_decode",
        "base_encode", "beaufort", "bifid", "big-endian", "binary",
        "blake2b", "blake2s", "blowfish", "braille", "brute-caesar",
        "brute-railfence", "brute-rotate", "brute-vigenere", "brute-xor",
        "caesar", "chacha20", "chain", "columnar", "custom-rot",
        "des", "des3", "detect", "enigma", "four-square",
        "hex", "base64", "hex-xor", "hmac-sha256", "hmac-sha512", "keyboard-shift",
        "keyword", "large", "little-endian", "lsb-embed", "lsb-extract",
        "md5", "morse", "octal", "pbkdf2", "playfair", "poly1305",
        "polybius", "proper-base", "qr", "railfence", "rc4", "rot13",
        "rot47", "rot8000", "scytale", "sha1", "sha256", "sha384", "sha512",
        "sha3-224", "sha3-256", "sha3-384", "sha3-512", "shake128", "shake256",
        "bcrypt", "scrypt",
        "str-xor", "substitution", "substitution-solve", "trifid",
        "urlcode", "vigenere", "weak-kdf-demo", "xor", "jwt-parse", "jwt-sign",
        "rsa-decrypt", "rsa-wiener", "rsa-hastad", "rsa-common-modulus",
        "rsa-factor-fermat", "rsa-factor-pollard", "rsa-parity-oracle",
        "rsa-encode", "rsa-info",
         "ec-add", "ec-mul", "dlp-bsgs", "dlp-pohlig", "lll",
         "ecb-detect", "cbc-padding-oracle", "hash-extend",
         "ecdsa-nonce-reuse", "dh-check", "zip-crack",
         "shamir-reconstruct", "gf256-mul", "gf256-inv",
         "tls-fingerprint", "parse-cert", "salsa20",
         "pem-decode", "der-decode", "asn1-parse",
         "ecdsa-keygen", "ecdsa-sign", "ecdsa-verify",
         "ed25519-keygen", "ed25519-sign", "ed25519-verify",
         "rsa-pss-keygen", "rsa-pss-sign", "rsa-pss-verify",
         nullptr
    };
    for (int j = 0; names[j]; j++) std::cout << names[j] << "\n";
}

int main(int argc, char *argv[]) {
    if (argc < 2) { suggestions(); return 0; }

    try {
        Context ctx = parse_args(argc, argv);

        if (ctx.mode.empty() || ctx.mode == "help") {
            suggestions();
            return 0;
        }

        if (ctx.mode == "list") {
            print_list();
            return 0;
        }

        static HandlerMap handlers = register_all_handlers();
        handlers["chain"] = [&](const Context &ctx) {
            chain_handler(handlers, ctx);
        };
        auto it = handlers.find(ctx.mode);
        if (it == handlers.end()) {
            std::cerr << "ob-crypt: unknown cipher '" << ctx.mode << "'" << std::endl;
            return 1;
        }

        it->second(ctx);
        return 0;

    } catch (const std::exception &e) {
        std::cerr << "ob-crypt: " << e.what() << std::endl;
        return 1;
    }
}
