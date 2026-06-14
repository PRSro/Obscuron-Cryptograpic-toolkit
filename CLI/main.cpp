#include "includes/register_handlers.h"
#include "includes/detector.h"
#include "includes/bytes.h"
#include <cstdio>
#include <unistd.h>

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
    while (i < argc) {
        std::string arg = argv[i];
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
    if (a == "-s" || a == "-k" || a == "--steps"
        || a == "--min-confidence" || a == "--top" || a == "--max-depth"
        || a == "-e" || a == "-n" || a == "-c" || a == "-d"
        || a == "-e1" || a == "-e2" || a == "-c1" || a == "-c2"
        || a == "-p" || a == "--e" || a == "-b" || a == "--oracle"
        || a == "--timeout" || a == "-i" || a == "--ciphertexts"
        || a == "--moduli" || a == "--x1" || a == "--y1"
        || a == "--x2" || a == "--y2" || a == "--a" || a == "--p"
        || a == "--k" || a == "--x" || a == "--y" || a == "--g"
        || a == "--h" || a == "--matrix") {
        ai++;
    }
    continue;
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
        "a1z26", "adfgvx", "aes-cbc", "aes-ctr", "aes-ecb", "affine",
        "analyze", "argon2id", "atbash", "autokey", "bacon", "base_decode",
        "base_encode", "beaufort", "bifid", "big-endian", "binary",
        "blake2b", "blake2s", "blowfish", "braille", "brute-caesar",
        "brute-railfence", "brute-rotate", "brute-vigenere", "brute-xor",
        "caesar", "chacha20", "chain", "columnar", "custom-rot",
        "des", "des3", "detect", "enigma", "four-square",
        "hex", "base64", "hex-xor", "hmac-sha256", "hmac-sha512", "keyboard-shift",
        "keyword", "large", "little-endian", "lsb-embed", "lsb-extract",
        "md5", "morse", "octal", "pbkdf2", "playfair", "poly1305",
        "polybius", "proper-base", "qr", "railfence", "rc4", "rot13",
        "rot47", "rot8000", "scytale", "sha1", "sha256", "sha512",
        "str-xor", "substitution", "substitution-solve", "trifid",
        "urlcode", "vigenere", "xor", "jwt-parse", "jwt-sign",
        "rsa-decrypt", "rsa-wiener", "rsa-hastad", "rsa-common-modulus",
        "rsa-factor-fermat", "rsa-factor-pollard", "rsa-parity-oracle",
        "rsa-encode", "rsa-info",
         "ec-add", "ec-mul", "dlp-bsgs", "dlp-pohlig", "lll",
         "ecb-detect", "cbc-padding-oracle", "hash-extend",
         "ecdsa-nonce-reuse", "dh-check", "zip-crack",
         "shamir-reconstruct", "gf256-mul", "gf256-inv",
         "tls-fingerprint", "parse-cert", "salsa20",
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
