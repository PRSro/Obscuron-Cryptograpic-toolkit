#include "../includes/register_handlers.h"
#include "../includes/ecdsa.h"
#include "../includes/eddsa.h"
#include "../includes/rsa_pss.h"
#include "../includes/modern_ciphers.h"

void register_signature_handlers(HandlerMap &map) {
    // ── ECDSA ──
    map["ecdsa-keygen"] = [](const Context &ctx) {
        std::string curve = ctx.opt_flag("--curve", "secp256k1");
        std::string d, Qx, Qy, err;
        if (!ecdsa_keygen(curve, d, Qx, Qy, err)) {
            std::cerr << "ob-crypt: ecdsa-keygen: " << err << "\n";
            return;
        }
        std::cout << "Curve:        " << curve << "\n";
        std::cout << "Private (d):  " << d << "\n";
        std::cout << "Public (Qx):  " << Qx << "\n";
        std::cout << "Public (Qy):  " << Qy << "\n";
    };

    map["ecdsa-sign"] = [](const Context &ctx) {
        std::string d = ctx.flag("-k");
        std::string curve = ctx.opt_flag("--curve", "secp256k1");
        std::string r, s, err;
        if (!ecdsa_sign(ctx.input, d, curve, r, s, err)) {
            std::cerr << "ob-crypt: ecdsa-sign: " << err << "\n";
            return;
        }
        std::cout << "r: " << r << "\n";
        std::cout << "s: " << s << "\n";
    };

    map["ecdsa-verify"] = [](const Context &ctx) {
        std::string Qx = ctx.flag("--qx");
        std::string Qy = ctx.flag("--qy");
        std::string r = ctx.flag("--r");
        std::string s = ctx.flag("--s");
        std::string curve = ctx.opt_flag("--curve", "secp256k1");
        bool valid = false;
        std::string err;
        if (!ecdsa_verify(ctx.input, Qx, Qy, r, s, curve, valid, err)) {
            std::cerr << "ob-crypt: ecdsa-verify: " << err << "\n";
            return;
        }
        std::cout << (valid ? "valid" : "invalid") << "\n";
    };

    // ── Ed25519 ──
    map["ed25519-keygen"] = [](const Context &ctx) {
        std::string priv, pub, err;
        if (!ed25519_keygen(priv, pub, err)) {
            std::cerr << "ob-crypt: ed25519-keygen: " << err << "\n";
            return;
        }
        std::cout << "Private key: " << priv << "\n";
        std::cout << "Public key:  " << pub << "\n";
    };

    map["ed25519-sign"] = [](const Context &ctx) {
        std::string priv = ctx.flag("-k");
        std::string sig, err;
        if (!ed25519_sign(ctx.input, priv, sig, err)) {
            std::cerr << "ob-crypt: ed25519-sign: " << err << "\n";
            return;
        }
        std::cout << sig << "\n";
    };

    map["ed25519-verify"] = [](const Context &ctx) {
        std::string pub = ctx.flag("--pubkey");
        std::string sig = ctx.flag("--sig");
        bool valid = false;
        std::string err;
        if (!ed25519_verify(ctx.input, pub, sig, valid, err)) {
            std::cerr << "ob-crypt: ed25519-verify: " << err << "\n";
            return;
        }
        std::cout << (valid ? "valid" : "invalid") << "\n";
    };

    // ── RSA-PSS ──
    map["rsa-pss-keygen"] = [](const Context &ctx) {
        int bits = ctx.opt_int_flag("--bits", 2048);
        std::string n, e, d, err;
        if (!rsa_pss_keygen(bits, n, e, d, err)) {
            std::cerr << "ob-crypt: rsa-pss-keygen: " << err << "\n";
            return;
        }
        std::cout << "n: " << n << "\n";
        std::cout << "e: " << e << "\n";
        std::cout << "d: " << d << "\n";
    };

    map["rsa-pss-sign"] = [](const Context &ctx) {
        std::string n = ctx.flag("-n");
        std::string d = ctx.flag("-k");
        int salt = ctx.opt_int_flag("--salt", -1);
        std::string sig, err;
        if (!rsa_pss_sign(ctx.input, n, d, salt, sig, err)) {
            std::cerr << "ob-crypt: rsa-pss-sign: " << err << "\n";
            return;
        }
        std::cout << sig << "\n";
    };

    map["rsa-pss-verify"] = [](const Context &ctx) {
        std::string n = ctx.flag("-n");
        std::string e = ctx.flag("-e");
        std::string sig = ctx.flag("--sig");
        int salt = ctx.opt_int_flag("--salt", -1);
        bool valid = false;
        std::string err;
        if (!rsa_pss_verify(ctx.input, n, e, sig, salt, valid, err)) {
            std::cerr << "ob-crypt: rsa-pss-verify: " << err << "\n";
            return;
        }
        std::cout << (valid ? "valid" : "invalid") << "\n";
    };
}
