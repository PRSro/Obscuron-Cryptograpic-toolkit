#include "../includes/register_handlers.h"
#include "../includes/modern_ciphers.h"

void register_modern_handlers(HandlerMap &map) {
    auto hash_handler = [](const Context &ctx, void (*hash_fn)(const std::string&, std::string&)) {
        std::string out;
        hash_fn(ctx.input, out);
        print_result(ctx, out);
    };

    map["md5"] = [hash_handler](const Context &ctx) { hash_handler(ctx, md5_hash); };
    map["sha1"] = [hash_handler](const Context &ctx) { hash_handler(ctx, sha1_hash); };
    map["sha256"] = [hash_handler](const Context &ctx) { hash_handler(ctx, sha256_hash); };
    map["sha512"] = [hash_handler](const Context &ctx) { hash_handler(ctx, sha512_hash); };

    map["blake2b"] = [](const Context &ctx) {
        std::string out;
        std::string k = ctx.opt_flag("-k", "");
        blake2b_hash(ctx.input, out, k);
        print_result(ctx, out);
    };

    map["blake2s"] = [](const Context &ctx) {
        std::string out;
        std::string k = ctx.opt_flag("-k", "");
        blake2s_hash(ctx.input, out, k);
        print_result(ctx, out);
    };

    map["hmac-sha256"] = [](const Context &ctx) {
        std::string out;
        hmac_sha256(ctx.input, ctx.flag("-k"), out);
        print_result(ctx, out);
    };

    map["hmac-sha512"] = [](const Context &ctx) {
        std::string out;
        hmac_sha512(ctx.input, ctx.flag("-k"), out);
        print_result(ctx, out);
    };

    auto aes_handler = [](const Context &ctx, int mode, const char *name) {
        std::string k = hex_decode_str(ctx.flag("-k"));
        std::string iv;
        if (mode != 0) iv = hex_decode_str(ctx.flag("-i"));
        std::string out;
        bool ok;
        if (ctx.has("--decrypt"))
            ok = aes_decrypt(ctx.input, k, iv, mode, out);
        else
            ok = aes_encrypt(ctx.input, k, iv, mode, out);
        if (!ok) throw CipherError(std::string("AES-") + name + " operation failed (check key size: 16/24/32 bytes hex)");
        print_result(ctx, out);
    };

    map["aes-ecb"] = [aes_handler](const Context &ctx) { aes_handler(ctx, 0, "ECB"); };
    map["aes-cbc"] = [aes_handler](const Context &ctx) { aes_handler(ctx, 1, "CBC"); };
    map["aes-ctr"] = [aes_handler](const Context &ctx) { aes_handler(ctx, 2, "CTR"); };

    map["chacha20"] = [](const Context &ctx) {
        std::string k = hex_decode_str(ctx.flag("-k"));
        std::string n = hex_decode_str(ctx.flag("-i"));
        uint32_t counter = (uint32_t)ctx.opt_int_flag("--counter", 0);
        std::string out;
        chacha20_crypt(ctx.input, k, n, counter, out);
        print_result(ctx, out);
    };

    map["salsa20"] = [](const Context &ctx) {
        std::string k = hex_decode_str(ctx.flag("-k"));
        std::string n = hex_decode_str(ctx.flag("-i"));
        uint32_t counter = (uint32_t)ctx.opt_int_flag("--counter", 0);
        std::string out;
        salsa20_crypt(ctx.input, k, n, counter, out);
        print_result(ctx, out);
    };

    map["poly1305"] = [](const Context &ctx) {
        std::string k = hex_decode_str(ctx.flag("-k"));
        if (k.size() < 32)
            throw CipherError("poly1305: key must be at least 32 bytes");
        std::string out;
        poly1305_mac(ctx.input, k, out);
        print_result(ctx, out);
    };

    map["pbkdf2"] = [](const Context &ctx) {
        std::string out;
        pbkdf2_sha256(ctx.input, ctx.flag("-s"),
                      (uint32_t)ctx.int_flag("--iter"),
                      (uint32_t)ctx.int_flag("--len"), out);
        print_result(ctx, out);
    };

    map["argon2id"] = [](const Context &ctx) {
        std::string out;
        bool ok = argon2id_hash(ctx.input, ctx.flag("-s"),
                                (uint32_t)ctx.int_flag("--iter"),
                                (uint32_t)ctx.int_flag("--mem"),
                                1,
                                (uint32_t)ctx.int_flag("--len"), out);
        if (!ok) throw CipherError("argon2id failed");
        print_result(ctx, out);
    };

    map["jwt-sign"] = [](const Context &ctx) {
        std::string out = jwt_sign(ctx.input, ctx.input, ctx.flag("-k"));
        std::cout << out;
        if (!ctx.raw) std::cout << "\n";
    };

    map["jwt-parse"] = [](const Context &ctx) {
        std::string k = ctx.opt_flag("-k", "");
        JwtToken tok = jwt_parse(ctx.input, k);
        std::cout << "header:  " << tok.header << "\n";
        std::cout << "payload: " << tok.payload << "\n";
        std::cout << "signature: " << tok.signature << "\n";
        std::cout << "valid:   " << (tok.signature_valid ? "yes" : "no") << "\n";
    };

    map["qr"] = [](const Context &ctx) {
        std::vector<std::vector<bool>> matrix = generate_qr_matrix(ctx.input);
        for (size_t y = 0; y < matrix.size(); y++) {
            for (size_t x = 0; x < matrix[y].size(); x++)
                std::cout << (matrix[y][x] ? "##" : "  ");
            std::cout << "\n";
        }
    };

    map["lsb-embed"] = [](const Context &ctx) {
        std::string out;
        bool ok = lsb_embed(ctx.input, ctx.flag("--secret"), out);
        if (!ok) throw CipherError("lsb-embed failed (carrier too small?)");
        print_result(ctx, out);
    };

    map["lsb-extract"] = [](const Context &ctx) {
        std::string out;
        bool ok = lsb_extract(ctx.input, out);
        if (!ok) throw CipherError("lsb-extract failed (no hidden data found?)");
        std::cout << out;
        if (!ctx.raw) std::cout << "\n";
    };

    map["xor"] = [](const Context &ctx) {
        std::string k = hex_decode_str(ctx.flag("-k"));
        std::string out = ctx.input;
        for (size_t j = 0; j < ctx.input.size(); j++)
            out[j] = ctx.input[j] ^ k[j % k.size()];
        print_result(ctx, out);
    };

    map["weak-kdf-demo"] = [](const Context &ctx) {
        if (!ctx.has("--i-understand-this-is-insecure")) {
            std::cerr << "ob-crypt: weak-kdf-demo: requires --i-understand-this-is-insecure flag\n";
            exit(2);
        }
        std::string out;
        bool ok = argon2id_hash(ctx.input, ctx.flag("-s"),
                                (uint32_t)ctx.int_flag("--iter"),
                                (uint32_t)ctx.int_flag("--mem"),
                                1,
                                (uint32_t)ctx.int_flag("--len"), out);
        if (!ok) throw CipherError("weak-kdf-demo failed");
        print_result(ctx, out);
    };
}
