#include "../includes/register_handlers.h"
#include "../includes/essential_ciphers.h"
#include "../includes/standard_ciphers.h"

void register_essential_handlers(HandlerMap &map) {
    map["base_encode"] = [](const Context &ctx) {
        std::string out;
        large_encrypt(ctx.input, out, ctx.int_flag("-b"));
        print_result(ctx, out);
    };

    map["base_decode"] = [](const Context &ctx) {
        std::string out;
        large_decrypt(ctx.input, out, ctx.int_flag("-b"));
        print_result(ctx, out);
    };

    map["large"] = [](const Context &ctx) {
        int base = ctx.int_flag("-b");
        std::string out;
        if (ctx.has("--decrypt")) {
            std::string dec;
            large_decrypt(dec, out, base);
        } else {
            large_encrypt(ctx.input, out, base);
        }
        print_result(ctx, out);
    };

    map["hex-xor"] = [](const Context &ctx) {
        std::string out;
        unsigned char key_byte = (unsigned char)std::strtol(ctx.flag("-k").c_str(), NULL, 16);
        hex_xor(ctx.input, key_byte, out);
        print_result(ctx, out);
    };
    map["hex_xor"] = map["hex-xor"];

    map["str-xor"] = [](const Context &ctx) {
        std::string out;
        str_xor(ctx.input, ctx.flag("-k"), out);
        print_result(ctx, out);
    };
    map["str_xor"] = map["str-xor"];

    map["urlcode"] = [](const Context &ctx) {
        std::string out;
        urlcode(ctx.input, out, !ctx.has("--decrypt"));
        print_result(ctx, out);
    };

    map["rot8000"] = [](const Context &ctx) {
        std::string out;
        rot8000(ctx.input, out, 0, !ctx.has("--decrypt"));
        print_result(ctx, out);
    };

    map["octal"] = [](const Context &ctx) {
        std::string out;
        octal(ctx.input, out, !ctx.has("--decrypt"));
        print_result(ctx, out);
    };

    map["binary"] = [](const Context &ctx) {
        std::string out;
        binary(ctx.input, out, !ctx.has("--decrypt"));
        print_result(ctx, out);
    };

}
