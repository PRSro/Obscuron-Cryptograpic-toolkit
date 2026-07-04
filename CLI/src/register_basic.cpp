#include "../includes/register_handlers.h"
#include "../includes/basic_ciphers.h"

void register_basic_handlers(HandlerMap &map) {
    map["custom-rot"] = [](const Context &ctx) {
        std::string out;
        custom_rot(ctx.input, ctx.int_flag("-s"), out);
        print_result(ctx, out);
    };
    map["custom_rot"] = map["custom-rot"];

    map["rot13"] = [](const Context &ctx) {
        std::string out;
        rot13(ctx.input, out);
        print_result(ctx, out);
    };

    map["a1z26"] = [](const Context &ctx) {
        std::string out;
        char sep = ctx.opt_flag("-s", "-")[0];
        a1z26(ctx.input, out, sep);
        print_result(ctx, out);
    };

    map["keyboard-shift"] = [](const Context &ctx) {
        std::string out;
        keyboard_shift(ctx.input, out, ctx.opt_int_flag("-x", 0), ctx.opt_int_flag("-y", 0), !ctx.has("--decrypt"));
        print_result(ctx, out);
    };
    map["keyboard_shift"] = map["keyboard-shift"];
}
