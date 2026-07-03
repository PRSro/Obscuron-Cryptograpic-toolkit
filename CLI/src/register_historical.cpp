#include "../includes/register_handlers.h"
#include "../includes/historical_ciphers.h"
#include "../includes/outdated_ciphers.h"
#include <sstream>

void register_historical_handlers(HandlerMap &map) {
    map["caesar"] = [](const Context &ctx) {
        std::string out;
        int shift = ctx.opt_int_flag("-s", 3);
        custom_rot(ctx.input, shift, out);
        print_result(ctx, out);
    };

    map["vigenere"] = [](const Context &ctx) {
        std::string out;
        vigenere(ctx.input, ctx.flag("-k"), out, !ctx.has("--decrypt"));
        print_result(ctx, out);
    };

    map["atbash"] = [](const Context &ctx) {
        std::string out;
        atbash(ctx.input, out);
        print_result(ctx, out);
    };

    map["playfair"] = [](const Context &ctx) {
        std::string out;
        playfair(ctx.input, out, ctx.flag("-k"), !ctx.has("--decrypt"));
        print_result(ctx, out);
    };

    map["affine"] = [](const Context &ctx) {
        std::string out;
        affine(ctx.input, out, ctx.int_flag("-a"), ctx.int_flag("-b"),
               !ctx.has("--decrypt"));
        print_result(ctx, out);
    };

    map["columnar"] = [](const Context &ctx) {
        std::string out;
        if (ctx.has("--decrypt")) {
            int col_len = ctx.opt_int_flag("--len", 0);
            if (col_len == 0) throw CipherError("columnar decrypt requires --len <int>");
            columnar_decrypt(ctx.input, out, ctx.flag("-k"), col_len);
        } else {
            columnar_encrypt(ctx.input, out, ctx.flag("-k"));
        }
        print_result(ctx, out);
    };

    map["railfence"] = [](const Context &ctx) {
        std::string out;
        railfence(ctx.input, out, ctx.int_flag("-k"), ctx.opt_int_flag("--offset", 0));
        print_result(ctx, out);
    };

    map["autokey"] = [](const Context &ctx) {
        std::string out;
        autokey(ctx.input, ctx.flag("-k"), out, !ctx.has("--decrypt"));
        print_result(ctx, out);
    };

    map["bacon"] = [](const Context &ctx) {
        std::string out;
        bacon(ctx.input, out, !ctx.has("--decrypt"));
        print_result(ctx, out);
    };

    map["beaufort"] = [](const Context &ctx) {
        std::string out;
        beaufort(ctx.input, ctx.flag("-k"), out);
        print_result(ctx, out);
    };

    map["bifid"] = [](const Context &ctx) {
        std::string k = ctx.opt_flag("-k", "ABCDEFGHIKLMNOPQRSTUVWXYZ");
        char grid[6][6] = {}; int row_of[256] = {}, col_of[256] = {};
        std::string rows[5];
        for (int r = 0; r < 5; r++) rows[r] = k.substr(r * 5, 5);
        build_bifid_grid(rows, grid, row_of, col_of);
        std::string input;
        for (char c : ctx.input) {
            if (c >= 'a' && c <= 'z') c = c-'a'+'A';
            if (c == 'J') c = 'I';
            if (c >= 'A' && c <= 'Z') input += c;
        }
        std::string out;
        if (ctx.has("--decrypt"))
            bifid_decrypt(input, out, grid, row_of, col_of);
        else
            bifid_encrypt(input, out, grid, row_of, col_of);
        print_result(ctx, out);
    };

    map["four-square"] = [](const Context &ctx) {
        std::string ks = ctx.flag("-k");
        size_t comma = ks.find(',');
        std::string k1, k2;
        if (comma != std::string::npos) {
            k1 = ks.substr(0, comma);
            k2 = ks.substr(comma + 1);
        } else { k1 = k2 = ks; }
        std::string out;
        four_square(ctx.input, out, k1, k2, !ctx.has("--decrypt"));
        print_result(ctx, out);
    };

    map["morse"] = [](const Context &ctx) {
        std::string out;
        if (ctx.has("--decrypt"))
            morse_decode(ctx.input, out);
        else
            morse_encode(ctx.input, out);
        print_result(ctx, out);
    };

    map["polybius"] = [](const Context &ctx) {
        std::string alpha = ctx.opt_flag("-k", "ABCDEFGHIKLMNOPQRSTUVWXYZ");
        std::string out;
        if (ctx.has("--decrypt"))
            polybius_decrypt(alpha, ctx.input, out);
        else
            polybius_encrypt(alpha, ctx.input, out);
        print_result(ctx, out);
    };

    map["scytale"] = [](const Context &ctx) {
        int key = ctx.int_flag("-k");
        std::string out;
        if (ctx.has("--decrypt"))
            scytale_decrypt(ctx.input, out, key);
        else
            scytale_encrypt(ctx.input, out, key);
        print_result(ctx, out);
    };

    map["trifid"] = [](const Context &ctx) {
        int period = ctx.opt_int_flag("--len", 5);
        std::string out;
        trifid(ctx.input, out, ctx.flag("-k"), period, !ctx.has("--decrypt"));
        print_result(ctx, out);
    };

    map["adfgvx"] = [](const Context &ctx) {
        std::string ks = ctx.flag("-k");
        size_t comma = ks.find(',');
        std::string poly_key, col_key;
        if (comma != std::string::npos) {
            poly_key = ks.substr(0, comma);
            col_key = ks.substr(comma + 1);
        } else { poly_key = ks; col_key = "ADFGVX"; }
        std::string out;
        adfgvx(ctx.input, out, poly_key, col_key, !ctx.has("--decrypt"));
        print_result(ctx, out);
    };

    map["enigma"] = [](const Context &ctx) {
        std::vector<int> rotors, offsets;
        std::vector<std::pair<int,int>> pb;
        std::stringstream rs(ctx.flag("-r"));
        std::string token;
        while (std::getline(rs, token, ','))
            rotors.push_back(std::atoi(token.c_str()));
        std::stringstream os(ctx.flag("-o"));
        while (std::getline(os, token, ','))
            offsets.push_back(std::atoi(token.c_str()));
        if (ctx.has("-p")) {
            std::string pb_str = ctx.flag("-p");
            std::stringstream pbs(pb_str);
            std::string pair;
            while (std::getline(pbs, pair, ',')) {
                size_t colon = pair.find(':');
                if (colon != std::string::npos) {
                    int a = std::atoi(pair.substr(0, colon).c_str());
                    int b = std::atoi(pair.substr(colon + 1).c_str());
                    pb.push_back({a, b});
                }
            }
        }
        std::string out;
        enigma(ctx.input, out, rotors, offsets, pb);
        print_result(ctx, out);
    };

    map["braille"] = [](const Context &ctx) {
        std::string out;
        if (ctx.has("--decrypt"))
            braille_decode(ctx.input, out);
        else
            braille_encode(ctx.input, out);
        print_result(ctx, out);
    };

    map["porta"] = [](const Context &ctx) {
        std::string out;
        porta(ctx.input, ctx.flag("-k"), out);
        print_result(ctx, out);
    };

    map["gronsfeld"] = [](const Context &ctx) {
        std::string out;
        gronsfeld(ctx.input, ctx.flag("-k"), out, !ctx.has("--decrypt"));
        print_result(ctx, out);
    };

    map["hill"] = [](const Context &ctx) {
        std::string out;
        int a = ctx.opt_int_flag("-a", 5);
        int b = ctx.opt_int_flag("-b", 7);
        int c = ctx.opt_int_flag("-c", 3);
        int d = ctx.opt_int_flag("-d", 11);
        bool ok;
        if (ctx.has("--decrypt"))
            ok = hill_decrypt(ctx.input, out, a, b, c, d);
        else
            ok = hill_encrypt(ctx.input, out, a, b, c, d);
        if (!ok)
            throw CipherError("Hill cipher: key matrix is not invertible modulo 26");
        print_result(ctx, out);
    };

    map["nihilist"] = [](const Context &ctx) {
        std::string out;
        if (ctx.has("--decrypt"))
            nihilist_decrypt(ctx.input, out, ctx.flag("-k"));
        else
            nihilist_encrypt(ctx.input, out, ctx.flag("-k"));
        print_result(ctx, out);
    };
}
