#include "../includes/register_handlers.h"
#include "../includes/asn1.h"
#include "../includes/modern_ciphers.h"
#include <fstream>
#include <sstream>

void register_asn1_handlers(HandlerMap &map) {
    map["pem-decode"] = [](const Context &ctx) {
        std::string type;
        std::string der = pem_decode(ctx.input, type);
        if (der.empty()) {
            std::cerr << "ob-crypt: pem-decode: invalid or missing PEM input\n";
            return;
        }
        if (!type.empty())
            std::cout << "Type: " << type << "\n";
        std::cout << "DER: " << to_hex((const unsigned char*)der.data(), der.size()) << "\n";
        std::cout << "Size: " << der.size() << " bytes\n";
    };

    map["der-decode"] = [](const Context &ctx) {
        std::string der;
        if (is_hex_string(ctx.input)) {
            der = from_hex(ctx.input);
        } else {
            der = ctx.input;
        }
        std::string tree = asn1_tree_string(der);
        if (tree.empty()) {
            std::cerr << "ob-crypt: der-decode: unable to parse DER data\n";
            return;
        }
        std::cout << tree;
    };

    map["asn1-parse"] = [](const Context &ctx) {
        std::string der;
        if (is_hex_string(ctx.input)) {
            der = from_hex(ctx.input);
        } else {
            der = ctx.input;
        }
        if (ctx.has("--json")) {
            std::string json = asn1_tree_json(der);
            if (json.empty() || json == "[]") {
                std::cerr << "ob-crypt: asn1-parse: unable to parse DER data\n";
                return;
            }
            std::cout << json << "\n";
        } else {
            std::string tree = asn1_tree_string(der);
            if (tree.empty()) {
                std::cerr << "ob-crypt: asn1-parse: unable to parse DER data\n";
                return;
            }
            std::cout << tree;
        }
    };
}
