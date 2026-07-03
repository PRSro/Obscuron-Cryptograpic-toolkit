#include "../includes/register_handlers.h"
#include "../includes/detector.h"
#include "../includes/branch_explorer.h"
#include "../includes/standard_ciphers.h"
#include "../includes/modern_ciphers.h"
#include "../includes/historical_ciphers.h"
#include "../includes/basic_ciphers.h"
#include <sstream>
#include <algorithm>
#include <unordered_set>

namespace {

static std::string sanitize_display(const std::string &s) {
    std::string out;
    for (unsigned char ch : s) {
        if (ch >= 32 && ch <= 126) out += (char)ch;
        else if (ch == '\t' || ch == '\n' || ch == '\r') out += (char)ch;
        else out += ' ';
    }
    return out;
}

int b64_val(unsigned char ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

std::string base64_decode_local(const std::string &s) {
    std::string clean;
    for (unsigned char ch : s)
        if (!std::isspace(ch) && ch != '=') clean += ch;
    std::string out;
    size_t i = 0;
    for (; i + 3 < clean.size(); i += 4) {
        int v0 = b64_val(clean[i]);
        int v1 = b64_val(clean[i+1]);
        int v2 = b64_val(clean[i+2]);
        int v3 = b64_val(clean[i+3]);
        out += (char)((v0 << 2) | (v1 >> 4));
        if (v2 >= 0) out += (char)((v1 << 4) | (v2 >> 2));
        if (v3 >= 0) out += (char)((v2 << 6) | v3);
    }
    size_t rem = clean.size() - i;
    if (rem >= 2) {
        int v0 = b64_val(clean[i]);
        int v1 = b64_val(clean[i+1]);
        out += (char)((v0 << 2) | (v1 >> 4));
        if (rem >= 3) {
            int v2 = b64_val(clean[i+2]);
            out += (char)((v1 << 4) | (v2 >> 2));
        }
    }
    return out;
}

} // anonymous namespace

void register_detector_handlers(HandlerMap &map) {
    map["hex"] = [](const Context &ctx) {
        print_result(ctx, hex_decode_str(ctx.input));
    };

    map["base64"] = [](const Context &ctx) {
        print_result(ctx, base64_decode_local(ctx.input));
    };

    map["detect"] = [](const Context &ctx) {
        bool solve = ctx.has("--solve");
        bool auto_mode = ctx.has("--auto");
        bool verbose = ctx.has("--verbose");
        bool no_branch = ctx.has("--no-branch");
        bool aggressive = ctx.has("--aggressive");
        double min_conf = ctx.opt_double_flag("--min-confidence", 0.1);
        int top_n = ctx.opt_int_flag("--top", 3);
        int max_depth = ctx.opt_int_flag("--max-depth", 5);

        if (ctx.input.empty()) {
            std::cout << "Empty input detected, nothing to be done\n";
            return;
        }

        if (auto_mode && top_n < 2) top_n = 2;

        static const std::unordered_set<std::string> ENCODING_NAMES = {
            "hex","base64","base32","base85","base58","binary","octal","url","large-base"
        };

        auto solve_check = [&](const std::vector<CipherCandidate> &r,
                                const std::string &input_text,
                                int lc) -> bool {
            if (r.empty() || r[0].confidence < min_conf) return false;
            if (ENCODING_NAMES.count(r[0].cipher_name)) {
                if (r[0].confidence >= 0.50) return true;
                if (r[0].confidence >= 0.15) {
                    int alpha = 0;
                    for (unsigned char ch : r[0].decrypted)
                        if (std::isalpha(ch)) alpha++;
                    double ar = r[0].decrypted.empty() ? 0 : (double)alpha / r[0].decrypted.size();
                    if (ar > 0.2) return true;
                }
                return false;
            }
            double gap = (r.size() >= 2) ? r[0].confidence - r[1].confidence : 1.0;
            double input_s = score_english_combined(input_text);
            double decoded_s = score_english_combined(r[0].decrypted);
            double improvement = -1.0;
            if (decoded_s < 999990.0 && input_s < 999990.0)
                improvement = 1.0 - decoded_s / input_s;
            else if (input_s >= 999990.0) improvement = 1.0;

            if (ctx.has("--debug")) {
                std::cerr << "debug: conf=" << r[0].confidence
                          << " gap=" << gap << " input_score=" << input_s
                          << " decoded_score=" << decoded_s
                          << " improvement=" << improvement
                          << " letter_count=" << lc
                          << " name=" << r[0].cipher_name << "\n";
            }

            if (r[0].confidence >= 0.5) return true;
            if (r[0].confidence >= 0.30) {
                if (improvement < -0.01) return false;
                if (lc < 15)
                    return gap >= 0.20;
                return (gap >= 0.07 || improvement > 0.20)
                    && (gap >= 0.05 || improvement > 0.10);
            }
            return false;
        };

        if (auto_mode) {
            std::string current = ctx.input;
            std::vector<std::string> seen;
            std::vector<std::pair<std::string, std::string>> steps;
            for (int d = 0; d < max_depth; d++) {
                std::vector<CipherCandidate> r = detect_cipher(current, top_n, aggressive);
                int lc = 0;
                for (unsigned char ch : current)
                    if (std::isalpha(ch)) lc++;
                if (!solve_check(r, current, lc)) break;
                if (r[0].decrypted == current) break;
                bool already_seen = false;
                for (auto &s : seen)
                    if (s == r[0].decrypted) { already_seen = true; break; }
                if (already_seen) break;
                seen.push_back(r[0].decrypted);
                steps.push_back({r[0].cipher_name, r[0].key});
                current = r[0].decrypted;
            }
            if (verbose || steps.size() > 1) {
                for (size_t i = 0; i < steps.size(); i++) {
                    if (i > 0) std::cout << " → ";
                    std::cout << steps[i].first;
                    if (!steps[i].second.empty())
                        std::cout << "(" << steps[i].second << ")";
                }
                if (!steps.empty()) std::cout << " → ";
            }
            std::cout << current;
            if (!ctx.raw) std::cout << "\n";
            return;
        }

        if (solve) {
            int letter_count = 0;
            for (unsigned char ch : ctx.input)
                if (std::isalpha(ch)) letter_count++;
            if (top_n < 2) top_n = 2;

            std::vector<CipherCandidate> results = detect_cipher(ctx.input, top_n, aggressive);
            if (solve_check(results, ctx.input, letter_count)) {
                if (verbose) {
                    std::string chain;
                    for (char ch : results[0].cipher_name) {
                        if (ch == '+') chain += " → ";
                        else chain += ch;
                    }
                    std::cout << chain << " → ";
                }
                std::cout << results[0].decrypted;
                if (!ctx.raw) std::cout << "\n";
                return;
            }
            std::cout << ctx.input;
            if (!ctx.raw) std::cout << "\n";
            return;
        }

        std::vector<CipherCandidate> results = detect_cipher(ctx.input, top_n, aggressive);
        if (ctx.raw) {
            for (size_t j = 0; j < results.size(); j++) {
                std::cout << results[j].cipher_name << "|"
                          << results[j].decrypted << "|"
                          << results[j].key << "|"
                          << results[j].confidence << "\n";
            }
        } else {
            double best_conf = results.empty() ? 1.0 : results[0].confidence;
            if (best_conf <= 0.0) best_conf = 1.0;
            for (size_t j = 0; j < results.size(); j++) {
                double display_conf = results[j].confidence / best_conf * 100.0;
                printf("%5.1f%% ", display_conf);
                if (j == 0) std::cout << "[best] ";
                else if (results[j].confidence / best_conf > 0.7) std::cout << "[likely] ";
                else std::cout << "[possible] ";
                std::cout << results[j].cipher_name;
                if (!results[j].key.empty())
                    std::cout << "  (key: " << results[j].key << ")";
                std::cout << "\n  " << sanitize_display(results[j].decrypted) << "\n";
            }

            if (!no_branch) {
                BranchExplorer explorer(2, 3);
                auto branch_results = explorer.explore(ctx.input, results, top_n);
                for (auto &br : branch_results) {
                    for (auto &sub : br.sub_candidates) {
                        double blended = br.parent_confidence * 0.4 + sub.confidence * 0.6;
                        if (score_english(sub.decrypted) > 60.0)
                            blended = br.parent_confidence;
                        if (blended > 0.95) blended = 0.95;
                        if (blended <= 0.0) continue;
                        double display_conf = (best_conf > 0.0)
                            ? blended / best_conf * 100.0
                            : 0.0;
                        printf("%5.1f%% ", display_conf);
                        std::cout << "[branched] " << br.parent_name;
                        if (!br.parent_key.empty())
                            std::cout << "(" << br.parent_key << ")";
                        std::cout << "+" << sub.cipher_name;
                        if (!sub.key.empty())
                            std::cout << "  (key: " << sub.key << ")";
                        std::cout << "\n  " << sanitize_display(sub.decrypted) << "\n";
                    }
                }
            }
        }
    };

    map["analyze"] = [](const Context &ctx) {
        double ioc_v = compute_ioc(ctx.input);
        double entropy_v = compute_entropy(ctx.input);
        std::string encoding = sniff_encoding(ctx.input);
        std::cout << "encoding: " << encoding << "\n";
        std::cout << "length: " << ctx.input.size() << "\n";
        std::cout << "ioc: " << ioc_v << "\n";
        std::cout << "entropy: " << entropy_v << "\n";

        int byte_counts[256] = {0};
        for (unsigned char ch : ctx.input) byte_counts[ch]++;
        std::cout << "\nbyte distribution (non-zero):\n";
        for (int b = 0; b < 256; b++) {
            if (byte_counts[b] > 0) {
                if (b >= 32 && b <= 126)
                    std::cout << "  '" << (char)b << "' (0x" << std::hex << b << std::dec << "): " << byte_counts[b] << "\n";
                else
                    std::cout << "  0x" << std::hex << b << std::dec << ": " << byte_counts[b] << "\n";
            }
        }

        std::vector<std::pair<char, double>> freqs;
        frequency_analysis(ctx.input, freqs);
        if (!freqs.empty()) {
            std::cout << "\nletter frequencies:\n";
            for (size_t j = 0; j < freqs.size(); j++)
                std::cout << "  " << freqs[j].first << ": " << freqs[j].second << "%\n";
        }
    };

}

void chain_handler(const HandlerMap &map, const Context &ctx) {
    std::string steps_str = ctx.opt_flag("--steps", "");
    bool detect_steps = ctx.has("--detect");
    bool auto_mode = ctx.has("--auto");
    bool aggressive = ctx.has("--aggressive");
    int top_n = ctx.opt_int_flag("--top", 3);
    int max_depth = ctx.opt_int_flag("--max-depth", 5);
    bool verbose = ctx.has("--verbose");
    double min_conf = ctx.opt_double_flag("--min-confidence", 0.1);
    std::string current = ctx.input;

    if (ctx.input.empty()) {
        std::cout << "Empty input detected, nothing to be done\n";
        return;
    }

    if (!steps_str.empty()) {
        std::vector<std::string> steps;
        std::stringstream ss(steps_str);
        std::string step;
        while (std::getline(ss, step, ','))
            if (!step.empty()) steps.push_back(step);

        for (size_t si = 0; si < steps.size(); si++) {
            const std::string &s = steps[si];
            size_t colon = s.find(':');
            std::string cipher = s.substr(0, colon);
            std::string param;
            if (colon != std::string::npos) param = s.substr(colon + 1);

            if (!ctx.raw && !detect_steps && !auto_mode) {
                std::cout << "  step " << (si + 1) << ": " << cipher;
                if (!param.empty())
                    std::cout << ":" << param;
                std::cout << "\n";
            }

            auto it = map.find(cipher);
            if (it != map.end()) {
                Context sub_ctx;
                sub_ctx.mode = cipher;
                sub_ctx.input = current;
                sub_ctx.raw = true;
                if (!param.empty()) {
                    bool is_numeric = !param.empty() &&
                        std::all_of(param.begin(), param.end(),
                            [](char c){ return c >= '0' && c <= '9'; });
                    if (is_numeric)
                        sub_ctx.args = {"-s", param};
                    else
                        sub_ctx.args = {"-k", param};
                }
                std::stringstream capture;
                auto old_buf = std::cout.rdbuf(capture.rdbuf());
                try {
                    it->second(sub_ctx);
                } catch (...) {
                    std::cout.rdbuf(old_buf);
                    throw;
                }
                std::cout.rdbuf(old_buf);
                current = capture.str();
                if (!current.empty() && current.back() == '\n')
                    current.pop_back();
            } else if (cipher == "base16") {
                current = hex_decode_str(current);
            } else if (!ctx.raw) {
                std::cerr << "  warning: unknown chain step '"
                          << cipher << "', skipping\n";
            }
        }
    }

    static const std::unordered_set<std::string> ENCODING_NAMES = {
        "hex","base64","base32","base85","base58","binary","octal","url","large-base"
    };

    auto run_auto_solve = [&](std::string &text,
                               std::vector<std::pair<std::string,std::string>> &layers) {
        std::vector<std::string> seen;
        for (int dd = 0; dd < max_depth; dd++) {
            int lc = 0;
            for (unsigned char ch : text)
                if (std::isalpha(ch)) lc++;
            std::vector<CipherCandidate> r = detect_cipher(text, top_n, aggressive);
            if (r.empty() || r[0].confidence < min_conf) break;
            bool is_encoding = ENCODING_NAMES.count(r[0].cipher_name);
            bool ok = is_encoding ? (r[0].confidence >= 0.50) ||
                (r[0].confidence >= 0.15 && [&](){
                    int a=0; for (unsigned char c: r[0].decrypted) if (std::isalpha(c)) a++;
                    return !r[0].decrypted.empty() && (double)a/r[0].decrypted.size() > 0.2;
                }()) : [&](){
                    double gap = (r.size()>=2) ? r[0].confidence-r[1].confidence : 1.0;
                    double is_ = score_english_combined(text);
                    double ds = score_english_combined(r[0].decrypted);
                    double imp = -1.0;
                    if (ds < 999990.0 && is_ < 999990.0) imp = 1.0 - ds/is_;
                    else if (is_ >= 999990.0) imp = 1.0;
                    if (r[0].confidence >= 0.5) return true;
                    if (r[0].confidence >= 0.30) {
                        if (imp < -0.01) return false;
                        if (lc < 15) return gap >= 0.20;
                        return (gap >= 0.07 || imp > 0.20) && (gap >= 0.05 || imp > 0.10);
                    }
                    return false;
                }();
            if (!ok) break;
            if (r[0].decrypted == text) break;
            bool already_seen = false;
            for (auto &s : seen)
                if (s == r[0].decrypted) { already_seen = true; break; }
            if (already_seen) break;
            seen.push_back(r[0].decrypted);
            layers.push_back({r[0].cipher_name, r[0].key});
            text = r[0].decrypted;
        }
    };

    if (detect_steps) {
        std::vector<CipherCandidate> results = detect_cipher(current, top_n, aggressive);
        bool is_english = false;
        for (auto &c : results)
            if (c.cipher_name == "plaintext") { is_english = true; break; }
        if (is_english) {
            for (size_t j = 0; j < results.size(); j++) {
                if (ctx.raw)
                    std::cout << results[j].cipher_name << "|" << results[j].decrypted << "|"
                              << results[j].confidence << "\n";
                else
                    std::cout << results[j].confidence << "  " << results[j].cipher_name
                              << "\n  " << results[j].decrypted << "\n";
            }
        } else {
            std::vector<std::pair<std::string,std::string>> layers;
            layers.push_back({results[0].cipher_name, results[0].key});
            current = results[0].decrypted;
            run_auto_solve(current, layers);
            if (!ctx.raw && (verbose || layers.size() > 1)) {
                for (size_t i = 0; i < layers.size(); i++) {
                    if (i > 0) std::cout << " → ";
                    std::cout << layers[i].first;
                    if (!layers[i].second.empty())
                        std::cout << "(" << layers[i].second << ")";
                }
                if (!layers.empty()) std::cout << " → ";
            }
            std::cout << current;
            if (!ctx.raw) std::cout << "\n";
        }
    } else if (auto_mode) {
        std::vector<std::pair<std::string,std::string>> layers;
        run_auto_solve(current, layers);
        if (!ctx.raw && (verbose || layers.size() > 1)) {
            for (size_t i = 0; i < layers.size(); i++) {
                if (i > 0) std::cout << " → ";
                std::cout << layers[i].first;
                if (!layers[i].second.empty())
                    std::cout << "(" << layers[i].second << ")";
            }
            if (!layers.empty()) std::cout << " → ";
        }
        std::cout << current;
        if (!ctx.raw) std::cout << "\n";
    } else {
        std::cout << format_output(current, ctx.hex_output);
        if (!ctx.raw) std::cout << "\n";
    }
}
