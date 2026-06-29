#include "../includes/branch_explorer.h"
#include "../includes/detector.h"
#include <future>
#include <chrono>
#include <algorithm>
#include <cmath>

BranchExplorer::BranchExplorer(int max_threads, int timeout_sec)
    : max_threads_(max_threads), timeout_sec_(timeout_sec) {}

bool BranchExplorer::should_branch(
    const std::vector<CipherCandidate> &candidates,
    const std::string &input,
    double /*threshold*/)
{
    if (candidates.size() < 2) return false;
    if (input.size() < 20) return false;

    const std::string &name = candidates[0].cipher_name;
    static const char *non_branchable[] = {
        "hex", "base64", "base32", "base58", "base85", "binary",
        "octal", "large-base", "morse", "bacon", "braille", "url",
        "high-entropy", "der-asn1", nullptr
    };
    for (const char **p = non_branchable; *p; p++) {
        if (name == *p) return false;
    }
    if (name.find("pem-") == 0 || name.find("rsa-") == 0) return false;

    if (candidates[0].confidence >= 0.85) return false;

    return true;
}

double compute_branch_score(
    const CipherCandidate &original,
    const std::vector<CipherCandidate> &sub)
{
    if (sub.empty()) return original.confidence * 0.85;

    double orig_chi = score_english_combined(original.decrypted);
    double sub_chi  = score_english_combined(sub[0].decrypted);
    (void)orig_chi;

    // HARD GATE: sub-result must not be worse than chi=60 to ever boost
    if (sub_chi > 60.0) {
        return std::min(original.confidence, original.confidence * 0.85);
    }

    bool sub_is_encoding = (sub[0].cipher_name == "hex" || sub[0].cipher_name == "base64"
        || sub[0].cipher_name == "base32" || sub[0].cipher_name == "base85"
        || sub[0].cipher_name == "base58" || sub[0].cipher_name == "binary"
        || sub[0].cipher_name == "octal");

    if (sub[0].decrypted == original.decrypted)
        return original.confidence * 0.80;

    if (sub[0].confidence > 0.70 && sub_chi < 30.0)
        return std::min(original.confidence * 1.3, 0.96);

    if (sub_is_encoding)
        return std::min(original.confidence * 1.1, 0.93);

    return original.confidence * 0.95;
}

std::vector<BranchResult> BranchExplorer::explore(
    const std::string &input,
    const std::vector<CipherCandidate> &candidates,
    int top_n)
{
    std::vector<BranchResult> results;
    if (!should_branch(candidates, input)) return results;

    int num = std::min(max_threads_, (int)candidates.size());

    std::vector<std::future<std::vector<CipherCandidate>>> futures;
    for (int i = 0; i < num; i++) {
        std::string decoded = candidates[i].decrypted;
        futures.push_back(std::async(std::launch::async, [decoded, top_n]() {
            return detect_cipher_no_branch(decoded, top_n);
        }));
    }

    for (int i = 0; i < num; i++) {
        BranchResult br;
        br.parent_name = candidates[i].cipher_name;
        br.parent_key = candidates[i].key;
        br.parent_confidence = candidates[i].confidence;
        br.decoded = candidates[i].decrypted;

        auto status = futures[i].wait_for(
            std::chrono::seconds(timeout_sec_));
        if (status == std::future_status::ready) {
            br.sub_candidates = futures[i].get();
            for (auto &sub : br.sub_candidates) {
                sub.was_branched = true;
                sub.confidence = compute_branch_score(candidates[i], br.sub_candidates);
            }
        }
        results.push_back(br);
    }

    return results;
}
