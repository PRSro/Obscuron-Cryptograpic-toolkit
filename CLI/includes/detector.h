#ifndef DETECTOR_H
#define DETECTOR_H

#include <string>
#include <vector>

struct CipherCandidate {
    std::string cipher_name;
    std::string decrypted;
    std::string key;
    double confidence;
    bool was_branched = false;
};

std::vector<CipherCandidate> detect_cipher(const std::string &input, int top_n);
std::vector<CipherCandidate> detect_cipher_no_branch(const std::string &input, int top_n);
std::vector<CipherCandidate> detect_base(const std::string &input, int top_n);
double score_english(const std::string &text);
double score_english_combined(const std::string &text);
double compute_entropy(const std::string &input);
double compute_ioc(const std::string &input);
std::string sniff_encoding(const std::string &input);

#endif
