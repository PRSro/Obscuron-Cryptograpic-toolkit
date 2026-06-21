#ifndef DETECTOR_HELPERS_H
#define DETECTOR_HELPERS_H

#include <string>
#include <vector>
#include <functional>
#include <algorithm>

struct KeySearchResult {
    std::string decrypted;
    std::string key;
    double score;
};

template<typename DecryptFn>
KeySearchResult hill_climb_key(
    const std::string &input,
    DecryptFn decrypt,
    const std::vector<std::string> &seed_keys,
    double (*scorer)(const std::string&),
    int max_iterations = 200)
{
    KeySearchResult best;
    best.score = 1e9;

    for (const auto &seed : seed_keys) {
        std::string key = seed;
        std::string result = decrypt(input, key);
        double score = scorer(result);

        if (score < best.score) {
            best.decrypted = result;
            best.key = key;
            best.score = score;
        }

        for (int iter = 0; iter < max_iterations; iter++) {
            double prev_score = score;
            bool improved = false;

            for (size_t pos = 0; pos < key.size(); pos++) {
                char orig = key[pos];
                for (char c = 'A'; c <= 'Z'; c++) {
                    if (c == orig) continue;
                    key[pos] = c;
                    result = decrypt(input, key);
                    score = scorer(result);
                    if (score < prev_score) {
                        prev_score = score;
                        improved = true;
                        if (score < best.score) {
                            best.decrypted = result;
                            best.key = key;
                            best.score = score;
                        }
                        break;
                    }
                }
                if (improved) break;
                key[pos] = orig;
            }

            if (!improved) break;
        }
    }

    return best;
}

#endif
