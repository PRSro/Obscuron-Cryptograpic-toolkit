#pragma once
#include <string>

void quadgram_load(const std::string &path);
double quadgram_score(const std::string &text);
double quadgram_score_per_letter(const std::string &text);
