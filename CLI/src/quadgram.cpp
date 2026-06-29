#include "../includes/quadgram.h"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <stdexcept>

static float scores[26][26][26][26];
static bool loaded = false;
static double floor_val = 0.0;

void quadgram_load(const std::string &path) {
    if (loaded) return;

    const char *paths[] = {
        path.c_str(),
        "./english_quadgrams.txt",
        "../english_quadgrams.txt",
        "CLI/english_quadgrams.txt",
    };

    const char *found = nullptr;
    for (auto *p : paths) {
        FILE *f = fopen(p, "r");
        if (f) { fclose(f); found = p; break; }
    }
    if (!found)
        throw std::runtime_error("quadgram_load: cannot find english_quadgrams.txt");

    for (int i = 0; i < 26; i++)
        for (int j = 0; j < 26; j++)
            for (int k = 0; k < 26; k++)
                for (int l = 0; l < 26; l++)
                    scores[i][j][k][l] = -99.0f;

    double total = 0.0;
    FILE *f = fopen(found, "r");
    char line[64];
    while (fgets(line, sizeof(line), f)) {
        int a, b, c, d;
        double count;
        if (std::sscanf(line, " %c%c%c%c %lf", &a, &b, &c, &d, &count) >= 5) {
            total += count;
        }
    }

    floor_val = std::log10(0.01 / total);
    std::rewind(f);
    while (fgets(line, sizeof(line), f)) {
        char q[8];
        double count;
        if (std::sscanf(line, " %4s %lf", q, &count) >= 2) {
            int i = q[0] - 'A', j = q[1] - 'A', k = q[2] - 'A', l = q[3] - 'A';
            if (i >= 0 && i < 26 && j >= 0 && j < 26 && k >= 0 && k < 26 && l >= 0 && l < 26) {
                double prob = count / total;
                scores[i][j][k][l] = (float)std::log10(prob);
            }
        }
    }
    fclose(f);
    loaded = true;
}

static void ensure_loaded() {
    if (!loaded) {
        for (auto *p : {"./english_quadgrams.txt", "../english_quadgrams.txt", "CLI/english_quadgrams.txt"}) {
            try { quadgram_load(p); return; }
            catch (...) { continue; }
        }
    }
}

double quadgram_score(const std::string &text) {
    ensure_loaded();
    std::string clean;
    for (unsigned char ch : text) {
        if (ch >= 'a' && ch <= 'z') clean += (char)(ch - 32);
        else if (ch >= 'A' && ch <= 'Z') clean += (char)ch;
    }
    if (clean.size() < 4) return 0.0;
    double sum = 0.0;
    for (size_t i = 0; i + 3 < clean.size(); i++) {
        int a = clean[i] - 'A', b = clean[i+1] - 'A', c = clean[i+2] - 'A', d = clean[i+3] - 'A';
        float v = scores[a][b][c][d];
        if (v < -90.0f) v = (float)floor_val;
        sum += v;
    }
    return sum;
}

double quadgram_score_per_letter(const std::string &text) {
    ensure_loaded();
    std::string clean;
    for (unsigned char ch : text) {
        if (ch >= 'a' && ch <= 'z') clean += (char)(ch - 32);
        else if (ch >= 'A' && ch <= 'Z') clean += (char)ch;
    }
    if (clean.size() < 4) return 0.0;
    double sum = 0.0;
    for (size_t i = 0; i + 3 < clean.size(); i++) {
        int a = clean[i] - 'A', b = clean[i+1] - 'A', c = clean[i+2] - 'A', d = clean[i+3] - 'A';
        float v = scores[a][b][c][d];
        if (v < -90.0f) v = (float)floor_val;
        sum += v;
    }
    return sum / (clean.size() - 3);
}
