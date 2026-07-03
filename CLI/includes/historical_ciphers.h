#ifndef HISTORICAL_CIPHERS_H
#define HISTORICAL_CIPHERS_H

#include <string>
#include "basic_ciphers.h"

void atbash(const std::string &a, std::string &out);
void affine(const std::string &a, std::string &out, int ka, int kb, bool encrypt);
void caesar(const std::string &a, std::string &out);
void vigenere(const std::string &a, const std::string &key, std::string &out, bool encrypt);
void autokey(const std::string &a, const std::string &key, std::string &out, bool encrypt);
void beaufort(const std::string &a, const std::string &key, std::string &out);
void railfence(const std::string &a, std::string &out, int key, int offset);
void scytale_encrypt(const std::string &a, std::string &out, int m);
void scytale_decrypt(const std::string &a, std::string &out, int m);
void polybius_encrypt(const std::string &alphabet, const std::string &a, std::string &out);
void polybius_decrypt(const std::string &alphabet, const std::string &a, std::string &out);
void columnar_encrypt(const std::string &a, std::string &out, const std::string &key);
void columnar_decrypt(const std::string &a, std::string &out, const std::string &key, int original_len);

void build_playfair_grid(const std::string &key, char grid[5][5]);
void playfair(const std::string &a, std::string &out, const std::string &key, bool encrypt);

void build_bifid_grid(const std::string rows[5], char grid[6][6], int row_of[256], int col_of[256]);
void bifid_encrypt(const std::string &msg, std::string &out, char grid[6][6], int row_of[256], int col_of[256]);
void bifid_decrypt(const std::string &msg, std::string &out, char grid[6][6], int row_of[256], int col_of[256]);

void build_trifid_grid(const std::string &key, char grid[3][3][3]);
void trifid(const std::string &a, std::string &out, const std::string &key, int period, bool encrypt);

void build_foursquare_grid(const std::string &key, char grid[5][5]);
void build_standard_grid(char grid[5][5]);
void four_square(const std::string &a, std::string &out, const std::string &key1, const std::string &key2, bool encrypt);

void build_adfgvx_grid(const std::string &key, char grid[6][6]);
void adfgvx(const std::string &a, std::string &out, const std::string &polybius_key, const std::string &col_key, bool encrypt);

void bacon(const std::string &a, std::string &out, bool encrypt);

void morse_encode(const std::string &a, std::string &out);
void morse_decode(const std::string &a, std::string &out);

void braille_to_dots(const std::string &cell, std::string &out);
void braille_print_dots(const std::string &a);
void simple_dots_to_braille(const std::string &dots, std::string &out);
void braille_to_simple_dots(const std::string &cell, std::string &out);
void braille_encode(const std::string &a, std::string &out);
void braille_decode(const std::string &a, std::string &out);

void porta(const std::string &a, const std::string &key, std::string &out);
void gronsfeld(const std::string &a, const std::string &key, std::string &out, bool encrypt);
bool hill_encrypt(const std::string &a, std::string &out, int a11, int a12, int a21, int a22);
bool hill_decrypt(const std::string &a, std::string &out, int a11, int a12, int a21, int a22);
void nihilist_encrypt(const std::string &a, std::string &out, const std::string &key);
void nihilist_decrypt(const std::string &a, std::string &out, const std::string &key);

#endif
