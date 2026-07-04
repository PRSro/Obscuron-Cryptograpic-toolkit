#ifndef BASIC_CIPHERS_H
#define BASIC_CIPHERS_H

#include <string>
#include <iostream>
#include <cstdlib>

extern const char padding;
extern const std::string alphabet;
extern const std::string alphabet_full;
extern const std::string alphabet_to_morse;
extern const std::string morse_to_alphabet[38];
extern const std::string braille_alphabet;
extern const std::string braille_map[28];
extern const std::string digit_map[10];
extern const std::string NUMBER_INDICATOR;
extern const std::string LETTER_INDICATOR;

void split(const std::string &a, std::string &out);
void parser(const std::string &a, std::string &out);
void reverser(const std::string &a, std::string &out);
int  deconvert_pair(const std::string &pair, int base);
void base_convert(long long b, std::string &out, int base);
void base_deconvert(const std::string &a, long long &b, int base);
void base_convert_full(long long b, std::string &out, int base);
void base_deconvert_full(const std::string &a, long long &b, int base);
void custom_rot(const std::string &a, int add, std::string &out);
void rot13(const std::string &a, std::string &out);
void a1z26(const std::string &a, std::string &out, char sep='-');
void keyboard_shift(const std::string &a, std::string &out, int dx, int dy, bool encrypt);
void suggestions();

#endif
