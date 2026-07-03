#ifndef ASN1_H
#define ASN1_H

#include <string>
#include <vector>
#include <cstdint>

struct Asn1Element {
    uint8_t tag;
    std::string value;
    size_t total = 0;
};

Asn1Element asn1_read(const std::string &der, size_t off);

std::string oid_to_string(const std::string &o);
std::string oid_lookup(const std::string &oid_bytes);

std::string pem_decode(const std::string &pem, std::string &type_out);

std::string asn1_tag_name(uint8_t tag);
std::string asn1_tree_string(const std::string &der, int depth = 0);
std::string asn1_tree_json(const std::string &der);

std::string strip_spaces(const std::string &s);
bool is_hex_string(const std::string &s);

std::string parse_utctime(const std::string &v);
std::string parse_generalized_time(const std::string &v);

void parse_rdn_sequence(const std::string &seq_val, std::string &cn, std::string &o, std::string &ou);
std::string parse_name(const std::string &seq_val);

#endif
