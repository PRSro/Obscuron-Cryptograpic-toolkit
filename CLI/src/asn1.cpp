#include "../includes/asn1.h"
#include "../includes/modern_ciphers.h"
#include <cstdlib>
#include <cctype>
#include <sstream>
#include <stdexcept>
#include <cstring>

// ── Core BER/DER TLV parser ──

Asn1Element asn1_read(const std::string &der, size_t off) {
    Asn1Element el;
    if (off >= der.size()) return el;
    el.tag = (uint8_t)der[off++];
    el.total = 1;
    if (off >= der.size()) { el.total = 0; return el; }
    uint8_t len_byte = (uint8_t)der[off++];
    el.total++;
    size_t length = 0;
    if (len_byte < 0x80) {
        length = len_byte;
    } else {
        uint8_t num_bytes = len_byte & 0x7F;
        if (num_bytes > 8 || off + num_bytes > der.size()) { el.total = 0; return el; }
        for (uint8_t i = 0; i < num_bytes; i++) {
            length = (length << 8) | (uint8_t)der[off++];
            el.total++;
        }
    }
    if (off + length > der.size()) { el.total = 0; return el; }
    el.value = der.substr(off, length);
    el.total += length;
    return el;
}

// ── OID helpers ──

std::string oid_to_string(const std::string &o) {
    if (o.empty()) return "";
    std::string r;
    uint8_t first = (uint8_t)o[0];
    r = std::to_string(first / 40) + "." + std::to_string(first % 40);
    uint64_t val = 0;
    for (size_t i = 1; i < o.size(); i++) {
        uint8_t b = (uint8_t)o[i];
        val = (val << 7) | (b & 0x7F);
        if (!(b & 0x80)) { r += "." + std::to_string(val); val = 0; }
    }
    return r;
}

struct OidEntry { const char *dots; const char *label; };
static const OidEntry OID_TABLE[] = {
    {"2.5.4.3", "CN"},
    {"2.5.4.4", "SN"},
    {"2.5.4.5", "serialNumber"},
    {"2.5.4.6", "C"},
    {"2.5.4.7", "L"},
    {"2.5.4.8", "ST"},
    {"2.5.4.9", "STREET"},
    {"2.5.4.10", "O"},
    {"2.5.4.11", "OU"},
    {"2.5.4.12", "title"},
    {"2.5.4.17", "postalCode"},
    {"2.5.4.42", "GN"},
    {"2.5.4.43", "initials"},
    {"1.2.840.113549.1.9.1", "emailAddress"},
    {"1.2.840.113549.1.1.1", "RSA"},
    {"1.2.840.10045.2.1", "EC"},
    {"1.2.840.113549.1.1.5", "sha1WithRSA"},
    {"1.2.840.113549.1.1.11", "sha256WithRSA"},
    {"1.2.840.113549.1.1.12", "sha384WithRSA"},
    {"1.2.840.113549.1.1.13", "sha512WithRSA"},
    {"1.2.840.10045.4.3.2", "ecdsaWithSHA256"},
    {"1.2.840.10045.4.3.3", "ecdsaWithSHA384"},
    {"1.3.101.112", "ed25519"},
    {"1.3.101.113", "ed448"},
    {"2.5.29.15", "Key Usage"},
    {"2.5.29.17", "Subject Alt Name"},
    {"2.5.29.19", "Basic Constraints"},
    {"2.5.29.37", "Extended Key Usage"},
    {"2.5.29.14", "Subject Key Identifier"},
    {"2.5.29.35", "Authority Key Identifier"},
    {nullptr, nullptr}
};

std::string oid_lookup(const std::string &oid_bytes) {
    std::string dots = oid_to_string(oid_bytes);
    for (int i = 0; OID_TABLE[i].dots != nullptr; i++) {
        if (dots == OID_TABLE[i].dots) return OID_TABLE[i].label;
    }
    return dots;
}

// ── PEM decoder ──

std::string pem_decode(const std::string &pem, std::string &type_out) {
    type_out.clear();
    auto begin_pos = pem.find("-----BEGIN ");
    if (begin_pos == std::string::npos) return "";
    auto nl = pem.find('\n', begin_pos);
    if (nl == std::string::npos) nl = pem.find('\r', begin_pos);
    if (nl == std::string::npos) return "";
    std::string hdr = pem.substr(begin_pos + 11, nl - begin_pos - 11);
    auto end_pos = hdr.find("-----");
    if (end_pos != std::string::npos) type_out = hdr.substr(0, end_pos);
    auto end_label = pem.find("-----END ", nl);
    if (end_label == std::string::npos) return "";
    auto end_marker = pem.rfind("-----", end_label);
    if (end_marker == std::string::npos || end_marker <= nl) return "";
    begin_pos = nl;
    std::string b64 = pem.substr(begin_pos + 1, end_marker - begin_pos - 1);
    b64 = strip_spaces(b64);
    return base64_decode(b64);
}

// ── Tag name lookup ──

std::string asn1_tag_name(uint8_t tag) {
    switch (tag) {
        case 0x01: return "BOOLEAN";
        case 0x02: return "INTEGER";
        case 0x03: return "BIT STRING";
        case 0x04: return "OCTET STRING";
        case 0x05: return "NULL";
        case 0x06: return "OID";
        case 0x0C: return "UTF8String";
        case 0x0D: return "RelativeOID";
        case 0x10: return "SEQUENCE";
        case 0x11: return "SET";
        case 0x12: return "NumericString";
        case 0x13: return "PrintableString";
        case 0x14: return "T61String";
        case 0x16: return "IA5String";
        case 0x17: return "UTCTime";
        case 0x18: return "GeneralizedTime";
        case 0x1E: return "BMPString";
        case 0x30: return "SEQUENCE";
        case 0x31: return "SET";
        default: {
            if ((tag & 0xC0) == 0x80) {
                if (tag == 0xA0) return "[0] (Context)";
                if (tag == 0xA1) return "[1] (Context)";
                if (tag == 0xA2) return "[2] (Context)";
                if (tag == 0xA3) return "[3] (Context)";
                if (tag == 0xA4) return "[4] (Context)";
                if (tag == 0xA5) return "[5] (Context)";
                if (tag == 0xA6) return "[6] (Context)";
                if (tag == 0xA7) return "[7] (Context)";
                if (tag == 0xA8) return "[8] (Context)";
                return "[" + std::to_string(tag & 0x1F) + "] (Context)";
            }
            return "TAG(0x" + to_hex(&tag, 1) + ")";
        }
    }
}

// ── Tree pretty printer ──

static std::string asn1_value_preview(const std::string &value, uint8_t tag) {
    if (value.empty()) return "(empty)";
    if (tag == 0x05) return "NULL";
    if (tag == 0x06) {
        std::string label = oid_lookup(value);
        if (label.find('.') == std::string::npos && !label.empty())
            return "(" + label + ")";
        return label;
    }
    if (value.size() <= 64) {
        bool printable = true;
        for (unsigned char c : value) {
            if (c < 32 && c != '\n' && c != '\r' && c != '\t') { printable = false; break; }
        }
        if (printable) {
            std::string s;
            for (unsigned char c : value) {
                if (c == '\n') s += "\\n";
                else if (c == '\r') s += "\\r";
                else if (c == '\t') s += "\\t";
                else if (c >= 32) s += c;
                else s += '.';
            }
            return "\"" + s + "\"";
        }
    }
    size_t show = value.size() > 32 ? 32 : value.size();
    std::string hex;
    for (size_t i = 0; i < show; i++)
        hex += to_hex((const unsigned char*)&value[i], 1);
    if (value.size() > 32)
        return "0x" + hex + "... (" + std::to_string(value.size()) + " bytes)";
    return "0x" + hex;
}

std::string asn1_tree_string(const std::string &der, int depth) {
    std::string out;
    size_t off = 0;
    int idx = 0;
    while (off < der.size()) {
        Asn1Element el = asn1_read(der, off);
        if (el.total == 0) break;
        std::string indent(depth * 2, ' ');
        out += indent + asn1_tag_name(el.tag);
        out += " (" + std::to_string(el.value.size()) + " bytes)";
        std::string preview = asn1_value_preview(el.value, el.tag);
        if (!preview.empty() && preview != "(empty)")
            out += " " + preview;
        out += "\n";
        if (el.tag == 0x10 || el.tag == 0x30 || el.tag == 0x11 || el.tag == 0x31 ||
            (el.tag >= 0xA0 && el.tag <= 0xA8)) {
            out += asn1_tree_string(el.value, depth + 1);
        }
        off += el.total;
        idx++;
        if (depth == 0 && idx >= 100) {
            out += indent + "... (truncated at 100 elements)\n";
            break;
        }
    }
    return out;
}

// ── JSON output ──

static std::string asn1_value_json(const std::string &value, uint8_t tag) {
    if (tag == 0x01) {
        return value.size() >= 1 && ((uint8_t)value[0] != 0) ? "true" : "false";
    }
    if (tag == 0x02) {
        std::string hex;
        for (size_t i = 0; i < value.size(); i++)
            hex += to_hex((const unsigned char*)&value[i], 1);
        return "\"" + hex + "\"";
    }
    if (tag == 0x05) return "null";
    if (tag == 0x06) {
        std::string dots = oid_to_string(value);
        std::string label = oid_lookup(value);
        if (label == dots) return "\"" + dots + "\"";
        return "{\"oid\":\"" + dots + "\",\"label\":\"" + label + "\"}";
    }
    if (tag == 0x17 || tag == 0x18) {
        return "\"" + value + "\"";
    }
    if (tag == 0x03) {
        std::string hex;
        for (size_t i = 0; i < value.size(); i++)
            hex += to_hex((const unsigned char*)&value[i], 1);
        return "{\"unused_bits\":" + std::to_string(value.empty() ? 0 : (uint8_t)value[0]) + ",\"hex\":\"" + hex + "\"}";
    }
    bool printable = true;
    for (unsigned char c : value) {
        if (c < 32 && c != '\n' && c != '\r' && c != '\t') { printable = false; break; }
    }
    if (printable && !value.empty()) {
        std::string escaped;
        for (unsigned char c : value) {
            if (c == '"') escaped += "\\\"";
            else if (c == '\\') escaped += "\\\\";
            else if (c == '\n') escaped += "\\n";
            else if (c == '\r') escaped += "\\r";
            else if (c == '\t') escaped += "\\t";
            else if (c >= 32) escaped += c;
        }
        return "\"" + escaped + "\"";
    }
    std::string hex;
    for (size_t i = 0; i < value.size(); i++)
        hex += to_hex((const unsigned char*)&value[i], 1);
    return "\"" + hex + "\"";
}

static std::string asn1_elements_json(const std::string &der) {
    std::string out;
    size_t off = 0;
    bool first = true;
    while (off < der.size()) {
        Asn1Element el = asn1_read(der, off);
        if (el.total == 0) break;
        if (!first) out += ",";
        first = false;
        off += el.total;
        out += "{\"tag\":" + std::to_string(el.tag);
        out += ",\"name\":\"" + asn1_tag_name(el.tag) + "\"";
        out += ",\"length\":" + std::to_string(el.value.size());
        if (el.tag == 0x10 || el.tag == 0x30 || el.tag == 0x11 || el.tag == 0x31 ||
            (el.tag >= 0xA0 && el.tag <= 0xA8)) {
            out += ",\"children\":[" + asn1_elements_json(el.value) + "]";
        } else {
            out += ",\"value\":" + asn1_value_json(el.value, el.tag);
        }
        out += "}";
    }
    return out;
}

std::string asn1_tree_json(const std::string &der) {
    return "[" + asn1_elements_json(der) + "]";
}

// ── Utility functions ──

std::string strip_spaces(const std::string &s) {
    std::string r;
    for (char c : s) if (c != ' ' && c != '\n' && c != '\r' && c != '\t') r += c;
    return r;
}

bool is_hex_string(const std::string &s) {
    if (s.empty()) return false;
    for (char c : s) if (!isxdigit((unsigned char)c) && c != ' ' && c != '\n' && c != '\r' && c != '\t') return false;
    return true;
}

// ── ASN.1 time helpers ──

std::string parse_utctime(const std::string &v) {
    if (v.size() < 11) return v;
    int yy = std::stoi(v.substr(0, 2));
    if (yy < 50) yy += 2000; else yy += 1900;
    return std::to_string(yy) + "-" + v.substr(2, 2) + "-" + v.substr(4, 2) + " " +
           v.substr(6, 2) + ":" + v.substr(8, 2) + ":" + v.substr(10, 2) + " UTC";
}

std::string parse_generalized_time(const std::string &v) {
    if (v.size() < 13) return v;
    return v.substr(0, 4) + "-" + v.substr(4, 2) + "-" + v.substr(6, 2) + " " +
           v.substr(8, 2) + ":" + v.substr(10, 2) + ":" + v.substr(12, 2) + " UTC";
}

// ── Distinguished Name helpers ──

void parse_rdn_sequence(const std::string &seq_val, std::string &cn, std::string &o, std::string &ou) {
    size_t off = 0;
    while (off < seq_val.size()) {
        Asn1Element rdn_set = asn1_read(seq_val, off);
        if (rdn_set.total == 0) break;
        off += rdn_set.total;
        size_t soff = 0;
        while (soff < rdn_set.value.size()) {
            Asn1Element attr_seq = asn1_read(rdn_set.value, soff);
            if (attr_seq.total == 0) break;
            soff += attr_seq.total;
            if (attr_seq.tag == 0x30) {
                Asn1Element oid_el = asn1_read(attr_seq.value, 0);
                if (oid_el.tag == 0x06) {
                    std::string label = oid_lookup(oid_el.value);
                    size_t val_off = oid_el.total;
                    Asn1Element val_el = asn1_read(attr_seq.value, val_off);
                    std::string str_val = val_el.value;
                    if (label == "CN") { if (cn.empty()) cn = str_val; }
                    else if (label == "O") { if (o.empty()) o = str_val; }
                    else if (label == "OU") { if (ou.empty()) ou = str_val; }
                }
            }
        }
    }
}

std::string parse_name(const std::string &seq_val) {
    std::string cn, o, ou;
    parse_rdn_sequence(seq_val, cn, o, ou);
    std::string r;
    if (!cn.empty()) r += "CN=" + cn;
    if (!o.empty()) { if (!r.empty()) r += ", "; r += "O=" + o; }
    if (!ou.empty()) { if (!r.empty()) r += ", "; r += "OU=" + ou; }
    return r.empty() ? "(unable to parse)" : r;
}
