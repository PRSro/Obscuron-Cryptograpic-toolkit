#include "plugin_crypto_bridge.h"
#include "basic_ciphers.h"
#include "historical_ciphers.h"
#include "standard_ciphers.h"
#include "essential_ciphers.h"
#include "modern_ciphers.h"
#include "detector.h"
#include "bytes.h"

#include <algorithm>
#include <sstream>
#include <iomanip>

PluginCryptoBridge::PluginCryptoBridge(QObject *parent) : QObject(parent) {}

QString PluginCryptoBridge::caesar(const QString &text, int shift) const {
    std::string in = text.toStdString(), out;
    ::custom_rot(in, shift, out);
    return QString::fromStdString(out);
}

QString PluginCryptoBridge::rot13(const QString &text) const {
    std::string in = text.toStdString(), out;
    ::rot13(in, out);
    return QString::fromStdString(out);
}

QString PluginCryptoBridge::rot47(const QString &text) const {
    std::string in = text.toStdString(), out;
    ::rot47(in, out);
    return QString::fromStdString(out);
}

QString PluginCryptoBridge::atbash(const QString &text) const {
    std::string in = text.toStdString(), out;
    ::atbash(in, out);
    return QString::fromStdString(out);
}

QString PluginCryptoBridge::vigenere(const QString &text, const QString &key, bool decrypt) const {
    std::string in = text.toStdString(), out;
    std::string k = key.toStdString();
    ::vigenere(in, k, out, !decrypt);
    return QString::fromStdString(out);
}

QString PluginCryptoBridge::railfence(const QString &text, int rails, int offset) const {
    std::string in = text.toStdString(), out;
    ::railfence(in, out, rails, offset);
    return QString::fromStdString(out);
}

QString PluginCryptoBridge::columnar_encrypt(const QString &text, const QString &key) const {
    std::string in = text.toStdString(), out;
    std::string k = key.toStdString();
    ::columnar_encrypt(in, out, k);
    return QString::fromStdString(out);
}

QString PluginCryptoBridge::columnar_decrypt(const QString &text, const QString &key, int origLen) const {
    std::string in = text.toStdString(), out;
    std::string k = key.toStdString();
    ::columnar_decrypt(in, out, k, origLen);
    return QString::fromStdString(out);
}

QString PluginCryptoBridge::beaufort(const QString &text, const QString &key) const {
    std::string in = text.toStdString(), out;
    std::string k = key.toStdString();
    ::beaufort(in, k, out);
    return QString::fromStdString(out);
}

QString PluginCryptoBridge::xor_single(const QString &text, int keyByte) const {
    std::string in = text.toStdString(), out;
    ::hex_xor(in, static_cast<unsigned char>(keyByte & 0xFF), out);
    return QString::fromStdString(out);
}

QString PluginCryptoBridge::xor_string(const QString &text, const QString &key) const {
    std::string in = text.toStdString(), out;
    std::string k = key.toStdString();
    ::str_xor(in, k, out);
    return QString::fromStdString(out);
}

QString PluginCryptoBridge::bacon(const QString &text, bool decrypt) const {
    std::string in = text.toStdString(), out;
    ::bacon(in, out, decrypt);
    return QString::fromStdString(out);
}

QString PluginCryptoBridge::morse_encode(const QString &text) const {
    std::string in = text.toStdString(), out;
    ::morse_encode(in, out);
    return QString::fromStdString(out);
}

QString PluginCryptoBridge::morse_decode(const QString &text) const {
    std::string in = text.toStdString(), out;
    ::morse_decode(in, out);
    return QString::fromStdString(out);
}

QString PluginCryptoBridge::hex_encode(const QString &data) const {
    std::string in = data.toStdString(), out;
    const std::string hexalpha = "0123456789ABCDEF";
    ::proper_base_convert(in, out, 4, hexalpha);
    return QString::fromStdString(out);
}

QString PluginCryptoBridge::hex_decode(const QString &data) const {
    return QString::fromStdString(::from_hex(data.toStdString()));
}

QString PluginCryptoBridge::base64_encode(const QString &data) const {
    return QString::fromStdString(::base64_encode(data.toStdString()));
}

QString PluginCryptoBridge::base64_decode(const QString &data) const {
    return QString::fromStdString(::base64url_decode(data.toStdString()));
}

QString PluginCryptoBridge::md5(const QString &data) const {
    std::string in = data.toStdString(), out;
    ::md5_hash(in, out);
    return QString::fromStdString(out);
}

QString PluginCryptoBridge::sha256(const QString &data) const {
    std::string in = data.toStdString(), out;
    ::sha256_hash(in, out);
    return QString::fromStdString(out);
}

double PluginCryptoBridge::entropy(const QString &data) const {
    return ::compute_entropy(data.toStdString());
}
