#include "script_engine.h"
#include "basic.h"
#include "modern_ciphers.h"
#include "bytes.h"
#include "detector.h"

#include <QJSEngine>
#include <QJSValue>
#include <algorithm>
#include <cctype>
#include <cstring>

// ── ScriptBridge ──

ScriptBridge::ScriptBridge(QObject *parent) : QObject(parent) {}

QString ScriptBridge::hex_encode(const QString &data) const {
    std::string in = data.toStdString(), out;
    const std::string hexalpha = "0123456789ABCDEF";
    proper_base_convert(in, out, 4, hexalpha);
    return QString::fromStdString(out);
}

QString ScriptBridge::hex_decode(const QString &data) const {
    std::string in = data.toStdString(), out;
    for (size_t i = 0; i + 1 < in.size(); i += 2) {
        while (i < in.size() && isspace((unsigned char)in[i])) i++;
        if (i + 1 >= in.size()) break;
        std::string pair = in.substr(i, 2);
        char byte = (char)strtol(pair.c_str(), nullptr, 16);
        out.push_back(byte);
    }
    return QString::fromStdString(out);
}

QString ScriptBridge::base64_encode(const QString &data) const {
    std::string in = data.toStdString(), out;
    const std::string b64alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    proper_base_convert(in, out, 6, b64alpha);
    return QString::fromStdString(out);
}

QString ScriptBridge::base64_decode(const QString &data) const {
    std::string in = data.toStdString();
    return QString::fromStdString(base64url_decode(in));
}

QString ScriptBridge::binary_encode(const QString &data) const {
    std::string in = data.toStdString(), out;
    binary(in, out, true);
    return QString::fromStdString(out);
}

QString ScriptBridge::binary_decode(const QString &data) const {
    std::string in = data.toStdString(), out;
    binary(in, out, false);
    return QString::fromStdString(out);
}

QString ScriptBridge::caesar(const QString &data, int shift) const {
    std::string in = data.toStdString(), out;
    ::custom_rot(in, shift, out);
    return QString::fromStdString(out);
}

QString ScriptBridge::rot13(const QString &data) const {
    std::string in = data.toStdString(), out;
    ::rot13(in, out);
    return QString::fromStdString(out);
}

QString ScriptBridge::rot47(const QString &data) const {
    std::string in = data.toStdString(), out;
    ::rot47(in, out);
    return QString::fromStdString(out);
}

QString ScriptBridge::atbash(const QString &data) const {
    std::string in = data.toStdString(), out;
    ::atbash(in, out);
    return QString::fromStdString(out);
}

QString ScriptBridge::reverse(const QString &data) const {
    std::string in = data.toStdString();
    std::reverse(in.begin(), in.end());
    return QString::fromStdString(in);
}

QString ScriptBridge::vigenere(const QString &data, const QString &key, bool encrypt) const {
    std::string in = data.toStdString(), k = key.toStdString(), out;
    ::vigenere(in, k, out, encrypt);
    return QString::fromStdString(out);
}

QString ScriptBridge::xor_cipher(const QString &data, const QString &key) const {
    std::string in = data.toStdString(), k = key.toStdString();
    if (k.empty()) return data;
    std::string out = in;
    for (size_t i = 0; i < in.size(); i++)
        out[i] = in[i] ^ k[i % k.size()];
    return QString::fromStdString(out);
}

QString ScriptBridge::to_upper(const QString &data) const {
    std::string in = data.toStdString();
    for (char &c : in) c = toupper((unsigned char)c);
    return QString::fromStdString(in);
}

QString ScriptBridge::to_lower(const QString &data) const {
    std::string in = data.toStdString();
    for (char &c : in) c = tolower((unsigned char)c);
    return QString::fromStdString(in);
}

double ScriptBridge::entropy(const QString &data) const {
    std::string in = data.toStdString();
    return compute_entropy(in);
}

int ScriptBridge::byte_length(const QString &data) const {
    return data.size();
}

QString ScriptBridge::md5(const QString &data) const {
    std::string in = data.toStdString(), out;
    md5_hash(in, out);
    return QString::fromStdString(out);
}

QString ScriptBridge::sha256(const QString &data) const {
    std::string in = data.toStdString(), out;
    sha256_hash(in, out);
    return QString::fromStdString(out);
}

// ── ScriptEngine ──

ScriptEngine::ScriptEngine(QObject *parent) : QObject(parent) {
    m_engine = new QJSEngine(this);
    m_bridge = new ScriptBridge(this);
    QJSValue bridgeObj = m_engine->newQObject(m_bridge);
    m_engine->globalObject().setProperty("crypto", bridgeObj);
}

QString ScriptEngine::evaluate(const QString &script, const QString &inputData, QString &errorMsg) {
    m_engine->globalObject().setProperty("input", inputData);
    m_engine->globalObject().setProperty("INPUT", inputData);

    QJSValue result = m_engine->evaluate(script);
    if (result.isError()) {
        errorMsg = QString("Line %1: %2")
            .arg(result.property("lineNumber").toInt())
            .arg(result.toString());
        return QString();
    }
    if (result.isUndefined() || result.isNull())
        return QString();
    return result.toString();
}
