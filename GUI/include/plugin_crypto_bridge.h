#ifndef PLUGIN_CRYPTO_BRIDGE_H
#define PLUGIN_CRYPTO_BRIDGE_H

#include <QObject>
#include <QString>

class PluginCryptoBridge : public QObject {
    Q_OBJECT
public:
    explicit PluginCryptoBridge(QObject *parent = nullptr);

    Q_INVOKABLE QString caesar(const QString &text, int shift) const;
    Q_INVOKABLE QString rot13(const QString &text) const;
    Q_INVOKABLE QString rot47(const QString &text) const;
    Q_INVOKABLE QString atbash(const QString &text) const;
    Q_INVOKABLE QString vigenere(const QString &text, const QString &key, bool decrypt) const;
    Q_INVOKABLE QString railfence(const QString &text, int rails, int offset) const;
    Q_INVOKABLE QString columnar_encrypt(const QString &text, const QString &key) const;
    Q_INVOKABLE QString columnar_decrypt(const QString &text, const QString &key, int origLen) const;
    Q_INVOKABLE QString beaufort(const QString &text, const QString &key) const;
    Q_INVOKABLE QString xor_single(const QString &text, int keyByte) const;
    Q_INVOKABLE QString xor_string(const QString &text, const QString &key) const;
    Q_INVOKABLE QString bacon(const QString &text, bool decrypt) const;
    Q_INVOKABLE QString morse_encode(const QString &text) const;
    Q_INVOKABLE QString morse_decode(const QString &text) const;
    Q_INVOKABLE QString hex_encode(const QString &data) const;
    Q_INVOKABLE QString hex_decode(const QString &data) const;
    Q_INVOKABLE QString base64_encode(const QString &data) const;
    Q_INVOKABLE QString base64_decode(const QString &data) const;
    Q_INVOKABLE QString md5(const QString &data) const;
    Q_INVOKABLE QString sha256(const QString &data) const;
    Q_INVOKABLE double entropy(const QString &data) const;
};

#endif
