#ifndef SCRIPT_ENGINE_H
#define SCRIPT_ENGINE_H

#include <QObject>
#include <QJSEngine>
#include <QJSValue>
#include <QString>

class ScriptBridge : public QObject {
    Q_OBJECT
public:
    explicit ScriptBridge(QObject *parent = nullptr);

    Q_INVOKABLE QString hex_encode(const QString &data) const;
    Q_INVOKABLE QString hex_decode(const QString &data) const;
    Q_INVOKABLE QString base64_encode(const QString &data) const;
    Q_INVOKABLE QString base64_decode(const QString &data) const;
    Q_INVOKABLE QString binary_encode(const QString &data) const;
    Q_INVOKABLE QString binary_decode(const QString &data) const;
    Q_INVOKABLE QString caesar(const QString &data, int shift) const;
    Q_INVOKABLE QString rot13(const QString &data) const;
    Q_INVOKABLE QString rot47(const QString &data) const;
    Q_INVOKABLE QString atbash(const QString &data) const;
    Q_INVOKABLE QString reverse(const QString &data) const;
    Q_INVOKABLE QString vigenere(const QString &data, const QString &key, bool encrypt = true) const;
    Q_INVOKABLE QString xor_cipher(const QString &data, const QString &key) const;
    Q_INVOKABLE QString to_upper(const QString &data) const;
    Q_INVOKABLE QString to_lower(const QString &data) const;
    Q_INVOKABLE double entropy(const QString &data) const;
    Q_INVOKABLE int byte_length(const QString &data) const;
    Q_INVOKABLE QString md5(const QString &data) const;
    Q_INVOKABLE QString sha256(const QString &data) const;
};

class ScriptEngine : public QObject {
    Q_OBJECT
public:
    explicit ScriptEngine(QObject *parent = nullptr);

    QString evaluate(const QString &script, const QString &inputData, QString &errorMsg);
    void interrupt() { m_engine->setInterrupted(true); }

private:
    QJSEngine *m_engine;
    ScriptBridge *m_bridge;
};

#endif
