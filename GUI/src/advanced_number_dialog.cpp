#include "advanced_number_dialog.h"
#include "theme_manager.h"
#include "modern_ciphers.h"
#include "outdated_ciphers.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QApplication>
#include <QClipboard>
#include <QFont>
#include <QLabel>
#include <QSettings>

#include <string>
#include <cstring>

AdvancedNumberDialog::AdvancedNumberDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("Advanced Cryptography");
    setMinimumSize(700, 600);
    resize(750, 650);
    {
        QSettings s("Obscuron", "CryptoSuite");
        int themeIdx = s.value("theme/index", 0).toInt();
        bool accentOn = s.value("accent/enabled", false).toBool();
        QColor accent(74, 124, 255);
        if (accentOn) {
            accent = QColor(
                s.value("accent/r", 74).toInt(),
                s.value("accent/g", 124).toInt(),
                s.value("accent/b", 255).toInt()
            );
        }
        ThemeMode mode = static_cast<ThemeMode>(themeIdx);
        setStyleSheet(ThemeManager::getStyleSheet(mode, accent));
    }
    setupUI();
}

void AdvancedNumberDialog::setupUI() {
    ThemePalette pal = ThemeManager::getPaletteFromSettings();

    QVBoxLayout *main = new QVBoxLayout(this);
    main->setContentsMargins(16, 12, 16, 12);
    main->setSpacing(8);

    QLabel *title = new QLabel("ADVANCED CRYPTOGRAPHY");
    QFont tf("Courier New", 14, QFont::Bold);
    tf.setLetterSpacing(QFont::AbsoluteSpacing, 3);
    title->setFont(tf);
    title->setStyleSheet("color: " + pal.text.name() + ";");
    main->addWidget(title, 0, Qt::AlignCenter);

    QHBoxLayout *opRow = new QHBoxLayout();
    opRow->addWidget(new QLabel("Operation:"));
    m_operation = new QComboBox();
    m_operation->addItem("AES-ECB Encrypt");
    m_operation->addItem("AES-ECB Decrypt");
    m_operation->addItem("AES-CBC Encrypt");
    m_operation->addItem("AES-CBC Decrypt");
    m_operation->addItem("AES-CTR Encrypt");
    m_operation->addItem("AES-CTR Decrypt");
    m_operation->addItem("ChaCha20");
    m_operation->addItem("Blowfish Encrypt");
    m_operation->addItem("Blowfish Decrypt");
    m_operation->addItem("DES Encrypt");
    m_operation->addItem("DES Decrypt");
    m_operation->addItem("RC4");
    m_operation->addItem("MD5 Hash");
    m_operation->addItem("SHA1 Hash");
    m_operation->addItem("SHA256 Hash");
    m_operation->addItem("SHA512 Hash");
    m_operation->addItem("BLAKE2b Hash");
    m_operation->addItem("BLAKE2s Hash");
    m_operation->addItem("HMAC-SHA256");
    m_operation->addItem("HMAC-SHA512");
    m_operation->addItem("PBKDF2-SHA256");
    m_operation->addItem("Base64 Encode");
    m_operation->addItem("Base64 Decode");
    m_operation->addItem("Base64url Encode");
    m_operation->addItem("Base64url Decode");
    m_operation->addItem("Hex Encode");
    m_operation->addItem("Hex Decode");
    m_operation->setMinimumWidth(250);
    opRow->addWidget(m_operation, 1);
    main->addLayout(opRow);

    connect(m_operation, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &AdvancedNumberDialog::onOpChanged);

    QFormLayout *paramForm = new QFormLayout();

    m_keyLabel = new QLabel("Key:");
    m_key = new QLineEdit();
    m_key->setPlaceholderText("key (hex or text)");
    paramForm->addRow(m_keyLabel, m_key);

    m_ivLabel = new QLabel("IV/Nonce:");
    m_iv = new QLineEdit();
    m_iv->setPlaceholderText("IV or nonce (hex)");
    paramForm->addRow(m_ivLabel, m_iv);

    m_counterLabel = new QLabel("Counter:");
    m_counter = new QSpinBox();
    m_counter->setRange(0, 999999);
    m_counter->setValue(0);
    paramForm->addRow(m_counterLabel, m_counter);

    m_modeLabel = new QLabel("AES Key Size:");
    m_mode = new QComboBox();
    m_mode->addItem("AES-128");
    m_mode->addItem("AES-192");
    m_mode->addItem("AES-256");
    m_mode->setCurrentIndex(2);
    paramForm->addRow(m_modeLabel, m_mode);

    main->addLayout(paramForm);

    QLabel *inLabel = new QLabel("Input");
    main->addWidget(inLabel);
    m_input = new QPlainTextEdit();
    m_input->setMinimumHeight(80);
    m_input->setMaximumHeight(140);
    main->addWidget(m_input);

    QHBoxLayout *btnRow = new QHBoxLayout();
    btnRow->addStretch();
    m_runBtn = new QPushButton("RUN");
    m_runBtn->setFixedSize(160, 40);
    m_runBtn->setObjectName("runButton");
    btnRow->addWidget(m_runBtn);
    btnRow->addStretch();
    main->addLayout(btnRow);

    connect(m_runBtn, &QPushButton::clicked, this, &AdvancedNumberDialog::onRun);

    QHBoxLayout *outRow = new QHBoxLayout();
    QLabel *outLabel = new QLabel("Output");
    QPushButton *copyBtn = new QPushButton("Copy");
    copyBtn->setFixedWidth(80);
    outRow->addWidget(outLabel);
    outRow->addStretch();
    outRow->addWidget(copyBtn);
    main->addLayout(outRow);

    m_output = new QPlainTextEdit();
    m_output->setReadOnly(true);
    m_output->setMinimumHeight(120);
    main->addWidget(m_output, 1);

    connect(copyBtn, &QPushButton::clicked, this, [this]{
        QApplication::clipboard()->setText(m_output->toPlainText());
    });

    onOpChanged(0);
}

void AdvancedNumberDialog::onOpChanged(int idx) {
    QString op = m_operation->currentText();
    bool needsKey = op.contains("Encrypt") || op.contains("Decrypt")
                    || op.contains("ChaCha20") || op.contains("RC4")
                    || op.contains("HMAC") || op.contains("PBKDF2")
                    || op.contains("Blowfish") || op.contains("DES")
                    || op.contains("BLAKE2");
    bool needsIV = op.contains("AES-CBC") || op.contains("AES-CTR") || op.contains("ChaCha20");
    bool needsCounter = op.contains("ChaCha20");
    bool needsMode = op.contains("AES-");

    m_keyLabel->setVisible(needsKey);
    m_key->setVisible(needsKey);
    m_ivLabel->setVisible(needsIV);
    m_iv->setVisible(needsIV);
    m_counterLabel->setVisible(needsCounter);
    m_counter->setVisible(needsCounter);
    m_modeLabel->setVisible(needsMode);
    m_mode->setVisible(needsMode);

    if (op.contains("PBKDF2")) {
        m_keyLabel->setText("Password:");
        m_ivLabel->setText("Salt:");
        m_counterLabel->setText("Iterations:");
        m_counter->setValue(10000);
        m_counterLabel->setVisible(true);
        m_counter->setVisible(true);
    } else if (op.contains("ChaCha20")) {
        m_keyLabel->setText("Key (32B hex):");
        m_ivLabel->setText("Nonce (12B hex):");
    } else {
        m_keyLabel->setText("Key:");
        m_ivLabel->setText("IV/Nonce:");
        m_counterLabel->setText("Counter:");
    }
}

QString AdvancedNumberDialog::runOp(const std::string &input, const std::string &op,
                                     const std::string &key, const std::string &iv,
                                     int counter, int mode)
{
    std::string out;

    if (op == "MD5 Hash") { md5_hash(input, out); }
    else if (op == "SHA1 Hash") { sha1_hash(input, out); }
    else if (op == "SHA256 Hash") { sha256_hash(input, out); }
    else if (op == "SHA512 Hash") { sha512_hash(input, out); }
    else if (op == "BLAKE2b Hash") { blake2b_hash(input, out, key); }
    else if (op == "BLAKE2s Hash") { blake2s_hash(input, out, key); }
    else if (op == "HMAC-SHA256") { hmac_sha256(input, key, out); }
    else if (op == "HMAC-SHA512") { hmac_sha512(input, key, out); }
    else if (op == "PBKDF2-SHA256") {
        uint32_t iters = (uint32_t)(counter > 0 ? counter : 10000);
        pbkdf2_sha256(input, iv, iters, 32, out);
    }
    else if (op == "AES-ECB Encrypt") {
        std::string k = from_hex(key); if (k.empty()) k = key;
        aes_encrypt(input, k, "", 0, out);
    }
    else if (op == "AES-ECB Decrypt") {
        std::string k = from_hex(key); if (k.empty()) k = key;
        aes_decrypt(input, k, "", 0, out);
    }
    else if (op == "AES-CBC Encrypt") {
        std::string k = from_hex(key), i = from_hex(iv);
        if (k.empty()) k = key;
        aes_encrypt(input, k, i, 1, out);
    }
    else if (op == "AES-CBC Decrypt") {
        std::string k = from_hex(key), i = from_hex(iv);
        if (k.empty()) k = key;
        aes_decrypt(input, k, i, 1, out);
    }
    else if (op == "AES-CTR Encrypt") {
        std::string k = from_hex(key), i = from_hex(iv);
        if (k.empty()) k = key;
        aes_encrypt(input, k, i, 2, out);
    }
    else if (op == "AES-CTR Decrypt") {
        std::string k = from_hex(key), i = from_hex(iv);
        if (k.empty()) k = key;
        aes_decrypt(input, k, i, 2, out);
    }
    else if (op == "ChaCha20") {
        std::string k = from_hex(key), n = from_hex(iv);
        chacha20_crypt(input, k, n, (uint32_t)counter, out);
    }
    else if (op == "Blowfish Encrypt") { blowfish_ecb(input, out, key, true); }
    else if (op == "Blowfish Decrypt") { blowfish_ecb(input, out, key, false); }
    else if (op == "DES Encrypt") { des_ecb(input, out, key, true); }
    else if (op == "DES Decrypt") { des_ecb(input, out, key, false); }
    else if (op == "RC4") { rc4(input, out, key); }
    else if (op == "Base64 Encode") { out = base64_encode(input); }
    else if (op == "Base64 Decode") { out = base64_decode(input); }
    else if (op == "Base64url Encode") { out = base64url_encode(input); }
    else if (op == "Base64url Decode") { out = base64url_decode(input); }
    else if (op == "Hex Encode") {
        out = to_hex((const unsigned char*)input.data(), input.size());
    }
    else if (op == "Hex Decode") { out = from_hex(input); }

    bool printable = true;
    for (unsigned char c : out)
        if (c < 32 && c != '\n' && c != '\t' && c != '\r') { printable = false; break; }
    if (!printable) {
        std::string hex = to_hex((const unsigned char*)out.data(), out.size());
        out = "[raw bytes] " + hex;
    }

    return QString::fromStdString(out);
}

void AdvancedNumberDialog::onRun() {
    std::string input = m_input->toPlainText().toStdString();
    if (input.empty()) return;

    QString op = m_operation->currentText();
    std::string key = m_key->text().toStdString();
    std::string iv  = m_iv->text().toStdString();
    int counter = m_counter->value();
    int mode = m_mode->currentIndex();

    QString result = runOp(input, op.toStdString(), key, iv, counter, mode);
    m_output->setPlainText(result);
}
