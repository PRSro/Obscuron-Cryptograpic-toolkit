#include "tls_attack_dialog.h"
#include "theme_manager.h"
#include "colours.h"
#include "modern_ciphers.h"
#include "pcap_reader.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QFont>
#include <QApplication>
#include <QClipboard>
#include <QScrollArea>
#include <QSettings>
#include <QDateTime>
#include <QTimeZone>
#include <sstream>

TlsAttackDialog::TlsAttackDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle("TLS/SSL Attack Panel");
    setMinimumSize(800, 700);
    resize(900, 750);
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
        m_tlsPal = ThemeManager::getPalette(mode, accent);
        QString ss = ThemeManager::getStyleSheet(mode, accent);
        ss +=
            "QTabWidget::pane { background: %1; border: 1px solid %4; }"
            "QTabBar::tab { background: %3; color: %5; border: 1px solid %4;"
            "  padding: 8px 16px; margin-right: 2px; border-top-left-radius: 4px; border-top-right-radius: 4px; }"
            "QTabBar::tab:selected { background: %1; color: %5; border-bottom: 2px solid %6; }"
        ;
        QString bg = (mode == THEME_LIGHT) ? "#f5f5f7" : (mode == THEME_OLED) ? "#000000" : "#0a0514";
        QString surf = (mode == THEME_LIGHT) ? "#ffffff" : (mode == THEME_OLED) ? "#0c0c0c" : "#120a20";
        QString surf2 = (mode == THEME_LIGHT) ? "#f0f0f5" : (mode == THEME_OLED) ? "#141414" : "#1a1030";
        QString border = (mode == THEME_LIGHT) ? "#d2d2d7" : (mode == THEME_OLED) ? "#1a1a1a" : "#1e1850";
        ss = ss.arg(bg).arg(surf).arg(surf2).arg(border).arg(
            (mode == THEME_LIGHT) ? "#1d1d1f" : "#e0e0f0"
        ).arg(accent.name());
        setStyleSheet(ss);
    }

    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(10, 10, 10, 10);

    m_tabs = new QTabWidget();
    mainLayout->addWidget(m_tabs);

    QWidget *fpTab = new QWidget();
    setupFingerprintTab(fpTab);
    m_tabs->addTab(fpTab, "Fingerprint");

    QWidget *sdTab = new QWidget();
    setupSessionDecryptTab(sdTab);
    m_tabs->addTab(sdTab, "Session Decrypt");

    QWidget *certTab = new QWidget();
    setupCertParserTab(certTab);
    m_tabs->addTab(certTab, "Certificate Parser");
}

void TlsAttackDialog::setupFingerprintTab(QWidget *tab) {
    QVBoxLayout *lay = new QVBoxLayout(tab);
    lay->setContentsMargins(8, 8, 8, 8);
    lay->setSpacing(6);

    m_fpInput = new QPlainTextEdit();
    m_fpInput->setPlaceholderText("Paste raw bytes, hex dump, PEM text, or pcap path...");
    m_fpInput->setMinimumHeight(100);
    lay->addWidget(new QLabel("Input:"));
    lay->addWidget(m_fpInput);

    QHBoxLayout *ctrlRow = new QHBoxLayout();
    m_fpAuto = new QCheckBox("Auto-detect on change");
    ctrlRow->addWidget(m_fpAuto);
    ctrlRow->addStretch();
    m_fpAnalyse = new QPushButton("Analyse");
    m_fpAnalyse->setObjectName("accentButton");
    ctrlRow->addWidget(m_fpAnalyse);
    lay->addLayout(ctrlRow);

    m_fpOutput = new QPlainTextEdit();
    m_fpOutput->setReadOnly(true);
    m_fpOutput->setMinimumHeight(120);
    QFont mono("Courier New", 11);
    m_fpOutput->setFont(mono);
    lay->addWidget(new QLabel("Analysis:"));
    lay->addWidget(m_fpOutput);

    m_fpIssues = new QListWidget();
    m_fpIssues->setMinimumHeight(80);
    m_fpIssues->setMaximumHeight(140);
    lay->addWidget(new QLabel("Detected Issues:"));
    lay->addWidget(m_fpIssues);

    connect(m_fpAnalyse, &QPushButton::clicked, this, &TlsAttackDialog::onAnalyse);
    connect(m_fpInput, &QPlainTextEdit::textChanged, this, [this]() {
        if (m_fpAuto->isChecked() && !m_fpInput->toPlainText().trimmed().isEmpty())
            onAnalyse();
    });
}

void TlsAttackDialog::setupSessionDecryptTab(QWidget *tab) {
    QVBoxLayout *lay = new QVBoxLayout(tab);
    lay->setContentsMargins(8, 8, 8, 8);
    lay->setSpacing(6);

    m_sdInput = new QPlainTextEdit();
    m_sdInput->setPlaceholderText("Paste pcap hex dump or raw TLS record bytes...");
    m_sdInput->setMinimumHeight(100);
    lay->addWidget(new QLabel("TLS Record / pcap:"));
    lay->addWidget(m_sdInput);

    m_sdKey = new QLineEdit();
    m_sdKey->setPlaceholderText("Private key (PEM text or hex modulus)");
    lay->addWidget(new QLabel("Private Key:"));
    lay->addWidget(m_sdKey);

    QHBoxLayout *paramRow = new QHBoxLayout();
    paramRow->addWidget(new QLabel("TLS Version:"));
    m_sdVersion = new QComboBox();
    m_sdVersion->addItems({"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"});
    paramRow->addWidget(m_sdVersion);
    paramRow->addWidget(new QLabel("Cipher:"));
    m_sdCipher = new QComboBox();
    m_sdCipher->addItems({"AES-128-CBC", "AES-256-CBC", "AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305"});
    paramRow->addWidget(m_sdCipher);
    paramRow->addStretch();
    lay->addLayout(paramRow);

    m_sdDecrypt = new QPushButton("Decrypt Session");
    m_sdDecrypt->setObjectName("runButton");
    lay->addWidget(m_sdDecrypt);

    m_sdOutput = new QPlainTextEdit();
    m_sdOutput->setReadOnly(true);
    m_sdOutput->setMinimumHeight(150);
    m_sdOutput->setFont(QFont("Courier New", 11));
    lay->addWidget(new QLabel("Decrypted Data:"));
    lay->addWidget(m_sdOutput);

    connect(m_sdDecrypt, &QPushButton::clicked, this, &TlsAttackDialog::onDecrypt);
}

void TlsAttackDialog::setupCertParserTab(QWidget *tab) {
    QVBoxLayout *lay = new QVBoxLayout(tab);
    lay->setContentsMargins(8, 8, 8, 8);
    lay->setSpacing(6);

    m_certInput = new QPlainTextEdit();
    m_certInput->setPlaceholderText("Paste PEM certificate, hex DER, or raw DER bytes...");
    m_certInput->setMinimumHeight(80);
    lay->addWidget(new QLabel("Certificate Input:"));
    lay->addWidget(m_certInput);

    m_certParse = new QPushButton("Parse Certificate");
    m_certParse->setObjectName("accentButton");
    lay->addWidget(m_certParse);

    m_certTree = new QTreeWidget();
    m_certTree->setHeaderLabels({"Field", "Value"});
    m_certTree->setAlternatingRowColors(false);
    m_certTree->setRootIsDecorated(false);
    m_certTree->setMinimumHeight(200);
    lay->addWidget(m_certTree);

    QHBoxLayout *btnRow = new QHBoxLayout();
    m_certExtractRsa = new QPushButton("Extract Public Key → RSA Attack");
    m_certExtractRsa->setObjectName("accentButton");
    btnRow->addWidget(m_certExtractRsa);

    m_certCheckExpiry = new QPushButton("Check Expiry");
    m_certCheckExpiry->setObjectName("runButton");
    btnRow->addWidget(m_certCheckExpiry);
    btnRow->addStretch();
    lay->addLayout(btnRow);

    connect(m_certParse, &QPushButton::clicked, this, &TlsAttackDialog::onParseCert);
    connect(m_certExtractRsa, &QPushButton::clicked, this, &TlsAttackDialog::onExtractRsa);
    connect(m_certCheckExpiry, &QPushButton::clicked, this, &TlsAttackDialog::onCheckExpiry);
}

void TlsAttackDialog::onAnalyse() {
    m_fpOutput->clear();
    m_fpIssues->clear();
    std::string input = m_fpInput->toPlainText().toStdString();
    if (input.empty()) return;

    TlsFingerprint fp = tls_fingerprint(input);

    std::ostringstream os;
    os << "Type:        " << fp.version << "\n";
    os << "Cipher:      " << fp.cipher << "\n";
    if (fp.key_bits > 0)
        os << "Key size:    " << fp.key_bits << "-bit " << fp.key_exchange << "\n";
    else
        os << "Key exchange: " << fp.key_exchange << "\n";
    if (!fp.suggested_attack.empty())
        os << "\nSuggested:   " << fp.suggested_attack << "\n";

    m_fpOutput->setPlainText(QString::fromStdString(os.str()));

    for (const auto &flag : fp.risk_flags) {
        QListWidgetItem *item = new QListWidgetItem(QString::fromStdString(flag));
        bool critical = (flag.find("DROWN") != std::string::npos ||
                        flag.find("WEAK") != std::string::npos ||
                        flag.find("exposed") != std::string::npos);
        bool warning = (flag.find("POODLE") != std::string::npos ||
                       flag.find("BEAST") != std::string::npos ||
                       flag.find("ROBOT") != std::string::npos ||
                       flag.find("CBC") != std::string::npos);
        if (critical)
            item->setForeground(QColor(255, 60, 60));
        else if (warning)
            item->setForeground(QColor(255, 170, 0));
        else
            item->setForeground(QColor(0, 200, 100));
        m_fpIssues->addItem(item);
    }
}

void TlsAttackDialog::onDecrypt() {
    std::string input = m_sdInput->toPlainText().toStdString();
    std::string key   = m_sdKey->text().toStdString();
    if (input.empty()) {
        m_sdOutput->setPlainText("Provide a pcap path or hex-encoded TLS records.");
        return;
    }

    std::vector<PcapPacket> packets;
    std::vector<TlsRecord> records;
    std::vector<TlsSession> sessions;
    std::string error;
    std::string result;

    // Try as pcap file first
    if (read_pcap(input, packets, error)) {
        result += "[pcap] loaded " + std::to_string(packets.size()) + " packets\n";
        if (!key.empty()) {
            std::vector<TlsSession> keylog_sessions;
            if (load_keylog(key, keylog_sessions, error)) {
                result += "[keylog] loaded " + std::to_string(keylog_sessions.size()) + " sessions\n";
                sessions = keylog_sessions;
            }
        }

        if (!extract_tls_records(packets, records, error)) {
            m_sdOutput->setPlainText(QString::fromStdString(result + "No TLS records found."));
            return;
        }
        result += "[tls] " + std::to_string(records.size()) + " records extracted\n";

        // Try to extract handshake random values
        std::vector<TlsSession> handshake_sessions;
        if (extract_tls_sessions(packets, handshake_sessions, error)) {
            result += "[handshake] " + std::to_string(handshake_sessions.size()) + " sessions\n";
            // Merge keylog master keys into handshake sessions by client_random
            for (auto &hs : handshake_sessions) {
                for (const auto &kl : sessions) {
                    if (kl.client_random == hs.client_random) {
                        hs.master_key = kl.master_key;
                        break;
                    }
                }
            }

            // Map cipher_dropdown to cipher_suite value
            int cipher_idx = m_sdCipher->currentIndex();
            uint16_t cs = 0x002F; // default AES-128-CBC-SHA
            switch (cipher_idx) {
                case 0: cs = 0x002F; break; // AES-128-CBC
                case 1: cs = 0x0035; break; // AES-256-CBC
                case 2: cs = 0x009C; break; // AES-128-GCM
                case 3: cs = 0x009D; break; // AES-256-GCM
                case 4: cs = 0x009C; break; // ChaCha20 -> use AES-128-GCM fallback
            }

            bool decrypted_any = false;
            for (auto &sess : handshake_sessions) {
                if (sess.master_key.empty()) {
                    result += "  [session] no master key for ClientHello " +
                              to_hex(sess.client_random.data(), 8) + "... skipping\n";
                    continue;
                }
                sess.cipher_suite = cs;
                if (!sessions.empty() && sessions[0].cipher_suite != 0)
                    sess.cipher_suite = sessions[0].cipher_suite;

                std::string output;
                if (tls_decrypt_application_data(records, sess, output, error)) {
                    result += "[decrypt] " + std::to_string(output.size()) + " bytes:\n";
                    // Show printable portion
                    bool printable = true;
                    for (unsigned char ch : output) {
                        if (ch < 32 && ch != '\n' && ch != '\r' && ch != '\t') {
                            printable = false; break;
                        }
                    }
                    if (printable) result += output + "\n";
                    else result += "(hex) " + to_hex((const unsigned char*)output.data(), output.size()) + "\n";
                    decrypted_any = true;
                } else {
                    result += "  [decrypt] failed: " + error + "\n";
                }
            }
            if (!decrypted_any)
                result += "[!] No application data decrypted. Check keylog cipher suite match.\n";
        }
    } else {
        // Treat input as hex-encoded TLS records directly
        std::string raw_str = from_hex(input);
        if (raw_str.empty() && !input.empty()) {
            m_sdOutput->setPlainText(QString::fromStdString("Cannot read as pcap file or hex input:\n" + error));
            return;
        }
        std::vector<uint8_t> raw(raw_str.begin(), raw_str.end());
        result += "[hex] parsed " + std::to_string(raw.size()) + " bytes\n";
        size_t off = 0;
        while (off + 5 <= raw.size()) {
            uint8_t ct = raw[off];
            uint16_t ver = ((uint16_t)raw[off+1]<<8)|raw[off+2];
            uint16_t len = ((uint16_t)raw[off+3]<<8)|raw[off+4];
            if (off + 5 + len > raw.size()) break;
            TlsRecord rec;
            rec.content_type = ct; rec.version = ver;
            rec.fragment.assign(raw.begin()+off+5, raw.begin()+off+5+len);
            records.push_back(rec);
            off += 5 + len;
        }
        result += "[tls] " + std::to_string(records.size()) + " records\n";
        if (records.empty()) {
            m_sdOutput->setPlainText("No valid TLS records found in hex data.");
            return;
        }

        // Parse handshake for random values
        for (const auto &rec : records) {
            if (rec.content_type != 22) continue;
            const auto &f = rec.fragment;
            if (f.size() < 4) continue;
            uint8_t hs_type = f[0];
            uint32_t hs_len = ((uint32_t)f[1]<<16)|((uint32_t)f[2]<<8)|f[3];
            if (hs_type == 1 && hs_len >= 38 && 4+38 <= f.size()) {
                TlsSession sess;
                sess.client_random.assign(f.begin()+6, f.begin()+38);
                sessions.push_back(sess);
            } else if (hs_type == 2 && hs_len >= 38 && !sessions.empty() && 4+38 <= f.size()) {
                TlsSession &sess = sessions.back();
                sess.server_random.assign(f.begin()+6, f.begin()+38);
            }
        }

        // Use cipher from dropdown
        uint16_t cs = 0x002F;
        switch (m_sdCipher->currentIndex()) {
            case 0: cs = 0x002F; break;
            case 1: cs = 0x0035; break;
            case 2: cs = 0x009C; break;
            case 3: cs = 0x009D; break;
        }
        for (auto &sess : sessions) sess.cipher_suite = cs;

        if (!key.empty()) {
            // Try key as hex master key (96 hex chars)
            if (key.size() == 96) {
                std::string mk_str = from_hex(key);
            std::vector<uint8_t> mk(mk_str.begin(), mk_str.end());
            if (!mk.empty() && mk.size() == 48)
                    for (auto &sess : sessions) sess.master_key = mk;
            }
        }

        bool decrypted = false;
        for (auto &sess : sessions) {
            if (sess.master_key.empty() || sess.server_random.empty()) continue;
            std::string output;
            if (tls_decrypt_application_data(records, sess, output, error)) {
                bool printable = true;
                for (unsigned char ch : output) {
                    if (ch < 32 && ch != '\n' && ch != '\r' && ch != '\t') {
                        printable = false; break;
                    }
                }
                result += "[decrypt] " + std::to_string(output.size()) + " bytes:\n";
                if (printable) result += output + "\n";
                else result += "(hex) " + to_hex((const unsigned char*)output.data(), output.size()) + "\n";
                decrypted = true;
            }
        }
        if (!decrypted)
            result += "[!] Decryption failed. Verify master key / keylog and cipher suite selection.\n";
    }

    m_sdOutput->setPlainText(QString::fromStdString(result));
}

void TlsAttackDialog::onParseCert() {
    m_certTree->clear();
    std::string input = m_certInput->toPlainText().toStdString();
    if (input.empty()) return;

    CertInfo ci = parse_certificate(input);

    auto addItem = [&](const QString &field, const QString &value, const QColor &color = QColor(224, 224, 240)) {
        QTreeWidgetItem *item = new QTreeWidgetItem({field, value});
        item->setForeground(0, QColor(136, 128, 160));
        item->setForeground(1, color);
        m_certTree->addTopLevelItem(item);
    };

    addItem("Subject CN", QString::fromStdString(ci.subject_cn));
    addItem("Subject O", QString::fromStdString(ci.subject_o));
    addItem("Issuer", QString::fromStdString(ci.issuer));
    addItem("Valid From", QString::fromStdString(ci.valid_from));
    addItem("Valid Until", QString::fromStdString(ci.valid_until));
    addItem("Public Key Algorithm", QString::fromStdString(ci.pubkey_algo));
    if (ci.pubkey_bits > 0)
        addItem("Public Key Bits", QString::number(ci.pubkey_bits));
    addItem("Serial Number (hex)", QString::fromStdString(ci.serial_hex));
    addItem("SHA256 Fingerprint", QString::fromStdString(ci.sha256_fingerprint));

    if (ci.pubkey_algo == "RSA") {
        addItem("Modulus (hex)", QString::fromStdString(ci.modulus_hex), QColor(0, 204, 136));
        addItem("Exponent (hex)", QString::fromStdString(ci.exponent_hex), QColor(0, 204, 136));
    }

    std::string san_str;
    for (size_t i = 0; i < ci.san_entries.size(); i++) {
        if (!san_str.empty()) san_str += "\n";
        san_str += ci.san_entries[i];
    }
    if (!san_str.empty())
        addItem("Subject Alt Names", QString::fromStdString(san_str));

    std::string ku_str;
    for (size_t i = 0; i < ci.key_usage.size(); i++) {
        if (!ku_str.empty()) ku_str += ", ";
        ku_str += ci.key_usage[i];
    }
    if (!ku_str.empty())
        addItem("Key Usage", QString::fromStdString(ku_str));

    addItem("Self-Signed", ci.is_self_signed ? "Yes" : "No",
            ci.is_self_signed ? QColor(255, 170, 0) : QColor(0, 200, 100));
}

void TlsAttackDialog::onExtractRsa() {
    // Find modulus and exponent from the tree
    QString mod, exp;
    for (int i = 0; i < m_certTree->topLevelItemCount(); i++) {
        QTreeWidgetItem *item = m_certTree->topLevelItem(i);
        if (item->text(0) == "Modulus (hex)")
            mod = item->text(1);
        if (item->text(0) == "Exponent (hex)")
            exp = item->text(1);
    }
    if (mod.isEmpty()) {
        // Try parsing again from input
        onParseCert();
        for (int i = 0; i < m_certTree->topLevelItemCount(); i++) {
            QTreeWidgetItem *item = m_certTree->topLevelItem(i);
            if (item->text(0) == "Modulus (hex)")
                mod = item->text(1);
            if (item->text(0) == "Exponent (hex)")
                exp = item->text(1);
        }
    }
    if (!mod.isEmpty())
        emit rsaParamsExtracted(mod, exp);
}

void TlsAttackDialog::onCheckExpiry() {
    QString validUntil;
    for (int i = 0; i < m_certTree->topLevelItemCount(); i++) {
        QTreeWidgetItem *item = m_certTree->topLevelItem(i);
        if (item->text(0) == "Valid Until")
            validUntil = item->text(1);
    }
    if (validUntil.isEmpty()) {
        m_certCheckExpiry->setText("No date parsed");
        return;
    }

    // Parse "YYYY-MM-DD HH:MM:SS UTC" format
    QDateTime dt = QDateTime::fromString(validUntil.left(19), "yyyy-MM-dd HH:mm:ss");
    if (!dt.isValid()) {
        m_certCheckExpiry->setText("Cannot parse date");
        return;
    }
    dt.setTimeZone(QTimeZone::utc());

    if (dt < QDateTime::currentDateTimeUtc()) {
        m_certCheckExpiry->setText("EXPIRED");
    } else {
        m_certCheckExpiry->setText("Valid (expires " + dt.toString("yyyy-MM-dd") + ")");
    }
}
