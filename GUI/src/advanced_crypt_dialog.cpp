#include "advanced_crypt_dialog.h"
#include "theme_manager.h"
#include "detector.h"
#include "basic_ciphers.h"
#include "standard_ciphers.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QApplication>
#include <QClipboard>
#include <QFont>
#include <QSettings>

#include <string>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <algorithm>
#include <map>

AdvancedCryptDialog::AdvancedCryptDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("Cryptanalysis & Analysis");
    setMinimumSize(700, 650);
    resize(750, 700);
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

void AdvancedCryptDialog::setupUI() {
    ThemePalette pal = ThemeManager::getPaletteFromSettings();

    QVBoxLayout *main = new QVBoxLayout(this);
    main->setContentsMargins(16, 12, 16, 12);
    main->setSpacing(8);

    QLabel *title = new QLabel("ADVANCED CRYPT ANALYSIS");
    QFont tf("Courier New", 14, QFont::Bold);
    tf.setLetterSpacing(QFont::AbsoluteSpacing, 3);
    title->setFont(tf);
    title->setStyleSheet("color: " + pal.text.name() + ";");
    main->addWidget(title, 0, Qt::AlignCenter);

    QHBoxLayout *opRow = new QHBoxLayout();
    opRow->addWidget(new QLabel("Analysis:"));
    m_operation = new QComboBox();
    m_operation->addItem("Auto-Detect Cipher");
    m_operation->addItem("Shannon Entropy");
    m_operation->addItem("Index of Coincidence");
    m_operation->addItem("Sniff Encoding");
    m_operation->addItem("Character Frequency");
    m_operation->addItem("Byte Histogram");
    m_operation->addItem("Entropy + IoC + Length");
    m_operation->setMinimumWidth(250);
    opRow->addWidget(m_operation, 1);
    main->addLayout(opRow);

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

    connect(m_runBtn, &QPushButton::clicked, this, &AdvancedCryptDialog::onRun);

    QLabel *candLabel = new QLabel("Detection Candidates");
    main->addWidget(candLabel);
    m_candidates = new QListWidget();
    m_candidates->setMaximumHeight(100);
    main->addWidget(m_candidates);

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
    m_output->setMinimumHeight(140);
    main->addWidget(m_output, 1);

    connect(copyBtn, &QPushButton::clicked, this, [this]{
        QApplication::clipboard()->setText(m_output->toPlainText());
    });
}

void AdvancedCryptDialog::onRun() {
    std::string input = m_input->toPlainText().toStdString();
    if (input.empty()) return;

    std::string op = m_operation->currentText().toStdString();
    std::ostringstream oss;
    m_candidates->clear();

    if (op == "Auto-Detect Cipher") {
        QSettings s("Obscuron", "CryptoSuite");
        bool aggressive = s.value("detection/aggressive", false).toBool();
        auto results = detect_cipher(input, 7, aggressive);
        if (results.empty()) {
            oss << "No candidates found.\n";
        } else {
            oss << "Top " << results.size() << " candidates:\n\n";
            for (auto &c : results) {
                oss << "  " << c.cipher_name
                    << " (confidence: " << (int)(c.confidence * 100) << "%)";
                if (!c.key.empty()) oss << "  key: " << c.key;
                oss << "\n";
                QListWidgetItem *item = new QListWidgetItem(
                    QString("[%1%] %2").arg((int)(c.confidence * 100))
                        .arg(QString::fromStdString(c.cipher_name)));
                m_candidates->addItem(item);
                if (!c.decrypted.empty()) {
                    std::string preview = c.decrypted.substr(0, 120);
                    if (c.decrypted.size() > 120) preview += "...";
                    oss << "    -> " << preview << "\n";
                }
            }
        }
    } else if (op == "Shannon Entropy") {
        double entropy = compute_entropy(input);
        oss << "Shannon Entropy: " << std::fixed << std::setprecision(4) << entropy << " bits/byte\n\n";
        oss << "Interpretation:\n";
        if (entropy < 1.0) oss << "  Very low entropy — likely plain text or repetitive data\n";
        else if (entropy < 3.0) oss << "  Low entropy — natural language text\n";
        else if (entropy < 5.0) oss << "  Medium entropy — compressed or encoded data\n";
        else if (entropy < 7.0) oss << "  High entropy — likely encrypted or random data\n";
        else oss << "  Very high entropy — probably random / encrypted binary\n";
    } else if (op == "Index of Coincidence") {
        double ioc = compute_ioc(input);
        oss << "Index of Coincidence: " << std::fixed << std::setprecision(6) << ioc << "\n\n";
        oss << "Interpretation:\n";
        oss << "  English text:     ~0.0667\n";
        oss << "  Random text:      ~0.0385\n";
        oss << "  Substitution CIP:  ~0.0667 (monoalphabetic)\n";
        oss << "  Polyalphabetic:   <0.052 (Vigenere etc.)\n";
        oss << "  Your value:       ";
        if (ioc > 0.060) oss << "Monoalphabetic / plaintext\n";
        else if (ioc > 0.045) oss << "Possibly polyalphabetic\n";
        else oss << "Near-random or very short text\n";
    } else if (op == "Sniff Encoding") {
        std::string encoding = sniff_encoding(input);
        oss << "Detected encoding: " << encoding << "\n\n";
        if (encoding == "hex") {
            std::string decoded;
            for (size_t i = 0; i + 1 < input.size(); i += 2) {
                std::string pair = {input[i], input[i+1]};
                long long v; base_deconvert(pair, v, 16);
                decoded += (char)(unsigned char)v;
            }
            oss << "Decoded preview: " << decoded.substr(0, 200) << "\n";
        } else if (encoding == "base64") {
            // Quick b64 decode hint
            oss << "May decode to text — use Base64 Decode in Advanced Crypto\n";
        }
    } else if (op == "Character Frequency") {
        int counts[256] = {0};
        int total = 0;
        for (unsigned char c : input) { counts[c]++; total++; }
        if (total == 0) { oss << "No data\n"; }
        else {
            oss << "Character frequency (top 20):\n\n";
            std::vector<std::pair<int, char>> sorted;
            for (int i = 0; i < 256; i++)
                if (counts[i] > 0) sorted.push_back({counts[i], (char)i});
            std::sort(sorted.begin(), sorted.end(), std::greater<>());
            int n = std::min(20, (int)sorted.size());
            for (int i = 0; i < n; i++) {
                double pct = 100.0 * sorted[i].first / total;
                char c = sorted[i].second;
                QString label;
                if (c >= 32 && c <= 126)
                    label = QString("  '%1'").arg(c);
                else
                    label = QString("  0x%1").arg((unsigned char)c, 2, 16, QChar('0'));
                oss << label.toStdString() << "  " << sorted[i].first
                    << " (" << std::fixed << std::setprecision(2) << pct << "%)\n";
            }
        }
    } else if (op == "Byte Histogram") {
        int counts[256] = {0};
        int total = 0;
        for (unsigned char c : input) { counts[c]++; total++; }
        if (total == 0) { oss << "No data\n"; }
        else {
            oss << "Byte histogram (bar chart for bytes 0-127):\n\n";
            int max_count = 1;
            for (int i = 0; i < 128; i++) max_count = std::max(max_count, counts[i]);
            for (int i = 0; i < 128; i++) {
                if (counts[i] == 0) continue;
                int bar = (int)(40.0 * counts[i] / max_count);
                oss << std::setw(2) << std::hex << i << std::dec << " |"
                    << std::string(bar, '#') << " " << counts[i] << "\n";
            }
        }
    } else if (op == "Entropy + IoC + Length") {
        double entropy = compute_entropy(input);
        double ioc = compute_ioc(input);
        double len = input.size();
        oss << "=== Statistical Profile ===\n\n";
        oss << "Length:           " << (int)len << " bytes\n";
        oss << "Shannon Entropy:  " << std::fixed << std::setprecision(4) << entropy << " bits/byte\n";
        oss << "Index of Coinc.:  " << std::fixed << std::setprecision(6) << ioc << "\n";
        oss << "Sniff Encoding:   " << sniff_encoding(input) << "\n\n";

        std::string probable;
        if (entropy > 7.0) probable = "Encrypted or compressed binary data";
        else if (entropy > 5.5) probable = "Encoded or obfuscated (Base64/Hex with text)";
        else if (entropy > 3.5) probable = "Encoded text or mixed content";
        else probable = "Natural language text or structured data";

        if (ioc > 0.065 && entropy < 4.5) probable += ", monoalphabetic substitution likely";
        else if (ioc < 0.045 && len > 50) probable += ", polyalphabetic or random";

        oss << "Probable type: " << probable << "\n";
    }

    m_output->setPlainText(QString::fromStdString(oss.str()));
}
