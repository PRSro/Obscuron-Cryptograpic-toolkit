#include "numberwindow.h"
#include "menuwindow.h"
#include "colours.h"
#include "advanced_number_dialog.h"
#include "rsa_attack_dialog.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFont>
#include <QPalette>
#include <QApplication>
#include <QClipboard>
#include <QGroupBox>
#include <QFormLayout>
#include <QSettings>

#include <string>
#include <cstdlib>
#include <cctype>
#include <sstream>
#include <functional>

#include "basic_ciphers.h"
#include "essential_ciphers.h"
#include "bytes.h"
#include "detector.h"
#include "ntl_bridge.h"
#include "bigint.hpp"
#include "theme_manager.h"

NumberWindow::NumberWindow(QWidget *parent) : QMainWindow(parent) {
    setupUI();
}

QWidget* NumberWindow::createConvertTab() {
    ThemePalette pal2 = ThemeManager::getPaletteFromSettings();
    QWidget *tab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(tab);
    layout->setContentsMargins(16, 12, 16, 12);
    layout->setSpacing(8);

    // ── Controls ──
    QHBoxLayout *ctrlRow = new QHBoxLayout();
    ctrlRow->setSpacing(16);

    QLabel *opLabel = new QLabel("Operation:");
    operationCombo = new QComboBox();
    operationCombo->addItem("Encode");
    operationCombo->addItem("Decode");

    QLabel *typeLabel = new QLabel("Type:");
    typeCombo = new QComboBox();
    typeCombo->addItem("Base N");
    typeCombo->addItem("Binary");
    typeCombo->addItem("Octal");
    typeCombo->addItem("Hex");

    baseLabel = new QLabel("Base:");
    baseSpin = new QSpinBox();
    baseSpin->setRange(2, 85);
    baseSpin->setValue(16);

    ctrlRow->addWidget(opLabel);
    ctrlRow->addWidget(operationCombo);
    ctrlRow->addSpacing(8);
    ctrlRow->addWidget(typeLabel);
    ctrlRow->addWidget(typeCombo);
    ctrlRow->addSpacing(8);
    ctrlRow->addWidget(baseLabel);
    ctrlRow->addWidget(baseSpin);
    ctrlRow->addStretch();

    runBtn = new QPushButton("RUN");
    runBtn->setFixedWidth(120);
    runBtn->setObjectName("runButton");
    ctrlRow->addWidget(runBtn);
    ctrlRow->addSpacing(12);

    advancedBtn = new QPushButton("ADVANCED");
    advancedBtn->setFixedWidth(120);
    advancedBtn->setObjectName("accentButton");
    ctrlRow->addWidget(advancedBtn);

    layout->addLayout(ctrlRow);

    connect(advancedBtn, &QPushButton::clicked, this, &NumberWindow::onAdvanced);

    detectBtn = new QPushButton("DETECT BASE");
    detectBtn->setFixedWidth(120);
    detectBtn->setObjectName("accentButton");
    ctrlRow->addWidget(detectBtn);
    ctrlRow->addSpacing(12);

    attackBtn = new QPushButton("ATTACK");
    attackBtn->setFixedWidth(100);
    attackBtn->setObjectName("runButton");
    ctrlRow->addWidget(attackBtn);

    connect(typeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &NumberWindow::onTypeChanged);
    connect(runBtn, &QPushButton::clicked, this, &NumberWindow::onRun);
    connect(detectBtn, &QPushButton::clicked, this, &NumberWindow::onDetect);
    connect(attackBtn, &QPushButton::clicked, this, &NumberWindow::onAttack);
    onTypeChanged(0);

    // ── Input ──
    QLabel *inLabel = new QLabel("Input");
    layout->addWidget(inLabel);
    inputArea = new QPlainTextEdit(this);
    inputArea->setMinimumHeight(100);
    inputArea->setPlaceholderText("Paste values here...");
    layout->addWidget(inputArea);

    // ── Output ──
    QHBoxLayout *outRow = new QHBoxLayout();
    QLabel *outLabel = new QLabel("Output");
    QPushButton *copyBtn = new QPushButton("Copy");
    copyBtn->setFixedWidth(80);
    outRow->addWidget(outLabel);
    outRow->addStretch();
    outRow->addWidget(copyBtn);
    layout->addLayout(outRow);

    outputArea = new QPlainTextEdit(this);
    outputArea->setReadOnly(true);
    outputArea->setMinimumHeight(100);
    layout->addWidget(outputArea, 1);

    connect(copyBtn, &QPushButton::clicked, this, [this]{
        QApplication::clipboard()->setText(outputArea->toPlainText());
    });

    // ── Detect Output ──
    QLabel *detLabel = new QLabel("Base Detection");
    layout->addWidget(detLabel);
    detectOutput = new QPlainTextEdit(this);
    detectOutput->setReadOnly(true);
    detectOutput->setMaximumHeight(100);
    detectOutput->setPlaceholderText("Click DETECT BASE to identify encoding...");
    layout->addWidget(detectOutput);

    return tab;
}

QWidget* NumberWindow::createAttackTab() {
    ThemePalette pal2 = ThemeManager::getPaletteFromSettings();
    QWidget *tab = new QWidget();
    QVBoxLayout *layout = new QVBoxLayout(tab);
    layout->setContentsMargins(16, 12, 16, 12);
    layout->setSpacing(8);

    QLabel *title = new QLabel("RSA AUTO ATTACK");
    QFont tf("Courier New", 14, QFont::Bold);
    tf.setLetterSpacing(QFont::AbsoluteSpacing, 3);
    title->setFont(tf);
    title->setStyleSheet("color: " + pal2.danger.name() + ";");
    layout->addWidget(title, 0, Qt::AlignCenter);

    QLabel *desc = new QLabel("Provide known RSA parameters. The tool tries Pollard Rho, Fermat, Wieners attack, and more.");
    desc->setWordWrap(true);
    desc->setStyleSheet("color: " + pal2.textDim.name() + "; font-size:11px;");
    layout->addWidget(desc);

    QFormLayout *form = new QFormLayout();
    form->setSpacing(6);

    attackN = new QLineEdit();
    attackN->setPlaceholderText("Modulus N (hex)");
    form->addRow("N (hex):", attackN);

    attackE = new QLineEdit();
    attackE->setPlaceholderText("Public exponent e (hex, e.g. 010001 for 65537)");
    form->addRow("E (hex):", attackE);

    attackC = new QLineEdit();
    attackC->setPlaceholderText("Ciphertext (hex, optional)");
    form->addRow("Ciphertext (hex):", attackC);

    layout->addLayout(form);

    QHBoxLayout *btnRow = new QHBoxLayout();
    btnRow->addStretch();
    attackRunBtn = new QPushButton("RUN AUTO ATTACK");
    attackRunBtn->setFixedSize(200, 42);
    attackRunBtn->setObjectName("runButton");
    btnRow->addWidget(attackRunBtn);
    btnRow->addStretch();
    layout->addLayout(btnRow);

    connect(attackRunBtn, &QPushButton::clicked, this, &NumberWindow::onAutoAttack);

    QLabel *outLabel = new QLabel("Attack Results");
    layout->addWidget(outLabel);

    attackOutput = new QPlainTextEdit(this);
    attackOutput->setReadOnly(true);
    attackOutput->setMinimumHeight(200);
    layout->addWidget(attackOutput, 1);

    QPushButton *copyBtn = new QPushButton("Copy Results");
    copyBtn->setFixedWidth(120);
    layout->addWidget(copyBtn, 0, Qt::AlignRight);
    connect(copyBtn, &QPushButton::clicked, this, [this]{
        QApplication::clipboard()->setText(attackOutput->toPlainText());
    });

    return tab;
}

static std::string strip_0x(const std::string &s) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        return s.substr(2);
    return s;
}

static std::string hex_to_text(const std::string &hex) {
    std::string bytes;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        std::string pair = {hex[i], hex[i+1]};
        long long v;
        base_deconvert(pair, v, 16);
        bytes += (char)(unsigned char)v;
    }
    size_t pos = 0;
    if (bytes.size() >= 2 && (unsigned char)bytes[0] == 0x00 && (unsigned char)bytes[1] == 0x02) {
        for (size_t i = 2; i < bytes.size(); i++)
            if ((unsigned char)bytes[i] == 0x00) { pos = i + 1; break; }
    }
    return (pos > 0 && pos < bytes.size()) ? bytes.substr(pos) : bytes;
}

void NumberWindow::runAttackChain(const std::string &n_hex, const std::string &e_hex,
                                   const std::string &c_hex, std::ostringstream &oss) {
    BigInt n = BigInt::from_hex(strip_0x(n_hex));
    BigInt e = e_hex.empty() ? BigInt(0) : BigInt::from_hex(strip_0x(e_hex));
    bool has_c = !c_hex.empty();

    auto bigint_sqrt = [](const BigInt &x) -> BigInt {
        if (x == BigInt(0)) return BigInt(0);
        BigInt r = x, two(2);
        BigInt y = (r + x / r) / two;
        while (y < r) { r = y; y = (r + x / r) / two; }
        return r;
    };

    auto bigint_gcd = [](const BigInt &a, const BigInt &b) -> BigInt {
        BigInt ta = a, tb = b;
        while (tb != BigInt(0)) { BigInt t = tb; tb = ta % tb; ta = t; }
        return ta;
    };

    BigInt p, q, d;
    bool factored = false;

    // 1. Pollard Rho
    oss << "[*] Trying Pollard Rho factoring...\n";
    {
        BigInt x(2), y(2), d1(1);
        auto f = [&n](const BigInt &v) { return (v * v + BigInt(1)) % n; };
        int iter = 0;
        while (d1 == BigInt(1) || d1 == n) {
            x = f(x); y = f(f(y));
            BigInt diff = (x < y) ? y - x : x - y;
            d1 = bigint_gcd(diff, n);
            if (++iter > 500000 || d1 == n) break;
        }
        if (d1 != BigInt(1) && d1 != n) {
            p = d1; q = n / d;
            oss << "[+] Pollard Rho succeeded!\n  p: " << p.toHex()
                << "\n  q: " << q.toHex() << "\n";
            factored = true;
        } else {
            oss << "[-] Pollard Rho failed.\n";
        }
    }

    // 2. Fermat
    if (!factored) {
        oss << "[*] Trying Fermat factoring...\n";
        BigInt a = bigint_sqrt(n);
        if (a * a < n) a = a + BigInt(1);
        for (int iter = 0; iter < 500000; iter++) {
            BigInt b2 = a * a - n;
            BigInt b = bigint_sqrt(b2);
            if (b * b == b2) {
                p = a - b; q = a + b;
                if (p * q == n) {
                    oss << "[+] Fermat factoring succeeded!\n  p: " << p.toHex()
                        << "\n  q: " << q.toHex() << "\n";
                    factored = true; break;
                }
            }
            a = a + BigInt(1);
        }
        if (!factored) oss << "[-] Fermat factoring failed (primes not close enough).\n";
    }

    // 3. Wiener
    if (!factored && e != BigInt(0)) {
        oss << "[*] Trying Wiener attack...\n";
        std::string d_hex, p_hex, q_hex, err;
        if (ntl_rsa_wiener(e.toHex().substr(2), n.toHex().substr(2), d_hex, p_hex, q_hex, err)) {
            d = BigInt::from_hex(d_hex);
            p = BigInt::from_hex(p_hex);
            q = BigInt::from_hex(q_hex);
            oss << "[+] Wiener attack succeeded!\n  d: " << d.toHex()
                << "\n  p: " << p.toHex() << "\n  q: " << q.toHex() << "\n";
            factored = true;
        } else {
            oss << "[-] Wiener attack failed.\n";
        }
    }

    // Decrypt if we have factors
    if (factored && has_c) {
        BigInt ct = BigInt::from_hex(strip_0x(c_hex));
        BigInt phi = (p - BigInt(1)) * (q - BigInt(1));
        d = e.modinv(phi);
        BigInt m = ct.modexp(d, n);
        std::string m_hex = m.toHex();
        std::string plain = hex_to_text(m_hex);
        oss << "\n[+] Decrypted message:\n  hex: " << m_hex
            << "\n  text: \"" << plain << "\"\n";
    } else if (factored && !has_c) {
        oss << "\n[+] Factoring succeeded but no ciphertext provided for decryption.\n";
    } else if (!factored) {
        // Last resort: try direct decrypt if d was provided via other means
        oss << "\n[-] All factoring methods exhausted. Consider providing additional parameters.\n";
        if (e != BigInt(0)) {
            oss << "[*] N bit length: " << (strip_0x(n_hex).size() * 4) << "\n";
        }
    }
}

void NumberWindow::setupUI() {
    setWindowTitle("Obscuron — Number Mode");
    setMinimumSize(800, 600);
    resize(900, 700);

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

    QWidget *central = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    // ── Top bar ──
    QHBoxLayout *topBar = new QHBoxLayout();
    topBar->setContentsMargins(16, 8, 16, 4);
    backBtn = new QPushButton("← Back");
    backBtn->setFixedWidth(100);
    QLabel *title = new QLabel("NUMBER MODE");
    QFont titleF("Courier New", 16, QFont::Bold);
    title->setFont(titleF);
    QPalette tp; tp.setColor(QPalette::WindowText, QColor(107, 156, 255)); title->setPalette(tp);
    topBar->addWidget(backBtn);
    topBar->addWidget(title, 1, Qt::AlignHCenter);
    mainLayout->addLayout(topBar);

    connect(backBtn, &QPushButton::clicked, this, [this]{
        MenuWindow *m = new MenuWindow(); m->setAttribute(Qt::WA_DeleteOnClose); m->show(); this->close();
    });

    // ── Tab Widget ──
    tabWidget = new QTabWidget();
    tabWidget->addTab(createConvertTab(), "Convert");
    tabWidget->addTab(createAttackTab(), "Attack: Auto Attack");
    mainLayout->addWidget(tabWidget, 1);

    setCentralWidget(central);
}

void NumberWindow::onTypeChanged(int index) {
    baseLabel->setVisible(index == 0);
    baseSpin->setVisible(index == 0);
}

void NumberWindow::onRun() {
    std::string input = inputArea->toPlainText().toStdString();
    if (input.empty()) return;

    bool encrypt = (operationCombo->currentIndex() == 0);
    int type = typeCombo->currentIndex();
    int base = baseSpin->value();
    std::string out;

    switch (type) {
    case 0:
        if (encrypt) large_encrypt(input, out, base);
        else large_decrypt(input, out, base);
        break;
    case 1:
        binary(input, out, encrypt);
        break;
    case 2:
        octal(input, out, encrypt);
        break;
    case 3:
        if (encrypt) large_encrypt(input, out, 16);
        else large_decrypt(input, out, 16);
        break;
    }

    outputArea->setPlainText(QString::fromStdString(out));
}

void NumberWindow::onDetect() {
    std::string input = inputArea->toPlainText().toStdString();
    if (input.empty()) {
        detectOutput->setPlainText("No input to analyze.");
        return;
    }
    auto results = detect_base(input, 6);
    std::ostringstream oss;
    if (results.empty()) {
        oss << "No base/encoding detected.\n";
        oss << "Try plain text, hex, base64, binary, octal, or space-separated base-N values.\n";
    } else {
        for (auto &c : results) {
            oss << "  " << (int)(c.confidence * 100) << "%  " << c.cipher_name;
            if (!c.key.empty()) oss << "  key: " << c.key;
            oss << "\n";
            if (!c.decrypted.empty()) {
                std::string preview = c.decrypted.substr(0, 120);
                if (c.decrypted.size() > 120) preview += "...";
                oss << "    \"" << preview << "\"\n";
            }
        }
    }
    detectOutput->setPlainText(QString::fromStdString(oss.str()));
}

void NumberWindow::onAdvanced() {
    AdvancedNumberDialog dlg(this);
    dlg.exec();
}

void NumberWindow::onAttack() {
    RsaAttackDialog dlg(this);
    dlg.exec();
}

void NumberWindow::onAutoAttack() {
    std::string n_hex = attackN->text().toStdString();
    std::string e_hex = attackE->text().toStdString();
    std::string c_hex = attackC->text().toStdString();

    if (n_hex.empty()) {
        attackOutput->setPlainText("Error: N (modulus) is required.");
        return;
    }

    std::ostringstream oss;
    oss << "=== RSA AUTO ATTACK ===\n\n";
    oss << "N hex: " << n_hex << "\n";
    if (!e_hex.empty()) oss << "E hex: " << e_hex << "\n";
    if (!c_hex.empty()) oss << "C hex: " << c_hex << "\n";
    oss << "\n";

    try {
        runAttackChain(n_hex, e_hex, c_hex, oss);
    } catch (std::exception &e) {
        oss << "\nError: " << e.what();
    }

    attackOutput->setPlainText(QString::fromStdString(oss.str()));
}
