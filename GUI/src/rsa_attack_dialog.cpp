#include "rsa_attack_dialog.h"
#include "theme_manager.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QFont>
#include <QApplication>
#include <QClipboard>
#include <QSettings>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <functional>

#include "detector.h"
#include "ntl_bridge.h"
#include "bigint.hpp"
#include "basic_ciphers.h"

RsaAttackDialog::RsaAttackDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle("RSA Attack Suite");
    setMinimumSize(750, 650);
    resize(800, 700);
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

void RsaAttackDialog::setupUI() {
    ThemePalette pal = ThemeManager::getPaletteFromSettings();
    QVBoxLayout *main = new QVBoxLayout(this);
    main->setContentsMargins(16, 12, 16, 12);
    main->setSpacing(8);

    QLabel *title = new QLabel("RSA ATTACK SUITE");
    QFont tf("Courier New", 14, QFont::Bold);
    tf.setLetterSpacing(QFont::AbsoluteSpacing, 3);
    title->setFont(tf);
    title->setStyleSheet("color: " + pal.text.name() + ";");
    main->addWidget(title, 0, Qt::AlignCenter);

    QHBoxLayout *opRow = new QHBoxLayout();
    opRow->addWidget(new QLabel("Operation:"));
    m_operation = new QComboBox();
    m_operation->addItem("RSA Decrypt");
    m_operation->addItem("RSA Wiener Attack");
    m_operation->addItem("RSA Hastad Broadcast");
    m_operation->addItem("RSA Common Modulus");
    m_operation->addItem("RSA Fermat Factor");
    m_operation->addItem("RSA Pollard Rho Factor");
    m_operation->addItem("RSA Encode");
    m_operation->addItem("RSA Info");
    m_operation->addItem("EC Point Add");
    m_operation->addItem("EC Scalar Mul");
    m_operation->addItem("DLP BSGS");
    m_operation->addItem("DLP Pohlig-Hellman");
    m_operation->addItem("LLL Reduce");
    m_operation->setMinimumWidth(280);
    opRow->addWidget(m_operation, 1);
    main->addLayout(opRow);

    connect(m_operation, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &RsaAttackDialog::onOpChanged);

    QFormLayout *paramForm = new QFormLayout();

    m_lbl1 = new QLabel("N (hex):");
    m_param1 = new QLineEdit();
    m_param1->setPlaceholderText("modulus hex");
    paramForm->addRow(m_lbl1, m_param1);

    m_lbl2 = new QLabel("E (hex):");
    m_param2 = new QLineEdit();
    m_param2->setPlaceholderText("public exponent hex");
    paramForm->addRow(m_lbl2, m_param2);

    m_lbl3 = new QLabel("Ciphertext (hex):");
    m_param3 = new QLineEdit();
    m_param3->setPlaceholderText("hex ciphertext");
    paramForm->addRow(m_lbl3, m_param3);

    m_lbl4 = new QLabel("D (hex):");
    m_param4 = new QLineEdit();
    m_param4->setPlaceholderText("private exponent hex");
    paramForm->addRow(m_lbl4, m_param4);

    m_lbl5 = new QLabel("Extra:");
    m_param5 = new QLineEdit();
    m_param5->setPlaceholderText("extra params");
    paramForm->addRow(m_lbl5, m_param5);

    main->addLayout(paramForm);

    QLabel *inLabel = new QLabel("Input / Plaintext");
    main->addWidget(inLabel);
    m_input = new QPlainTextEdit();
    m_input->setMinimumHeight(70);
    m_input->setMaximumHeight(120);
    main->addWidget(m_input);

    QHBoxLayout *btnRow = new QHBoxLayout();
    btnRow->addStretch();
    m_runBtn = new QPushButton("RUN");
    m_runBtn->setFixedSize(160, 40);
    m_runBtn->setObjectName("runButton");
    btnRow->addWidget(m_runBtn);
    btnRow->addStretch();
    main->addLayout(btnRow);

    connect(m_runBtn, &QPushButton::clicked, this, &RsaAttackDialog::onRun);

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
    m_output->setMinimumHeight(150);
    main->addWidget(m_output, 1);

    connect(copyBtn, &QPushButton::clicked, this, [this]{
        QApplication::clipboard()->setText(m_output->toPlainText());
    });

    onOpChanged(0);
}

void RsaAttackDialog::onOpChanged(int) {
    updateParams();
}

void RsaAttackDialog::updateParams() {
    QString op = m_operation->currentText();
    m_lbl1->setVisible(true); m_param1->setVisible(true);
    m_lbl2->setVisible(true); m_param2->setVisible(true);
    m_lbl3->setVisible(true); m_param3->setVisible(true);
    m_lbl4->setVisible(true); m_param4->setVisible(true);
    m_lbl5->setVisible(true); m_param5->setVisible(true);
    m_input->setVisible(false);
    m_lbl1->setText("N (hex):"); m_param1->setPlaceholderText("modulus hex");
    m_lbl2->setText("E (hex):"); m_param2->setPlaceholderText("public exponent hex");
    m_lbl3->setText("Ciphertext (hex):"); m_param3->setPlaceholderText("hex ciphertext");
    m_lbl4->setText("D (hex):"); m_param4->setPlaceholderText("private exponent hex");
    m_lbl5->setText("Extra:"); m_param5->setPlaceholderText("extra params");

    if (op == "RSA Decrypt") {
        m_lbl1->setText("N (hex):"); m_param1->setPlaceholderText("modulus hex");
        m_lbl2->setText("D (hex):"); m_param2->setPlaceholderText("private exponent hex");
        m_param3->setPlaceholderText("ciphertext hex");
        m_lbl4->setVisible(false); m_param4->setVisible(false);
        m_lbl5->setVisible(false); m_param5->setVisible(false);
    } else if (op == "RSA Wiener Attack") {
        m_lbl3->setVisible(false); m_param3->setVisible(false);
        m_lbl4->setVisible(false); m_param4->setVisible(false);
        m_lbl5->setVisible(false); m_param5->setVisible(false);
    } else if (op == "RSA Hastad Broadcast") {
        m_lbl2->setText("E (decimal):"); m_param2->setPlaceholderText("public exponent e.g. 3");
        m_lbl3->setText("Ciphertexts (csv):"); m_param3->setPlaceholderText("c1,c2,c3 (hex)");
        m_lbl4->setText("Moduli (csv):"); m_param4->setPlaceholderText("n1,n2,n3 (hex)");
        m_lbl5->setVisible(false); m_param5->setVisible(false);
    } else if (op == "RSA Common Modulus") {
        m_lbl1->setText("N (hex):"); m_param1->setPlaceholderText("shared modulus hex");
        m_lbl2->setText("E1 (hex):"); m_param2->setPlaceholderText("first exponent hex");
        m_lbl3->setText("C1 (hex):"); m_param3->setPlaceholderText("first ciphertext hex");
        m_lbl4->setText("E2 (hex):"); m_param4->setPlaceholderText("second exponent hex");
        m_lbl5->setText("C2 (hex):"); m_param5->setPlaceholderText("second ciphertext hex");
    } else if (op == "RSA Fermat Factor" || op == "RSA Pollard Rho Factor") {
        m_lbl2->setVisible(false); m_param2->setVisible(false);
        m_lbl3->setVisible(false); m_param3->setVisible(false);
        m_lbl4->setVisible(false); m_param4->setVisible(false);
        m_lbl5->setVisible(false); m_param5->setVisible(false);
    } else if (op == "RSA Encode") {
        m_lbl3->setVisible(false); m_param3->setVisible(false);
        m_lbl4->setVisible(false); m_param4->setVisible(false);
        m_lbl5->setVisible(false); m_param5->setVisible(false);
        m_input->setVisible(true);
    } else if (op == "RSA Info") {
        m_lbl2->setVisible(true);
        m_lbl3->setVisible(false); m_param3->setVisible(false);
        m_lbl4->setVisible(false); m_param4->setVisible(false);
        m_lbl5->setVisible(false); m_param5->setVisible(false);
    } else if (op == "EC Point Add") {
        m_lbl1->setText("X1 (hex):"); m_param1->setPlaceholderText("x1 hex");
        m_lbl2->setText("Y1 (hex):"); m_param2->setPlaceholderText("y1 hex");
        m_lbl3->setText("X2 (hex):"); m_param3->setPlaceholderText("x2 hex");
        m_lbl4->setText("Y2 (hex):"); m_param4->setPlaceholderText("y2 hex");
        m_lbl5->setText("A,P (hex):"); m_param5->setPlaceholderText("a,p hex (comma)");
    } else if (op == "EC Scalar Mul") {
        m_lbl1->setText("K (hex):"); m_param1->setPlaceholderText("scalar hex");
        m_lbl2->setText("X (hex):"); m_param2->setPlaceholderText("x hex");
        m_lbl3->setText("Y (hex):"); m_param3->setPlaceholderText("y hex");
        m_lbl4->setText("A (hex):"); m_param4->setPlaceholderText("curve parameter a");
        m_lbl5->setText("P (hex):"); m_param5->setPlaceholderText("field prime p");
    } else if (op == "DLP BSGS" || op == "DLP Pohlig-Hellman") {
        m_lbl1->setText("G (hex):"); m_param1->setPlaceholderText("generator g hex");
        m_lbl2->setText("H (hex):"); m_param2->setPlaceholderText("target h hex");
        m_lbl3->setText("P (hex):"); m_param3->setPlaceholderText("modulus p hex");
        m_lbl4->setVisible(false); m_param4->setVisible(false);
        m_lbl5->setVisible(false); m_param5->setVisible(false);
    } else if (op == "LLL Reduce") {
        m_lbl1->setText("Matrix:"); m_param1->setPlaceholderText("[[a,b],[c,d]]");
        m_lbl2->setVisible(false); m_param2->setVisible(false);
        m_lbl3->setVisible(false); m_param3->setVisible(false);
        m_lbl4->setVisible(false); m_param4->setVisible(false);
        m_lbl5->setVisible(false); m_param5->setVisible(false);
    }
}

static std::string strip_0x(const std::string &s) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        return s.substr(2);
    return s;
}

void RsaAttackDialog::onRun() {
    QString op = m_operation->currentText();
    std::string input = m_input->toPlainText().toStdString();
    std::string p1 = m_param1->text().toStdString();
    std::string p2 = m_param2->text().toStdString();
    std::string p3 = m_param3->text().toStdString();
    std::string p4 = m_param4->text().toStdString();
    std::string p5 = m_param5->text().toStdString();

    std::ostringstream oss;

    try {
        if (op == "RSA Decrypt") {
            std::string m_hex, err;
            if (!ntl_rsa_decrypt(p3, p2, p1, m_hex, err))
                throw std::runtime_error(err);
            std::string bytes;
            for (size_t i = 0; i + 1 < m_hex.size(); i += 2) {
                std::string pair = {m_hex[i], m_hex[i+1]};
                long long v;
                base_deconvert(pair, v, 16);
                bytes += (char)(unsigned char)v;
            }
            size_t pos = 0;
            if (bytes.size() >= 2 && (unsigned char)bytes[0] == 0x00
                && (unsigned char)bytes[1] == 0x02) {
                for (size_t i = 2; i < bytes.size(); i++)
                    if ((unsigned char)bytes[i] == 0x00) { pos = i + 1; break; }
            }
            std::string plaintext = (pos > 0 && pos < bytes.size())
                ? bytes.substr(pos) : bytes;
            oss << "Decrypted: " << plaintext << "\nhex: " << m_hex;
        } else if (op == "RSA Wiener Attack") {
            std::string d_hex, p_hex, q_hex, err;
            if (!ntl_rsa_wiener(p1, p2, d_hex, p_hex, q_hex, err))
                throw std::runtime_error(err);
            BigInt d = BigInt::from_hex(d_hex);
            oss << "d (hex): " << d_hex << "\nd (dec): " << d.toString();
        } else if (op == "RSA Hastad Broadcast") {
            int e = std::atoi(p2.c_str());
            auto split = [](const std::string &s) {
                std::vector<std::string> r; std::string cur;
                for (char c : s) { if (c == ',') { if (!cur.empty()) r.push_back(strip_0x(cur)); cur.clear(); } else cur += c; }
                if (!cur.empty()) r.push_back(strip_0x(cur)); return r;
            };
            auto c_list = split(p3), n_list = split(p4);
            std::string m_hex, err;
            if (!ntl_rsa_hastad(c_list, n_list, e, m_hex, err))
                throw std::runtime_error(err);
            std::string bytes;
            for (size_t i = 0; i + 1 < m_hex.size(); i += 2) {
                std::string pair = {m_hex[i], m_hex[i+1]};
                long long v;
                base_deconvert(pair, v, 16);
                bytes += (char)(unsigned char)v;
            }
            size_t pos = 0;
            if (bytes.size() >= 2 && (unsigned char)bytes[0] == 0x00 && (unsigned char)bytes[1] == 0x02) {
                for (size_t i = 2; i < bytes.size(); i++)
                    if ((unsigned char)bytes[i] == 0x00) { pos = i + 1; break; }
            }
            std::string plaintext = (pos > 0 && pos < bytes.size()) ? bytes.substr(pos) : bytes;
            oss << "Recovered: " << plaintext << "\nhex: " << m_hex;
        } else if (op == "RSA Common Modulus") {
            BigInt n = BigInt::from_hex(strip_0x(p1));
            BigInt e1 = BigInt::from_hex(strip_0x(p2));
            BigInt c1 = BigInt::from_hex(strip_0x(p3));
            BigInt e2 = BigInt::from_hex(strip_0x(p4));
            BigInt c2 = BigInt::from_hex(strip_0x(p5));
            std::function<BigInt(const BigInt&, const BigInt&, BigInt&, BigInt&)> bigint_gcd;
            bigint_gcd = [&bigint_gcd](const BigInt &a, const BigInt &b, BigInt &x, BigInt &y) -> BigInt {
                if (b == BigInt(0)) { x = BigInt(1); y = BigInt(0); return a; }
                BigInt x1, y1;
                BigInt g = bigint_gcd(b, a % b, x1, y1);
                x = y1; y = x1 - (a / b) * y1;
                return g;
            };
            BigInt s1, s2;
            BigInt g = bigint_gcd(e1, e2, s1, s2);
            if (g != BigInt(1)) throw std::runtime_error("e1 and e2 not coprime");
            BigInt m;
            if (s1.negative) {
                BigInt inv = c1.modinv(n);
                BigInt as = s1; as.negative = false;
                m = inv.modexp(as, n);
            } else { m = c1.modexp(s1, n); }
            if (s2.negative) {
                BigInt inv = c2.modinv(n);
                BigInt as = s2; as.negative = false;
                m = m * inv.modexp(as, n) % n;
            } else { m = m * c2.modexp(s2, n) % n; }
            std::string m_hex = m.toHex();
            std::string bytes;
            for (size_t i = 0; i + 1 < m_hex.size(); i += 2) {
                std::string pair = {m_hex[i], m_hex[i+1]};
                long long v;
                base_deconvert(pair, v, 16);
                bytes += (char)(unsigned char)v;
            }
            size_t pos = 0;
            if (bytes.size() >= 2 && (unsigned char)bytes[0] == 0x00 && (unsigned char)bytes[1] == 0x02) {
                for (size_t i = 2; i < bytes.size(); i++)
                    if ((unsigned char)bytes[i] == 0x00) { pos = i + 1; break; }
            }
            std::string plaintext = (pos > 0 && pos < bytes.size()) ? bytes.substr(pos) : bytes;
            oss << "Recovered: " << plaintext;
        } else if (op == "RSA Fermat Factor") {
            BigInt n = BigInt::from_hex(strip_0x(p1));
            auto bigint_sqrt = [](const BigInt &n) -> BigInt {
                if (n == BigInt(0)) return BigInt(0);
                BigInt x = n, two(2);
                BigInt y = (x + n / x) / two;
                while (y < x) { x = y; y = (x + n / x) / two; }
                return x;
            };
            BigInt a = bigint_sqrt(n);
            if (a * a < n) a = a + BigInt(1);
            bool found = false;
            for (int iter = 0; iter < 100000; iter++) {
                BigInt b2 = a * a - n;
                BigInt b = bigint_sqrt(b2);
                if (b * b == b2) {
                    BigInt p = a - b, q = a + b;
                    if (p * q == n) {
                        oss << "p (hex): " << p.toHex() << "\np (dec): " << p.toString()
                            << "\nq (hex): " << q.toHex() << "\nq (dec): " << q.toString();
                        found = true; break;
                    }
                }
                a = a + BigInt(1);
            }
            if (!found) oss << "Fermat factoring failed (primes not close enough)";
        } else if (op == "RSA Pollard Rho Factor") {
            BigInt n = BigInt::from_hex(strip_0x(p1));
            if (n % BigInt(2) == BigInt(0)) {
                BigInt q = n / BigInt(2);
                oss << "p: 2\nq (hex): " << q.toHex() << "\nq (dec): " << q.toString();
            } else {
                BigInt x(2), y(2), d(1);
                auto f = [&n](const BigInt &v) { return (v * v + BigInt(1)) % n; };
                auto bigint_gcd_simple = [](const BigInt &a, const BigInt &b) -> BigInt {
                    BigInt ta = a, tb = b;
                    while (tb != BigInt(0)) { BigInt t = tb; tb = ta % tb; ta = t; }
                    return ta;
                };
                auto bigint_iabs = [](const BigInt &n) -> BigInt { BigInt r = n; r.negative = false; return r; };
                while (d == BigInt(1) || d == n) {
                    x = f(x); y = f(f(y));
                    BigInt diff = (x.negative != y.negative) ? bigint_iabs(x) + bigint_iabs(y)
                        : (x < y) ? bigint_iabs(y - x) : bigint_iabs(x - y);
                    d = bigint_gcd_simple(diff, n);
                    if (d == n) { oss << "Pollard Rho failed (d == n)"; break; }
                }
                if (d != BigInt(1) && d != n) {
                    BigInt q = n / d;
                    oss << "p (hex): " << d.toHex() << "\np (dec): " << d.toString()
                        << "\nq (hex): " << q.toHex() << "\nq (dec): " << q.toString();
                }
            }
        } else if (op == "RSA Encode") {
            BigInt e = BigInt::from_hex(strip_0x(p2));
            BigInt n = BigInt::from_hex(strip_0x(p1));
            std::string m_hex;
            for (unsigned char ch : input) {
                std::string h;
                base_convert((long long)ch, h, 16);
                if (h.size() == 1) m_hex += '0';
                m_hex += h;
            }
            BigInt m = BigInt::from_hex(m_hex);
            BigInt ct = m.modexp(e, n);
            oss << "Ciphertext (hex): " << ct.toHex() << "\n(dec): " << ct.toString();
        } else if (op == "RSA Info") {
            std::string err;
            oss << "Key analysis:\n";
            {
                BigInt n = BigInt::from_hex(strip_0x(p1));
                BigInt e = BigInt::from_hex(strip_0x(p2));
                oss << "n bits: " << (p1.size() * 4) << "\n";
                oss << "n (dec): " << n.toString() << "\n";
                if (e == BigInt(3)) oss << "⚠ e=3: Hastad broadcast RISK\n";
                else if (e == BigInt(65537)) oss << "e=65537: standard (recommended)\n";
                else oss << "e: non-standard\n";
            }
        } else if (op == "EC Point Add") {
            std::string xr, yr, err;
            auto csv = [](const std::string &s, int idx) -> std::string {
                size_t p = 0; int c = 0;
                while (c < idx && p < s.size()) { if (s[p] == ',') c++; p++; }
                size_t e = p;
                while (e < s.size() && s[e] != ',') e++;
                return strip_0x(s.substr(p, e - p));
            };
            std::string ap = p5;
            if (!ntl_ec_add(p1, p2, p3, p4, csv(ap, 0), csv(ap, 1), xr, yr, err))
                throw std::runtime_error(err);
            oss << "x: " << xr << "\ny: " << yr;
        } else if (op == "EC Scalar Mul") {
            std::string xr, yr, err;
            if (!ntl_ec_scalar_mul(p1, p2, p3, p4, p5, xr, yr, err))
                throw std::runtime_error(err);
            oss << "x: " << xr << "\ny: " << yr;
        } else if (op == "DLP BSGS") {
            std::string x_hex, err;
            if (!ntl_bsgs(p1, p2, p3, x_hex, err))
                throw std::runtime_error(err);
            BigInt x = BigInt::from_hex(x_hex);
            oss << "x (hex): " << x_hex << "\nx (dec): " << x.toString();
        } else if (op == "DLP Pohlig-Hellman") {
            std::string x_hex, err;
            if (!ntl_pohlig_hellman(p1, p2, p3, x_hex, err))
                throw std::runtime_error(err);
            BigInt x = BigInt::from_hex(x_hex);
            oss << "x (hex): " << x_hex << "\nx (dec): " << x.toString();
        } else if (op == "LLL Reduce") {
            std::string err;
            auto parse_matrix = [](const std::string &s) {
                std::vector<std::vector<std::string>> rows;
                size_t pos = 0;
                while (pos < s.size() && s[pos] != '[') pos++;
                if (pos >= s.size()) return rows;
                pos++;
                while (pos < s.size()) {
                    while (pos < s.size() && s[pos] != '[') pos++;
                    if (pos >= s.size()) break; pos++;
                    std::vector<std::string> row;
                    std::string cur;
                    while (pos < s.size() && s[pos] != ']') {
                        if (s[pos] == ',' || s[pos] == ' ') {
                            if (!cur.empty()) { row.push_back(strip_0x(cur)); cur.clear(); }
                            pos++; continue;
                        }
                        cur += s[pos]; pos++;
                    }
                    if (!cur.empty()) row.push_back(strip_0x(cur));
                    if (!row.empty()) rows.push_back(row);
                    while (pos < s.size() && s[pos] != ']') pos++;
                    if (pos < s.size()) pos++;
                    while (pos < s.size() && (s[pos] == ',' || s[pos] == ' ' || s[pos] == ',')) pos++;
                }
                return rows;
            };
            auto rows = parse_matrix(p1);
            std::vector<std::vector<std::string>> out;
            if (!ntl_lll(rows, out, err)) throw std::runtime_error(err);
            oss << "Reduced matrix:\n[";
            for (size_t i = 0; i < out.size(); i++) {
                if (i > 0) oss << ",\n ";
                oss << "[";
                for (size_t j = 0; j < out[i].size(); j++) {
                    if (j > 0) oss << ", ";
                    oss << out[i][j];
                }
                oss << "]";
            }
            oss << "]";
        }
    } catch (std::exception &e) {
        oss << "Error: " << e.what();
    }

    m_output->setPlainText(QString::fromStdString(oss.str()));
}
