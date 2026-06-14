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

#include <string>
#include <cstdlib>
#include <cctype>
#include <sstream>

#include "basic_ciphers.h"
#include "essential_ciphers.h"
#include "bytes.h"
#include "detector.h"

NumberWindow::NumberWindow(QWidget *parent) : QMainWindow(parent) {
    setupUI();
}

void NumberWindow::setupUI() {
    setWindowTitle("Obscuron — Number Mode");
    setMinimumSize(800, 600);

    setStyleSheet(
        "QMainWindow, QWidget { background:#0a0514; color:#e0e0f0; }"
        "QPlainTextEdit { background:#120a20; color:#e0e0f0; border:1px solid #1e1850;"
        "  border-radius:4px; padding:8px; font-family:'Courier New',monospace; font-size:12px; }"
        "QPlainTextEdit:focus { border:1px solid #4a7cff; }"
        "QComboBox { background:#120a20; color:#e0e0f0; border:1px solid #1e1850;"
        "  border-radius:4px; padding:4px 8px; min-height:28px; min-width:120px; }"
        "QComboBox:focus { border:1px solid #4a7cff; }"
        "QComboBox QAbstractItemView { background:#120a20; color:#e0e0f0;"
        "  selection-background-color:#006644; border:1px solid #1e1850; }"
        "QSpinBox { background:#120a20; color:#e0e0f0; border:1px solid #1e1850;"
        "  border-radius:4px; padding:2px 4px; min-height:24px; min-width:80px; }"
        "QSpinBox:focus { border:1px solid #4a7cff; }"
        "QPushButton { background:#1a1030; color:#e0e0f0; border:1px solid #1e1850;"
        "  border-radius:4px; padding:8px 20px; font-family:'Courier New',monospace; }"
        "QPushButton:hover { border:1px solid #4a7cff; color:#6b9cff; }"
        "QPushButton:pressed { background:#006644; }"
        "QLabel { color:#e0e0f0; font-family:'Courier New',monospace; }"
        "QGroupBox { border:1px solid #1e1850; border-radius:6px; margin-top:12px;"
        "  padding-top:16px; font-family:'Courier New',monospace; color:#7a7898; }"
        "QGroupBox::title { subcontrol-origin:margin; left:12px; padding:0 4px; }"
    );

    QWidget *central = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(16, 12, 16, 12);
    mainLayout->setSpacing(8);

    // ── Top bar ──
    QHBoxLayout *topBar = new QHBoxLayout();
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
    runBtn->setStyleSheet(
        "QPushButton { background:#1e1850; color:#00cc88; border:1px solid #2a2270;"
        "  border-radius:4px; padding:10px 24px; font-size:13px; font-weight:bold; }"
        "QPushButton:hover { border-color:#4a7cff; color:#6b9cff; }"
    );
    ctrlRow->addWidget(runBtn);
    ctrlRow->addSpacing(12);

    advancedBtn = new QPushButton("ADVANCED");
    advancedBtn->setFixedWidth(120);
    advancedBtn->setStyleSheet(
        "QPushButton { background:#1a1030; color:#6b9cff; border:1px solid #2a2270;"
        "  border-radius:4px; padding:10px 16px; font-size:11px; font-weight:bold; }"
        "QPushButton:hover { border-color:#4a7cff; color:#4a7cff; background:#120a20; }"
    );
    ctrlRow->addWidget(advancedBtn);

    mainLayout->addLayout(ctrlRow);

    connect(advancedBtn, &QPushButton::clicked, this, &NumberWindow::onAdvanced);
    
    detectBtn = new QPushButton("DETECT BASE");
    detectBtn->setFixedWidth(120);
    detectBtn->setStyleSheet(
        "QPushButton { background:#1a1030; color:#6b9cff; border:1px solid #2a2270;"
        "  border-radius:4px; padding:10px 16px; font-size:11px; font-weight:bold; }"
        "QPushButton:hover { border-color:#4a7cff; color:#4a7cff; background:#120a20; }"
    );
    ctrlRow->addWidget(detectBtn);
    ctrlRow->addSpacing(12);

    attackBtn = new QPushButton("ATTACK");
    attackBtn->setFixedWidth(100);
    attackBtn->setStyleSheet(
        "QPushButton { background:#1a1030; color:#ff6b6b; border:1px solid #502020;"
        "  border-radius:4px; padding:10px 16px; font-size:11px; font-weight:bold; }"
        "QPushButton:hover { border-color:#ff4a4a; color:#ff4a4a; background:#120a20; }"
    );
    ctrlRow->addWidget(attackBtn);

    connect(typeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &NumberWindow::onTypeChanged);
    connect(runBtn, &QPushButton::clicked, this, &NumberWindow::onRun);
    connect(detectBtn, &QPushButton::clicked, this, &NumberWindow::onDetect);
    connect(attackBtn, &QPushButton::clicked, this, &NumberWindow::onAttack);
    onTypeChanged(0);

    // ── Input ──
    QLabel *inLabel = new QLabel("Input");
    mainLayout->addWidget(inLabel);
    inputArea = new QPlainTextEdit(this);
    inputArea->setMinimumHeight(100);
    inputArea->setPlaceholderText("Paste values here...");
    mainLayout->addWidget(inputArea);

    // ── Output ──
    QHBoxLayout *outRow = new QHBoxLayout();
    QLabel *outLabel = new QLabel("Output");
    QPushButton *copyBtn = new QPushButton("Copy");
    copyBtn->setFixedWidth(80);
    outRow->addWidget(outLabel);
    outRow->addStretch();
    outRow->addWidget(copyBtn);
    mainLayout->addLayout(outRow);

    outputArea = new QPlainTextEdit(this);
    outputArea->setReadOnly(true);
    outputArea->setMinimumHeight(100);
    mainLayout->addWidget(outputArea, 1);

    connect(copyBtn, &QPushButton::clicked, this, [this]{
        QApplication::clipboard()->setText(outputArea->toPlainText());
    });

    // ── Detect Output ──
    QLabel *detLabel = new QLabel("Base Detection");
    mainLayout->addWidget(detLabel);
    detectOutput = new QPlainTextEdit(this);
    detectOutput->setReadOnly(true);
    detectOutput->setMaximumHeight(100);
    detectOutput->setPlaceholderText("Click DETECT BASE to identify encoding...");
    mainLayout->addWidget(detectOutput);

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
    case 0: // Base N
        if (encrypt) large_encrypt(input, out, base);
        else large_decrypt(input, out, base);
        break;
    case 1: // Binary
        binary(input, out, encrypt);
        break;
    case 2: // Octal
        octal(input, out, encrypt);
        break;
    case 3: // Hex
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
