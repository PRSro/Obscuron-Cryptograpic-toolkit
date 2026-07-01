#include "basewindow.h"
#include "menuwindow.h"
#include "colours.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFont>
#include <QPalette>
#include <QApplication>
#include <QClipboard>

#include <string>
#include <stdexcept>

#include "bigint.hpp"

BaseWindow::BaseWindow(QWidget *parent) : QMainWindow(parent) {
    setupUI();
}

void BaseWindow::setupUI() {
    setWindowTitle("Obscuron — Base Mode");
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
        "QSpinBox, QLineEdit { background:#120a20; color:#e0e0f0; border:1px solid #1e1850;"
        "  border-radius:4px; padding:4px 8px; min-height:24px; }"
        "QSpinBox:focus, QLineEdit:focus { border:1px solid #4a7cff; }"
        "QPushButton { background:#1a1030; color:#e0e0f0; border:1px solid #1e1850;"
        "  border-radius:4px; padding:8px 20px; font-family:'Courier New',monospace; }"
        "QPushButton:hover { border:1px solid #4a7cff; color:#6b9cff; }"
        "QPushButton:pressed { background:#006644; }"
        "QLabel { color:#e0e0f0; font-family:'Courier New',monospace; }"
    );

    QWidget *central = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(16, 12, 16, 12);
    mainLayout->setSpacing(8);

    // ── Top bar ──
    QHBoxLayout *topBar = new QHBoxLayout();
    backBtn = new QPushButton("← Back");
    backBtn->setFixedWidth(100);
    QLabel *title = new QLabel("BASE MODE");
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

    QLabel *baseLabel = new QLabel("Base:");
    baseSpin = new QSpinBox();
    baseSpin->setRange(2, 92);
    baseSpin->setValue(85);

    ctrlRow->addWidget(opLabel);
    ctrlRow->addWidget(operationCombo);
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

    mainLayout->addLayout(ctrlRow);

    // ── Alphabet ──
    QHBoxLayout *alphaRow = new QHBoxLayout();
    QLabel *alphaLabel = new QLabel("Alphabet (optional):");
    alphabetInput = new QLineEdit();
    alphabetInput->setPlaceholderText("Leave empty for default (0-9A-Za-z!#$%...)");
    alphaRow->addWidget(alphaLabel);
    alphaRow->addWidget(alphabetInput, 1);
    mainLayout->addLayout(alphaRow);

    connect(runBtn, &QPushButton::clicked, this, &BaseWindow::onRun);

    // ── Input ──
    QLabel *inLabel = new QLabel("Input");
    mainLayout->addWidget(inLabel);
    inputArea = new QPlainTextEdit(this);
    inputArea->setMinimumHeight(100);
    inputArea->setPlaceholderText("Paste text or base-N value here...");
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

    setCentralWidget(central);
}

void BaseWindow::onRun() {
    std::string input = inputArea->toPlainText().toStdString();
    if (input.empty()) return;

    bool encode = (operationCombo->currentIndex() == 0);
    int base = baseSpin->value();
    std::string alphabet = alphabetInput->text().toStdString();
    std::string out;

    try {
        if (encode) {
            BigInt n = BigInt::from_bytes(input);
            out = n.toBase(base, alphabet);
        } else {
            BigInt n = BigInt::from_base(input, base, alphabet);
            out = n.toBytes();
        }
        outputArea->setPlainText(QString::fromStdString(out));
    } catch (std::exception &e) {
        outputArea->setPlainText(QString("Error: ") + e.what());
    }
}
