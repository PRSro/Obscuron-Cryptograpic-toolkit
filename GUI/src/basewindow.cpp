#include "basewindow.h"
#include "menuwindow.h"
#include "colours.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFont>
#include <QPalette>
#include <QApplication>
#include <QClipboard>
#include <QSettings>

#include <string>
#include <stdexcept>

#include "bigint.hpp"
#include "theme_manager.h"

BaseWindow::BaseWindow(QWidget *parent) : QMainWindow(parent) {
    setupUI();
}

void BaseWindow::setupUI() {
    setWindowTitle("Obscuron — Base Mode");
    setMinimumSize(800, 600);

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
    runBtn->setObjectName("runButton");
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
        if (base < 2) {
            outputArea->setPlainText("Error: Base must be >= 2");
            return;
        }
        if (encode) {
            if (!alphabet.empty() && (int)alphabet.size() < base) {
                outputArea->setPlainText(QString("Error: Alphabet length (%1) < base (%2)")
                    .arg(alphabet.size()).arg(base));
                return;
            }
            BigInt n = BigInt::from_bytes(input);
            out = n.toBase(base, alphabet);
            if (out.empty() && !input.empty()) {
                out = "(empty result — input may be all zeros or invalid for this base)";
            }
        } else {
            out = BigInt::from_base(input, base, alphabet).toBytes();
        }
        outputArea->setPlainText(QString::fromStdString(out));
    } catch (std::exception &e) {
        outputArea->setPlainText(QString("Error: ") + e.what());
    }
}
