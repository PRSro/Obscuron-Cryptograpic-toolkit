#include "script_console_dialog.h"
#include "script_engine.h"
#include "colours.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFont>
#include <QMessageBox>
#include <QApplication>

ScriptConsoleDialog::ScriptConsoleDialog(const QString &currentInput, QWidget *parent)
    : QDialog(parent), m_currentInput(currentInput)
{
    setWindowTitle("Script Console");
    setMinimumSize(700, 500);
    resize(800, 600);
    m_engine = new ScriptEngine(this);
    setupUI();
}

void ScriptConsoleDialog::setupUI() {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(8);
    mainLayout->setContentsMargins(12, 12, 12, 12);

    // Info header
    QLabel *infoLabel = new QLabel(
        "Write JavaScript to transform the input. Use the <b>input</b> variable for current data."
    );
    infoLabel->setWordWrap(true);
    infoLabel->setStyleSheet("color: #8880a0; font-size: 11px; padding: 4px;");
    mainLayout->addWidget(infoLabel);

    QSplitter *splitter = new QSplitter(Qt::Vertical);

    // Editor panel
    QGroupBox *editorGroup = new QGroupBox("Script");
    QVBoxLayout *editLayout = new QVBoxLayout(editorGroup);

    m_editor = new QPlainTextEdit();
    m_editor->setPlaceholderText(
        "// JavaScript — use 'input' for current data\n"
        "// Examples:\n"
        "//   crypto.caesar(input, 3)\n"
        "//   crypto.hex_encode(input)\n"
        "//   crypto.xor_cipher(input, 'secret')\n"
        "//   input.split('').reverse().join('')"
    );
    QFont editorFont("Courier New", 12);
    editorFont.setStyleHint(QFont::Monospace);
    m_editor->setFont(editorFont);
    m_editor->setTabStopDistance(m_editor->fontMetrics().horizontalAdvance(' ') * 4);
    m_editor->setMinimumHeight(180);
    m_editor->setStyleSheet(
        "QPlainTextEdit { background:#0a0514; color:#e0e0f0; border:1px solid #2a2270;"
        "  border-radius:4px; padding:8px; }"
    );
    editLayout->addWidget(m_editor);

    // Button row
    QHBoxLayout *btnRow = new QHBoxLayout();
    m_exampleBtn = new QPushButton("Load Example");
    m_exampleBtn->setStyleSheet(
        "QPushButton { background:#1a1030; color:#8880a0; border:1px solid #2a2270;"
        "  border-radius:4px; padding:6px 14px; font-size:10px; }"
        "QPushButton:hover { border-color:#4a7cff; color:#4a7cff; }"
    );
    btnRow->addWidget(m_exampleBtn);
    connect(m_exampleBtn, &QPushButton::clicked, this, &ScriptConsoleDialog::onInsertExample);

    btnRow->addStretch();

    m_runBtn = new QPushButton("RUN SCRIPT");
    m_runBtn->setStyleSheet(
        "QPushButton { background:#004422; color:#00cc88; border:1px solid #006633;"
        "  border-radius:4px; padding:8px 24px; font-size:12px; font-weight:bold; }"
        "QPushButton:hover { background:#006633; border-color:#00cc88; }"
    );
    btnRow->addWidget(m_runBtn);
    connect(m_runBtn, &QPushButton::clicked, this, &ScriptConsoleDialog::onRun);

    QPushButton *sendBtn = new QPushButton("Send to Output");
    sendBtn->setStyleSheet(
        "QPushButton { background:#1a1030; color:#6b9cff; border:1px solid #2a2270;"
        "  border-radius:4px; padding:6px 14px; font-size:10px; }"
        "QPushButton:hover { border-color:#4a7cff; }"
    );
    btnRow->addWidget(sendBtn);
    connect(sendBtn, &QPushButton::clicked, this, [this]() {
        if (!m_result.isEmpty()) accept();
    });

    editLayout->addLayout(btnRow);
    splitter->addWidget(editorGroup);

    // Output panel
    QGroupBox *outputGroup = new QGroupBox("Output");
    QVBoxLayout *outLayout = new QVBoxLayout(outputGroup);

    m_output = new QPlainTextEdit();
    m_output->setReadOnly(true);
    QFont outFont("Courier New", 11);
    outFont.setStyleHint(QFont::Monospace);
    m_output->setFont(outFont);
    m_output->setStyleSheet(
        "QPlainTextEdit { background:#0a0514; color:#e0e0f0; border:1px solid #1e1850;"
        "  border-radius:4px; padding:8px; }"
    );
    outLayout->addWidget(m_output);

    m_statusLabel = new QLabel("Ready");
    m_statusLabel->setStyleSheet("color: #8880a0; font-size: 10px;");
    outLayout->addWidget(m_statusLabel);

    splitter->addWidget(outputGroup);
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 1);

    mainLayout->addWidget(splitter);

    // Bottom buttons
    QHBoxLayout *bottomRow = new QHBoxLayout();
    bottomRow->addStretch();
    QPushButton *closeBtn = new QPushButton("Close");
    closeBtn->setStyleSheet(
        "QPushButton { background:#1a1030; color:#e0e0f0; border:1px solid #2a2270;"
        "  border-radius:4px; padding:6px 14px; }"
        "QPushButton:hover { border-color:#4a7cff; }"
    );
    bottomRow->addWidget(closeBtn);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::reject);
    mainLayout->addLayout(bottomRow);
}

void ScriptConsoleDialog::onRun() {
    QString script = m_editor->toPlainText().trimmed();
    if (script.isEmpty()) return;

    m_statusLabel->setText("Running...");
    m_statusLabel->setStyleSheet("color: #4a7cff; font-size: 10px;");
    m_runBtn->setEnabled(false);
    QApplication::processEvents();

    QString errorMsg;
    QString result = m_engine->evaluate(script, m_currentInput, errorMsg);

    m_runBtn->setEnabled(true);

    if (!errorMsg.isEmpty()) {
        m_output->setPlainText("ERROR: " + errorMsg);
        m_statusLabel->setText("Error");
        m_statusLabel->setStyleSheet("color: #ff6b6b; font-size: 10px;");
        m_result.clear();
        return;
    }

    m_output->setPlainText(result);
    m_result = result;
    int lines = result.count('\n') + 1;
    m_statusLabel->setText(QString("OK — %1 chars, %2 lines").arg(result.length()).arg(lines));
    m_statusLabel->setStyleSheet("color: #00cc88; font-size: 10px;");
}

void ScriptConsoleDialog::onInsertExample() {
    const QString examples[] = {
        "// Caesar shift by 3\ncrypto.caesar(input, 3)",
        "// XOR with key\ncrypto.xor_cipher(input, \"secret\")",
        "// Base64 decode then hex encode\nvar d = crypto.base64_decode(input);\ncrypto.hex_encode(d)",
        "// Reverse each word\ninput.split(' ').map(w => w.split('').reverse().join('')).join(' ')",
        "// Custom XOR transform\nvar key = 0x42;\ninput.split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ key)).join('')",
        "// Letter frequency analysis\nvar f = {};\nfor (var c of input.toUpperCase()) {\n  if (c >= 'A' && c <= 'Z') f[c] = (f[c] || 0) + 1;\n}\nJSON.stringify(f, null, 2)",
        "// ROT13 then base64\ncrypto.base64_encode(crypto.rot13(input))",
        "// Entropy analysis\ncrypto.entropy(input)"
    };
    static int idx = 0;
    m_editor->setPlainText(examples[idx % 8]);
    idx++;
}
