#include "script_console_dialog.h"
#include "script_engine.h"
#include "colours.h"
#include "theme_manager.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFont>
#include <QMessageBox>
#include <QApplication>
#include <QTimer>
#include <QJSEngine>
#include <QJSValue>
#include <QSettings>

ScriptConsoleDialog::ScriptConsoleDialog(const QString &currentInput, QWidget *parent)
    : QDialog(parent), m_currentInput(currentInput)
{
    setWindowTitle("Script Console");
    setMinimumSize(700, 500);
    resize(800, 600);
    m_engine = new ScriptEngine(this);
    setupUI();
}

ScriptConsoleDialog::~ScriptConsoleDialog() {
    if (m_evalThread && m_evalThread->isRunning()) {
        m_evalThread->requestInterruption();
        m_evalThread->quit();
        m_evalThread->wait(3000);
    }
}

void ScriptConsoleDialog::setupUI() {
    ThemePalette sp = ThemeManager::getPaletteFromSettings();
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(8);
    mainLayout->setContentsMargins(12, 12, 12, 12);

    // Info header
    QLabel *infoLabel = new QLabel(
        "Write JavaScript to transform the input. Use the <b>input</b> variable for current data."
    );
    infoLabel->setWordWrap(true);
    infoLabel->setStyleSheet("color: " + sp.textDim.name() + "; font-size: 11px; padding: 4px;");
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
        "QPlainTextEdit { background:" + sp.surf.name() + "; color:" + sp.text.name() + "; border:1px solid " + sp.surf2.name() + ";"
        "  border-radius:4px; padding:8px; }"
    );
    editLayout->addWidget(m_editor);

    // Button row
    QHBoxLayout *btnRow = new QHBoxLayout();
    m_exampleBtn = new QPushButton("Load Example");
    m_exampleBtn->setObjectName("accentButton");
    btnRow->addWidget(m_exampleBtn);
    connect(m_exampleBtn, &QPushButton::clicked, this, &ScriptConsoleDialog::onInsertExample);

    btnRow->addStretch();

    m_runBtn = new QPushButton("RUN SCRIPT");
    m_runBtn->setObjectName("runButton");
    btnRow->addWidget(m_runBtn);
    connect(m_runBtn, &QPushButton::clicked, this, &ScriptConsoleDialog::onRun);

    QPushButton *sendBtn = new QPushButton("Send to Output");
    sendBtn->setObjectName("accentButton");
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
        "QPlainTextEdit { background:" + sp.surf.name() + "; color:" + sp.text.name() + "; border:1px solid " + sp.border.name() + ";"
        "  border-radius:4px; padding:8px; }"
    );
    outLayout->addWidget(m_output);

    m_statusLabel = new QLabel("Ready");
    m_statusLabel->setStyleSheet("color: " + sp.textDim.name() + "; font-size: 10px;");
    outLayout->addWidget(m_statusLabel);

    splitter->addWidget(outputGroup);
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 1);

    mainLayout->addWidget(splitter);

    // Bottom buttons
    QHBoxLayout *bottomRow = new QHBoxLayout();
    bottomRow->addStretch();
    QPushButton *closeBtn = new QPushButton("Close");
    closeBtn->setObjectName("cancelButton");
    bottomRow->addWidget(closeBtn);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::reject);
    mainLayout->addLayout(bottomRow);
}

void ScriptConsoleDialog::onRun() {
    ThemePalette sp = ThemeManager::getPaletteFromSettings();
    QString script = m_editor->toPlainText().trimmed();
    if (script.isEmpty()) return;

    if (m_evalThread && m_evalThread->isRunning()) {
        m_evalThread->requestInterruption();
        m_evalThread->quit();
        m_evalThread->wait(1000);
        m_evalThread = nullptr;
    }

    m_statusLabel->setText("Running...");
    m_statusLabel->setStyleSheet("color: " + sp.accent.name() + "; font-size: 10px;");
    m_runBtn->setEnabled(false);
    QApplication::processEvents();

    QString inputCopy = m_currentInput;

    QThread *thread = QThread::create([this, script, inputCopy]() {
        QJSEngine engine;
        ScriptBridge bridge(&engine);
        QJSValue bridgeObj = engine.newQObject(&bridge);
        engine.globalObject().setProperty("crypto", bridgeObj);
        engine.globalObject().setProperty("input", inputCopy);
        engine.globalObject().setProperty("INPUT", inputCopy);

        QJSValue result = engine.evaluate(script);

        if (QThread::currentThread()->isInterruptionRequested())
            return;

        QString resultStr;
        QString errorStr;

        if (result.isError()) {
            errorStr = QString("Line %1: %2")
                .arg(result.property("lineNumber").toInt())
                .arg(result.toString());
        } else if (!result.isUndefined() && !result.isNull()) {
            resultStr = result.toString();
        }

        QMetaObject::invokeMethod(this, [this, resultStr, errorStr]() {
            handleResult(resultStr, errorStr);
        }, Qt::QueuedConnection);
    });

    m_evalThread = thread;
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);
    connect(thread, &QThread::finished, this, [this]() {
        m_evalThread = nullptr;
    });

    QTimer *timeoutTimer = new QTimer(this);
    timeoutTimer->setSingleShot(true);
    connect(timeoutTimer, &QTimer::timeout, this, [this, thread, sp]() {
        if (thread && thread->isRunning()) {
            thread->requestInterruption();
            m_statusLabel->setText("Timed out");
            m_statusLabel->setStyleSheet("color: " + sp.danger.name() + "; font-size: 10px;");
            m_output->setPlainText("ERROR: Script timed out after 5 seconds");
            m_result.clear();
            m_runBtn->setEnabled(true);
        }
    });
    connect(thread, &QThread::finished, timeoutTimer, &QObject::deleteLater);

    timeoutTimer->start(5000);
    thread->start();
}

void ScriptConsoleDialog::handleResult(const QString &resultStr, const QString &errorStr) {
    ThemePalette sp = ThemeManager::getPaletteFromSettings();
    m_runBtn->setEnabled(true);

    if (!errorStr.isEmpty()) {
        m_output->setPlainText("ERROR: " + errorStr);
        m_statusLabel->setText("Error");
        m_statusLabel->setStyleSheet("color: #ff6b6b; font-size: 10px;");
        m_result.clear();
        return;
    }

    m_output->setPlainText(resultStr);
    m_result = resultStr;
    int lines = resultStr.count('\n') + 1;
    m_statusLabel->setText(QString("OK — %1 chars, %2 lines").arg(resultStr.length()).arg(lines));
    m_statusLabel->setStyleSheet("color: " + sp.success.name() + "; font-size: 10px;");
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
