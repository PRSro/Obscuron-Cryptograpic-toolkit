#include "solve_window.h"
#include "menuwindow.h"
#include "sage_runner.h"
#include "terminal_widget.h"
#include "solve_ctf_panel.h"
#include "colours.h"
#include "includes.h"
#include "theme_manager.h"
#include "plugin_loader.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QApplication>
#include <QFont>
#include <QPalette>
#include <QScrollBar>
#include <QDir>
#include <QJsonDocument>
#include <QJsonValue>
#include <QUrlQuery>
#include <QClipboard>
#include <QGroupBox>
#include <QFrame>
#include <QSettings>

// ═════════════════════════════════════════════════════════════════════════════
// AI Provider definitions
// ═════════════════════════════════════════════════════════════════════════════
const SolveWindow::ProviderDef SolveWindow::m_providers[9] = {
    { "OpenAI",     "https://api.openai.com/v1",                          "gpt-4o",                                       AiOpenAI },
    { "Grok (xAI)", "https://api.x.ai/v1",                               "grok-2",                                       AiOpenAI },
    { "DeepSeek",   "https://api.deepseek.com/v1",                        "deepseek-chat",                                AiOpenAI },
    { "Ollama",     "http://localhost:11434/v1",                          "llama3.2",                                     AiOpenAI },
    { "NVIDIA",     "https://integrate.api.nvidia.com/v1",                "nvidia/llama-3.1-nemotron-70b-instruct",       AiOpenAI },
    { "GLM (Zhipu)","https://open.bigmodel.cn/api/paas/v4",               "glm-4-plus",                                   AiOpenAI },
    { "Kimi",       "https://api.moonshot.cn/v1",                         "moonshot-v1-8k",                               AiOpenAI },
    { "Anthropic",  "https://api.anthropic.com/v1",                       "claude-sonnet-4-20250514",                      AiAnthropic },
    { "Gemini",     "https://generativelanguage.googleapis.com/v1beta",   "gemini-2.0-flash",                              AiGemini },
};

// ═════════════════════════════════════════════════════════════════════════════
// Construction
// ═════════════════════════════════════════════════════════════════════════════
SolveWindow::SolveWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle("Obscuron — Solve Crypto");
    setMinimumSize(1200, 700);
    resize(1400, 850);

    m_runner = new SageRunner(this);
    m_net = new QNetworkAccessManager(this);
    m_pluginLoader = new PluginLoader(this);

    setupUI();
    setupAI();
    setupPluginOps();
}

SolveWindow::~SolveWindow() {
    if (m_ai_pending_reply) {
        m_ai_pending_reply->abort();
        m_ai_pending_reply->deleteLater();
    }
}

QString SolveWindow::cliPath() {
    return QCoreApplication::applicationDirPath() + "/../CLI/ob-crypt";
}

// ═════════════════════════════════════════════════════════════════════════════
// UI Setup
// ═════════════════════════════════════════════════════════════════════════════
void SolveWindow::setupUI() {
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
    auto *mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    // ── Top Bar ──
    auto *topBar = new QHBoxLayout;
    topBar->setContentsMargins(12, 6, 12, 4);

    auto *backBtn = new QPushButton("← Back");
    backBtn->setFixedWidth(90);
    connect(backBtn, &QPushButton::clicked, this, [this]{
        MenuWindow *m = new MenuWindow();
        m->setAttribute(Qt::WA_DeleteOnClose);
        m->show();
        this->close();
    });

    auto *title = new QLabel("SOLVE CRYPTO");
    QFont titleFont("Courier New", 16, QFont::Bold);
    title->setFont(titleFont);

    // Interpreter selection
    m_interpreter_combo = new QComboBox;
    m_interpreter_combo->setMinimumWidth(120);
    QStringList interpreters = SageRunner::detectInterpreters();
    if (interpreters.isEmpty())
        m_interpreter_combo->addItem("python3 (not found)");
    else {
        for (const auto &i : interpreters)
            m_interpreter_combo->addItem(i);
    }

    auto *runBtn = new QPushButton("RUN");
    runBtn->setFixedWidth(100);
    runBtn->setFont(QFont("Courier New", 12, QFont::Bold));
    runBtn->setObjectName("runButton");
    connect(runBtn, &QPushButton::clicked, this, &SolveWindow::onRunClicked);

    topBar->addWidget(backBtn);
    topBar->addWidget(title, 1, Qt::AlignHCenter);
    topBar->addWidget(new QLabel("Interpreter:"));
    topBar->addWidget(m_interpreter_combo);
    topBar->addWidget(runBtn);
    mainLayout->addLayout(topBar);

    // ── Main 3-panel Splitter ──
    auto *hSplit = new QSplitter(Qt::Horizontal);
    hSplit->setHandleWidth(2);

    // Left 2/5: Editor + Console (stacked vertically)
    auto *leftStack = new QSplitter(Qt::Vertical);
    leftStack->setHandleWidth(2);

    m_editor = new QPlainTextEdit;
    m_editor->setPlaceholderText("# Python / Sage code\n# Example:\nimport math\nprint(\"Hello from Sage!\")");
    m_editor->setStyleSheet(
        "QPlainTextEdit { background:#0d0718; color:#e0e0f0; border:1px solid #1e1850; "
        "font-family:'Courier New',monospace; font-size:12px; }"
    );
    leftStack->addWidget(m_editor);

    m_console = new QPlainTextEdit;
    m_console->setReadOnly(true);
    m_console->setPlaceholderText("Output will appear here...");
    m_console->setStyleSheet(
        "QPlainTextEdit { background:#0a0514; color:#00cc88; border:1px solid #1e1850; "
        "font-family:'Courier New',monospace; font-size:12px; }"
    );
    leftStack->addWidget(m_console);

    hSplit->addWidget(leftStack);

    // Center 2/5: CTF Panel
    m_ctf_panel = new SolveCtfPanel;
    hSplit->addWidget(m_ctf_panel);

    // Right 1/5: AI Chat (placeholder, populated in setupAI)
    auto *aiWidget = new QWidget;
    auto *aiLayout = new QVBoxLayout(aiWidget);
    aiLayout->setContentsMargins(4, 4, 4, 4);
    aiLayout->setSpacing(4);

    // Provider row
    auto *provRow = new QHBoxLayout;
    m_ai_provider = new QComboBox;
    for (const auto &p : m_providers)
        m_ai_provider->addItem(p.name);
    connect(m_ai_provider, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SolveWindow::onProviderChanged);
    provRow->addWidget(new QLabel("AI:"));
    provRow->addWidget(m_ai_provider, 1);
    aiLayout->addLayout(provRow);

    // Endpoint + Key
    auto *epRow = new QHBoxLayout;
    m_ai_endpoint = new QLineEdit(m_providers[0].endpoint);
    m_ai_key = new QLineEdit;
    m_ai_key->setEchoMode(QLineEdit::Password);
    m_ai_key->setPlaceholderText("API key");
    epRow->addWidget(m_ai_endpoint, 2);
    epRow->addWidget(m_ai_key, 1);
    aiLayout->addLayout(epRow);

    // Model + Connect
    auto *modelRow = new QHBoxLayout;
    m_ai_model = new QLineEdit(m_providers[0].model);
    m_ai_connect = new QPushButton("Connect");
    m_ai_connect->setFixedWidth(80);
    connect(m_ai_connect, &QPushButton::clicked, this, &SolveWindow::onConnectClicked);
    ThemePalette aiPal = ThemeManager::getPaletteFromSettings();
    m_ai_status = new QLabel("Disconnected");
    m_ai_status->setStyleSheet("color:" + aiPal.textDim.name() + "; font-size:10px;");
    modelRow->addWidget(m_ai_model, 1);
    modelRow->addWidget(m_ai_connect);
    modelRow->addWidget(m_ai_status);
    aiLayout->addLayout(modelRow);

    // Chat history
    m_ai_history = new QTextEdit;
    m_ai_history->setReadOnly(true);
    m_ai_history->setPlaceholderText("Connect to an AI provider to get help solving your challenge...");
    aiLayout->addWidget(m_ai_history, 1);

    // Input row
    auto *inputRow = new QHBoxLayout;
    m_ai_input = new QPlainTextEdit;
    m_ai_input->setPlaceholderText("Ask the AI...");
    m_ai_input->setMaximumHeight(60);
    m_ai_input->setEnabled(false);
    m_ai_send = new QPushButton("Send");
    m_ai_send->setFixedSize(60, 32);
    m_ai_send->setEnabled(false);
    connect(m_ai_send, &QPushButton::clicked, this, &SolveWindow::onSendClicked);
    inputRow->addWidget(m_ai_input, 1);
    inputRow->addWidget(m_ai_send);
    aiLayout->addLayout(inputRow);

    hSplit->addWidget(aiWidget);

    // Set stretch factors: 2 : 2 : 1
    hSplit->setStretchFactor(0, 2);
    hSplit->setStretchFactor(1, 2);
    hSplit->setStretchFactor(2, 1);

    mainLayout->addWidget(hSplit, 1);

    // ── Plugin Operations bar ──
    auto *pluginRow = new QHBoxLayout;
    pluginRow->setSpacing(4);
    ThemePalette sp = ThemeManager::getPaletteFromSettings();
    auto *pluginLabel = new QLabel("Plugin Op:");
    pluginLabel->setStyleSheet("color: " + sp.textDim.name() + "; font-size: 10px;");
    m_pluginOpCombo = new QComboBox;
    m_pluginOpCombo->setMinimumWidth(200);
    m_pluginOpCombo->setStyleSheet(
        "QComboBox { background:" + sp.surf.name() + "; color:" + sp.text.name() + "; border:1px solid " + sp.border.name() + ";"
        "  padding:3px 6px; font-family:'Courier New',monospace; font-size:10px; }"
        "QComboBox:hover { border-color:" + sp.accent.name() + "; }"
        "QComboBox QAbstractItemView { background:" + sp.surf.name() + "; color:" + sp.text.name() + "; "
        "  selection-background-color:" + sp.accent.name() + "; }"
    );
    m_pluginOpRunBtn = new QPushButton("Run Plugin Op");
    m_pluginOpRunBtn->setFixedHeight(26);
    m_pluginOpRunBtn->setObjectName("accentButton");
    connect(m_pluginOpRunBtn, &QPushButton::clicked, this, &SolveWindow::onPluginOpRun);
    m_pluginOpOutput = new QLabel("Plugin output will appear here...");
    m_pluginOpOutput->setStyleSheet("color: " + sp.textDim.name() + "; font-size: 10px; padding: 4px;");
    m_pluginOpOutput->setWordWrap(true);
    pluginRow->addWidget(pluginLabel);
    pluginRow->addWidget(m_pluginOpCombo);
    pluginRow->addWidget(m_pluginOpRunBtn);
    pluginRow->addWidget(m_pluginOpOutput, 1);
    mainLayout->addLayout(pluginRow);
    refreshPluginOps();

    // ── Terminal at bottom ──
    m_terminal = new TerminalWidget;
    m_terminal->setMinimumHeight(100);
    m_terminal->setMaximumHeight(350);
    mainLayout->addWidget(m_terminal);

    setCentralWidget(central);
}

void SolveWindow::setupAI() {
    // Called after constructor initialization ensures m_ai_endpoint is set
    m_ai_provider_name = m_providers[0].name;
}

void SolveWindow::setupPluginOps() {
    connect(m_pluginLoader, &PluginLoader::pluginLoaded, this, [this](const QString&) { refreshPluginOps(); });
    connect(m_pluginLoader, &PluginLoader::pluginError, this, [this](const QString &, const QString &err) {
        m_pluginOpOutput->setText("Plugin error: " + err);
    });

    QString pluginDir = QDir::homePath() + "/.obscuron/plugins/";
    QDir dir(pluginDir);
    if (dir.exists()) {
        QStringList filters = {"*.so", "*.py", "*.js"};
        for (const QFileInfo &fi : dir.entryInfoList(filters, QDir::Files)) {
            QString path = fi.absoluteFilePath();
            if (path.endsWith(".py", Qt::CaseInsensitive))
                m_pluginLoader->loadPythonPlugin(path.toStdString());
            else if (path.endsWith(".js", Qt::CaseInsensitive))
                m_pluginLoader->loadJSPlugin(path.toStdString());
            else
                m_pluginLoader->loadPlugin(path.toStdString());
        }
    }
}

void SolveWindow::refreshPluginOps() {
    QString current = m_pluginOpCombo->currentText();
    m_pluginOpCombo->clear();
    for (const auto &op : m_pluginLoader->allPluginOperations())
        m_pluginOpCombo->addItem(QString::fromStdString(op));
    int idx = m_pluginOpCombo->findText(current);
    if (idx >= 0) m_pluginOpCombo->setCurrentIndex(idx);
    m_pluginOpRunBtn->setEnabled(m_pluginOpCombo->count() > 0);
}

void SolveWindow::onPluginOpRun() {
    QString op = m_pluginOpCombo->currentText();
    if (op.isEmpty()) return;

    // Use the CTF panel's preview text as input, or the editor text as fallback
    QString input;
    if (m_ctf_panel) {
        // Try to get text from CTF panel's preview (the SolveCtfPanel doesn't expose it directly,
        // so we check a known child object pattern)
        auto *preview = m_ctf_panel->findChild<QPlainTextEdit*>();
        if (preview && !preview->toPlainText().trimmed().isEmpty())
            input = preview->toPlainText();
    }
    if (input.isEmpty())
        input = m_editor->toPlainText();

    if (input.trimmed().isEmpty()) {
        m_pluginOpOutput->setText("No input data — type in the editor or open a CTF file.");
        return;
    }

    bool success = false;
    std::string error_msg;
    std::string result = m_pluginLoader->tryExecute(
        op.toStdString(), input.toStdString(),
        "", "", 0, 0, 1, success, error_msg);

    if (success) {
        m_pluginOpOutput->setText(QString::fromStdString(result).left(200)
            + (result.size() > 200 ? "..." : ""));
        m_console->appendPlainText("── Plugin Op: " + op + " ──");
        m_console->appendPlainText(QString::fromStdString(result));
    } else {
        QString err = error_msg.empty() ? "Operation failed" : QString::fromStdString(error_msg);
        m_pluginOpOutput->setText(err);
        m_console->appendPlainText("── Plugin Op Error: " + op + " ──");
        m_console->appendPlainText(err);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Sage Runner
// ═════════════════════════════════════════════════════════════════════════════
void SolveWindow::onRunClicked() {
    QString code = m_editor->toPlainText().trimmed();
    if (code.isEmpty()) return;

    QString interp = m_interpreter_combo->currentText();
    if (interp.contains("not found")) {
        m_console->appendPlainText("Error: No Python/Sage interpreter detected.");
        return;
    }

    if (!m_runner->isRunning()) {
        if (!m_runner->start(interp)) {
            m_console->appendPlainText("Error: Failed to start " + interp);
            return;
        }
        connect(m_runner, &SageRunner::outputReceived, this, [this](const QString &text) {
            m_console->appendPlainText(text);
            QScrollBar *sb = m_console->verticalScrollBar();
            if (sb) sb->setValue(sb->maximum());
        });
        connect(m_runner, &SageRunner::finished, this, [this](int code) {
            m_console->appendPlainText(QString("\n[Process exited with code %1]\n").arg(code));
        });
    }

    m_console->appendPlainText(QString(">>> %1\n").arg(code.split('\n').first()));
    m_runner->execute(code);
}

// ═════════════════════════════════════════════════════════════════════════════
// AI Chat — Provider selection & connection
// ═════════════════════════════════════════════════════════════════════════════
void SolveWindow::onProviderChanged(int idx) {
    if (idx < 0 || idx >= 9) return;
    m_ai_endpoint->setText(m_providers[idx].endpoint);
    m_ai_model->setText(m_providers[idx].model);
    // Don't clear the API key
}

void SolveWindow::onConnectClicked() {
    ThemePalette aiPal = ThemeManager::getPaletteFromSettings();
    if (m_ai_connected) {
        m_ai_connected = false;
        m_ai_connect->setText("Connect");
        m_ai_status->setText("Disconnected");
        m_ai_status->setStyleSheet("color:" + aiPal.textDim.name() + "; font-size:10px;");
        m_ai_send->setEnabled(false);
        m_ai_input->setEnabled(false);
        m_messages = QJsonArray();
        return;
    }

    QString key = m_ai_key->text().trimmed();
    if (key.isEmpty()) {
        m_ai_status->setText("Error: API key required");
        m_ai_status->setStyleSheet("color:" + aiPal.danger.name() + "; font-size:10px;");
        return;
    }

    m_ai_connected = true;
    m_ai_provider_name = m_providers[m_ai_provider->currentIndex()].name;
    m_ai_connect->setText("Disconnect");
    m_ai_status->setText(QString("Connected: %1").arg(m_ai_provider_name));
    m_ai_status->setStyleSheet("color:" + aiPal.success.name() + "; font-size:10px;");
    m_ai_send->setEnabled(true);
    m_ai_input->setEnabled(true);
    m_ai_input->setPlaceholderText("Describe your crypto problem...");
    m_messages = QJsonArray();
}

// ═════════════════════════════════════════════════════════════════════════════
// AI Chat — Sending & Reply Handling (OpenAI-compatible API)
// ═════════════════════════════════════════════════════════════════════════════
void SolveWindow::onSendClicked() {
    QString text = m_ai_input->toPlainText().trimmed();
    if (text.isEmpty() || !m_ai_connected) return;

    aiAddMessage("user", text);
    QJsonObject userMsg;
    userMsg["role"] = "user";
    userMsg["content"] = text;
    m_messages.append(userMsg);
    m_ai_input->clear();

    aiSend();
}

void SolveWindow::aiAddMessage(const QString &role, const QString &content) {
    QString color;
    if (role == "user")            color = "#6b9cff";
    else if (role == "assistant")  color = "#00cc88";
    else if (role == "tool")       color = "#ffaa44";
    else                           color = "#e0e0f0";

    QString esc = content;
    esc.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
       .replace("\n", "<br>");
    m_ai_history->append(QString("<b style='color:%1'>%2</b>").arg(color, role));
    m_ai_history->append(esc);
    m_ai_history->append("");
    QScrollBar *sb = m_ai_history->verticalScrollBar();
    if (sb) sb->setValue(sb->maximum());
}

void SolveWindow::aiSend() {
    // Build OpenAI-compatible JSON request
    int idx = m_ai_provider->currentIndex();
    if (idx < 0 || idx >= 9) return;

    QString endpoint = m_ai_endpoint->text().trimmed();
    QString model = m_ai_model->text().trimmed();
    QString key = m_ai_key->text().trimmed();

    // System prompt
    QJsonObject sysMsg;
    sysMsg["role"] = "system";
    sysMsg["content"] = "You are a cryptanalysis assistant. You have the function `run_cli_command` "
                        "which executes the ob-crypt CLI tool. Use it to analyze, detect, decode, "
                        "and decrypt ciphertexts. Run `detect <input>` first for unknown ciphers, "
                        "then try appropriate decryption commands. Interpret results for the user.";

    QJsonArray msgs;
    msgs.append(sysMsg);
    for (const auto &m : m_messages)
        msgs.append(m);

    // Tool definition
    QJsonObject toolDef;
    toolDef["type"] = "function";
    QJsonObject funcDef;
    funcDef["name"] = "run_cli_command";
    funcDef["description"] = "Run an ob-crypt CLI command and return its output";
    QJsonObject params;
    params["type"] = "object";
    QJsonObject cmdProp;
    cmdProp["type"] = "string";
    cmdProp["description"] = "The ob-crypt command and arguments";
    QJsonObject props;
    props["command"] = cmdProp;
    params["properties"] = props;
    params["required"] = QJsonArray{"command"};
    funcDef["parameters"] = params;
    toolDef["function"] = funcDef;

    QJsonArray tools;
    tools.append(toolDef);

    QJsonObject body;
    body["model"] = model;
    body["messages"] = msgs;
    body["tools"] = tools;
    body["tool_choice"] = "auto";
    body["max_tokens"] = 4096;

    AiProviderFormat fmt = m_providers[idx].format;
    QUrl url;
    if (fmt == AiGemini)
        url = QUrl(endpoint + "/openai/chat/completions");
    else
        url = QUrl(endpoint + "/chat/completions");
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    switch (fmt) {
    case AiOpenAI:
        req.setRawHeader("Authorization", ("Bearer " + key).toUtf8());
        break;
    case AiAnthropic:
        req.setRawHeader("x-api-key", key.toUtf8());
        req.setRawHeader("anthropic-version", "2023-06-01");
        break;
    case AiGemini:
        req.setRawHeader("x-goog-api-key", key.toUtf8());
        break;
    }

    QNetworkReply *reply = m_net->post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    if (m_ai_pending_reply) {
        m_ai_pending_reply->abort();
        m_ai_pending_reply->deleteLater();
    }
    m_ai_pending_reply = reply;
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        if (m_ai_pending_reply == reply)
            m_ai_pending_reply = nullptr;
        aiHandleReply(reply);
    });
}

void SolveWindow::aiHandleReply(QNetworkReply *reply) {
    reply->deleteLater();

    if (reply->error() != QNetworkReply::NoError) {
        QString errBody = QString::fromUtf8(reply->readAll());
        aiAddMessage("system", "API error: " + reply->errorString() + "\n" + errBody);
        m_ai_send->setEnabled(true);
        return;
    }

    QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
    QJsonObject root = doc.object();

    QJsonArray choices = root["choices"].toArray();
    if (choices.isEmpty()) {
        aiAddMessage("system", "API returned empty choices");
        m_ai_send->setEnabled(true);
        return;
    }

    QJsonObject choice = choices[0].toObject();
    QJsonObject message = choice["message"].toObject();
    QString role = message["role"].toString();
    QString content = message["content"].toString();

    QJsonArray toolCalls = message["tool_calls"].toArray();

    // Store single assistant message with content + tool_calls
    QJsonObject asstMsg;
    asstMsg["role"] = "assistant";
    asstMsg["content"] = content;
    if (!toolCalls.isEmpty())
        asstMsg["tool_calls"] = toolCalls;
    m_messages.append(asstMsg);

    if (!content.isEmpty())
        aiAddMessage("assistant", content);

    if (toolCalls.isEmpty()) {
        m_tool_call_count = 0;
        m_ai_send->setEnabled(true);
        return;
    }

    // Process tool calls
    for (const auto &tc : toolCalls) {
        QJsonObject tcObj = tc.toObject();
        QString tcId = tcObj["id"].toString();
        QString funcName = tcObj["function"].toObject()["name"].toString();
        QString funcArgs = tcObj["function"].toObject()["arguments"].toString();

        aiHandleToolCall(funcName, funcArgs, tcId);
    }
}

void SolveWindow::aiHandleToolCall(const QString &name, const QString &argsJson,
                                    const QString &toolCallId) {
    if (name != "run_cli_command") {
        QJsonObject toolMsg;
        toolMsg["role"] = "tool";
        toolMsg["tool_call_id"] = toolCallId;
        toolMsg["content"] = QString("Unknown function: %1").arg(name);
        m_messages.append(toolMsg);
        aiSend();
        return;
    }

    QJsonObject args = QJsonDocument::fromJson(argsJson.toUtf8()).object();
    QString cmd = args["command"].toString();

    aiAddMessage("tool", QString("[Running: ob-crypt %1]").arg(cmd));

    // Execute via QProcess (same pattern as PassiveWindow)
    QProcess proc;
    proc.setProgram(cliPath());

    // Parse command args
    QStringList parts;
    QString cur;
    bool inQuote = false;
    QChar quoteChar;
    for (int i = 0; i < cmd.size(); i++) {
        QChar c = cmd[i];
        if (inQuote) {
            if (c == quoteChar) inQuote = false;
            else cur += c;
        } else if (c == '"' || c == '\'') { inQuote = true; quoteChar = c; }
        else if (c == ' ') { if (!cur.isEmpty()) { parts << cur; cur.clear(); } }
        else cur += c;
    }
    if (!cur.isEmpty()) parts << cur;

    proc.setArguments(parts);
    proc.setProcessChannelMode(QProcess::MergedChannels);

    QTimer timer;
    timer.setSingleShot(true);
    QEventLoop loop;
    connect(&proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            &loop, [&](int, QProcess::ExitStatus) { loop.quit(); });
    connect(&timer, &QTimer::timeout, &loop, [&]{
        if (proc.state() != QProcess::NotRunning) proc.kill();
        loop.quit();
    });
    timer.start(30000);
    proc.start();

    if (proc.state() == QProcess::Running) loop.exec();

    QString output;
    if (timer.isActive()) {
        timer.stop();
        output = QString::fromUtf8(proc.readAllStandardOutput());
        if (output.isEmpty()) output = QString::fromUtf8(proc.readAllStandardError());
    } else {
        output = "(command timed out after 30s)";
    }
    if (output.isEmpty() && proc.exitCode() != 0)
        output = QString("(exit code %1)").arg(proc.exitCode());

    // Store tool result & continue
    QJsonObject toolMsg;
    toolMsg["role"] = "tool";
    toolMsg["tool_call_id"] = toolCallId;
    toolMsg["content"] = output.trimmed().isEmpty() ? "(no output)" : output.trimmed();
    m_messages.append(toolMsg);

    aiAddMessage("tool", output.trimmed());

    m_tool_call_count++;
    if (m_tool_call_count > 10) {
        aiAddMessage("system", "Tool call limit reached (10). Start a new conversation.");
        m_ai_send->setEnabled(true);
        return;
    }

    aiSend();
}
