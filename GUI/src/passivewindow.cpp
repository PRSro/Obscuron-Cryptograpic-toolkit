#include "passivewindow.h"
#include "menuwindow.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFormLayout>
#include <QFont>
#include <QPalette>
#include <QScrollBar>
#include <QJsonDocument>
#include <QJsonValue>
#include <QApplication>
#include <QClipboard>
#include <QTimer>
#include <QFrame>
#include <QUrlQuery>
#include <QSettings>
#include "theme_manager.h"

// ═════════════════════════════════════════════════════════════════════════════
// Provider definitions
// ═════════════════════════════════════════════════════════════════════════════
const ProviderInfo PassiveWindow::providers[9] = {
    { "OpenAI",     "https://api.openai.com/v1",                          "gpt-4o",                                        ProvOpenAI },
    { "Grok (xAI)", "https://api.x.ai/v1",                               "grok-2",                                        ProvOpenAI },
    { "DeepSeek",   "https://api.deepseek.com/v1",                        "deepseek-chat",                                 ProvOpenAI },
    { "Ollama",     "http://localhost:11434/v1",                          "llama3.2",                                      ProvOpenAI },
    { "NVIDIA",     "https://integrate.api.nvidia.com/v1",                "nvidia/llama-3.1-nemotron-70b-instruct",        ProvOpenAI },
    { "GLM (Zhipu)","https://open.bigmodel.cn/api/paas/v4",               "glm-4-plus",                                    ProvOpenAI },
    { "Kimi",       "https://api.moonshot.cn/v1",                         "moonshot-v1-8k",                                ProvOpenAI },
    { "Anthropic",  "https://api.anthropic.com/v1",                       "claude-sonnet-4-20250514",                      ProvAnthropic },
    { "Gemini",     "https://generativelanguage.googleapis.com/v1beta",   "gemini-2.0-flash",                              ProvGemini },
};

// ═════════════════════════════════════════════════════════════════════════════
// System prompt (same for all providers)
// ═════════════════════════════════════════════════════════════════════════════
static const char *SYSTEM_PROMPT = R"(You are an AI cryptanalysis assistant integrated with the Obscuron Crypto Suite CLI tool `ob-crypt`. Your goal is to help the user analyze, decode, decrypt, and solve any cryptography-related problem they present.

CAPABILITIES:
You have the function `run_cli_command` which executes the `ob-crypt` CLI and returns its output. Use this to run detection, analysis, decoding, decryption, and any other crypto operation.

WORKFLOW (recommended for unknown ciphertext):
1. Use `detect <input>` for automatic cipher identification
2. Use `analyze <input>` for statistical properties (entropy, IoC, frequency)
3. Based on results, try appropriate decryption/decoding commands
4. Interpret results clearly for the user
5. For multi-layer encodings, use `chain` or run detection repeatedly

AVAILABLE Cipher Commands (96 total):

=== Encodings ===
hex, base64, base_encode/base_decode (-b N for base 2-85), binary, octal, urlcode (--decrypt), rot13, rot47, rot8000, large (-b N, --decrypt)

=== Classical Ciphers ===
caesar (-k N shift, default 3), vigenere (-k KEYWORD), atbash, playfair (-k KEYWORD), affine (-k A,B), columnar (-k KEYWORD, --len for decrypt), railfence (-k N rails), autokey (-k KEYWORD), beaufort (-k KEYWORD), bifid (-k KEYWORD), four-square (-k KEY1,KEY2), scytale (-k N diameter), polybius (-k KEYWORD), enigma, trifid, adfgvx, morse, braille, bacon, a1z26, keyboard-shift, keyword (-k KEYWORD)

=== Substitution ===
substitution (-k 26-char-key, --decrypt), substitution-solve, rot13, rot47

=== Modern Ciphers ===
aes-ecb, aes-cbc, aes-ctr (-k hex-key, -i hex-iv for CBC/CTR), chacha20 (-k 32-byte-hex-key, -i 12-byte-hex-nonce), salsa20 (-k 32-byte-hex-key, -i 8-byte-hex-nonce), rc4, des, des3, blowfish (-k key), xor (-k hex-key), hex-xor (-k hex-byte), str-xor (-k string), poly1305 (-k 32-byte-hex-key)

=== Hashes & KDFs ===
md5, sha1, sha256, sha512, blake2b, blake2s (optional -k key), hmac-sha256, hmac-sha512 (-k key), pbkdf2 (-s salt, --iter N, --len N), argon2id (-s salt, --iter N, --mem N, --len N), weak-kdf-demo (--i-understand-this-is-insecure)

=== Brute Force ===
brute-caesar, brute-rotate, brute-railfence (-k start_key, --max max_key), brute-xor, brute-vigenere (--max max_len)

=== RSA & Public Key ===
rsa-encode (-k e,n), rsa-decrypt (-k d,n), rsa-info, rsa-wiener (-k e,n), rsa-hastad, rsa-common-modulus, rsa-factor-fermat, rsa-factor-pollard, rsa-parity-oracle

=== CTF Attacks ===
ecb-detect, cbc-padding-oracle, hash-extend, ecdsa-nonce-reuse, dh-check, zip-crack, shamir-reconstruct, gf256-mul, gf256-inv

=== EC & DLP ===
ec-add, ec-mul, dlp-bsgs, dlp-pohlig, lll

=== TLS & Certs ===
tls-fingerprint, parse-cert

=== Utilities ===
jwt-sign (-k key), jwt-parse (optional -k key), qr, lsb-embed (--secret TEXT), lsb-extract, little-endian (--len N), big-endian (--len N), proper-base (--bits N, -k alphabet), chain, detect, analyze

GLOBAL OPTIONS (place before input):
--raw, --hex-output, -f FILE, -, -k KEY, -i IV/NONCE, -s SALT/SEP, --iter N, --mem N KB, --len N, --counter N, --max N, --bits N, --secret TEXT

EXAMPLES:
  ob-crypt detect "Uryyb, Jbeyq!"
  ob-crypt analyze "SGVsbG8gV29ybGQ="
  ob-crypt caesar -k 3 "plaintext"
  ob-crypt caesar -k 3 --decrypt "FHDWHU"
  ob-crypt brute-caesar "FHDWHU"
  ob-crypt base64 "SGVsbG8="
  ob-crypt aes-cbc -k 00112233445566778899aabbccddeeff -i 0102030405060708 --decrypt "cipherhex"
  ob-crypt rsa-wiener -k e_hex,n_hex
  ob-crypt chain "input" --hex "base64" "caesar"
  ob-crypt vigenere -k KEYWORD --decrypt "ciphertext"
  ob-crypt substitution-solve "ciphertext"
  ob-crypt brute-xor "hex ciphertext"
  ob-crypt urlcode --decrypt "%48%65%6c%6c%6f"
  ob-crypt xor -k 2a2b "cipherhex"
  ob-crypt detect --solve "ciphertext"
  ob-crypt detect --top 5 "ciphertext"
  ob-crypt analyze "ciphertext"
  ob-crypt columnar -k GERMAN --decrypt --len 36 "ciphertext"
  ob-crypt playfair -k PLAYFAIR --decrypt "ciphertext"

CHAIN PIPELINE:
  ob-crypt chain "input" --hex "step1" "step2" ...
  Each step is a cipher name with optional flags.
  Adding --detect runs detector on each step's output.

DETECTION:
  The detector has 40+ detection passes with branching for multi-layer ciphers.
  Use --solve to attempt automatic decryption.
  Use --top N to show N best candidates.
  Use --verbose for detailed per-pass results.

ANALYSIS shows:
  Shannon entropy, Index of Coincidence (IoC), character frequency,
  length, encoding detection, chi-squared statistic.

HINTS:
- Run `detect` first if unsure what cipher was used
- `analyze` reveals statistical properties: high entropy = modern encryption,
  medium entropy = encoding, low entropy = classical cipher
- Multi-layer encodings are common in CTFs; use `chain` for these
- Most keys are passed with -k, IVs/nonces with -i, salts with -s
- Hex keys should NOT have 0x prefix
- Use --hex-input when the input itself is hex-encoded
- Use --decrypt for decryption operations)";

// ═════════════════════════════════════════════════════════════════════════════
// Construction
// ═════════════════════════════════════════════════════════════════════════════
PassiveWindow::PassiveWindow(QWidget *parent) : QMainWindow(parent) {
    connected = false;
    toolCallCount = 0;
    netMan = new QNetworkAccessManager(this);
    setupUI();
}

PassiveWindow::~PassiveWindow() {
    if (m_pendingReply) {
        m_pendingReply->abort();
        m_pendingReply->deleteLater();
    }
}

ProviderFormat PassiveWindow::currentFormat() {
    int idx = providerCombo->currentIndex();
    if (idx < 0 || idx >= 9) return ProvOpenAI;
    return providers[idx].format;
}

QString PassiveWindow::getCliPath() {
    return QCoreApplication::applicationDirPath() + "/../CLI/ob-crypt";
}

void PassiveWindow::setConnected(bool state) {
    connected = state;
    if (state) {
        connectBtn->setText("Disconnect");
        statusLabel->setText(QString("Connected: ") + providers[providerCombo->currentIndex()].name);
        sendBtn->setEnabled(true);
        inputEdit->setPlaceholderText("Paste ciphertext or describe your crypto problem...");
    } else {
        connectBtn->setText("Connect");
        statusLabel->setText("Disconnected");
        sendBtn->setEnabled(false);
        inputEdit->setPlaceholderText("Configure settings and click Connect...");
    }
}

QString PassiveWindow::buildSystemPrompt() {
    return QString::fromUtf8(SYSTEM_PROMPT);
}

// ═════════════════════════════════════════════════════════════════════════════
// UI Setup
// ═════════════════════════════════════════════════════════════════════════════
void PassiveWindow::setupUI() {
    setWindowTitle("Obscuron — Passive Mode");
    setMinimumSize(860, 680);
    resize(960, 740);

    ThemePalette pal;
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
        pal = ThemeManager::getPalette(mode, accent);
        setStyleSheet(ThemeManager::getStyleSheet(mode, accent));
    }

    QWidget *central = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    // ── Top Bar ──
    QHBoxLayout *topBar = new QHBoxLayout();
    topBar->setContentsMargins(16, 8, 16, 4);
    QPushButton *backBtn = new QPushButton("← Back");
    backBtn->setFixedWidth(100);
    QLabel *title = new QLabel("PASSIVE MODE");
    QFont titleF("Courier New", 16, QFont::Bold);
    title->setFont(titleF);
    title->setStyleSheet("color: " + pal.text.name() + ";");
    statusLabel = new QLabel("Disconnected");
    statusLabel->setStyleSheet("color:" + pal.textDim.name() + "; font-size:11px;");
    topBar->addWidget(backBtn);
    topBar->addWidget(title, 1, Qt::AlignHCenter);
    topBar->addWidget(statusLabel);
    mainLayout->addLayout(topBar);

    connect(backBtn, &QPushButton::clicked, this, [this]{
        MenuWindow *m = new MenuWindow();
        m->setAttribute(Qt::WA_DeleteOnClose);
        m->show();
        this->close();
    });

    // ── Settings Panel ──
    settingsPanel = new QWidget();
    settingsPanel->setStyleSheet("background:" + pal.bg.name() + "; border-bottom:1px solid " + pal.border.name() + ";");
    QHBoxLayout *settingsRow = new QHBoxLayout(settingsPanel);
    settingsRow->setContentsMargins(16, 8, 16, 8);
    settingsRow->setSpacing(6);

    QLabel *provLbl = new QLabel("Provider:");
    providerCombo = new QComboBox();
    for (const auto &p : providers) providerCombo->addItem(p.name);
    providerCombo->setFixedWidth(130);

    QLabel *epLbl = new QLabel("Endpoint:");
    endpointEdit = new QLineEdit(providers[0].endpoint);
    endpointEdit->setFixedWidth(200);

    QLabel *keyLbl = new QLabel("API Key:");
    apiKeyEdit = new QLineEdit();
    apiKeyEdit->setEchoMode(QLineEdit::Password);
    apiKeyEdit->setPlaceholderText("API key / token");
    apiKeyEdit->setFixedWidth(200);

    QLabel *modLbl = new QLabel("Model:");
    modelEdit = new QLineEdit(providers[0].defaultModel);
    modelEdit->setFixedWidth(120);

    connectBtn = new QPushButton("Connect");
    connectBtn->setFixedWidth(100);

    settingsRow->addWidget(provLbl);
    settingsRow->addWidget(providerCombo);
    settingsRow->addSpacing(4);
    settingsRow->addWidget(epLbl);
    settingsRow->addWidget(endpointEdit);
    settingsRow->addSpacing(4);
    settingsRow->addWidget(keyLbl);
    settingsRow->addWidget(apiKeyEdit);
    settingsRow->addSpacing(4);
    settingsRow->addWidget(modLbl);
    settingsRow->addWidget(modelEdit);
    settingsRow->addSpacing(4);
    settingsRow->addWidget(connectBtn);
    settingsRow->addStretch();

    mainLayout->addWidget(settingsPanel);

    connect(providerCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PassiveWindow::onProviderChanged);

    // ── Main Area ──
    QTabWidget *tabWidget = new QTabWidget();

    // ── Chat Tab ──
    QWidget *chatTab = new QWidget();
    QVBoxLayout *chatLayout = new QVBoxLayout(chatTab);
    chatLayout->setContentsMargins(12, 8, 12, 8);
    chatLayout->setSpacing(6);

    chatDisplay = new QTextEdit();
    chatDisplay->setReadOnly(true);
    chatDisplay->setMinimumHeight(300);
    chatDisplay->setPlaceholderText("Select a provider, enter your API key, and click Connect.\n\nThe AI assistant will use the ob-crypt CLI to analyze and decrypt your ciphertexts.");
    QFont chatFont("Segoe UI", 11);
    chatDisplay->setFont(chatFont);
    chatLayout->addWidget(chatDisplay, 1);

    QHBoxLayout *inputRow = new QHBoxLayout();
    inputRow->setSpacing(8);
    inputEdit = new QPlainTextEdit();
    inputEdit->setPlaceholderText("Configure settings and click Connect...");
    inputEdit->setMinimumHeight(60);
    inputEdit->setMaximumHeight(100);
    inputEdit->setEnabled(false);
    inputRow->addWidget(inputEdit, 1);

    sendBtn = new QPushButton("Send");
    sendBtn->setFixedSize(100, 42);
    sendBtn->setEnabled(false);
    inputRow->addWidget(sendBtn);

    QPushButton *clearChat = new QPushButton("Clear");
    clearChat->setFixedSize(80, 42);
    inputRow->addWidget(clearChat);

    chatLayout->addLayout(inputRow);
    tabWidget->addTab(chatTab, "Chat");

    // ── System Prompt Tab ──
    QWidget *sysTab = new QWidget();
    QVBoxLayout *sysLayout = new QVBoxLayout(sysTab);
    sysLayout->setContentsMargins(12, 8, 12, 8);

    sysPromptDisplay = new QTextEdit();
    sysPromptDisplay->setReadOnly(true);
    sysPromptDisplay->setPlainText(buildSystemPrompt());
    sysLayout->addWidget(sysPromptDisplay, 1);

    QHBoxLayout *sysBtnRow = new QHBoxLayout();
    QPushButton *copySysPrompt = new QPushButton("Copy System Prompt");
    copySysPrompt->setFixedWidth(180);
    sysBtnRow->addStretch();
    sysBtnRow->addWidget(copySysPrompt);
    sysLayout->addLayout(sysBtnRow);
    tabWidget->addTab(sysTab, "System Prompt");

    connect(copySysPrompt, &QPushButton::clicked, this, [this]{
        QApplication::clipboard()->setText(sysPromptDisplay->toPlainText());
    });

    mainLayout->addWidget(tabWidget, 1);
    setCentralWidget(central);

    // ── Signals ──
    connect(connectBtn, &QPushButton::clicked, this, [this]{
        if (connected) {
            setConnected(false);
        } else {
            QString key = apiKeyEdit->text().trimmed();
            if (key.isEmpty()) {
                statusLabel->setText("Error: API key is required");
                return;
            }
            setConnected(true);
        }
    });

    connect(sendBtn, &QPushButton::clicked, this, &PassiveWindow::sendChat);
    connect(clearChat, &QPushButton::clicked, this, [this]{
        chatDisplay->clear();
        messages = QJsonArray();
        toolCallCount = 0;
    });
}

void PassiveWindow::onProviderChanged(int idx) {
    if (idx < 0 || idx >= 9) return;
    endpointEdit->setText(providers[idx].endpoint);
    modelEdit->setText(providers[idx].defaultModel);
    apiKeyEdit->setPlaceholderText(
        idx == 8 ? "Google API key" :  // Gemini
        "API key / token");
}

// ═════════════════════════════════════════════════════════════════════════════
// Message display helpers
// ═════════════════════════════════════════════════════════════════════════════
void PassiveWindow::addMessage(const QString &role, const QString &content) {
    QString prefix;
    QString color;
    if (role == "user")            { prefix = "You:";       color = "#6b9cff"; }
    else if (role == "assistant")  { prefix = "Assistant:"; color = "#00cc88"; }
    else if (role == "system")     { prefix = "System:";    color = "#7a7898"; }
    else if (role == "tool")       { prefix = "Tool:";      color = "#ffaa44"; }
    else                           { prefix = role + ":";   color = "#e0e0f0"; }

    chatDisplay->append(QString("<b style='color:%1'>%2</b>").arg(color, prefix));
    QString esc = content;
    esc.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
       .replace("\n", "<br>");
    chatDisplay->append(esc);
    chatDisplay->append("");
    QScrollBar *sb = chatDisplay->verticalScrollBar();
    sb->setValue(sb->maximum());
}

void PassiveWindow::addToolResult(const QString &toolCallId, const QString &output) {
    // Store in history in generic format (OpenAI-like is our canonical form)
    QJsonObject toolMsg;
    toolMsg["role"] = "tool";
    toolMsg["tool_call_id"] = toolCallId;
    toolMsg["content"] = output.isEmpty() ? "(no output)" : output;
    messages.append(toolMsg);

    QString esc = output;
    esc.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
       .replace("\n", "<br>");
    chatDisplay->append(QString("<b style='color:%1'>[Command Output]</b>").arg("#ffaa44"));
    chatDisplay->append(esc);
    chatDisplay->append("");
}

// ═════════════════════════════════════════════════════════════════════════════
// CLI execution (shared by all providers)
// ═════════════════════════════════════════════════════════════════════════════
void PassiveWindow::handleToolCall(const QString &name, const QString &argsJson,
                                    const QString &toolCallId) {
    if (name != "run_cli_command") {
        addToolResult(toolCallId, QString("Unknown function: %1").arg(name));
        sendChat();
        return;
    }

    QJsonObject args = QJsonDocument::fromJson(argsJson.toUtf8()).object();
    QString cmd = args["command"].toString();

    chatDisplay->append(QString("<b style='color:#ffaa44'>[Running: ob-crypt %1]</b>")
                        .arg(cmd.toHtmlEscaped()));
    chatDisplay->append("");

    QProcess proc;
    QString cliPath = getCliPath();
    proc.setProgram(cliPath);

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

    addToolResult(toolCallId, output.trimmed());
    sendChat();
}

// ═════════════════════════════════════════════════════════════════════════════
// sendChat — dispatches to provider-specific builder
// ═════════════════════════════════════════════════════════════════════════════
void PassiveWindow::sendChat() {
    if (!connected) return;

    QString text = inputEdit->toPlainText().trimmed();
    if (text.isEmpty() && toolCallCount == 0) return;

    if (toolCallCount == 0) {
        addMessage("user", text);
        QJsonObject userMsg;
        userMsg["role"] = "user";
        userMsg["content"] = text;
        messages.append(userMsg);
        inputEdit->clear();
    }

    toolCallCount++;
    if (toolCallCount > 10) {
        addMessage("system", "Tool call limit reached (10). Please start a new conversation.");
        toolCallCount = 0;
        return;
    }

    QByteArray data;
    QNetworkRequest req;
    ProviderFormat fmt = currentFormat();

    switch (fmt) {
    case ProvOpenAI: {
        QJsonObject body = buildOpenAIRequest();
        QJsonDocument doc(body);
        data = doc.toJson(QJsonDocument::Compact);
        req.setUrl(QUrl(endpointEdit->text().trimmed() + "/chat/completions"));
        req.setRawHeader("Authorization",
                         ("Bearer " + apiKeyEdit->text().trimmed()).toUtf8());
        break;
    }
    case ProvAnthropic: {
        QJsonObject body = buildAnthropicRequest();
        QJsonDocument doc(body);
        data = doc.toJson(QJsonDocument::Compact);
        req.setUrl(QUrl(endpointEdit->text().trimmed() + "/messages"));
        req.setRawHeader("x-api-key", apiKeyEdit->text().trimmed().toUtf8());
        req.setRawHeader("anthropic-version", "2023-06-01");
        break;
    }
    case ProvGemini: {
        QJsonObject body = buildGeminiRequest();
        QJsonDocument doc(body);
        data = doc.toJson(QJsonDocument::Compact);
        QString model = modelEdit->text().trimmed();
        QString url = endpointEdit->text().trimmed()
                      + "/models/" + model + ":generateContent";
        QUrl qurl(url);
        req.setUrl(qurl);
        req.setRawHeader("x-goog-api-key", apiKeyEdit->text().trimmed().toUtf8());
        break;
    }
    }

    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QNetworkReply *reply = netMan->post(req, data);
    if (m_pendingReply) {
        m_pendingReply->abort();
        m_pendingReply->deleteLater();
    }
    m_pendingReply = reply;
    connect(reply, &QNetworkReply::finished, this, [this, reply]{
        if (m_pendingReply == reply)
            m_pendingReply = nullptr;
        handleReply(reply);
    });
}

// ═════════════════════════════════════════════════════════════════════════════
// handleReply — dispatches to provider-specific parser
// ═════════════════════════════════════════════════════════════════════════════
void PassiveWindow::handleReply(QNetworkReply *reply) {
    reply->deleteLater();

    if (reply->error() != QNetworkReply::NoError) {
        QString errBody = QString::fromUtf8(reply->readAll());
        QString errMsg = reply->errorString();
        addMessage("system", QString("API Error: %1\n%2").arg(errMsg, errBody));
        toolCallCount = 0;
        return;
    }

    QByteArray respData = reply->readAll();
    QJsonDocument doc = QJsonDocument::fromJson(respData);
    QJsonObject root = doc.object();

    QJsonObject parsed;
    ProviderFormat fmt = currentFormat();
    switch (fmt) {
    case ProvOpenAI:    parsed = parseOpenAIResponse(root);    break;
    case ProvAnthropic: parsed = parseAnthropicResponse(root); break;
    case ProvGemini:    parsed = parseGeminiResponse(root);    break;
    }

    QString content = parsed["content"].toString();
    QJsonArray toolCalls = parsed["tool_calls"].toArray();

    // Store assistant message in history
    QJsonObject histMsg;
    histMsg["role"] = "assistant";
    histMsg["content"] = content;
    if (!toolCalls.isEmpty()) histMsg["tool_calls"] = toolCalls;
    messages.append(histMsg);

    if (!content.isEmpty()) addMessage("assistant", content);

    if (!toolCalls.isEmpty()) {
        QJsonObject tc = toolCalls[0].toObject();
        QString tcId = tc["id"].toString();
        QString fnName = tc["name"].toString();
        QString fnArgs = QJsonDocument(tc["arguments"].toObject()).toJson(QJsonDocument::Compact);
        handleToolCall(fnName, fnArgs, tcId);
    } else {
        toolCallCount = 0;
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Provider-specific request builders
// ═════════════════════════════════════════════════════════════════════════════

QJsonObject PassiveWindow::buildOpenAIRequest() {
    QJsonObject body;
    body["model"] = modelEdit->text().trimmed();

    QJsonArray msgArray;
    // System prompt
    QJsonObject sysMsg;
    sysMsg["role"] = "system";
    sysMsg["content"] = buildSystemPrompt();
    msgArray.append(sysMsg);
    // History
    for (const auto &m : messages) msgArray.append(m);
    body["messages"] = msgArray;

    // Tool definition
    QJsonObject func;
    func["name"] = "run_cli_command";
    func["description"] = "Execute an ob-crypt CLI command and return its output.";
    QJsonObject params;
    params["type"] = "object";
    QJsonObject props;
    QJsonObject cmdProp;
    cmdProp["type"] = "string";
    cmdProp["description"] = "The ob-crypt command (everything after 'ob-crypt ').";
    props["command"] = cmdProp;
    params["properties"] = props;
    params["required"] = QJsonArray{"command"};
    func["parameters"] = params;
    QJsonObject tool;
    tool["type"] = "function";
    tool["function"] = func;
    QJsonArray tools; tools.append(tool);
    body["tools"] = tools;
    body["tool_choice"] = "auto";

    return body;
}

QJsonObject PassiveWindow::buildAnthropicRequest() {
    QJsonObject body;
    body["model"] = modelEdit->text().trimmed();
    body["max_tokens"] = 4096;
    body["system"] = buildSystemPrompt();

    // Convert generic messages to Anthropic format
    QJsonArray msgs;
    for (const auto &m : messages) {
        QJsonObject msg = m.toObject();
        QString role = msg["role"].toString();

        if (role == "tool") {
            // Anthropic tool_result is a user message with content array
            QJsonObject toolResult;
            toolResult["type"] = "tool_result";
            toolResult["tool_use_id"] = msg["tool_call_id"].toString();
            toolResult["content"] = msg["content"].toString();

            QJsonObject userMsg;
            userMsg["role"] = "user";
            QJsonArray content;
            content.append(toolResult);
            userMsg["content"] = content;
            msgs.append(userMsg);
        } else if (role == "assistant") {
            QJsonObject assistantMsg;
            assistantMsg["role"] = "assistant";
            QJsonArray content;

            // Add text content if present
            if (!msg["content"].toString().isEmpty()) {
                QJsonObject textBlock;
                textBlock["type"] = "text";
                textBlock["text"] = msg["content"].toString();
                content.append(textBlock);
            }

            // Add tool_use blocks
            QJsonArray tcs = msg["tool_calls"].toArray();
            for (const auto &tc : tcs) {
                QJsonObject tcObj = tc.toObject();
                QJsonObject toolUse;
                toolUse["type"] = "tool_use";
                toolUse["id"] = tcObj["id"].toString();
                toolUse["name"] = tcObj["name"].toString();  // Anthropic calls it "name"
                toolUse["input"] = tcObj["arguments"];
                content.append(toolUse);
            }

            assistantMsg["content"] = content;
            msgs.append(assistantMsg);
        } else if (role == "user") {
            QJsonObject userMsg;
            userMsg["role"] = "user";
            QJsonObject textBlock;
            textBlock["type"] = "text";
            textBlock["text"] = msg["content"].toString();
            QJsonArray content; content.append(textBlock);
            userMsg["content"] = content;
            msgs.append(userMsg);
        }
    }
    body["messages"] = msgs;

    // Tool definition (Anthropic uses input_schema, camelCase naming)
    QJsonObject toolDef;
    toolDef["name"] = "run_cli_command";
    toolDef["description"] = "Execute an ob-crypt CLI command and return its output.";
    QJsonObject inputSchema;
    inputSchema["type"] = "object";
    QJsonObject props;
    QJsonObject cmdProp;
    cmdProp["type"] = "string";
    cmdProp["description"] = "The ob-crypt command to execute.";
    props["command"] = cmdProp;
    inputSchema["properties"] = props;
    inputSchema["required"] = QJsonArray{"command"};
    toolDef["input_schema"] = inputSchema;
    QJsonArray tools; tools.append(toolDef);
    body["tools"] = tools;

    return body;
}

QJsonObject PassiveWindow::buildGeminiRequest() {
    QJsonObject body;

    // System instruction
    QJsonObject sysPart;
    sysPart["text"] = buildSystemPrompt();
    QJsonArray sysParts; sysParts.append(sysPart);
    QJsonObject sysInstruction;
    sysInstruction["parts"] = sysParts;
    body["system_instruction"] = sysInstruction;

    // Convert generic messages to Gemini format
    QJsonArray geminiContents;
    for (const auto &m : messages) {
        QJsonObject msg = m.toObject();
        QString role = msg["role"].toString();

        if (role == "tool") {
            // Gemini uses functionResponse parts
            QJsonObject fr;
            fr["name"] = "run_cli_command";
            QJsonObject resp;
            resp["content"] = msg["content"].toString();
            fr["response"] = resp;

            QJsonObject frPart;
            frPart["functionResponse"] = fr;
            QJsonArray parts; parts.append(frPart);

            QJsonObject funcMsg;
            funcMsg["role"] = "function";
            funcMsg["parts"] = parts;
            geminiContents.append(funcMsg);
        } else if (role == "assistant") {
            QJsonObject assistantMsg;
            assistantMsg["role"] = "model";
            QJsonArray parts;

            // Text content
            if (!msg["content"].toString().isEmpty()) {
                QJsonObject textPart;
                textPart["text"] = msg["content"].toString();
                parts.append(textPart);
            }

            // Function calls
            QJsonArray tcs = msg["tool_calls"].toArray();
            for (const auto &tc : tcs) {
                QJsonObject tcObj = tc.toObject();
                QJsonObject fc;
                fc["name"] = tcObj["name"].toString();
                fc["args"] = tcObj["arguments"];
                QJsonObject fcPart;
                fcPart["functionCall"] = fc;
                parts.append(fcPart);
            }

            assistantMsg["parts"] = parts;
            geminiContents.append(assistantMsg);
        } else if (role == "user") {
            QJsonObject userMsg;
            userMsg["role"] = "user";
            QJsonObject textPart;
            textPart["text"] = msg["content"].toString();
            QJsonArray parts; parts.append(textPart);
            userMsg["parts"] = parts;
            geminiContents.append(userMsg);
        }
    }
    body["contents"] = geminiContents;

    // Tool definitions (Gemini uses function_declarations with camelCase)
    QJsonObject funcDecl;
    funcDecl["name"] = "run_cli_command";
    funcDecl["description"] = "Execute an ob-crypt CLI command and return its output.";
    QJsonObject params;
    params["type"] = "object";
    QJsonObject props;
    QJsonObject cmdProp;
    cmdProp["type"] = "string";
    cmdProp["description"] = "The ob-crypt command to execute.";
    props["command"] = cmdProp;
    params["properties"] = props;
    params["required"] = QJsonArray{"command"};
    funcDecl["parameters"] = params;
    QJsonArray funcs; funcs.append(funcDecl);
    QJsonObject tool;
    tool["function_declarations"] = funcs;
    QJsonArray tools; tools.append(tool);
    body["tools"] = tools;

    return body;
}

// ═════════════════════════════════════════════════════════════════════════════
// Provider-specific response parsers
// ═════════════════════════════════════════════════════════════════════════════

QJsonObject PassiveWindow::parseOpenAIResponse(const QJsonObject &root) {
    QJsonObject result;
    result["content"] = QString();
    result["tool_calls"] = QJsonArray();

    QJsonArray choices = root["choices"].toArray();
    if (choices.isEmpty()) return result;

    QJsonObject choice = choices[0].toObject();
    QJsonObject msg = choice["message"].toObject();
    result["content"] = msg["content"].toString();

    QJsonArray tcs = msg["tool_calls"].toArray();
    QJsonArray out;
    for (const auto &tc : tcs) {
        QJsonObject tcObj = tc.toObject();
        QJsonObject fc = tcObj["function"].toObject();
        QJsonObject outTc;
        outTc["id"] = tcObj["id"].toString();
        outTc["name"] = fc["name"].toString();
        outTc["arguments"] = QJsonDocument::fromJson(
            fc["arguments"].toString().toUtf8()).object();
        out.append(outTc);
    }
    result["tool_calls"] = out;
    return result;
}

QJsonObject PassiveWindow::parseAnthropicResponse(const QJsonObject &root) {
    QJsonObject result;
    result["content"] = QString();
    result["tool_calls"] = QJsonArray();

    QJsonArray contentBlocks = root["content"].toArray();
    QString text;
    QJsonArray toolCalls;

    for (const auto &block : contentBlocks) {
        QJsonObject b = block.toObject();
        QString type = b["type"].toString();
        if (type == "text") {
            text += b["text"].toString();
        } else if (type == "tool_use") {
            QJsonObject tc;
            tc["id"] = b["id"].toString();
            tc["name"] = b["name"].toString();
            tc["arguments"] = b["input"].toObject();
            toolCalls.append(tc);
        }
    }
    result["content"] = text;
    result["tool_calls"] = toolCalls;
    return result;
}

QJsonObject PassiveWindow::parseGeminiResponse(const QJsonObject &root) {
    QJsonObject result;
    result["content"] = QString();
    result["tool_calls"] = QJsonArray();

    QJsonArray candidates = root["candidates"].toArray();
    if (candidates.isEmpty()) return result;

    QJsonObject content = candidates[0].toObject()["content"].toObject();
    QJsonArray parts = content["parts"].toArray();

    QString text;
    QJsonArray toolCalls;
    for (const auto &part : parts) {
        QJsonObject p = part.toObject();
        if (p.contains("text")) {
            text += p["text"].toString();
        } else if (p.contains("functionCall")) {
            QJsonObject fc = p["functionCall"].toObject();
            QJsonObject tc;
            tc["id"] = "fc-" + fc["name"].toString(); // Gemini has no separate id
            tc["name"] = fc["name"].toString();
            tc["arguments"] = fc["args"].toObject();
            toolCalls.append(tc);
        }
    }
    result["content"] = text;
    result["tool_calls"] = toolCalls;
    return result;
}
