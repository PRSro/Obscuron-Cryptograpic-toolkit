#ifndef PASSIVEWINDOW_H
#define PASSIVEWINDOW_H

#include <QMainWindow>
#include <QTextEdit>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QLabel>
#include <QTabWidget>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonArray>
#include <QJsonObject>
#include <QProcess>
#include <QWidget>
#include <QScrollArea>
#include <QJsonValue>

enum ProviderFormat {
    ProvOpenAI,   // OpenAI, Grok, DeepSeek, Ollama, NVIDIA, GLM, Kimi
    ProvAnthropic,// Claude
    ProvGemini    // Google Gemini
};

struct ProviderInfo {
    const char *name;
    const char *endpoint;
    const char *defaultModel;
    ProviderFormat format;
};

class PassiveWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit PassiveWindow(QWidget *parent = nullptr);
    ~PassiveWindow() = default;

private:
    // Settings
    QComboBox  *providerCombo;
    QLineEdit  *endpointEdit;
    QLineEdit  *apiKeyEdit;
    QLineEdit  *modelEdit;
    QPushButton *connectBtn;
    QWidget    *settingsPanel;

    // Chat
    QTextEdit     *chatDisplay;
    QPlainTextEdit *inputEdit;
    QPushButton   *sendBtn;

    // Status
    QLabel *statusLabel;

    // Network
    QNetworkAccessManager *netMan;

    // Conversation history (generic format)
    QJsonArray messages;
    int toolCallCount;
    bool connected;

    // System prompt tab
    QTextEdit *sysPromptDisplay;

    // Helpers
    static const ProviderInfo providers[9];
    ProviderFormat currentFormat();

    void setupUI();
    void sendChat();
    void handleReply(QNetworkReply *reply);
    void handleToolCall(const QString &name, const QString &argsJson,
                        const QString &toolCallId);

    void addMessage(const QString &role, const QString &content);
    void addToolResult(const QString &toolCallId, const QString &output);

    void setConnected(bool state);
    QString getCliPath();
    QString buildSystemPrompt();

    // Provider-specific request builders
    QJsonObject buildOpenAIRequest();
    QJsonObject buildAnthropicRequest();
    QJsonObject buildGeminiRequest();

    // Provider-specific response parsers
    // Returns: { assistantContent, toolCallsArray }
    // toolCallsArray = [{ name, arguments, id }, ...]
    QJsonObject parseOpenAIResponse(const QJsonObject &root);
    QJsonObject parseAnthropicResponse(const QJsonObject &root);
    QJsonObject parseGeminiResponse(const QJsonObject &root);

    // Provider-specific tool result injection
    void injectToolResult(const QString &toolCallId, const QString &output,
                          QJsonArray &outMessages);

private slots:
    void onProviderChanged(int idx);
};

#endif
