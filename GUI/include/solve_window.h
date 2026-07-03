#ifndef SOLVE_WINDOW_H
#define SOLVE_WINDOW_H

#include <QMainWindow>
#include <QPlainTextEdit>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QLabel>
#include <QSplitter>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonArray>
#include <QJsonObject>
#include <QProcess>
#include <QTimer>

class SageRunner;
class TerminalWidget;
class SolveCtfPanel;
class PluginLoader;

enum AiProviderFormat {
    AiOpenAI,
    AiAnthropic,
    AiGemini
};

class SolveWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit SolveWindow(QWidget *parent = nullptr);
    ~SolveWindow();

private slots:
    void onRunClicked();
    void onProviderChanged(int idx);
    void onConnectClicked();
    void onSendClicked();
    void onPluginOpRun();

private:
    void setupUI();
    void setupAI();
    void setupPluginOps();
    void refreshPluginOps();

    // Sage/Python
    SageRunner *m_runner = nullptr;
    QComboBox *m_interpreter_combo;
    QPlainTextEdit *m_editor;
    QPlainTextEdit *m_console;

    // Plugin Operations
    PluginLoader *m_pluginLoader;
    QComboBox *m_pluginOpCombo;
    QPushButton *m_pluginOpRunBtn;
    QLabel *m_pluginOpOutput;

    // CTF Panel
    SolveCtfPanel *m_ctf_panel;

    // Terminal
    TerminalWidget *m_terminal;

    // AI Chat — inline, simplified from PassiveWindow
    QComboBox *m_ai_provider;
    QLineEdit *m_ai_endpoint;
    QLineEdit *m_ai_key;
    QLineEdit *m_ai_model;
    QPushButton *m_ai_connect;
    QLabel *m_ai_status;
    QTextEdit *m_ai_history;
    QPlainTextEdit *m_ai_input;
    QPushButton *m_ai_send;
    QNetworkAccessManager *m_net;
    QNetworkReply *m_ai_pending_reply = nullptr;
    QJsonArray m_messages;
    int m_tool_call_count = 0;
    bool m_ai_connected = false;
    QString m_ai_provider_name;

    struct ProviderDef {
        const char *name;
        const char *endpoint;
        const char *model;
        AiProviderFormat format;
    };
    static const ProviderDef m_providers[9];

    void aiAddMessage(const QString &role, const QString &content);
    void aiSend();
    void aiHandleReply(QNetworkReply *reply);
    void aiHandleToolCall(const QString &name, const QString &argsJson,
                          const QString &toolCallId);

    static QString cliPath();
};

#endif
