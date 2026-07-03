#ifndef TERMINAL_WIDGET_H
#define TERMINAL_WIDGET_H

#include <QWidget>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QSocketNotifier>
#include <QTimer>
#include <QVBoxLayout>

class TerminalWidget : public QWidget {
    Q_OBJECT
public:
    explicit TerminalWidget(QWidget *parent = nullptr);
    ~TerminalWidget();
    void terminate();
    bool isRunning() const { return m_child_pid > 0; }

signals:
    void commandOutput(const QString &text);

private slots:
    void onInputReturn();
    void onPtyReadable(int fd);
    void onFlushTimeout();

private:
    void startShell();
    void appendOutput(const QString &text);

    int m_pty_fd = -1;
    pid_t m_child_pid = 0;
    QSocketNotifier *m_notifier = nullptr;
    QPlainTextEdit *m_output = nullptr;
    QLineEdit *m_input = nullptr;
    QTimer *m_flush_timer = nullptr;
    QByteArray m_pending_output;
};

#endif
