#ifndef SAGE_RUNNER_H
#define SAGE_RUNNER_H

#include <QObject>
#include <QProcess>
#include <QStringList>

class SageRunner : public QObject {
    Q_OBJECT
public:
    explicit SageRunner(QObject *parent = nullptr);
    ~SageRunner();

    bool start(const QString &interpreter = "python3");
    void stop();
    void execute(const QString &code);
    bool isRunning() const;
    QString interpreter() const { return m_interpreter; }

    static QStringList detectInterpreters();

signals:
    void outputReceived(const QString &text);
    void errorReceived(const QString &text);
    void finished(int exitCode);

private slots:
    void onReadyReadStdout();
    void onReadyReadStderr();
    void onProcessFinished(int exitCode, QProcess::ExitStatus status);

private:
    QProcess *m_process = nullptr;
    QString m_interpreter;
};

#endif
