#include "sage_runner.h"
#include <QCoreApplication>
#include <QFileInfo>

SageRunner::SageRunner(QObject *parent) : QObject(parent) {
}

SageRunner::~SageRunner() {
    stop();
}

static QString venvPython() {
    QString path = QCoreApplication::applicationDirPath()
                   + "/../.solve_venv/bin/python3";
    if (QFileInfo::exists(path))
        return path;
    return {};
}

bool SageRunner::start(const QString &interpreter) {
    if (m_process) stop();

    m_interpreter = interpreter;
    m_process = new QProcess(this);

    connect(m_process, &QProcess::readyReadStandardOutput,
            this, &SageRunner::onReadyReadStdout);
    connect(m_process, &QProcess::readyReadStandardError,
            this, &SageRunner::onReadyReadStderr);
    connect(m_process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &SageRunner::onProcessFinished);

    QString python;
    QStringList args;
    if (interpreter == "sage") {
        args << "-python";
        python = "sage";
    } else {
        args << "-iu";  // interactive + unbuffered
        python = venvPython();
        if (python.isEmpty())
            python = interpreter;  // fallback to system python
    }

    m_process->start(python, args);

    if (!m_process->waitForStarted(5000)) {
        delete m_process;
        m_process = nullptr;
        m_interpreter.clear();
        return false;
    }

    return true;
}

void SageRunner::stop() {
    if (m_process) {
        m_process->kill();
        m_process->waitForFinished(2000);
        delete m_process;
        m_process = nullptr;
    }
    m_interpreter.clear();
}

void SageRunner::execute(const QString &code) {
    if (!m_process || m_process->state() != QProcess::Running)
        return;

    QByteArray data = code.toUtf8();
    if (!data.endsWith('\n'))
        data.append('\n');
    m_process->write(data);
    m_process->write("sys.stdout.flush()\n");
}

bool SageRunner::isRunning() const {
    return m_process && m_process->state() == QProcess::Running;
}

QStringList SageRunner::detectInterpreters() {
    QStringList found;

    // Prefer project venv if it exists
    QString venv = venvPython();
    if (!venv.isEmpty())
        found << venv;

    // Check for sage
    {
        QProcess which;
        which.start("which", QStringList() << "sage");
        if (which.waitForFinished(3000) && which.exitCode() == 0)
            found << "sage";
    }

    // Fallback system python
    QStringList fallbacks = {"python3", "python"};
    for (const auto &name : fallbacks) {
        QProcess which;
        which.start("which", QStringList() << name);
        if (which.waitForFinished(3000) && which.exitCode() == 0) {
            QString path = QString::fromUtf8(which.readAllStandardOutput()).trimmed();
            if (!path.isEmpty())
                found << name;
        }
    }

    return found;
}

void SageRunner::onReadyReadStdout() {
    QString text = QString::fromUtf8(m_process->readAllStandardOutput());
    if (!text.isEmpty())
        emit outputReceived(text);
}

void SageRunner::onReadyReadStderr() {
    QString text = QString::fromUtf8(m_process->readAllStandardError());
    if (!text.isEmpty()) {
        // Python prints prompts and warnings to stderr
        emit errorReceived(text);
        emit outputReceived(text);
    }
}

void SageRunner::onProcessFinished(int exitCode, QProcess::ExitStatus status) {
    Q_UNUSED(status);
    emit finished(exitCode);
}
