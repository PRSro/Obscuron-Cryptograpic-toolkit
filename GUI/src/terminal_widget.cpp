#include "terminal_widget.h"
#include "colours.h"

#include <QFont>
#include <QPalette>
#include <QScrollBar>
#include <QCoreApplication>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <signal.h>
#include <cstdlib>
#include <cstring>
#include <string>
#include <termios.h>

static QString stripAnsi(const QString &text) {
    QString out;
    out.reserve(text.size());
    auto inRange = [](QChar c, int lo, int hi) {
        ushort u = c.unicode();
        return u >= (ushort)lo && u <= (ushort)hi;
    };
    for (int i = 0; i < text.size(); ++i) {
        QChar c = text[i];
        if (c == '\033') {
            ++i;
            if (i < text.size() && text[i] == '[') {
                ++i;
                while (i < text.size() && inRange(text[i], 0x30, 0x3F)) ++i;
                while (i < text.size() && inRange(text[i], 0x20, 0x2F)) ++i;
                if (i < text.size() && inRange(text[i], 0x40, 0x7E)) ; else --i;
            }
        } else if (c == '\r' || c == '\b' || c == '\a' || c == '\f') {
        } else {
            out += c;
        }
    }
    return out.trimmed();
}

TerminalWidget::TerminalWidget(QWidget *parent) : QWidget(parent) {
    setMinimumHeight(120);
    setMaximumHeight(400);

    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    m_output = new QPlainTextEdit(this);
    m_output->setReadOnly(true);
    m_output->setUndoRedoEnabled(false);
    m_output->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
    m_output->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_output->setLineWrapMode(QPlainTextEdit::NoWrap);

    QFont termFont("Courier New", 11);
    termFont.setStyleHint(QFont::Monospace);
    m_output->setFont(termFont);

    QPalette pal = m_output->palette();
    pal.setColor(QPalette::Base, QColor(0, 0, 0));
    pal.setColor(QPalette::Text, QColor(0, 220, 100));
    m_output->setPalette(pal);

    m_output->setStyleSheet(
        "QPlainTextEdit { background: #000000; color: #00dc64; "
        "border: 1px solid #1a1a2e; }"
        "QPlainTextEdit::selection { background: #004422; }"
    );

    m_input = new QLineEdit(this);
    m_input->setPlaceholderText("$");
    m_input->setFont(termFont);

    QPalette inPal = m_input->palette();
    inPal.setColor(QPalette::Base, QColor(0, 0, 0));
    inPal.setColor(QPalette::Text, QColor(0, 220, 100));
    inPal.setColor(QPalette::PlaceholderText, QColor(40, 60, 40));
    m_input->setPalette(inPal);

    m_input->setStyleSheet(
        "QLineEdit { background: #000000; color: #00dc64; "
        "border: 1px solid #1a1a2e; padding: 6px 10px; }"
        "QLineEdit:focus { border: 1px solid #00dc64; }"
    );

    layout->addWidget(m_output, 1);
    layout->addWidget(m_input);

    connect(m_input, &QLineEdit::returnPressed, this, &TerminalWidget::onInputReturn);

    m_flush_timer = new QTimer(this);
    m_flush_timer->setSingleShot(true);
    connect(m_flush_timer, &QTimer::timeout, this, &TerminalWidget::onFlushTimeout);

    startShell();
}

TerminalWidget::~TerminalWidget() {
    terminate();
}

void TerminalWidget::startShell() {
    m_pty_fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (m_pty_fd < 0) {
        appendOutput("error: posix_openpt failed\n");
        return;
    }
    if (grantpt(m_pty_fd) < 0) {
        appendOutput("error: grantpt failed\n");
        ::close(m_pty_fd); m_pty_fd = -1;
        return;
    }
    if (unlockpt(m_pty_fd) < 0) {
        appendOutput("error: unlockpt failed\n");
        ::close(m_pty_fd); m_pty_fd = -1;
        return;
    }

    const char *slave_name = ptsname(m_pty_fd);
    if (!slave_name) {
        appendOutput("error: ptsname failed\n");
        ::close(m_pty_fd); m_pty_fd = -1;
        return;
    }

    // Disable echo on slave so shell doesn't echo commands back to us
    int slave_fd = open(slave_name, O_RDWR);
    if (slave_fd >= 0) {
        struct termios t;
        tcgetattr(slave_fd, &t);
        t.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
        tcsetattr(slave_fd, TCSANOW, &t);
        ::close(slave_fd);
    }

    struct winsize ws = {};
    ioctl(m_pty_fd, TIOCGWINSZ, &ws);
    ws.ws_row = 40;
    ws.ws_col = 120;
    ioctl(m_pty_fd, TIOCSWINSZ, &ws);

    // Compute venv path relative to GUI binary (before fork)
    std::string gui_dir = QCoreApplication::applicationDirPath().toStdString();
    std::string proj_root = gui_dir + "/..";
    std::string venv_path = proj_root + "/.solve_venv";

    m_child_pid = fork();
    if (m_child_pid == 0) {
        setsid();
        int slave = open(slave_name, O_RDWR);
        if (slave < 0) _exit(1);
        dup2(slave, 0);
        dup2(slave, 1);
        dup2(slave, 2);
        if (slave > 2) ::close(slave);
        ::close(m_pty_fd);

        // Activate venv in terminal environment
        setenv("VIRTUAL_ENV", venv_path.c_str(), 1);
        std::string new_path = venv_path + "/bin:" + getenv("PATH");
        setenv("PATH", new_path.c_str(), 1);
        setenv("PS1", "(solve-venv) \\w $ ", 1);
        // Ensure we start in project root
        chdir(proj_root.c_str());

        const char *shell = getenv("SHELL");
        if (!shell) shell = "/bin/bash";
        const char *base = std::strrchr(shell, '/');
        base = base ? base + 1 : shell;
        bool is_zsh = (std::strcmp(base, "zsh") == 0);
        execlp(shell, shell, is_zsh ? "--no-rcs" : "--norc", nullptr);
        _exit(1);
    }

    if (m_child_pid < 0) {
        appendOutput("error: fork failed\n");
        ::close(m_pty_fd);
        m_pty_fd = -1;
        return;
    }

    int flags = fcntl(m_pty_fd, F_GETFL, 0);
    fcntl(m_pty_fd, F_SETFL, flags | O_NONBLOCK);

    m_notifier = new QSocketNotifier(m_pty_fd, QSocketNotifier::Read, this);
    connect(m_notifier, &QSocketNotifier::activated, this, &TerminalWidget::onPtyReadable);
}

void TerminalWidget::terminate() {
    m_flush_timer->stop();
    if (m_notifier) {
        m_notifier->setEnabled(false);
        delete m_notifier;
        m_notifier = nullptr;
    }
    if (m_child_pid > 0) {
        ::kill(m_child_pid, SIGTERM);
        int status;
        ::waitpid(m_child_pid, &status, 0);
        m_child_pid = 0;
    }
    if (m_pty_fd >= 0) {
        ::close(m_pty_fd);
        m_pty_fd = -1;
    }
}

void TerminalWidget::onInputReturn() {
    QString cmd = m_input->text().trimmed();
    if (cmd.isEmpty()) return;
    m_input->clear();

    // Flush any remaining pending output as a block
    if (!m_pending_output.isEmpty()) {
        onFlushTimeout();
    }

    // Display the command as a clean prompt line
    appendOutput("$ " + cmd + "\n");

    // Send command to shell
    QByteArray data = cmd.toUtf8() + "\n";
    if (m_pty_fd >= 0 && m_child_pid > 0)
        ::write(m_pty_fd, data.constData(), data.size());
}

void TerminalWidget::onPtyReadable(int fd) {
    if (fd != m_pty_fd || m_pty_fd < 0)
        return;
    char buf[4096];
    ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    if (n > 0) {
        m_pending_output.append(buf, n);
        m_flush_timer->start(300);
    } else if (n == 0) {
        terminate();
    }
}

void TerminalWidget::onFlushTimeout() {
    if (m_pty_fd < 0 || m_pending_output.isEmpty()) return;

    QString cleaned = stripAnsi(QString::fromUtf8(m_pending_output));
    m_pending_output.clear();

    if (!cleaned.isEmpty())
        appendOutput(cleaned + "\n");
}

void TerminalWidget::appendOutput(const QString &text) {
    m_output->moveCursor(QTextCursor::End);
    m_output->insertPlainText(text);
    QScrollBar *sb = m_output->verticalScrollBar();
    if (sb) sb->setValue(sb->maximum());
}
