#include "solve_ctf_panel.h"
#include "colours.h"
#include "theme_manager.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QLabel>
#include <QFileDialog>
#include <QFile>
#include <QTextStream>
#include <QRegularExpression>
#include <QFont>
#include <QPalette>
#include <QScrollBar>
#include <QApplication>
#include <QClipboard>
#include <QMessageBox>
#include <QProcess>
#include <QSettings>

SolveCtfPanel::SolveCtfPanel(QWidget *parent) : QWidget(parent) {
    setupUI();
}

void SolveCtfPanel::setupUI() {
    ThemePalette sp = ThemeManager::getPaletteFromSettings();
    auto *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(4, 4, 4, 4);
    mainLayout->setSpacing(6);

    // Open file
    auto *topRow = new QHBoxLayout;
    auto *openBtn = new QPushButton("OPEN CTF FILE");
    openBtn->setFixedHeight(32);
    QFont btnFont("Courier New", 10);
    openBtn->setFont(btnFont);
    openBtn->setObjectName("accentButton");
    connect(openBtn, &QPushButton::clicked, this, &SolveCtfPanel::onOpenFile);
    topRow->addWidget(openBtn);
    topRow->addStretch();
    mainLayout->addLayout(topRow);

    // File preview
    m_preview = new QPlainTextEdit(this);
    m_preview->setReadOnly(true);
    m_preview->setMaximumBlockCount(5000);
    QFont monoFont("Courier New", 11);
    monoFont.setStyleHint(QFont::Monospace);
    m_preview->setFont(monoFont);
    m_preview->setStyleSheet(
        "QPlainTextEdit { background: " + sp.surf.name() + "; color: " + sp.text.name() + "; "
        "border: 1px solid " + sp.border.name() + "; padding: 6px; }"
    );
    m_preview->setPlaceholderText("Open a CTF challenge file or paste content here...");
    mainLayout->addWidget(m_preview, 3);

    // Flag regex row
    auto *flagRow = new QHBoxLayout;
    auto *flagLabel = new QLabel("Flag regex:");
    flagLabel->setStyleSheet("color: " + sp.textDim.name() + "; font-size: 11px;");
    m_flag_regex = new QLineEdit("flag\\{.*\\}");
    m_flag_regex->setStyleSheet(
        "QLineEdit { background: " + sp.surf.name() + "; color: " + sp.text.name() + "; border: 1px solid " + sp.border.name() + "; "
        "padding: 4px 8px; }"
    );
    auto *searchBtn = new QPushButton("SEARCH");
    searchBtn->setFixedHeight(28);
    searchBtn->setObjectName("accentButton");
    connect(searchBtn, &QPushButton::clicked, this, &SolveCtfPanel::onSearchFlag);
    flagRow->addWidget(flagLabel);
    flagRow->addWidget(m_flag_regex, 1);
    flagRow->addWidget(searchBtn);
    mainLayout->addLayout(flagRow);

    // Flag results list
    m_flag_results = new QListWidget(this);
    m_flag_results->setMaximumHeight(100);
    m_flag_results->setStyleSheet(
        "QListWidget { background: " + sp.surf.name() + "; color: " + sp.success.name() + "; border: 1px solid " + sp.border.name() + "; "
        "font-size: 13px; }"
        "QListWidget::item { padding: 4px 8px; }"
        "QListWidget::item:selected { background: " + sp.success.darker(140).name() + "; }"
    );
    connect(m_flag_results, &QListWidget::itemDoubleClicked, [](QListWidgetItem *item) {
        QApplication::clipboard()->setText(item->text());
    });
    mainLayout->addWidget(m_flag_results);

    // Quick decode buttons
    auto *decodeLabel = new QLabel("Quick decode / analyze:");
    decodeLabel->setStyleSheet("color: " + sp.textDim.name() + "; font-size: 11px;");
    mainLayout->addWidget(decodeLabel);

    auto *btnRow = new QHBoxLayout;
    btnRow->setSpacing(4);

    QStringList quickOps = {"detect", "analyze", "hex", "base64", "rot13", "xor"};
    for (const auto &op : quickOps) {
        auto *btn = new QPushButton(op);
        btn->setFixedHeight(26);
        btn->setObjectName("accentButton");
        QString operation = op;
        connect(btn, &QPushButton::clicked, this, [this, operation]() {
            onQuickDecode(operation);
        });
        btnRow->addWidget(btn);
    }
    btnRow->addStretch();
    mainLayout->addLayout(btnRow);

    // Results pane
    auto *resultsLabel = new QLabel("Results:");
    resultsLabel->setStyleSheet("color: " + sp.textDim.name() + "; font-size: 11px;");
    mainLayout->addWidget(resultsLabel);

    m_results = new QPlainTextEdit(this);
    m_results->setReadOnly(true);
    m_results->setMaximumBlockCount(2000);
    m_results->setFont(monoFont);
    m_results->setStyleSheet(
        "QTextEdit { background: " + sp.surf.name() + "; color: " + sp.success.name() + "; border: 1px solid " + sp.border.name() + "; "
        "padding: 6px; }"
    );
    mainLayout->addWidget(m_results, 2);
}

void SolveCtfPanel::onOpenFile() {
    QString path = QFileDialog::getOpenFileName(this, "Open CTF File", QString(),
                                                "All Files (*)");
    if (path.isEmpty()) return;
    loadFile(path);
}

void SolveCtfPanel::loadFile(const QString &path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        m_results->appendPlainText("Error: cannot open " + path);
        return;
    }
    m_current_file = path;

    QTextStream in(&file);
    // Qt6 defaults to UTF-8
    QString content = in.readAll();

    // Check for binary content
    bool is_binary = false;
    for (int i = 0; i < content.size() && i < 4096; i++) {
        QChar c = content[i];
        if (c.unicode() == 0) { is_binary = true; break; }
    }

    if (is_binary) {
        m_preview->setPlainText("[Binary file - showing text content only]\n\n"
                                + content.left(10000));
        m_results->appendPlainText("Warning: file appears to contain binary data");
    } else {
        m_preview->setPlainText(content);
    }

    setWindowTitle("CTF: " + path.section('/', -1));
}

QString SolveCtfPanel::currentContent() const {
    return m_preview->toPlainText();
}

void SolveCtfPanel::onSearchFlag() {
    QString pattern = m_flag_regex->text();
    if (pattern.isEmpty()) {
        m_flag_results->clear();
        return;
    }

    QRegularExpression re(pattern);
    if (!re.isValid()) {
        m_flag_results->clear();
        auto *item = new QListWidgetItem("Invalid regex: " + re.errorString());
        item->setForeground(QColor(255, 80, 80));
        m_flag_results->addItem(item);
        return;
    }

    m_flag_results->clear();
    QString content = m_preview->toPlainText();
    auto matches = re.globalMatch(content);

    bool found = false;
    while (matches.hasNext()) {
        auto match = matches.next();
        QString flag = match.captured(0);
        // Display with group(1) if available, else full match
        if (match.lastCapturedIndex() >= 1)
            flag = match.captured(1);
        auto *item = new QListWidgetItem(flag);
        item->setForeground(QColor(0, 204, 136));
        m_flag_results->addItem(item);
        found = true;
    }

    if (!found) {
        auto *item = new QListWidgetItem("(no matches found)");
        item->setForeground(QColor(136, 128, 160));
        m_flag_results->addItem(item);
    }
}

void SolveCtfPanel::onQuickDecode(const QString &operation) {
    QString content = m_preview->toPlainText().trimmed();
    if (content.isEmpty()) return;

    // Run ob-crypt command via QProcess
    QString cliPath = QCoreApplication::applicationDirPath() + "/../CLI/ob-crypt";
    QProcess proc;
    QStringList args;
    args << operation << content.split('\n').first();

    proc.start(cliPath, args);
    if (!proc.waitForFinished(10000)) {
        m_results->appendPlainText(QString("[%1] timeout\n").arg(operation));
        return;
    }

    QString out = QString::fromUtf8(proc.readAllStandardOutput()).trimmed();
    QString err = QString::fromUtf8(proc.readAllStandardError()).trimmed();

    m_results->appendPlainText(QString("── %1 ──\n").arg(operation));
    if (!out.isEmpty())
        m_results->appendPlainText(out + "\n");
    if (!err.isEmpty())
        m_results->appendPlainText(QString("stderr: %1\n").arg(err));
}

void SolveCtfPanel::addResult(const QString &text) {
    m_results->appendPlainText(text);
}
