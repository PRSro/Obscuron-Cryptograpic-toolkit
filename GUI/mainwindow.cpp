#include "mainwindow.h"
#include "menuwindow.h"
#include "colours.h"
#include "theme_manager.h"
#include "visualizer_widgets.h"
#include "modern_ciphers.h"
#include "advanced_crypt_dialog.h"
#include "tls_attack_dialog.h"
#include "settings_dialog.h"
#include "detector.h"
#include "basic.h"
#include "command_palette.h"
#include "toast_widget.h"
#include "plugin_browser_dialog.h"
#include "script_console_dialog.h"
#include <sstream>
#include <iomanip>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QMimeData>
#include <QFile>
#include <QFileInfo>
#include <QUrl>
#include <QFont>
#include <QPalette>
#include <QMessageBox>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QFileDialog>
#include <QInputDialog>
#include <QSettings>
#include <QTextStream>
#include <QScrollBar>
#include <QShortcut>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDir>
#include <QTimer>
#include <QGraphicsDropShadowEffect>
#include <QRegularExpression>
#include <QTextEdit>
#include <QScrollArea>

// ── DropEdit ──────────────────────────────────────────────────────────

DropEdit::DropEdit(QWidget *parent) : QPlainTextEdit(parent) {
    setAcceptDrops(true);
    setPlaceholderText("Type, paste, or drag a file here...");
}

void DropEdit::dragEnterEvent(QDragEnterEvent *e) {
    if (e->mimeData()->hasUrls() || e->mimeData()->hasText())
        e->acceptProposedAction();
}

void DropEdit::dropEvent(QDropEvent *e) {
    const QMimeData *mime = e->mimeData();
    if (mime->hasUrls()) {
        QString path = mime->urls().first().toLocalFile();
        QFile f(path);
        if (f.open(QIODevice::ReadOnly)) {
            QByteArray content = f.readAll();
            emit fileDropped(path, content);
            e->acceptProposedAction();
            return;
        }
    }
    QPlainTextEdit::dropEvent(e);
}

// ── MainWindow ───────────────────────────────────────────────────────

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    m_recipeModel = new RecipeModel(this);
    m_undoStack = new QUndoStack(this);
    m_undoStack->setUndoLimit(100);

    setupUI();
    m_undoStack->clear(); // initial state
    m_undoBtn->setEnabled(false);
    m_redoBtn->setEnabled(false);

    // Plugin system
    m_engine.setPluginLoader(&m_pluginLoader);
    connect(&m_pluginLoader, &PluginLoader::pluginLoaded,
            this, &MainWindow::onPluginLibraryChanged);

    // Auto-scan ~/.obscuron/plugins/
    QString pluginDir = QDir::homePath() + "/.obscuron/plugins/";
    QDir dir(pluginDir);
    if (dir.exists()) {
        for (const QFileInfo &fi : dir.entryInfoList({"*.so"}, QDir::Files))
            m_pluginLoader.loadPlugin(fi.absoluteFilePath().toStdString());
        onPluginLibraryChanged();
    }
}

void MainWindow::setupUI() {
    setWindowTitle("Obscuron — Cryptographic Analysis Workspace");
    setMinimumSize(1200, 800);

    setStyleSheet(QString::fromStdString(
        "QMainWindow { background: #0a0514; }"
        "QWidget { color: #e0e0f0; font-family: 'Courier New', monospace; }"
        "QPlainTextEdit, QLineEdit { background: #120a20; color: #e0e0f0; border: 1px solid #1e1850; "
        "  border-radius: 6px; padding: 8px; font-family: 'Courier New', monospace; font-size: 12px; }"
        "QPlainTextEdit:focus, QLineEdit:focus { border: 1px solid #4a7cff; }"
        "QComboBox { background: #120a20; color: #e0e0f0; border: 1px solid #1e1850; "
        "  border-radius: 6px; padding: 4px 12px; min-height: 28px; font-family: 'Courier New', monospace; }"
        "QComboBox:focus { border: 1px solid #4a7cff; }"
        "QComboBox::drop-down { border: none; width: 24px; }"
        "QComboBox QAbstractItemView { background: #120a20; color: #e0e0f0; "
        "  selection-background-color: #4a7cff; border: 1px solid #1e1850; }"
        "QSpinBox { background: #120a20; color: #e0e0f0; border: 1px solid #1e1850; "
        "  border-radius: 6px; padding: 4px; min-height: 26px; }"
        "QSpinBox:focus { border: 1px solid #4a7cff; }"
        "QPushButton { background: #1a1030; color: #e0e0f0; border: 1px solid #1e1850; "
        "  border-radius: 6px; padding: 8px 18px; font-family: 'Courier New', monospace; font-weight: bold; }"
        "QPushButton:hover { border: 1px solid #4a7cff; color: #6b9cff; background: #120a20; }"
        "QPushButton:pressed { background: #4a7cff; color: #ffffff; }"
        "QListView { background:#0a0514; border:1px dashed #2a2270; border-radius:4px; }"
        "QListView::item { background:transparent; }"
        "QListView::item:selected { background:#1a1030; border:1px solid #4a7cff; }"
        "QLabel { color: #e0e0f0; font-family: 'Courier New', monospace; }"
        "QGroupBox { border: 1px solid #1e1850; border-radius: 8px; margin-top: 14px; "
        "  padding-top: 16px; font-family: 'Courier New', monospace; font-weight: bold; color: #6b9cff; }"
        "QGroupBox::title { subcontrol-origin: margin; left: 14px; padding: 0 6px; }"
        "QTabWidget::pane { border: 1px solid #1e1850; background: #120a20; border-radius: 6px; }"
        "QTabBar::tab { background: #1a1030; border: 1px solid #1e1850; border-bottom: none; "
        "  border-top-left-radius: 6px; border-top-right-radius: 6px; padding: 8px 16px; margin-right: 2px; }"
        "QTabBar::tab:selected { background: #120a20; border-bottom: 1px solid #120a20; color: #6b9cff; font-weight: bold; }"
        "QTabBar::tab:hover { background: #120a20; }"
        "QScrollBar:vertical { background: #0a0514; width: 10px; margin: 0px; }"
        "QScrollBar::handle:vertical { background: #1e1850; min-height: 20px; border-radius: 5px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }"
        "QScrollBar:horizontal { background: #0a0514; height: 10px; margin: 0px; }"
        "QScrollBar::handle:horizontal { background: #1e1850; min-width: 20px; border-radius: 5px; }"
        "QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; }"
        "QSplitter::handle { background: #1e1850; }"
    ));

    QWidget *central = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(central);
    mainLayout->setContentsMargins(12, 8, 12, 8);
    mainLayout->setSpacing(6);

    // ─────────────────────────────────────────────────────────────────────
    // 1. TOP BAR
    // ─────────────────────────────────────────────────────────────────────
    QHBoxLayout *topBar = new QHBoxLayout();

    QPushButton *backBtn = new QPushButton("← BACK MENU");
    backBtn->setFixedWidth(120);
    topBar->addWidget(backBtn);
    connect(backBtn, &QPushButton::clicked, this, [this]{
        MenuWindow *m = new MenuWindow();
        m->setAttribute(Qt::WA_DeleteOnClose);
        m->show();
        this->close();
    });

    QLabel *title = new QLabel("CORE VISION WORKSPACE");
    QFont titleF("Courier New", 14, QFont::Bold);
    titleF.setLetterSpacing(QFont::AbsoluteSpacing, 3);
    title->setFont(titleF);
    title->setStyleSheet("color: #6b9cff;");
    topBar->addWidget(title, 1, Qt::AlignCenter);

    m_metricsLabel = new QLabel("Time: 0.0 ms | Speed: 0.0 MB/s | Mem: 0 B");
    m_metricsLabel->setStyleSheet("color: #00cc88; font-weight: bold; font-size: 10px; margin-right: 12px;");
    topBar->addWidget(m_metricsLabel);

    m_autoRunCheck = new QCheckBox("AUTO RUN");
    m_autoRunCheck->setChecked(true);
    m_autoRunCheck->setStyleSheet("font-weight: bold; color: #8880a0;");
    topBar->addWidget(m_autoRunCheck);

    m_undoBtn = new QPushButton("⟲");
    m_undoBtn->setFixedSize(30, 28);
    m_undoBtn->setToolTip("Undo");
    topBar->addWidget(m_undoBtn);
    connect(m_undoBtn, &QPushButton::clicked, m_undoStack, &QUndoStack::undo);
    connect(m_undoStack, &QUndoStack::canUndoChanged, m_undoBtn, &QPushButton::setEnabled);
    connect(m_undoStack, &QUndoStack::canUndoChanged, this, [this](){
        if (!m_undoStack->canUndo()) m_redoBtn->setEnabled(m_undoStack->canRedo());
    });

    m_redoBtn = new QPushButton("⟳");
    m_redoBtn->setFixedSize(30, 28);
    m_redoBtn->setToolTip("Redo");
    topBar->addWidget(m_redoBtn);
    connect(m_redoBtn, &QPushButton::clicked, m_undoStack, &QUndoStack::redo);
    connect(m_undoStack, &QUndoStack::canRedoChanged, m_redoBtn, &QPushButton::setEnabled);

    m_cancelBtn = new QPushButton("✕");
    m_cancelBtn->setFixedSize(30, 28);
    m_cancelBtn->setToolTip("Cancel running operation");
    m_cancelBtn->setVisible(false);
    m_cancelBtn->setStyleSheet(
        "QPushButton { background:#4a0000; color:#ff6b6b; border:1px solid #8b0000;"
        "  border-radius:4px; font-weight:bold; font-size:14px; }"
        "QPushButton:hover { background:#6b0000; }"
    );
    topBar->addWidget(m_cancelBtn);
    connect(m_cancelBtn, &QPushButton::clicked, this, &MainWindow::onCancelAsync);

    m_themeCombo = new QComboBox();
    m_themeCombo->addItem("DARK THEME");
    m_themeCombo->addItem("LIGHT THEME");
    m_themeCombo->addItem("OLED BLACK");
    m_themeCombo->setFixedWidth(130);
    topBar->addWidget(m_themeCombo);
    connect(m_themeCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(onThemeChanged(int)));

    QPushButton *settingsBtn = new QPushButton("⚙");
    settingsBtn->setFixedSize(30, 28);
    settingsBtn->setToolTip("Settings");
    topBar->addWidget(settingsBtn);
    connect(settingsBtn, &QPushButton::clicked, this, &MainWindow::onOpenSettings);

    QPushButton *scriptBtn = new QPushButton("SCRIPT");
    scriptBtn->setFixedWidth(70);
    scriptBtn->setStyleSheet(
        "QPushButton { background:#1a1030; color:#00cc88; border:1px solid #006633;"
        "  border-radius:4px; padding:6px 8px; font-size:10px; font-weight:bold; }"
        "QPushButton:hover { border-color:#00cc88; background:#003322; }"
    );
    topBar->addWidget(scriptBtn);
    connect(scriptBtn, &QPushButton::clicked, this, [this]{
        ScriptConsoleDialog dlg(QString::fromStdString(m_rawInput), this);
        if (dlg.exec() == QDialog::Accepted) {
            std::string scriptResult = dlg.result().toStdString();
            if (!scriptResult.empty())
                applyPipelineResults(scriptResult);
        }
    });

    QPushButton *advancedBtn = new QPushButton("ADVANCED");
    advancedBtn->setFixedWidth(100);
    advancedBtn->setStyleSheet(
        "QPushButton { background:#1a1030; color:#6b9cff; border:1px solid #2a2270;"
        "  border-radius:4px; padding:6px 12px; font-size:10px; font-weight:bold; }"
        "QPushButton:hover { border-color:#4a7cff; color:#4a7cff; }"
    );
    {
        auto *glow = new QGraphicsDropShadowEffect(advancedBtn);
        glow->setBlurRadius(12);
        glow->setOffset(0, 0);
        glow->setColor(QColor(74, 124, 255, 60));
        advancedBtn->setGraphicsEffect(glow);
    }
    topBar->addWidget(advancedBtn);
    connect(advancedBtn, &QPushButton::clicked, this, [this]{
        AdvancedCryptDialog dlg(this);
        dlg.exec();
    });

    QPushButton *detectBtn = new QPushButton("DETECT");
    detectBtn->setFixedWidth(100);
    detectBtn->setStyleSheet(
        "QPushButton { background:#1a1030; color:#00cc88; border:1px solid #006644;"
        "  border-radius:4px; padding:6px 12px; font-size:10px; font-weight:bold; }"
        "QPushButton:hover { border-color:#4a7cff; color:#4a7cff; }"
    );
    {
        auto *glow = new QGraphicsDropShadowEffect(detectBtn);
        glow->setBlurRadius(14);
        glow->setOffset(0, 0);
        glow->setColor(QColor(0, 204, 136, 50));
        detectBtn->setGraphicsEffect(glow);
    }
    topBar->addWidget(detectBtn);
    connect(detectBtn, &QPushButton::clicked, this, &MainWindow::onDetectCipher);

    mainLayout->addLayout(topBar);

    // ─────────────────────────────────────────────────────────────────────
    // 2. MAIN LAYOUT SPLITTER
    // ─────────────────────────────────────────────────────────────────────
    QSplitter *mainSplitter = new QSplitter(Qt::Horizontal, this);

    // LEFT PANEL
    QWidget *leftPanel = new QWidget();
    QVBoxLayout *leftLayout = new QVBoxLayout(leftPanel);
    leftLayout->setContentsMargins(0, 0, 0, 0);
    leftLayout->setSpacing(4);

    QLabel *libLabel = new QLabel("OPERATION LIBRARY");
    libLabel->setStyleSheet("font-weight: bold; color: #4a7cff;");
    leftLayout->addWidget(libLabel);

    m_librarySearch = new QLineEdit();
    m_librarySearch->setPlaceholderText("Search operations...");
    leftLayout->addWidget(m_librarySearch);

    m_opLibrary = new QTreeWidget();
    m_opLibrary->setHeaderHidden(true);
    m_opLibrary->setAnimated(true);

    auto addCategory = [this](const QString &catName, const QStringList &ops) {
        QTreeWidgetItem *category = new QTreeWidgetItem(m_opLibrary);
        category->setText(0, catName);
        category->setFont(0, QFont("Courier New", 10, QFont::Bold));
        category->setForeground(0, COL_ACCENT_GL);
        for (const QString &op : ops) {
            QTreeWidgetItem *item = new QTreeWidgetItem(category);
            item->setText(0, op);
            item->setFont(0, QFont("Courier New", 9));
        }
    };

    addCategory("Classical Ciphers", {
        "Caesar", "ROT13", "ROT47", "Atbash", "Vigenere", "Playfair", "Affine",
        "Railfence", "Columnar", "Morse", "Baconian", "Keyword", "Substitution",
        "A1Z26", "Keyboard Shift", "Beaufort", "Autokey", "Scytale",
        "Polybius Square", "Bifid", "Trifid", "Four-Square"
    });
    addCategory("Modern Cryptography", {
        "AES-ECB", "AES-CBC", "AES-CTR", "ChaCha20", "Poly1305", "HMAC-SHA256", "HMAC-SHA512"
    });
    addCategory("Hashes & KDFs", {
        "MD5", "SHA-1", "SHA-256", "SHA-512", "BLAKE2b", "BLAKE2s", "PBKDF2-SHA256", "Argon2id"
    });
    addCategory("Encodings", {
        "Base64", "Hex", "Binary", "Octal", "URL Encode"
    });
    addCategory("CTF & Advanced", {
        "JWT Sign", "JWT Verify", "QR Code", "LSB Embed", "LSB Extract", "Leetspeak"
    });

    QTreeWidgetItem *pluginsCategory = new QTreeWidgetItem(m_opLibrary);
    pluginsCategory->setText(0, "Plugins");
    pluginsCategory->setFont(0, QFont("Courier New", 10, QFont::Bold));
    pluginsCategory->setForeground(0, QColor("#00cc88"));

    m_opLibrary->expandAll();
    leftLayout->addWidget(m_opLibrary);

    QPushButton *managePluginsBtn = new QPushButton("MANAGE PLUGINS");
    managePluginsBtn->setStyleSheet(
        "font-size: 9px; padding: 4px; color: #00cc88;"
        "border: 1px solid #00cc88; border-radius: 4px;"
    );
    leftLayout->addWidget(managePluginsBtn);
    connect(managePluginsBtn, &QPushButton::clicked, this, &MainWindow::onOpenPluginBrowser);

    QLabel *descHelp = new QLabel("Double-click to add to recipe.");
    descHelp->setStyleSheet("color: #8880a0; font-size: 9px;");
    leftLayout->addWidget(descHelp);

    mainSplitter->addWidget(leftPanel);

    // CENTER PANEL: Recipe Canvas
    QWidget *centerPanel = new QWidget();
    QVBoxLayout *centerLayout = new QVBoxLayout(centerPanel);
    centerLayout->setContentsMargins(0, 0, 0, 0);
    centerLayout->setSpacing(4);

    QHBoxLayout *recipeTitleRow = new QHBoxLayout();
    QLabel *recLabel = new QLabel("RECIPE PIPELINE");
    recLabel->setStyleSheet("font-weight: bold; color: #4a7cff;");
    recipeTitleRow->addWidget(recLabel);

    QPushButton *clearRecipeBtn = new QPushButton("Clear");
    clearRecipeBtn->setFixedSize(50, 20);
    clearRecipeBtn->setStyleSheet("font-size: 9px; padding: 2px;");
    recipeTitleRow->addWidget(clearRecipeBtn);
    connect(clearRecipeBtn, &QPushButton::clicked, this, [this]() {
        m_recipeModel->clear();
        m_undoStack->clear();
        updateSettingsPanel(-1);
        runRecipeOnSteps();
    });

    recipeTitleRow->addStretch();
    QPushButton *saveBtn = new QPushButton("SAVE");
    saveBtn->setFixedSize(50, 20);
    saveBtn->setStyleSheet("font-size: 9px; padding: 2px; color: #00cc88;");
    recipeTitleRow->addWidget(saveBtn);
    connect(saveBtn, &QPushButton::clicked, this, &MainWindow::onSaveRecipe);

    QPushButton *loadBtn = new QPushButton("LOAD");
    loadBtn->setFixedSize(50, 20);
    loadBtn->setStyleSheet("font-size: 9px; padding: 2px; color: #4a7cff;");
    recipeTitleRow->addWidget(loadBtn);
    connect(loadBtn, &QPushButton::clicked, this, &MainWindow::onLoadRecipe);

    centerLayout->addLayout(recipeTitleRow);

    // Recipe List View with Model + Delegate
    m_recipeView = new QListView();
    m_recipeView->setModel(m_recipeModel);
    m_recipeDelegate = new RecipeDelegate(this);
    m_recipeView->setItemDelegate(m_recipeDelegate);
    m_recipeView->setDragDropMode(QAbstractItemView::InternalMove);
    m_recipeView->setDefaultDropAction(Qt::MoveAction);
    m_recipeView->setSelectionMode(QAbstractItemView::SingleSelection);
    m_recipeView->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    centerLayout->addWidget(m_recipeView);

    connect(m_recipeDelegate, &RecipeDelegate::deleteClicked, this, &MainWindow::onRecipeCardDelete);
    connect(m_recipeDelegate, &RecipeDelegate::toggleEnabledClicked, this, &MainWindow::onRecipeCardToggleEnabled);
    connect(m_recipeDelegate, &RecipeDelegate::moveUpClicked, this, &MainWindow::onRecipeCardMoveUp);
    connect(m_recipeDelegate, &RecipeDelegate::moveDownClicked, this, &MainWindow::onRecipeCardMoveDown);
    connect(m_recipeView->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, [this](const QModelIndex &idx, const QModelIndex &) {
        updateSettingsPanel(idx.isValid() ? idx.row() : -1);
    });

    // Template Selector
    QHBoxLayout *tmplRow = new QHBoxLayout();
    QComboBox *tmplCombo = new QComboBox();
    tmplCombo->addItem("PRESET SCENARIOS...");
    tmplCombo->addItem("Argon2id derivation check");
    tmplCombo->addItem("AES CBC encrypted flag pipeline");
    tmplCombo->addItem("JWT inspector check");
    tmplCombo->addItem("LSB Pixel stego extraction");
    tmplCombo->setMinimumWidth(180);
    tmplRow->addWidget(new QLabel("Preset:"));
    tmplRow->addWidget(tmplCombo, 1);
    centerLayout->addLayout(tmplRow);
    connect(tmplCombo, SIGNAL(currentIndexChanged(int)), this, SLOT(onTemplateSelected(int)));

    mainSplitter->addWidget(centerPanel);

    // RIGHT PANEL: Step Parameters
    QWidget *rightPanel = new QWidget();
    QVBoxLayout *rightLayout = new QVBoxLayout(rightPanel);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->setSpacing(4);

    QLabel *setLabel = new QLabel("STEP PARAMETERS");
    setLabel->setStyleSheet("font-weight: bold; color: #4a7cff;");
    rightLayout->addWidget(setLabel);

    m_settingsContainer = new QWidget();
    QPalette contPal; contPal.setColor(QPalette::Window, QColor(10, 5, 20));
    m_settingsContainer->setPalette(contPal);
    m_settingsContainer->setAutoFillBackground(true);
    m_settingsLayout = new QVBoxLayout(m_settingsContainer);
    m_settingsLayout->setContentsMargins(4, 4, 4, 4);

    QScrollArea *scroll = new QScrollArea();
    scroll->setWidgetResizable(true);
    scroll->setWidget(m_settingsContainer);
    scroll->setStyleSheet(
        "QScrollArea { background:#0a0514; border:1px solid #1e1850; border-radius:4px; }"
        "QScrollBar:vertical { background:#0a0514; width:10px; margin:0px; }"
        "QScrollBar::handle:vertical { background:#1e1850; min-height:20px; border-radius:5px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0px; }"
    );
    rightLayout->addWidget(scroll);

    // Macro Editor
    QGroupBox *macroGroup = new QGroupBox("Macro Editor");
    QVBoxLayout *macroLayout = new QVBoxLayout(macroGroup);
    macroLayout->setContentsMargins(8, 8, 8, 8);
    macroLayout->setSpacing(4);

    QLineEdit *macroInput = new QLineEdit();
    macroInput->setPlaceholderText("base64() | rot13() | sha256()");
    macroLayout->addWidget(macroInput);

    QPushButton *applyMacroBtn = new QPushButton("APPLY MACRO CHAIN");
    applyMacroBtn->setStyleSheet("font-size: 10px; font-weight: bold;");
    macroLayout->addWidget(applyMacroBtn);
    rightLayout->addWidget(macroGroup);

    connect(applyMacroBtn, &QPushButton::clicked, this, [this, macroInput]() {
        std::string err;
        if (m_engine.parseMacroScript(macroInput->text().toStdString(), m_recipeModel, err)) {
            m_undoStack->clear();
            updateSettingsPanel(0);
            runRecipeOnSteps();
        } else {
            QMessageBox::warning(this, "Macro Compile Error", QString::fromStdString(err));
        }
    });

    mainSplitter->addWidget(rightPanel);
    mainSplitter->setStretchFactor(0, 2);
    mainSplitter->setStretchFactor(1, 3);
    mainSplitter->setStretchFactor(2, 2);
    mainLayout->addWidget(mainSplitter, 3);

    // ─────────────────────────────────────────────────────────────────────
    // 3. BOTTOM SPLITTER
    // ─────────────────────────────────────────────────────────────────────
    QSplitter *ioSplitter = new QSplitter(Qt::Horizontal, this);

    QWidget *inputPanel = new QWidget();
    QVBoxLayout *inputLayout = new QVBoxLayout(inputPanel);
    inputLayout->setContentsMargins(0, 0, 0, 0);
    inputLayout->setSpacing(4);

    QLabel *inLabel = new QLabel("INPUT (Paste Text or Drop File)");
    inLabel->setStyleSheet("font-weight: bold; color: #00cc88;");
    inputLayout->addWidget(inLabel);

    m_inputEdit = new DropEdit(this);
    m_inputEdit->setMinimumHeight(150);
    inputLayout->addWidget(m_inputEdit);

    m_fileUploadFrame = new QFrame();
    m_fileUploadFrame->setFrameShape(QFrame::StyledPanel);
    m_fileUploadFrame->setVisible(false);
    QHBoxLayout *fileLayout = new QHBoxLayout(m_fileUploadFrame);
    fileLayout->setContentsMargins(6, 4, 6, 4);
    m_fileNameLabel = new QLabel("Loaded: file.bin (0 bytes)");
    m_fileProgress = new QProgressBar();
    m_fileProgress->setValue(100);
    m_fileProgress->setFixedHeight(12);
    QPushButton *clearFileBtn = new QPushButton("✕");
    clearFileBtn->setFixedSize(20, 20);
    fileLayout->addWidget(m_fileNameLabel, 1);
    fileLayout->addWidget(m_fileProgress);
    fileLayout->addWidget(clearFileBtn);
    inputLayout->addWidget(m_fileUploadFrame);

    m_miniMap = new DataMiniMap(this);
    m_miniMap->setVisible(false);
    inputLayout->addWidget(m_miniMap);
    connect(m_miniMap, &DataMiniMap::positionClicked, this, [this](double frac) {
        if (!m_rawInput.empty()) {
            size_t pos = frac * m_rawInput.size();
            m_inputEdit->setFocus();
            QTextCursor cursor = m_inputEdit->textCursor();
            cursor.setPosition(std::min((int)pos, (int)m_inputEdit->toPlainText().size()));
            m_inputEdit->setTextCursor(cursor);
            m_inputEdit->ensureCursorVisible();
        }
    });
    connect(clearFileBtn, &QPushButton::clicked, this, &MainWindow::onClearFile);

    ioSplitter->addWidget(inputPanel);

    QWidget *outputPanel = new QWidget();
    QVBoxLayout *outputLayout = new QVBoxLayout(outputPanel);
    outputLayout->setContentsMargins(0, 0, 0, 0);
    outputLayout->setSpacing(4);

    QHBoxLayout *outHeaderRow = new QHBoxLayout();
    QLabel *outLabel = new QLabel("OUTPUT WORKSPACE");
    outLabel->setStyleSheet("font-weight: bold; color: #00cc88;");
    outHeaderRow->addWidget(outLabel);
    outHeaderRow->addStretch();

    QPushButton *copyBtn = new QPushButton("COPY");
    copyBtn->setFixedWidth(60);
    copyBtn->setStyleSheet("font-size: 10px; padding: 4px;");
    outHeaderRow->addWidget(copyBtn);
    connect(copyBtn, &QPushButton::clicked, this, &MainWindow::onCopyOutput);

    QPushButton *saveBinBtn = new QPushButton("SAVE BIN");
    saveBinBtn->setFixedWidth(80);
    saveBinBtn->setStyleSheet("font-size: 10px; padding: 4px;");
    outHeaderRow->addWidget(saveBinBtn);
    connect(saveBinBtn, &QPushButton::clicked, this, [this](){ onExportOutput("bin"); });

    outputLayout->addLayout(outHeaderRow);

    m_outputTabs = new QTabWidget();

    m_outputText = new QTextEdit();
    m_outputText->setReadOnly(true);
    m_outputText->setMinimumHeight(150);
    m_outputText->setStyleSheet(
        "QTextEdit { background: #120a20; color: #e0e0f0; border: none;"
        "  font-family: 'Courier New', monospace; font-size: 12px; padding: 8px; }"
    );
    m_outputTabs->addTab(m_outputText, "FORMATTED");

    m_outputByteBreakdown = new QPlainTextEdit();
    m_outputByteBreakdown->setReadOnly(true);
    m_outputTabs->addTab(m_outputByteBreakdown, "BYTE BREAKDOWN");

    m_outputDiff = new QPlainTextEdit();
    m_outputDiff->setReadOnly(true);
    m_outputTabs->addTab(m_outputDiff, "DIFF COMPARISON");

    m_hexDiff = new HexDiffViewer(this);
    m_outputTabs->addTab(m_hexDiff, "HEX DIFF");

    QWidget *plotsTab = new QWidget();
    QHBoxLayout *plotsLayout = new QHBoxLayout(plotsTab);
    plotsLayout->setContentsMargins(4, 4, 4, 4);
    plotsLayout->setSpacing(6);

    m_histogram = new FrequencyHistogram(this);
    plotsLayout->addWidget(m_histogram, 2);

    QWidget *entropyBox = new QWidget();
    QVBoxLayout *entLayout = new QVBoxLayout(entropyBox);
    entLayout->setContentsMargins(0, 0, 0, 0);
    entLayout->setSpacing(4);
    m_heatmap = new EntropyHeatmap(this);
    m_entropyGraph = new ShannonEntropyGraph(this);
    entLayout->addWidget(m_heatmap);
    entLayout->addWidget(m_entropyGraph);
    plotsLayout->addWidget(entropyBox, 2);

    m_encodingWheel = new EncodingWheel(this);
    plotsLayout->addWidget(m_encodingWheel, 1);

    m_outputTabs->addTab(plotsTab, "ANALYSIS PLOTS");

    QWidget *periodTab = new QWidget();
    QHBoxLayout *periodLayout = new QHBoxLayout(periodTab);
    periodLayout->setContentsMargins(4, 4, 4, 4);
    periodLayout->setSpacing(6);
    m_autocorrGraph = new AutocorrelationGraph(this);
    m_ngramHeatmap = new NGramHeatmap(this);
    periodLayout->addWidget(m_autocorrGraph, 2);
    periodLayout->addWidget(m_ngramHeatmap, 1);
    m_outputTabs->addTab(periodTab, "PERIODICITY");

    m_blockViz = new BlockCipherModeViz(this);
    m_outputTabs->addTab(m_blockViz, "BLOCK MODES");

    QWidget *ctfTab = new QWidget();
    QHBoxLayout *ctfLayout = new QHBoxLayout(ctfTab);
    ctfLayout->setContentsMargins(6, 6, 6, 6);
    ctfLayout->setSpacing(8);

    QGroupBox *ctfGroup = new QGroupBox("Auto Cracker & Flag Checker");
    QVBoxLayout *ctfLeft = new QVBoxLayout(ctfGroup);
    m_ctfFlagRegex = new QLineEdit();
    m_ctfFlagRegex->setPlaceholderText("Flag Format regex (e.g. flag\\{[a-z]+\\})");
    ctfLeft->addWidget(new QLabel("Flag Pattern:"));
    ctfLeft->addWidget(m_ctfFlagRegex);

    m_ctfWordlist = new QPlainTextEdit();
    m_ctfWordlist->setPlaceholderText("dictionary wordlist (one word per line)");
    m_ctfWordlist->setMaximumHeight(80);
    ctfLeft->addWidget(new QLabel("Dictionary words (optional):"));
    ctfLeft->addWidget(m_ctfWordlist);

    QPushButton *bruteCtfBtn = new QPushButton("LAUNCH CTF ATTACK SEARCH");
    bruteCtfBtn->setStyleSheet("background: #00aa77; font-weight: bold;");
    ctfLeft->addWidget(bruteCtfBtn);

    QPushButton *tlsAttackBtn = new QPushButton("TLS / SSL ATTACK PANEL");
    tlsAttackBtn->setStyleSheet("background: #4a7cff; font-weight: bold; margin-top:4px;");
    ctfLeft->addWidget(tlsAttackBtn);

    ctfLayout->addWidget(ctfGroup, 2);

    QGroupBox *ctfResGroup = new QGroupBox("Identified Candidates");
    QVBoxLayout *ctfRight = new QVBoxLayout(ctfResGroup);
    m_ctfResults = new QListWidget();
    m_ctfMatchCount = new QLabel("0 Matches found");
    ctfRight->addWidget(m_ctfResults);
    ctfRight->addWidget(m_ctfMatchCount);
    ctfLayout->addWidget(ctfResGroup, 3);

    m_outputTabs->addTab(ctfTab, "CTF TOOLS");

    outputLayout->addWidget(m_outputTabs);
    ioSplitter->addWidget(outputPanel);

    ioSplitter->setStretchFactor(0, 1);
    ioSplitter->setStretchFactor(1, 2);
    mainLayout->addWidget(ioSplitter, 2);

    setCentralWidget(central);

    // Signal Connections
    connect(m_inputEdit, &QPlainTextEdit::textChanged, this, &MainWindow::onInputTextChanged);
    connect(m_inputEdit, &DropEdit::fileDropped, this, &MainWindow::onFileLoaded);
    connect(m_librarySearch, &QLineEdit::textChanged, this, [this](const QString &text) {
        for (int i = 0; i < m_opLibrary->topLevelItemCount(); ++i) {
            QTreeWidgetItem *cat = m_opLibrary->topLevelItem(i);
            int visibleChildCount = 0;
            for (int j = 0; j < cat->childCount(); ++j) {
                QTreeWidgetItem *child = cat->child(j);
                if (child->text(0).contains(text, Qt::CaseInsensitive)) {
                    child->setHidden(false);
                    visibleChildCount++;
                } else {
                    child->setHidden(true);
                }
            }
            cat->setHidden(visibleChildCount == 0 && !text.isEmpty());
        }
    });
    connect(m_opLibrary, &QTreeWidget::itemDoubleClicked, this, &MainWindow::onAddOperation);
    connect(m_encodingWheel, SIGNAL(baseSelected(int)), this, SLOT(onWheelBaseSelected(int)));
    connect(bruteCtfBtn, &QPushButton::clicked, this, &MainWindow::onRunCtfSearch);
    connect(tlsAttackBtn, &QPushButton::clicked, this, &MainWindow::onRunTlsAttack);

    updateRecipeCanvas();

    // Command Palette (Ctrl+P)
    CommandPalette *palette = new CommandPalette(this);
    palette->hide();
    new QShortcut(QKeySequence("Ctrl+P"), this, [this, palette]() {
        palette->showPalette();
    });
    connect(palette, &CommandPalette::operationSelected, this, [this](const QString &name) {
        RecipeStep step;
        step.operation_name = name.toStdString();
        step.enabled = true;
        m_undoStack->push(new AddStepCommand(m_recipeModel, step));
        updateSettingsPanel(m_recipeModel->stepCount() - 1);
        runRecipeOnSteps();
        ToastWidget::show(this, "Added: " + name, ToastWidget::Success, 2000);
    });
}

// ── Recipe management ──────────────────────────────────────────────────

void MainWindow::onAddOperation(QTreeWidgetItem *item, int column) {
    Q_UNUSED(column);
    if (item->childCount() > 0) return;
    RecipeStep step;
    step.operation_name = item->text(0).toStdString();
    step.enabled = true;
    m_undoStack->push(new AddStepCommand(m_recipeModel, step));
    int lastRow = m_recipeModel->stepCount() - 1;
    m_recipeView->setCurrentIndex(m_recipeModel->index(lastRow));
    updateSettingsPanel(lastRow);
    runRecipeOnSteps();
}

void MainWindow::updateRecipeCanvas() {
    // Model-driven: the view is already connected to the model.
    // Ensure the selection model is connected.
}

void MainWindow::onRecipeCardDelete(int index) {
    if (index < 0 || index >= m_recipeModel->stepCount()) return;
    m_undoStack->push(new RemoveStepCommand(m_recipeModel, index));
    int newRow = qMin(index, m_recipeModel->stepCount() - 1);
    if (newRow >= 0)
        m_recipeView->setCurrentIndex(m_recipeModel->index(newRow));
    updateSettingsPanel(newRow);
    runRecipeOnSteps();
}

void MainWindow::onRecipeCardToggleEnabled(int index) {
    if (index < 0 || index >= m_recipeModel->stepCount()) return;
    m_undoStack->push(new ToggleStepCommand(m_recipeModel, index));
    runRecipeOnSteps();
}

void MainWindow::onRecipeCardMoveUp(int index) {
    if (index <= 0 || index >= m_recipeModel->stepCount()) return;
    m_undoStack->push(new MoveStepCommand(m_recipeModel, index, index - 1));
    m_recipeView->setCurrentIndex(m_recipeModel->index(index - 1));
    runRecipeOnSteps();
}

void MainWindow::onRecipeCardMoveDown(int index) {
    if (index < 0 || index >= m_recipeModel->stepCount() - 1) return;
    m_undoStack->push(new MoveStepCommand(m_recipeModel, index, index + 1));
    m_recipeView->setCurrentIndex(m_recipeModel->index(index + 1));
    runRecipeOnSteps();
}

// ── Dynamic Settings Form ──────────────────────────────────────────────

void MainWindow::updateSettingsPanel(int stepIndex) {
    delete m_settingsLayout;
    qDeleteAll(m_settingsContainer->findChildren<QWidget*>(QString(), Qt::FindDirectChildrenOnly));
    m_settingsLayout = new QVBoxLayout(m_settingsContainer);
    m_settingsLayout->setContentsMargins(4, 4, 4, 4);

    if (stepIndex < 0 || stepIndex >= m_recipeModel->stepCount()) {
        QLabel *empty = new QLabel("Select an operation step to edit parameters.");
        empty->setStyleSheet("color: #8880a0; font-style: italic;");
        m_settingsLayout->addWidget(empty);
        return;
    }

    RecipeStep step = m_recipeModel->stepAt(stepIndex);
    std::string op = step.operation_name;

    QFormLayout *form = new QFormLayout();
    form->setSpacing(8);
    form->setLabelAlignment(Qt::AlignRight);

    auto addLineEdit = [&](const QString &label, const std::string &initVal, auto callback) {
        QLineEdit *edit = new QLineEdit();
        edit->setText(QString::fromStdString(initVal));
        edit->setStyleSheet(
            "QLineEdit { background:#120a20; color:#e0e0f0; border:1px solid #1e1850;"
            "  border-radius:4px; padding:4px; font-family:'Courier New',monospace; min-height:26px; }"
            "QLineEdit:focus { border:1px solid #4a7cff; }"
        );
        form->addRow(label, edit);
        QLabel *lb = qobject_cast<QLabel*>(form->labelForField(edit));
        if (lb) lb->setStyleSheet("font-weight:bold; color:#8880a0; font-size:10px;");
        connect(edit, &QLineEdit::textChanged, this, [this, stepIndex, callback](const QString &text) {
            auto oldState = m_recipeModel->stepAt(stepIndex);
            auto newState = oldState;
            callback(newState, text.toStdString());
            auto cmd = new ModifyStepCommand(m_recipeModel, stepIndex, oldState, newState);
            m_undoStack->push(cmd);
            m_recipeModel->setStepParam(stepIndex, newState.params);
            onParameterChanged();
        });
    };

    auto addSpinBox = [&](const QString &label, int minVal, int maxVal, int initVal, auto callback) {
        QSpinBox *spin = new QSpinBox();
        spin->setRange(minVal, maxVal);
        spin->setValue(initVal);
        spin->setStyleSheet(
            "QSpinBox { background:#120a20; color:#e0e0f0; border:1px solid #1e1850;"
            "  border-radius:4px; padding:4px; font-family:'Courier New',monospace; min-height:26px; }"
            "QSpinBox:focus { border:1px solid #4a7cff; }"
            "QSpinBox::up-button { border-left:1px solid #1e1850; background:#1a1030;"
            "  border-top-right-radius:4px; }"
            "QSpinBox::down-button { border-left:1px solid #1e1850; background:#1a1030;"
            "  border-bottom-right-radius:4px; }"
            "QSpinBox::up-arrow { width:8px; height:8px; }"
            "QSpinBox::down-arrow { width:8px; height:8px; }"
        );
        form->addRow(label, spin);
        QLabel *lb = qobject_cast<QLabel*>(form->labelForField(spin));
        if (lb) lb->setStyleSheet("font-weight:bold; color:#8880a0; font-size:10px;");
        connect(spin, QOverload<int>::of(&QSpinBox::valueChanged), this, &MainWindow::onParameterChanged);
        connect(spin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this, stepIndex, callback](int val) {
            auto oldState = m_recipeModel->stepAt(stepIndex);
            auto newState = oldState;
            callback(newState, val);
            auto cmd = new ModifyStepCommand(m_recipeModel, stepIndex, oldState, newState);
            m_undoStack->push(cmd);
            m_recipeModel->setStepParam(stepIndex, newState.params);
        });
    };

    auto addCheckbox = [&](const QString &label, bool checked, auto callback) {
        QCheckBox *chk = new QCheckBox(label);
        chk->setChecked(checked);
        chk->setStyleSheet(
            "QCheckBox { color:#e0e0f0; font-weight:bold; font-size:10px; spacing:8px; }"
            "QCheckBox::indicator { width:16px; height:16px; border:1px solid #1e1850;"
            "  border-radius:3px; background:#120a20; }"
            "QCheckBox::indicator:checked { background:#4a7cff; }"
        );
        form->addRow("", chk);
        connect(chk, &QCheckBox::clicked, this, &MainWindow::onParameterChanged);
        connect(chk, &QCheckBox::clicked, this, [this, stepIndex, callback](bool c) {
            auto oldState = m_recipeModel->stepAt(stepIndex);
            auto newState = oldState;
            callback(newState, c);
            auto cmd = new ModifyStepCommand(m_recipeModel, stepIndex, oldState, newState);
            m_undoStack->push(cmd);
            m_recipeModel->setStepParam(stepIndex, newState.params);
        });
    };

    QLabel *headerLabel = new QLabel(QString::fromStdString(op).toUpper());
    headerLabel->setStyleSheet("font-weight: bold; color: #6b9cff; margin-bottom: 6px;");
    m_settingsLayout->addWidget(headerLabel);

    if (op == "Caesar") {
        addSpinBox("Shift:", -25, 25, step.params.param1, [](RecipeStep &s, int v) { s.params.param1 = v; });
    } else if (op == "Affine") {
        addSpinBox("a (coprime 26):", 1, 25, step.params.param1, [](RecipeStep &s, int v) { s.params.param1 = v; });
        addSpinBox("b:", 0, 25, step.params.param2, [](RecipeStep &s, int v) { s.params.param2 = v; });
        addCheckbox("Decrypt instead", !step.params.encrypt, [](RecipeStep &s, bool c) { s.params.encrypt = !c; });
    } else if (op == "Vigenere" || op == "Playfair" || op == "Keyword" || op == "Autokey" || op == "Beaufort") {
        addLineEdit("Key:", step.params.key, [](RecipeStep &s, const std::string &v) { s.params.key = v; });
        if (op != "Beaufort")
            addCheckbox("Decrypt instead", !step.params.encrypt, [](RecipeStep &s, bool c) { s.params.encrypt = !c; });
    } else if (op == "Substitution") {
        addLineEdit("Alphabet (26 chars):", step.params.key, [](RecipeStep &s, const std::string &v) { s.params.key = v; });
        addCheckbox("Decrypt instead", !step.params.encrypt, [](RecipeStep &s, bool c) { s.params.encrypt = !c; });
    } else if (op == "Railfence") {
        addSpinBox("Rails:", 2, 20, step.params.param1, [](RecipeStep &s, int v) { s.params.param1 = v; });
        addSpinBox("Offset:", 0, 20, step.params.param2, [](RecipeStep &s, int v) { s.params.param2 = v; });
    } else if (op == "Columnar") {
        addLineEdit("Key:", step.params.key, [](RecipeStep &s, const std::string &v) { s.params.key = v; });
        addCheckbox("Decrypt instead", !step.params.encrypt, [](RecipeStep &s, bool c) { s.params.encrypt = !c; });
    } else if (op == "XOR (hex key)" || op == "RC4") {
        addLineEdit("Key:", step.params.key, [](RecipeStep &s, const std::string &v) { s.params.key = v; });
    } else if (op == "Blowfish" || op == "DES") {
        addLineEdit("Key:", step.params.key, [](RecipeStep &s, const std::string &v) { s.params.key = v; });
        addCheckbox("Decrypt instead", !step.params.encrypt, [](RecipeStep &s, bool c) { s.params.encrypt = !c; });
    } else if (op == "Scytale") {
        addSpinBox("Columns:", 2, 20, step.params.param1, [](RecipeStep &s, int v) { s.params.param1 = v; });
        addCheckbox("Decrypt instead", !step.params.encrypt, [](RecipeStep &s, bool c) { s.params.encrypt = !c; });
    } else if (op == "Trifid") {
        addLineEdit("Key Grid:", step.params.key, [](RecipeStep &s, const std::string &v) { s.params.key = v; });
        addSpinBox("Period:", 2, 20, step.params.param1, [](RecipeStep &s, int v) { s.params.param1 = v; });
        addCheckbox("Decrypt instead", !step.params.encrypt, [](RecipeStep &s, bool c) { s.params.encrypt = !c; });
    } else if (op == "Four-Square") {
        addLineEdit("Keys:", step.params.key, [](RecipeStep &s, const std::string &v) { s.params.key = v; });
        addCheckbox("Decrypt instead", !step.params.encrypt, [](RecipeStep &s, bool c) { s.params.encrypt = !c; });
    } else if (op == "Keyboard Shift") {
        addSpinBox("Shift:", -10, 10, step.params.param1, [](RecipeStep &s, int v) { s.params.param1 = v; });
        addCheckbox("Decrypt instead", !step.params.encrypt, [](RecipeStep &s, bool c) { s.params.encrypt = !c; });
    }
    else if (op == "AES-ECB" || op == "AES-CBC" || op == "AES-CTR") {
        addLineEdit("Key (16 or 32 bytes):", step.params.key, [](RecipeStep &s, const std::string &v) { s.params.key = v; });
        if (op != "AES-ECB")
            addLineEdit("IV (16 bytes):", step.params.iv, [](RecipeStep &s, const std::string &v) { s.params.iv = v; });
        addCheckbox("Decrypt instead", !step.params.encrypt, [](RecipeStep &s, bool c) { s.params.encrypt = !c; });
    } else if (op == "ChaCha20") {
        addLineEdit("Key (32 bytes):", step.params.key, [](RecipeStep &s, const std::string &v) { s.params.key = v; });
        addLineEdit("Nonce (12 bytes):", step.params.iv, [](RecipeStep &s, const std::string &v) { s.params.iv = v; });
        addSpinBox("Counter (starts 0):", 0, 999999, step.params.param1, [](RecipeStep &s, int v) { s.params.param1 = v; });
    } else if (op == "Poly1305" || op == "HMAC-SHA256" || op == "HMAC-SHA512") {
        addLineEdit("Secret Key:", step.params.key, [](RecipeStep &s, const std::string &v) { s.params.key = v; });
    } else if (op == "PBKDF2-SHA256" || op == "Argon2id") {
        addLineEdit("Salt:", step.params.iv, [](RecipeStep &s, const std::string &v) { s.params.iv = v; });
        addSpinBox("Iterations:", 1, 5000, step.params.param1, [](RecipeStep &s, int v) { s.params.param1 = v; });
        addSpinBox("Memory Size (KB):", 8, 65536, step.params.param2, [](RecipeStep &s, int v) { s.params.param2 = v; });
    } else if (op == "BLAKE2b" || op == "BLAKE2s") {
        addLineEdit("Key (Optional):", step.params.key, [](RecipeStep &s, const std::string &v) { s.params.key = v; });
    } else if (op == "JWT Sign") {
        addLineEdit("Secret Key:", step.params.key, [](RecipeStep &s, const std::string &v) { s.params.key = v; });
        addLineEdit("Header JSON (Optional):", step.params.iv, [](RecipeStep &s, const std::string &v) { s.params.iv = v; });
    } else if (op == "JWT Verify") {
        addLineEdit("Secret Key (Optional):", step.params.key, [](RecipeStep &s, const std::string &v) { s.params.key = v; });
    } else if (op == "LSB Embed") {
        addLineEdit("Secret Text to Hide:", step.params.key, [](RecipeStep &s, const std::string &v) { s.params.key = v; });
    } else if (op == "Morse" || op == "Baconian" || op == "Binary" || op == "Octal" || op == "Base64" || op == "Hex" || op == "URL Encode") {
        addCheckbox("Decrypt/Decode", !step.params.encrypt, [](RecipeStep &s, bool c) { s.params.encrypt = !c; });
    } else {
        QLabel *noParams = new QLabel("Operation has no configurable parameters.");
        noParams->setStyleSheet("color: #8880a0; font-style: italic;");
        form->addRow("", noParams);
    }

    m_settingsLayout->addLayout(form);
    m_settingsLayout->addStretch();
}

void MainWindow::onParameterChanged() {
    if (m_autoRunCheck->isChecked())
        runRecipeOnSteps();
}

// ── Execution ──────────────────────────────────────────────────────────

void MainWindow::runRecipeOnSteps() {
    if (m_engine.isThreadingEnabled() && m_engine.isRunningAsync())
        return;

    QSettings s("Obscuron", "CryptoSuite");
    bool useThreading = s.value("performance/multiThread", false).toBool();
    m_engine.setThreadingEnabled(useThreading);

    if (useThreading) {
        setUIControlsEnabled(false);
        m_cancelBtn->setVisible(true);
        disconnect(m_asyncFinishConn);
        m_asyncFinishConn = connect(&m_engine, &RecipeEngine::executionFinished,
            this, &MainWindow::onAsyncExecutionFinished);
        m_engine.runAsync(m_rawInput, m_recipeModel->steps());
    } else {
        std::vector<RecipeStep> steps = m_recipeModel->steps();
        std::string out = m_engine.run(m_rawInput, steps);
        for (size_t i = 0; i < steps.size(); ++i) {
            const auto &s = steps[i];
            m_recipeModel->setStepResult(i, s.intermediate_output, s.has_error,
                                          s.error_message, s.execution_time_ms);
        }
        applyPipelineResults(out);
    }
}

void MainWindow::onRunRecipe() {
    runRecipeOnSteps();
}

void MainWindow::onAsyncExecutionFinished(const std::string &out, const RecipeMetrics &) {
    m_engine.syncResultsToModel(m_recipeModel);
    m_cancelBtn->setVisible(false);
    setUIControlsEnabled(true);
    applyPipelineResults(out);
}

void MainWindow::onCancelAsync() {
    m_engine.cancelAsync();
    m_cancelBtn->setVisible(false);
    setUIControlsEnabled(true);
}

void MainWindow::setUIControlsEnabled(bool enabled) {
    m_recipeView->setEnabled(enabled);
    m_opLibrary->setEnabled(enabled);
    m_inputEdit->setEnabled(enabled);
    m_undoBtn->setEnabled(enabled && m_undoStack->canUndo());
    m_redoBtn->setEnabled(enabled && m_undoStack->canRedo());
}

void MainWindow::applyPipelineResults(const std::string &out) {
    // Update metrics
    const RecipeMetrics &m = m_engine.getLatestMetrics();
    QString speed = QString("%1").arg(m.throughput_mbs, 0, 'f', 2);
    m_metricsLabel->setText(
        QString("Time: %1 ms | Speed: %2 MB/s | Mem: %3 B")
            .arg(m.total_time_ms, 0, 'f', 1)
            .arg(speed)
            .arg(m.memory_used_bytes)
    );

    displayOutputFormat(out);

    m_histogram->setData(out);
    m_heatmap->setData(out);
    m_entropyGraph->setData(out);
    m_encodingWheel->setValue(out);
    m_autocorrGraph->setData(out);
    m_ngramHeatmap->setData(out);
    m_hexDiff->setData(m_rawInput, out);
    m_blockViz->setData(out);

    if (m_rawInput.size() > 1024) {
        m_miniMap->setData(m_rawInput);
        m_miniMap->setVisible(true);
    } else {
        m_miniMap->setVisible(false);
    }
}

static QString markdownToHtml(const std::string &md) {
    QString html;
    std::istringstream stream(md);
    std::string line;
    bool inCodeBlock = false;
    while (std::getline(stream, line)) {
        if (line.rfind("```", 0) == 0) {
            if (inCodeBlock) {
                html += "</pre></code>";
                inCodeBlock = false;
            } else {
                html += "<code><pre style='background:#0a0514; padding:8px; border-radius:4px;"
                        " font-family:\"Courier New\",monospace; font-size:11px;'>";
                inCodeBlock = true;
            }
            continue;
        }
        if (inCodeBlock) {
            html += line.empty() ? "<br>" : QString::fromStdString(line) + "\n";
            continue;
        }
        if (line.rfind("# ", 0) == 0) {
            QString t = QString::fromStdString(line.substr(2));
            html += "<h2 style='color:#4a7cff; font-family:\"Courier New\",monospace;'>" + t + "</h2>";
        } else if (line.rfind("## ", 0) == 0) {
            QString t = QString::fromStdString(line.substr(3));
            html += "<h3 style='color:#6b9cff; font-family:\"Courier New\",monospace;'>" + t + "</h3>";
        } else if (line.rfind("---", 0) == 0 || line.rfind("___", 0) == 0) {
            html += "<hr style='border:1px solid #1e1850;'>";
        } else if (line.rfind("- ", 0) == 0 || line.rfind("* ", 0) == 0) {
            html += "<li style='color:#e0e0f0;'>" + QString::fromStdString(line.substr(2)) + "</li>";
        } else if (line.rfind("|", 0) == 0) {
            QStringList cells = QString::fromStdString(line).split('|');
            html += "<tr>";
            for (int ci = 1; ci < cells.size() - 1; ++ci)
                html += "<td style='padding:2px 8px; border:1px solid #1e1850;'>" + cells[ci].trimmed() + "</td>";
            html += "</tr>";
        } else if (!line.empty()) {
            QString escaped = QString::fromStdString(line);
            escaped.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
            escaped.replace(QRegularExpression("\\*\\*(.+?)\\*\\*"), "<b>\\1</b>");
            escaped.replace(QRegularExpression("\\*(.+?)\\*"), "<i>\\1</i>");
            html += "<p style='margin:2px 0; color:#e0e0f0;'>" + escaped + "</p>";
        } else {
            html += "<br>";
        }
    }
    if (inCodeBlock) html += "</pre></code>";
    return "<div style='font-family:\"Courier New\",monospace; font-size:12px;'>" + html + "</div>";
}

void MainWindow::displayOutputFormat(const std::string &output) {
    bool printable = true;
    for (unsigned char c : output) {
        if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
            printable = false; break;
        }
    }

    if (printable) {
        std::string s(output);
        bool isMarkdown = (s.find("```") != std::string::npos) ||
                          (s.find("\n#") != std::string::npos) ||
                          (s.find("\n|") != std::string::npos);
        if (isMarkdown)
            m_outputText->setHtml(markdownToHtml(s));
        else
            m_outputText->setPlainText(QString::fromStdString(s));
    } else {
        std::stringstream ss;
        ss << "[RAW BINARY DATA (" << output.size() << " bytes)]\n\n";
        for (size_t i = 0; i < output.size(); ++i) {
            ss << std::hex << std::setfill('0') << std::setw(2) << (int)(unsigned char)output[i] << " ";
            if ((i + 1) % 16 == 0) ss << "\n";
        }
        m_outputText->setPlainText(QString::fromStdString(ss.str()));
    }

    std::stringstream bb;
    bb << "Offset    Hex  Dec  Char\n";
    bb << "────────────────────────\n";
    for (size_t i = 0; i < std::min((size_t)1000, output.size()); ++i) {
        unsigned char c = output[i];
        bb << "0x" << std::setfill('0') << std::setw(6) << std::hex << i << "  ";
        bb << std::setw(2) << (int)c << "  ";
        bb << std::setfill(' ') << std::setw(3) << std::dec << (int)c << "  ";
        if (c == '\n') bb << "<LF>";
        else if (c == '\r') bb << "<CR>";
        else if (c == '\t') bb << "<TAB>";
        else if (c >= 32 && c <= 126) bb << (char)c;
        else bb << "<.>";
        bb << "\n";
    }
    if (output.size() > 1000) bb << "... truncated ...";
    m_outputByteBreakdown->setPlainText(QString::fromStdString(bb.str()));

    std::stringstream df;
    df << "=== INPUT DATA ===\n" << m_rawInput << "\n\n";
    df << "=== OUTPUT DATA ===\n" << (printable ? output : "[Raw non-printable bytes]");
    m_outputDiff->setPlainText(QString::fromStdString(df.str()));
}

void MainWindow::onInputTextChanged() {
    m_rawInput = m_inputEdit->toPlainText().toStdString();
    onParameterChanged();
}

void MainWindow::onFileLoaded(const QString &filePath, const QByteArray &content) {
    m_rawInput = content.toStdString();
    QFileInfo fi(filePath);
    m_fileNameLabel->setText(QString("Loaded File: %1 (%2 bytes)").arg(fi.fileName()).arg(content.size()));
    m_fileUploadFrame->setVisible(true);
    m_inputEdit->setPlainText(QString::fromStdString(m_rawInput.substr(0, std::min((size_t)2000, m_rawInput.size()))));
    m_inputEdit->setPlaceholderText("File loaded. Showing first 2000 chars.");
    onParameterChanged();
}

void MainWindow::onClearFile() {
    m_fileUploadFrame->setVisible(false);
    m_inputEdit->setPlaceholderText("Type, paste, or drag a file here...");
    m_inputEdit->clear();
    m_rawInput.clear();
    onParameterChanged();
}

void MainWindow::onCopyOutput() {
    QApplication::clipboard()->setText(m_outputText->toPlainText());
}

void MainWindow::onExportOutput(const QString &ext) {
    QString path = QFileDialog::getSaveFileName(this, "Export File", "", "*." + ext);
    if (path.isEmpty()) return;
    QFile f(path);
    if (f.open(QIODevice::WriteOnly)) {
        std::string raw_out = m_outputText->toPlainText().toStdString();
        f.write(raw_out.data(), raw_out.size());
        f.close();
    }
}

void MainWindow::onWheelBaseSelected(int radix) {
    RecipeStep step;
    step.enabled = true;
    if (radix == 2) step.operation_name = "Binary";
    else if (radix == 8) step.operation_name = "Octal";
    else if (radix == 16) step.operation_name = "Hex";
    else if (radix == 64) step.operation_name = "Base64";
    else return;
    m_undoStack->push(new AddStepCommand(m_recipeModel, step));
    int lastRow = m_recipeModel->stepCount() - 1;
    m_recipeView->setCurrentIndex(m_recipeModel->index(lastRow));
    updateSettingsPanel(lastRow);
    runRecipeOnSteps();
}

void MainWindow::onRecipeItemSelectionChanged() {} // handled by QListView selection model

// ── Undo/Redo replaced by QUndoStack ──────────────────────────────────

// ── Themes, Presets, CTF ──────────────────────────────────────────────

void MainWindow::onOpenSettings() {
    SettingsDialog dlg(this);
    dlg.exec();
}

void MainWindow::onThemeChanged(int index) {
    QColor accent(74, 124, 255);
    ThemeMode mode = THEME_DARK;
    if (index == 1) mode = THEME_LIGHT;
    else if (index == 2) mode = THEME_OLED;
    setStyleSheet(ThemeManager::getStyleSheet(mode, accent));
}

void MainWindow::onTemplateSelected(int index) {
    m_recipeModel->clear();
    m_undoStack->clear();

    if (index == 1) {
        RecipeStep s1; s1.operation_name = "Argon2id"; s1.enabled = true;
        s1.params.iv = "salty_parameter"; s1.params.param1 = 3; s1.params.param2 = 1024;
        m_recipeModel->addStep(s1.operation_name, s1.params);
    } else if (index == 2) {
        RecipeStep s1; s1.operation_name = "Base64"; s1.enabled = true;
        s1.params.encrypt = false;
        m_recipeModel->addStep(s1.operation_name, s1.params);
        RecipeStep s2; s2.operation_name = "AES-CBC"; s2.enabled = true;
        s2.params.key = "1234567890123456"; s2.params.iv = "0000000000000000";
        s2.params.encrypt = false;
        m_recipeModel->addStep(s2.operation_name, s2.params);
    } else if (index == 3) {
        RecipeStep s1; s1.operation_name = "JWT Verify"; s1.enabled = true;
        s1.params.key = "jwt_signing_key";
        m_recipeModel->addStep(s1.operation_name, s1.params);
    } else if (index == 4) {
        RecipeStep s1; s1.operation_name = "LSB Extract"; s1.enabled = true;
        m_recipeModel->addStep(s1.operation_name, s1.params);
    } else {
        return;
    }
    updateSettingsPanel(0);
    runRecipeOnSteps();
}

void MainWindow::onRunTlsAttack() {
    TlsAttackDialog *dlg = new TlsAttackDialog(this);
    connect(dlg, &TlsAttackDialog::rsaParamsExtracted, this, [this](const QString &mod, const QString &exp) {
        m_ctfFlagRegex->setText("RSA: n=" + mod.left(48) + "... e=" + exp.left(8));
        m_ctfResults->addItem("[RSA] Modulus: " + mod);
        m_ctfResults->addItem("[RSA] Exponent: " + exp);
        m_ctfMatchCount->setText("RSA parameters extracted — use ob-crypt rsa-wiener");
    });
    dlg->setModal(false);
    dlg->show();
}

void MainWindow::onRunCtfSearch() {
    m_ctfResults->clear();
    std::string pattern = m_ctfFlagRegex->text().toStdString();
    if (pattern.empty())
        pattern = "flag\\{[a-zA-Z0-9_]+\\}";
    runCtfDictionaryBrute(m_rawInput, pattern);
}

void MainWindow::runCtfDictionaryBrute(const std::string &input, const std::string &flagFormat) {
    QRegularExpression re(QString::fromStdString(flagFormat));
    int match_count = 0;

    auto testCandidate = [&](const std::string &candidate, const QString &method) {
        QString text = QString::fromStdString(candidate);
        QRegularExpressionMatchIterator it = re.globalMatch(text);
        while (it.hasNext()) {
            QRegularExpressionMatch match = it.next();
            QString label = QString("[%1] Match: %2").arg(method).arg(match.captured(0));
            m_ctfResults->addItem(label);
            match_count++;
        }
    };

    for (int shift = 1; shift < 26; ++shift) {
        std::string cand;
        custom_rot(input, shift, cand);
        testCandidate(cand, QString("Caesar Shift %1").arg(shift));
    }
    { std::string cand; rot47(input, cand); testCandidate(cand, "ROT47"); }
    { std::string cand; atbash(input, cand); testCandidate(cand, "Atbash"); }
    {
        std::string b64 = base64url_decode(input);
        if (!b64.empty()) {
            testCandidate(b64, "Base64 Raw");
            for (int shift = 1; shift < 26; ++shift) {
                std::string cand;
                custom_rot(b64, shift, cand);
                testCandidate(cand, QString("Base64 + Caesar %1").arg(shift));
            }
        }
    }
    m_ctfMatchCount->setText(QString("%1 Matches found").arg(match_count));
}

void MainWindow::onCtfFlagCheck() {}

void MainWindow::onDetectCipher() {
    std::string input = m_inputEdit->toPlainText().toStdString();
    if (input.empty()) {
        QMessageBox::information(this, "Detect Cipher", "Enter text to analyze first.");
        return;
    }
    auto results = detect_cipher(input, 8);
    std::ostringstream oss;
    oss << "=== Detection Results ===\n\n";
    if (results.empty()) {
        oss << "No cipher detected.\n";
    } else {
        for (auto &c : results) {
            oss << "  [" << (int)(c.confidence * 100) << "%] " << c.cipher_name;
            if (!c.key.empty()) oss << "  key: " << c.key;
            oss << "\n";
            if (!c.decrypted.empty()) {
                std::string preview = c.decrypted.substr(0, 200);
                if (c.decrypted.size() > 200) preview += "...";
                oss << "    -> \"" << preview << "\"\n";
            }
        }
        oss << "\n--- The top result has been loaded as output ---\n";
    }
    m_outputText->setPlainText(QString::fromStdString(oss.str()));
    m_outputTabs->setCurrentIndex(0);
    if (!results.empty() && !results[0].decrypted.empty())
        m_outputText->setPlainText(QString::fromStdString(results[0].decrypted));
    if (!results.empty()) {
        std::ostringstream meta;
        meta << "Detected: " << results[0].cipher_name
             << " (" << (int)(results[0].confidence * 100) << "%)";
        if (!results[0].key.empty()) meta << " key=" << results[0].key;
        m_metricsLabel->setText(QString::fromStdString(meta.str()));
    }
}

void MainWindow::onApplyMacro() {
    QMessageBox::information(this, "Macro Scripting", "Use the Macro Editor in the right panel.");
}

void MainWindow::onSaveRecipe() {
    QString path = QFileDialog::getSaveFileName(this, "Save Workspace", "",
        "Obscuron Workspace (*.obscuron);;JSON Recipe (*.json)");
    if (path.isEmpty()) return;

    QJsonObject root;
    root["version"] = 1;
    root["input"] = QString::fromStdString(m_rawInput);
    root["recipe"] = QJsonDocument::fromJson(
        QByteArray::fromStdString(m_recipeModel->exportToJSON())).array();

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        ToastWidget::show(this, "Failed to save: " + file.errorString(), ToastWidget::Error);
        return;
    }
    file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
    file.close();
    ToastWidget::show(this, "Workspace saved: " + QFileInfo(path).fileName(), ToastWidget::Success);
}

void MainWindow::onLoadRecipe() {
    QString path = QFileDialog::getOpenFileName(this, "Load Workspace", "",
        "Obscuron Workspace (*.obscuron);;JSON Recipe (*.json)");
    if (path.isEmpty()) return;

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        ToastWidget::show(this, "Failed to load: " + file.errorString(), ToastWidget::Error);
        return;
    }
    QByteArray data = file.readAll();
    file.close();

    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(data, &err);
    if (doc.isNull()) {
        ToastWidget::show(this, "Parse error: " + err.errorString(), ToastWidget::Error);
        return;
    }

    std::string input;
    if (doc.isObject()) {
        QJsonObject root = doc.object();
        input = root["input"].toString().toStdString();
        QJsonArray recipe = root["recipe"].toArray();
        QJsonDocument recipeDoc(recipe);
        std::string recipeJson = recipeDoc.toJson(QJsonDocument::Compact).toStdString();
        std::string importErr;
        if (!m_recipeModel->importFromJSON(recipeJson, importErr)) {
            ToastWidget::show(this, "Recipe error: " + QString::fromStdString(importErr), ToastWidget::Error);
            return;
        }
    } else if (doc.isArray()) {
        std::string recipeJson = data.toStdString();
        std::string importErr;
        if (!m_recipeModel->importFromJSON(recipeJson, importErr)) {
            ToastWidget::show(this, "Recipe error: " + QString::fromStdString(importErr), ToastWidget::Error);
            return;
        }
    } else {
        ToastWidget::show(this, "Invalid workspace format", ToastWidget::Error);
        return;
    }

    if (!input.empty()) {
        m_rawInput = input;
        m_inputEdit->setPlainText(QString::fromStdString(input));
    }

    m_undoStack->clear();
    updateSettingsPanel(0);
    runRecipeOnSteps();
    ToastWidget::show(this, "Workspace loaded", ToastWidget::Info);
}

void MainWindow::onOpenPluginBrowser() {
    PluginBrowserDialog dialog(&m_pluginLoader, this);
    connect(&dialog, &PluginBrowserDialog::pluginsChanged,
            this, &MainWindow::onPluginLibraryChanged);
    dialog.exec();
}

void MainWindow::onPluginLibraryChanged() {
    for (int i = 0; i < m_opLibrary->topLevelItemCount(); ++i) {
        QTreeWidgetItem *cat = m_opLibrary->topLevelItem(i);
        if (cat->text(0) == "Plugins") {
            while (cat->childCount() > 0)
                delete cat->takeChild(0);
            for (const auto &op : m_pluginLoader.allPluginOperations()) {
                QTreeWidgetItem *item = new QTreeWidgetItem(cat);
                item->setText(0, QString::fromStdString(op));
                item->setFont(0, QFont("Courier New", 9));
                item->setForeground(0, QColor("#00cc88"));
            }
            cat->setExpanded(true);
            break;
        }
    }
}
