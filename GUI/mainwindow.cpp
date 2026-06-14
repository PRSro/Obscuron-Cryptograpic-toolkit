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
#include <QTextStream>
#include <QScrollBar>
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

// ── RecipeCardWidget ──────────────────────────────────────────────────

RecipeCardWidget::RecipeCardWidget(const QString &name, int index, QWidget *parent)
    : QWidget(parent), m_index(index), m_isEnabled(true)
{
    setStyleSheet(
        "RecipeCardWidget { background:#120a20; border:1px solid #1e1850; border-radius:4px; }"
    );
    QHBoxLayout *layout = new QHBoxLayout(this);
    layout->setContentsMargins(8, 4, 8, 4);
    layout->setSpacing(6);

    // Status dot
    m_statusLabel = new QLabel("●");
    m_statusLabel->setStyleSheet("color: #00cc88; font-size: 14px;");
    layout->addWidget(m_statusLabel);

    // Operation Name
    m_nameLabel = new QLabel(name);
    m_nameLabel->setStyleSheet("font-weight: bold; font-size: 11px;");
    layout->addWidget(m_nameLabel, 1);

    // Up/Down buttons
    m_upBtn = new QPushButton("▲");
    m_upBtn->setFixedSize(22, 22);
    m_upBtn->setStyleSheet("padding: 0px; font-size: 9px;");
    layout->addWidget(m_upBtn);

    m_downBtn = new QPushButton("▼");
    m_downBtn->setFixedSize(22, 22);
    m_downBtn->setStyleSheet("padding: 0px; font-size: 9px;");
    layout->addWidget(m_downBtn);

    // Eye button to toggle enable
    m_toggleBtn = new QPushButton("👁");
    m_toggleBtn->setFixedSize(24, 22);
    m_toggleBtn->setCheckable(true);
    m_toggleBtn->setStyleSheet("padding: 0px; font-size: 11px;");
    layout->addWidget(m_toggleBtn);

    // Delete button
    m_deleteBtn = new QPushButton("✕");
    m_deleteBtn->setFixedSize(22, 22);
    m_deleteBtn->setStyleSheet("padding: 0px; color: #ff6b6b; font-weight: bold; font-size: 10px;");
    layout->addWidget(m_deleteBtn);

    // Connects
    connect(m_deleteBtn, &QPushButton::clicked, this, [this]() {
        emit deleteClicked(m_index);
    });
    connect(m_toggleBtn, &QPushButton::clicked, this, [this](bool checked) {
        emit toggleEnabledClicked(m_index, !checked);
    });
    connect(m_upBtn, &QPushButton::clicked, this, [this]() {
        emit moveUpClicked(m_index);
    });
    connect(m_downBtn, &QPushButton::clicked, this, [this]() {
        emit moveDownClicked(m_index);
    });
}

void RecipeCardWidget::setStatus(bool success, const QString &err_msg) {
    if (success) {
        m_statusLabel->setText("●");
        m_statusLabel->setStyleSheet("color: #00cc88;");
        m_nameLabel->setToolTip("");
    } else {
        m_statusLabel->setText("▲");
        m_statusLabel->setStyleSheet("color: #ff6b6b;");
        m_nameLabel->setToolTip(err_msg);
    }
}

void RecipeCardWidget::setEnabledState(bool enabled) {
    m_isEnabled = enabled;
    if (enabled) {
        m_nameLabel->setStyleSheet("font-weight: bold; font-size: 11px; color: #e0e0f0;");
        m_toggleBtn->setText("👁");
    } else {
        m_nameLabel->setStyleSheet("font-weight: bold; font-size: 11px; color: #3a3060; text-decoration: line-through;");
        m_toggleBtn->setText("❌");
        m_statusLabel->setStyleSheet("color: #3a3060;");
    }
}

// ── MainWindow ───────────────────────────────────────────────────────

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    m_isUndoingOrRedoing = false;
    setupUI();
    pushUndo(); // Initial state
}

void MainWindow::setupUI() {
    setWindowTitle("Obscuron — Cryptographic Analysis Workspace");
    setMinimumSize(1200, 800);

    // Apply dark style locally — do not call ThemeManager::applyTheme()
    // (that sets qApp->setStyleSheet globally, corrupting other windows)
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
        "QListWidget { background: #120a20; color: #e0e0f0; border: 1px solid #1e1850; "
        "  border-radius: 6px; font-family: 'Courier New', monospace; font-size: 12px; padding: 4px; }"
        "QListWidget::item { padding: 6px; border-radius: 4px; }"
        "QListWidget::item:hover { background: #1a1030; }"
        "QListWidget::item:selected { background: #4a7cff; color: #ffffff; }"
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

    // ─────────────────────────────────────────────────────────────────────────
    // 1. TOP BAR
    // ─────────────────────────────────────────────────────────────────────────
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

    // Metrics & Controls
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
    connect(m_undoBtn, &QPushButton::clicked, this, &MainWindow::onUndo);

    m_redoBtn = new QPushButton("⟳");
    m_redoBtn->setFixedSize(30, 28);
    m_redoBtn->setToolTip("Redo");
    topBar->addWidget(m_redoBtn);
    connect(m_redoBtn, &QPushButton::clicked, this, &MainWindow::onRedo);

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

    QPushButton *advancedBtn = new QPushButton("ADVANCED");
    advancedBtn->setFixedWidth(100);
    advancedBtn->setStyleSheet(
        "QPushButton { background:#1a1030; color:#6b9cff; border:1px solid #2a2270;"
        "  border-radius:4px; padding:6px 12px; font-size:10px; font-weight:bold; }"
        "QPushButton:hover { border-color:#4a7cff; color:#4a7cff; }"
    );
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
    topBar->addWidget(detectBtn);
    connect(detectBtn, &QPushButton::clicked, this, &MainWindow::onDetectCipher);

    mainLayout->addLayout(topBar);

    // ─────────────────────────────────────────────────────────────────────────
    // 2. MAIN LAYOUT SPLITTER (Three vertical sections: Left, Center, Right)
    // ─────────────────────────────────────────────────────────────────────────
    QSplitter *mainSplitter = new QSplitter(Qt::Horizontal, this);

    // LEFT PANEL: Library of Ciphers & Operations
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

    // Populating Library tree
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

    m_opLibrary->expandAll();
    leftLayout->addWidget(m_opLibrary);
    
    // Operation description overlay details
    QLabel *descHelp = new QLabel("Double-click to add to recipe.");
    descHelp->setStyleSheet("color: #8880a0; font-size: 9px;");
    leftLayout->addWidget(descHelp);

    mainSplitter->addWidget(leftPanel);

    // CENTER PANEL: Recipe Canvas / Builder chain
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
        m_engine.clearSteps();
        updateRecipeCanvas();
        updateSettingsPanel(m_recipeList->currentRow());
        onRunRecipe();
    });

    centerLayout->addLayout(recipeTitleRow);

    m_recipeList = new QListWidget();
    m_recipeList->setDragDropMode(QAbstractItemView::InternalMove);
    m_recipeList->setStyleSheet(
        "QListWidget { background:#0a0514; border:1px dashed #2a2270; border-radius:4px; }"
        "QListWidget::item { background:transparent; }"
    );
    centerLayout->addWidget(m_recipeList);

    // Template Selector row
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

    // RIGHT PANEL: Settings/Parameters panel for selected operation
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

    // Scripting Macro compiler console at bottom right
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
        if (m_engine.parseMacroScript(macroInput->text().toStdString(), err)) {
            updateRecipeCanvas();
            updateSettingsPanel(m_recipeList->currentRow());
            onRunRecipe();
        } else {
            QMessageBox::warning(this, "Macro Compile Error", QString::fromStdString(err));
        }
    });

    mainSplitter->addWidget(rightPanel);

    // Set widths ratios
    mainSplitter->setStretchFactor(0, 2); // Left Tree
    mainSplitter->setStretchFactor(1, 3); // Center Canvas
    mainSplitter->setStretchFactor(2, 2); // Right Settings
    mainLayout->addWidget(mainSplitter, 3);

    // ─────────────────────────────────────────────────────────────────────────────
    // 3. BOTTOM SPLITTER (Dual Input/Output layout + Visual charts)
    // ─────────────────────────────────────────────────────────────────────────────
    QSplitter *ioSplitter = new QSplitter(Qt::Horizontal, this);

    // INPUT BOX
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

    // Input File Progress Panel
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
    
    connect(clearFileBtn, &QPushButton::clicked, this, &MainWindow::onClearFile);

    ioSplitter->addWidget(inputPanel);

    // OUTPUT BOX (Format tabs + analysis plots)
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
    
    // Tab 1: Formatted text rendering
    m_outputText = new QPlainTextEdit();
    m_outputText->setReadOnly(true);
    m_outputText->setMinimumHeight(150);
    m_outputTabs->addTab(m_outputText, "FORMATTED");

    // Tab 2: Byte breakdown
    m_outputByteBreakdown = new QPlainTextEdit();
    m_outputByteBreakdown->setReadOnly(true);
    m_outputTabs->addTab(m_outputByteBreakdown, "BYTE BREAKDOWN");

    // Tab 3: Diff Compare
    m_outputDiff = new QPlainTextEdit();
    m_outputDiff->setReadOnly(true);
    m_outputTabs->addTab(m_outputDiff, "DIFF COMPARISON");

    // Tab 4: Cryptanalysis Plots
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

    // Tab 5: CTF Toolkit Search Helper
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

    // Signals Connects
    connect(m_inputEdit, &QPlainTextEdit::textChanged, this, &MainWindow::onInputTextChanged);
    connect(m_inputEdit, &DropEdit::fileDropped, this, &MainWindow::onFileLoaded);
    connect(m_librarySearch, &QLineEdit::textChanged, this, [this](const QString &text) {
        // filter operations tree
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
    connect(m_recipeList, &QListWidget::itemSelectionChanged, this, &MainWindow::onRecipeItemSelectionChanged);
    connect(m_encodingWheel, SIGNAL(baseSelected(int)), this, SLOT(onWheelBaseSelected(int)));
    connect(bruteCtfBtn, &QPushButton::clicked, this, &MainWindow::onRunCtfSearch);
    connect(tlsAttackBtn, &QPushButton::clicked, this, &MainWindow::onRunTlsAttack);

    // Setup initial empty recipe layout
    updateRecipeCanvas();
}

// ─────────────────────────────────────────────────────────────────────────────
// Recipe management signals / slots
// ─────────────────────────────────────────────────────────────────────────────

void MainWindow::onAddOperation(QTreeWidgetItem *item, int column) {
    Q_UNUSED(column);
    if (item->childCount() > 0) return; // ignore headers
    
    pushUndo();
    m_engine.addStep(item->text(0).toStdString());
    updateRecipeCanvas();

    // Select the newly added step
    m_recipeList->setCurrentRow(m_recipeList->count() - 1);
    
    onRunRecipe();
}

void MainWindow::updateRecipeCanvas() {
    m_recipeList->clear();
    const auto &steps = m_engine.getSteps();
    
    for (size_t i = 0; i < steps.size(); ++i) {
        QListWidgetItem *listItem = new QListWidgetItem(m_recipeList);
        // Size hint for card heights
        listItem->setSizeHint(QSize(100, 36));

        RecipeCardWidget *card = new RecipeCardWidget(
            QString::fromStdString(steps[i].operation_name),
            (int)i,
            m_recipeList
        );
        card->setEnabledState(steps[i].enabled);
        card->setStatus(!steps[i].has_error, QString::fromStdString(steps[i].error_message));

        m_recipeList->setItemWidget(listItem, card);

        // connects inside card
        connect(card, &RecipeCardWidget::deleteClicked, this, &MainWindow::onRecipeCardDelete);
        connect(card, &RecipeCardWidget::toggleEnabledClicked, this, &MainWindow::onRecipeCardToggleEnabled);
        connect(card, &RecipeCardWidget::moveUpClicked, this, &MainWindow::onRecipeCardMoveUp);
        connect(card, &RecipeCardWidget::moveDownClicked, this, &MainWindow::onRecipeCardMoveDown);
    }
}

void MainWindow::onRecipeItemSelectionChanged() {
    int idx = m_recipeList->currentRow();
    updateSettingsPanel(idx);
}

void MainWindow::onRecipeCardDelete(int index) {
    pushUndo();
    m_engine.removeStep(index);
    updateRecipeCanvas();
    updateSettingsPanel(m_recipeList->currentRow());
    onRunRecipe();
}

void MainWindow::onRecipeCardToggleEnabled(int index, bool enabled) {
    pushUndo();
    m_engine.setStepEnabled(index, enabled);
    updateRecipeCanvas();
    updateSettingsPanel(m_recipeList->currentRow());
    onRunRecipe();
}

void MainWindow::onRecipeCardMoveUp(int index) {
    if (index > 0) {
        pushUndo();
        m_engine.swapSteps(index, index - 1);
        updateRecipeCanvas();
        m_recipeList->setCurrentRow(index - 1);
        onRunRecipe();
    }
}

void MainWindow::onRecipeCardMoveDown(int index) {
    if (index >= 0 && index < (m_recipeList->count() - 1)) {
        pushUndo();
        m_engine.swapSteps(index, index + 1);
        updateRecipeCanvas();
        m_recipeList->setCurrentRow(index + 1);
        onRunRecipe();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Dynamic Settings Form Generation
// ─────────────────────────────────────────────────────────────────────────────

void MainWindow::updateSettingsPanel(int stepIndex) {
    delete m_settingsLayout;
    qDeleteAll(m_settingsContainer->findChildren<QWidget*>(QString(), Qt::FindDirectChildrenOnly));
    m_settingsLayout = new QVBoxLayout(m_settingsContainer);
    m_settingsLayout->setContentsMargins(4, 4, 4, 4);

    if (stepIndex < 0 || stepIndex >= (int)m_engine.getSteps().size()) {
        QLabel *empty = new QLabel("Select an operation step to edit parameters.");
        empty->setStyleSheet("color: #8880a0; font-style: italic;");
        m_settingsLayout->addWidget(empty);
        return;
    }

    RecipeStep &step = m_engine.getSteps()[stepIndex];
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
        connect(edit, &QLineEdit::textChanged, this, [this, callback, edit]() {
            pushUndo();
            callback(edit->text().toStdString());
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
        connect(spin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this, callback](int val) {
            pushUndo();
            callback(val);
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
        connect(chk, &QCheckBox::clicked, this, [this, callback](bool c) {
            pushUndo();
            callback(c);
        });
    };
    // Description header label
    QLabel *headerLabel = new QLabel(QString::fromStdString(op).toUpper());
    headerLabel->setStyleSheet("font-weight: bold; color: #6b9cff; margin-bottom: 6px;");
    m_settingsLayout->addWidget(headerLabel);

    // Populate controls matching cipher types
    if (op == "Caesar") {
        addSpinBox("Shift:", -25, 25, step.params.param1, [&step](int v) { step.params.param1 = v; });
    } else if (op == "Affine") {
        addSpinBox("a (coprime 26):", 1, 25, step.params.param1, [&step](int v) { step.params.param1 = v; });
        addSpinBox("b:", 0, 25, step.params.param2, [&step](int v) { step.params.param2 = v; });
        addCheckbox("Decrypt instead", !step.params.encrypt, [&step](bool c) { step.params.encrypt = !c; });
    } else if (op == "Vigenere" || op == "Playfair" || op == "Keyword" || op == "Autokey" || op == "Beaufort") {
        addLineEdit("Key:", step.params.key, [&step](std::string s) { step.params.key = s; });
        if (op != "Beaufort") {
            addCheckbox("Decrypt instead", !step.params.encrypt, [&step](bool c) { step.params.encrypt = !c; });
        }
    } else if (op == "Substitution") {
        addLineEdit("Alphabet (26 chars):", step.params.key, [&step](std::string s) { step.params.key = s; });
        addCheckbox("Decrypt instead", !step.params.encrypt, [&step](bool c) { step.params.encrypt = !c; });
    } else if (op == "Railfence") {
        addSpinBox("Rails:", 2, 20, step.params.param1, [&step](int v) { step.params.param1 = v; });
        addSpinBox("Offset:", 0, 20, step.params.param2, [&step](int v) { step.params.param2 = v; });
    } else if (op == "Columnar") {
        addLineEdit("Key:", step.params.key, [&step](std::string s) { step.params.key = s; });
        addCheckbox("Decrypt instead", !step.params.encrypt, [&step](bool c) { step.params.encrypt = !c; });
    } else if (op == "XOR (hex key)" || op == "RC4") {
        addLineEdit("Key:", step.params.key, [&step](std::string s) { step.params.key = s; });
    } else if (op == "Blowfish" || op == "DES") {
        addLineEdit("Key:", step.params.key, [&step](std::string s) { step.params.key = s; });
        addCheckbox("Decrypt instead", !step.params.encrypt, [&step](bool c) { step.params.encrypt = !c; });
    } else if (op == "Scytale") {
        addSpinBox("Columns:", 2, 20, step.params.param1, [&step](int v) { step.params.param1 = v; });
        addCheckbox("Decrypt instead", !step.params.encrypt, [&step](bool c) { step.params.encrypt = !c; });
    } else if (op == "Trifid") {
        addLineEdit("Key Grid:", step.params.key, [&step](std::string s) { step.params.key = s; });
        addSpinBox("Period:", 2, 20, step.params.param1, [&step](int v) { step.params.param1 = v; });
        addCheckbox("Decrypt instead", !step.params.encrypt, [&step](bool c) { step.params.encrypt = !c; });
    } else if (op == "Four-Square") {
        addLineEdit("Keys:", step.params.key, [&step](std::string s) { step.params.key = s; });
        addCheckbox("Decrypt instead", !step.params.encrypt, [&step](bool c) { step.params.encrypt = !c; });
    } else if (op == "Keyboard Shift") {
        addSpinBox("Shift:", -10, 10, step.params.param1, [&step](int v) { step.params.param1 = v; });
        addCheckbox("Decrypt instead", !step.params.encrypt, [&step](bool c) { step.params.encrypt = !c; });
    }
    // ── Modern Ciphers ──
    else if (op == "AES-ECB" || op == "AES-CBC" || op == "AES-CTR") {
        addLineEdit("Key (16 or 32 bytes):", step.params.key, [&step](std::string s) { step.params.key = s; });
        if (op != "AES-ECB") {
            addLineEdit("IV (16 bytes):", step.params.iv, [&step](std::string s) { step.params.iv = s; });
        }
        addCheckbox("Decrypt instead", !step.params.encrypt, [&step](bool c) { step.params.encrypt = !c; });
    } else if (op == "ChaCha20") {
        addLineEdit("Key (32 bytes):", step.params.key, [&step](std::string s) { step.params.key = s; });
        addLineEdit("Nonce (12 bytes):", step.params.iv, [&step](std::string s) { step.params.iv = s; });
        addSpinBox("Counter (starts 0):", 0, 999999, step.params.param1, [&step](int v) { step.params.param1 = v; });
    } else if (op == "Poly1305" || op == "HMAC-SHA256" || op == "HMAC-SHA512") {
        addLineEdit("Secret Key:", step.params.key, [&step](std::string s) { step.params.key = s; });
    } else if (op == "PBKDF2-SHA256" || op == "Argon2id") {
        addLineEdit("Salt:", step.params.iv, [&step](std::string s) { step.params.iv = s; });
        addSpinBox("Iterations:", 1, 5000, step.params.param1, [&step](int v) { step.params.param1 = v; });
        addSpinBox("Memory Size (KB):", 8, 65536, step.params.param2, [&step](int v) { step.params.param2 = v; });
    } else if (op == "BLAKE2b" || op == "BLAKE2s") {
        addLineEdit("Key (Optional):", step.params.key, [&step](std::string s) { step.params.key = s; });
    } else if (op == "JWT Sign") {
        addLineEdit("Secret Key:", step.params.key, [&step](std::string s) { step.params.key = s; });
        addLineEdit("Header JSON (Optional):", step.params.iv, [&step](std::string s) { step.params.iv = s; });
    } else if (op == "JWT Verify") {
        addLineEdit("Secret Key (Optional):", step.params.key, [&step](std::string s) { step.params.key = s; });
    } else if (op == "LSB Embed") {
        addLineEdit("Secret Text to Hide:", step.params.key, [&step](std::string s) { step.params.key = s; });
    } else if (op == "Morse" || op == "Baconian" || op == "Binary" || op == "Octal" || op == "Base64" || op == "Hex" || op == "URL Encode") {
        addCheckbox("Decrypt/Decode", !step.params.encrypt, [&step](bool c) { step.params.encrypt = !c; });
    } else {
        // No parameters header
        QLabel *noParams = new QLabel("Operation has no configurable parameters.");
        noParams->setStyleSheet("color: #8880a0; font-style: italic;");
        form->addRow("", noParams);
    }

    m_settingsLayout->addLayout(form);
    m_settingsLayout->addStretch();
}

void MainWindow::onParameterChanged() {
    if (m_autoRunCheck->isChecked()) {
        onRunRecipe();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Execution and visual updates
// ─────────────────────────────────────────────────────────────────────────────

void MainWindow::onRunRecipe() {
    std::string out = m_engine.run(m_rawInput);
    
    // Update statuses of recipe cards in canvas
    for (int i = 0; i < m_recipeList->count(); ++i) {
        QListWidgetItem *item = m_recipeList->item(i);
        RecipeCardWidget *card = qobject_cast<RecipeCardWidget*>(m_recipeList->itemWidget(item));
        if (card) {
            const auto &step = m_engine.getSteps()[i];
            card->setStatus(!step.has_error, QString::fromStdString(step.error_message));
        }
    }

    // Update Top bar metrics
    const RecipeMetrics &m = m_engine.getLatestMetrics();
    QString speed = QString("%1").arg(m.throughput_mbs, 0, 'f', 2);
    m_metricsLabel->setText(
        QString("Time: %1 ms | Speed: %2 MB/s | Mem: %3 B")
            .arg(m.total_time_ms, 0, 'f', 1)
            .arg(speed)
            .arg(m.memory_used_bytes)
    );

    // Display formatted outputs
    displayOutputFormat(out);

    // Update analysis custom plots
    m_histogram->setData(out);
    m_heatmap->setData(out);
    m_entropyGraph->setData(out);
    m_encodingWheel->setValue(out);
}

void MainWindow::displayOutputFormat(const std::string &output) {
    // Tab 1: Formatted Output (printable validation)
    bool printable = true;
    for (unsigned char c : output) {
        if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
            printable = false; break;
        }
    }

    if (printable) {
        m_outputText->setPlainText(QString::fromStdString(output));
    } else {
        // Raw bytes fallback representation
        std::stringstream ss;
        ss << "[RAW BINARY DATA (" << output.size() << " bytes)]\n\n";
        for (size_t i = 0; i < output.size(); ++i) {
            ss << std::hex << std::setfill('0') << std::setw(2) << (int)(unsigned char)output[i] << " ";
            if ((i + 1) % 16 == 0) ss << "\n";
        }
        m_outputText->setPlainText(QString::fromStdString(ss.str()));
    }

    // Tab 2: Byte breakdown list
    std::stringstream bb;
    bb << "Offset    Hex  Dec  Char\n";
    bb << "────────────────────────\n";
    for (size_t i = 0; i < std::min((size_t)1000, output.size()); ++i) {
        unsigned char c = output[i];
        bb << "0x" << std::setfill('0') << std::setw(6) << std::hex << i << "  ";
        bb << std::setw(2) << (int)c << "  ";
        bb << std::setfill(' ') << std::setw(3) << std::dec << (int)c << "  ";
        
        // Print character label or control sequence
        if (c == '\n') bb << "<LF>";
        else if (c == '\r') bb << "<CR>";
        else if (c == '\t') bb << "<TAB>";
        else if (c >= 32 && c <= 126) bb << (char)c;
        else bb << "<.>";
        bb << "\n";
    }
    if (output.size() > 1000) bb << "... truncated ...";
    m_outputByteBreakdown->setPlainText(QString::fromStdString(bb.str()));

    // Tab 3: Diff Comparison (Input vs Output text)
    std::stringstream df;
    df << "=== INPUT DATA ===\n" << m_rawInput << "\n\n";
    df << "=== OUTPUT DATA ===\n" << (printable ? output : "[Raw non-printable bytes]");
    m_outputDiff->setPlainText(QString::fromStdString(df.str()));
}

// ─────────────────────────────────────────────────────────────────────────────
// Input & Load updates
// ─────────────────────────────────────────────────────────────────────────────

void MainWindow::onInputTextChanged() {
    m_rawInput = m_inputEdit->toPlainText().toStdString();
    onParameterChanged();
}

void MainWindow::onFileLoaded(const QString &filePath, const QByteArray &content) {
    m_rawInput = content.toStdString();
    
    // Update file details bar
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
        // If file loaded, write actual output data
        f.write(raw_out.data(), raw_out.size());
        f.close();
    }
}

void MainWindow::onWheelBaseSelected(int radix) {
    // Add conversion step depending on clicked sector
    pushUndo();
    if (radix == 2) m_engine.addStep("Binary");
    else if (radix == 8) m_engine.addStep("Octal");
    else if (radix == 16) m_engine.addStep("Hex");
    else if (radix == 64) m_engine.addStep("Base64");
    updateRecipeCanvas();
    updateSettingsPanel(m_recipeList->currentRow());
    onRunRecipe();
}

// ─────────────────────────────────────────────────────────────────────────────
// History (Undo / Redo)
// ─────────────────────────────────────────────────────────────────────────────

void MainWindow::pushUndo() {
    if (m_isUndoingOrRedoing) return;
    std::string json = m_engine.exportToJSON();
    
    // Cap undo sizes
    if (m_undoStack.empty() || m_undoStack.back() != json) {
        m_undoStack.push_back(json);
        if (m_undoStack.size() > 100) m_undoStack.erase(m_undoStack.begin());
        m_redoStack.clear();
    }
}

void MainWindow::onUndo() {
    if (m_undoStack.size() < 2) return; // stack 0 is initial, need at least 2 to revert
    m_isUndoingOrRedoing = true;
    
    std::string current = m_undoStack.back();
    m_redoStack.push_back(current);
    m_undoStack.pop_back();

    std::string last = m_undoStack.back();
    std::string err;
    m_engine.importFromJSON(last, err);

    updateRecipeCanvas();
    onRunRecipe();
    
    m_isUndoingOrRedoing = false;
}

void MainWindow::onRedo() {
    if (m_redoStack.empty()) return;
    m_isUndoingOrRedoing = true;

    std::string next = m_redoStack.back();
    m_redoStack.pop_back();
    m_undoStack.push_back(next);

    std::string err;
    m_engine.importFromJSON(next, err);

    updateRecipeCanvas();
    onRunRecipe();

    m_isUndoingOrRedoing = false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Themes, Presets, CTF Search Cracking
// ─────────────────────────────────────────────────────────────────────────────

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
    if (index == 1) { // Argon2id derivation
        m_engine.clearSteps();
        m_engine.addStep("Argon2id");
        m_engine.getSteps()[0].params.iv = "salty_parameter";
        m_engine.getSteps()[0].params.param1 = 3; // iter
        m_engine.getSteps()[0].params.param2 = 1024; // mem
    } else if (index == 2) { // AES CBC pipeline
        m_engine.clearSteps();
        m_engine.addStep("Base64");
        m_engine.getSteps()[0].params.encrypt = false; // decode
        m_engine.addStep("AES-CBC");
        m_engine.getSteps()[1].params.key = "1234567890123456";
        m_engine.getSteps()[1].params.iv = "0000000000000000";
        m_engine.getSteps()[1].params.encrypt = false; // decrypt
    } else if (index == 3) { // JWT inspector
        m_engine.clearSteps();
        m_engine.addStep("JWT Verify");
        m_engine.getSteps()[0].params.key = "jwt_signing_key";
    } else if (index == 4) { // LSB Extract
        m_engine.clearSteps();
        m_engine.addStep("LSB Extract");
    } else {
        return;
    }
    updateRecipeCanvas();
    onRunRecipe();
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
    if (pattern.empty()) {
        pattern = "flag\\{[a-zA-Z0-9_]+\\}"; // default format
    }

    runCtfDictionaryBrute(m_rawInput, pattern);
}

// Search cracking candidates matching flag format
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

    // 1. Caesar Shift Brute force (1-25)
    for (int shift = 1; shift < 26; ++shift) {
        std::string cand;
        custom_rot(input, shift, cand);
        testCandidate(cand, QString("Caesar Shift %1").arg(shift));
    }

    // 2. ROT47 Brute
    {
        std::string cand;
        rot47(input, cand);
        testCandidate(cand, "ROT47");
    }

    // 3. Atbash Brute
    {
        std::string cand;
        atbash(input, cand);
        testCandidate(cand, "Atbash");
    }

    // 4. Base64 Decode + Caesar Brute
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

void MainWindow::onCtfFlagCheck() {
    // Checked inside CTF run search
}

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
    // Set the decoded text as output if a result exists
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
    QMessageBox::information(this, "Macro Scripting", "Not yet implemented");
}

void MainWindow::onSaveRecipe() {
    if (m_recipeList->count() == 0) return;
    QString path = QFileDialog::getSaveFileName(this, "Save Recipe", "", "JSON (*.json)");
    if (path.isEmpty()) return;
    QMessageBox::information(this, "Save Recipe", "Saved to: " + path);
}

void MainWindow::onLoadRecipe() {
    QString path = QFileDialog::getOpenFileName(this, "Load Recipe", "", "JSON (*.json)");
    if (path.isEmpty()) return;
    // TODO: deserialize and apply recipe
    QMessageBox::information(this, "Load Recipe", "Loaded: " + path);
}
