#include "settings_dialog.h"
#include "theme_manager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QSettings>
#include <QApplication>
#include <QDialogButtonBox>
#include <QFrame>
#include <QFont>

SettingsDialog::SettingsDialog(QWidget *parent) : QDialog(parent) {
    setWindowTitle("Settings");
    setMinimumSize(520, 400);
    resize(560, 440);
    setupUI();
    loadSettings();
}

void SettingsDialog::setupUI() {
    ThemePalette sPal = ThemeManager::getPaletteFromSettings();
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(12);

    m_tabs = new QTabWidget(this);

    // ── Theme Tab ──
    QWidget *themeTab = new QWidget();
    QVBoxLayout *themeLayout = new QVBoxLayout(themeTab);
    themeLayout->setSpacing(10);

    QGroupBox *themeGrp = new QGroupBox("Theme Mode");
    QVBoxLayout *thL = new QVBoxLayout(themeGrp);
    m_themeCombo = new QComboBox();
    m_themeCombo->addItem("Dark");
    m_themeCombo->addItem("Light");
    m_themeCombo->addItem("OLED Black");
    thL->addWidget(m_themeCombo);
    themeLayout->addWidget(themeGrp);

    QGroupBox *accentGrp = new QGroupBox("Accent Color");
    QVBoxLayout *acL = new QVBoxLayout(accentGrp);

    m_accentEnabled = new QCheckBox("Custom accent color");
    acL->addWidget(m_accentEnabled);

    QHBoxLayout *rgbRow = new QHBoxLayout();
    m_accentR = new QSlider(Qt::Horizontal); m_accentR->setRange(0, 255);
    m_accentG = new QSlider(Qt::Horizontal); m_accentG->setRange(0, 255);
    m_accentB = new QSlider(Qt::Horizontal); m_accentB->setRange(0, 255);
    rgbRow->addWidget(new QLabel("R"));
    rgbRow->addWidget(m_accentR);
    rgbRow->addWidget(new QLabel("G"));
    rgbRow->addWidget(m_accentG);
    rgbRow->addWidget(new QLabel("B"));
    rgbRow->addWidget(m_accentB);
    acL->addLayout(rgbRow);

    m_accentPreview = new QLabel("  ██████████  ");
    m_accentPreview->setFixedHeight(28);
    m_accentPreview->setAlignment(Qt::AlignCenter);
    m_accentPreview->setStyleSheet("border: 1px solid #555; border-radius: 4px; font-weight: bold;");
    acL->addWidget(m_accentPreview);

    connect(m_accentR, &QSlider::valueChanged, this, &SettingsDialog::onAccentSliderChanged);
    connect(m_accentG, &QSlider::valueChanged, this, &SettingsDialog::onAccentSliderChanged);
    connect(m_accentB, &QSlider::valueChanged, this, &SettingsDialog::onAccentSliderChanged);

    themeLayout->addWidget(accentGrp);
    themeLayout->addStretch();

    m_applyThemeBtn = new QPushButton("Apply Theme");
    connect(m_applyThemeBtn, &QPushButton::clicked, this, &SettingsDialog::onApply);
    themeLayout->addWidget(m_applyThemeBtn);

    m_tabs->addTab(themeTab, "Theme");

    // ── Font Tab ──
    QWidget *fontTab = new QWidget();
    QVBoxLayout *fontLayout = new QVBoxLayout(fontTab);
    fontLayout->setSpacing(10);

    QGroupBox *fontGrp = new QGroupBox("Font Settings");
    QFormLayout *fL = new QFormLayout(fontGrp);

    m_fontFamily = new QFontComboBox();
    fL->addRow("Family:", m_fontFamily);

    m_fontSize = new QSpinBox();
    m_fontSize->setRange(8, 48);
    m_fontSize->setValue(12);
    fL->addRow("Size:", m_fontSize);

    m_fontBold = new QCheckBox("Bold");
    fL->addRow("", m_fontBold);

    fontLayout->addWidget(fontGrp);
    fontLayout->addStretch();
    m_tabs->addTab(fontTab, "Font");

    // ── Display Tab ──
    QWidget *displayTab = new QWidget();
    QVBoxLayout *dispLayout = new QVBoxLayout(displayTab);
    dispLayout->setSpacing(10);

    QGroupBox *dispGrp = new QGroupBox("Display Preferences");
    QVBoxLayout *dL = new QVBoxLayout(dispGrp);

    m_showHexAddr = new QCheckBox("Show hex addresses in byte breakdown");
    m_showHexAddr->setChecked(true);
    dL->addWidget(m_showHexAddr);

    m_autoRunDefault = new QCheckBox("Auto-run by default");
    m_autoRunDefault->setChecked(true);
    dL->addWidget(m_autoRunDefault);

    QHBoxLayout *maxRow = new QHBoxLayout();
    maxRow->addWidget(new QLabel("Max output lines:"));
    m_maxOutputLines = new QSpinBox();
    m_maxOutputLines->setRange(100, 100000);
    m_maxOutputLines->setValue(5000);
    m_maxOutputLines->setSingleStep(100);
    maxRow->addWidget(m_maxOutputLines);
    maxRow->addStretch();
    dL->addLayout(maxRow);

    dispLayout->addWidget(dispGrp);
    dispLayout->addStretch();
    m_tabs->addTab(displayTab, "Display");

    // ── Performance Tab ──
    QWidget *perfTab = new QWidget();
    QVBoxLayout *perfLayout = new QVBoxLayout(perfTab);
    perfLayout->setSpacing(10);

    QGroupBox *perfGrp = new QGroupBox("Pipeline Execution");
    QVBoxLayout *pL = new QVBoxLayout(perfGrp);

    m_multiThread = new QCheckBox("Enable multi-threaded pipeline execution");
    m_multiThread->setToolTip("Runs recipe operations in a background thread to keep the UI responsive");
    pL->addWidget(m_multiThread);

    m_aggressiveDetect = new QCheckBox("Aggressive detection chaining");
    m_aggressiveDetect->setToolTip("When enabled, the detector brute-forces keys and alphabets for common ciphers "
                                    "instead of just identifying the cipher type.");
    pL->addWidget(m_aggressiveDetect);

    QLabel *perfNote = new QLabel(
        "When enabled, long-running operations will not freeze the interface.\n"
        "Controls are temporarily disabled during execution."
    );
    perfNote->setWordWrap(true);
    perfNote->setStyleSheet("color: " + sPal.textDim.name() + "; font-size: 10px; padding: 4px;");
    pL->addWidget(perfNote);

    perfLayout->addWidget(perfGrp);
    perfLayout->addStretch();
    m_tabs->addTab(perfTab, "Performance");

    // ── About Tab ──
    QWidget *aboutTab = new QWidget();
    QVBoxLayout *aboutLayout = new QVBoxLayout(aboutTab);
    aboutLayout->setSpacing(8);

    QLabel *title = new QLabel("Obscuron Crypto Suite");
    QFont tf("Courier New", 16, QFont::Bold);
    title->setFont(tf);
    title->setAlignment(Qt::AlignCenter);
    aboutLayout->addWidget(title);

    QLabel *version = new QLabel("Version 2.0");
    version->setAlignment(Qt::AlignCenter);
    aboutLayout->addWidget(version);

    aboutLayout->addSpacing(12);

    QLabel *desc = new QLabel(
        "A comprehensive cryptographic analysis workspace\n"
        "with support for classical, modern, and attack-oriented cryptography.\n\n"
        "Features:\n"
        "  • 100+ cipher implementations\n"
        "  • Recipe-style multi-step pipelines\n"
        "  • CTF attack toolkit\n"
        "  • Visual cryptanalysis tools\n\n"
        "Built with Qt and NTL."
    );
    desc->setWordWrap(true);
    desc->setAlignment(Qt::AlignLeft);
    aboutLayout->addWidget(desc);

    aboutLayout->addStretch();
    m_tabs->addTab(aboutTab, "About");

    mainLayout->addWidget(m_tabs);

    // Button row
    QDialogButtonBox *btnBox = new QDialogButtonBox();
    QPushButton *closeBtn = new QPushButton("Close");
    closeBtn->setDefault(true);
    btnBox->addButton(closeBtn, QDialogButtonBox::AcceptRole);
    mainLayout->addWidget(btnBox);
    connect(closeBtn, &QPushButton::clicked, this, &SettingsDialog::onClose);
}

void SettingsDialog::onAccentSliderChanged() {
    QColor c(m_accentR->value(), m_accentG->value(), m_accentB->value());
    m_accentPreview->setStyleSheet(
        QString("background: %1; color: %2; border: 1px solid #555; border-radius: 4px; font-weight: bold;")
        .arg(c.name(), (c.lightness() > 128 ? "#000" : "#fff"))
    );
}

void SettingsDialog::loadSettings() {
    QSettings s("Obscuron", "CryptoSuite");

    int themeIdx = s.value("theme/index", 0).toInt();
    m_themeCombo->setCurrentIndex(themeIdx);

    bool accentOn = s.value("accent/enabled", false).toBool();
    m_accentEnabled->setChecked(accentOn);

    int ar = s.value("accent/r", 74).toInt();
    int ag = s.value("accent/g", 124).toInt();
    int ab = s.value("accent/b", 255).toInt();
    m_accentR->setValue(ar);
    m_accentG->setValue(ag);
    m_accentB->setValue(ab);

    m_fontFamily->setCurrentFont(QFont(s.value("font/family", "Courier New").toString()));
    m_fontSize->setValue(s.value("font/size", 12).toInt());
    m_fontBold->setChecked(s.value("font/bold", false).toBool());

    m_showHexAddr->setChecked(s.value("display/showHexAddr", true).toBool());
    m_autoRunDefault->setChecked(s.value("display/autoRun", true).toBool());
    m_maxOutputLines->setValue(s.value("display/maxLines", 5000).toInt());

    m_multiThread->setChecked(s.value("performance/multiThread", false).toBool());
    m_aggressiveDetect->setChecked(s.value("detection/aggressive", false).toBool());

    onAccentSliderChanged();
}

void SettingsDialog::saveSettings() {
    QSettings s("Obscuron", "CryptoSuite");

    s.setValue("theme/index", m_themeCombo->currentIndex());

    s.setValue("accent/enabled", m_accentEnabled->isChecked());
    s.setValue("accent/r", m_accentR->value());
    s.setValue("accent/g", m_accentG->value());
    s.setValue("accent/b", m_accentB->value());

    s.setValue("font/family", m_fontFamily->currentFont().family());
    s.setValue("font/size", m_fontSize->value());
    s.setValue("font/bold", m_fontBold->isChecked());

    s.setValue("display/showHexAddr", m_showHexAddr->isChecked());
    s.setValue("display/autoRun", m_autoRunDefault->isChecked());
    s.setValue("display/maxLines", m_maxOutputLines->value());

    s.setValue("performance/multiThread", m_multiThread->isChecked());
    s.setValue("detection/aggressive", m_aggressiveDetect->isChecked());

    s.sync();
}

void SettingsDialog::onApply() {
    saveSettings();
    apply();
}

void SettingsDialog::apply() {
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
    ThemeMode mode = THEME_DARK;
    if (themeIdx == 1) mode = THEME_LIGHT;
    else if (themeIdx == 2) mode = THEME_OLED;
    ThemeManager::applyTheme(mode, accent);

    QFont font(s.value("font/family", "Courier New").toString(),
               s.value("font/size", 12).toInt());
    font.setBold(s.value("font/bold", false).toBool());
    qApp->setFont(font);
}

void SettingsDialog::onClose() {
    saveSettings();
    apply();
    accept();
}
