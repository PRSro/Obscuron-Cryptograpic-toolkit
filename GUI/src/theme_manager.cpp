#include "theme_manager.h"
#include <QApplication>
#include <QPalette>
#include <QPointer>
#include <QSettings>
#include <QTimer>
#include <QWidget>

void ThemeManager::applyTheme(ThemeMode mode, const QColor &accent) {
    QPointer<QWidget> focused = QApplication::focusWidget();

    QString stylesheet = getStyleSheet(mode, accent);
    qApp->setStyleSheet(stylesheet);

    // Apply color palette variables if needed
    QPalette pal = qApp->palette();
    if (mode == THEME_LIGHT) {
        pal.setColor(QPalette::Window, QColor(245, 245, 247));
        pal.setColor(QPalette::WindowText, QColor(30, 30, 30));
        pal.setColor(QPalette::Base, QColor(255, 255, 255));
        pal.setColor(QPalette::Text, QColor(30, 30, 30));
        pal.setColor(QPalette::Button, QColor(235, 235, 240));
        pal.setColor(QPalette::ButtonText, QColor(30, 30, 30));
    } else {
        QColor bg = (mode == THEME_OLED) ? QColor(0, 0, 0) : QColor(10, 5, 20);
        QColor surf = (mode == THEME_OLED) ? QColor(10, 10, 10) : QColor(18, 10, 32);
        pal.setColor(QPalette::Window, bg);
        pal.setColor(QPalette::WindowText, QColor(224, 224, 240));
        pal.setColor(QPalette::Base, surf);
        pal.setColor(QPalette::Text, QColor(224, 224, 240));
        pal.setColor(QPalette::Button, surf);
        pal.setColor(QPalette::ButtonText, QColor(224, 224, 240));
    }
    qApp->setPalette(pal);

    if (focused) {
        QTimer::singleShot(0, [focused]() {
            if (focused) focused->setFocus();
        });
    }
}

QString ThemeManager::getStyleSheet(ThemeMode mode, const QColor &accent) {
    QString hexAccent = accent.name();
    QString hexGlow = accent.lighter(130).name();

    QString bg, surf, surf2, border, text, text_dim, scrollBg, scrollHandle;
    QString successColor, successGlow, dangerColor, dangerGlow;

    if (mode == THEME_LIGHT) {
        bg = "#f5f5f7";
        surf = "#ffffff";
        surf2 = "#f0f0f5";
        border = "#d2d2d7";
        text = "#1d1d1f";
        text_dim = "#86868b";
        scrollBg = "#f5f5f7";
        scrollHandle = "#c1c1c7";
        successColor = "#008844"; successGlow = QColor(successColor).lighter(130).name();
        dangerColor = "#cc3333"; dangerGlow = QColor(dangerColor).lighter(130).name();
    } else if (mode == THEME_OLED) {
        bg = "#000000";
        surf = "#0c0c0c";
        surf2 = "#141414";
        border = "#1a1a1a";
        text = "#e8e6f0";
        text_dim = "#7a7898";
        scrollBg = "#080808";
        scrollHandle = "#2c2c2c";
        successColor = "#00cc88"; successGlow = QColor(successColor).lighter(130).name();
        dangerColor = "#ff6b6b"; dangerGlow = QColor(dangerColor).lighter(130).name();
    } else { // THEME_DARK - violet-blue-green palette
        bg = "#0a0514";
        surf = "#120a20";
        surf2 = "#1a1030";
        border = "#1e1850";
        text = "#e0e0f0";
        text_dim = "#8880a0";
        scrollBg = "#0a0514";
        scrollHandle = "#1e1850";
        successColor = "#00cc88"; successGlow = QColor(successColor).lighter(130).name();
        dangerColor = "#ff6b6b"; dangerGlow = QColor(dangerColor).lighter(130).name();
    }

    return QString(
        "QMainWindow, QDialog { background: %1; }"
        "QWidget { color: %5; font-family: 'Courier New', monospace; }"
        "QCheckBox { color: %5; spacing: 6px; }"
        "QCheckBox::indicator { width: 16px; height: 16px; background: %2; border: 1px solid %4; border-radius: 3px; }"
        "QCheckBox::indicator:checked { background: %6; }"
        "QTreeWidget { background: %2; color: %5; border: 1px solid %4; border-radius: 6px; }"
        "QTreeWidget::item { padding: 4px; border-radius: 4px; }"
        "QTreeWidget::item:selected { background: %3; }"
        "QHeaderView::section { background: %3; color: %5; border: 1px solid %4; padding: 4px; }"
        "QTextBrowser { background: %2; color: %5; border: 1px solid %4; border-radius: 6px; padding: 8px; font-family: 'Courier New', monospace; font-size: 12px; }"
        "QPlainTextEdit, QLineEdit { background: %2; color: %5; border: 1px solid %4; "
        "  border-radius: 6px; padding: 8px; font-family: 'Courier New', monospace; font-size: 12px; }"
        "QPlainTextEdit:focus, QLineEdit:focus { border: 1px solid %6; }"
        "QComboBox { background: %2; color: %5; border: 1px solid %4; "
        "  border-radius: 6px; padding: 4px 12px; min-height: 28px; font-family: 'Courier New', monospace; }"
        "QComboBox:hover { border: 1px solid %6; }"
        "QComboBox:focus { border: 1px solid %6; }"
        "QComboBox::drop-down { border: none; width: 24px; }"
        "QComboBox QAbstractItemView { background: %2; color: %5; "
        "  selection-background-color: %6; border: 1px solid %4; }"
        "QSpinBox { background: %2; color: %5; border: 1px solid %4; "
        "  border-radius: 6px; padding: 4px; min-height: 26px; }"
        "QSpinBox:focus { border: 1px solid %6; }"
        "QPushButton { background: %3; color: %5; border: 1px solid %4; "
        "  border-radius: 6px; padding: 8px 18px; font-family: 'Courier New', monospace; font-weight: bold; }"
        "QPushButton:hover { border: 1px solid %6; color: %7; background: %2; }"
        "QPushButton:pressed { background: %6; color: #ffffff; }"
        "QPushButton#runButton { background: %10; color: #ffffff; border: 1px solid %10; font-weight: bold; }"
        "QPushButton#runButton:hover { background: %11; }"
        "QPushButton#cancelButton { background: %12; color: #ffffff; border: 1px solid %12; font-weight: bold; }"
        "QPushButton#cancelButton:hover { background: %13; }"
        "QPushButton#accentButton { border-color: %6; color: %6; }"
        "QPushButton#accentButton:hover { background: %6; color: #ffffff; }"
        "QListWidget { background: %2; color: %5; border: 1px solid %4; "
        "  border-radius: 6px; font-family: 'Courier New', monospace; font-size: 12px; padding: 4px; }"
        "QListWidget::item { padding: 6px; border-radius: 4px; }"
        "QListWidget::item:hover { background: %3; }"
        "QListWidget::item:selected { background: %6; color: #ffffff; }"
        "QLabel { color: %5; font-family: 'Courier New', monospace; }"
        "QGroupBox { border: 1px solid %4; border-radius: 8px; margin-top: 14px; "
        "  padding-top: 16px; font-family: 'Courier New', monospace; font-weight: bold; color: %7; }"
        "QGroupBox::title { subcontrol-origin: margin; left: 14px; padding: 0 6px; }"
        "QTabWidget::pane { border: 1px solid %4; background: %2; border-radius: 6px; top: -1px; }"
        "QTabBar::tab { background: %3; border: 1px solid %4; border-bottom: none; "
        "  border-top-left-radius: 6px; border-top-right-radius: 6px; padding: 8px 16px; margin-right: 2px; }"
        "QTabBar::tab:selected { background: %2; border-bottom: 1px solid %2; color: %7; font-weight: bold; }"
        "QTabBar::tab:hover { background: %2; }"
        "QScrollBar:vertical { background: %8; width: 10px; margin: 0px; }"
        "QScrollBar::handle:vertical { background: %9; min-height: 20px; border-radius: 5px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }"
        "QScrollBar:horizontal { background: %8; height: 10px; margin: 0px; }"
        "QScrollBar::handle:horizontal { background: %9; min-width: 20px; border-radius: 5px; }"
        "QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; }"
        "QSplitter::handle { background: %4; }"
    )
    .arg(bg)
    .arg(surf)
    .arg(surf2)
    .arg(border)
    .arg(text)
    .arg(hexAccent)
    .arg(hexGlow)
    .arg(scrollBg)
    .arg(scrollHandle)
    .arg(successColor)
    .arg(successGlow)
    .arg(dangerColor)
    .arg(dangerGlow)
    ;
}

ThemePalette ThemeManager::getPaletteFromSettings() {
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
    return getPalette(static_cast<ThemeMode>(themeIdx), accent);
}

ThemePalette ThemeManager::getPalette(ThemeMode mode, const QColor &accent) {
    ThemePalette p;
    p.accent = accent;
    if (mode == THEME_LIGHT) {
        p.bg = QColor("#f5f5f7"); p.surf = QColor("#ffffff"); p.surf2 = QColor("#f0f0f5");
        p.border = QColor("#d2d2d7"); p.text = QColor("#1d1d1f"); p.textDim = QColor("#86868b");
        p.success = QColor("#008844"); p.danger = QColor("#cc3333");
    } else if (mode == THEME_OLED) {
        p.bg = QColor("#000000"); p.surf = QColor("#0c0c0c"); p.surf2 = QColor("#141414");
        p.border = QColor("#1a1a1a"); p.text = QColor("#e8e6f0"); p.textDim = QColor("#7a7898");
        p.success = QColor("#00cc88"); p.danger = QColor("#ff6b6b");
    } else {
        p.bg = QColor("#0a0514"); p.surf = QColor("#120a20"); p.surf2 = QColor("#1a1030");
        p.border = QColor("#1e1850"); p.text = QColor("#e0e0f0"); p.textDim = QColor("#8880a0");
        p.success = QColor("#00cc88"); p.danger = QColor("#ff6b6b");
    }
    return p;
}
