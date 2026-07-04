#include "menuwindow.h"
#include "mainwindow.h"
#include "basewindow.h"
#include "numberwindow.h"
#include "passivewindow.h"
#include "solve_window.h"
#include "settings_dialog.h"
#include "includes.h"
#include "theme_manager.h"
#include "colours.h"
#include <QSettings>

MenuWindow::MenuWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle("Obscuron Cryptographic Suite");
    setMinimumSize(640, 560);
    resize(640, 560);

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
    ThemeMode mode = static_cast<ThemeMode>(themeIdx);

    QColor titleColor, subColor, btnTextColor;
    if (mode == THEME_LIGHT) {
        titleColor = QColor(0, 130, 100);
        subColor   = QColor(100, 80, 180);
        btnTextColor = QColor(80, 80, 80);
    } else if (mode == THEME_OLED) {
        titleColor = QColor(0, 180, 140);
        subColor   = QColor(60, 40, 140);
        btnTextColor = QColor(150, 140, 170);
    } else {
        titleColor = COL_ACCENT_GL;
        subColor   = COL_BORDER_HI;
        btnTextColor = COL_TEXT_DIM;
    }

    QWidget *central = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(central);
    layout->setContentsMargins(60, 50, 60, 50);
    layout->setSpacing(0);

    QLabel *title = new QLabel("OBSCURON");
    title->setAlignment(Qt::AlignHCenter);
    QFont titleFont("Courier New", 36, QFont::Bold);
    titleFont.setLetterSpacing(QFont::AbsoluteSpacing, 10);
    title->setFont(titleFont);
    title->setStyleSheet(QString("color: %1;").arg(titleColor.name()));
    title->setAutoFillBackground(false);

    QLabel *sub = new QLabel("cryptographic suite");
    sub->setAlignment(Qt::AlignHCenter);
    QFont subFont("Courier New", 12);
    subFont.setLetterSpacing(QFont::AbsoluteSpacing, 6);
    sub->setFont(subFont);
    sub->setStyleSheet(QString("color: %1;").arg(subColor.name()));
    sub->setAutoFillBackground(false);

    auto makeBtn = [&](const QString &text) -> QPushButton* {
        QPushButton *b = new QPushButton(text);
        b->setFixedWidth(320);
        b->setFixedHeight(46);
        b->setCursor(Qt::PointingHandCursor);
        QFont btnFont("Courier New", 13);
        btnFont.setLetterSpacing(QFont::AbsoluteSpacing, 3);
        b->setFont(btnFont);
        b->setStyleSheet(QString(
            "QPushButton { background: transparent; color: %1; border: 1px solid %2;"
            "  border-radius: 6px; font-weight: bold; }"
            "QPushButton:hover { border-color: %3; color: %3; }"
        ).arg(btnTextColor.name()).arg(btnTextColor.name()).arg(accent.name()));
        return b;
    };

    btnCipher   = makeBtn("CIPHER SUITE");
    btnBase     = makeBtn("BASE MODE");
    btnNumber   = makeBtn("NUMBER MODE");
    btnPassive  = makeBtn("PASSIVE MODE");
    btnSolve    = makeBtn("SOLVE CRYPTO");
    btnSettings = makeBtn("SETTINGS");

    QLabel *ver = new QLabel("\nv2.0  |  Obscuron");
    ver->setAlignment(Qt::AlignHCenter);
    QFont verFont("Courier New", 10);
    verFont.setLetterSpacing(QFont::AbsoluteSpacing, 3);
    ver->setFont(verFont);
    ver->setStyleSheet(QString("color: %1;").arg(btnTextColor.name()));
    ver->setAutoFillBackground(false);

    layout->addStretch(2);
    layout->addWidget(title);
    layout->addWidget(sub);
    layout->addSpacing(24);
    layout->addWidget(btnCipher,   0, Qt::AlignHCenter);
    layout->addSpacing(8);
    layout->addWidget(btnBase,     0, Qt::AlignHCenter);
    layout->addSpacing(8);
    layout->addWidget(btnNumber,   0, Qt::AlignHCenter);
    layout->addSpacing(8);
    layout->addWidget(btnPassive,  0, Qt::AlignHCenter);
    layout->addSpacing(8);
    layout->addWidget(btnSolve,    0, Qt::AlignHCenter);
    layout->addSpacing(8);
    layout->addWidget(btnSettings, 0, Qt::AlignHCenter);
    layout->addStretch(1);
    layout->addWidget(ver);

    setCentralWidget(central);

    connect(btnCipher, &QPushButton::clicked, this, &MenuWindow::onCipherClicked);
    connect(btnBase, &QPushButton::clicked, this, &MenuWindow::onBaseClicked);
    connect(btnNumber, &QPushButton::clicked, this, &MenuWindow::onNumberClicked);
    connect(btnPassive, &QPushButton::clicked, this, &MenuWindow::onPassiveClicked);
    connect(btnSolve, &QPushButton::clicked, this, &MenuWindow::onSolveClicked);
    connect(btnSettings, &QPushButton::clicked, this, [this]{
        SettingsDialog dlg(this);
        dlg.exec();
    });
}

void MenuWindow::onCipherClicked() {
    MainWindow *w = new MainWindow();
    w->setAttribute(Qt::WA_DeleteOnClose);
    w->show();
    this->close();
}

void MenuWindow::onBaseClicked() {
    BaseWindow *w = new BaseWindow();
    w->setAttribute(Qt::WA_DeleteOnClose);
    w->show();
    this->close();
}

void MenuWindow::onNumberClicked() {
    NumberWindow *w = new NumberWindow();
    w->setAttribute(Qt::WA_DeleteOnClose);
    w->show();
    this->close();
}

void MenuWindow::onPassiveClicked() {
    PassiveWindow *w = new PassiveWindow();
    w->setAttribute(Qt::WA_DeleteOnClose);
    w->show();
    this->close();
}

void MenuWindow::onSolveClicked() {
    SolveWindow *w = new SolveWindow();
    w->setAttribute(Qt::WA_DeleteOnClose);
    w->show();
    this->close();
}
