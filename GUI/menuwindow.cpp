#include "menuwindow.h"
#include "mainwindow.h"
#include "basewindow.h"
#include "numberwindow.h"
#include "passivewindow.h"
#include "settings_dialog.h"
#include "includes.h"
#include "colours.h"

MenuWindow::MenuWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle("Obscuron Cryptographic Suite");
    setFixedSize(640, 480);

    QPalette winPal = palette();
    winPal.setColor(QPalette::Window,     COL_BG);
    winPal.setColor(QPalette::WindowText, COL_TEXT);
    winPal.setColor(QPalette::Base,       COL_SURFACE);
    winPal.setColor(QPalette::Text,       COL_TEXT);
    setPalette(winPal);
    setAutoFillBackground(true);

    QWidget *central = new QWidget(this);
    central->setAutoFillBackground(true);
    central->setPalette(winPal);
    QVBoxLayout *layout = new QVBoxLayout(central);
    layout->setContentsMargins(60, 50, 60, 50);
    layout->setSpacing(0);

    QLabel *title = new QLabel("OBSCURON");
    title->setAlignment(Qt::AlignHCenter);
    QFont titleFont("Courier New", 36, QFont::Bold);
    titleFont.setLetterSpacing(QFont::AbsoluteSpacing, 10);
    title->setFont(titleFont);
    QPalette titlePal = title->palette();
    titlePal.setColor(QPalette::WindowText, COL_ACCENT_GL);
    title->setPalette(titlePal);
    title->setAutoFillBackground(false);

    QLabel *sub = new QLabel("cryptographic suite");
    sub->setAlignment(Qt::AlignHCenter);
    QFont subFont("Courier New", 12);
    subFont.setLetterSpacing(QFont::AbsoluteSpacing, 6);
    sub->setFont(subFont);
    QPalette subPal = sub->palette();
    subPal.setColor(QPalette::WindowText, COL_BORDER_HI);
    sub->setPalette(subPal);
    sub->setAutoFillBackground(false);

    auto makeBtn = [&](const QString &text) -> QPushButton* {
        QPushButton *b = new QPushButton(text);
        b->setFixedWidth(320);
        b->setFixedHeight(46);
        b->setCursor(Qt::PointingHandCursor);
        b->setAutoFillBackground(true);
        b->setFlat(false);
        QFont btnFont("Courier New", 13);
        btnFont.setLetterSpacing(QFont::AbsoluteSpacing, 3);
        b->setFont(btnFont);
        QPalette btnPal = b->palette();
        btnPal.setColor(QPalette::Button,     COL_SURFACE);
        btnPal.setColor(QPalette::ButtonText, COL_TEXT_DIM);
        btnPal.setColor(QPalette::Window,     COL_SURFACE);
        b->setPalette(btnPal);
        return b;
    };

    btnCipher   = makeBtn("CIPHER SUITE");
    btnBase     = makeBtn("BASE MODE");
    btnNumber   = makeBtn("NUMBER MODE");
    btnPassive  = makeBtn("PASSIVE MODE");
    btnSettings = makeBtn("SETTINGS");

    QLabel *ver = new QLabel("v1.0  |  Obscuron");
    ver->setAlignment(Qt::AlignHCenter);
    QFont verFont("Courier New", 10);
    verFont.setLetterSpacing(QFont::AbsoluteSpacing, 3);
    ver->setFont(verFont);
    QPalette verPal = ver->palette();
    verPal.setColor(QPalette::WindowText, COL_BORDER);
    ver->setPalette(verPal);
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
    layout->addWidget(btnSettings, 0, Qt::AlignHCenter);
    layout->addStretch(1);
    layout->addWidget(ver);

    setCentralWidget(central);

    connect(btnCipher, &QPushButton::clicked, this, &MenuWindow::onCipherClicked);
    connect(btnBase, &QPushButton::clicked, this, &MenuWindow::onBaseClicked);
    connect(btnNumber, &QPushButton::clicked, this, &MenuWindow::onNumberClicked);
    connect(btnPassive, &QPushButton::clicked, this, &MenuWindow::onPassiveClicked);
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
