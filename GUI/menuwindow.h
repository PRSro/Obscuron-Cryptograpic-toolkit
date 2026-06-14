#ifndef MENUWINDOW_H
#define MENUWINDOW_H

#include <QMainWindow>
#include <QPushButton>

class MenuWindow : public QMainWindow {
    Q_OBJECT
public:
    MenuWindow(QWidget *parent = nullptr);

private:
    QPushButton *btnCipher;
    QPushButton *btnNumber;
    QPushButton *btnSettings;

private slots:
    void onCipherClicked();
    void onNumberClicked();
};

#endif
