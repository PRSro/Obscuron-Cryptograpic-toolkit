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
    QPushButton *btnBase;
    QPushButton *btnNumber;
    QPushButton *btnPassive;
    QPushButton *btnSettings;

private slots:
    void onCipherClicked();
    void onBaseClicked();
    void onNumberClicked();
    void onPassiveClicked();
};

#endif
