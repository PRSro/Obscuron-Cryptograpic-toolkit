#ifndef BASEWINDOW_H
#define BASEWINDOW_H

#include <QMainWindow>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QPushButton>
#include <QLabel>

class BaseWindow : public QMainWindow {
    Q_OBJECT
public:
    BaseWindow(QWidget *parent = nullptr);
    ~BaseWindow() = default;

private:
    QPlainTextEdit *inputArea;
    QPlainTextEdit *outputArea;
    QComboBox *operationCombo;
    QSpinBox *baseSpin;
    QLineEdit *alphabetInput;
    QPushButton *runBtn;
    QPushButton *backBtn;

    void setupUI();

private slots:
    void onRun();
};

#endif
