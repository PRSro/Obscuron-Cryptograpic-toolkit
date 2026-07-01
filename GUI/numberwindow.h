#ifndef NUMBERWINDOW_H
#define NUMBERWINDOW_H

#include <QMainWindow>
#include <QPlainTextEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QTabWidget>

class NumberWindow : public QMainWindow {
    Q_OBJECT
public:
    NumberWindow(QWidget *parent = nullptr);
    ~NumberWindow() = default;

private:
    QTabWidget *tabWidget;

    // Convert tab
    QPlainTextEdit *inputArea;
    QPlainTextEdit *outputArea;
    QComboBox *operationCombo;
    QComboBox *typeCombo;
    QSpinBox *baseSpin;
    QLabel *baseLabel;
    QPushButton *runBtn;
    QPushButton *backBtn;
    QPushButton *advancedBtn;
    QPlainTextEdit *detectOutput;
    QPushButton *detectBtn;
    QPushButton *attackBtn;

    // Auto Attack tab
    QLineEdit *attackN;
    QLineEdit *attackE;
    QLineEdit *attackC;
    QPlainTextEdit *attackOutput;
    QPushButton *attackRunBtn;

    void setupUI();
    QWidget* createConvertTab();
    QWidget* createAttackTab();
    void runAttackChain(const std::string &n_hex, const std::string &e_hex,
                        const std::string &c_hex, std::ostringstream &oss);

private slots:
    void onRun();
    void onTypeChanged(int index);
    void onAdvanced();
    void onDetect();
    void onAttack();
    void onAutoAttack();
};

#endif
