#ifndef ADVANCED_NUMBER_DIALOG_H
#define ADVANCED_NUMBER_DIALOG_H

#include <QDialog>
#include <QPlainTextEdit>
#include <QComboBox>
#include <QLineEdit>
#include <QSpinBox>
#include <QPushButton>
#include <QLabel>

class AdvancedNumberDialog : public QDialog {
    Q_OBJECT
public:
    AdvancedNumberDialog(QWidget *parent = nullptr);

private:
    QPlainTextEdit *m_input;
    QPlainTextEdit *m_output;
    QComboBox *m_operation;
    QLineEdit *m_key;
    QLineEdit *m_iv;
    QSpinBox *m_counter;
    QComboBox *m_mode;
    QLabel *m_keyLabel;
    QLabel *m_ivLabel;
    QLabel *m_counterLabel;
    QLabel *m_modeLabel;
    QPushButton *m_runBtn;

    void setupUI();
    void updateParams();
    QString runOp(const std::string &input, const std::string &op,
                  const std::string &key, const std::string &iv,
                  int counter, int mode);

private slots:
    void onRun();
    void onOpChanged(int idx);
};

#endif
