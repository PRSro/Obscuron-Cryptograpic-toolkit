#ifndef RSA_ATTACK_DIALOG_H
#define RSA_ATTACK_DIALOG_H

#include <QDialog>
#include <QPlainTextEdit>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>

class RsaAttackDialog : public QDialog {
    Q_OBJECT
public:
    explicit RsaAttackDialog(QWidget *parent = nullptr);

private:
    QPlainTextEdit *m_input;
    QPlainTextEdit *m_output;
    QComboBox *m_operation;
    QLineEdit *m_param1;
    QLineEdit *m_param2;
    QLineEdit *m_param3;
    QLineEdit *m_param4;
    QLineEdit *m_param5;
    QLabel *m_lbl1;
    QLabel *m_lbl2;
    QLabel *m_lbl3;
    QLabel *m_lbl4;
    QLabel *m_lbl5;
    QPushButton *m_runBtn;

    void setupUI();
    void updateParams();

private slots:
    void onRun();
    void onOpChanged(int idx);
};

#endif
