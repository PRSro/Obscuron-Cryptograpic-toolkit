#ifndef ADVANCED_CRYPT_DIALOG_H
#define ADVANCED_CRYPT_DIALOG_H

#include <QDialog>
#include <QPlainTextEdit>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QListWidget>

class AdvancedCryptDialog : public QDialog {
    Q_OBJECT
public:
    AdvancedCryptDialog(QWidget *parent = nullptr);

private:
    QPlainTextEdit *m_input;
    QPlainTextEdit *m_output;
    QComboBox *m_operation;
    QPushButton *m_runBtn;
    QListWidget *m_candidates;

    void setupUI();

private slots:
    void onRun();
};

#endif
