#ifndef SCRIPT_CONSOLE_DIALOG_H
#define SCRIPT_CONSOLE_DIALOG_H

#include <QDialog>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QSplitter>

class ScriptEngine;

class ScriptConsoleDialog : public QDialog {
    Q_OBJECT
public:
    explicit ScriptConsoleDialog(const QString &currentInput, QWidget *parent = nullptr);
    QString result() const { return m_result; }

private slots:
    void onRun();
    void onInsertExample();

private:
    void setupUI();

    QPlainTextEdit *m_editor;
    QPlainTextEdit *m_output;
    QPushButton *m_runBtn;
    QPushButton *m_exampleBtn;
    QLabel *m_statusLabel;
    ScriptEngine *m_engine;
    QString m_currentInput;
    QString m_result;
};

#endif
