#ifndef SOLVE_CTF_PANEL_H
#define SOLVE_CTF_PANEL_H

#include <QWidget>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLineEdit>
#include <QListWidget>

class SolveCtfPanel : public QWidget {
    Q_OBJECT
public:
    explicit SolveCtfPanel(QWidget *parent = nullptr);

    void loadFile(const QString &path);
    QString currentContent() const;
    void addResult(const QString &text);

signals:
    void runCliCommand(const QString &command);

private slots:
    void onOpenFile();
    void onSearchFlag();
    void onQuickDecode(const QString &operation);

private:
    void setupUI();
    QPushButton *makeBtn(const QString &text);

    QPlainTextEdit *m_preview;
    QLineEdit *m_flag_regex;
    QPlainTextEdit *m_results;
    QListWidget *m_flag_results;
    QString m_current_file;
};

#endif
