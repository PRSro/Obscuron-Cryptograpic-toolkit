#ifndef COMMAND_PALETTE_H
#define COMMAND_PALETTE_H

#include <QWidget>
#include <QLineEdit>
#include <QListWidget>
#include <QStringList>

class CommandPalette : public QWidget {
    Q_OBJECT
public:
    explicit CommandPalette(QWidget *parent = nullptr);
    void showPalette();

signals:
    void operationSelected(const QString &name);

protected:
    void keyPressEvent(QKeyEvent *event) override;

private:
    QLineEdit *m_search;
    QListWidget *m_results;
    QStringList m_allOperations;
    void filterResults(const QString &text);
    void selectCurrent();
    static int fuzzyScore(const QString &pattern, const QString &text);
};

#endif
