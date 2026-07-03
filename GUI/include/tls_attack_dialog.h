#ifndef TLS_ATTACK_DIALOG_H
#define TLS_ATTACK_DIALOG_H

#include <QDialog>
#include <QPlainTextEdit>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QTabWidget>
#include <QListWidget>
#include <QTreeWidget>
#include <QCheckBox>
#include "theme_manager.h"

class TlsAttackDialog : public QDialog {
    Q_OBJECT
public:
    explicit TlsAttackDialog(QWidget *parent = nullptr);

signals:
    void rsaParamsExtracted(const QString &modulus_hex, const QString &exponent_hex);

private:
    QTabWidget *m_tabs;

    // Tab 1: Fingerprint
    QPlainTextEdit *m_fpInput;
    QCheckBox *m_fpAuto;
    QPushButton *m_fpAnalyse;
    QPlainTextEdit *m_fpOutput;
    QListWidget *m_fpIssues;

    // Tab 2: Session Decrypt
    QPlainTextEdit *m_sdInput;
    QLineEdit *m_sdKey;
    QComboBox *m_sdVersion;
    QComboBox *m_sdCipher;
    QPushButton *m_sdDecrypt;
    QPlainTextEdit *m_sdOutput;

    // Tab 3: Certificate Parser
    QPlainTextEdit *m_certInput;
    QPushButton *m_certParse;
    QTreeWidget *m_certTree;
    QPushButton *m_certExtractRsa;
    QPushButton *m_certCheckExpiry;

    ThemePalette m_tlsPal;
    void setupFingerprintTab(QWidget *tab);
    void setupSessionDecryptTab(QWidget *tab);
    void setupCertParserTab(QWidget *tab);

private slots:
    void onAnalyse();
    void onDecrypt();
    void onParseCert();
    void onExtractRsa();
    void onCheckExpiry();
};

#endif
