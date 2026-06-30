#include "command_palette.h"
#include <QKeyEvent>
#include <QVBoxLayout>
#include <QPropertyAnimation>
#include <QEasingCurve>
#include <QAbstractAnimation>
#include <QGraphicsDropShadowEffect>
#include <QScrollBar>
#include <QShortcut>
#include <algorithm>

CommandPalette::CommandPalette(QWidget *parent)
    : QWidget(parent)
{
    setWindowFlags(Qt::Tool | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint);
    setAttribute(Qt::WA_ShowWithoutActivating);
    setAttribute(Qt::WA_DeleteOnClose);
    setFixedSize(480, 360);

    QGraphicsDropShadowEffect *shadow = new QGraphicsDropShadowEffect(this);
    shadow->setBlurRadius(30);
    shadow->setOffset(0, 8);
    shadow->setColor(QColor(0, 0, 0, 160));
    setGraphicsEffect(shadow);

    setStyleSheet(
        "CommandPalette { background: #120a20; border: 1px solid #2a2270; border-radius: 10px; }"
        "QLineEdit { background: #0a0514; color: #e0e0f0; border: 1px solid #4a7cff;"
        "  border-radius: 6px; padding: 10px 14px; font-family: 'Courier New', monospace;"
        "  font-size: 14px; min-height: 20px; }"
        "QListWidget { background: transparent; color: #e0e0f0; border: none;"
        "  font-family: 'Courier New', monospace; font-size: 12px; padding: 4px; }"
        "QListWidget::item { padding: 8px 12px; border-radius: 4px; }"
        "QListWidget::item:hover { background: #1a1030; }"
        "QListWidget::item:selected { background: #4a7cff; color: #ffffff; }"
        "QScrollBar:vertical { background: #0a0514; width: 6px; margin: 0px; }"
        "QScrollBar::handle:vertical { background: #1e1850; min-height: 20px; border-radius: 3px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }"
    );

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(12, 12, 12, 12);
    layout->setSpacing(8);

    m_search = new QLineEdit();
    m_search->setPlaceholderText("Search operations...");
    layout->addWidget(m_search);

    m_results = new QListWidget();
    layout->addWidget(m_results);

    m_allOperations = {
        "Caesar", "ROT13", "ROT47", "Atbash", "Vigenere", "Playfair", "Affine",
        "Railfence", "Columnar", "Morse", "Baconian", "Keyword", "Substitution",
        "A1Z26", "Keyboard Shift", "Beaufort", "Autokey", "Scytale",
        "Polybius Square", "Bifid", "Trifid", "Four-Square",
        "AES-ECB", "AES-CBC", "AES-CTR", "ChaCha20", "Poly1305",
        "HMAC-SHA256", "HMAC-SHA512",
        "MD5", "SHA-1", "SHA-256", "SHA-512", "BLAKE2b", "BLAKE2s",
        "PBKDF2-SHA256", "Argon2id",
        "Base64", "Hex", "Binary", "Octal", "URL Encode",
        "JWT Sign", "JWT Verify", "QR Code", "LSB Embed", "LSB Extract", "Leetspeak"
    };

    for (const QString &op : m_allOperations) {
        m_results->addItem(op);
    }

    connect(m_search, &QLineEdit::textChanged, this, &CommandPalette::filterResults);
    connect(m_results, &QListWidget::itemClicked, this, [this](QListWidgetItem *item) {
        emit operationSelected(item->text());
        close();
    });
    connect(m_results, &QListWidget::itemDoubleClicked, this, [this](QListWidgetItem *item) {
        emit operationSelected(item->text());
        close();
    });
}

void CommandPalette::filterResults(const QString &text) {
    m_results->clear();
    if (text.isEmpty()) {
        for (const QString &op : m_allOperations)
            m_results->addItem(op);
        return;
    }
    QList<QPair<int, QString>> scored;
    for (const QString &op : m_allOperations) {
        int score = fuzzyScore(text, op);
        if (score > 0)
            scored.append({score, op});
    }
    std::sort(scored.begin(), scored.end(),
        [](const QPair<int, QString> &a, const QPair<int, QString> &b) {
            return a.first > b.first;
        });
    for (const auto &pair : scored)
        m_results->addItem(pair.second);
}

void CommandPalette::selectCurrent() {
    QListWidgetItem *item = m_results->currentItem();
    if (item) {
        emit operationSelected(item->text());
        close();
    }
}

int CommandPalette::fuzzyScore(const QString &pattern, const QString &text) {
    int pIdx = 0, score = 0, lastMatch = -1;
    for (const QChar &ch : pattern) {
        QChar lower = ch.toLower();
        int pos = -1;
        for (int i = lastMatch + 1; i < text.size(); ++i) {
            if (text[i].toLower() == lower) { pos = i; break; }
        }
        if (pos < 0) return 0;
        if (pos == lastMatch + 1) score += 10;
        else if (pos == pIdx) score += 5;
        else score += 1;
        lastMatch = pos;
        pIdx++;
    }
    if (pattern.length() > 0 && text.startsWith(pattern, Qt::CaseInsensitive))
        score += 50;
    return score;
}

void CommandPalette::showPalette() {
    if (parentWidget()) {
        QPoint center = parentWidget()->mapToGlobal(parentWidget()->rect().center());
        move(center.x() - width() / 2, center.y() - height() / 2);
    }
    setWindowOpacity(0.0);
    QWidget::show();
    raise();
    m_search->clear();
    m_search->setFocus();
    filterResults("");
    // Fade in
    auto *anim = new QPropertyAnimation(this, "windowOpacity", this);
    anim->setDuration(150);
    anim->setStartValue(0.0);
    anim->setEndValue(1.0);
    anim->setEasingCurve(QEasingCurve::OutCubic);
    anim->start(QAbstractAnimation::DeleteWhenStopped);
}

void CommandPalette::keyPressEvent(QKeyEvent *event) {
    if (event->key() == Qt::Key_Down) {
        int row = m_results->currentRow();
        if (row < m_results->count() - 1)
            m_results->setCurrentRow(row + 1);
    } else if (event->key() == Qt::Key_Up) {
        int row = m_results->currentRow();
        if (row > 0)
            m_results->setCurrentRow(row - 1);
    } else if (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter) {
        selectCurrent();
    } else if (event->key() == Qt::Key_Escape) {
        close();
    } else {
        QWidget::keyPressEvent(event);
    }
}
