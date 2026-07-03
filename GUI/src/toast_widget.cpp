#include "toast_widget.h"
#include <QVBoxLayout>
#include <QGraphicsDropShadowEffect>
#include <QApplication>
#include <algorithm>

QList<QPointer<ToastWidget>> ToastWidget::s_activeToasts;

void ToastWidget::show(QWidget *parent, const QString &message, Type type, int durationMs) {
    auto *toast = new ToastWidget(parent, message, type, durationMs);
    toast->raise();
    toast->QWidget::show();
    toast->slideIn();
}

ToastWidget::ToastWidget(QWidget *parent, const QString &message, Type type, int durationMs)
    : QFrame(parent)
{
    setWindowFlags(Qt::Tool | Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TransparentForMouseEvents, false);
    setAttribute(Qt::WA_DeleteOnClose);
    setFixedWidth(360);
    setMinimumHeight(44);

    QGraphicsDropShadowEffect *shadow = new QGraphicsDropShadowEffect(this);
    shadow->setBlurRadius(20);
    shadow->setOffset(0, 4);
    setGraphicsEffect(shadow);

    QColor bg, accent;
    QString icon;
    switch (type) {
        case Success:
            bg = QColor(0, 40, 30);
            accent = QColor(0, 204, 136);
            icon = "●";
            break;
        case Warning:
            bg = QColor(45, 35, 10);
            accent = QColor(255, 180, 0);
            icon = "▲";
            break;
        case Error:
            bg = QColor(45, 10, 15);
            accent = QColor(255, 80, 80);
            icon = "✕";
            break;
        default: // Info
            bg = QColor(15, 20, 45);
            accent = QColor(74, 124, 255);
            icon = "●";
            break;
    }

    setStyleSheet(QString(
        "ToastWidget { background: %1; border: 1px solid %2; border-radius: 8px; }"
        "QLabel { color: #e0e0f0; font-family: 'Courier New', monospace; font-size: 11px; padding: 6px; }"
    ).arg(bg.name()).arg(accent.name()));

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(12, 8, 12, 8);

    m_label = new QLabel(icon + "  " + message);
    m_label->setWordWrap(true);
    layout->addWidget(m_label);

    adjustSize();

    // Position at top-right of parent
    QPoint parentTopRight = parent->mapToGlobal(QPoint(parent->width(), 0));
    s_activeToasts.erase(
        std::remove_if(s_activeToasts.begin(), s_activeToasts.end(),
            [](const QPointer<ToastWidget> &p) { return p.isNull(); }),
        s_activeToasts.end()
    );
    int yOffset = 10;
    for (ToastWidget *t : s_activeToasts) {
        yOffset += t->height() + 8;
    }
    move(parentTopRight.x() - width() - 12, yOffset);
    setWindowOpacity(0.0);

    s_activeToasts.append(this);

    m_dismissTimer = new QTimer(this);
    m_dismissTimer->setSingleShot(true);
    connect(m_dismissTimer, &QTimer::timeout, this, &ToastWidget::dismiss);
    m_dismissTimer->start(durationMs);
}

void ToastWidget::slideIn() {
    m_opacityAnim = new QPropertyAnimation(this, "opacity", this);
    m_opacityAnim->setDuration(250);
    m_opacityAnim->setStartValue(0.0);
    m_opacityAnim->setEndValue(1.0);
    m_opacityAnim->setEasingCurve(QEasingCurve::OutCubic);
    m_opacityAnim->start(QAbstractAnimation::DeleteWhenStopped);
}

void ToastWidget::dismiss() {
    m_opacityAnim = new QPropertyAnimation(this, "opacity", this);
    m_opacityAnim->setDuration(200);
    m_opacityAnim->setStartValue(1.0);
    m_opacityAnim->setEndValue(0.0);
    m_opacityAnim->setEasingCurve(QEasingCurve::InCubic);
    connect(m_opacityAnim, &QPropertyAnimation::finished, this, [this]() {
        s_activeToasts.removeOne(this);
        repositionAll();
        close();
    });
    m_opacityAnim->start(QAbstractAnimation::DeleteWhenStopped);
}

void ToastWidget::repositionAll() {
    s_activeToasts.erase(
        std::remove_if(s_activeToasts.begin(), s_activeToasts.end(),
            [](const QPointer<ToastWidget> &p) { return p.isNull(); }),
        s_activeToasts.end()
    );
    int yOffset = 10;
    for (ToastWidget *t : s_activeToasts) {
        QPoint parentTopRight = t->parentWidget()
            ? t->parentWidget()->mapToGlobal(QPoint(t->parentWidget()->width(), 0))
            : QPoint(0, 0);
        t->move(parentTopRight.x() - t->width() - 12, yOffset);
        yOffset += t->height() + 8;
    }
}
