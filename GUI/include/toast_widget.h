#ifndef TOAST_WIDGET_H
#define TOAST_WIDGET_H

#include <QFrame>
#include <QLabel>
#include <QTimer>
#include <QPropertyAnimation>
#include <QList>
#include <QPointer>

class ToastWidget : public QFrame {
    Q_OBJECT
    Q_PROPERTY(qreal opacity READ windowOpacity WRITE setWindowOpacity)
public:
    enum Type { Info, Success, Warning, Error };

    static void show(QWidget *parent, const QString &message,
                     Type type = Info, int durationMs = 3000);

private:
    ToastWidget(QWidget *parent, const QString &message, Type type, int durationMs);
    void slideIn();
    void dismiss();

    static QList<QPointer<ToastWidget>> s_activeToasts;
    static void repositionAll();

    QLabel *m_label;
    QTimer *m_dismissTimer;
    QPropertyAnimation *m_opacityAnim;
};

#endif // TOAST_WIDGET_H
