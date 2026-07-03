#include <QApplication>
#include <QSettings>
#include "menuwindow.h"
#include "theme_manager.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    {
        QSettings s("Obscuron", "CryptoSuite");
        int themeIdx = s.value("theme/index", 0).toInt();
        bool accentOn = s.value("accent/enabled", false).toBool();
        QColor accent(74, 124, 255);
        if (accentOn) {
            accent = QColor(
                s.value("accent/r", 74).toInt(),
                s.value("accent/g", 124).toInt(),
                s.value("accent/b", 255).toInt()
            );
        }
        ThemeMode mode = static_cast<ThemeMode>(themeIdx);
        ThemeManager::applyTheme(mode, accent);
    }
    MenuWindow w;
    w.show();
    return app.exec();
}
