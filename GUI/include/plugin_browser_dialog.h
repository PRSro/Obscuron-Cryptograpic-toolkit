#ifndef PLUGIN_BROWSER_DIALOG_H
#define PLUGIN_BROWSER_DIALOG_H

#include <QDialog>
#include <QListWidget>
#include <QLabel>
#include <QPushButton>
#include "plugin_loader.h"

class PluginBrowserDialog : public QDialog {
    Q_OBJECT
public:
    explicit PluginBrowserDialog(PluginLoader *loader, QWidget *parent = nullptr);

signals:
    void pluginsChanged();

private slots:
    void onLoadPlugin();
    void onUnloadPlugin();
    void onPluginSelected();
    void refreshList();

private:
    PluginLoader *m_loader;
    QListWidget *m_pluginList;
    QLabel *m_infoLabel;
    QPushButton *m_loadBtn;
    QPushButton *m_unloadBtn;
};

#endif
