#include "plugin_browser_dialog.h"
#include "colours.h"
#include "theme_manager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QMessageBox>
#include <QGroupBox>
#include <QFileInfo>
#include <QSettings>

PluginBrowserDialog::PluginBrowserDialog(PluginLoader *loader, QWidget *parent)
    : QDialog(parent), m_loader(loader)
{
    setWindowTitle("Plugin Manager");
    setFixedSize(520, 400);
    ThemePalette sp = ThemeManager::getPaletteFromSettings();
    setStyleSheet(
        "QDialog { background: " + sp.bg.name() + "; }"
        "QLabel { color: " + sp.text.name() + "; font-family: 'Courier New', monospace; }"
        "QPushButton { background: " + sp.surf2.name() + "; color: " + sp.text.name() + "; border: 1px solid " + sp.surf2.name() + ";"
        "  border-radius: 4px; padding: 6px 16px; font-family: 'Courier New', monospace; }"
        "QPushButton:hover { border-color: " + sp.accent.name() + "; }"
        "QListWidget { background: " + sp.surf.name() + "; color: " + sp.text.name() + "; border: 1px solid " + sp.border.name() + ";"
        "  border-radius: 4px; font-family: 'Courier New', monospace; }"
        "QListWidget::item { padding: 6px; }"
        "QListWidget::item:selected { background: " + sp.accent.name() + "; }"
    );

    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(8);

    QLabel *title = new QLabel("PLUGIN MANAGER");
    title->setStyleSheet("font-weight: bold; color: " + sp.accent.name() + "; font-size: 14px;");
    mainLayout->addWidget(title);

    QLabel *subtitle = new QLabel("Load external cipher modules (.so, .py, .js files)");
    subtitle->setStyleSheet("color: " + sp.textDim.name() + "; font-size: 10px;");
    mainLayout->addWidget(subtitle);

    // Plugin list
    m_pluginList = new QListWidget();
    m_pluginList->setMinimumHeight(200);
    mainLayout->addWidget(m_pluginList);
    connect(m_pluginList, &QListWidget::itemSelectionChanged, this, &PluginBrowserDialog::onPluginSelected);

    // Info label
    m_infoLabel = new QLabel("Select a plugin to see details");
    m_infoLabel->setStyleSheet("color: " + sp.textDim.name() + "; font-size: 10px; padding: 4px;");
    m_infoLabel->setWordWrap(true);
    mainLayout->addWidget(m_infoLabel);

    // Buttons
    QHBoxLayout *btnRow = new QHBoxLayout();
    m_loadBtn = new QPushButton("LOAD PLUGIN");
    m_loadBtn->setObjectName("runButton");
    btnRow->addWidget(m_loadBtn);
    connect(m_loadBtn, &QPushButton::clicked, this, &PluginBrowserDialog::onLoadPlugin);

    m_unloadBtn = new QPushButton("UNLOAD");
    m_unloadBtn->setEnabled(false);
    m_unloadBtn->setObjectName("cancelButton");
    btnRow->addWidget(m_unloadBtn);
    connect(m_unloadBtn, &QPushButton::clicked, this, &PluginBrowserDialog::onUnloadPlugin);

    btnRow->addStretch();

    QPushButton *closeBtn = new QPushButton("CLOSE");
    closeBtn->setObjectName("cancelButton");
    btnRow->addWidget(closeBtn);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);

    mainLayout->addLayout(btnRow);

    // Plugin directory hint
    QLabel *hint = new QLabel("Plugins directory: ~/.obscuron/plugins/");
    hint->setStyleSheet("color: " + sp.textDim.darker(150).name() + "; font-size: 9px;");
    mainLayout->addWidget(hint);

    refreshList();
}

void PluginBrowserDialog::onLoadPlugin() {
    QString path = QFileDialog::getOpenFileName(this, "Load Plugin", "",
        "All Plugins (*.so *.py *.js);;Shared Libraries (*.so);;Python (*.py);;JavaScript (*.js);;All Files (*)");
    if (path.isEmpty()) return;

    bool ok = false;
    if (path.endsWith(".py", Qt::CaseInsensitive))
        ok = m_loader->loadPythonPlugin(path.toStdString());
    else if (path.endsWith(".js", Qt::CaseInsensitive))
        ok = m_loader->loadJSPlugin(path.toStdString());
    else
        ok = m_loader->loadPlugin(path.toStdString());

    if (ok) {
        refreshList();
        emit pluginsChanged();
    }
}

void PluginBrowserDialog::onUnloadPlugin() {
    auto *item = m_pluginList->currentItem();
    if (!item) return;
    std::string name = item->text().toStdString();
    // Extract name before " — " separator
    size_t sep = name.find(" — ");
    if (sep != std::string::npos) name = name.substr(0, sep);
    m_loader->unloadPlugin(name);
    refreshList();
    emit pluginsChanged();
}

void PluginBrowserDialog::onPluginSelected() {
    auto *item = m_pluginList->currentItem();
    if (!item) {
        m_infoLabel->setText("Select a plugin to see details");
        m_unloadBtn->setEnabled(false);
        return;
    }
    m_unloadBtn->setEnabled(true);

    // Find the plugin
    std::string itemText = item->text().toStdString();
    for (const auto &lp : m_loader->plugins()) {
        std::string langTag;
        if (lp->lang == PluginLang_Python) langTag = " [Python]";
        else if (lp->lang == PluginLang_JS) langTag = " [JavaScript]";
        else langTag = " [C/.so]";
        std::string label = lp->pluginName + " — v" + lp->pluginVersion + langTag
            + " (" + std::to_string(lp->operationNames.size()) + " ops)";
        if (label == itemText) {
            QString info;
            info += "Name: " + QString::fromStdString(lp->pluginName) + "\n";
            info += "Author: " + QString::fromStdString(lp->pluginAuthor.empty() ? "Unknown" : lp->pluginAuthor) + "\n";
            info += "Version: " + QString::fromStdString(lp->pluginVersion.empty() ? "?" : lp->pluginVersion) + "\n";
            info += "Description: " + QString::fromStdString(lp->pluginDescription) + "\n";
            QString langName = (lp->lang == PluginLang_Python) ? "Python" : (lp->lang == PluginLang_JS) ? "JavaScript" : "C/.so";
            info += "Language: " + langName + "\n";
            info += "Operations: " + QString::number(lp->operationNames.size()) + "\n";
            info += "Path: " + QString::fromStdString(lp->filepath);
            m_infoLabel->setText(info);
            return;
        }
    }
}

void PluginBrowserDialog::refreshList() {
    m_pluginList->clear();
    for (const auto &lp : m_loader->plugins()) {
        QString langTag;
        if (lp->lang == PluginLang_Python) langTag = " [Python]";
        else if (lp->lang == PluginLang_JS) langTag = " [JavaScript]";
        else langTag = " [C/.so]";
        QString label = QString::fromStdString(lp->pluginName)
            + " — v" + QString::fromStdString(lp->pluginVersion.empty() ? "?" : lp->pluginVersion)
            + langTag
            + " (" + QString::number(lp->operationNames.size()) + " ops)";
        m_pluginList->addItem(label);
    }
    onPluginSelected();
}
