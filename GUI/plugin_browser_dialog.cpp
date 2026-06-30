#include "plugin_browser_dialog.h"
#include "colours.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QMessageBox>
#include <QGroupBox>
#include <QFileInfo>

PluginBrowserDialog::PluginBrowserDialog(PluginLoader *loader, QWidget *parent)
    : QDialog(parent), m_loader(loader)
{
    setWindowTitle("Plugin Manager");
    setFixedSize(520, 400);
    setStyleSheet(
        "QDialog { background: #0a0514; }"
        "QLabel { color: #e0e0f0; font-family: 'Courier New', monospace; }"
        "QPushButton { background: #1a1030; color: #e0e0f0; border: 1px solid #2a2270;"
        "  border-radius: 4px; padding: 6px 16px; font-family: 'Courier New', monospace; }"
        "QPushButton:hover { border-color: #4a7cff; }"
        "QListWidget { background: #120a20; color: #e0e0f0; border: 1px solid #1e1850;"
        "  border-radius: 4px; font-family: 'Courier New', monospace; }"
        "QListWidget::item { padding: 6px; }"
        "QListWidget::item:selected { background: #4a7cff; }"
    );

    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(8);

    QLabel *title = new QLabel("PLUGIN MANAGER");
    title->setStyleSheet("font-weight: bold; color: #4a7cff; font-size: 14px;");
    mainLayout->addWidget(title);

    QLabel *subtitle = new QLabel("Load external cipher modules (.so files)");
    subtitle->setStyleSheet("color: #8880a0; font-size: 10px;");
    mainLayout->addWidget(subtitle);

    // Plugin list
    m_pluginList = new QListWidget();
    m_pluginList->setMinimumHeight(200);
    mainLayout->addWidget(m_pluginList);
    connect(m_pluginList, &QListWidget::itemSelectionChanged, this, &PluginBrowserDialog::onPluginSelected);

    // Info label
    m_infoLabel = new QLabel("Select a plugin to see details");
    m_infoLabel->setStyleSheet("color: #8880a0; font-size: 10px; padding: 4px;");
    m_infoLabel->setWordWrap(true);
    mainLayout->addWidget(m_infoLabel);

    // Buttons
    QHBoxLayout *btnRow = new QHBoxLayout();
    m_loadBtn = new QPushButton("LOAD PLUGIN");
    m_loadBtn->setStyleSheet("font-weight: bold; color: #00cc88;");
    btnRow->addWidget(m_loadBtn);
    connect(m_loadBtn, &QPushButton::clicked, this, &PluginBrowserDialog::onLoadPlugin);

    m_unloadBtn = new QPushButton("UNLOAD");
    m_unloadBtn->setEnabled(false);
    m_unloadBtn->setStyleSheet("color: #ff6b6b;");
    btnRow->addWidget(m_unloadBtn);
    connect(m_unloadBtn, &QPushButton::clicked, this, &PluginBrowserDialog::onUnloadPlugin);

    btnRow->addStretch();

    QPushButton *closeBtn = new QPushButton("CLOSE");
    closeBtn->setStyleSheet("color: #4a7cff;");
    btnRow->addWidget(closeBtn);
    connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);

    mainLayout->addLayout(btnRow);

    // Plugin directory hint
    QLabel *hint = new QLabel("Plugins directory: ~/.obscuron/plugins/");
    hint->setStyleSheet("color: #3a3060; font-size: 9px;");
    mainLayout->addWidget(hint);

    refreshList();
}

void PluginBrowserDialog::onLoadPlugin() {
    QString path = QFileDialog::getOpenFileName(this, "Load Plugin", "",
        "Shared Libraries (*.so);;All Files (*)");
    if (path.isEmpty()) return;

    if (m_loader->loadPlugin(path.toStdString())) {
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
        std::string label = std::string(lp->plugin->name) + " — v" + lp->plugin->version_str;
        if (label == itemText) {
            QString info;
            info += "Name: " + QString::fromStdString(lp->plugin->name) + "\n";
            info += "Author: " + QString::fromStdString(lp->plugin->author ? lp->plugin->author : "Unknown") + "\n";
            info += "Version: " + QString::fromStdString(lp->plugin->version_str ? lp->plugin->version_str : "?") + "\n";
            info += "Description: " + QString::fromStdString(lp->plugin->description ? lp->plugin->description : "") + "\n";
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
        QString label = QString::fromStdString(lp->plugin->name)
            + " — v" + QString::fromStdString(lp->plugin->version_str ? lp->plugin->version_str : "?")
            + " (" + QString::number(lp->operationNames.size()) + " ops)";
        m_pluginList->addItem(label);
    }
    onPluginSelected();
}
