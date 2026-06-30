#ifndef PLUGIN_LOADER_H
#define PLUGIN_LOADER_H

#include <QObject>
#include <string>
#include <vector>
#include <memory>
#include "plugin_api.h"

struct RecipeStep;

struct LoadedPlugin {
    void *handle = nullptr;
    ObscuronPluginV1 *plugin = nullptr;
    std::string filepath;
    std::vector<std::string> operationNames;
};

class PluginLoader : public QObject {
    Q_OBJECT
public:
    explicit PluginLoader(QObject *parent = nullptr);
    ~PluginLoader();

    bool loadPlugin(const std::string &path);
    void unloadPlugin(const std::string &name);
    void unloadAll();

    const std::vector<std::unique_ptr<LoadedPlugin>>& plugins() const { return m_plugins; }

    std::string tryExecute(const std::string &op, const std::string &input,
                           const std::string &key, const std::string &iv,
                           int param1, int param2, int encrypt,
                           bool &success, std::string &error_msg);

    std::vector<std::string> allPluginOperations() const;

signals:
    void pluginLoaded(const QString &name);
    void pluginError(const QString &path, const QString &error);

private:
    std::vector<std::unique_ptr<LoadedPlugin>> m_plugins;
};

#endif
