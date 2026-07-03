#ifndef PLUGIN_LOADER_H
#define PLUGIN_LOADER_H

#include <QObject>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include "plugin_api.h"

struct RecipeStep;
class PluginCryptoBridge;

enum PluginLang { PluginLang_C, PluginLang_Python, PluginLang_JS };

struct LoadedPlugin {
    PluginLang lang = PluginLang_C;
    void *handle = nullptr;
    ObscuronPluginV1 *c_plugin = nullptr;
    std::string filepath;
    std::string pluginName;
    std::string pluginDescription;
    std::string pluginCategory;
    std::string pluginAuthor;
    std::string pluginVersion;
    std::vector<std::string> operationNames;
    std::map<std::string, std::string> functionText;
    void *pyModule = nullptr;
};

class PluginLoader : public QObject {
    Q_OBJECT
public:
    explicit PluginLoader(QObject *parent = nullptr);
    ~PluginLoader();

    bool loadPlugin(const std::string &path);
    bool loadPythonPlugin(const std::string &path);
    bool loadJSPlugin(const std::string &path);
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
    bool parseMetadata(const std::string &content, const std::string &commentPrefix,
                       std::string &name, std::string &desc,
                       std::string &author, std::string &version,
                       std::string &category,
                       std::vector<std::string> &ops);

    std::string executePythonPlugin(LoadedPlugin *lp, const std::string &op,
        const std::string &input, const std::string &key, const std::string &iv,
        int param1, int param2, int encrypt, bool &success, std::string &error_msg);

    std::string executeJSPlugin(LoadedPlugin *lp, const std::string &op,
        const std::string &input, const std::string &key, const std::string &iv,
        int param1, int param2, int encrypt, bool &success, std::string &error_msg);

    std::vector<std::unique_ptr<LoadedPlugin>> m_plugins;
    PluginCryptoBridge *m_cryptoBridge = nullptr;
};

#endif
