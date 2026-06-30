#include "plugin_loader.h"
#include <dlfcn.h>
#include <cstring>

PluginLoader::PluginLoader(QObject *parent) : QObject(parent) {}
PluginLoader::~PluginLoader() { unloadAll(); }

bool PluginLoader::loadPlugin(const std::string &path) {
    void *handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        emit pluginError(QString::fromStdString(path), QString::fromUtf8(dlerror()));
        return false;
    }

    auto *plugin = (ObscuronPluginV1*)dlsym(handle, OBSCURON_PLUGIN_SYMBOL);
    if (!plugin) {
        dlclose(handle);
        emit pluginError(QString::fromStdString(path), "Missing plugin symbol");
        return false;
    }

    if (plugin->api_version != OBSCURON_PLUGIN_API_VERSION) {
        dlclose(handle);
        emit pluginError(QString::fromStdString(path),
            QString("Incompatible API version: ") + QString::fromStdString(std::to_string(plugin->api_version)));
        return false;
    }

    if (!plugin->name || !plugin->execute || !plugin->free_string ||
        !plugin->get_operation_name || plugin->operation_count <= 0) {
        dlclose(handle);
        emit pluginError(QString::fromStdString(path), "Invalid plugin structure");
        return false;
    }

    auto lp = std::make_unique<LoadedPlugin>();
    lp->handle = handle;
    lp->plugin = plugin;
    lp->filepath = path;

    for (int i = 0; i < plugin->operation_count; ++i) {
        const char *opName = plugin->get_operation_name(i);
        if (opName) lp->operationNames.push_back(opName);
    }

    m_plugins.push_back(std::move(lp));
    emit pluginLoaded(QString::fromStdString(plugin->name));
    return true;
}

void PluginLoader::unloadPlugin(const std::string &name) {
    for (auto it = m_plugins.begin(); it != m_plugins.end(); ++it) {
        if ((*it)->plugin->name == name) {
            dlclose((*it)->handle);
            m_plugins.erase(it);
            return;
        }
    }
}

void PluginLoader::unloadAll() {
    for (auto &lp : m_plugins) {
        if (lp->handle) dlclose(lp->handle);
    }
    m_plugins.clear();
}

std::string PluginLoader::tryExecute(const std::string &op, const std::string &input,
                                      const std::string &key, const std::string &iv,
                                      int param1, int param2, int encrypt,
                                      bool &success, std::string &error_msg) {
    success = false;
    for (const auto &lp : m_plugins) {
        for (const auto &name : lp->operationNames) {
            if (name == op) {
                char *err = nullptr;
                char *result = lp->plugin->execute(op.c_str(), input.c_str(),
                    key.c_str(), iv.c_str(), param1, param2, encrypt, &err);
                if (result) {
                    std::string out(result);
                    lp->plugin->free_string(result);
                    success = true;
                    return out;
                }
                if (err) {
                    error_msg = err;
                    lp->plugin->free_string(err);
                }
                return {};
            }
        }
    }
    return {};
}

std::vector<std::string> PluginLoader::allPluginOperations() const {
    std::vector<std::string> ops;
    for (const auto &lp : m_plugins) {
        for (const auto &name : lp->operationNames)
            ops.push_back(name);
    }
    return ops;
}
