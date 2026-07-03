#include "py_plugin_host.h"
#include "plugin_loader.h"
#include <dlfcn.h>
#include <cstring>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QProcess>
#include <QCoreApplication>
#include <functional>
#include <QJSEngine>
#include <QJSValue>
#include <QJSValueList>
#include "plugin_crypto_bridge.h"

PluginLoader::PluginLoader(QObject *parent) : QObject(parent) {
    PyPluginHost::initialize();
    m_cryptoBridge = new PluginCryptoBridge(this);
}
PluginLoader::~PluginLoader() {
    unloadAll();
    PyPluginHost::finalize();
}

// ── Metadata parser for Python / JS plugins ──
bool PluginLoader::parseMetadata(const std::string &content, const std::string &commentPrefix,
                                  std::string &name, std::string &desc,
                                  std::string &author, std::string &version,
                                  std::string &category,
                                  std::vector<std::string> &ops)
{
    name.clear(); desc.clear(); author.clear();
    version.clear(); category.clear(); ops.clear();

    auto parseField = [&](const std::string &line, const std::string &prefix) -> std::string {
        size_t p = line.find(prefix);
        if (p == std::string::npos) return {};
        std::string val = line.substr(p + prefix.size());
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
            val.erase(val.begin());
        while (!val.empty() && (val.back() == '\r' || val.back() == '\n'))
            val.pop_back();
        return val;
    };

    auto startsWith = [](const std::string &s, const std::string &p) -> bool {
        return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
    };

    size_t start = 0;
    while (true) {
        size_t nl = content.find('\n', start);
        std::string line = content.substr(start, (nl == std::string::npos) ? std::string::npos : nl - start);
        size_t commentPos = line.find(commentPrefix);
        if (commentPos == std::string::npos) break;

        std::string text = line.substr(commentPos + commentPrefix.size());
        if (startsWith(text, " plugin_name:"))
            name = parseField(text, " plugin_name:");
        else if (startsWith(text, " plugin_description:"))
            desc = parseField(text, " plugin_description:");
        else if (startsWith(text, " plugin_author:"))
            author = parseField(text, " plugin_author:");
        else if (startsWith(text, " plugin_version:"))
            version = parseField(text, " plugin_version:");
        else if (startsWith(text, " plugin_category:"))
            category = parseField(text, " plugin_category:");
        else if (startsWith(text, " operations:")) {
            std::string opsStr = parseField(text, " operations:");
            size_t pos = 0;
            while (pos < opsStr.size()) {
                while (pos < opsStr.size() && (opsStr[pos] == ' ' || opsStr[pos] == ',')) pos++;
                if (pos >= opsStr.size()) break;
                size_t end = pos;
                while (end < opsStr.size() && opsStr[end] != ',' && opsStr[end] != ' ') end++;
                ops.push_back(opsStr.substr(pos, end - pos));
                pos = end;
            }
        }

        if (nl == std::string::npos) break;
        start = nl + 1;
    }

    return !name.empty() && !ops.empty();
}

// ── C .so plugin ──
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
    lp->lang = PluginLang_C;
    lp->handle = handle;
    lp->c_plugin = plugin;
    lp->filepath = path;
    lp->pluginName = plugin->name ? plugin->name : "";
    lp->pluginDescription = plugin->description ? plugin->description : "";
    lp->pluginCategory = plugin->category ? plugin->category : "Plugins";
    lp->pluginAuthor = plugin->author ? plugin->author : "";
    lp->pluginVersion = plugin->version_str ? plugin->version_str : "";

    for (int i = 0; i < plugin->operation_count; ++i) {
        const char *opName = plugin->get_operation_name(i);
        if (opName) lp->operationNames.push_back(opName);
    }

    m_plugins.push_back(std::move(lp));
    emit pluginLoaded(QString::fromStdString(plugin->name));
    return true;
}

// ── Python plugin ──
bool PluginLoader::loadPythonPlugin(const std::string &path) {
    QFile f(QString::fromStdString(path));
    if (!f.open(QIODevice::ReadOnly)) {
        emit pluginError(QString::fromStdString(path), "Cannot read file");
        return false;
    }
    std::string content = f.readAll().toStdString();
    f.close();

    std::string name, desc, author, version, category;
    std::vector<std::string> ops;
    if (!parseMetadata(content, "#", name, desc, author, version, category, ops)) {
        emit pluginError(QString::fromStdString(path), "Missing or invalid metadata headers");
        return false;
    }
    if (category.empty()) category = "Plugins";

    auto lp = std::make_unique<LoadedPlugin>();
    lp->lang = PluginLang_Python;
    lp->filepath = path;
    lp->pluginName = name;
    lp->pluginDescription = desc;
    lp->pluginCategory = category;
    lp->pluginAuthor = author;
    lp->pluginVersion = version;
    lp->operationNames = ops;
    lp->functionText.clear();

    std::string pyError;
    PyObject *module = PyPluginHost::instance().loadScript(path, pyError);
    if (!module) {
        emit pluginError(QString::fromStdString(path), QString::fromStdString(pyError));
        return false;
    }
    lp->pyModule = static_cast<void*>(module);

    m_plugins.push_back(std::move(lp));
    emit pluginLoaded(QString::fromStdString(name));
    return true;
}

// ── JavaScript plugin ──
bool PluginLoader::loadJSPlugin(const std::string &path) {
    QFile f(QString::fromStdString(path));
    if (!f.open(QIODevice::ReadOnly)) {
        emit pluginError(QString::fromStdString(path), "Cannot read file");
        return false;
    }
    std::string content = f.readAll().toStdString();
    f.close();

    std::string name, desc, author, version, category;
    std::vector<std::string> ops;
    if (!parseMetadata(content, "//", name, desc, author, version, category, ops)) {
        emit pluginError(QString::fromStdString(path), "Missing or invalid metadata headers");
        return false;
    }
    if (category.empty()) category = "Plugins";

    auto lp = std::make_unique<LoadedPlugin>();
    lp->lang = PluginLang_JS;
    lp->filepath = path;
    lp->pluginName = name;
    lp->pluginDescription = desc;
    lp->pluginCategory = category;
    lp->pluginAuthor = author;
    lp->pluginVersion = version;
    lp->operationNames = ops;

    // Extract function bodies for each operation
    for (const auto &op : ops) {
        std::string marker = "function " + op + "(";
        size_t fnPos = content.find(marker);
        if (fnPos != std::string::npos) {
            size_t bodyStart = content.find('{', fnPos);
            if (bodyStart != std::string::npos) {
                int depth = 0;
                size_t bodyEnd = std::string::npos;
                for (size_t i = bodyStart; i < content.size(); ++i) {
                    if (content[i] == '{') depth++;
                    else if (content[i] == '}') {
                        depth--;
                        if (depth == 0) {
                            bodyEnd = i + 1;
                            break;
                        }
                    }
                }
                if (bodyEnd != std::string::npos)
                    lp->functionText[op] = content.substr(bodyStart, bodyEnd - bodyStart);
            }
        }
    }

    m_plugins.push_back(std::move(lp));
    emit pluginLoaded(QString::fromStdString(name));
    return true;
}

void PluginLoader::unloadPlugin(const std::string &name) {
    for (auto it = m_plugins.begin(); it != m_plugins.end(); ++it) {
        if ((*it)->pluginName == name) {
            if ((*it)->lang == PluginLang_C) {
                if ((*it)->handle) dlclose((*it)->handle);
            } else if ((*it)->lang == PluginLang_Python) {
                if ((*it)->pyModule) Py_DECREF(static_cast<PyObject*>((*it)->pyModule));
            }
            m_plugins.erase(it);
            return;
        }
    }
}

void PluginLoader::unloadAll() {
    for (auto &lp : m_plugins) {
        if (lp->lang == PluginLang_C && lp->handle)
            dlclose(lp->handle);
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
                if (lp->lang == PluginLang_C && lp->c_plugin) {
                    char *err = nullptr;
                    char *result = lp->c_plugin->execute(op.c_str(), input.c_str(),
                        key.c_str(), iv.c_str(), param1, param2, encrypt, &err);
                    if (result) {
                        std::string out(result);
                        lp->c_plugin->free_string(result);
                        success = true;
                        return out;
                    }
                    if (err) {
                        error_msg = err;
                        lp->c_plugin->free_string(err);
                    }
                    return {};
                } else if (lp->lang == PluginLang_Python) {
                    return executePythonPlugin(lp.get(), op, input, key, iv,
                                               param1, param2, encrypt, success, error_msg);
                } else if (lp->lang == PluginLang_JS) {
                    return executeJSPlugin(lp.get(), op, input, key, iv,
                                           param1, param2, encrypt, success, error_msg);
                }
                return {};
            }
        }
    }
    return {};
}

// ── Python plugin execution via embedded Python ──
std::string PluginLoader::executePythonPlugin(LoadedPlugin *lp, const std::string &op,
    const std::string &input, const std::string &key, const std::string &iv,
    int param1, int param2, int encrypt, bool &success, std::string &error_msg)
{
    return PyPluginHost::instance().execute(static_cast<PyObject*>(lp->pyModule), op,
                                            input, key, iv,
                                            param1, param2, encrypt, success, error_msg);
}

// ── JavaScript plugin execution via QJSEngine ──
std::string PluginLoader::executeJSPlugin(LoadedPlugin *lp, const std::string &op,
    const std::string &input, const std::string &key, const std::string &iv,
    int param1, int param2, int encrypt, bool &success, std::string &error_msg)
{
    QFile f(QString::fromStdString(lp->filepath));
    if (!f.open(QIODevice::ReadOnly)) {
        error_msg = "Cannot read JS plugin file";
        return {};
    }
    QString script = QString::fromUtf8(f.readAll());
    f.close();

    QJSEngine engine;

    if (m_cryptoBridge) {
        QJSValue bridgeObj = engine.newQObject(m_cryptoBridge);
        engine.globalObject().setProperty("crypto", bridgeObj);
    }

    QJSValue result = engine.evaluate(script);
    if (result.isError()) {
        error_msg = ("JS parse error: " + result.toString()).toStdString();
        return {};
    }

    QJSValue fn = engine.globalObject().property(QString::fromStdString(op));
    if (!fn.isCallable()) {
        error_msg = "JS function '" + op + "' not found in plugin";
        return {};
    }

    QJSValueList jsArgs;
    jsArgs << QString::fromStdString(input)
           << QString::fromStdString(key)
           << QString::fromStdString(iv)
           << param1 << param2 << encrypt;

    QJSValue jsResult = fn.call(jsArgs);
    if (jsResult.isError()) {
        error_msg = ("JS execution error: " + jsResult.toString()).toStdString();
        return {};
    }

    if (jsResult.isUndefined() || jsResult.isNull())
        return {};

    success = true;
    return jsResult.toString().toStdString();
}

std::vector<std::string> PluginLoader::allPluginOperations() const {
    std::vector<std::string> ops;
    for (const auto &lp : m_plugins) {
        for (const auto &name : lp->operationNames)
            ops.push_back(name);
    }
    return ops;
}
