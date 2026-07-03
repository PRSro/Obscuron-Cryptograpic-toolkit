#ifndef PY_PLUGIN_HOST_H
#define PY_PLUGIN_HOST_H

#include <string>
#include <map>
#include <Python.h>

class PyPluginHost {
public:
    static PyPluginHost& instance();
    static bool initialize();
    static void finalize();

    PyObject* loadScript(const std::string &path, std::string &error);
    std::string execute(PyObject *module, const std::string &funcName,
                        const std::string &input, const std::string &key,
                        const std::string &iv,
                        int param1, int param2, int encrypt,
                        bool &success, std::string &error);

private:
    PyPluginHost() = default;
    ~PyPluginHost() { finalize(); }
    PyPluginHost(const PyPluginHost&) = delete;
    PyPluginHost& operator=(const PyPluginHost&) = delete;

    bool m_initialized = false;
    PyObject *m_bridgeModule = nullptr;
};

#endif
